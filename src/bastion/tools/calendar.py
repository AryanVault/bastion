"""Calendar tools for the owner's primary calendar.

* Listing: invitations, events guests can edit, and events Bastion wrote from untrusted content
  are untrusted (they taint the conversation); the owner's own events are not.
* Events Bastion creates or changes while the conversation is tainted are marked, so their text
  comes back untrusted later (the calendar counterpart of memory provenance).
* Anything that reaches other people (inviting guests, changing an event they are on) is a
  ``send`` action. The model must declare it (``notify_guests``), and code checks the
  declaration against the live event, so it cannot be understated to dodge an approval.
* Changes and deletions name the event they expect (its title, and its start for deletions).
  Code compares that with the live event before acting, so an approval prompt always describes
  what will really change, and the ETag makes Google refuse if the event changed in between.
"""

import copy
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from typing import Any, Self

from pydantic import Field, model_validator

from bastion.google.calendar import MAX_EVENTS, CalendarClient, SendUpdates, as_instant
from bastion.google.events import (
    MAX_TITLE_CHARS,
    NO_TITLE,
    ORIGIN_PROPERTY,
    OWNER_ORIGIN,
    UNTRUSTED_ORIGIN,
    CalendarTime,
    Event,
    EventId,
    When,
    normalize_title,
    parse_when,
    render_event,
    same_when,
    when_text,
    when_to_google,
)
from bastion.google.mail import EmailAddress, SingleLine
from bastion.tools.base import (
    RiskTier,
    Tool,
    ToolArgs,
    ToolContext,
    ToolDenied,
    ToolError,
    ToolOutput,
    Trust,
)

DEFAULT_DAYS = 7
MAX_RANGE_DAYS = 366
MAX_GUESTS = 50

_MISMATCH = (
    "The event's current details do not match the ones given. List the events again and use "
    "the exact title and start shown."
)
_SERIES = (
    "That id is a whole recurring series. Bastion changes single occurrences only: use the "
    "occurrence's id from calendar_list_events."
)
_NOT_ORGANISER = "Only events the owner organises can be changed or deleted by Bastion."
_GUESTS = (
    "This affects the event's other guests: they see the change and are notified. Call again "
    "with notify_guests=true; the owner will be asked to approve it."
)


def _check_span(start: When, end: When) -> None:
    if isinstance(start, datetime) != isinstance(end, datetime):
        raise ValueError("start and end must both be dates (all day) or both date-times")
    if not as_instant(end) > as_instant(start):
        raise ValueError("end must be after start")


def _origin(ctx: ToolContext) -> str:
    return UNTRUSTED_ORIGIN if ctx.tainted else OWNER_ORIGIN


def _domains(addresses: tuple[str, ...] | None) -> list[str]:
    return sorted({a.rpartition("@")[2] for a in addresses or ()})


def _local_now() -> datetime:
    return datetime.now().astimezone()


# --------------------------------------------------------------------- list


class CalendarListArgs(ToolArgs):
    start: CalendarTime | None = Field(
        default=None,
        description="From: a date-time with the owner's UTC offset (best), or YYYY-MM-DD. "
        "Default: now.",
    )
    end: CalendarTime | None = Field(default=None, description="Until. Default: 7 days later.")
    query: SingleLine | None = Field(default=None, max_length=200, description="Words to match.")
    limit: int = Field(default=20, ge=1, le=MAX_EVENTS)


class CalendarListTool(Tool[CalendarListArgs]):
    name = "calendar_list_events"
    description = "List events on the owner's primary calendar, with ids for changing them."
    args_model = CalendarListArgs
    risk = RiskTier.READ

    def __init__(
        self, calendar: CalendarClient, clock: Callable[[], datetime] = _local_now
    ) -> None:
        self._calendar = calendar
        self._clock = clock

    async def run(self, args: CalendarListArgs, ctx: ToolContext) -> ToolOutput:
        start: When = parse_when(args.start) if args.start else self._clock()
        end: When = (
            parse_when(args.end) if args.end else as_instant(start) + timedelta(days=DEFAULT_DAYS)
        )
        if not as_instant(end) > as_instant(start):
            raise ToolError("end must be after start")
        if as_instant(end) - as_instant(start) > timedelta(days=MAX_RANGE_DAYS):
            raise ToolError(f"the range can be at most {MAX_RANGE_DAYS} days")
        events = await self._calendar.list(start, end, args.query, args.limit)
        span = f"{when_text(start)} to {when_text(end)}"
        if not events:
            return ToolOutput(f"No events from {span}.", Trust.TRUSTED, "calendar")
        content = f"Events from {span}:\n" + "\n".join(render_event(e) for e in events)
        if all(e.owner_written for e in events):
            return ToolOutput(content, Trust.TRUSTED, "calendar")
        return ToolOutput(content, Trust.UNTRUSTED, "calendar:invitations")


# ------------------------------------------------------------------- create


class CalendarCreateArgs(ToolArgs):
    summary: SingleLine = Field(min_length=1, max_length=200, description="The title.")
    start: CalendarTime = Field(description="YYYY-MM-DD (all day) or a date-time with offset.")
    end: CalendarTime = Field(description="Same form as start; for all-day events, exclusive.")
    location: SingleLine | None = Field(default=None, max_length=300)
    description: str | None = Field(default=None, max_length=5000)
    attendees: tuple[EmailAddress, ...] = Field(
        default=(),
        max_length=MAX_GUESTS,
        description="Guests to invite (they receive an invitation email).",
    )

    @model_validator(mode="after")
    def _span(self) -> Self:
        _check_span(parse_when(self.start), parse_when(self.end))
        return self


class CalendarCreateTool(Tool[CalendarCreateArgs]):
    name = "calendar_create_event"
    description = "Create an event on the owner's primary calendar, optionally inviting guests."
    args_model = CalendarCreateArgs
    risk = RiskTier.WRITE

    def __init__(self, calendar: CalendarClient) -> None:
        self._calendar = calendar

    def risk_for(self, args: CalendarCreateArgs) -> RiskTier:
        return RiskTier.SEND if args.attendees else RiskTier.WRITE

    def describe(self, args: CalendarCreateArgs) -> str:
        place = f" at {args.location}" if args.location else ""
        guests = f", inviting {', '.join(args.attendees)}" if args.attendees else ""
        return (
            f"Create calendar event '{args.summary}' from {args.start} to {args.end}{place}{guests}"
        )

    def audit_view(self, args: CalendarCreateArgs) -> dict[str, Any]:
        return {**super().audit_view(args), "attendee_domains": _domains(args.attendees)}

    async def run(self, args: CalendarCreateArgs, ctx: ToolContext) -> ToolOutput:
        body: dict[str, Any] = {
            "summary": args.summary,
            "start": when_to_google(parse_when(args.start)),
            "end": when_to_google(parse_when(args.end)),
            "extendedProperties": {"private": {ORIGIN_PROPERTY: _origin(ctx)}},
        }
        if args.location:
            body["location"] = args.location
        if args.description:
            body["description"] = args.description
        if args.attendees:
            body["attendees"] = [{"email": a} for a in args.attendees]
        event = await self._calendar.insert(body, "all" if args.attendees else "none")
        sent = " Invitations were sent." if args.attendees else ""
        return ToolOutput(
            f"Created event {event.id}: {args.summary}, {when_text(event.start)} to "
            f"{when_text(event.end)}.{sent}",
            Trust.TRUSTED,
            self.name,
        )


# ------------------------------------------------------------ update/delete


def _same_title(event: Event, given: str) -> bool:
    expected = "" if given == NO_TITLE else normalize_title(given)
    return event.title[:MAX_TITLE_CHARS] == expected


def _check_target(event: Event, title: str, start: str) -> None:
    """The live event must be the one the approval named, and one Bastion may change."""
    if not _same_title(event, title) or not same_when(event.start, parse_when(start)):
        raise ToolDenied(_MISMATCH)
    if event.series:
        raise ToolDenied(_SERIES)
    if not event.organizer_self:
        raise ToolDenied(_NOT_ORGANISER)


def _check_reach(event: Event, notify_guests: bool, new_guests: tuple[str, ...] = ()) -> None:
    if (event.other_guests or new_guests) and not notify_guests:
        raise ToolDenied(_GUESTS)


def _time_field(value: When, current: Any) -> dict[str, str]:
    """A new start or end, keeping the event's named time zone (recurrence and DST need it)."""
    field = when_to_google(value)
    zone = current.get("timeZone") if isinstance(current, Mapping) else None
    if "dateTime" in field and isinstance(zone, str):
        field["timeZone"] = zone
    return field


def _merged_guests(current: Any, wanted: tuple[str, ...]) -> list[Any]:
    """The new guest list, keeping the owner and each remaining guest's reply."""
    entries = [a for a in (current if isinstance(current, list) else []) if isinstance(a, Mapping)]
    own = [a for a in entries if a.get("self") is True]
    by_email = {str(a.get("email", "")).lower(): a for a in entries if a.get("self") is not True}
    own_emails = {str(a.get("email", "")).lower() for a in own}
    guests = [
        by_email.get(email.lower(), {"email": email})
        for email in dict.fromkeys(wanted)
        if email.lower() not in own_emails
    ]
    return [*own, *guests]


class CalendarUpdateArgs(ToolArgs):
    event_id: EventId = Field(description="An id from calendar_list_events.")
    event_summary: SingleLine = Field(
        max_length=MAX_TITLE_CHARS,
        description="The event's current title, exactly as listed (checked before changing).",
    )
    event_start: CalendarTime = Field(
        description="The event's current start, exactly as listed (checked before changing)."
    )
    summary: SingleLine | None = Field(default=None, min_length=1, max_length=MAX_TITLE_CHARS)
    start: CalendarTime | None = None
    end: CalendarTime | None = None
    location: SingleLine | None = Field(default=None, max_length=300)
    description: str | None = Field(default=None, max_length=5000)
    attendees: tuple[EmailAddress, ...] | None = Field(
        default=None, max_length=MAX_GUESTS, description="The complete new guest list."
    )
    notify_guests: bool = Field(
        default=False,
        description="Must be true if the event has other guests (they see the change).",
    )

    @model_validator(mode="after")
    def _has_change(self) -> Self:
        changes = (self.summary, self.start, self.end, self.location, self.description)
        if all(value is None for value in changes) and self.attendees is None:
            raise ValueError("nothing to change")
        return self


def _changes(args: CalendarUpdateArgs) -> str:
    parts = [
        f"{label} -> {value}"
        for label, value in (
            ("title", args.summary),
            ("start", args.start),
            ("end", args.end),
            ("location", args.location),
        )
        if value is not None
    ]
    if args.description is not None:
        parts.append(f"notes -> {len(args.description)} characters")
    if args.attendees is not None:
        parts.append(f"guests -> {', '.join(args.attendees) or 'none'}")
    return ", ".join(parts)


class CalendarUpdateTool(Tool[CalendarUpdateArgs]):
    name = "calendar_update_event"
    description = (
        "Change one event (or one occurrence of a recurring event) that the owner organises. "
        "Give its id, current title and current start exactly as listed."
    )
    args_model = CalendarUpdateArgs
    risk = RiskTier.WRITE

    def __init__(self, calendar: CalendarClient) -> None:
        self._calendar = calendar

    def risk_for(self, args: CalendarUpdateArgs) -> RiskTier:
        return RiskTier.SEND if args.notify_guests or args.attendees else RiskTier.WRITE

    def describe(self, args: CalendarUpdateArgs) -> str:
        notify = " and notify its guests" if args.notify_guests else ""
        return (
            f"Change calendar event '{args.event_summary}' at {args.event_start}: "
            f"{_changes(args)}{notify}"
        )

    def audit_view(self, args: CalendarUpdateArgs) -> dict[str, Any]:
        return {**super().audit_view(args), "attendee_domains": _domains(args.attendees)}

    async def run(self, args: CalendarUpdateArgs, ctx: ToolContext) -> ToolOutput:
        event = await self._calendar.get(args.event_id)
        _check_target(event, args.event_summary, args.event_start)
        _check_reach(event, args.notify_guests, args.attendees or ())
        start = parse_when(args.start) if args.start else event.start
        end = parse_when(args.end) if args.end else event.end
        if start is None or end is None:
            raise ToolError("the event's current times could not be read")
        try:
            _check_span(start, end)
        except ValueError as exc:
            raise ToolError(str(exc)) from exc
        send_updates: SendUpdates = "all" if args.notify_guests else "none"
        updated = await self._calendar.update(event, self._body(event, args, ctx), send_updates)
        return ToolOutput(
            f"Updated event {updated.id} ({args.summary or args.event_summary}): "
            f"{when_text(updated.start)} to {when_text(updated.end)}.",
            Trust.TRUSTED,
            self.name,
        )

    @staticmethod
    def _body(event: Event, args: CalendarUpdateArgs, ctx: ToolContext) -> dict[str, Any]:
        # Start from the event exactly as read: fields Bastion does not change (time zone,
        # recurrence details, reminders, guests' replies) go back untouched.
        body: dict[str, Any] = copy.deepcopy(dict(event.raw))
        for key in ("start", "end"):
            value = getattr(args, key)
            if value is not None:
                body[key] = _time_field(parse_when(value), body.get(key))
        for key in ("summary", "location", "description"):
            value = getattr(args, key)
            if value is not None:
                body[key] = value
        if args.attendees is not None:
            body["attendees"] = _merged_guests(body.get("attendees"), args.attendees)
        if ctx.tainted:  # sticky: once written from untrusted content, always untrusted
            properties = body.setdefault("extendedProperties", {})
            properties.setdefault("private", {})[ORIGIN_PROPERTY] = UNTRUSTED_ORIGIN
        return body


class CalendarDeleteArgs(ToolArgs):
    event_id: EventId = Field(description="An id from calendar_list_events.")
    event_summary: SingleLine = Field(
        max_length=MAX_TITLE_CHARS, description="The event's current title, exactly as listed."
    )
    event_start: CalendarTime = Field(description="The event's current start, as listed.")
    notify_guests: bool = Field(
        default=False, description="Must be true if the event has other guests."
    )


class CalendarDeleteTool(Tool[CalendarDeleteArgs]):
    name = "calendar_delete_event"
    description = (
        "Delete one event (or one occurrence of a recurring event) that the owner organises. "
        "Give its id, title and start as listed."
    )
    args_model = CalendarDeleteArgs
    # Irreversible: always approved, with a one-time code where step-up is on; never tainted.
    risk = RiskTier.DESTRUCTIVE

    def __init__(self, calendar: CalendarClient) -> None:
        self._calendar = calendar

    def describe(self, args: CalendarDeleteArgs) -> str:
        notify = " and notify its guests" if args.notify_guests else ""
        return f"Delete calendar event '{args.event_summary}' at {args.event_start}{notify}"

    async def run(self, args: CalendarDeleteArgs, ctx: ToolContext) -> ToolOutput:
        event = await self._calendar.get(args.event_id)
        _check_target(event, args.event_summary, args.event_start)
        _check_reach(event, args.notify_guests)
        await self._calendar.delete(event, "all" if args.notify_guests else "none")
        return ToolOutput(
            f"Deleted event {args.event_id} ({args.event_summary}).", Trust.TRUSTED, self.name
        )
