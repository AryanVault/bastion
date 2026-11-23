"""Calendar events as Bastion sees them: times, parsing, and whose words an event contains.

An invitation is written by whoever sent it: its title, description and location can carry a
prompt injection just like an email. So an event counts as the owner's own words only if the
owner organised *and* created it, it is an ordinary event (not, say, one Gmail made from an
email), guests can neither edit it nor add people to it, and Bastion did not write it while the
conversation contained untrusted content (it marks such events, the calendar counterpart of
memory provenance).
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime
from types import MappingProxyType
from typing import Annotated, Any

from pydantic import AfterValidator

from bastion.text import strip_invisible

ORIGIN_PROPERTY = "bastion_origin"
UNTRUSTED_ORIGIN = "untrusted"
OWNER_ORIGIN = "owner"
MAX_NOTES_CHARS = 500
MAX_TITLE_CHARS = 200
MAX_LOCATION_CHARS = 300
NO_TITLE = "(no title)"
_OWN_TYPES = frozenset({"", "default"})
MAX_LISTED_GUESTS = 10

type When = datetime | date

_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_EVENT_ID = re.compile(r"[A-Za-z0-9_-]{3,256}")
_WHEN_HELP = "use YYYY-MM-DD for all-day, or a date-time with a UTC offset (2026-11-25T15:00+05:30)"


def parse_when(value: str) -> When:
    """A calendar time: ``YYYY-MM-DD`` (all-day) or an ISO 8601 date-time with an offset.

    Offsets are required: a bare "15:00" would be read in whichever time zone the server
    assumes, which is how a meeting silently moves by hours.
    """
    if _DATE.fullmatch(value):
        try:
            return date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError(_WHEN_HELP) from exc
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(_WHEN_HELP) from exc
    if parsed.tzinfo is None:
        raise ValueError(_WHEN_HELP)
    return parsed


def _normalized_when(value: str) -> str:
    return parse_when(value).isoformat()


def _event_id(value: str) -> str:
    if not _EVENT_ID.fullmatch(value):
        raise ValueError("not a calendar event id")
    return value


CalendarTime = Annotated[str, AfterValidator(_normalized_when)]
EventId = Annotated[str, AfterValidator(_event_id)]


def normalize_title(text: str) -> str:
    """A title as Bastion shows it, and compares it: no invisible characters, single spaces."""
    return " ".join(strip_invisible(text).split())


def when_to_google(value: When) -> dict[str, str]:
    if isinstance(value, datetime):
        return {"dateTime": value.isoformat()}
    return {"date": value.isoformat()}


def same_when(a: When | None, b: When | None) -> bool:
    """Same moment (date-times compare as instants, whatever their offsets) or same day."""
    if isinstance(a, datetime) and isinstance(b, datetime):
        return a == b
    if isinstance(a, datetime) or isinstance(b, datetime):
        return False
    return a is not None and a == b


def when_text(value: When | None) -> str:
    if value is None:
        return "(unknown)"
    if isinstance(value, datetime):
        return value.isoformat(timespec="minutes")
    return f"{value.isoformat()} (all day)"


@dataclass(frozen=True)
class Attendee:
    email: str
    response: str
    is_self: bool


@dataclass(frozen=True)
class Event:
    id: str
    etag: str
    summary: str
    start: When | None
    end: When | None
    location: str = ""
    description: str = ""
    status: str = ""
    organizer_self: bool = False
    organizer_email: str = ""
    creator_self: bool = False
    guests_can_modify: bool = False
    guests_can_invite: bool = True  # Google's default
    event_type: str = ""
    attendees: tuple[Attendee, ...] = ()
    origin: str | None = None
    # The resource exactly as Google returned it: updates send it back whole (with If-Match).
    raw: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    @property
    def title(self) -> str:
        return normalize_title(self.summary)

    @property
    def series(self) -> bool:
        """A whole recurring series (its "master" event), as opposed to one occurrence."""
        return bool(self.raw.get("recurrence"))

    @property
    def other_guests(self) -> tuple[str, ...]:
        return tuple(a.email for a in self.attendees if not a.is_self)

    @property
    def owner_written(self) -> bool:
        """Whether every word in the event is the owner's own (see the module docstring)."""
        return (
            self.organizer_self
            and self.creator_self
            and self.event_type in _OWN_TYPES
            and not self.guests_can_modify
            and not (self.other_guests and self.guests_can_invite)
            and self.origin != UNTRUSTED_ORIGIN
        )


def _str(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    return value if isinstance(value, str) else ""


def _flag(data: Any, key: str) -> bool:
    return isinstance(data, Mapping) and data.get(key) is True


def _when(data: Any) -> When | None:
    if not isinstance(data, Mapping):
        return None
    value = data.get("dateTime") or data.get("date")
    if not isinstance(value, str):
        return None
    try:
        return parse_when(value)
    except ValueError:
        return None


def _attendees(data: Any) -> tuple[Attendee, ...]:
    if not isinstance(data, list):
        return ()
    return tuple(
        Attendee(_str(item, "email"), _str(item, "responseStatus"), item.get("self") is True)
        for item in data
        if isinstance(item, Mapping) and _str(item, "email")
    )


def _origin(data: Mapping[str, Any]) -> str | None:
    properties = data.get("extendedProperties")
    private = properties.get("private") if isinstance(properties, Mapping) else None
    value = private.get(ORIGIN_PROPERTY) if isinstance(private, Mapping) else None
    return value if isinstance(value, str) else None


def parse_event(data: Mapping[str, Any]) -> Event:
    organizer = data.get("organizer")
    return Event(
        id=_str(data, "id"),
        etag=_str(data, "etag"),
        summary=_str(data, "summary"),
        start=_when(data.get("start")),
        end=_when(data.get("end")),
        location=_str(data, "location"),
        description=_str(data, "description"),
        status=_str(data, "status"),
        organizer_self=_flag(organizer, "self"),
        organizer_email=_str(organizer, "email") if isinstance(organizer, Mapping) else "",
        creator_self=_flag(data.get("creator"), "self"),
        guests_can_modify=data.get("guestsCanModify") is True,
        guests_can_invite=data.get("guestsCanInviteOthers") is not False,
        event_type=_str(data, "eventType"),
        attendees=_attendees(data.get("attendees")),
        origin=_origin(data),
        raw=MappingProxyType(dict(data)),
    )


def render_event(event: Event) -> str:
    """A few plain lines describing an event, for the model."""
    kind = "" if event.owner_written else " (written by someone else or from untrusted content)"
    lines = [
        f"[{event.id}] {when_text(event.start)} to {when_text(event.end)}: "
        f"{event.title[:MAX_TITLE_CHARS] or NO_TITLE}{kind}"
    ]
    if event.location:
        lines.append(f"   where: {event.location[:MAX_LOCATION_CHARS]}")
    organiser = "you" if event.organizer_self else (event.organizer_email or "someone else")
    guests = [f"{a.email} ({a.response or 'no reply'})" for a in event.attendees if not a.is_self]
    extra = len(guests) - MAX_LISTED_GUESTS
    guest_text = ", ".join(guests[:MAX_LISTED_GUESTS]) + (f" and {extra} more" if extra > 0 else "")
    lines.append(f"   organiser: {organiser}" + (f"; guests: {guest_text}" if guests else ""))
    if event.description:
        notes = event.description[:MAX_NOTES_CHARS]
        cut = "..." if len(event.description) > MAX_NOTES_CHARS else ""
        lines.append(f"   notes: {notes}{cut}")
    return "\n".join(lines)
