from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from bastion.google.events import (
    MAX_LISTED_GUESTS,
    MAX_NOTES_CHARS,
    ORIGIN_PROPERTY,
    UNTRUSTED_ORIGIN,
    CalendarTime,
    EventId,
    normalize_title,
    parse_event,
    parse_when,
    render_event,
    same_when,
    when_text,
    when_to_google,
)

IST = timezone(timedelta(hours=5, minutes=30))


def event(**fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "evt123",
        "etag": '"3181161784712000"',
        "summary": "Dentist",
        "start": {"dateTime": "2026-11-25T15:00:00+05:30"},
        "end": {"dateTime": "2026-11-25T16:00:00+05:30"},
        "status": "confirmed",
        "organizer": {"email": "me@example.com", "self": True},
        "creator": {"email": "me@example.com", "self": True},
    }
    return base | fields


# -------------------------------------------------------------------- times


def test_dates_and_offset_date_times_are_parsed() -> None:
    assert parse_when("2026-11-25") == date(2026, 11, 25)
    assert parse_when("2026-11-25T15:00:00+05:30") == datetime(2026, 11, 25, 15, tzinfo=IST)
    assert parse_when("2026-11-25T09:30Z") == datetime(2026, 11, 25, 9, 30, tzinfo=UTC)


@pytest.mark.parametrize(
    "value", ["2026-11-25T15:00:00", "tomorrow", "2026-13-01", "2026-11-25 3pm", ""]
)
def test_times_without_an_offset_or_malformed_are_refused(value: str) -> None:
    with pytest.raises(ValueError, match="UTC offset"):
        parse_when(value)


class _Args(BaseModel):
    when: CalendarTime
    event_id: EventId


def test_calendar_time_fields_normalise_their_value() -> None:
    args = _Args(when="2026-11-25T15:00+05:30", event_id="abc_20261125T100000Z")

    assert args.when == "2026-11-25T15:00:00+05:30"


@pytest.mark.security
@pytest.mark.parametrize("bad", ["../calendars/x", "a b", "ab", "x" * 300, "id?x=1"])
def test_event_ids_are_restricted_to_safe_characters(bad: str) -> None:
    with pytest.raises(ValidationError, match="event id"):
        _Args(when="2026-11-25", event_id=bad)


def test_when_to_google_uses_date_or_date_time() -> None:
    assert when_to_google(date(2026, 11, 25)) == {"date": "2026-11-25"}
    assert when_to_google(datetime(2026, 11, 25, 15, tzinfo=IST)) == {
        "dateTime": "2026-11-25T15:00:00+05:30"
    }


def test_same_when_compares_instants_across_offsets() -> None:
    ist = datetime(2026, 11, 25, 15, tzinfo=IST)
    utc = datetime(2026, 11, 25, 9, 30, tzinfo=UTC)

    assert same_when(ist, utc)
    assert not same_when(ist, utc + timedelta(minutes=1))
    assert same_when(date(2026, 11, 25), date(2026, 11, 25))
    assert not same_when(date(2026, 11, 25), ist)
    assert not same_when(None, None)


def test_when_text_is_readable() -> None:
    assert when_text(datetime(2026, 11, 25, 15, tzinfo=IST)) == "2026-11-25T15:00+05:30"
    assert when_text(date(2026, 11, 25)) == "2026-11-25 (all day)"
    assert when_text(None) == "(unknown)"


# ------------------------------------------------------------------- events


def test_events_are_parsed() -> None:
    parsed = parse_event(
        event(
            location="Clinic",
            attendees=[
                {"email": "me@example.com", "self": True, "responseStatus": "accepted"},
                {"email": "bob@example.org", "responseStatus": "needsAction"},
                {"responseStatus": "accepted"},
                "junk",
            ],
        )
    )

    assert parsed.id == "evt123"
    assert parsed.start == datetime(2026, 11, 25, 15, tzinfo=IST)
    assert parsed.location == "Clinic"
    assert parsed.other_guests == ("bob@example.org",)
    assert parsed.raw["summary"] == "Dentist"
    assert not parsed.owner_written  # guests may add people (Google's default)
    assert parse_event(event(attendees=[], guestsCanInviteOthers=True)).owner_written


def test_all_day_events_are_parsed() -> None:
    parsed = parse_event(event(start={"date": "2026-11-25"}, end={"date": "2026-11-26"}))

    assert parsed.start == date(2026, 11, 25)
    assert parsed.end == date(2026, 11, 26)


def test_malformed_events_are_tolerated() -> None:
    parsed = parse_event({"start": {"dateTime": "garbage"}, "summary": 5, "organizer": "x"})

    assert parsed.start is None
    assert parsed.summary == ""
    assert not parsed.organizer_self
    assert not parsed.owner_written


@pytest.mark.security
@pytest.mark.parametrize(
    "fields",
    [
        {"organizer": {"email": "eve@evil.example"}},  # an invitation
        {"creator": {"email": "eve@evil.example"}},
        {"guestsCanModify": True},  # guests could rewrite the text
        {"extendedProperties": {"private": {ORIGIN_PROPERTY: UNTRUSTED_ORIGIN}}},
        {"eventType": "fromGmail"},  # made by Gmail from an email
        {"attendees": [{"email": "bob@example.org"}]},  # guests can invite others by default
    ],
)
def test_events_not_entirely_written_by_the_owner_are_untrusted(fields: dict[str, Any]) -> None:
    assert not parse_event(event(**fields)).owner_written


def test_events_bastion_marked_as_the_owners_stay_trusted() -> None:
    parsed = parse_event(event(extendedProperties={"private": {ORIGIN_PROPERTY: "owner"}}))

    assert parsed.origin == "owner"
    assert parsed.owner_written


def test_render_marks_invitations_and_caps_long_fields() -> None:
    guests = [{"email": f"g{i}@example.com", "responseStatus": "accepted"} for i in range(15)]
    parsed = parse_event(
        event(
            organizer={"email": "eve@evil.example"},
            description="x" * (MAX_NOTES_CHARS + 50),
            attendees=guests,
            location="Room 1",
        )
    )

    text = render_event(parsed)

    assert "[evt123] 2026-11-25T15:00+05:30 to 2026-11-25T16:00+05:30: Dentist" in text
    assert "written by someone else" in text
    assert "organiser: eve@evil.example" in text
    assert f"and {15 - MAX_LISTED_GUESTS} more" in text
    assert "where: Room 1" in text
    assert "x" * MAX_NOTES_CHARS + "..." in text
    assert "x" * (MAX_NOTES_CHARS + 1) not in text


def test_render_of_an_owner_event_is_plain() -> None:
    text = render_event(parse_event(event(summary="")))

    assert "(no title)" in text
    assert "organiser: you" in text
    assert "someone else" not in text


def test_guests_who_cannot_invite_keep_an_owner_event_trusted() -> None:
    parsed = parse_event(
        event(attendees=[{"email": "bob@example.org"}], guestsCanInviteOthers=False)
    )

    assert parsed.owner_written


def test_titles_are_normalised() -> None:
    hidden = "Den" + chr(0x200B) + "tist" + chr(9) + " " + chr(10) + "visit"

    assert normalize_title(hidden) == "Dentist visit"
    assert parse_event(event(summary=hidden)).title == "Dentist visit"


def test_a_recurring_master_is_a_series() -> None:
    assert parse_event(event(recurrence=["RRULE:FREQ=WEEKLY"])).series
    assert not parse_event(event(recurringEventId="evt0")).series


def test_render_clips_long_titles_and_locations() -> None:
    text = render_event(parse_event(event(summary="t" * 300, location="l" * 400)))

    assert "t" * 200 in text and "t" * 201 not in text
    assert "l" * 300 in text and "l" * 301 not in text
