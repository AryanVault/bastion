import base64
import email
from datetime import date, datetime, timedelta, timezone
from email.policy import default
from typing import Any

import httpx2
import pytest

from bastion.google.api import GoogleApiError
from bastion.google.calendar import CalendarClient, as_instant
from bastion.google.events import parse_when
from bastion.google.gmail import GmailClient, MessageId
from bastion.google.mail import OutgoingEmail
from support.google import EVENTS, GMAIL, FakeGoogle, body_of, calendar_event, gmail_message

IST = timezone(timedelta(hours=5, minutes=30))
CRLF = chr(13) + chr(10)
EMAIL = OutgoingEmail(to=("bob@example.org",), cc=(), subject="Hi", body="Hello Bob")


def raw_message(request: httpx2.Request, *path: str) -> email.message.EmailMessage:
    data: Any = body_of(request)
    for key in path:
        data = data[key]
    decoded = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    parsed = email.message_from_bytes(decoded, policy=default)
    assert isinstance(parsed, email.message.EmailMessage)
    return parsed


# ------------------------------------------------------------------- Gmail


async def test_profile_email() -> None:
    google = FakeGoogle()
    google.on("GET", f"{GMAIL}/profile", {"emailAddress": "me@example.com"})

    assert await GmailClient(google.api()).profile_email() == "me@example.com"


async def test_search_lists_ids_then_fetches_metadata() -> None:
    google = FakeGoogle()
    google.on(
        "GET",
        f"{GMAIL}/messages",
        {"messages": [{"id": "m1aaaa"}, {"id": "m2bbbb"}, {"id": "../evil"}, "junk"]},
    )
    google.on("GET", f"{GMAIL}/messages/m1aaaa", gmail_message("m1aaaa", labels=("UNREAD",)))
    google.on("GET", f"{GMAIL}/messages/m2bbbb", gmail_message("m2bbbb", subject="Re: x"))

    results = await GmailClient(google.api()).search("from:alice", 50)

    assert [r.id for r in results] == ["m1aaaa", "m2bbbb"]
    assert results[0].unread and not results[1].unread
    assert results[0].sender == "Alice <alice@example.com>"
    assert results[1].subject == "Re: x"
    listing = google.sent("GET", f"{GMAIL}/messages")[0]
    assert listing.url.params["q"] == "from:alice"
    assert listing.url.params["maxResults"] == "20"  # capped
    metadata = google.sent("GET", f"{GMAIL}/messages/m1aaaa")[0]
    assert metadata.url.params["format"] == "metadata"
    assert metadata.url.params.get_list("metadataHeaders") == ["From", "Subject", "Date"]


async def test_search_with_no_results() -> None:
    google = FakeGoogle()
    google.on("GET", f"{GMAIL}/messages", {"resultSizeEstimate": 0})

    assert await GmailClient(google.api()).search("x", 5) == []


async def test_read_returns_headers_and_body() -> None:
    google = FakeGoogle()
    google.on(
        "GET",
        f"{GMAIL}/messages/m1aaaa",
        gmail_message("m1aaaa", text=None, html="<p>Hi</p>", extra_headers=(("Cc", "c@x.com"),)),
    )

    received = await GmailClient(google.api()).read("m1aaaa")

    assert received.sender == "Alice <alice@example.com>"
    assert received.cc == "c@x.com"
    assert received.body.text == "<p>Hi</p>"
    assert received.body.is_html
    assert google.requests[0].url.params["format"] == "full"


async def test_unexpected_responses_are_reported() -> None:
    google = FakeGoogle()
    google.on("GET", f"{GMAIL}/messages/m1aaaa", ["not", "a", "message"])

    with pytest.raises(GoogleApiError, match="unexpected response"):
        await GmailClient(google.api()).read("m1aaaa")


async def test_reply_context_builds_the_reference_chain() -> None:
    google = FakeGoogle()
    google.on(
        "GET",
        f"{GMAIL}/messages/m2bbbb",
        gmail_message("m2bbbb", extra_headers=(("References", "<m0@mail.example.com>"),)),
    )

    context = await GmailClient(google.api()).reply_context("m2bbbb")

    assert context.thread_id == "t-m2bbbb"
    assert context.in_reply_to == "<m2bbbb@mail.example.com>"
    assert context.references == ("<m0@mail.example.com>", "<m2bbbb@mail.example.com>")


@pytest.mark.security
async def test_reply_context_drops_injected_threading_headers() -> None:
    google = FakeGoogle()
    message = gmail_message("m2bbbb")
    message["payload"]["headers"] = [
        {"name": "Message-ID", "value": "<a@x>" + CRLF + "Bcc: attacker@evil.example"},
        {"name": "References", "value": "<a@x> <b@x>" + CRLF + "Bcc: attacker@evil.example"},
    ]
    google.on("GET", f"{GMAIL}/messages/m2bbbb", message)

    context = await GmailClient(google.api()).reply_context("m2bbbb")

    assert context.in_reply_to is None
    assert context.references == ()


async def test_create_draft_posts_the_raw_message_in_the_thread() -> None:
    google = FakeGoogle()
    google.on("POST", f"{GMAIL}/drafts", {"id": "r-123", "message": {"id": "x"}})

    draft_id = await GmailClient(google.api()).create_draft(EMAIL, thread_id="t-1")

    assert draft_id == "r-123"
    request = google.requests[0]
    assert body_of(request)["message"]["threadId"] == "t-1"
    assert raw_message(request, "message", "raw")["To"] == "bob@example.org"


async def test_send_posts_the_raw_message() -> None:
    google = FakeGoogle()
    google.on("POST", f"{GMAIL}/messages/send", {"id": "s-1", "threadId": "t"})

    sent_id = await GmailClient(google.api()).send(EMAIL)

    assert sent_id == "s-1"
    assert "threadId" not in body_of(google.requests[0])
    assert raw_message(google.requests[0], "raw")["Subject"] == "Hi"


def test_message_ids_are_validated() -> None:
    from pydantic import TypeAdapter, ValidationError

    adapter: TypeAdapter[str] = TypeAdapter(MessageId)
    assert adapter.validate_python("18c2f0a1b2c3d4e5") == "18c2f0a1b2c3d4e5"
    with pytest.raises(ValidationError, match="Gmail message id"):
        adapter.validate_python("../../profile")


# ---------------------------------------------------------------- Calendar


def test_dates_become_local_midnight_for_queries() -> None:
    instant = as_instant(date(2026, 11, 25))

    assert instant.tzinfo is not None
    assert (instant.year, instant.month, instant.day, instant.hour) == (2026, 11, 25, 0)
    aware = datetime(2026, 11, 25, 9, tzinfo=IST)
    assert as_instant(aware) is aware


async def test_calendar_name_uses_an_events_endpoint() -> None:
    google = FakeGoogle()
    google.on("GET", EVENTS, {"summary": "me@example.com", "items": []})

    assert await CalendarClient(google.api()).calendar_name() == "me@example.com"
    assert google.requests[0].url.params["maxResults"] == "1"


async def test_list_queries_single_events_in_order_and_skips_cancelled() -> None:
    google = FakeGoogle()
    google.on(
        "GET",
        EVENTS,
        {
            "items": [
                calendar_event("evt1"),
                calendar_event("evt2", status="cancelled"),
                {"summary": "no id"},
                "junk",
            ]
        },
    )
    start = parse_when("2026-11-25T00:00:00+05:30")
    end = parse_when("2026-11-26")

    events = await CalendarClient(google.api()).list(start, end, "dentist", 500)

    assert [e.id for e in events] == ["evt1"]
    params = google.requests[0].url.params
    assert params["timeMin"] == "2026-11-25T00:00:00+05:30"
    assert params["timeMax"].startswith("2026-11-26T00:00:00")
    assert params["singleEvents"] == "true"
    assert params["orderBy"] == "startTime"
    assert params["maxResults"] == "50"
    assert params["q"] == "dentist"


async def test_list_without_items() -> None:
    google = FakeGoogle()
    google.on("GET", EVENTS, {})

    events = await CalendarClient(google.api()).list(
        date(2026, 11, 25), date(2026, 11, 26), None, 5
    )

    assert events == []
    assert "q" not in google.requests[0].url.params


async def test_insert_update_and_delete_use_send_updates_and_etags() -> None:
    google = FakeGoogle()
    google.on("GET", f"{EVENTS}/evt1", calendar_event("evt1"))
    google.on("POST", EVENTS, calendar_event("new1"))
    google.on("PUT", f"{EVENTS}/evt1", calendar_event("evt1", summary="Moved"))
    google.on("DELETE", f"{EVENTS}/evt1", httpx2.Response(204))
    client = CalendarClient(google.api())

    created = await client.insert({"summary": "Dentist"}, "none")
    event = await client.get("evt1")
    updated = await client.update(event, {"summary": "Moved"}, "all")
    await client.delete(event, "none")

    assert created.id == "new1"
    assert updated.summary == "Moved"
    insert, _, put, delete = google.requests
    assert insert.url.params["sendUpdates"] == "none"
    assert body_of(insert) == {"summary": "Dentist"}
    assert put.url.params["sendUpdates"] == "all"
    assert put.headers["If-Match"] == '"etag-evt1"'
    assert delete.headers["If-Match"] == '"etag-evt1"'


async def test_a_changed_event_is_not_overwritten() -> None:
    google = FakeGoogle()
    google.on("GET", f"{EVENTS}/evt1", calendar_event("evt1"))
    google.on("PUT", f"{EVENTS}/evt1", httpx2.Response(412))
    client = CalendarClient(google.api())
    event = await client.get("evt1")

    with pytest.raises(GoogleApiError, match="changed since it was read"):
        await client.update(event, {"summary": "Moved"}, "none")


async def test_unexpected_calendar_responses_are_reported() -> None:
    google = FakeGoogle()
    google.on("GET", f"{EVENTS}/evt1", ["junk"])

    with pytest.raises(GoogleApiError, match="unexpected response"):
        await CalendarClient(google.api()).get("evt1")


async def test_search_skips_a_message_deleted_since_it_was_listed() -> None:
    google = FakeGoogle()
    google.on("GET", f"{GMAIL}/messages", {"messages": [{"id": "m1aaaa"}, {"id": "gone00"}]})
    google.on("GET", f"{GMAIL}/messages/m1aaaa", gmail_message("m1aaaa"))

    results = await GmailClient(google.api()).search("x", 5)

    assert [r.id for r in results] == ["m1aaaa"]


async def test_search_reports_the_error_when_every_fetch_fails() -> None:
    google = FakeGoogle()
    google.on("GET", f"{GMAIL}/messages", {"messages": [{"id": "gone00"}]})

    with pytest.raises(GoogleApiError, match="not found"):
        await GmailClient(google.api()).search("x", 5)
