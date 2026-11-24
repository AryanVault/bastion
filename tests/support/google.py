"""A scripted stand-in for Google's REST APIs, plus builders for Gmail and Calendar JSON."""

import base64
import json
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs

import httpx2

from bastion.google.api import GoogleApi

type Reply = httpx2.Response | Callable[[httpx2.Request], httpx2.Response] | Any

GMAIL = "/gmail/v1/users/me"
EVENTS = "/calendar/v3/calendars/primary/events"
ACCESS_TOKEN = "ya29.test-access-token-0001"


class StaticToken:
    async def token(self) -> str:
        return ACCESS_TOKEN

    def invalidate(self) -> None:
        pass


class FakeGoogle:
    """Routes requests by method and exact path; unknown routes get a 404."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], Reply] = {}
        self.requests: list[httpx2.Request] = []

    def on(self, method: str, path: str, reply: Reply) -> None:
        self.routes[(method, path)] = reply

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        reply = self.routes.get((request.method, request.url.path))
        if reply is None:
            return httpx2.Response(404, json={"error": {"errors": [{"reason": "notFound"}]}})
        if isinstance(reply, httpx2.Response):
            return reply
        if callable(reply):
            return reply(request)
        return httpx2.Response(200, json=reply)

    def client(self) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.MockTransport(self))

    def api(self) -> GoogleApi:
        return GoogleApi(StaticToken(), self.client())

    def sent(self, method: str, path: str) -> list[httpx2.Request]:
        return [r for r in self.requests if r.method == method and r.url.path == path]


def body_of(request: httpx2.Request) -> Any:
    return json.loads(request.content)


def form_of(request: httpx2.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


def b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def gmail_message(
    message_id: str = "m1",
    *,
    sender: str = "Alice <alice@example.com>",
    subject: str = "Lunch",
    text: str | None = "See you at noon.",
    html: str | None = None,
    labels: tuple[str, ...] = ("INBOX",),
    extra_headers: tuple[tuple[str, str], ...] = (),
    snippet: str = "See you at noon.",
) -> dict[str, Any]:
    headers = [
        {"name": "From", "value": sender},
        {"name": "To", "value": "me@example.com"},
        {"name": "Subject", "value": subject},
        {"name": "Date", "value": "Tue, 24 Nov 2026 09:00:00 +0000"},
        {"name": "Message-ID", "value": f"<{message_id}@mail.example.com>"},
        *({"name": n, "value": v} for n, v in extra_headers),
    ]
    parts = []
    if text is not None:
        parts.append({"mimeType": "text/plain", "body": {"data": b64(text)}})
    if html is not None:
        parts.append({"mimeType": "text/html", "body": {"data": b64(html)}})
    return {
        "id": message_id,
        "threadId": f"t-{message_id}",
        "labelIds": list(labels),
        "snippet": snippet,
        "payload": {"mimeType": "multipart/alternative", "headers": headers, "parts": parts},
    }


def calendar_event(event_id: str = "evt1", **fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": event_id,
        "etag": f'"etag-{event_id}"',
        "summary": "Dentist",
        "start": {"dateTime": "2026-11-25T15:00:00+05:30"},
        "end": {"dateTime": "2026-11-25T16:00:00+05:30"},
        "status": "confirmed",
        "organizer": {"email": "me@example.com", "self": True},
        "creator": {"email": "me@example.com", "self": True},
        "htmlLink": "https://calendar.google.com/event?eid=x",
    }
    return base | fields
