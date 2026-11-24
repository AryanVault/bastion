"""The red-team sandbox: a fake mailbox, calendar, web and search engine.

Nothing here touches the real network or the owner's data. Bastion's real tools talk to these
fakes through the same code paths they use in production: Gmail and Calendar through their
REST clients (over an in-process transport), and web pages through the real egress guard,
with only DNS and the network *below* its address checks replaced. Every effect an attack
could have (an email or invitation sent, an event changed or deleted, a web request made) is
recorded as an ``Effect``, which the harness inspects after each scenario.
"""

import base64
import binascii
import email
import email.policy
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import unquote

import httpcore2
import httpx2

from bastion.security.egress import guarded_client
from bastion.tools.web_search import SearchResult

OWNER = "owner@bastion.test"
GMAIL_PATH = "/gmail/v1/users/me"
EVENTS_PATH = "/calendar/v3/calendars/primary/events"
# Every host in the sandbox resolves here unless a scenario says otherwise. It is a public
# address only so that the egress guard accepts it; no connection is ever made to it.
PUBLIC_ADDRESS = "93.184.215.14"
MAX_REQUEST_BYTES = 64_000


class EffectKind(StrEnum):
    EMAIL_SENT = "email.sent"
    DRAFT_SAVED = "draft.saved"
    INVITE_SENT = "invite.sent"
    EVENT_CHANGED = "event.changed"
    EVENT_DELETED = "event.deleted"
    WEB_REQUEST = "web.request"
    MEMORY_TRUSTED = "memory.trusted"
    TASK_CREATED = "task.created"
    PLANNER_INPUT = "planner.input"


@dataclass(frozen=True)
class Effect:
    kind: EffectKind
    text: str


@dataclass(frozen=True)
class Email:
    id: str
    sender: str
    subject: str
    body: str
    snippet: str = ""


@dataclass(frozen=True)
class CalendarEvent:
    id: str
    summary: str
    start: str
    end: str
    organizer: str = OWNER
    description: str = ""
    attendees: tuple[str, ...] = ()


@dataclass(frozen=True)
class Page:
    url: str
    body: str
    content_type: str = "text/html; charset=utf-8"


@dataclass(frozen=True)
class WorldSpec:
    """What a scenario puts in the world before the attack starts."""

    emails: tuple[Email, ...] = ()
    events: tuple[CalendarEvent, ...] = ()
    pages: tuple[Page, ...] = ()
    search_results: tuple[SearchResult, ...] = ()
    trusted_memories: tuple[str, ...] = ()
    untrusted_memories: tuple[str, ...] = ()
    # Host -> address overrides, e.g. a name that resolves to an internal address.
    dns: Mapping[str, str] = field(default_factory=dict)


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def gmail_message(mail: Email) -> dict[str, Any]:
    headers = [
        {"name": "From", "value": mail.sender},
        {"name": "To", "value": OWNER},
        {"name": "Subject", "value": mail.subject},
        {"name": "Date", "value": "Tue, 24 Nov 2026 07:30:00 +0000"},
        {"name": "Message-ID", "value": f"<{mail.id}@mail.example>"},
    ]
    return {
        "id": mail.id,
        "threadId": f"t{mail.id}",
        "labelIds": ["INBOX", "UNREAD"],
        "snippet": mail.snippet or mail.body[:120],
        "payload": {
            "mimeType": "multipart/alternative",
            "headers": headers,
            "parts": [{"mimeType": "text/plain", "body": {"data": _b64(mail.body)}}],
        },
    }


def _person(address: str) -> dict[str, Any]:
    return {"email": address, "self": True} if address == OWNER else {"email": address}


def calendar_event(event: CalendarEvent) -> dict[str, Any]:
    guests = [*event.attendees, OWNER] if event.organizer != OWNER else list(event.attendees)
    return {
        "id": event.id,
        "etag": f'"{event.id}-1"',
        "status": "confirmed",
        "eventType": "default",
        "summary": event.summary,
        "description": event.description,
        "start": {"dateTime": event.start},
        "end": {"dateTime": event.end},
        "organizer": _person(event.organizer),
        "creator": _person(event.organizer),
        "attendees": [_person(guest) for guest in dict.fromkeys(guests)],
        "htmlLink": f"https://calendar.google.com/event?eid={event.id}",
    }


def _decode_raw(raw: Any) -> str:
    """An outgoing message's recipients, subject and body as one line of text per field."""
    if not isinstance(raw, str):
        return ""
    try:
        data = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except (binascii.Error, ValueError):
        return ""
    message = email.message_from_bytes(data, policy=email.policy.default)
    body = message.get_body(preferencelist=("plain",)) if message.is_multipart() else message
    content = body.get_content() if body is not None else ""
    return (
        f"to: {message.get('To', '')}\ncc: {message.get('Cc', '')}\n"
        f"subject: {message.get('Subject', '')}\n{content}"
    )


class World:
    """The sandbox's state for one scenario, and the record of everything done to it."""

    def __init__(self, spec: WorldSpec) -> None:
        self.spec = spec
        self.effects: list[Effect] = []
        self._emails = {mail.id: mail for mail in spec.emails}
        self._events = {event.id: calendar_event(event) for event in spec.events}
        self._pages = {page.url: page for page in spec.pages}
        self._created = 0

    def record(self, kind: EffectKind, text: str) -> None:
        self.effects.append(Effect(kind, text))

    # ------------------------------------------------------------------ search

    async def search(self, query: str, count: int) -> list[SearchResult]:
        return list(self.spec.search_results[:count])

    # ------------------------------------------------------------------- web

    def fetch_client(self) -> httpx2.AsyncClient:
        """The real guarded client, over fake DNS and a fake network."""
        return guarded_client(resolver=self.resolve, network=FakeNetwork(self))

    async def resolve(self, host: str, port: int) -> list[str]:
        return [self.spec.dns.get(host.lower(), PUBLIC_ADDRESS)]

    def serve(self, url: str) -> tuple[int, str, str]:
        """(status, content type, body) for a request that reached the network."""
        self.record(EffectKind.WEB_REQUEST, unquote(url))
        page = self._pages.get(url)
        if page is None:
            return 404, "text/plain", "Not found"
        return 200, page.content_type, page.body

    # ---------------------------------------------------------------- google

    def google(self, request: httpx2.Request) -> httpx2.Response:
        """A minimal Gmail and Calendar REST API (the parts Bastion's clients use)."""
        path = request.url.path
        if path.startswith(GMAIL_PATH):
            return self._gmail(request.method, path.removeprefix(GMAIL_PATH), request)
        if path.startswith(EVENTS_PATH):
            return self._calendar(request.method, path.removeprefix(EVENTS_PATH), request)
        return _not_found()

    def _gmail(self, method: str, path: str, request: httpx2.Request) -> httpx2.Response:
        if method == "GET" and path == "/profile":
            return httpx2.Response(200, json={"emailAddress": OWNER})
        if method == "GET" and path == "/messages":
            listed = [{"id": m.id, "threadId": f"t{m.id}"} for m in self._emails.values()]
            return httpx2.Response(200, json={"messages": listed})
        if method == "GET" and path.startswith("/messages/"):
            mail = self._emails.get(path.removeprefix("/messages/"))
            return _not_found() if mail is None else httpx2.Response(200, json=gmail_message(mail))
        body = _json(request)
        if method == "POST" and path == "/messages/send":
            self.record(EffectKind.EMAIL_SENT, _decode_raw(body.get("raw")))
            return httpx2.Response(200, json={"id": "sent00000001", "threadId": "tsent0001"})
        if method == "POST" and path == "/drafts":
            message = body.get("message")
            raw = message.get("raw") if isinstance(message, Mapping) else None
            self.record(EffectKind.DRAFT_SAVED, _decode_raw(raw))
            return httpx2.Response(200, json={"id": "draft0000001"})
        return _not_found()

    def _calendar(self, method: str, path: str, request: httpx2.Request) -> httpx2.Response:
        if method == "GET" and path == "":
            return httpx2.Response(
                200, json={"summary": OWNER, "items": list(self._events.values())}
            )
        if method == "POST" and path == "":
            self._created += 1
            event_id = f"created{self._created:04d}"
            return self._write_event(event_id, _json(request), request)
        event_id = path.removeprefix("/")
        event = self._events.get(event_id)
        if event is None:
            return _not_found()
        if method == "GET":
            return httpx2.Response(200, json=event)
        if method == "PUT":
            return self._write_event(event_id, _json(request), request)
        if method == "DELETE":
            del self._events[event_id]
            self.record(EffectKind.EVENT_DELETED, f"{event.get('summary', '')} ({event_id})")
            return httpx2.Response(204)
        return _not_found()

    def _write_event(
        self, event_id: str, body: dict[str, Any], request: httpx2.Request
    ) -> httpx2.Response:
        notify = request.url.params.get("sendUpdates", "none") != "none"
        kind = (
            EffectKind.INVITE_SENT if notify and body.get("attendees") else EffectKind.EVENT_CHANGED
        )
        self.record(kind, json.dumps(body, sort_keys=True, ensure_ascii=False))
        stored = body | {
            "id": event_id,
            "etag": f'"{event_id}-2"',
            "status": "confirmed",
            "eventType": "default",
            "organizer": _person(OWNER),
            "creator": _person(OWNER),
        }
        self._events[event_id] = stored
        return httpx2.Response(200, json=stored)


def _json(request: httpx2.Request) -> dict[str, Any]:
    try:
        data = json.loads(request.content or b"{}")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _not_found() -> httpx2.Response:
    return httpx2.Response(404, json={"error": {"errors": [{"reason": "notFound"}]}})


# ----------------------------------------------------------- the fake network


class FakeNetwork(httpcore2.AsyncNetworkBackend):
    """Stands in for TCP below the egress guard: it answers HTTP from the world's pages.

    The guard has already resolved and checked the address by the time a connection gets
    here, so anything recorded here is a request that would really have left the machine.
    """

    def __init__(self, world: World) -> None:
        self._world = world

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        return _FakeStream(self._world, host)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        raise httpcore2.ConnectError("no unix sockets in the sandbox")

    async def sleep(self, seconds: float) -> None:
        return None


class _FakeStream(httpcore2.AsyncNetworkStream):
    def __init__(self, world: World, address: str) -> None:
        self._world = world
        self._address = address
        self._scheme = "http"
        self._request = b""
        self._response: bytes | None = None

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._request += buffer
        if len(self._request) > MAX_REQUEST_BYTES:
            raise httpcore2.WriteError("request too large for the sandbox")

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        if self._response is None:
            self._response = self._answer()
        chunk, self._response = self._response[:max_bytes], self._response[max_bytes:]
        return chunk

    def _answer(self) -> bytes:
        head = self._request.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        lines = head.split("\r\n")
        target = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else "/"
        host = next(
            (
                line.split(":", 1)[1].strip()
                for line in lines[1:]
                if line.lower().startswith("host:")
            ),
            self._address,
        )
        status, content_type, body = self._world.serve(f"{self._scheme}://{host}{target}")
        payload = body.encode("utf-8")
        reason = "OK" if status == 200 else "Not Found"
        return (
            f"HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n"
            f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
        ).encode("latin-1") + payload

    async def aclose(self) -> None:
        return None

    async def start_tls(
        self,
        ssl_context: Any,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        self._scheme = "https"
        return self

    def get_extra_info(self, info: str) -> Any:
        return None
