"""A thin Google Calendar API client for the owner's primary calendar.

Changes and deletions send the event's ETag in ``If-Match``: if the event changed between
Bastion reading it (to check it is the event the owner approved) and writing it, Google refuses
with HTTP 412 instead of applying the change to something that was not checked.

Only event endpoints are used, because the narrow ``calendar.events`` scopes cover nothing else.
"""

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal
from urllib.parse import quote

from bastion.google.api import GoogleApi, GoogleApiError
from bastion.google.events import Event, When, parse_event

CALENDAR_BASE = "https://www.googleapis.com/calendar/v3/calendars/primary"
MAX_EVENTS = 50

type SendUpdates = Literal["all", "none"]


def as_instant(value: When) -> datetime:
    """A date-time for API queries; a bare date means local midnight on this machine."""
    if isinstance(value, datetime):
        return value
    return datetime(value.year, value.month, value.day).astimezone()


def _mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GoogleApiError("Google Calendar returned an unexpected response")
    return value


class CalendarClient:
    def __init__(self, api: GoogleApi) -> None:
        self._api = api

    def _event_url(self, event_id: str) -> str:
        return f"{CALENDAR_BASE}/events/{quote(event_id, safe='')}"

    async def calendar_name(self) -> str:
        """The primary calendar's name (the account's address), from an events listing.

        ``GET calendars/primary`` would need a broader scope than Bastion asks for.
        """
        params = {"maxResults": 1}
        data = _mapping(await self._api.request("GET", f"{CALENDAR_BASE}/events", params=params))
        value = data.get("summary")
        return value if isinstance(value, str) else ""

    async def list(self, start: When, end: When, query: str | None, limit: int) -> list[Event]:
        params: dict[str, Any] = {
            "timeMin": as_instant(start).isoformat(),
            "timeMax": as_instant(end).isoformat(),
            "singleEvents": "true",
            "orderBy": "startTime",
            "maxResults": min(limit, MAX_EVENTS),
        }
        if query:
            params["q"] = query
        data = _mapping(await self._api.request("GET", f"{CALENDAR_BASE}/events", params=params))
        items = data.get("items")
        if not isinstance(items, list):
            return []
        events = (parse_event(item) for item in items if isinstance(item, Mapping))
        return [e for e in events if e.id and e.status != "cancelled"][:MAX_EVENTS]

    async def get(self, event_id: str) -> Event:
        return parse_event(_mapping(await self._api.request("GET", self._event_url(event_id))))

    async def insert(self, body: Mapping[str, Any], send_updates: SendUpdates) -> Event:
        data = await self._api.request(
            "POST",
            f"{CALENDAR_BASE}/events",
            params={"sendUpdates": send_updates},
            json_body=body,
        )
        return parse_event(_mapping(data))

    async def update(
        self, event: Event, body: Mapping[str, Any], send_updates: SendUpdates
    ) -> Event:
        data = await self._api.request(
            "PUT",
            self._event_url(event.id),
            params={"sendUpdates": send_updates},
            json_body=body,
            headers={"If-Match": event.etag},
        )
        return parse_event(_mapping(data))

    async def delete(self, event: Event, send_updates: SendUpdates) -> None:
        await self._api.request(
            "DELETE",
            self._event_url(event.id),
            params={"sendUpdates": send_updates},
            headers={"If-Match": event.etag},
        )
