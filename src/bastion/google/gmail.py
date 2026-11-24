"""A thin Gmail API client: search, read, draft, send. Attachments are never downloaded."""

import asyncio
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Annotated, Any
from urllib.parse import quote

from pydantic import AfterValidator

from bastion.google.api import GoogleApi, GoogleApiError
from bastion.google.mail import (
    MessageBody,
    OutgoingEmail,
    build_raw,
    extract_body,
    header,
    message_ids,
)

GMAIL_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
MAX_SEARCH_RESULTS = 20
FETCH_CONCURRENCY = 5
_SUMMARY_HEADERS = ("From", "Subject", "Date")
_REPLY_HEADERS = ("Message-ID", "References", "Subject")
_ID = re.compile(r"[A-Za-z0-9_-]{6,64}")


def _message_id(value: str) -> str:
    if not _ID.fullmatch(value):
        raise ValueError("not a Gmail message id")
    return value


MessageId = Annotated[str, AfterValidator(_message_id)]


@dataclass(frozen=True)
class MessageSummary:
    id: str
    thread_id: str
    sender: str
    subject: str
    date: str
    snippet: str
    unread: bool


@dataclass(frozen=True)
class ReceivedEmail:
    id: str
    thread_id: str
    sender: str
    to: str
    cc: str
    subject: str
    date: str
    body: MessageBody


@dataclass(frozen=True)
class ReplyContext:
    thread_id: str
    in_reply_to: str | None
    references: tuple[str, ...]


def _headers(message: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    payload = message.get("payload")
    headers = payload.get("headers") if isinstance(payload, Mapping) else None
    return headers if isinstance(headers, list) else []


def _str(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    return value if isinstance(value, str) else ""


def _mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GoogleApiError("Gmail returned an unexpected response")
    return value


class GmailClient:
    def __init__(self, api: GoogleApi) -> None:
        self._api = api

    def _message_url(self, message_id: str) -> str:
        return f"{GMAIL_BASE}/messages/{quote(message_id, safe='')}"

    async def profile_email(self) -> str:
        data = _mapping(await self._api.request("GET", f"{GMAIL_BASE}/profile"))
        return _str(data, "emailAddress")

    async def search(self, query: str, limit: int) -> list[MessageSummary]:
        params = {"q": query, "maxResults": min(limit, MAX_SEARCH_RESULTS)}
        data = _mapping(await self._api.request("GET", f"{GMAIL_BASE}/messages", params=params))
        found = data.get("messages")
        ids = [
            _str(item, "id")
            for item in (found if isinstance(found, list) else [])
            if isinstance(item, Mapping) and _ID.fullmatch(_str(item, "id"))
        ][:MAX_SEARCH_RESULTS]
        gate = asyncio.Semaphore(FETCH_CONCURRENCY)

        async def fetch(message_id: str) -> MessageSummary | GoogleApiError:
            async with gate:
                try:
                    return await self._summary(message_id)
                except GoogleApiError as exc:  # e.g. deleted since it was listed
                    return exc

        async with asyncio.TaskGroup() as group:  # a crash cancels the other fetches
            tasks = [group.create_task(fetch(i)) for i in ids]
        results = [task.result() for task in tasks]
        found_summaries = [r for r in results if isinstance(r, MessageSummary)]
        failures = [r for r in results if isinstance(r, GoogleApiError)]
        if failures and not found_summaries:
            raise failures[0]
        return found_summaries

    async def _metadata(self, message_id: str, headers: tuple[str, ...]) -> Mapping[str, Any]:
        params = {"format": "metadata", "metadataHeaders": list(headers)}
        return _mapping(
            await self._api.request("GET", self._message_url(message_id), params=params)
        )

    async def _summary(self, message_id: str) -> MessageSummary:
        message = await self._metadata(message_id, _SUMMARY_HEADERS)
        headers = _headers(message)
        labels = message.get("labelIds")
        return MessageSummary(
            id=message_id,
            thread_id=_str(message, "threadId"),
            sender=header(headers, "From"),
            subject=header(headers, "Subject"),
            date=header(headers, "Date"),
            snippet=_str(message, "snippet"),
            unread=isinstance(labels, list) and "UNREAD" in labels,
        )

    async def read(self, message_id: str) -> ReceivedEmail:
        message = _mapping(
            await self._api.request("GET", self._message_url(message_id), params={"format": "full"})
        )
        payload = message.get("payload")
        headers = _headers(message)
        return ReceivedEmail(
            id=message_id,
            thread_id=_str(message, "threadId"),
            sender=header(headers, "From"),
            to=header(headers, "To"),
            cc=header(headers, "Cc"),
            subject=header(headers, "Subject"),
            date=header(headers, "Date"),
            body=extract_body(payload if isinstance(payload, Mapping) else {}),
        )

    async def reply_context(self, message_id: str) -> ReplyContext:
        """Threading details for a reply. Malformed ids from the original are dropped."""
        message = await self._metadata(message_id, _REPLY_HEADERS)
        headers = _headers(message)
        own = message_ids(header(headers, "Message-ID"))
        parent = own[0] if len(own) == 1 else None
        references = message_ids(header(headers, "References"))
        chain = (*references, parent) if parent else references
        return ReplyContext(_str(message, "threadId"), parent, tuple(chain[-10:]))

    async def create_draft(self, email: OutgoingEmail, thread_id: str | None = None) -> str:
        message: dict[str, Any] = {"raw": build_raw(email)}
        if thread_id:
            message["threadId"] = thread_id
        data = _mapping(
            await self._api.request("POST", f"{GMAIL_BASE}/drafts", json_body={"message": message})
        )
        return _str(data, "id")

    async def send(self, email: OutgoingEmail, thread_id: str | None = None) -> str:
        message: dict[str, Any] = {"raw": build_raw(email)}
        if thread_id:
            message["threadId"] = thread_id
        data = _mapping(
            await self._api.request("POST", f"{GMAIL_BASE}/messages/send", json_body=message)
        )
        return _str(data, "id")
