"""Email helpers that never touch the network: address checks, MIME building, body extraction.

Everything here handles attacker-controlled input. Headers and bodies of received mail are
written by whoever sent it, and outgoing fields are proposed by a model that may have read
such mail. So addresses must be bare and ASCII (no display names to disguise the real
recipient), single-line fields must not smuggle extra headers, and parsing has fixed limits.
"""

import base64
import binascii
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from email.message import EmailMessage, Message
from email.policy import SMTP
from email.utils import parseaddr
from typing import Annotated, Any

from pydantic import AfterValidator

MAX_ADDRESS_CHARS = 254
MAX_REFERENCES = 10
MAX_PARTS = 200
MAX_DEPTH = 10
MAX_FILENAME_CHARS = 100

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_ADDRESS = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@" + _LABEL + r"(?:\." + _LABEL + ")+")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_MESSAGE_ID = re.compile(r"<[!-;=?-~]{1,250}>")  # printable ASCII without '<' and '>'
_DOMAIN = re.compile(r"[a-z0-9.-]{1,80}")
_TEXT_TYPES = ("text/plain", "text/html")


def normalize_address(value: str) -> str:
    """A bare ``name@example.com`` address, with the domain lowercased.

    Display names (``"Alice" <evil@example.com>``), lists, and non-ASCII characters are
    refused: an approval prompt must show the one real recipient, which look-alike letters
    from other scripts could disguise.
    """
    if len(value) > MAX_ADDRESS_CHARS or not _ADDRESS.fullmatch(value):
        raise ValueError("must be a plain email address such as name@example.com")
    local, domain = value.rsplit("@", 1)
    if local.startswith(".") or local.endswith(".") or ".." in local:
        raise ValueError("must be a plain email address such as name@example.com")
    return f"{local}@{domain.lower()}"


def single_line(value: str) -> str:
    """Refuse line breaks and other control characters (they would inject email headers)."""
    if _CONTROL.search(value):
        raise ValueError("must be a single line without control characters")
    return value


EmailAddress = Annotated[str, AfterValidator(normalize_address)]
SingleLine = Annotated[str, AfterValidator(single_line)]


@dataclass(frozen=True)
class OutgoingEmail:
    to: tuple[str, ...]
    cc: tuple[str, ...]
    subject: str
    body: str
    in_reply_to: str | None = None
    references: tuple[str, ...] = ()


def message_ids(value: str | None) -> tuple[str, ...]:
    """Well-formed ``<id@host>`` tokens from a Message-ID or References header, newest last.

    These headers come from received mail, so anything malformed is dropped rather than
    copied into a reply's headers.
    """
    if not value:
        return ()
    tokens = value.split()
    if not all(_MESSAGE_ID.fullmatch(token) for token in tokens):
        return ()
    return tuple(tokens[-MAX_REFERENCES:])


def build_raw(email: OutgoingEmail) -> str:
    """The message as base64url-encoded RFC 2822, as the Gmail API expects.

    No ``From`` header: Gmail sets it to the signed-in account, so the model cannot choose it.
    """
    message = EmailMessage(policy=SMTP)
    message["To"] = ", ".join(email.to)
    if email.cc:
        message["Cc"] = ", ".join(email.cc)
    message["Subject"] = email.subject
    if email.in_reply_to:
        message["In-Reply-To"] = email.in_reply_to
    if email.references:
        message["References"] = " ".join(email.references)
    message.set_content(email.body)
    return base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")


# ----------------------------------------------------------------- received mail


@dataclass(frozen=True)
class Attachment:
    filename: str
    mime_type: str
    size: int


@dataclass(frozen=True)
class MessageBody:
    text: str
    is_html: bool
    attachments: tuple[Attachment, ...]


def header(headers: Sequence[Mapping[str, Any]] | None, name: str) -> str:
    """The first header with this name (case-insensitive), or an empty string."""
    wanted = name.lower()
    for item in headers or ():
        if isinstance(item, Mapping) and str(item.get("name", "")).lower() == wanted:
            return str(item.get("value", ""))
    return ""


def sender_domain(from_header: str) -> str:
    """The sender's domain, reduced to safe characters, for labelling where text came from.

    ``From`` is chosen by the sender (and easily forged), so this is a label, never an
    identity, and anything unusual becomes ``unknown``.
    """
    address = parseaddr(from_header)[1]
    domain = address.rpartition("@")[2].lower().rstrip(".")
    return domain if "@" in address and _DOMAIN.fullmatch(domain) else "unknown"


def _decode_data(data: str) -> bytes | None:
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except (binascii.Error, ValueError):
        return None


def _charset(headers: Sequence[Mapping[str, Any]] | None) -> str:
    content_type = header(headers, "Content-Type")
    if not content_type:
        return "utf-8"
    parsed = Message()
    parsed["Content-Type"] = _CONTROL.sub(" ", content_type)
    return parsed.get_content_charset() or "utf-8"


def _decode_text(raw: bytes, charset: str) -> str:
    try:
        return raw.decode(charset, errors="replace")
    except (LookupError, ValueError, TypeError):  # unknown or non-text codec names
        return raw.decode("utf-8", errors="replace")


def _parts(payload: Mapping[str, Any]) -> Iterator[Mapping[str, Any]]:
    """MIME parts in document order, with limits on depth and count.

    A forwarded message (``message/*``) is listed but not entered: its text is not this
    email's body.
    """
    stack: list[tuple[Mapping[str, Any], int]] = [(payload, 0)]
    count = 0
    while stack and count < MAX_PARTS:
        part, depth = stack.pop()
        count += 1
        yield part
        children = part.get("parts")
        forwarded = str(part.get("mimeType", "")).lower().startswith("message/")
        if depth < MAX_DEPTH and isinstance(children, list) and not forwarded:
            stack.extend((c, depth + 1) for c in reversed(children) if isinstance(c, Mapping))


def _attachment(
    part: Mapping[str, Any], mime_type: str, body: Mapping[str, Any], unnamed: str = "(unnamed)"
) -> Attachment:
    filename = _CONTROL.sub("", str(part.get("filename") or ""))[:MAX_FILENAME_CHARS]
    size = body.get("size")
    return Attachment(filename or unnamed, mime_type, size if type(size) is int else 0)


def extract_body(payload: Mapping[str, Any]) -> MessageBody:
    """The readable body of a Gmail ``format=full`` payload, preferring plain text.

    HTML is returned as-is (``is_html``) so that the caller can convert it off the event loop.
    Attachments are only listed: their contents are never downloaded.
    """
    plain: str | None = None
    html: str | None = None
    attachments: list[Attachment] = []
    for part in _parts(payload):
        mime_type = str(part.get("mimeType", "")).lower()
        raw_body = part.get("body")
        body: Mapping[str, Any] = raw_body if isinstance(raw_body, Mapping) else {}
        if part.get("filename") or (body.get("attachmentId") and not mime_type.startswith("text/")):
            attachments.append(_attachment(part, mime_type, body))
            continue
        if mime_type.startswith("message/"):
            attachments.append(_attachment(part, mime_type, body, "(forwarded message)"))
            continue
        data = body.get("data")
        if mime_type not in _TEXT_TYPES:
            continue
        if not isinstance(data, str):
            if body.get("attachmentId"):  # Gmail kept a large text part out of the response
                attachments.append(_attachment(part, mime_type, body, "(text not included)"))
            continue
        raw = _decode_data(data)
        if raw is None:
            continue
        headers = part.get("headers")
        text = _decode_text(raw, _charset(headers if isinstance(headers, list) else None))
        if not text.strip():
            continue
        if mime_type == "text/plain" and plain is None:
            plain = text
        elif mime_type == "text/html" and html is None:
            html = text
    if plain is not None:
        return MessageBody(plain, False, tuple(attachments))
    return MessageBody(html or "", html is not None, tuple(attachments))
