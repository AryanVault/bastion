import base64
import email
from email.policy import default
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from bastion.google.mail import (
    MAX_DEPTH,
    MAX_PARTS,
    Attachment,
    EmailAddress,
    OutgoingEmail,
    SingleLine,
    build_raw,
    extract_body,
    header,
    message_ids,
    normalize_address,
    sender_domain,
)

CRLF = chr(13) + chr(10)


def b64(text: str, encoding: str = "utf-8") -> str:
    return base64.urlsafe_b64encode(text.encode(encoding)).decode("ascii").rstrip("=")


def part(
    mime: str,
    text: str | None = None,
    *,
    filename: str = "",
    headers: list[dict[str, str]] | None = None,
    parts: list[dict[str, Any]] | None = None,
    attachment_id: str | None = None,
    size: int = 0,
    encoding: str = "utf-8",
) -> dict[str, Any]:
    body: dict[str, Any] = {"size": size}
    if text is not None:
        body["data"] = b64(text, encoding)
    if attachment_id is not None:
        body["attachmentId"] = attachment_id
    return {
        "mimeType": mime,
        "filename": filename,
        "headers": headers or [],
        "body": body,
        "parts": parts or [],
    }


def decode_raw(raw: str) -> email.message.EmailMessage:
    data = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    message = email.message_from_bytes(data, policy=default)
    assert isinstance(message, email.message.EmailMessage)
    return message


# ------------------------------------------------------------------ addresses


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("alice@example.com", "alice@example.com"),
        ("Alice.Smith+tag@Example.COM", "Alice.Smith+tag@example.com"),
        ("o'brien@mail.example.co.uk", "o'brien@mail.example.co.uk"),
    ],
)
def test_plain_addresses_are_accepted_with_lowercased_domain(raw: str, expected: str) -> None:
    assert normalize_address(raw) == expected


@pytest.mark.security
@pytest.mark.parametrize(
    "raw",
    [
        '"Alice" <attacker@evil.example>',  # a display name could disguise the real recipient
        "alice@example.com, bob@example.com",  # a list smuggled into one field
        "alice@example.com" + CRLF + "Bcc: attacker@evil.example",  # header injection
        "alice@example.com" + chr(10),
        chr(0x0430) + "lice@example.com",  # Cyrillic look-alike letter
        "alice@ex" + chr(0x200B) + "ample.com",  # zero-width space
        "alice@localhost",
        "alice@-example.com",
        "alice..smith@example.com",
        ".alice@example.com",
        "alice@",
        "@example.com",
        "a" * 65 + "@example.com",
        "alice@" + "a" * 250 + ".com",
    ],
)
def test_disguised_or_malformed_addresses_are_refused(raw: str) -> None:
    with pytest.raises(ValueError, match="plain email address"):
        normalize_address(raw)


class _Fields(BaseModel):
    to: EmailAddress
    subject: SingleLine


@pytest.mark.security
@pytest.mark.parametrize("bad", [CRLF + "Bcc: x@evil.example", chr(13), chr(0), chr(0x85)])
def test_single_line_fields_refuse_line_breaks_and_controls(bad: str) -> None:
    with pytest.raises(ValidationError, match="single line"):
        _Fields(to="a@example.com", subject=f"Hello{bad}")


def test_annotated_fields_validate_inside_models() -> None:
    fields = _Fields(to="Bob@Example.org", subject="Lunch?")

    assert fields.to == "Bob@example.org"


# ---------------------------------------------------------------- building MIME


def test_build_raw_produces_plain_text_without_a_from_header() -> None:
    raw = build_raw(
        OutgoingEmail(
            to=("alice@example.com", "bob@example.org"),
            cc=("carol@example.net",),
            subject="Café plans",
            body="See you at 7.\nBring the tickets.",
        )
    )

    message = decode_raw(raw)
    assert message["To"] == "alice@example.com, bob@example.org"
    assert message["Cc"] == "carol@example.net"
    assert message["Subject"] == "Café plans"
    assert message["From"] is None  # Gmail fills in the signed-in account
    assert message.get_content_type() == "text/plain"
    assert message.get_content().replace(CRLF, "\n") == "See you at 7.\nBring the tickets.\n"
    assert "=" not in raw.rstrip("=")  # base64url, as the Gmail API expects


def test_build_raw_sets_threading_headers_for_replies() -> None:
    raw = build_raw(
        OutgoingEmail(
            to=("alice@example.com",),
            cc=(),
            subject="Re: Plans",
            body="Yes!",
            in_reply_to="<m2@mail.example.com>",
            references=("<m1@mail.example.com>", "<m2@mail.example.com>"),
        )
    )

    message = decode_raw(raw)
    assert message["In-Reply-To"] == "<m2@mail.example.com>"
    assert message["References"] == "<m1@mail.example.com> <m2@mail.example.com>"
    assert message["Cc"] is None


def test_message_ids_keep_well_formed_ids_newest_last() -> None:
    ids = " ".join(f"<m{i}@example.com>" for i in range(15))

    kept = message_ids(ids)

    assert len(kept) == 10
    assert kept[-1] == "<m14@example.com>"
    assert message_ids(None) == ()
    assert message_ids("") == ()


@pytest.mark.security
@pytest.mark.parametrize(
    "value",
    [
        "<a@example.com>" + CRLF + "Bcc: attacker@evil.example",
        "<a@example.com> not-an-id",
        "<a<b@example.com>",
        "<" + "a" * 300 + ">",
    ],
)
def test_malformed_message_ids_from_received_mail_are_dropped(value: str) -> None:
    assert message_ids(value) == ()


# -------------------------------------------------------------- received mail


def test_header_lookup_is_case_insensitive() -> None:
    headers = [{"name": "Subject", "value": "Hi"}, {"name": "FROM", "value": "a@example.com"}]

    assert header(headers, "from") == "a@example.com"
    assert header(headers, "Date") == ""
    assert header(None, "From") == ""


@pytest.mark.parametrize(
    ("value", "domain"),
    [
        ("Alice <alice@Mail.Example.com>", "mail.example.com"),
        ("bob@example.org", "example.org"),
        ("no address here", "unknown"),
        ('"x" <a@exa_mple.com>', "unknown"),
        ("a@" + "b" * 90 + ".com", "unknown"),
    ],
)
def test_sender_domain_is_a_sanitised_label(value: str, domain: str) -> None:
    assert sender_domain(value) == domain


def test_plain_text_is_preferred_over_html() -> None:
    payload = part(
        "multipart/alternative",
        parts=[part("text/plain", "Plain body"), part("text/html", "<p>HTML body</p>")],
    )

    body = extract_body(payload)

    assert body.text == "Plain body"
    assert not body.is_html


def test_html_is_returned_unconverted_when_there_is_no_plain_part() -> None:
    body = extract_body(part("text/html", "<p>Only HTML</p>"))

    assert body.text == "<p>Only HTML</p>"
    assert body.is_html


def test_nested_multipart_bodies_and_attachments_are_found() -> None:
    payload = part(
        "multipart/mixed",
        parts=[
            part(
                "multipart/alternative",
                parts=[part("text/plain", "Report attached."), part("text/html", "<p>x</p>")],
            ),
            part("application/pdf", filename="report.pdf", attachment_id="att1", size=1234),
            part("image/png", attachment_id="att2", size=99),
            part("text/plain", "attached notes", filename="notes.txt", size=14),
        ],
    )

    body = extract_body(payload)

    assert body.text == "Report attached."
    assert body.attachments == (
        Attachment("report.pdf", "application/pdf", 1234),
        Attachment("(unnamed)", "image/png", 99),
        Attachment("notes.txt", "text/plain", 14),
    )


def test_charsets_from_part_headers_are_honoured() -> None:
    latin = part(
        "text/plain",
        "Café",
        encoding="latin-1",
        headers=[{"name": "Content-Type", "value": 'text/plain; charset="ISO-8859-1"'}],
    )

    assert extract_body(latin).text == "Café"


@pytest.mark.parametrize("charset", ["no-such-charset", "base64_codec", "rot13"])
def test_unknown_or_non_text_charsets_fall_back_to_utf8(charset: str) -> None:
    payload = part(
        "text/plain",
        "naïve",
        headers=[{"name": "Content-Type", "value": f"text/plain; charset={charset}"}],
    )

    assert extract_body(payload).text == "naïve"


def test_undecodable_data_is_skipped() -> None:
    payload = part(
        "multipart/alternative", parts=[part("text/plain"), part("text/html", "<b>ok</b>")]
    )
    payload["parts"][0]["body"]["data"] = "!!!not base64!!!"

    body = extract_body(payload)

    assert body.text == "<b>ok</b>"


def test_empty_payload_gives_an_empty_body() -> None:
    body = extract_body({})

    assert body.text == ""
    assert not body.is_html
    assert body.attachments == ()


@pytest.mark.security
def test_deeply_nested_parts_stop_at_the_depth_limit() -> None:
    payload = part("text/plain", "buried")
    for _ in range(MAX_DEPTH + 5):
        payload = part("multipart/mixed", parts=[payload])

    assert extract_body(payload).text == ""


@pytest.mark.security
def test_part_count_is_limited() -> None:
    payload = part(
        "multipart/mixed",
        parts=[part("application/octet-stream", filename=f"f{i}") for i in range(MAX_PARTS * 2)],
    )

    assert len(extract_body(payload).attachments) == MAX_PARTS - 1


@pytest.mark.security
def test_attachment_names_lose_control_characters_and_are_capped() -> None:
    payload = part("application/pdf", filename="evil" + chr(27) + "[2J" + "x" * 200 + ".pdf")

    name = extract_body(payload).attachments[0].filename

    assert chr(27) not in name
    assert len(name) == 100


def test_malformed_structures_are_tolerated() -> None:
    payload = {"mimeType": "multipart/mixed", "parts": ["junk", {"mimeType": "text/plain"}, 5]}

    assert extract_body(payload).text == ""


def test_a_forwarded_message_is_listed_not_read_as_the_body() -> None:
    forwarded = part("message/rfc822", parts=[part("text/plain", "the attacker's old email")])
    payload = part("multipart/mixed", parts=[part("text/html", "<p>Real body</p>"), forwarded])

    body = extract_body(payload)

    assert body.text == "<p>Real body</p>"
    assert body.attachments == (Attachment("(forwarded message)", "message/rfc822", 0),)


def test_an_empty_plain_part_does_not_hide_the_html() -> None:
    payload = part(
        "multipart/alternative", parts=[part("text/plain", ""), part("text/html", "<b>x</b>")]
    )

    assert extract_body(payload).text == "<b>x</b>"


def test_text_that_gmail_did_not_include_is_noted() -> None:
    payload = part("text/plain", attachment_id="big1", size=5_000_000)

    body = extract_body(payload)

    assert body.text == ""
    assert body.attachments == (Attachment("(text not included)", "text/plain", 5_000_000),)
