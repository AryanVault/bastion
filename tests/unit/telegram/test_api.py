import json
import logging
from collections.abc import Callable
from typing import Any

import httpx2
import pytest

from bastion.telegram.api import (
    ALLOWED_UPDATES,
    BotApi,
    TelegramError,
    parse_update,
    skip_backlog,
    utf16_len,
    valid_token,
)

TOKEN = "123456789:" + "A" * 35  # gitleaks:allow (dummy test token)

type Handler = Callable[[httpx2.Request], httpx2.Response]


class Recorder:
    def __init__(self, *responses: Any) -> None:
        self.responses = list(responses)
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        body = self.responses.pop(0)
        if isinstance(body, httpx2.Response):
            return body
        return httpx2.Response(200, json=body)

    def payload(self, index: int = -1) -> dict[str, Any]:
        return json.loads(self.requests[index].content)

    def method(self, index: int = -1) -> str:
        return self.requests[index].url.path.rsplit("/", 1)[-1]


def api_with(handler: Handler) -> BotApi:
    client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
    return BotApi(TOKEN, client=client)


def ok(result: Any) -> dict[str, Any]:
    return {"ok": True, "result": result}


MESSAGE = {
    "update_id": 7,
    "message": {
        "message_id": 70,
        "date": 1_700_000_000,
        "chat": {"id": 4242, "type": "private"},
        "from": {"id": 4242, "is_bot": False, "first_name": "Ada", "username": "ada"},
        "text": "hello",
    },
}


# ------------------------------------------------------------------- parsing


def test_a_text_message_is_parsed() -> None:
    update = parse_update(MESSAGE)

    assert update is not None and update.message is not None
    assert update.message.text == "hello"
    assert update.message.sender is not None and update.message.sender.id == 4242
    assert update.message.chat.type == "private"
    assert update.message.forwarded is False


@pytest.mark.security
@pytest.mark.parametrize(
    "marker",
    [
        {"forward_origin": {"type": "user", "date": 1}},
        {"via_bot": {"id": 9, "is_bot": True, "first_name": "Other"}},
        {"is_automatic_forward": True},
    ],
)
def test_forwarded_and_bot_made_messages_are_flagged(marker: dict[str, Any]) -> None:
    raw = {"update_id": 1, "message": {**MESSAGE["message"], **marker}}

    update = parse_update(raw)

    assert update is not None and update.message is not None
    assert update.message.forwarded is True


def test_a_callback_query_is_parsed() -> None:
    raw = {
        "update_id": 8,
        "callback_query": {
            "id": "q1",
            "from": {"id": 4242, "is_bot": False, "first_name": "Ada"},
            "data": "ap:tok:y",
            "message": {"message_id": 55, "chat": {"id": 4242, "type": "private"}},
        },
    }

    update = parse_update(raw)

    assert update is not None and update.callback is not None
    assert update.callback.data == "ap:tok:y"
    assert (update.callback.chat_id, update.callback.message_id) == (4242, 55)


@pytest.mark.security
@pytest.mark.parametrize(
    "message",
    [
        {"message_id": "70", "date": 1, "chat": {"id": 1, "type": "private"}},
        {"message_id": 70, "date": 1, "chat": {"id": True, "type": "private"}},
        {"message_id": 70, "date": 1},
    ],
)
def test_malformed_messages_are_dropped_but_the_update_is_kept(message: dict[str, Any]) -> None:
    update = parse_update({"update_id": 3, "message": message})

    assert update is not None
    assert update.message is None  # nothing to act on, but the offset still advances


def test_updates_without_an_id_are_skipped() -> None:
    assert parse_update({"message": MESSAGE["message"]}) is None
    assert parse_update(["not", "a", "dict"]) is None


def test_a_sender_with_a_non_integer_id_is_ignored() -> None:
    raw = {"update_id": 1, "message": {**MESSAGE["message"], "from": {"id": "4242"}}}

    update = parse_update(raw)

    assert update is not None and update.message is not None
    assert update.message.sender is None


# -------------------------------------------------------------------- client


async def test_get_updates_long_polls_for_messages_and_button_taps_only() -> None:
    recorder = Recorder(ok([MESSAGE, {"no": "id"}]))

    updates = await api_with(recorder).get_updates(5, 50)

    assert [u.update_id for u in updates] == [7]
    assert recorder.method() == "getUpdates"
    assert recorder.payload() == {
        "offset": 5,
        "timeout": 50,
        "allowed_updates": list(ALLOWED_UPDATES),
    }


async def test_long_poll_wait_is_capped() -> None:
    recorder = Recorder(ok([]))

    await api_with(recorder).get_updates(None, 10_000)

    assert recorder.payload()["timeout"] == 50
    assert "offset" not in recorder.payload()


@pytest.mark.security
async def test_messages_are_plain_text_without_link_previews() -> None:
    recorder = Recorder(ok({"message_id": 99}))

    message_id = await api_with(recorder).send_message(
        4242, "see https://example.com", buttons=[("Approve", "ap:t:y")]
    )

    payload = recorder.payload()
    assert message_id == 99
    assert "parse_mode" not in payload
    assert payload["link_preview_options"] == {"is_disabled": True}
    assert payload["reply_markup"] == {
        "inline_keyboard": [[{"text": "Approve", "callback_data": "ap:t:y"}]]
    }


async def test_edits_and_callback_answers() -> None:
    recorder = Recorder(ok(True), ok(True), ok(True), ok(True), ok({"id": 1}))
    api = api_with(recorder)

    await api.edit_message(1, 2, "done")
    await api.answer_callback("q1", "x" * 500)
    await api.send_typing(1)
    await api.set_commands([("new", "New conversation")])

    assert recorder.method(0) == "editMessageText"
    assert "reply_markup" not in recorder.payload(0)  # editing removes the buttons
    assert len(recorder.payload(1)["text"]) == 200
    assert recorder.payload(2) == {"chat_id": 1, "action": "typing"}
    assert recorder.payload(3) == {
        "commands": [{"command": "new", "description": "New conversation"}]
    }


async def test_get_me_returns_the_bot_user() -> None:
    recorder = Recorder(ok({"id": 1, "is_bot": True, "first_name": "B", "username": "b_bot"}))

    me = await api_with(recorder).get_me()

    assert me.is_bot and me.username == "b_bot"


async def test_api_errors_carry_status_and_retry_after() -> None:
    recorder = Recorder(
        httpx2.Response(
            429,
            json={
                "ok": False,
                "error_code": 429,
                "description": "Too Many Requests: retry after 7",
                "parameters": {"retry_after": 7},
            },
        )
    )

    with pytest.raises(TelegramError) as caught:
        await api_with(recorder).send_message(1, "hi")

    assert caught.value.status == 429
    assert caught.value.retry_after == 7.0
    assert not caught.value.unauthorized and not caught.value.conflict


@pytest.mark.parametrize(
    ("status", "unauthorized", "conflict"), [(401, True, False), (409, False, True)]
)
async def test_error_kinds(status: int, unauthorized: bool, conflict: bool) -> None:
    body = {"ok": False, "error_code": status, "description": "nope"}
    recorder = Recorder(httpx2.Response(status, json=body))

    with pytest.raises(TelegramError) as caught:
        await api_with(recorder).get_updates(None, 0)

    assert caught.value.unauthorized is unauthorized
    assert caught.value.conflict is conflict


async def test_a_non_json_response_is_an_error() -> None:
    recorder = Recorder(httpx2.Response(502, text="<html>Bad gateway</html>"))

    with pytest.raises(TelegramError, match="HTTP 502"):
        await api_with(recorder).get_me()


@pytest.mark.parametrize("result", [None, {"id": "x"}, [1]])
async def test_unexpected_results_are_errors(result: Any) -> None:
    recorder = Recorder(ok(result), ok(result))
    api = api_with(recorder)

    with pytest.raises(TelegramError):
        await api.send_message(1, "hi")
    with pytest.raises(TelegramError):
        await api.get_me()


@pytest.mark.security
async def test_network_errors_never_reveal_the_token() -> None:
    def refuse(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError(f"cannot connect to {request.url}", request=request)

    with pytest.raises(TelegramError) as caught:
        await api_with(refuse).get_me()

    assert TOKEN not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__suppress_context__


@pytest.mark.security
def test_request_logging_that_would_print_the_token_is_silenced() -> None:
    logging.getLogger("httpx2").setLevel(logging.NOTSET)

    BotApi(TOKEN)

    assert logging.getLogger("httpx2").level >= logging.WARNING
    assert logging.getLogger("httpcore2").level >= logging.WARNING


@pytest.mark.security
def test_the_token_is_not_in_the_repr() -> None:
    assert TOKEN not in repr(BotApi(TOKEN))


@pytest.mark.parametrize("token", ["", "abc", "123:short", "12345678:" + "A" * 35 + " x"])
def test_malformed_tokens_are_rejected(token: str) -> None:
    assert not valid_token(token)
    with pytest.raises(ValueError, match="bot token"):
        BotApi(token)


async def test_oversized_or_empty_messages_and_callback_data_are_refused() -> None:
    api = api_with(Recorder())

    with pytest.raises(ValueError, match="too long"):
        await api.send_message(1, "x" * 4097)
    with pytest.raises(ValueError, match="empty"):
        await api.send_message(1, "  ")
    with pytest.raises(ValueError, match="1-64 bytes"):
        await api.send_message(1, "hi", buttons=[("A", "x" * 65)])


def test_utf16_length_counts_astral_characters_twice() -> None:
    assert utf16_len("ab") == 2
    assert utf16_len("a\U0001f600") == 3


async def test_skip_backlog_forgets_queued_updates() -> None:
    recorder = Recorder(ok([MESSAGE]), ok([]))
    api = api_with(recorder)

    assert await skip_backlog(api) == 8
    assert recorder.payload(0)["offset"] == -1
    assert await skip_backlog(api) is None


async def test_aclose_closes_the_client() -> None:
    client = httpx2.AsyncClient(transport=httpx2.MockTransport(Recorder()))
    api = BotApi(TOKEN, client=client)

    await api.aclose()

    assert client.is_closed
