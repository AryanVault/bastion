import pytest

from bastion.security.redact import Redactor
from bastion.security.vault import TELEGRAM_OWNER, MemoryStore, Vault, VaultError
from bastion.telegram.api import Chat, Update
from bastion.telegram.pairing import (
    CODE_ALPHABET,
    CODE_LENGTH,
    Owner,
    PairingError,
    PairingRequest,
    clear_owner,
    display_code,
    load_owner,
    new_code,
    save_owner,
    wait_for_pairing,
)
from support.telegram import OWNER_ID, STRANGER_ID, FakeTelegramApi, message, person

CODE = "ABCD2345"


class Ticker:
    """A clock that advances one second per reading, so pairing deadlines pass quickly."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        self.now += 1.0
        return self.now


def fake(*batches: list[Update]) -> FakeTelegramApi:
    return FakeTelegramApi([], *batches, block_when_idle=False)  # first batch: the backlog


async def pair(api: FakeTelegramApi) -> PairingRequest | None:
    return await wait_for_pairing(api, CODE, clock=Ticker(), timeout_seconds=30)


async def test_the_right_code_from_a_private_chat_pairs() -> None:
    api = fake([message(1, "/pair ABCD-2345")])

    request = await pair(api)

    assert request is not None
    assert request.user.id == OWNER_ID
    assert request.chat.id == OWNER_ID
    assert api.polls[0] == (-1, 0)  # the backlog was skipped first


@pytest.mark.parametrize(
    "text", ["/pair abcd2345", "/pair abcd 2345", "/pair@bastion_test_bot ABCD-2345"]
)
async def test_code_formatting_is_forgiving(text: str) -> None:
    assert await pair(fake([message(1, text)])) is not None


@pytest.mark.security
@pytest.mark.parametrize(
    "update",
    [
        message(1, "/pair ABCD-2345", chat_type="group", chat_id=-100),
        message(1, "/pair ABCD-2345", is_bot=True),
        message(1, "/pair ABCD-2345", forwarded=True),
        message(1, "ABCD-2345"),
        message(1, "/start ABCD-2345"),
    ],
)
async def test_codes_only_count_from_a_person_in_a_private_chat(update: Update) -> None:
    assert await pair(fake([update])) is None


@pytest.mark.security
async def test_too_many_wrong_codes_cancel_pairing() -> None:
    guesses = [message(i, f"/pair WRONG{i:03d}", user_id=STRANGER_ID) for i in range(1, 6)]
    api = fake(guesses, [message(9, "/pair ABCD-2345")])

    with pytest.raises(PairingError, match="too many wrong codes"):
        await pair(api)


async def test_wrong_codes_below_the_limit_still_allow_the_right_one() -> None:
    api = fake([message(1, "/pair NOPE2345", user_id=STRANGER_ID)], [message(2, "/pair ABCD2345")])

    request = await pair(api)

    assert request is not None and request.user.id == OWNER_ID


async def test_the_code_expires() -> None:
    api = fake()

    assert await pair(api) is None
    assert len(api.polls) > 1


def test_new_codes_use_the_unambiguous_alphabet() -> None:
    codes = {new_code() for _ in range(50)}

    assert len(codes) == 50
    assert all(len(c) == CODE_LENGTH and set(c) <= set(CODE_ALPHABET) for c in codes)
    assert display_code("ABCD2345") == "ABCD-2345"


# --------------------------------------------------------------------- owner


@pytest.mark.security
def test_only_the_owner_in_their_private_chat_matches() -> None:
    owner = Owner(OWNER_ID, OWNER_ID)
    private = Chat(OWNER_ID, "private")

    assert owner.matches(person(OWNER_ID), private)
    assert not owner.matches(person(STRANGER_ID), private)
    assert not owner.matches(person(OWNER_ID), Chat(-100, "group"))
    assert not owner.matches(person(OWNER_ID), Chat(OWNER_ID, "group"))
    assert not owner.matches(None, private)


def test_the_owner_round_trips_through_the_keyring() -> None:
    vault = Vault(MemoryStore(), Redactor())

    assert load_owner(vault) is None
    save_owner(vault, Owner(1, 2))
    assert load_owner(vault) == Owner(1, 2)
    clear_owner(vault)
    assert load_owner(vault) is None


@pytest.mark.parametrize("raw", ["garbage", "1:x", "12"])
def test_a_corrupt_owner_record_is_an_error(raw: str) -> None:
    store = MemoryStore()
    store.set(TELEGRAM_OWNER, raw)

    with pytest.raises(VaultError, match="corrupt"):
        load_owner(Vault(store, Redactor()))
