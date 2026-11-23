import pytest

from bastion.security.redact import REDACTED, Redactor


@pytest.mark.parametrize(
    "secret",
    [
        "sk-ant-api03-" + "a" * 40,
        "sk-proj-" + "B" * 40,
        "AIza" + "C" * 35,
        "ya29." + "d" * 40,
        "1//" + "e" * 40,
        "123456789:" + "F" * 35,
        "AKIA" + "G" * 16,
        "ghp_" + "h" * 36,
        "xoxb-1234567890-abcdef",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ],
)
def test_known_token_formats_are_redacted(secret: str) -> None:
    out = Redactor().redact(f"here it is: {secret} ok")

    assert secret not in out
    assert REDACTED in out


def test_bearer_token_keeps_the_scheme_word() -> None:
    out = Redactor().redact("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456")

    assert out == f"Authorization: Bearer {REDACTED}"


def test_key_value_assignment_keeps_the_key_name() -> None:
    out = Redactor().redact('api_key="s3cr3t-value-123"')

    assert "s3cr3t-value-123" not in out
    assert out.startswith("api_key")


def test_private_key_block_is_redacted() -> None:
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----"

    assert Redactor().redact(f"x {pem} y") == f"x {REDACTED} y"


def test_registered_secret_is_redacted_even_without_a_known_format() -> None:
    redactor = Redactor()
    redactor.register_secret("BSAopaqueBraveKey123")

    assert redactor.redact("key BSAopaqueBraveKey123 used") == f"key {REDACTED} used"


def test_short_values_are_not_registered() -> None:
    redactor = Redactor()
    redactor.register_secret("abc")

    assert redactor.redact("abc") == "abc"


def test_redact_obj_recurses_without_mutating_the_input() -> None:
    redactor = Redactor()
    data = {
        "headers": {"auth": "Bearer abcdefghijklmnopqrstuvwxyz123456"},
        "items": ["sk-ant-" + "x" * 30],
        "count": 3,
    }

    out = redactor.redact_obj(data)

    assert data["items"] == ["sk-ant-" + "x" * 30]
    assert REDACTED in out["headers"]["auth"]
    assert out["items"] == [REDACTED]
    assert out["count"] == 3


def test_plain_text_is_unchanged() -> None:
    text = "Meet Alice at 5pm about the budget."

    assert Redactor().redact(text) == text
