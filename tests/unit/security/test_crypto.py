import pytest

from bastion.security.crypto import DecryptionError, FieldCipher, generate_key


@pytest.fixture
def cipher() -> FieldCipher:
    return FieldCipher(generate_key())


def test_round_trip(cipher: FieldCipher) -> None:
    token = cipher.encrypt("remember: dentist on Friday", context="memory:1")

    assert cipher.decrypt(token, context="memory:1") == "remember: dentist on Friday"


def test_token_is_versioned_and_not_plaintext(cipher: FieldCipher) -> None:
    token = cipher.encrypt("secret note", context="memory:1")

    assert token.startswith("v1:")
    assert "secret note" not in token


def test_same_plaintext_encrypts_differently_each_time(cipher: FieldCipher) -> None:
    assert cipher.encrypt("x", context="c") != cipher.encrypt("x", context="c")


def test_ciphertext_is_bound_to_its_context(cipher: FieldCipher) -> None:
    token = cipher.encrypt("hello", context="memory:1")

    with pytest.raises(DecryptionError):
        cipher.decrypt(token, context="memory:2")


def test_wrong_key_fails(cipher: FieldCipher) -> None:
    token = cipher.encrypt("hello", context="c")

    with pytest.raises(DecryptionError):
        FieldCipher(generate_key()).decrypt(token, context="c")


def test_tampered_ciphertext_fails(cipher: FieldCipher) -> None:
    token = cipher.encrypt("hello", context="c")
    flipped = token[:-2] + ("A" if token[-2] != "A" else "B") + token[-1]

    with pytest.raises(DecryptionError):
        cipher.decrypt(flipped, context="c")


@pytest.mark.parametrize("token", ["v1:!!!not-base64!!!", "nope", "v2:AAAA", "v1:AAAA"])
def test_malformed_tokens_raise_decryption_error(cipher: FieldCipher, token: str) -> None:
    with pytest.raises(DecryptionError):
        cipher.decrypt(token, context="c")


def test_rejects_keys_of_the_wrong_length() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        FieldCipher(b"too-short")
