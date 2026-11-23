from datetime import UTC, datetime, timedelta

import pyotp
import pytest

from bastion.security.totp import (
    ISSUER,
    TotpError,
    TotpVerifier,
    looks_like_code,
    new_secret,
    provisioning_uri,
)

SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
NOW = datetime(2026, 11, 23, 12, 0, 15, tzinfo=UTC)


class Clock:
    def __init__(self, now: datetime = NOW) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def code_at(when: datetime) -> str:
    return pyotp.TOTP(SECRET).at(when)


def test_the_current_code_is_accepted() -> None:
    assert TotpVerifier(SECRET, clock=Clock()).verify(code_at(NOW))


def test_spaces_in_the_code_are_ignored() -> None:
    code = code_at(NOW)

    assert TotpVerifier(SECRET, clock=Clock()).verify(f" {code[:3]} {code[3:]} ")


@pytest.mark.security
def test_a_wrong_code_is_rejected() -> None:
    code = code_at(NOW)
    wrong = f"{(int(code) + 1) % 1_000_000:06d}"

    assert not TotpVerifier(SECRET, clock=Clock()).verify(wrong)


@pytest.mark.security
def test_a_code_cannot_be_replayed() -> None:
    verifier = TotpVerifier(SECRET, clock=Clock())
    code = code_at(NOW)

    assert verifier.verify(code)
    assert not verifier.verify(code)


@pytest.mark.security
def test_an_older_code_is_refused_after_a_newer_one_was_used() -> None:
    verifier = TotpVerifier(SECRET, clock=Clock())

    assert verifier.verify(code_at(NOW))
    assert not verifier.verify(code_at(NOW - timedelta(seconds=30)))


def test_one_step_of_clock_drift_is_tolerated() -> None:
    assert TotpVerifier(SECRET, clock=Clock()).verify(code_at(NOW - timedelta(seconds=30)))
    assert TotpVerifier(SECRET, clock=Clock()).verify(code_at(NOW + timedelta(seconds=30)))


@pytest.mark.security
def test_codes_outside_the_window_are_rejected() -> None:
    assert not TotpVerifier(SECRET, clock=Clock()).verify(code_at(NOW - timedelta(minutes=5)))


@pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", "12 34 5a"])
def test_malformed_codes_are_rejected(code: str) -> None:
    assert not TotpVerifier(SECRET, clock=Clock()).verify(code)


@pytest.mark.parametrize("secret", ["not base32!", "JBSWY3DP"])
def test_bad_secrets_are_refused(secret: str) -> None:
    with pytest.raises(TotpError):
        TotpVerifier(secret)


def test_new_secrets_are_strong_and_unique() -> None:
    first, second = new_secret(), new_secret()

    assert len(first) == 32 and first != second
    TotpVerifier(first)  # valid


def test_the_provisioning_uri_names_the_issuer() -> None:
    uri = provisioning_uri(SECRET)

    assert uri.startswith("otpauth://totp/")
    assert f"issuer={ISSUER}" in uri
    assert SECRET in uri


@pytest.mark.parametrize(
    ("text", "expected"), [("123456", True), ("123 456", True), ("12345", False), ("hello", False)]
)
def test_looks_like_code(text: str, expected: bool) -> None:
    assert looks_like_code(text) is expected


@pytest.mark.security
def test_digits_from_other_scripts_are_refused_not_crashing() -> None:
    arabic_indic = "".join(chr(0x0660 + int(d)) for d in code_at(NOW))  # the same code

    assert not looks_like_code(arabic_indic)
    assert not TotpVerifier(SECRET, clock=Clock()).verify(arabic_indic)
