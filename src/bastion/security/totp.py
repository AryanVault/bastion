"""Authenticator-app codes for step-up approvals (control C5; RFC 6238 TOTP).

A hijacked Telegram account can tap "Approve", but it cannot produce the six-digit code from
the owner's authenticator app. Each code is accepted at most once: a code seen over the
owner's shoulder, or replayed from a captured message, is useless after its first use.
"""

import base64
import binascii
import hmac
import re
from collections.abc import Callable
from datetime import datetime

import pyotp

from bastion.common import utc_now

ISSUER = "Bastion"
SECRET_CHARS = 32  # base32 characters: 160 bits, the RFC 4226 recommendation
MIN_SECRET_BYTES = 16
_CODE = re.compile(r"^[0-9]{6}$")  # ASCII only: digits from other scripts are refused
_WHITESPACE = re.compile(r"\s+")


class TotpError(Exception):
    """The stored TOTP secret is malformed."""


def new_secret() -> str:
    return pyotp.random_base32(length=SECRET_CHARS)


def provisioning_uri(secret: str, account: str = "owner") -> str:
    """The ``otpauth://`` URI that authenticator apps import (as text or a QR code)."""
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=ISSUER)


def looks_like_code(text: str) -> bool:
    return bool(_CODE.match(_WHITESPACE.sub("", text)))


class TotpVerifier:
    def __init__(
        self, secret: str, *, clock: Callable[[], datetime] = utc_now, window: int = 1
    ) -> None:
        try:
            raw = base64.b32decode(secret, casefold=True)
        except (binascii.Error, ValueError) as exc:
            raise TotpError("the stored TOTP secret is not valid base32") from exc
        if len(raw) < MIN_SECRET_BYTES:
            raise TotpError("the stored TOTP secret is too short")
        self._totp = pyotp.TOTP(secret)
        self._clock = clock
        self._window = window
        # Highest time step already used: codes at or before it are refused (no replay).
        self._last_step = -1

    def verify(self, code: str) -> bool:
        candidate = _WHITESPACE.sub("", code)
        if not _CODE.match(candidate):
            return False
        current = self._totp.timecode(self._clock())
        # Tolerate one step of clock drift either way, but never accept a step twice.
        for step in range(current - self._window, current + self._window + 1):
            if step <= self._last_step:
                continue
            if hmac.compare_digest(self._totp.generate_otp(step), candidate):
                self._last_step = step
                return True
        return False
