"""A token-bucket rate limiter, for requests arriving over always-on channels."""

import time
from collections.abc import Callable

_SECONDS_PER_HOUR = 3600.0


class TokenBucket:
    """Allows bursts of up to ``capacity``, refilled at ``per_hour`` tokens an hour."""

    def __init__(
        self, capacity: int, per_hour: int, clock: Callable[[], float] = time.monotonic
    ) -> None:
        if capacity < 1 or per_hour < 1:
            raise ValueError("capacity and per_hour must be positive")
        self._capacity = float(capacity)
        self._rate = per_hour / _SECONDS_PER_HOUR
        self._clock = clock
        self._tokens = float(capacity)
        self._updated = clock()

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self._capacity, self._tokens + (now - self._updated) * self._rate)
        self._updated = now

    def take(self) -> bool:
        self._refill()
        if self._tokens < 1:
            return False
        self._tokens -= 1
        return True

    def seconds_until_available(self) -> float:
        self._refill()
        return 0.0 if self._tokens >= 1 else (1 - self._tokens) / self._rate
