from datetime import UTC, datetime
from pathlib import Path

import pytest

from bastion.security.killswitch import STOP_FILE, KillSwitch
from bastion.security.ratelimit import TokenBucket


class Ticker:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


# --------------------------------------------------------------- kill switch


def test_the_kill_switch_starts_released(tmp_path: Path) -> None:
    assert not KillSwitch(tmp_path).engaged()


def test_engaging_persists_across_instances(tmp_path: Path) -> None:
    KillSwitch(tmp_path).engage(via="telegram", at=datetime(2026, 11, 23, tzinfo=UTC))

    assert KillSwitch(tmp_path).engaged()
    assert "via telegram" in (tmp_path / STOP_FILE).read_text(encoding="utf-8")


def test_release_reports_whether_it_was_engaged(tmp_path: Path) -> None:
    switch = KillSwitch(tmp_path)
    switch.engage(via="telegram", at=datetime(2026, 11, 23, tzinfo=UTC))

    assert switch.release() is True
    assert switch.release() is False
    assert not switch.engaged()


# ---------------------------------------------------------------- rate limit


def test_a_burst_is_allowed_then_refused() -> None:
    bucket = TokenBucket(3, 60, Ticker())

    assert [bucket.take() for _ in range(4)] == [True, True, True, False]


def test_tokens_refill_at_the_hourly_rate() -> None:
    ticker = Ticker()
    bucket = TokenBucket(1, 60, ticker)  # one per minute
    bucket.take()

    assert not bucket.take()
    assert bucket.seconds_until_available() == pytest.approx(60)
    ticker.now = 60.0
    assert bucket.take()


def test_refill_never_exceeds_the_capacity() -> None:
    ticker = Ticker()
    bucket = TokenBucket(2, 3600, ticker)
    ticker.now = 10_000.0

    assert [bucket.take() for _ in range(3)] == [True, True, False]


@pytest.mark.parametrize(("capacity", "per_hour"), [(0, 1), (1, 0)])
def test_invalid_limits_are_rejected(capacity: int, per_hour: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        TokenBucket(capacity, per_hour)
