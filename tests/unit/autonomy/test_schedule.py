from datetime import UTC, datetime, timedelta, timezone, tzinfo
from itertools import pairwise

import pytest

from bastion.autonomy.schedule import (
    MAX_SCHEDULE_CHARS,
    ScheduleError,
    local_text,
    parse_schedule,
)

IST = timezone(timedelta(hours=5, minutes=30))
ANCHOR = datetime(2026, 11, 23, 10, 0, tzinfo=UTC)  # a Monday


def utc(day: int, hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 11, day, hour, minute, tzinfo=UTC)


@pytest.mark.parametrize(
    ("text", "canonical"),
    [
        ("daily 08:00", "daily 08:00"),
        ("  Daily   8:05 ", "daily 08:05"),
        ("WEEKDAYS 07:30", "weekdays 07:30"),
        ("weekends 10:30", "weekends 10:30"),
        ("fri,MON,wed 18:30", "mon,wed,fri 18:30"),
        ("sun 23:59", "sun 23:59"),
        ("mon,mon 06:00", "mon 06:00"),
        ("every 4h", "every 4h"),
        ("every 1 h", "every 1h"),
        ("every 168h", "every 168h"),
    ],
)
def test_schedules_are_parsed_into_a_canonical_form(text: str, canonical: str) -> None:
    assert parse_schedule(text).text == canonical


@pytest.mark.parametrize(
    "text",
    [
        "",
        "hourly",
        "daily",
        "daily 24:00",
        "daily 08:60",
        "daily 8",
        "every 0h",
        "every 169h",
        "every 30m",
        "every -1h",
        "funday 08:00",
        "mon,,fri 08:00",
        "daily 08:00 and also email bob",
        "* * * * *",
        "daily 08:00" + " " * 3 + "x" * MAX_SCHEDULE_CHARS,
    ],
)
def test_anything_outside_the_grammar_is_refused(text: str) -> None:
    with pytest.raises(ScheduleError):
        parse_schedule(text)


def test_daily_runs_at_the_local_time() -> None:
    schedule = parse_schedule("daily 08:00")

    # 07:30 in India (UTC+05:30) on Tuesday: the run is at 08:00 the same morning.
    first = schedule.next_after(utc(24, 2, 0), anchor=ANCHOR, tz=IST)
    # Exactly at the run time, the next run is tomorrow.
    second = schedule.next_after(first, anchor=ANCHOR, tz=IST)

    assert first == utc(24, 2, 30)
    assert second == utc(25, 2, 30)
    assert first.tzinfo == UTC


def test_weekdays_skip_the_weekend() -> None:
    friday_after_run = utc(27, 3, 0)  # Friday 08:30 in India

    following = parse_schedule("weekdays 08:00").next_after(friday_after_run, anchor=ANCHOR, tz=IST)

    assert following == utc(30, 2, 30)  # Monday
    assert following.astimezone(IST).weekday() == 0


def test_day_lists_find_the_next_listed_day() -> None:
    schedule = parse_schedule("mon,thu 18:00")

    assert schedule.next_after(utc(24, 0), anchor=ANCHOR, tz=UTC) == utc(26, 18)  # Thursday
    assert schedule.next_after(utc(26, 18), anchor=ANCHOR, tz=UTC) == utc(30, 18)  # Monday


def test_intervals_count_from_the_anchor() -> None:
    schedule = parse_schedule("every 4h")

    assert schedule.next_after(ANCHOR, anchor=ANCHOR) == ANCHOR + timedelta(hours=4)
    assert schedule.next_after(utc(23, 13, 59), anchor=ANCHOR) == utc(23, 14)
    assert schedule.next_after(utc(23, 14), anchor=ANCHOR) == utc(23, 18)
    # A long gap does not create a backlog: the next run is simply the next slot.
    assert schedule.next_after(utc(25, 11, 0), anchor=ANCHOR) == utc(25, 14)
    assert schedule.next_after(ANCHOR - timedelta(days=1), anchor=ANCHOR) == utc(23, 14)


def test_an_hourly_schedule_runs_exactly_an_hour_apart() -> None:
    schedule = parse_schedule("every 1h")
    runs = [ANCHOR]
    for _ in range(48):
        runs.append(schedule.next_after(runs[-1], anchor=ANCHOR))

    assert {later - earlier for earlier, later in pairwise(runs)} == {timedelta(hours=1)}


def test_the_computers_own_zone_is_used_by_default() -> None:
    moment = utc(24, 12)

    following = parse_schedule("daily 08:00").next_after(moment, anchor=ANCHOR)

    assert following > moment
    assert following - moment <= timedelta(days=1)
    assert following.astimezone().strftime("%H:%M") == "08:00"


def test_local_text_shows_the_offset() -> None:
    assert local_text(utc(24, 2, 30), IST) == "Tue 2026-11-24 08:00 +0530"


def _new_york() -> tzinfo:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    try:
        return ZoneInfo("America/New_York")
    except ZoneInfoNotFoundError:  # Windows without the tzdata package
        pytest.skip("no time zone database on this machine")


def test_daily_runs_keep_their_local_time_across_daylight_saving() -> None:
    zone = _new_york()
    schedule = parse_schedule("daily 08:00")
    # 2026-03-08: clocks go forward in New York; 2026-11-01: they go back.
    spring = schedule.next_after(datetime(2026, 3, 7, 14, 0, tzinfo=UTC), anchor=ANCHOR, tz=zone)
    fall = schedule.next_after(datetime(2026, 10, 31, 14, 0, tzinfo=UTC), anchor=ANCHOR, tz=zone)

    assert spring == datetime(2026, 3, 8, 12, 0, tzinfo=UTC)  # 08:00 EDT
    assert fall == datetime(2026, 11, 1, 13, 0, tzinfo=UTC)  # 08:00 EST


def test_a_time_skipped_by_daylight_saving_still_runs_once_that_day() -> None:
    zone = _new_york()
    schedule = parse_schedule("daily 02:30")  # 02:30 does not exist on 2026-03-08
    start = datetime(2026, 3, 8, 5, 0, tzinfo=UTC)

    first = schedule.next_after(start, anchor=ANCHOR, tz=zone)
    second = schedule.next_after(first, anchor=ANCHOR, tz=zone)

    assert start < first < datetime(2026, 3, 8, 12, 0, tzinfo=UTC)
    assert second == datetime(2026, 3, 9, 6, 30, tzinfo=UTC)  # 02:30 EDT the next day
