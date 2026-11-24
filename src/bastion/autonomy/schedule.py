"""When scheduled tasks run (control C11).

A small fixed grammar, so a schedule reads plainly in an approval prompt and can never fire more
than once an hour:

    daily 08:00          every day at 08:00
    weekdays 08:00       Monday to Friday
    weekends 10:30       Saturday and Sunday
    mon,wed,fri 18:30    the days listed
    every 4h             every 4 hours (1 to 168), counted from when the task was created

Times are the computer's local time (``tz=None``); tests pass a fixed zone.
"""

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta, tzinfo

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_GROUPS: dict[str, frozenset[int]] = {
    "daily": frozenset(range(7)),
    "weekdays": frozenset(range(5)),
    "weekends": frozenset({5, 6}),
}
_AT = re.compile(r"([a-z,]+) ([01]?\d|2[0-3]):([0-5]\d)")
_EVERY = re.compile(r"every (\d{1,3}) ?h")
MIN_INTERVAL_HOURS = 1
MAX_INTERVAL_HOURS = 168
MAX_SCHEDULE_CHARS = 40
EXAMPLES = "daily 08:00, weekdays 08:00, weekends 10:30, mon,wed,fri 18:30, every 4h"


class ScheduleError(ValueError):
    """The schedule is not in the supported grammar."""


@dataclass(frozen=True)
class Schedule:
    text: str  # canonical form, as stored and shown
    days: frozenset[int] = frozenset()
    at: time | None = None
    every_hours: int | None = None

    def next_after(
        self, moment: datetime, *, anchor: datetime, tz: tzinfo | None = None
    ) -> datetime:
        """The first run strictly after ``moment``, in UTC. ``anchor`` (the task's creation
        time) is where an ``every Nh`` schedule starts counting."""
        moment = moment.astimezone(UTC)  # compare instants, never wall-clock times
        if self.every_hours is not None:
            step = timedelta(hours=self.every_hours)
            elapsed = max(timedelta(0), moment - anchor)
            return (anchor + step * (elapsed // step + 1)).astimezone(UTC)
        if self.at is None:
            raise ScheduleError(f"schedule {self.text!r} has no time of day")
        local = moment.astimezone(tz)
        for offset in range(8):
            day = local.date() + timedelta(days=offset)
            if day.weekday() not in self.days:
                continue
            candidate = _local_datetime(day, self.at, tz)
            if candidate > moment:
                return candidate.astimezone(UTC)
        raise ScheduleError(f"schedule {self.text!r} never runs")  # unreachable: days is non-empty


def _local_datetime(day: date, at: time, tz: tzinfo | None) -> datetime:
    naive = datetime.combine(day, at)
    # Without a zone, astimezone() reads a naive time as the computer's local time (DST-aware).
    return naive.replace(tzinfo=tz) if tz is not None else naive.astimezone()


def parse_schedule(text: str) -> Schedule:
    normalized = " ".join(text.lower().split())
    if not normalized or len(normalized) > MAX_SCHEDULE_CHARS:
        raise ScheduleError(f"use one of: {EXAMPLES}")
    every = _EVERY.fullmatch(normalized)
    if every is not None:
        hours = int(every.group(1))
        if not MIN_INTERVAL_HOURS <= hours <= MAX_INTERVAL_HOURS:
            raise ScheduleError(
                f"an interval must be {MIN_INTERVAL_HOURS} to {MAX_INTERVAL_HOURS} hours"
            )
        return Schedule(text=f"every {hours}h", every_hours=hours)
    match = _AT.fullmatch(normalized)
    if match is None:
        raise ScheduleError(f"use one of: {EXAMPLES}")
    day_text, hour, minute = match.groups()
    at = time(int(hour), int(minute))
    if day_text in _GROUPS:
        return Schedule(text=f"{day_text} {at:%H:%M}", days=_GROUPS[day_text], at=at)
    names = day_text.split(",")
    if any(name not in DAYS for name in names):
        raise ScheduleError(f"days are written {','.join(DAYS)} (or daily, weekdays, weekends)")
    days = frozenset(DAYS.index(name) for name in names)
    canonical = ",".join(DAYS[day] for day in sorted(days))
    return Schedule(text=f"{canonical} {at:%H:%M}", days=days, at=at)


def local_text(moment: datetime, tz: tzinfo | None = None) -> str:
    """A run time as the owner reads it: local time with its UTC offset."""
    return f"{moment.astimezone(tz):%a %Y-%m-%d %H:%M %z}"
