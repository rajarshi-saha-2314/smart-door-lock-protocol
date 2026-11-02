"""Injectable clocks.

Every entity takes its timestamps from a ``Clock`` instead of calling
``time.time()`` directly, so tests can freeze or advance time and the demo can
simulate any time of day for the access policy.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Protocol


class Clock(Protocol):
    def now_ms(self) -> int:
        """Unix time in milliseconds."""
        ...

    def now_dt(self) -> datetime:
        """Local wall-clock time (used by the timetable policy)."""
        ...


class SystemClock:
    """Real time, optionally shifted by a fixed offset."""

    def __init__(self, offset_ms: int = 0) -> None:
        self.offset_ms = offset_ms

    @classmethod
    def starting_at(cls, when: datetime) -> SystemClock:
        """A clock that reads ``when`` right now and then runs in real time."""
        return cls(offset_ms=int(when.timestamp() * 1000) - int(time.time() * 1000))

    def now_ms(self) -> int:
        return int(time.time() * 1000) + self.offset_ms

    def now_dt(self) -> datetime:
        return datetime.fromtimestamp(self.now_ms() / 1000)


class FakeClock:
    """Fully manual clock for tests."""

    def __init__(self, start: datetime | int | None = None) -> None:
        if start is None:
            self._ms = int(time.time() * 1000)
        elif isinstance(start, datetime):
            self._ms = int(start.timestamp() * 1000)
        else:
            self._ms = start

    def now_ms(self) -> int:
        return self._ms

    def now_dt(self) -> datetime:
        return datetime.fromtimestamp(self._ms / 1000)

    def set(self, when: datetime) -> None:
        self._ms = int(when.timestamp() * 1000)

    def advance(self, ms: int) -> None:
        self._ms += ms


def is_fresh(clock: Clock, T: int, delta_t_ms: int) -> tuple[bool, int]:
    """Return (|now − T| ≤ ΔT, Δ in ms)."""
    delta = abs(clock.now_ms() - T)
    return delta <= delta_t_ms, delta
