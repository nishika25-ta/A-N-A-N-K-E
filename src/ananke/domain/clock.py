"""Clocks. Experiments use a logical clock; a protected wall clock is a later, live-mode concern.

The agent never holds a reference that can advance the clock: only the scenario controller does.
"""

from __future__ import annotations


class ClockError(ValueError):
    """Invalid clock operation (e.g. attempting to move backwards)."""


class LogicalClock:
    """Monotonic integer tick clock, starting at a non-negative tick."""

    __slots__ = ("_tick",)

    def __init__(self, start: int = 0) -> None:
        if isinstance(start, bool) or not isinstance(start, int) or start < 0:
            raise ClockError("start tick must be a non-negative int")
        self._tick = start

    def now(self) -> int:
        return self._tick

    def advance(self, ticks: int = 1) -> int:
        if isinstance(ticks, bool) or not isinstance(ticks, int) or ticks < 1:
            raise ClockError("advance requires a positive int")
        self._tick += ticks
        return self._tick

    def advance_to(self, tick: int) -> int:
        if isinstance(tick, bool) or not isinstance(tick, int) or tick < self._tick:
            raise ClockError("logical clock cannot move backwards")
        self._tick = tick
        return self._tick
