import pytest

from ananke.domain import ClockError, LogicalClock


def test_starts_and_advances() -> None:
    c = LogicalClock()
    assert c.now() == 0
    assert c.advance() == 1
    assert c.advance(9) == 10
    assert c.advance_to(10) == 10  # idempotent
    assert c.advance_to(20) == 20


@pytest.mark.parametrize("bad", [0, -1, True, 1.5])
def test_advance_rejects_nonpositive_or_nonint(bad: object) -> None:
    with pytest.raises(ClockError):
        LogicalClock().advance(bad)  # type: ignore[arg-type]


def test_cannot_move_backwards() -> None:
    c = LogicalClock(5)
    with pytest.raises(ClockError):
        c.advance_to(4)
    assert c.now() == 5


@pytest.mark.parametrize("bad", [-1, True, 0.0])
def test_invalid_start(bad: object) -> None:
    with pytest.raises(ClockError):
        LogicalClock(bad)  # type: ignore[arg-type]
