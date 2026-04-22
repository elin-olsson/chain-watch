import argparse
from datetime import datetime
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from chainwatch import _parse_time_arg, _filter_events


def ev(ts):
    return {"event_type": "failed_login", "timestamp": ts}


# ── _parse_time_arg ───────────────────────────────────────────────────────────

def test_parse_hhmm():
    dt = _parse_time_arg("03:00")
    assert dt.hour == 3 and dt.minute == 0 and dt.second == 0


def test_parse_hhmmss():
    dt = _parse_time_arg("03:45:30")
    assert dt.hour == 3 and dt.minute == 45 and dt.second == 30


def test_parse_full_datetime():
    dt = _parse_time_arg("2026-04-21 03:00:00")
    assert dt == datetime(2026, 4, 21, 3, 0, 0)


def test_parse_full_datetime_no_seconds():
    dt = _parse_time_arg("2026-04-21 03:00")
    assert dt == datetime(2026, 4, 21, 3, 0, 0)


def test_parse_invalid_raises():
    import pytest
    with pytest.raises(argparse.ArgumentTypeError):
        _parse_time_arg("not-a-time")


# ── _filter_events ────────────────────────────────────────────────────────────

EVENTS = [
    ev(datetime(2026, 4, 21, 2, 0, 0)),
    ev(datetime(2026, 4, 21, 3, 0, 0)),
    ev(datetime(2026, 4, 21, 4, 0, 0)),
    ev(datetime(2026, 4, 21, 5, 0, 0)),
]


def test_filter_since():
    result = _filter_events(EVENTS, since=datetime(2026, 4, 21, 3, 0, 0), until=None)
    assert [e["timestamp"].hour for e in result] == [3, 4, 5]


def test_filter_until():
    result = _filter_events(EVENTS, since=None, until=datetime(2026, 4, 21, 4, 0, 0))
    assert [e["timestamp"].hour for e in result] == [2, 3, 4]


def test_filter_since_and_until():
    result = _filter_events(EVENTS,
                            since=datetime(2026, 4, 21, 3, 0, 0),
                            until=datetime(2026, 4, 21, 4, 0, 0))
    assert [e["timestamp"].hour for e in result] == [3, 4]


def test_filter_no_bounds_returns_all():
    result = _filter_events(EVENTS, since=None, until=None)
    assert result == EVENTS


def test_filter_empty_list():
    assert _filter_events([], since=datetime(2026, 4, 21, 3, 0, 0), until=None) == []
