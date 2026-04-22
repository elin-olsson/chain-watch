from datetime import datetime
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from chainwatch import _parse_timestamp


def _today(year, month, day):
    return datetime(year, month, day, 12, 0, 0)


def test_normal_date_same_year():
    dt = _parse_timestamp("Apr 20 10:00:00", _today=_today(2026, 4, 22))
    assert dt == datetime(2026, 4, 20, 10, 0, 0)


def test_december_entry_parsed_in_january_rolls_back():
    # Log entry from Dec 31, parsed on Jan 5 the following year
    dt = _parse_timestamp("Dec 31 23:59:00", _today=_today(2026, 1, 5))
    assert dt == datetime(2025, 12, 31, 23, 59, 0)


def test_entry_same_day_not_rolled_back():
    dt = _parse_timestamp("Jan  5 08:00:00", _today=_today(2026, 1, 5))
    assert dt == datetime(2026, 1, 5, 8, 0, 0)


def test_entry_yesterday_not_rolled_back():
    dt = _parse_timestamp("Jan  4 23:00:00", _today=_today(2026, 1, 5))
    assert dt == datetime(2026, 1, 4, 23, 0, 0)


def test_future_time_today_not_rolled_back():
    # Same date but a later time-of-day — still "today", not future in date terms
    dt = _parse_timestamp("Apr 22 23:59:59", _today=_today(2026, 4, 22))
    assert dt == datetime(2026, 4, 22, 23, 59, 59)


def test_november_parsed_in_december_not_rolled_back():
    dt = _parse_timestamp("Nov 30 10:00:00", _today=_today(2026, 12, 1))
    assert dt == datetime(2026, 11, 30, 10, 0, 0)
