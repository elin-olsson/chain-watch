from datetime import datetime, timedelta
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from chainwatch import correlate_events, _severity_rank

BASE = datetime(2026, 4, 21, 10, 0, 0)


def ts(s):
    return BASE + timedelta(seconds=s)


def fail(ip, s, user="root"):
    return {"event_type": "failed_login", "source_ip": ip, "user": user, "timestamp": ts(s)}


def ok(ip, user, s):
    return {"event_type": "successful_login", "source_ip": ip, "user": user, "timestamp": ts(s)}


def block(ip, port, s):
    return {"event_type": "fw_block", "src_ip": ip, "dst_port": port,
            "protocol": "TCP", "firewall": "ufw", "timestamp": ts(s)}


def _make_mixed_incidents():
    """Return incidents spanning medium, high, and critical severity."""
    # medium: brute_force only
    brute_auth = [fail("1.1.1.1", i) for i in range(6)]
    # critical: brute_then_login
    btl_auth = [fail("2.2.2.2", i) for i in range(6)] + [ok("2.2.2.2", "root", 10)]
    # high: portscan_then_login
    ps_ufw = [block("3.3.3.3", 22 + i, i) for i in range(3)]
    ps_auth = [ok("3.3.3.3", "root", 10)]
    return (
        brute_auth + btl_auth + ps_auth,
        ps_ufw,
        [],
    )


class TestSeverityRank:
    def test_ranks_are_ordered(self):
        assert _severity_rank("medium") < _severity_rank("high") < _severity_rank("critical")

    def test_unknown_severity_is_zero(self):
        assert _severity_rank("unknown") == 0

    def test_case_insensitive(self):
        assert _severity_rank("HIGH") == _severity_rank("high")


class TestLevelFilter:
    def _incidents(self):
        auth, ufw, audit = _make_mixed_incidents()
        return correlate_events(auth, ufw, audit, window_seconds=600)

    def test_no_filter_returns_all(self):
        incidents = self._incidents()
        severities = {inc["severity"] for inc in incidents}
        assert "medium" in severities

    def test_level_medium_keeps_all(self):
        incidents = self._incidents()
        min_rank = _severity_rank("medium")
        filtered = [inc for inc in incidents if _severity_rank(inc["severity"]) >= min_rank]
        assert len(filtered) == len(incidents)

    def test_level_high_removes_medium(self):
        incidents = self._incidents()
        min_rank = _severity_rank("high")
        filtered = [inc for inc in incidents if _severity_rank(inc["severity"]) >= min_rank]
        assert all(inc["severity"] in ("high", "critical") for inc in filtered)
        assert not any(inc["severity"] == "medium" for inc in filtered)

    def test_level_critical_keeps_only_critical(self):
        incidents = self._incidents()
        min_rank = _severity_rank("critical")
        filtered = [inc for inc in incidents if _severity_rank(inc["severity"]) >= min_rank]
        assert all(inc["severity"] == "critical" for inc in filtered)
        assert len(filtered) >= 1

    def test_level_critical_does_not_remove_critical(self):
        incidents = self._incidents()
        critical_before = [inc for inc in incidents if inc["severity"] == "critical"]
        min_rank = _severity_rank("critical")
        filtered = [inc for inc in incidents if _severity_rank(inc["severity"]) >= min_rank]
        assert len(filtered) == len(critical_before)
