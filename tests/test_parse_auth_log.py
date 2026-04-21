import textwrap
import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from chainwatch import parse_auth_log


def write_log(tmp_path, content):
    p = tmp_path / "auth.log"
    p.write_text(textwrap.dedent(content).lstrip())
    return str(p)


# ── failed logins ─────────────────────────────────────────────────────────────

def test_failed_password(tmp_path):
    f = write_log(tmp_path, """
        Apr 20 10:00:01 host sshd[1000]: Failed password for root from 203.0.113.5 port 54321 ssh2
    """)
    events = parse_auth_log(f)
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "failed_login"
    assert ev["user"] == "root"
    assert ev["source_ip"] == "203.0.113.5"


def test_failed_password_invalid_user(tmp_path):
    f = write_log(tmp_path, """
        Apr 20 10:00:01 host sshd[1000]: Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2
    """)
    events = parse_auth_log(f)
    assert len(events) == 1
    assert events[0]["event_type"] == "failed_login"
    assert events[0]["user"] == "admin"
    assert events[0]["source_ip"] == "203.0.113.5"


# ── successful logins ─────────────────────────────────────────────────────────

def test_accepted_publickey(tmp_path):
    f = write_log(tmp_path, """
        Apr 20 10:00:01 host sshd[1001]: Accepted publickey for alice from 10.0.0.2 port 22 ssh2
    """)
    events = parse_auth_log(f)
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "successful_login"
    assert ev["user"] == "alice"
    assert ev["source_ip"] == "10.0.0.2"


def test_accepted_password(tmp_path):
    f = write_log(tmp_path, """
        Apr 20 10:00:01 host sshd[1001]: Accepted password for bob from 10.0.0.3 port 22 ssh2
    """)
    events = parse_auth_log(f)
    assert len(events) == 1
    assert events[0]["event_type"] == "successful_login"
    assert events[0]["user"] == "bob"


# ── sudo ──────────────────────────────────────────────────────────────────────

def test_sudo_usage(tmp_path):
    f = write_log(tmp_path, """
        Apr 20 10:00:01 host sudo[1002]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id
    """)
    events = parse_auth_log(f)
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "sudo_usage"
    assert ev["user"] == "alice"
    assert ev["target_user"] == "root"
    assert ev["command"] == "/usr/bin/id"


def test_sudo_pam_session_noise_ignored(tmp_path):
    f = write_log(tmp_path, """
        Apr 20 10:00:01 host sudo[1002]: pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)
        Apr 20 10:00:02 host sudo[1002]: pam_unix(sudo:session): session closed for user root
    """)
    events = parse_auth_log(f)
    assert events == []


# ── timestamp edge cases ──────────────────────────────────────────────────────

def test_single_digit_day(tmp_path):
    f = write_log(tmp_path, """
        Apr  5 10:00:01 host sshd[1000]: Failed password for root from 203.0.113.5 port 12345 ssh2
    """)
    events = parse_auth_log(f)
    assert len(events) == 1
    assert events[0]["timestamp"].month == 4
    assert events[0]["timestamp"].day == 5


# ── error handling ────────────────────────────────────────────────────────────

def test_file_not_found(capsys):
    events = parse_auth_log("/nonexistent/path/auth.log")
    assert events == []
    assert "not found" in capsys.readouterr().err


def test_permission_denied(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text("Apr 20 10:00:01 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n")
    p.chmod(0o000)
    try:
        events = parse_auth_log(str(p))
        assert events == []
    finally:
        p.chmod(0o644)


# ── mixed log ─────────────────────────────────────────────────────────────────

def test_mixed_events_all_parsed(tmp_path):
    f = write_log(tmp_path, """
        Apr 20 10:00:00 host sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2
        Apr 20 10:00:01 host sshd[2]: Failed password for invalid user admin from 1.2.3.4 port 2 ssh2
        Apr 20 10:00:02 host sshd[3]: Accepted publickey for alice from 10.0.0.1 port 22 ssh2
        Apr 20 10:00:03 host sudo[4]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
        Apr 20 10:00:04 host sudo[4]: pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)
    """)
    events = parse_auth_log(f)
    types = [e["event_type"] for e in events]
    assert types == ["failed_login", "failed_login", "successful_login", "sudo_usage"]
