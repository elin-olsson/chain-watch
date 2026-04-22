"""
Tests for follow mode using a controlled sleep mock to avoid timing races.
Each test drives the poll loop iteration-by-iteration via a patched time.sleep.
"""
from datetime import datetime
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

import chainwatch
from chainwatch import _follow_mode


def _syslog_ts():
    """Current time in syslog header format (e.g. 'Apr 22 15:30:01')."""
    now = datetime.now()
    return now.strftime(f"%b {now.day:2d} %H:%M:%S")


_TCP = ("IN=eth0 OUT= MAC=aa:bb SRC={ip} DST=192.168.1.1 LEN=44 "
        "PROTO=TCP SPT=12345 DPT={port} WINDOW=1024 SYN URGP=0")


def _ufw_block(ip, port):
    return (f"{_syslog_ts()} host kernel: [1.0] [UFW BLOCK] "
            + _TCP.format(ip=ip, port=port))


def _ssh_fail(ip, user="root"):
    return (f"{_syslog_ts()} host sshd[1]: "
            f"Failed password for {user} from {ip} port 54321 ssh2")


def _ssh_ok(ip, user="alice"):
    return (f"{_syslog_ts()} host sshd[1]: "
            f"Accepted password for {user} from {ip} port 54321 ssh2")


def _controlled_follow(path_args, actions, window=600):
    """
    Run _follow_mode with a patched time.sleep that executes `actions` in
    order on each poll iteration, then raises KeyboardInterrupt.
    """
    orig_sleep = chainwatch.time.sleep
    step = [0]

    def mock_sleep(_n):
        if step[0] < len(actions):
            actions[step[0]]()
            step[0] += 1
        else:
            raise KeyboardInterrupt
        orig_sleep(0.001)

    chainwatch.time.sleep = mock_sleep
    try:
        _follow_mode(*path_args, window_seconds=window, poll_interval=1)
    finally:
        chainwatch.time.sleep = orig_sleep


# ── brute force detected ──────────────────────────────────────────────────────

def test_follow_detects_brute_force(tmp_path, capsys):
    auth = tmp_path / "auth.log"
    auth.write_text("")

    def write_failures():
        with auth.open("a") as f:
            for _ in range(5):
                f.write(_ssh_fail("1.2.3.4") + "\n")

    _controlled_follow((str(auth), None, None), [write_failures, lambda: None])

    out = capsys.readouterr().out
    assert "brute_force" in out
    assert "1.2.3.4" in out


# ── portscan_then_login detected ──────────────────────────────────────────────

def test_follow_detects_portscan(tmp_path, capsys):
    fw = tmp_path / "fw.log"
    fw.write_text("")
    auth = tmp_path / "auth.log"
    auth.write_text("")

    def write_fw():
        with fw.open("a") as f:
            f.write(_ufw_block("2.2.2.2", 22) + "\n")
            f.write(_ufw_block("2.2.2.2", 80) + "\n")

    def write_auth():
        with auth.open("a") as f:
            f.write(_ssh_fail("2.2.2.2") + "\n")

    _controlled_follow(
        (str(auth), str(fw), None),
        [write_fw, write_auth, lambda: None],
    )

    out = capsys.readouterr().out
    assert "portscan_then_login" in out


# ── existing content is skipped (tail behaviour) ──────────────────────────────

def test_follow_skips_existing_content(tmp_path, capsys):
    auth = tmp_path / "auth.log"
    with auth.open("w") as f:
        for _ in range(5):
            f.write(_ssh_fail("9.9.9.9") + "\n")

    _controlled_follow((str(auth), None, None), [lambda: None])

    out = capsys.readouterr().out
    assert "brute_force" not in out


# ── file rotation / truncation resets offset ─────────────────────────────────

def test_follow_handles_rotation(tmp_path, capsys):
    auth = tmp_path / "auth.log"
    with auth.open("w") as f:
        f.write(_ssh_fail("9.9.9.9") + "\n")

    def truncate():
        # Rotation: new empty file; follow loop sees size < old offset → resets
        auth.write_text("")

    def write_new():
        with auth.open("a") as f:
            for _ in range(5):
                f.write(_ssh_fail("3.3.3.3") + "\n")

    _controlled_follow((str(auth), None, None), [truncate, write_new, lambda: None])

    out = capsys.readouterr().out
    assert "brute_force" in out
    assert "3.3.3.3" in out


# ── missing log file does not crash ──────────────────────────────────────────

def test_follow_handles_missing_file(tmp_path, capsys):
    _controlled_follow((str(tmp_path / "nonexistent.log"), None, None), [lambda: None])
