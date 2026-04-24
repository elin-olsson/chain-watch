import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from chainwatch import _parse_journal_lines

_BASE_TS = str(int(datetime(2026, 4, 20, 10, 0, 0).timestamp() * 1_000_000))


def _rec(identifier, message, ts_us=None, hostname="testhost"):
    return json.dumps({
        "__REALTIME_TIMESTAMP": ts_us or _BASE_TS,
        "SYSLOG_IDENTIFIER": identifier,
        "_HOSTNAME": hostname,
        "MESSAGE": message,
    })


# ── SSH events ────────────────────────────────────────────────────────────────

def test_ssh_failed_password():
    auth, fw = _parse_journal_lines([
        _rec("sshd", "Failed password for root from 203.0.113.5 port 54321 ssh2")
    ])
    assert len(auth) == 1
    assert auth[0]["event_type"] == "failed_login"
    assert auth[0]["user"] == "root"
    assert auth[0]["source_ip"] == "203.0.113.5"
    assert fw == []


def test_ssh_failed_invalid_user():
    auth, fw = _parse_journal_lines([
        _rec("sshd", "Failed password for invalid user admin from 10.0.0.1 port 22 ssh2")
    ])
    assert len(auth) == 1
    assert auth[0]["event_type"] == "failed_login"
    assert auth[0]["user"] == "admin"


def test_ssh_accepted_password():
    auth, fw = _parse_journal_lines([
        _rec("sshd", "Accepted password for alice from 10.0.0.2 port 22 ssh2")
    ])
    assert len(auth) == 1
    assert auth[0]["event_type"] == "successful_login"
    assert auth[0]["user"] == "alice"
    assert auth[0]["source_ip"] == "10.0.0.2"


def test_ssh_accepted_publickey():
    auth, fw = _parse_journal_lines([
        _rec("sshd", "Accepted publickey for bob from 10.0.0.3 port 22 ssh2")
    ])
    assert len(auth) == 1
    assert auth[0]["event_type"] == "successful_login"
    assert auth[0]["user"] == "bob"


def test_sshd_noise_ignored():
    auth, fw = _parse_journal_lines([
        _rec("sshd", "Server listening on 0.0.0.0 port 22."),
        _rec("sshd", "Disconnected from 10.0.0.1 port 22"),
    ])
    assert auth == []
    assert fw == []


# ── sudo events ───────────────────────────────────────────────────────────────

def test_sudo_usage():
    auth, fw = _parse_journal_lines([
        _rec("sudo", "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id")
    ])
    assert len(auth) == 1
    ev = auth[0]
    assert ev["event_type"] == "sudo_usage"
    assert ev["user"] == "alice"
    assert ev["target_user"] == "root"
    assert ev["command"] == "/usr/bin/id"


def test_sudo_noise_ignored():
    auth, fw = _parse_journal_lines([
        _rec("sudo", "pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)")
    ])
    assert auth == []


# ── firewall events ───────────────────────────────────────────────────────────

def test_kernel_ufw_block():
    msg = "[UFW BLOCK] IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=192.168.1.1 LEN=40 TOS=0x00 PREC=0x00 TTL=238 ID=0 PROTO=TCP DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0"
    auth, fw = _parse_journal_lines([_rec("kernel", msg)])
    assert auth == []
    assert len(fw) == 1
    ev = fw[0]
    assert ev["event_type"] == "fw_block"
    assert ev["firewall"] == "ufw"
    assert ev["src_ip"] == "1.2.3.4"
    assert ev["dst_port"] == 22


def test_kernel_ufw_allow():
    msg = "[UFW ALLOW] IN=eth0 OUT= SRC=10.0.0.5 DST=192.168.1.1 PROTO=TCP DPT=80"
    auth, fw = _parse_journal_lines([_rec("kernel", msg)])
    assert len(fw) == 1
    assert fw[0]["event_type"] == "fw_allow"


def test_kernel_firewalld_block():
    msg = "FINAL_REJECT: IN=eth0 OUT= SRC=5.6.7.8 DST=10.0.0.1 PROTO=TCP DPT=3306"
    auth, fw = _parse_journal_lines([_rec("kernel", msg)])
    assert len(fw) == 1
    assert fw[0]["firewall"] == "firewalld"
    assert fw[0]["src_ip"] == "5.6.7.8"


def test_kernel_no_src_ignored():
    # Kernel lines without SRC= must be skipped (not netfilter packet logs)
    msg = "[UFW BLOCK] IN=eth0 OUT= PROTO=TCP DPT=22"
    auth, fw = _parse_journal_lines([_rec("kernel", msg)])
    assert fw == []


# ── timestamp ─────────────────────────────────────────────────────────────────

def test_timestamp_correct():
    ts = datetime(2026, 4, 20, 10, 0, 0)
    ts_us = str(int(ts.timestamp() * 1_000_000))
    auth, fw = _parse_journal_lines([
        _rec("sshd", "Failed password for root from 1.2.3.4 port 22 ssh2", ts_us=ts_us)
    ])
    assert auth[0]["timestamp"].hour == 10
    assert auth[0]["timestamp"].minute == 0


def test_missing_timestamp_skipped():
    rec = json.dumps({"SYSLOG_IDENTIFIER": "sshd",
                      "MESSAGE": "Failed password for root from 1.2.3.4 port 22 ssh2"})
    auth, fw = _parse_journal_lines([rec])
    assert auth == []


# ── robustness ────────────────────────────────────────────────────────────────

def test_message_as_byte_array():
    rec = json.dumps({
        "__REALTIME_TIMESTAMP": _BASE_TS,
        "SYSLOG_IDENTIFIER": "sshd",
        "_HOSTNAME": "host",
        "MESSAGE": list(b"Failed password for root from 9.9.9.9 port 22 ssh2"),
    })
    auth, fw = _parse_journal_lines([rec])
    assert len(auth) == 1
    assert auth[0]["source_ip"] == "9.9.9.9"


def test_invalid_json_skipped():
    auth, fw = _parse_journal_lines(["not valid json", "{broken"])
    assert auth == []
    assert fw == []


def test_empty_lines_skipped():
    auth, fw = _parse_journal_lines(["", "   ", "\n"])
    assert auth == []


def test_unknown_identifier_ignored():
    auth, fw = _parse_journal_lines([
        _rec("cron", "some cron job output"),
        _rec("nginx", "GET /index.html 200"),
    ])
    assert auth == []
    assert fw == []


def test_hostname_propagated():
    auth, fw = _parse_journal_lines([
        _rec("sshd", "Failed password for root from 1.2.3.4 port 22 ssh2", hostname="mybox")
    ])
    assert auth[0]["hostname"] == "mybox"


# ── mixed input ───────────────────────────────────────────────────────────────

def test_mixed_events():
    ts1 = str(int(datetime(2026, 4, 20, 10, 0, 0).timestamp() * 1_000_000))
    ts2 = str(int(datetime(2026, 4, 20, 10, 0, 5).timestamp() * 1_000_000))
    ts3 = str(int(datetime(2026, 4, 20, 10, 0, 10).timestamp() * 1_000_000))
    fw_msg = "[UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=10.0.0.1 PROTO=TCP DPT=22"
    lines = [
        _rec("sshd", "Failed password for root from 1.2.3.4 port 22 ssh2", ts_us=ts1),
        _rec("kernel", fw_msg, ts_us=ts2),
        _rec("sshd", "Accepted password for alice from 10.0.0.2 port 22 ssh2", ts_us=ts3),
    ]
    auth, fw = _parse_journal_lines(lines)
    assert len(auth) == 2
    assert len(fw) == 1
    assert auth[0]["event_type"] == "failed_login"
    assert auth[1]["event_type"] == "successful_login"
