import textwrap
import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from chainwatch import parse_firewall_log, parse_ufw_log


def write_log(tmp_path, content):
    p = tmp_path / "fw.log"
    p.write_text(textwrap.dedent(content).lstrip())
    return str(p)


# shared netfilter suffix used across formats
_TCP_SUFFIX = "IN=eth0 OUT= MAC=aa:bb:cc:dd SRC=203.0.113.5 DST=192.168.1.1 LEN=44 TOS=0x00 PREC=0x00 TTL=50 ID=1 DF PROTO=TCP SPT=54321 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0"
_UDP_SUFFIX = "IN=eth0 OUT= MAC=aa:bb:cc:dd SRC=198.51.100.9 DST=192.168.1.1 LEN=28 PROTO=UDP SPT=53 DPT=1900 LEN=8"
_ICMP_SUFFIX = "IN=eth0 OUT= MAC=aa:bb:cc:dd SRC=198.51.100.9 DST=192.168.1.1 LEN=28 PROTO=ICMP"


# ── UFW ───────────────────────────────────────────────────────────────────────

def test_ufw_block_tcp(tmp_path):
    f = write_log(tmp_path, f"Apr 20 10:00:01 ubuntu kernel: [1.0] [UFW BLOCK] {_TCP_SUFFIX}\n")
    events = parse_firewall_log(f)
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "ufw_block"
    assert ev["firewall"] == "ufw"
    assert ev["src_ip"] == "203.0.113.5"
    assert ev["dst_port"] == 22
    assert ev["protocol"] == "TCP"


def test_ufw_allow(tmp_path):
    f = write_log(tmp_path, f"Apr 20 10:00:01 ubuntu kernel: [1.0] [UFW ALLOW] {_TCP_SUFFIX}\n")
    events = parse_firewall_log(f)
    assert len(events) == 1
    assert events[0]["event_type"] == "ufw_allow"
    assert events[0]["firewall"] == "ufw"


def test_ufw_block_udp(tmp_path):
    f = write_log(tmp_path, f"Apr 20 10:00:01 ubuntu kernel: [1.0] [UFW BLOCK] {_UDP_SUFFIX}\n")
    events = parse_firewall_log(f)
    assert len(events) == 1
    ev = events[0]
    assert ev["protocol"] == "UDP"
    assert ev["dst_port"] == 1900


def test_ufw_icmp_no_dst_port(tmp_path):
    f = write_log(tmp_path, f"Apr 20 10:00:01 ubuntu kernel: [1.0] [UFW BLOCK] {_ICMP_SUFFIX}\n")
    events = parse_firewall_log(f)
    assert len(events) == 1
    assert events[0]["dst_port"] is None
    assert events[0]["protocol"] == "ICMP"


# ── firewalld ─────────────────────────────────────────────────────────────────

def test_firewalld_final_reject(tmp_path):
    f = write_log(tmp_path, f"Apr 20 10:00:01 fedora kernel: [1.0] FINAL_REJECT: {_TCP_SUFFIX}\n")
    events = parse_firewall_log(f)
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "ufw_block"
    assert ev["firewall"] == "firewalld"
    assert ev["src_ip"] == "203.0.113.5"
    assert ev["dst_port"] == 22


def test_firewalld_zone_drop(tmp_path):
    f = write_log(tmp_path, f"Apr 20 10:00:01 fedora kernel: [1.0] IN_public_DROP: {_TCP_SUFFIX}\n")
    events = parse_firewall_log(f)
    assert len(events) == 1
    assert events[0]["event_type"] == "ufw_block"
    assert events[0]["firewall"] == "firewalld"


def test_firewalld_zone_reject(tmp_path):
    f = write_log(tmp_path, f"Apr 20 10:00:01 fedora kernel: [1.0] IN_external_REJECT: {_TCP_SUFFIX}\n")
    events = parse_firewall_log(f)
    assert len(events) == 1
    assert events[0]["firewall"] == "firewalld"


def test_firewalld_zone_accept(tmp_path):
    f = write_log(tmp_path, f"Apr 20 10:00:01 fedora kernel: [1.0] IN_public_ACCEPT: {_TCP_SUFFIX}\n")
    events = parse_firewall_log(f)
    assert len(events) == 1
    assert events[0]["event_type"] == "ufw_allow"
    assert events[0]["firewall"] == "firewalld"


# ── iptables ──────────────────────────────────────────────────────────────────

def test_iptables_dropped(tmp_path):
    f = write_log(tmp_path, f"Apr 20 10:00:01 ubuntu kernel: [1.0] DROPPED: {_TCP_SUFFIX}\n")
    events = parse_firewall_log(f)
    assert len(events) == 1
    assert events[0]["event_type"] == "ufw_block"
    assert events[0]["firewall"] == "iptables"


def test_iptables_rejected(tmp_path):
    f = write_log(tmp_path, f"Apr 20 10:00:01 ubuntu kernel: [1.0] REJECTED: {_TCP_SUFFIX}\n")
    events = parse_firewall_log(f)
    assert len(events) == 1
    assert events[0]["firewall"] == "iptables"


# ── nftables ──────────────────────────────────────────────────────────────────

def test_nftables_drop(tmp_path):
    f = write_log(tmp_path, f"Apr 20 10:00:01 host kernel: [1.0] nft drop: {_TCP_SUFFIX}\n")
    events = parse_firewall_log(f)
    assert len(events) == 1
    assert events[0]["firewall"] == "nftables"


# ── noise filtering ───────────────────────────────────────────────────────────

def test_non_firewall_kernel_lines_ignored(tmp_path):
    f = write_log(tmp_path, """
        Apr 20 10:00:01 host kernel: [1.0] usb 1-1: new high-speed USB device number 2
        Apr 20 10:00:02 host kernel: [2.0] EXT4-fs (sda1): mounted filesystem
        Apr 20 10:00:03 host kernel: [3.0] some unrelated kernel message
    """)
    events = parse_firewall_log(f)
    assert events == []


def test_action_without_netfilter_kv_ignored(tmp_path):
    # Has [UFW BLOCK] but no SRC= — not a real packet log line
    f = write_log(tmp_path, "Apr 20 10:00:01 host kernel: [1.0] [UFW BLOCK] something without src\n")
    events = parse_firewall_log(f)
    assert events == []


# ── backward compat alias ─────────────────────────────────────────────────────

def test_parse_ufw_log_alias(tmp_path):
    f = write_log(tmp_path, f"Apr 20 10:00:01 ubuntu kernel: [1.0] [UFW BLOCK] {_TCP_SUFFIX}\n")
    assert parse_ufw_log(f) == parse_firewall_log(f)


# ── error handling ────────────────────────────────────────────────────────────

def test_file_not_found(capsys):
    events = parse_firewall_log("/nonexistent/fw.log")
    assert events == []
    assert "not found" in capsys.readouterr().err


def test_permission_denied(tmp_path):
    p = tmp_path / "fw.log"
    p.write_text(f"Apr 20 10:00:01 host kernel: [1.0] [UFW BLOCK] {_TCP_SUFFIX}\n")
    p.chmod(0o000)
    try:
        assert parse_firewall_log(str(p)) == []
    finally:
        p.chmod(0o644)


# ── mixed firewall types in one log ───────────────────────────────────────────

def test_mixed_firewall_types(tmp_path):
    f = write_log(tmp_path, f"""
        Apr 20 10:00:01 ubuntu kernel: [1.0] [UFW BLOCK] {_TCP_SUFFIX}
        Apr 20 10:00:02 fedora kernel: [2.0] FINAL_REJECT: {_TCP_SUFFIX}
        Apr 20 10:00:03 host   kernel: [3.0] DROPPED: {_TCP_SUFFIX}
    """)
    events = parse_firewall_log(f)
    assert len(events) == 3
    firewalls = {ev["firewall"] for ev in events}
    assert firewalls == {"ufw", "firewalld", "iptables"}
