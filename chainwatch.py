import argparse
import html as html_module
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

__version__ = "1.1.0"

# ANSI colour codes — applied only when stdout is a real TTY
_ANSI_RED    = "\033[31m"
_ANSI_YELLOW = "\033[33m"
_ANSI_BLUE   = "\033[34m"
_ANSI_BOLD   = "\033[1m"
_ANSI_DIM    = "\033[2m"
_ANSI_RESET  = "\033[0m"

_SEV_COLOUR = {
    "critical": _ANSI_RED,
    "high":     _ANSI_YELLOW,
    "medium":   _ANSI_BLUE,
}


def _c(text: str, code: str) -> str:
    """Apply an ANSI code only when stdout is a real TTY."""
    if code and sys.stdout.isatty():
        return f"{code}{text}{_ANSI_RESET}"
    return text


# Syslog header: "Apr 20 03:06:34 hostname service[pid]: message"
_HEADER = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w()\-]+)(?:\[\d+\])?\s*:\s+(.*)$'
)

# SSH failure: "Failed password for [invalid user] bob from 1.2.3.4 port 22 ssh2"
_FAILED_SSH = re.compile(
    r'Failed \S+ for (?:invalid user )?(\S+) from ([\d.a-f:]+) port \d+'
)

# SSH success: "Accepted password for bob from 1.2.3.4 port 22 ssh2"
_ACCEPTED_SSH = re.compile(
    r'Accepted \S+ for (\S+) from ([\d.a-f:]+) port \d+'
)

# sudo command line: "bob : TTY=pts/3 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id"
_SUDO_CMD = re.compile(
    r'^(\S+)\s*:\s+TTY=\S+\s*;\s+PWD=\S+\s*;\s+USER=(\S+)\s*;\s+COMMAND=(.+)$'
)

# Detect Fedora/RHEL vs Debian/Ubuntu log path
_DEFAULT_PATHS = ["/var/log/auth.log", "/var/log/secure"]

# Firewall log auto-detection: UFW dedicated file → kernel logs → syslog
_FIREWALL_DEFAULT_PATHS = [
    "/var/log/ufw.log",    # Ubuntu: UFW dedicated log
    "/var/log/kern.log",   # Ubuntu/Debian: kernel log (UFW + nftables)
    "/var/log/messages",   # RHEL/Fedora/CentOS: kernel + system log (firewalld)
    "/var/log/syslog",     # Debian/Ubuntu: general syslog
]

# Action-detection patterns for each supported firewall, in priority order.
# Each entry: (compiled regex, action, firewall_name)
_FW_ACTION_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # UFW
    (re.compile(r'\[UFW BLOCK\]'),                              "BLOCK", "ufw"),
    (re.compile(r'\[UFW ALLOW\]'),                              "ALLOW", "ufw"),
    # firewalld (iptables/nftables backend): FINAL_REJECT, IN_<zone>_REJECT/DROP/ACCEPT
    (re.compile(r'\bFINAL_REJECT:|\bIN_\w+_(?:REJECT|DROP):'), "BLOCK", "firewalld"),
    (re.compile(r'\bIN_\w+_ACCEPT:'),                           "ALLOW", "firewalld"),
    # iptables LOG target with common prefixes
    (re.compile(r'\b(?:DROPPED?|REJECTED?)\s*:', re.IGNORECASE), "BLOCK", "iptables"),
    # nftables log statement (prefix often starts with "nft")
    (re.compile(r'\bnft\b[^:]*:'),                              "BLOCK", "nftables"),
]

# Minimum check: must have SRC= to be a netfilter packet log line
_NETFILTER_SRC = re.compile(r'\bSRC=[\dA-Fa-f.:]+')

# Key=value pairs emitted by netfilter log target (UFW, firewalld, iptables, nftables)
_KV = re.compile(r'(\w+)=([\S]*)')

# --- auditd log constants and helpers ---

_AUDIT_LOG_PATH = "/var/log/audit/audit.log"

# type=TYPE msg=audit(epoch.ms:seqnum): body
_AUDIT_RECORD = re.compile(r'^type=(\w+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)')

# Inner msg='...' block present on USER_* records; closed before trailing UID=/AUID=
_AUDIT_INNER = re.compile(r"\bmsg='(.*?)'(?=\s*[A-Z]+=|\s*$)")

# key=value: double-quoted value, or unquoted token (handles colons, parens, slashes, ?)
_AUDIT_KV = re.compile(r'(\w+)=(?:"([^"]*?)"|([^\s"\']+))')

# auditd hex-encodes strings with special chars: all hex digits, even length, >=4 chars
_AUDIT_HEX = re.compile(r'^[0-9A-Fa-f]{4,}$')

# The event types from auditd we care about
_AUDIT_TYPES = frozenset({"USER_AUTH", "USER_LOGIN", "ADD_USER", "DEL_USER", "SYSCALL", "EXECVE"})

# auid value meaning "not set" (uint32 -1)
_UNSET_AUID = "4294967295"


def _parse_audit_kv(s: str) -> dict[str, str]:
    result = {}
    for m in _AUDIT_KV.finditer(s):
        # group(2) = double-quoted value, group(3) = unquoted value
        result[m.group(1)] = m.group(2) if m.group(2) is not None else (m.group(3) or "")
    return result


def _decode_audit_hex(s: str) -> str:
    """Decode auditd hex-encoded strings (e.g. cmd=, EXECVE args)."""
    if _AUDIT_HEX.match(s) and len(s) % 2 == 0:
        try:
            return bytes.fromhex(s).decode("utf-8", errors="replace")
        except ValueError:
            pass
    return s


def _parse_audit_record(line: str) -> tuple[str, float, int, dict] | None:
    """
    Parse one audit log line into (type, epoch_float, seqnum, kv_dict).
    Returns None if the line doesn't match the audit record format.
    The kv_dict merges outer fields, inner msg='...' fields, and trailing UID/AUID fields.
    """
    m = _AUDIT_RECORD.match(line)
    if not m:
        return None

    rec_type, epoch_str, seq_str, body = m.groups()
    epoch = float(epoch_str)
    seqnum = int(seq_str)

    inner_kv: dict[str, str] = {}
    outer_body = body

    inner_m = _AUDIT_INNER.search(body)
    if inner_m:
        inner_kv = _parse_audit_kv(inner_m.group(1))
        outer_body = body[: inner_m.start()] + body[inner_m.end():]

    outer_kv = _parse_audit_kv(outer_body)

    # Merge: inner fields (acct, res, op, exe) take precedence over outer numeric fields
    kv = {**outer_kv, **inner_kv}
    return rec_type, epoch, seqnum, kv


def _resolve_user(kv: dict) -> str:
    """Best available username: human-readable AUID, then acct, then numeric auid."""
    auid_name = kv.get("AUID", "")
    if auid_name and auid_name != "unset":
        return auid_name
    acct = kv.get("acct", "")
    if acct:
        return acct
    auid = kv.get("auid", "")
    return "" if auid == _UNSET_AUID else auid


def _parse_timestamp(raw: str, _today: datetime | None = None) -> datetime:
    normalized = re.sub(r'\s+', ' ', raw.strip())
    today = _today or datetime.now()
    dt = datetime.strptime(f"{today.year} {normalized}", "%Y %b %d %H:%M:%S")
    # If the parsed date is in the future, the log entry is from the previous year
    # (e.g. a December entry parsed in January).
    if dt.date() > today.date():
        dt = dt.replace(year=today.year - 1)
    return dt


# ── line-level parsers (no file I/O, used by both batch and follow mode) ─────

def _parse_auth_lines(lines: list[str]) -> list[dict]:
    events: list[dict] = []
    for line in lines:
        m = _HEADER.match(line)
        if not m:
            continue
        raw_ts, hostname, service, message = m.groups()
        try:
            timestamp = _parse_timestamp(raw_ts)
        except ValueError:
            continue
        base = {"timestamp": timestamp, "hostname": hostname,
                "service": service, "message": message}
        fm = _FAILED_SSH.search(message)
        if fm and "sshd" in service.lower():
            events.append({**base, "event_type": "failed_login",
                           "user": fm.group(1), "source_ip": fm.group(2)})
            continue
        am = _ACCEPTED_SSH.search(message)
        if am and "sshd" in service.lower():
            events.append({**base, "event_type": "successful_login",
                           "user": am.group(1), "source_ip": am.group(2)})
            continue
        sm = _SUDO_CMD.match(message)
        if sm and service.lower() == "sudo":
            events.append({**base, "event_type": "sudo_usage",
                           "user": sm.group(1), "target_user": sm.group(2),
                           "command": sm.group(3).strip()})
    return events


def _parse_firewall_lines(lines: list[str]) -> list[dict]:
    events: list[dict] = []
    for line in lines:
        m = _HEADER.match(line)
        if not m:
            continue
        raw_ts, hostname, service, message = m.groups()
        action = firewall = None
        for pattern, act, fw_name in _FW_ACTION_PATTERNS:
            if pattern.search(message):
                action, firewall = act, fw_name
                break
        if action is None or not _NETFILTER_SRC.search(message):
            continue
        try:
            timestamp = _parse_timestamp(raw_ts)
        except ValueError:
            continue
        kv = dict(_KV.findall(message))
        raw_dpt = kv.get("DPT")
        dst_port = int(raw_dpt) if raw_dpt and raw_dpt.isdigit() else None
        events.append({
            "timestamp": timestamp, "hostname": hostname,
            "service": service, "message": message,
            "event_type": "fw_block" if action == "BLOCK" else "fw_allow",
            "action": action, "firewall": firewall,
            "src_ip": kv.get("SRC", ""), "dst_ip": kv.get("DST", ""),
            "dst_port": dst_port, "protocol": kv.get("PROTO", ""),
        })
    return events


def _parse_audit_lines(lines: list[str]) -> list[dict]:
    execve_args: dict[int, str] = {}
    for line in lines:
        parsed = _parse_audit_record(line)
        if not parsed:
            continue
        rec_type, _, seqnum, kv = parsed
        if rec_type != "EXECVE":
            continue
        argc = int(kv.get("argc", "0"))
        args = [_decode_audit_hex(kv.get(f"a{i}", "")) for i in range(argc)]
        execve_args[seqnum] = " ".join(args)

    events: list[dict] = []
    for line in lines:
        parsed = _parse_audit_record(line)
        if not parsed:
            continue
        rec_type, epoch, seqnum, kv = parsed
        if rec_type not in _AUDIT_TYPES or rec_type == "EXECVE":
            continue
        timestamp = datetime.fromtimestamp(epoch)
        pid = kv.get("pid", "")
        user = _resolve_user(kv)
        if rec_type == "USER_AUTH":
            events.append({"timestamp": timestamp, "event_type": "user_auth",
                           "user": kv.get("acct") or user, "pid": pid,
                           "result": kv.get("res", ""), "source_ip": kv.get("addr", "")})
        elif rec_type == "USER_LOGIN":
            events.append({"timestamp": timestamp, "event_type": "user_login",
                           "user": kv.get("acct") or user, "pid": pid,
                           "result": kv.get("res", ""), "source_ip": kv.get("addr", "")})
        elif rec_type == "ADD_USER":
            events.append({"timestamp": timestamp, "event_type": "add_user",
                           "user": user, "target_user": kv.get("acct", ""),
                           "pid": pid, "result": kv.get("res", ""), "command": None})
        elif rec_type == "DEL_USER":
            events.append({"timestamp": timestamp, "event_type": "del_user",
                           "user": user, "target_user": kv.get("acct", ""),
                           "pid": pid, "result": kv.get("res", ""), "command": None})
        elif rec_type == "SYSCALL" and kv.get("SYSCALL") == "execve":
            raw_success = kv.get("success", "")
            result = ("success" if raw_success == "yes"
                      else "failed" if raw_success == "no" else raw_success)
            exe = kv.get("exe", kv.get("comm", ""))
            events.append({"timestamp": timestamp, "event_type": "execve",
                           "user": user, "pid": pid, "result": result,
                           "command": execve_args.get(seqnum) or exe})
    return events


def parse_auth_log(log_path: str | None = None) -> list[dict]:
    """Read an auth log and return structured SSH and sudo events."""
    if log_path is None:
        for candidate in _DEFAULT_PATHS:
            if Path(candidate).exists():
                log_path = candidate
                break
        else:
            print(
                f"Error: no auth log found at {_DEFAULT_PATHS}. "
                "Pass an explicit path or run as root.",
                file=sys.stderr,
            )
            return []

    try:
        text = Path(log_path).read_text(errors="replace")
    except FileNotFoundError:
        print(f"Error: auth log not found at {log_path}.", file=sys.stderr)
        return []
    except PermissionError:
        print(
            f"Error: permission denied reading {log_path}. Try running as root.",
            file=sys.stderr,
        )
        return []

    events = _parse_auth_lines(text.splitlines())

    counts = {"failed_login": 0, "successful_login": 0, "sudo_usage": 0}
    for ev in events:
        counts[ev["event_type"]] += 1

    print(f"Parsed {log_path}")
    print(f"  failed logins:      {counts['failed_login']}")
    print(f"  successful logins:  {counts['successful_login']}")
    print(f"  sudo invocations:   {counts['sudo_usage']}")

    return events


def parse_firewall_log(log_path: str | None = None) -> list[dict]:
    """
    Read a firewall log and return structured block/allow events.
    Supports UFW, firewalld (FINAL_REJECT / IN_<zone>_DROP), iptables LOG
    target, and nftables. Auto-detects the log file if no path is given.
    """
    if log_path is None:
        for candidate in _FIREWALL_DEFAULT_PATHS:
            if Path(candidate).exists():
                log_path = candidate
                break
        else:
            print(
                f"Error: no firewall log found at {_FIREWALL_DEFAULT_PATHS}. "
                "Pass an explicit path or run as root.",
                file=sys.stderr,
            )
            return []

    try:
        text = Path(log_path).read_text(errors="replace")
    except FileNotFoundError:
        print(f"Error: firewall log not found at {log_path}.", file=sys.stderr)
        return []
    except PermissionError:
        print(
            f"Error: permission denied reading {log_path}. Try running as root.",
            file=sys.stderr,
        )
        return []

    events = _parse_firewall_lines(text.splitlines())

    fw_counts: dict[str, int] = defaultdict(int)
    for ev in events:
        fw_counts[ev["firewall"]] += 1
    blocks = sum(1 for e in events if e["event_type"] == "fw_block")
    allows = sum(1 for e in events if e["event_type"] == "fw_allow")

    print(f"Parsed {log_path}")
    print(f"  blocks: {blocks}  allows: {allows}", end="")
    if fw_counts:
        detail = "  (" + "  ".join(f"{fw}: {n}" for fw, n in sorted(fw_counts.items())) + ")"
        print(detail, end="")
    print()
    return events


# Backward-compatible alias
parse_ufw_log = parse_firewall_log


# ── journald parser ───────────────────────────────────────────────────────────

def _parse_journal_lines(lines: list[str]) -> tuple[list[dict], list[dict]]:
    """
    Parse journalctl -o json output.  Each line is a JSON object.
    Returns (auth_events, fw_events) using the same event schema as the
    file-based parsers so the output can be merged before correlation.
    """
    auth_events: list[dict] = []
    fw_events:   list[dict] = []

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue

        ts_us = rec.get("__REALTIME_TIMESTAMP")
        if not ts_us:
            continue
        try:
            timestamp = datetime.fromtimestamp(int(ts_us) / 1_000_000)
        except (ValueError, OSError):
            continue

        # MESSAGE is a string normally; a JSON byte-array when non-UTF-8
        msg = rec.get("MESSAGE", "")
        if isinstance(msg, list):
            try:
                msg = bytes(msg).decode("utf-8", errors="replace")
            except (TypeError, ValueError):
                msg = ""

        identifier = rec.get("SYSLOG_IDENTIFIER", "")
        hostname   = rec.get("_HOSTNAME", "")
        base = {"timestamp": timestamp, "hostname": hostname,
                "service": identifier, "message": msg}

        if identifier == "sshd":
            fm = _FAILED_SSH.search(msg)
            if fm:
                auth_events.append({**base, "event_type": "failed_login",
                                    "user": fm.group(1), "source_ip": fm.group(2)})
                continue
            am = _ACCEPTED_SSH.search(msg)
            if am:
                auth_events.append({**base, "event_type": "successful_login",
                                    "user": am.group(1), "source_ip": am.group(2)})
                continue

        if identifier == "sudo":
            sm = _SUDO_CMD.match(msg)
            if sm:
                auth_events.append({**base, "event_type": "sudo_usage",
                                    "user": sm.group(1), "target_user": sm.group(2),
                                    "command": sm.group(3).strip()})
                continue

        if identifier == "kernel":
            action = firewall = None
            for pattern, act, fw_name in _FW_ACTION_PATTERNS:
                if pattern.search(msg):
                    action, firewall = act, fw_name
                    break
            if action is not None and _NETFILTER_SRC.search(msg):
                kv = dict(_KV.findall(msg))
                raw_dpt = kv.get("DPT")
                dst_port = int(raw_dpt) if raw_dpt and raw_dpt.isdigit() else None
                fw_events.append({
                    **base,
                    "event_type": "fw_block" if action == "BLOCK" else "fw_allow",
                    "action": action, "firewall": firewall,
                    "src_ip": kv.get("SRC", ""), "dst_ip": kv.get("DST", ""),
                    "dst_port": dst_port, "protocol": kv.get("PROTO", ""),
                })

    return auth_events, fw_events


def parse_journal_log(
    since: datetime | None = None,
    until: datetime | None = None,
) -> tuple[list[dict], list[dict]]:
    """
    Query the systemd journal via journalctl and return (auth_events, fw_events).
    Pass --since / --until to scope the query; without them the full journal is read.
    """
    cmd = ["journalctl", "-o", "json", "--no-pager"]
    if since:
        cmd += ["--since", since.strftime("%Y-%m-%d %H:%M:%S")]
    if until:
        cmd += ["--until", until.strftime("%Y-%m-%d %H:%M:%S")]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=120
        )
    except FileNotFoundError:
        print("Error: journalctl not found — is this a systemd system?", file=sys.stderr)
        return [], []
    except PermissionError:
        print("Error: permission denied running journalctl. Try running as root.",
              file=sys.stderr)
        return [], []

    auth_events, fw_events = _parse_journal_lines(result.stdout.splitlines())

    a_counts: dict[str, int] = {}
    for ev in auth_events:
        a_counts[ev["event_type"]] = a_counts.get(ev["event_type"], 0) + 1

    print("Parsed systemd journal")
    for et, n in sorted(a_counts.items()):
        print(f"  {et + ':':<20} {n}")
    if fw_events:
        fw_name_counts: dict[str, int] = defaultdict(int)
        for ev in fw_events:
            fw_name_counts[ev["firewall"]] += 1
        blocks = sum(1 for e in fw_events if e["event_type"] == "fw_block")
        allows = sum(1 for e in fw_events if e["event_type"] == "fw_allow")
        detail = "  (" + "  ".join(
            f"{fw}: {n}" for fw, n in sorted(fw_name_counts.items())
        ) + ")"
        print(f"  fw_block: {blocks}  fw_allow: {allows}{detail}")
    if not a_counts and not fw_events:
        print("  (no matching events found)")

    return auth_events, fw_events


def parse_audit_log(log_path: str | None = None) -> list[dict]:
    """Read an auditd log and return structured security events."""
    path = log_path or _AUDIT_LOG_PATH

    try:
        lines = Path(path).read_text(errors="replace").splitlines()
    except FileNotFoundError:
        print(f"Error: audit log not found at {path}.", file=sys.stderr)
        return []
    except PermissionError:
        print(
            f"Error: permission denied reading {path}. Try running as root.",
            file=sys.stderr,
        )
        return []

    events = _parse_audit_lines(lines)

    counts: dict[str, int] = {}
    for ev in events:
        counts[ev["event_type"]] = counts.get(ev["event_type"], 0) + 1

    print(f"Parsed {path}")
    for et, n in sorted(counts.items()):
        print(f"  {et + ':':<16} {n}")
    if not counts:
        print("  (no matching events found)")

    return events


# --- correlation constants ---

_BRUTE_THRESHOLD = 5  # failed logins needed to declare brute_force

# Commands that, when run shortly after an SSH login, indicate post-exploitation
_SUSPICIOUS_BINS = frozenset({"wget", "curl", "nc", "ncat", "netcat", "bash", "sh"})
# Subset that implies outbound network access — escalates severity to critical
_NETWORK_BINS = frozenset({"wget", "curl", "nc", "ncat", "netcat"})


def _event_ip(ev: dict) -> str:
    """Return source IP regardless of which parser produced the event."""
    return ev.get("source_ip") or ev.get("src_ip") or ""


def _command_bin(command: str) -> str:
    """Extract the bare binary name from a command string."""
    if not command:
        return ""
    return os.path.basename(command.split()[0])


def correlate_events(
    auth_events: list[dict],
    ufw_events: list[dict],
    audit_events: list[dict],
    window_seconds: int = 600,
    quiet: bool = False,
) -> list[dict]:
    """
    Correlate events from all three log parsers into named attack-chain incidents.

    Detected chains
    ---------------
    brute_force       — ≥5 failed_login from the same IP within the time window
    brute_then_login — brute_force cluster immediately followed by a successful_login
    portscan_then_login    — ufw_block(s) from an IP preceding a login attempt from that IP
    lateral_movement  — successful_login followed by suspicious execve by the same user

    Returns a list of incident dicts sorted by start_time.
    """
    window = timedelta(seconds=window_seconds)
    incidents: list[dict] = []

    # ── partition events by type ──────────────────────────────────────────────
    failed_logins = sorted(
        (e for e in auth_events if e["event_type"] == "failed_login"),
        key=lambda e: e["timestamp"],
    )
    successful_logins = sorted(
        (e for e in auth_events if e["event_type"] == "successful_login"),
        key=lambda e: e["timestamp"],
    )
    ufw_blocks = sorted(
        (e for e in ufw_events if e["event_type"] == "fw_block"),
        key=lambda e: e["timestamp"],
    )
    execve_events = sorted(
        (e for e in audit_events if e["event_type"] == "execve"),
        key=lambda e: e["timestamp"],
    )

    # ── group by IP / user for O(1) lookup ────────────────────────────────────
    fails_by_ip: dict[str, list[dict]] = defaultdict(list)
    for ev in failed_logins:
        if ip := _event_ip(ev):
            fails_by_ip[ip].append(ev)

    success_by_ip: dict[str, list[dict]] = defaultdict(list)
    for ev in successful_logins:
        if ip := _event_ip(ev):
            success_by_ip[ip].append(ev)

    blocks_by_ip: dict[str, list[dict]] = defaultdict(list)
    for ev in ufw_blocks:
        if ip := _event_ip(ev):
            blocks_by_ip[ip].append(ev)

    auth_attempts_by_ip: dict[str, list[dict]] = defaultdict(list)
    for ev in failed_logins + successful_logins:
        if ip := _event_ip(ev):
            auth_attempts_by_ip[ip].append(ev)

    execve_by_user: dict[str, list[dict]] = defaultdict(list)
    for ev in execve_events:
        if user := ev.get("user", ""):
            execve_by_user[user].append(ev)

    sudo_by_user: dict[str, list[dict]] = defaultdict(list)
    for ev in auth_events:
        if ev["event_type"] == "sudo_usage":
            if user := ev.get("user", ""):
                sudo_by_user[user].append(ev)

    # ── 1 & 2: brute_force / brute_then_login ──────────────────────────────
    for ip, fails in fails_by_ip.items():
        i = 0
        while i < len(fails):
            t0 = fails[i]["timestamp"]
            # Extend the cluster: all failures within window of the first event
            j = i
            while j < len(fails) and (fails[j]["timestamp"] - t0) <= window:
                j += 1
            cluster = fails[i:j]

            if len(cluster) >= _BRUTE_THRESHOLD:
                cluster_end = cluster[-1]["timestamp"]
                # Successful login from the same IP within one window after the cluster
                follow_successes = [
                    e for e in success_by_ip.get(ip, [])
                    if cluster_end <= e["timestamp"] <= cluster_end + window
                ]
                if follow_successes:
                    incidents.append({
                        "chain_type": "brute_then_login",
                        "source_ip": ip,
                        "events": cluster + follow_successes,
                        "start_time": t0,
                        "end_time": follow_successes[-1]["timestamp"],
                        "severity": "critical",
                    })
                else:
                    incidents.append({
                        "chain_type": "brute_force",
                        "source_ip": ip,
                        "events": cluster,
                        "start_time": t0,
                        "end_time": cluster_end,
                        "severity": "medium",
                    })
                i = j  # skip past the reported cluster
            else:
                i += 1

    # ── 3: portscan_then_login ─────────────────────────────────────────────────────
    for ip, blocks in blocks_by_ip.items():
        ip_auths = auth_attempts_by_ip.get(ip, [])
        if not ip_auths:
            continue

        # An auth attempt qualifies if at least one block from this IP preceded it
        # within the window.  Collect both the qualifying auths and their paired blocks.
        qualifying_auths: list[dict] = []
        paired_block_ids: set[int] = set()
        for auth_ev in ip_auths:
            preceding = [
                b for b in blocks
                if timedelta(0) <= auth_ev["timestamp"] - b["timestamp"] <= window
            ]
            if preceding:
                qualifying_auths.append(auth_ev)
                paired_block_ids.update(id(b) for b in preceding)

        if not qualifying_auths:
            continue

        used_blocks = [b for b in blocks if id(b) in paired_block_ids]
        # Require blocks against at least 2 distinct ports — a single blocked
        # connection could be normal noise, not a scan.
        distinct_ports = {b["dst_port"] for b in used_blocks if b.get("dst_port") is not None}
        if len(distinct_ports) < 2:
            continue

        all_events = sorted(used_blocks + qualifying_auths, key=lambda e: e["timestamp"])
        incidents.append({
            "chain_type": "portscan_then_login",
            "source_ip": ip,
            "events": all_events,
            "start_time": all_events[0]["timestamp"],
            "end_time": all_events[-1]["timestamp"],
            "severity": "high",
        })

    # ── 4: lateral_movement ───────────────────────────────────────────────────
    for login in successful_logins:
        login_user = login.get("user", "")
        if not login_user:
            continue
        login_time = login["timestamp"]

        follow_execs = [
            e for e in execve_by_user.get(login_user, [])
            if timedelta(0) <= e["timestamp"] - login_time <= window
            and _command_bin(e.get("command", "")) in _SUSPICIOUS_BINS
        ]
        follow_sudos = [
            e for e in sudo_by_user.get(login_user, [])
            if timedelta(0) <= e["timestamp"] - login_time <= window
        ]
        if not follow_execs and not follow_sudos:
            continue

        bins_used = {_command_bin(e.get("command", "")) for e in follow_execs}
        sudo_to_root = any(e.get("target_user") == "root" for e in follow_sudos)
        severity = "critical" if (bins_used & _NETWORK_BINS or sudo_to_root) else "high"

        follow_all = sorted(follow_execs + follow_sudos, key=lambda e: e["timestamp"])
        incidents.append({
            "chain_type": "lateral_movement",
            "source_ip": _event_ip(login),
            "events": [login] + follow_all,
            "start_time": login_time,
            "end_time": max(e["timestamp"] for e in follow_all),
            "severity": severity,
        })

    incidents.sort(key=lambda inc: inc["start_time"])

    # ── summary ───────────────────────────────────────────────────────────────
    total_events = len(auth_events) + len(ufw_events) + len(audit_events)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    counts: dict[str, int] = defaultdict(int)
    for inc in incidents:
        counts[inc["chain_type"]] += 1

    if not quiet:
        print(f"Correlated {total_events} events → {len(incidents)} incident(s)")
        for chain_type, n in sorted(counts.items()):
            sevs = [inc["severity"] for inc in incidents if inc["chain_type"] == chain_type]
            worst = min(sevs, key=lambda s: severity_order.get(s, 99))
            print(f"  {chain_type + ':':<24} {n}  (worst severity: {worst})")
        if not incidents:
            print("  (no attack chains detected)")

    return incidents


# ── terminal report helpers ───────────────────────────────────────────────────

_W = 62  # report width


def _rule(char: str = "─") -> str:
    return char * _W


def _sev_tag(severity: str) -> str:
    label = f"[{severity.upper():<8}]"
    return _c(label, _SEV_COLOUR.get(severity.lower(), ""))


def _fmt_duration(start: datetime, end: datetime) -> str:
    total = int((end - start).total_seconds())
    if total < 60:
        return f"{total}s"
    m, s = divmod(total, 60)
    if m < 60:
        return f"{m}m {s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m"


def _fmt_event(ev: dict) -> str:
    """Format one contributing event as a single terminal line."""
    et   = ev["event_type"]
    ts   = ev["timestamp"].strftime("%H:%M:%S")
    ip   = ev.get("source_ip") or ev.get("src_ip") or ""
    user = ev.get("user", "")

    if et in ("failed_login", "successful_login", "user_auth", "user_login"):
        return f"    {ts}  {et:<20}  user={user:<12}  ip={ip}"
    if et in ("fw_block", "fw_allow"):
        port  = ev.get("dst_port", "")
        proto = ev.get("protocol", "")
        return f"    {ts}  {et:<20}  src={ip:<15}  port={port}/{proto}"
    if et == "execve":
        cmd = (ev.get("command") or "")[:52]
        return f"    {ts}  {et:<20}  user={user:<12}  cmd={cmd}"
    if et == "sudo_usage":
        cmd = (ev.get("command") or "")[:52]
        return f"    {ts}  {et:<20}  user={user:<12}  cmd={cmd}"
    if et in ("add_user", "del_user"):
        target = ev.get("target_user", "")
        return f"    {ts}  {et:<20}  user={user:<12}  target={target}"
    return f"    {ts}  {et}"


def _print_terminal_report(
    incidents: list[dict],
    auth_events: list[dict],
    ufw_events: list[dict],
    audit_events: list[dict],
    window_seconds: int,
) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    n_auth, n_ufw, n_aud = len(auth_events), len(ufw_events), len(audit_events)

    print(_c(_rule("═"), _ANSI_BOLD))
    print(_c(f"  chain-watch  —  Attack Chain Correlation Report", _ANSI_BOLD))
    print(_c(_rule("═"), _ANSI_BOLD))
    print(f"  Generated   {now}")
    print(f"  Window      {window_seconds} s")
    print(f"  Parsed      {n_auth + n_ufw + n_aud} events"
          f"  ({n_auth} auth  ·  {n_ufw} ufw  ·  {n_aud} audit)")
    print(f"  Incidents   {len(incidents)}")

    if not incidents:
        print()
        print(_c("  No attack chains detected.", _ANSI_DIM))
        print(_rule())
        return

    for i, inc in enumerate(incidents, 1):
        print()
        print(_rule())
        sev      = inc["severity"]
        duration = _fmt_duration(inc["start_time"], inc["end_time"])
        date_str = inc["start_time"].strftime("%Y-%m-%d")
        t_start  = inc["start_time"].strftime("%H:%M:%S")
        t_end    = inc["end_time"].strftime("%H:%M:%S")

        print(f"  {_sev_tag(sev)}  #{i}  {inc['chain_type']}  —  {inc['source_ip']}")
        print(f"  {_c(date_str, _ANSI_DIM)}  {t_start}  →  {t_end}  "
              f"({duration})  ·  {len(inc['events'])} events")
        print(_rule())
        print()
        for ev in inc["events"]:
            print(_fmt_event(ev))

    print()
    print(_rule("═"))


# ── JSON export ───────────────────────────────────────────────────────────────

def _ev_to_dict(ev: dict) -> dict:
    """Serialise one event dict to JSON-safe types (datetime → ISO string)."""
    return {
        k: (v.isoformat() if isinstance(v, datetime) else v)
        for k, v in ev.items()
        if k != "message"   # omit raw log line — verbose and redundant
    }


def _write_json_report(
    path: str,
    incidents: list[dict],
    auth_events: list[dict],
    ufw_events: list[dict],
    audit_events: list[dict],
    window_seconds: int,
) -> None:
    payload = {
        "generated": datetime.now().isoformat(),
        "window_seconds": window_seconds,
        "event_counts": {
            "auth":  len(auth_events),
            "ufw":   len(ufw_events),
            "audit": len(audit_events),
            "total": len(auth_events) + len(ufw_events) + len(audit_events),
        },
        "incident_count": len(incidents),
        "incidents": [
            {
                "chain_type":       inc["chain_type"],
                "source_ip":        inc["source_ip"],
                "severity":         inc["severity"],
                "start_time":       inc["start_time"].isoformat(),
                "end_time":         inc["end_time"].isoformat(),
                "duration_seconds": int((inc["end_time"] - inc["start_time"]).total_seconds()),
                "event_count":      len(inc["events"]),
                "events":           [_ev_to_dict(e) for e in inc["events"]],
            }
            for inc in incidents
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    print(f"JSON report written to {path}")


# ── HTML export ───────────────────────────────────────────────────────────────

_HTML_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 14px;
       background: #f4f6f9; color: #222; padding: 24px; }
h1   { font-size: 24px; color: #1a3a5c; margin-bottom: 4px; }
h2   { font-size: 16px; color: #1a3a5c; margin: 28px 0 10px;
       border-bottom: 2px solid #1a3a5c; padding-bottom: 4px; }
.subtitle { color: #555; margin-bottom: 24px; font-size: 13px; }
.summary-box  { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 28px; }
.summary-card { background: #fff; border-radius: 6px; padding: 14px 20px;
                box-shadow: 0 1px 4px rgba(0,0,0,0.1); min-width: 120px; text-align: center; }
.summary-card .number { font-size: 28px; font-weight: 700; }
.summary-card .label  { font-size: 11px; color: #777; margin-top: 2px;
                         text-transform: uppercase; letter-spacing: 0.4px; }
.num-critical { color: #c0392b; }
.num-high     { color: #d35400; }
.num-medium   { color: #1a56b0; }
.incident-block { background: #fff; border-radius: 8px; padding: 18px 22px;
                  margin-bottom: 20px; box-shadow: 0 2px 6px rgba(0,0,0,0.07);
                  border-left: 5px solid #ccc; }
.incident-block.critical { border-color: #e74c3c; }
.incident-block.high     { border-color: #e67e22; }
.incident-block.medium   { border-color: #2980b9; }
.incident-block.low      { border-color: #27ae60; }
.incident-header { display: flex; align-items: baseline; gap: 10px; margin-bottom: 6px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 3px;
         font-size: 11px; font-weight: 700; letter-spacing: 0.5px; }
.badge.critical { background: #fdecea; color: #c0392b; }
.badge.high     { background: #fef0e6; color: #d35400; }
.badge.medium   { background: #e8f0fe; color: #1a56b0; }
.badge.low      { background: #e6f4ea; color: #1e7e34; }
.chain-type { font-size: 16px; font-weight: 600; color: #1a3a5c; }
.meta-line  { font-size: 12px; color: #666; margin-bottom: 10px; }
details { margin-top: 8px; }
summary { cursor: pointer; font-size: 12px; color: #1a56b0; user-select: none; }
summary:hover { text-decoration: underline; }
.event-list { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 12px;
              margin-top: 8px; background: #f8f9fb; border-radius: 4px;
              padding: 10px 14px; color: #333; }
.event-row  { padding: 2px 0; border-bottom: 1px solid #eee; white-space: nowrap; }
.event-row:last-child { border-bottom: none; }
.ev-ts   { color: #888; margin-right: 8px; }
.ev-type { color: #1a3a5c; font-weight: 600; margin-right: 8px; min-width: 160px;
           display: inline-block; }
.ev-detail { color: #444; }
"""


def _html_event_row(ev: dict) -> str:
    e  = html_module.escape
    et = ev["event_type"]
    ts = ev["timestamp"].strftime("%H:%M:%S")

    ip   = e(ev.get("source_ip") or ev.get("src_ip") or "")
    user = e(ev.get("user", ""))

    if et in ("failed_login", "successful_login", "user_auth", "user_login"):
        detail = f"user={user}  ip={ip}"
    elif et in ("fw_block", "fw_allow"):
        port  = e(str(ev.get("dst_port", "")))
        proto = e(ev.get("protocol", ""))
        detail = f"src={ip}  port={port}/{proto}"
    elif et in ("execve", "sudo_usage"):
        cmd    = e((ev.get("command") or "")[:80])
        detail = f"user={user}  cmd={cmd}"
    elif et in ("add_user", "del_user"):
        target = e(ev.get("target_user", ""))
        detail = f"user={user}  target={target}"
    else:
        detail = f"user={user}"

    return (
        f'<div class="event-row">'
        f'<span class="ev-ts">{ts}</span>'
        f'<span class="ev-type">{e(et)}</span>'
        f'<span class="ev-detail">{detail}</span>'
        f'</div>'
    )


def _write_html_report(
    path: str,
    incidents: list[dict],
    auth_events: list[dict],
    ufw_events: list[dict],
    audit_events: list[dict],
    window_seconds: int,
) -> None:
    e   = html_module.escape
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sev_counts: dict[str, int] = defaultdict(int)
    for inc in incidents:
        sev_counts[inc["severity"]] += 1

    parts: list[str] = [f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>chain-watch Report — {e(now)}</title>
<style>{_HTML_CSS}</style>
</head>
<body>
<h1>chain-watch &mdash; Attack Chain Correlation Report</h1>
<p class="subtitle">Generated: {e(now)} &nbsp;&middot;&nbsp; Window: {window_seconds}&thinsp;s
 &nbsp;&middot;&nbsp; Parsed: {len(auth_events)} auth / {len(ufw_events)} ufw / {len(audit_events)} audit events</p>
"""]

    # ── summary cards ──────────────────────────────────────────────────────────
    parts.append('<div class="summary-box">\n')
    parts.append(
        f'<div class="summary-card">'
        f'<div class="number">{len(incidents)}</div>'
        f'<div class="label">Incidents</div></div>\n'
    )
    for sev, cls in (("critical", "num-critical"), ("high", "num-high"), ("medium", "num-medium")):
        n = sev_counts.get(sev, 0)
        parts.append(
            f'<div class="summary-card">'
            f'<div class="number {cls}">{n}</div>'
            f'<div class="label">{sev.capitalize()}</div></div>\n'
        )
    parts.append('</div>\n')

    if not incidents:
        parts.append('<p style="color:#666;">No attack chains detected.</p>\n')
    else:
        parts.append('<h2>Incidents</h2>\n')
        for i, inc in enumerate(incidents, 1):
            sev      = inc["severity"]
            duration = _fmt_duration(inc["start_time"], inc["end_time"])
            t_start  = inc["start_time"].strftime("%Y-%m-%d %H:%M:%S")
            t_end    = inc["end_time"].strftime("%H:%M:%S")

            parts.append(f'<div class="incident-block {e(sev)}">\n')
            parts.append(
                f'<div class="incident-header">'
                f'<span class="badge {e(sev)}">{e(sev.upper())}</span>'
                f'<span class="chain-type">#{i} &nbsp;{e(inc["chain_type"])}</span>'
                f'</div>\n'
            )
            parts.append(
                f'<div class="meta-line">'
                f'<strong>Source IP:</strong> {e(inc["source_ip"])} &nbsp;&middot;&nbsp; '
                f'<strong>Time:</strong> {e(t_start)} &rarr; {e(t_end)} ({e(duration)}) &nbsp;&middot;&nbsp; '
                f'<strong>Events:</strong> {len(inc["events"])}'
                f'</div>\n'
            )
            parts.append('<details><summary>Show contributing events</summary>\n')
            parts.append('<div class="event-list">\n')
            for ev in inc["events"]:
                parts.append(_html_event_row(ev) + "\n")
            parts.append('</div></details>\n')
            parts.append('</div>\n')

    parts.append('</body></html>\n')

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(parts))
    print(f"HTML report written to {path}")


# ── time-window filter ───────────────────────────────────────────────────────

_TIME_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%H:%M:%S",
    "%H:%M",
]


def _parse_time_arg(value: str) -> datetime:
    """Parse --since / --until value. Time-only formats assume today's date."""
    for fmt in _TIME_FORMATS:
        try:
            dt = datetime.strptime(value, fmt)
            if fmt in ("%H:%M:%S", "%H:%M"):
                dt = dt.replace(year=datetime.now().year,
                                month=datetime.now().month,
                                day=datetime.now().day)
            return dt
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(
        f"Cannot parse time {value!r}. "
        "Use HH:MM, HH:MM:SS, or YYYY-MM-DD HH:MM[:SS]."
    )


def _filter_events(
    events: list[dict],
    since: datetime | None,
    until: datetime | None,
) -> list[dict]:
    result = events
    if since:
        result = [e for e in result if e["timestamp"] >= since]
    if until:
        result = [e for e in result if e["timestamp"] <= until]
    return result


# ── follow mode ───────────────────────────────────────────────────────────────

_AUTH_EVENT_TYPES  = frozenset({"failed_login", "successful_login", "sudo_usage"})
_FW_EVENT_TYPES    = frozenset({"fw_block", "fw_allow"})
_AUDIT_EVENT_TYPES = frozenset({"execve", "user_auth", "user_login", "add_user", "del_user"})


def _print_follow_incident(inc: dict) -> None:
    sev      = inc["severity"]
    duration = _fmt_duration(inc["start_time"], inc["end_time"])
    t_start  = inc["start_time"].strftime("%H:%M:%S")
    t_end    = inc["end_time"].strftime("%H:%M:%S")
    print()
    print(_rule())
    print(f"  {_sev_tag(sev)}  {inc['chain_type']}  —  {inc['source_ip']}")
    print(f"  {t_start}  →  {t_end}  ({duration})  ·  {len(inc['events'])} events")
    print(_rule())
    for ev in inc["events"]:
        print(_fmt_event(ev))
    print()


def _follow_mode(
    auth_path: str | None,
    ufw_path: str | None,
    audit_path: str | None,
    window_seconds: int,
    poll_interval: int,
    use_journal: bool = False,
) -> None:
    monitored = [
        (auth_path,  "auth"),
        (ufw_path,   "fw"),
        (audit_path, "audit"),
    ]

    # Start from the current end of each file — don't replay history
    offsets: dict[str, int] = {}
    for path, _ in monitored:
        if path:
            try:
                offsets[path] = Path(path).stat().st_size
            except (FileNotFoundError, PermissionError):
                offsets[path] = 0

    event_buffer: list[dict] = []
    seen_incidents: set[tuple] = set()
    window = timedelta(seconds=window_seconds)
    journal_since = datetime.now()

    print(_c(f"Following logs (poll every {poll_interval}s, window {window_seconds}s)… "
             "Ctrl+C to stop.", _ANSI_DIM))
    try:
        while True:
            time.sleep(poll_interval)
            now = datetime.now()
            got_new = False

            for path, kind in monitored:
                if not path:
                    continue
                try:
                    size = Path(path).stat().st_size
                except (FileNotFoundError, PermissionError):
                    continue

                prev = offsets.get(path, size)
                if size < prev:
                    prev = 0  # file rotated / truncated
                if size <= prev:
                    offsets[path] = size
                    continue

                with open(path, errors="replace") as fh:
                    fh.seek(prev)
                    new_text = fh.read()
                offsets[path] = size

                new_lines = new_text.splitlines()
                if kind == "auth":
                    new_events = _parse_auth_lines(new_lines)
                elif kind == "fw":
                    new_events = _parse_firewall_lines(new_lines)
                else:
                    new_events = _parse_audit_lines(new_lines)

                if new_events:
                    event_buffer.extend(new_events)
                    got_new = True

            if use_journal:
                poll_until = datetime.now()
                cmd = [
                    "journalctl", "-o", "json", "--no-pager",
                    "--since", journal_since.strftime("%Y-%m-%d %H:%M:%S"),
                    "--until", poll_until.strftime("%Y-%m-%d %H:%M:%S"),
                ]
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True,
                        errors="replace", timeout=30,
                    )
                    j_auth, j_fw = _parse_journal_lines(result.stdout.splitlines())
                    if j_auth or j_fw:
                        event_buffer.extend(j_auth)
                        event_buffer.extend(j_fw)
                        got_new = True
                except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
                    pass
                journal_since = poll_until

            if not got_new:
                continue

            # Drop events and seen-incident keys older than 2× window
            cutoff = now - window * 2
            event_buffer = [e for e in event_buffer if e["timestamp"] >= cutoff]
            seen_incidents = {k for k in seen_incidents if k[2] >= cutoff}

            auth_buf  = [e for e in event_buffer if e["event_type"] in _AUTH_EVENT_TYPES]
            fw_buf    = [e for e in event_buffer if e["event_type"] in _FW_EVENT_TYPES]
            audit_buf = [e for e in event_buffer if e["event_type"] in _AUDIT_EVENT_TYPES]

            incidents = correlate_events(
                auth_buf, fw_buf, audit_buf, window_seconds=window_seconds, quiet=True
            )
            for inc in incidents:
                key = (inc["chain_type"], inc["source_ip"], inc["start_time"])
                if key not in seen_incidents:
                    seen_incidents.add(key)
                    _print_follow_incident(inc)

    except KeyboardInterrupt:
        print("\nStopped.")


# ── path resolution helper ────────────────────────────────────────────────────

def _resolve_log_paths(
    log_dir: str | None,
    auth: str | None,
    ufw: str | None,
    audit: str | None,
) -> tuple[str | None, str | None, str | None]:
    """
    If --log-dir is given, look for standard log filenames inside it.
    Explicit --auth-log / --ufw-log / --audit-log always take priority.
    Returning None for a path tells the parser to use its own auto-detection.
    """
    if log_dir:
        d = Path(log_dir)
        if auth is None:
            for name in ("auth.log", "secure"):
                if (d / name).exists():
                    auth = str(d / name)
                    break
        if ufw is None:
            for name in ("ufw.log", "kern.log"):
                if (d / name).exists():
                    ufw = str(d / name)
                    break
        if audit is None:
            for sub in ("audit/audit.log", "audit.log"):
                if (d / sub).exists():
                    audit = str(d / sub)
                    break
    return auth, ufw, audit


# ── main entry point ──────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="chainwatch",
        description="Correlate Linux security logs to detect attack chains.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  sudo chainwatch                              auto-detect all log paths
  sudo chainwatch /var/log                     use a specific log directory
  sudo chainwatch --window 300                 5-minute correlation window
  sudo chainwatch --since 03:00 --until 05:00  analyse a specific time range
  sudo chainwatch --since "2026-04-21 00:00"   from a specific date/time
  sudo chainwatch --follow                     watch logs and alert in real time
  sudo chainwatch --follow --interval 10       poll every 10 seconds
  sudo chainwatch --journal                    read from systemd journal
  sudo chainwatch --journal --since 06:00      journal entries since 06:00
  sudo chainwatch --json out.json              write JSON report
  sudo chainwatch --html report.html           write HTML report
  chainwatch --auth-log auth.log.sample        test with a specific file
""",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "log_dir", nargs="?", metavar="LOG_DIR",
        help="directory containing log files (auto-detects standard paths if omitted)",
    )
    parser.add_argument(
        "--auth-log", metavar="FILE",
        help="explicit path to auth.log or /var/log/secure",
    )
    parser.add_argument(
        "--ufw-log", metavar="FILE",
        help="explicit path to firewall log (ufw.log, kern.log, /var/log/messages)",
    )
    parser.add_argument(
        "--audit-log", metavar="FILE",
        help="explicit path to audit/audit.log",
    )
    parser.add_argument(
        "--window", type=int, default=600, metavar="SECONDS",
        help="correlation time window in seconds (default: 600)",
    )
    parser.add_argument(
        "--follow", action="store_true",
        help="watch log files for new entries and alert on new incidents in real time",
    )
    parser.add_argument(
        "--interval", type=int, default=5, metavar="SECONDS",
        help="polling interval for --follow mode in seconds (default: 5)",
    )
    parser.add_argument(
        "--since", metavar="TIME", type=_parse_time_arg,
        help="ignore events before TIME (HH:MM, HH:MM:SS, or YYYY-MM-DD HH:MM[:SS])",
    )
    parser.add_argument(
        "--until", metavar="TIME", type=_parse_time_arg,
        help="ignore events after TIME (same formats as --since)",
    )
    parser.add_argument(
        "--journal", action="store_true",
        help=(
            "read from systemd journal via journalctl "
            "(merged with any file-based sources; use --since to limit scope)"
        ),
    )
    parser.add_argument(
        "--json", metavar="FILE", dest="json_out",
        help="write JSON report to FILE",
    )
    parser.add_argument(
        "--html", metavar="FILE", dest="html_out",
        help="write self-contained HTML report to FILE",
    )
    args = parser.parse_args()

    auth_path, ufw_path, audit_path = _resolve_log_paths(
        args.log_dir, args.auth_log, args.ufw_log, args.audit_log,
    )

    if args.follow:
        _follow_mode(auth_path, ufw_path, audit_path, args.window, args.interval, args.journal)
        return

    print(_c("Parsing logs…", _ANSI_DIM))
    auth_events  = parse_auth_log(auth_path)
    ufw_events   = parse_ufw_log(ufw_path)
    audit_events = parse_audit_log(audit_path)

    if args.journal:
        since_arg = getattr(args, "since", None)
        until_arg = getattr(args, "until", None)
        j_auth, j_fw = parse_journal_log(since=since_arg, until=until_arg)
        auth_events = auth_events + j_auth
        ufw_events  = ufw_events  + j_fw

    print()

    since = getattr(args, "since", None)
    until = getattr(args, "until", None)
    if since and until and since > until:
        print(
            f"Error: --since ({since.strftime('%Y-%m-%d %H:%M:%S')}) is after "
            f"--until ({until.strftime('%Y-%m-%d %H:%M:%S')}) — no events will match.",
            file=sys.stderr,
        )
        sys.exit(1)
    if since or until:
        auth_events  = _filter_events(auth_events,  since, until)
        ufw_events   = _filter_events(ufw_events,   since, until)
        audit_events = _filter_events(audit_events, since, until)
        lo = since.strftime("%H:%M:%S") if since else "start"
        hi = until.strftime("%H:%M:%S") if until else "end"
        print(_c(f"  Time filter: {lo} → {hi}  "
                 f"({len(auth_events)} auth  ·  {len(ufw_events)} ufw  ·  {len(audit_events)} audit)", _ANSI_DIM))
        print()

    incidents = correlate_events(
        auth_events, ufw_events, audit_events, window_seconds=args.window,
    )

    print()
    _print_terminal_report(incidents, auth_events, ufw_events, audit_events, args.window)

    if args.json_out:
        _write_json_report(
            args.json_out, incidents, auth_events, ufw_events, audit_events, args.window,
        )
    if args.html_out:
        _write_html_report(
            args.html_out, incidents, auth_events, ufw_events, audit_events, args.window,
        )


if __name__ == "__main__":
    main()
