<img src="banner.png" alt="chain-watch banner">

# chain-watch

A Python CLI security log correlator for Linux systems.

Reads multiple log sources simultaneously — `auth.log`, UFW/firewalld logs, and `auditd` — and correlates events by IP address and time window to detect attack chains.

## Usage

```
sudo python3 chainwatch.py [LOG_DIR] [options]
```

| Flag | Description |
|---|---|
| `--window SECONDS` | Correlation time window (default: 600) |
| `--json FILE` | Write JSON report to FILE |
| `--html FILE` | Write self-contained HTML report to FILE |
| `--auth-log FILE` | Explicit path to auth.log / secure |
| `--ufw-log FILE` | Explicit path to firewall log (ufw.log, kern.log, /var/log/messages) |
| `--audit-log FILE` | Explicit path to audit/audit.log |

## Log sources

- `/var/log/auth.log` / `/var/log/secure` — SSH brute-force, sudo escalation, PAM failures
- `/var/log/ufw.log` / `/var/log/messages` — UFW, firewalld, iptables, nftables
- `/var/log/audit/audit.log` — auditd syscall and file access events

## Detected attack chains

| Chain | Description | Severity |
|---|---|---|
| `brute_force` | ≥5 failed logins from the same IP within the time window | medium |
| `brute_then_login` | Brute-force cluster followed by a successful login | critical |
| `portscan_then_login` | Firewall blocks from an IP followed by a login attempt | high |
| `lateral_movement` | Successful login followed by suspicious commands (wget, curl, nc, bash, sh) | high / critical |

## Supported firewalls

| Firewall | Log format detected |
|---|---|
| UFW | `[UFW BLOCK]` / `[UFW ALLOW]` |
| firewalld | `FINAL_REJECT:` / `IN_<zone>_DROP:` / `IN_<zone>_REJECT:` |
| iptables | `DROPPED:` / `REJECTED:` |
| nftables | `nft ...:` |

## How it works

Events from different log sources are parsed, normalised, and grouped by source IP address within a configurable time window. When events from multiple sources cluster around the same IP, chain-watch flags them as a potential attack chain (e.g. port scan → SSH brute-force → privilege escalation attempt).

## Requirements

See `requirements.txt`. No runtime dependencies — stdlib only. Install `pytest` for tests:

```
pip install pytest
python -m pytest tests/
```

---

<p align="center">
  <img src="logo.png" alt="chain-watch logo" width="140">
</p>
