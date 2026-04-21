# watch-chain

A Python CLI security log correlator for Linux systems.

Reads multiple log sources simultaneously — `auth.log`, UFW firewall logs, and `auditd` — and correlates events by IP address and time window to detect attack chains.

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
| `--ufw-log FILE` | Explicit path to ufw.log / kern.log |
| `--audit-log FILE` | Explicit path to audit/audit.log |

## Log sources

- `/var/log/auth.log` / `/var/log/secure` — SSH brute-force, sudo escalation, PAM failures
- `/var/log/ufw.log` — UFW firewall blocks and allows
- `/var/log/audit/audit.log` — auditd syscall and file access events

## Detected attack chains

| Chain | Description | Severity |
|---|---|---|
| `brute_force` | ≥5 failed logins from the same IP within the time window | medium |
| `brute_then_success` | Brute-force cluster followed by a successful login | critical |
| `scan_then_auth` | UFW blocks from an IP followed by a login attempt | high |
| `lateral_movement` | Successful login followed by suspicious commands (wget, curl, nc, bash, sh) | high / critical |

## How it works

Events from different log sources are parsed, normalised, and grouped by source IP address within a configurable time window. When events from multiple sources cluster around the same IP, watch-chain flags them as a potential attack chain (e.g. port scan → SSH brute-force → privilege escalation attempt).

## Requirements

See `requirements.txt`.
