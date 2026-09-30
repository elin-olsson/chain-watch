import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from chainwatch import correlate_events, _write_pdf_report

BASE = datetime(2026, 4, 21, 10, 0, 0)


def ts(s):
    return BASE + timedelta(seconds=s)


def fail(ip, s, user="root"):
    return {"event_type": "failed_login", "source_ip": ip, "user": user, "timestamp": ts(s)}


def block(ip, port, s):
    return {"event_type": "fw_block", "src_ip": ip, "dst_port": port,
            "protocol": "TCP", "firewall": "ufw", "timestamp": ts(s)}


def _write(incidents, auth, ufw, audit):
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        path = f.name
    try:
        _write_pdf_report(path, incidents, auth, ufw, audit, 600)
        with open(path, "rb") as f:
            return f.read()
    finally:
        os.unlink(path)


def test_writes_valid_pdf_with_incidents():
    auth = [fail("1.2.3.4", i * 10) for i in range(5)]
    incidents = correlate_events(auth, [], [], window_seconds=600)
    data = _write(incidents, auth, [], [])
    assert data.startswith(b"%PDF-1.4")
    assert data.rstrip().endswith(b"%%EOF")


def test_writes_valid_pdf_with_no_incidents():
    data = _write([], [], [], [])
    assert data.startswith(b"%PDF-1.4")


def test_handles_multiple_chain_types():
    auth = [fail("1.2.3.4", i * 10) for i in range(5)]
    ufw = [block("5.6.7.8", 22, i * 5) for i in range(3)]
    incidents = correlate_events(auth, ufw, [], window_seconds=600)
    data = _write(incidents, auth, ufw, [])
    assert data.startswith(b"%PDF-1.4")
