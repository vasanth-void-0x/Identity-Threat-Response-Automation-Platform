"""tests/test_normalizer.py - Tests for the event normalization layer."""

from parsers.normalizer import normalize_batch, normalize_raw_event
from tests.conftest import make_raw_event


def test_normalize_basic_event():
    raw = make_raw_event()
    event = normalize_raw_event(raw)
    assert event.user == "alice"
    assert event.event_type == "logon_success"
    assert event.status == "success"
    assert event.source_ip == "192.0.2.10"


def test_normalize_handles_missing_fields():
    event = normalize_raw_event({"event_code": "4625", "timestamp": "2026-07-20T09:00:00Z"})
    assert event.user is None
    assert event.event_type == "logon_failure"


def test_normalize_batch_skips_bad_events():
    good = make_raw_event()
    bad = {"event_code": "4624"}  # missing timestamp -> should be skipped, not raise
    events = normalize_batch([good, bad])
    assert len(events) == 1


def test_powershell_event_type_mapping():
    raw = make_raw_event(event_code="4104", command_line="powershell -enc abc123", status="success")
    event = normalize_raw_event(raw)
    assert event.event_type == "powershell_script_block"
    assert event.command_line == "powershell -enc abc123"
