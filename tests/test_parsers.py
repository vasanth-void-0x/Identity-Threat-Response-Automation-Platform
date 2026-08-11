"""tests/test_parsers.py - Tests for JSON/CSV parsers."""

import json

from parsers.csv_parser import parse_csv_file
from parsers.json_parser import parse_json_file
from tests.conftest import make_raw_event


def test_parse_json_file(tmp_path):
    events = [make_raw_event(user="alice"), make_raw_event(user="bob", event_code="4625", status="failure")]
    path = tmp_path / "events.json"
    path.write_text(json.dumps(events))

    result = parse_json_file(path)
    assert len(result) == 2
    assert result[0].user in ("alice", "bob")
    assert result[0].event_type in ("logon_success", "logon_failure")


def test_parse_json_file_missing_raises(tmp_path):
    from core.exceptions import ParsingError
    import pytest
    with pytest.raises(ParsingError):
        parse_json_file(tmp_path / "does_not_exist.json")


def test_parse_csv_file(tmp_path):
    path = tmp_path / "events.csv"
    path.write_text("event_code,timestamp,user,source_ip,hostname,status\n"
                     "4624,2026-07-20T09:00:00Z,alice,192.0.2.10,WKS-ALICE-01,success\n")
    result = parse_csv_file(path)
    assert len(result) == 1
    assert result[0].user == "alice"
    assert result[0].event_type == "logon_success"
