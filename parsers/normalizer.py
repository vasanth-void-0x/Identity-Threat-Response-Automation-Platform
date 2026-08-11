"""
parsers/normalizer.py
Converts raw Windows/Sysmon-style event dicts (regardless of source parser) into
the common NormalizedEvent schema. All format-specific parsers funnel through this.
"""

from __future__ import annotations

from typing import Any

from core.constants import EVENT_ID_DESCRIPTIONS
from core.logger import get_logger
from models.event import NormalizedEvent

logger = get_logger(__name__)

_EVENT_TYPE_MAP = {
    "4624": "logon_success",
    "4625": "logon_failure",
    "4634": "logoff",
    "4648": "logon_explicit_creds",
    "4672": "special_privileges_assigned",
    "4688": "process_created",
    "4720": "account_created",
    "4722": "account_enabled",
    "4725": "account_disabled",
    "4726": "account_deleted",
    "4728": "global_group_member_added",
    "4732": "local_group_member_added",
    "4740": "account_locked_out",
    "4768": "kerberos_tgt_request",
    "4769": "kerberos_service_ticket",
    "4771": "kerberos_preauth_failed",
    "4776": "credential_validation",
    "4104": "powershell_script_block",
    "1": "sysmon_process_creation",
    "3": "sysmon_network_connection",
    "11": "sysmon_file_creation",
    "22": "sysmon_dns_query",
}


def normalize_raw_event(raw: dict[str, Any], source: str = "sample_data") -> NormalizedEvent:
    """
    Accepts a raw event dict using flexible/aliased keys (as produced by
    json_parser, csv_parser, windows_event_parser, sysmon_parser) and returns
    a validated NormalizedEvent. Missing fields are handled safely.
    """
    event_code = str(raw.get("event_code") or raw.get("EventID") or raw.get("event_id_code") or "")
    event_type = raw.get("event_type") or _EVENT_TYPE_MAP.get(event_code, "unknown")

    status = raw.get("status")
    if not status:
        if event_type == "logon_success":
            status = "success"
        elif event_type == "logon_failure":
            status = "failure"
        else:
            status = raw.get("result", "unknown")

    location = raw.get("location") or {}

    try:
        event = NormalizedEvent(
            timestamp=raw.get("timestamp") or raw.get("TimeCreated"),
            source=source,
            provider=raw.get("provider", "windows"),
            channel=raw.get("channel", "Security"),
            event_type=event_type,
            event_code=event_code,
            user=raw.get("user") or raw.get("TargetUserName") or raw.get("SubjectUserName"),
            domain=raw.get("domain") or raw.get("TargetDomainName"),
            target_user=raw.get("target_user") or raw.get("MemberName"),
            source_ip=raw.get("source_ip") or raw.get("ip") or raw.get("IpAddress"),
            source_port=_safe_int(raw.get("source_port") or raw.get("IpPort")),
            destination_ip=raw.get("destination_ip") or raw.get("DestinationIp"),
            destination_port=_safe_int(raw.get("destination_port") or raw.get("DestinationPort")),
            hostname=raw.get("hostname") or raw.get("WorkstationName") or raw.get("Computer"),
            device_id=raw.get("device") or raw.get("device_id"),
            logon_type=str(raw.get("logon_type") or raw.get("LogonType") or "") or None,
            process_name=raw.get("process_name") or raw.get("NewProcessName") or raw.get("Image"),
            process_id=str(raw.get("process_id") or raw.get("NewProcessId") or "") or None,
            parent_process=raw.get("parent_process") or raw.get("ParentProcessName") or raw.get("ParentImage"),
            command_line=raw.get("command_line") or raw.get("CommandLine") or raw.get("ScriptBlockText"),
            status=status,
            failure_reason=raw.get("failure_reason") or raw.get("FailureReason"),
            country=location.get("country") or raw.get("country"),
            city=location.get("city") or raw.get("city"),
            latitude=location.get("lat") or raw.get("latitude"),
            longitude=location.get("lon") or raw.get("longitude"),
            raw_event=raw,
            metadata={
                "event_description": EVENT_ID_DESCRIPTIONS.get(event_code, "Unknown event"),
                "target_role": raw.get("target_role"),
                "action": raw.get("action"),
            },
        )
    except Exception as exc:  # noqa: BLE001
        from core.exceptions import ParsingError
        raise ParsingError(f"Failed to normalize event: {exc}") from exc

    return event


def _safe_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None and value != "" else None
    except (ValueError, TypeError):
        return None


def normalize_batch(raw_events: list[dict[str, Any]], source: str = "sample_data") -> list[NormalizedEvent]:
    normalized = []
    for raw in raw_events:
        try:
            normalized.append(normalize_raw_event(raw, source=source))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Skipping unparsable event: %s", exc)
    return normalized
