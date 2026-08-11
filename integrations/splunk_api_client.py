"""Live, analyst-triggered Splunk Enterprise REST ingestion for ITRAP.

Uses a bearer token against Splunk's management API (normally port 8089).
Secrets are never logged. Search is bounded by time, relevant Windows event
IDs and a hard result cap. No background polling is performed.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

import requests

from core.config import SplunkAPIConfig, load_config
from core.exceptions import ITRAPBaseException
from core.logger import get_logger

logger = get_logger(__name__)

RELEVANT_EVENT_CODES = (4624, 4625, 4672, 4688, 4720, 4728, 4732, 4740, 4768, 4769, 4771, 4776)
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.:\-]+$")


def _raw_field(raw: Any, *field_names: str) -> str | None:
    """Extract common Windows rendered/XML fields when Splunk has not parsed them."""
    text = str(raw or "")
    for name in field_names:
        patterns = (
            rf"(?im)^\s*{re.escape(name)}\s*:\s*([^\r\n]+)",
            rf"(?i)<Data\s+Name=['\"]{re.escape(name)}['\"]>([^<]*)</Data>",
            rf"(?i){re.escape(name)}\s*=\s*['\"]([^'\"]+)['\"]",
        )
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                value = match.group(1).strip()
                if value and value not in {"-", "N/A", "None"}:
                    return value
    return None


class SplunkAPIError(ITRAPBaseException):
    pass


class SplunkAPIClient:
    def __init__(self, config: SplunkAPIConfig | None = None):
        self.config = config or load_config().splunk_api

    @property
    def is_configured(self) -> bool:
        return self.config.is_configured

    def _headers(self) -> dict[str, str]:
        if not self.is_configured:
            raise SplunkAPIError("Splunk is not configured; set SPLUNK_TOKEN in .env")
        return {"Authorization": f"Bearer {self.config.token}", "Accept": "application/json"}

    def _request(self, method: str, path: str, **kwargs):
        try:
            response = requests.request(
                method, f"{self.config.url.rstrip('/')}{path}", headers=self._headers(),
                verify=self.config.verify_ssl, timeout=self.config.request_timeout_seconds, **kwargs,
            )
        except requests.exceptions.SSLError as exc:
            raise SplunkAPIError("Splunk SSL verification failed; use SPLUNK_VERIFY_SSL=false only for trusted localhost labs") from exc
        except requests.exceptions.Timeout as exc:
            raise SplunkAPIError("Splunk API request timed out") from exc
        except requests.exceptions.ConnectionError as exc:
            raise SplunkAPIError("Could not connect to the Splunk management API") from exc
        except requests.exceptions.RequestException as exc:
            raise SplunkAPIError(f"Splunk API request failed: {exc}") from exc
        if response.status_code in (401, 403):
            raise SplunkAPIError("Splunk authentication/authorization failed; verify the token and its user permissions")
        if response.status_code >= 400:
            raise SplunkAPIError(f"Splunk API returned HTTP {response.status_code}")
        return response

    def test_connection(self) -> dict[str, Any]:
        try:
            response = self._request("GET", "/services/server/info", params={"output_mode": "json"})
            payload = response.json()
            entry = (payload.get("entry") or [{}])[0]
            content = entry.get("content") or {}
            return {"connected": True, "version": content.get("version", "unknown"), "server_name": entry.get("name", "Splunk")}
        except (ValueError, IndexError, TypeError):
            return {"connected": False, "error": "Splunk returned malformed server information"}
        except SplunkAPIError as exc:
            return {"connected": False, "error": str(exc)}

    def export_events(self, earliest: str = "-15m", max_events: int | None = None) -> list[dict[str, Any]]:
        if not _SAFE_NAME.fullmatch(self.config.index) or not _SAFE_NAME.fullmatch(self.config.sourcetype):
            raise SplunkAPIError("Unsafe Splunk index or sourcetype configuration")
        limit = min(max_events or self.config.max_events, 1000)
        codes = ",".join(str(code) for code in RELEVANT_EVENT_CODES)
        search = (
            f'search index="{self.config.index}" sourcetype="{self.config.sourcetype}" earliest={earliest} '
            f'EventCode IN ({codes}) | sort 0 _time | head {limit}'
        )
        response = self._request(
            "POST", "/services/search/jobs/export",
            data={"search": search, "output_mode": "json", "exec_mode": "oneshot"},
        )
        records: list[dict[str, Any]] = []
        for line in response.text.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SplunkAPIError("Splunk search export returned malformed JSON") from exc
            result = item.get("result")
            if isinstance(result, dict):
                records.append(result)
        return records[:limit]


def event_fingerprint(result: dict[str, Any]) -> str:
    basis = "|".join(str(result.get(k, "")) for k in ("_indextime", "_time", "host", "EventCode", "RecordNumber", "_raw"))
    return "splunk:" + hashlib.sha256(basis.encode("utf-8", errors="ignore")).hexdigest()


def splunk_result_to_raw_event(r: dict[str, Any]) -> dict[str, Any]:
    raw = r.get("_raw")
    event_code = str(r.get("EventCode") or r.get("EventID") or "")
    parsed_user = (
        r.get("TargetUserName")
        or r.get("SubjectUserName")
        or r.get("Account_Name")
        or r.get("user")
        or _raw_field(raw, "TargetUserName", "SubjectUserName", "Account Name")
    )
    return {
        "timestamp": r.get("_time") or r.get("TimeCreated"),
        "event_code": event_code,
        "user": parsed_user,
        "domain": r.get("TargetDomainName") or r.get("Account_Domain"),
        "source_ip": r.get("IpAddress") or r.get("src_ip") or r.get("src") or _raw_field(raw, "IpAddress", "Source Network Address"),
        "source_port": r.get("IpPort") or r.get("src_port"),
        "hostname": r.get("ComputerName") or r.get("host") or r.get("WorkstationName") or _raw_field(raw, "WorkstationName", "Workstation Name"),
        "device": r.get("WorkstationName") or r.get("host"),
        "logon_type": r.get("LogonType"),
        "process_name": r.get("NewProcessName") or r.get("ProcessName"),
        "process_id": r.get("NewProcessId") or r.get("ProcessId"),
        "parent_process": r.get("ParentProcessName"),
        "command_line": r.get("CommandLine") or r.get("Process_Command_Line"),
        "target_user": r.get("MemberName"),
        "group_name": r.get("TargetUserName") if event_code in ("4728", "4732") else None,
        "provider": "splunk_windows",
        "channel": r.get("LogName") or "Security",
        "raw_splunk_event": raw,
    }


def sync_splunk_events(earliest: str = "-15m", max_events: int | None = None) -> dict[str, Any]:
    from database import repository
    from detection_engine.engine import DetectionEngine
    from parsers.normalizer import normalize_raw_event

    result = {"success": False, "error": None, "events_retrieved": 0, "events_ingested": 0,
              "alerts_generated": 0, "incidents_generated": 0,
              "synced_at": datetime.now(timezone.utc).isoformat()}
    client = SplunkAPIClient()
    try:
        raw_results = client.export_events(earliest=earliest, max_events=max_events)
        result["events_retrieved"] = len(raw_results)
        new_results, fingerprints = [], []
        for raw in raw_results:
            fp = event_fingerprint(raw)
            if not repository.is_splunk_fingerprint_seen(fp):
                new_results.append(raw)
                fingerprints.append(fp)
        normalized, accepted_fingerprints = [], []
        for raw, fingerprint in zip(new_results, fingerprints):
            try:
                normalized.append(normalize_raw_event(splunk_result_to_raw_event(raw), source="splunk_api"))
                accepted_fingerprints.append(fingerprint)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Skipping an unparsable Splunk event: %s", exc)
        repository.save_events(normalized)
        repository.mark_splunk_fingerprints_seen(accepted_fingerprints)
        alerts, incidents = DetectionEngine().run(normalized)
        repository.save_alerts(alerts)
        repository.save_incidents(incidents)
        result.update(success=True, events_ingested=len(normalized), alerts_generated=len(alerts), incidents_generated=len(incidents))
    except SplunkAPIError as exc:
        result["error"] = str(exc)
        logger.error("Splunk sync failed: %s", exc)
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"Splunk ingestion pipeline failed: {exc}"
        logger.error("Splunk ingestion failed: %s", exc)
    repository.save_splunk_sync_state(result)
    return result
