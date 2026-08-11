"""
integrations/wazuh_api_client.py
Experimental, optional Wazuh REST connector. Complements (does not replace) the
existing file-based integrations/wazuh_adapter.py JSON export adapter.

Configuration comes ONLY from environment variables (see core.config.
WazuhAPIConfig) - WAZUH_API_URL, WAZUH_API_USERNAME, WAZUH_API_PASSWORD,
WAZUH_VERIFY_SSL, WAZUH_REQUEST_TIMEOUT. Nothing is hardcoded, and
credentials/tokens are never logged (core.logger's SecretRedactingFilter
also scrubs common secret patterns as a second line of defense).

IMPORTANT - endpoint assumptions: this client authenticates against the
standard Wazuh Manager RESTful API JWT flow (`POST /security/user/authenticate`
with HTTP Basic Auth), which is consistent across Wazuh 4.x. Alert retrieval
uses a configurable `/alerts` path. Wazuh 4.x deployments commonly query
alerts via the Wazuh Indexer (OpenSearch) API rather than the manager API -
if your deployment does that, set WAZUH_API_URL to your indexer endpoint;
the JWT auth step will simply be skipped if the indexer uses basic auth
directly on each request instead. This module has been built and unit
tested against mocked responses matching Wazuh's documented API contracts,
but has NOT been validated against a live Wazuh server - verify the alert
endpoint path against your specific deployment before relying on it.
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from core.config import WazuhAPIConfig, load_config
from core.exceptions import ITRAPBaseException
from core.logger import get_logger

logger = get_logger(__name__)


class WazuhAPIError(ITRAPBaseException):
    """Raised for Wazuh API connection, authentication, or response errors."""


class WazuhAuthenticationError(WazuhAPIError):
    """Raised when Wazuh API credentials are rejected."""


class WazuhAPIClient:
    """
    Thin, defensive wrapper around the Wazuh REST API. Handles JWT
    authentication/refresh, pagination, timeouts, SSL verification, and
    malformed/empty responses without raising uncaught exceptions into
    calling code - callers get clear WazuhAPIError subclasses instead.
    """

    TOKEN_TTL_SECONDS = 900  # Wazuh JWT tokens are short-lived (~15 min default)

    def __init__(self, config: WazuhAPIConfig | None = None):
        self.config = config or load_config().wazuh_api
        self._token: str | None = None
        self._token_obtained_at: float = 0.0

    # -- configuration / status -----------------------------------------------
    @property
    def is_configured(self) -> bool:
        return self.config.is_configured

    def masked_url(self) -> str:
        """Returns the API URL for display purposes - never exposes credentials."""
        return self.config.api_url or "(not configured)"

    # -- authentication ---------------------------------------------------------
    def _token_is_valid(self) -> bool:
        return bool(self._token) and (time.time() - self._token_obtained_at) < self.TOKEN_TTL_SECONDS

    def authenticate(self, force: bool = False) -> str:
        """
        Obtains (or refreshes) a JWT token via HTTP Basic Auth against
        POST /security/user/authenticate. Never logs the username, password,
        or resulting token.
        """
        if not self.is_configured:
            raise WazuhAPIError(
                "Wazuh API is not configured - set WAZUH_API_URL, WAZUH_API_USERNAME, "
                "WAZUH_API_PASSWORD in your environment."
            )

        if not force and self._token_is_valid():
            return self._token  # type: ignore[return-value]

        url = f"{self.config.api_url.rstrip('/')}/security/user/authenticate"

        try:
            resp = requests.post(
                url,
                auth=(self.config.username, self.config.password),
                verify=self.config.verify_ssl,
                timeout=self.config.request_timeout_seconds,
            )
        except requests.exceptions.SSLError as exc:
            raise WazuhAPIError(
                "SSL verification failed connecting to Wazuh API. If you understand the "
                "risk, set WAZUH_VERIFY_SSL=false (not recommended outside an isolated lab)."
            ) from exc
        except requests.exceptions.Timeout as exc:
            raise WazuhAPIError(f"Wazuh API authentication timed out after "
                                 f"{self.config.request_timeout_seconds}s") from exc
        except requests.exceptions.ConnectionError as exc:
            raise WazuhAPIError(f"Could not connect to Wazuh API at {self.masked_url()}: "
                                 f"connection refused or host unreachable") from exc
        except requests.exceptions.RequestException as exc:
            raise WazuhAPIError(f"Wazuh API request failed: {exc}") from exc

        if resp.status_code == 401:
            raise WazuhAuthenticationError("Wazuh API rejected the configured credentials (401 Unauthorized)")
        if resp.status_code == 403:
            raise WazuhAuthenticationError("Wazuh API credentials are valid but access is forbidden (403)")
        if resp.status_code >= 400:
            raise WazuhAPIError(f"Wazuh API authentication failed with HTTP {resp.status_code}")

        try:
            payload = resp.json()
        except ValueError as exc:
            raise WazuhAPIError("Wazuh API returned a malformed (non-JSON) authentication response") from exc

        token = (payload.get("data") or {}).get("token")
        if not token:
            raise WazuhAPIError("Wazuh API authentication response did not include a token")

        self._token = token
        self._token_obtained_at = time.time()
        logger.info("Wazuh API authentication successful")
        return token

    def _headers(self) -> dict[str, str]:
        token = self.authenticate()
        return {"Authorization": f"Bearer {token}"}

    # -- connection test ----------------------------------------------------------
    def test_connection(self) -> dict[str, Any]:
        """Used by the Settings page 'Test Connection' button. Never raises - returns a status dict."""
        if not self.is_configured:
            return {"connected": False, "error": "Wazuh API is not configured (missing environment variables)"}
        try:
            self.authenticate(force=True)
            return {"connected": True, "error": None}
        except WazuhAuthenticationError as exc:
            return {"connected": False, "error": f"Authentication failed: {exc}"}
        except WazuhAPIError as exc:
            return {"connected": False, "error": str(exc)}

    # -- alert retrieval --------------------------------------------------------
    def get_alerts(
        self,
        hours_back: int = 24,
        max_events: int = 500,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Retrieves alerts from the last `hours_back` hours, paginating until
        `max_events` is reached or the API reports no more results. Returns
        raw Wazuh alert dicts (not yet normalized). Never raises for empty
        results - only for genuine connection/auth/response failures.
        """
        if not self.is_configured:
            raise WazuhAPIError("Wazuh API is not configured")

        since = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        url = f"{self.config.api_url.rstrip('/')}/alerts"

        all_records: list[dict[str, Any]] = []
        offset = 0

        while len(all_records) < max_events:
            limit = min(page_size, max_events - len(all_records))
            params = {
                "limit": limit,
                "offset": offset,
                "sort": "-timestamp",
                "q": f"timestamp>{since.isoformat()}",
            }

            try:
                resp = requests.get(
                    url, headers=self._headers(), params=params,
                    verify=self.config.verify_ssl, timeout=self.config.request_timeout_seconds,
                )
            except requests.exceptions.Timeout as exc:
                raise WazuhAPIError(f"Wazuh API request timed out after "
                                     f"{self.config.request_timeout_seconds}s (offset={offset})") from exc
            except requests.exceptions.ConnectionError as exc:
                raise WazuhAPIError(f"Lost connection to Wazuh API while paginating (offset={offset})") from exc
            except requests.exceptions.RequestException as exc:
                raise WazuhAPIError(f"Wazuh API request failed: {exc}") from exc

            if resp.status_code == 401:
                # Token may have expired mid-sync - refresh once and retry this page.
                self.authenticate(force=True)
                continue
            if resp.status_code >= 400:
                raise WazuhAPIError(f"Wazuh API returned HTTP {resp.status_code} retrieving alerts")

            try:
                payload = resp.json()
            except ValueError as exc:
                raise WazuhAPIError(f"Wazuh API returned a malformed (non-JSON) alerts response "
                                     f"at offset={offset}") from exc

            records = None
            data_field = payload.get("data")
            if isinstance(data_field, dict):
                records = data_field.get("affected_items")
            elif isinstance(data_field, list):
                records = data_field

            if not isinstance(records, list):
                logger.warning("Unexpected Wazuh alerts response shape at offset=%d - stopping pagination", offset)
                break
            if not records:
                break  # no more results

            all_records.extend(records)
            offset += len(records)

            if len(records) < limit:
                break  # last page was partial - no more data

        return all_records[:max_events]


def event_fingerprint(raw_alert: dict[str, Any]) -> str:
    """
    Deterministic fingerprint used for duplicate-ingestion prevention.
    Prefers Wazuh's own alert id when present; falls back to a stable hash
    of the record's identifying fields so re-syncing an overlapping time
    window never double-ingests the same alert.
    """
    wazuh_id = raw_alert.get("id") or raw_alert.get("_id")
    if wazuh_id:
        return f"wazuh:{wazuh_id}"

    basis = "|".join(str(raw_alert.get(k, "")) for k in (
        "timestamp", "rule", "agent", "full_log", "syscheck",
    ))
    return "wazuh:" + hashlib.sha256(basis.encode("utf-8", errors="ignore")).hexdigest()


def wazuh_alert_to_raw_event(alert: dict[str, Any]) -> dict[str, Any]:
    """
    Maps a raw Wazuh API alert record into the flexible-key dict shape that
    parsers.normalizer.normalize_raw_event() understands - the same target
    shape used by the file-based integrations/wazuh_adapter.py, so both
    ingestion paths feed the detection engine identically.
    """
    data = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}
    win = data.get("win", {}) if isinstance(data.get("win"), dict) else {}
    eventdata = win.get("eventdata", {}) if isinstance(win.get("eventdata"), dict) else {}
    system = win.get("system", {}) if isinstance(win.get("system"), dict) else {}
    agent = alert.get("agent", {}) if isinstance(alert.get("agent"), dict) else {}
    rule = alert.get("rule", {}) if isinstance(alert.get("rule"), dict) else {}

    return {
        "timestamp": alert.get("timestamp"),
        "event_code": system.get("eventID") or str(rule.get("id", "")) or None,
        "user": eventdata.get("targetUserName") or eventdata.get("subjectUserName") or data.get("srcuser"),
        "source_ip": eventdata.get("ipAddress") or data.get("srcip"),
        "hostname": agent.get("name") or system.get("computer"),
        "device": agent.get("id"),
        "process_name": eventdata.get("newProcessName"),
        "command_line": eventdata.get("commandLine"),
        "target_user": eventdata.get("memberName"),
        "group_name": eventdata.get("targetUserName") if system.get("eventID") in ("4728", "4732") else None,
        "status": "success" if system.get("eventID") == "4624" else (
            "failure" if system.get("eventID") == "4625" else None
        ),
        "wazuh_alert_id": alert.get("id"),
        "wazuh_rule_description": rule.get("description"),
        "wazuh_rule_level": rule.get("level"),
        "raw_wazuh_alert": alert,
    }


def sync_wazuh_events(hours_back: int = 24, max_events: int = 500) -> dict[str, Any]:
    """
    Full sync orchestration: authenticate, retrieve alerts, deduplicate,
    normalize, run through the detection engine, and persist everything.
    Only ever invoked by an explicit analyst action (Settings page 'Sync
    Wazuh Events' button, or a direct CLI call) - never on a background
    timer/poller. Never raises - always returns a result dict so the UI can
    display a clear success/error status; the app keeps working in offline
    demo mode regardless of the outcome.
    """
    from database import repository
    from detection_engine.engine import DetectionEngine
    from parsers.normalizer import normalize_batch

    result: dict[str, Any] = {
        "success": False,
        "error": None,
        "events_retrieved": 0,
        "events_ingested": 0,
        "alerts_generated": 0,
        "incidents_generated": 0,
        "synced_at": datetime.now(timezone.utc).isoformat(),
    }

    client = WazuhAPIClient()

    if not client.is_configured:
        result["error"] = "Wazuh API is not configured (missing WAZUH_API_URL/USERNAME/PASSWORD)"
        repository.save_wazuh_sync_state(result)
        return result

    try:
        raw_alerts = client.get_alerts(hours_back=hours_back, max_events=max_events)
    except WazuhAPIError as exc:
        result["error"] = str(exc)
        logger.error("Wazuh sync failed during retrieval: %s", exc)
        repository.save_wazuh_sync_state(result)
        return result

    result["events_retrieved"] = len(raw_alerts)

    # Duplicate-ingestion prevention via deterministic fingerprint
    new_alerts = []
    fingerprints = []
    for raw in raw_alerts:
        fp = event_fingerprint(raw)
        if not repository.is_wazuh_fingerprint_seen(fp):
            new_alerts.append(raw)
            fingerprints.append(fp)

    if not new_alerts:
        result["success"] = True
        result["error"] = None
        repository.save_wazuh_sync_state(result)
        return result

    raw_events = [wazuh_alert_to_raw_event(a) for a in new_alerts]
    normalized = normalize_batch(raw_events, source="wazuh_api")

    try:
        repository.save_events(normalized)
        repository.mark_wazuh_fingerprints_seen(fingerprints)

        engine = DetectionEngine()
        alerts, incidents = engine.run(normalized)
        repository.save_alerts(alerts)
        repository.save_incidents(incidents)

        result["success"] = True
        result["events_ingested"] = len(normalized)
        result["alerts_generated"] = len(alerts)
        result["incidents_generated"] = len(incidents)
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"Ingestion pipeline failed: {exc}"
        logger.error("Wazuh sync failed during ingestion: %s", exc)

    repository.save_wazuh_sync_state(result)
    return result
