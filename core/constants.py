"""core/constants.py - Shared constant definitions used across the platform."""

# --- Windows Security Event IDs -------------------------------------------------
WIN_EVENT_LOGON_SUCCESS = "4624"
WIN_EVENT_LOGON_FAILURE = "4625"
WIN_EVENT_LOGOFF = "4634"
WIN_EVENT_LOGON_EXPLICIT_CREDS = "4648"
WIN_EVENT_SPECIAL_PRIVILEGES = "4672"
WIN_EVENT_PROCESS_CREATED = "4688"
WIN_EVENT_ACCOUNT_CREATED = "4720"
WIN_EVENT_ACCOUNT_ENABLED = "4722"
WIN_EVENT_ACCOUNT_DISABLED = "4725"
WIN_EVENT_ACCOUNT_DELETED = "4726"
WIN_EVENT_GLOBAL_GROUP_MEMBER_ADDED = "4728"
WIN_EVENT_LOCAL_GROUP_MEMBER_ADDED = "4732"
WIN_EVENT_ACCOUNT_LOCKED_OUT = "4740"
WIN_EVENT_KERBEROS_TGT_REQUEST = "4768"
WIN_EVENT_KERBEROS_SERVICE_TICKET = "4769"
WIN_EVENT_KERBEROS_PREAUTH_FAILED = "4771"
WIN_EVENT_CREDENTIAL_VALIDATION = "4776"
WIN_EVENT_POWERSHELL_SCRIPT_BLOCK = "4104"

SYSMON_PROCESS_CREATION = "1"
SYSMON_NETWORK_CONNECTION = "3"
SYSMON_FILE_CREATION = "11"
SYSMON_DNS_QUERY = "22"

EVENT_ID_DESCRIPTIONS = {
    WIN_EVENT_LOGON_SUCCESS: "Successful logon",
    WIN_EVENT_LOGON_FAILURE: "Failed logon",
    WIN_EVENT_LOGOFF: "Logoff",
    WIN_EVENT_LOGON_EXPLICIT_CREDS: "Logon using explicit credentials",
    WIN_EVENT_SPECIAL_PRIVILEGES: "Special privileges assigned to new logon",
    WIN_EVENT_PROCESS_CREATED: "New process created",
    WIN_EVENT_ACCOUNT_CREATED: "User account created",
    WIN_EVENT_ACCOUNT_ENABLED: "User account enabled",
    WIN_EVENT_ACCOUNT_DISABLED: "User account disabled",
    WIN_EVENT_ACCOUNT_DELETED: "User account deleted",
    WIN_EVENT_GLOBAL_GROUP_MEMBER_ADDED: "Member added to global security group",
    WIN_EVENT_LOCAL_GROUP_MEMBER_ADDED: "Member added to local security group",
    WIN_EVENT_ACCOUNT_LOCKED_OUT: "User account locked out",
    WIN_EVENT_KERBEROS_TGT_REQUEST: "Kerberos authentication ticket (TGT) requested",
    WIN_EVENT_KERBEROS_SERVICE_TICKET: "Kerberos service ticket requested",
    WIN_EVENT_KERBEROS_PREAUTH_FAILED: "Kerberos pre-authentication failed",
    WIN_EVENT_CREDENTIAL_VALIDATION: "Credential validation (NTLM)",
    WIN_EVENT_POWERSHELL_SCRIPT_BLOCK: "PowerShell script block logging",
    SYSMON_PROCESS_CREATION: "Sysmon: Process creation",
    SYSMON_NETWORK_CONNECTION: "Sysmon: Network connection",
    SYSMON_FILE_CREATION: "Sysmon: File creation",
    SYSMON_DNS_QUERY: "Sysmon: DNS query",
}

# --- Severity bands ---------------------------------------------------------------
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

SEVERITY_ORDER = [SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL]

RISK_BANDS = [
    (0, 29, SEVERITY_LOW),
    (30, 59, SEVERITY_MEDIUM),
    (60, 79, SEVERITY_HIGH),
    (80, 100, SEVERITY_CRITICAL),
]


def score_to_severity(score: int) -> str:
    score = max(0, min(100, score))
    for low, high, label in RISK_BANDS:
        if low <= score <= high:
            return label
    return SEVERITY_LOW


# --- Incident / alert status -------------------------------------------------------
STATUS_NEW = "new"
STATUS_TRIAGED = "triaged"
STATUS_INVESTIGATING = "investigating"
STATUS_CONTAINED = "contained"
STATUS_RESOLVED = "resolved"
STATUS_FALSE_POSITIVE = "false_positive"

# --- Suspicious PowerShell indicators (safe, detection-only strings) --------------
SUSPICIOUS_POWERSHELL_INDICATORS = [
    "-encodedcommand",
    "-enc ",
    "frombase64string",
    "invoke-expression",
    "iex(",
    "iex (",
    "downloadstring",
    "webclient",
    "invoke-webrequest",
    "-windowstyle hidden",
    "-w hidden",
    "-executionpolicy bypass",
    "-ep bypass",
]

PRIVILEGED_GROUPS = [
    "administrators",
    "domain admins",
    "enterprise admins",
    "schema admins",
    "remote desktop users",
]

RESERVED_DEMO_IP_RANGES = ["192.0.2.", "198.51.100.", "203.0.113."]
