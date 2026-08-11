# Sysmon Setup (Optional Roadmap)

The core platform runs without Sysmon (Windows Security Event Log alone
covers most rules). Installing Sysmon adds process-lineage visibility for
the `suspicious_process` rule.

## Installation overview
1. Download Sysmon from Microsoft Sysinternals.
2. Use a well-reviewed community config (e.g. SwiftOnSecurity's sysmonconfig)
   as a starting point - do not run with defaults in production.
3. Install: `sysmon64.exe -i sysmonconfig.xml -accepteula`

## Important event IDs used by this platform
| ID | Event | Used by |
|---|---|---|
| 1 | Process creation | `suspicious_process` rule (parent-child pairs) |
| 3 | Network connection | Future correlation of PowerShell -> C2-like connections |
| 11 | File creation | Future dropped-file correlation |
| 22 | DNS query | Future DNS-based IOC correlation |

## Safe configuration guidance
- Log process creation with full command lines (`<CommandLine>` in
  `ProcessCreate` rule)
- Exclude noisy, low-value processes (browsers' helper processes, etc.) to
  reduce volume - never exclude PowerShell, cmd, wscript, cscript
- Forward the `Microsoft-Windows-Sysmon/Operational` channel to your SIEM
  or export via `wevtutil` for `parsers/sysmon_parser.py`
