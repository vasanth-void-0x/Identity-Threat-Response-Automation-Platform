# Detection Rules

All 11 rules live in `detection_engine/rules/` and are toggled/tuned via
`configs/detection_rules.yaml`.

| Rule | File | MITRE | Trigger |
|---|---|---|---|
| Brute Force | `brute_force.py` | T1110 | >= N failed logons (4625) for a user/IP in a rolling window |
| Successful Login After Failures | `successful_login_after_failures.py` | T1078, T1110 | 4624 success shortly after several 4625 failures |
| New Source IP | `new_source_ip.py` | T1078 | Success login from an IP never seen for that user |
| New Device | `new_device.py` | T1078 | Success login from a device/host never seen for that user |
| Impossible Travel | `impossible_travel.py` | T1078 | Two logins geographically implausible given elapsed time (Haversine) |
| Privileged Logon | `privileged_logon.py` | T1078, T1548 | 4672 special privileges assigned, risk-boosted by new IP/recent failures |
| Suspicious PowerShell | `suspicious_powershell.py` | T1059.001 | 4104 script block matches known-suspicious indicators |
| Account Lockout | `account_lockout.py` | T1110 | 4740 correlated with prior failed logons |
| Account Creation | `account_creation.py` | T1136.001 | 4720, risk-boosted outside business hours or fast group-add |
| Group Membership Change | `group_membership_change.py` | T1098, T1069 | 4728/4732 into a group, flagged if privileged (Administrators, etc.) |
| Suspicious Process | `suspicious_process.py` | T1204, T1059.001 | Unusual parent-child process pairs (e.g. winword.exe -> powershell.exe) |

Each rule extends `BaseDetectionRule` and returns a list of `Alert` objects
with `event_ids`, `mitre_techniques`, and rule-specific `metadata` used later
for risk scoring and analyst display.
