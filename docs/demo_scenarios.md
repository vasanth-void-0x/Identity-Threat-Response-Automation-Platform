# Demo Scenarios

`python seed_demo.py` loads all scenarios below from `sample_data/*.json`
and runs them through detection + correlation.

| # | Scenario | File | Expected outcome |
|---|---|---|---|
| 1 | Normal employee authentication | `benign_events.json` | No alerts |
| 2 | Multiple failed logins | `brute_force_events.json` | `brute_force` alert |
| 3 | Successful login after brute force | `brute_force_events.json` | `successful_login_after_failures` alert |
| 4 | New IP login | `brute_force_events.json` | `new_source_ip` alert |
| 5 | New device login | `brute_force_events.json` | `new_device` alert |
| 6 | Impossible travel | `impossible_travel_events.json` | `impossible_travel` alert, Chennai -> Lagos in 15 min |
| 7 | Privileged logon | `privilege_events.json` | `privileged_logon` alert |
| 8 | Suspicious PowerShell | `powershell_events.json` | `suspicious_powershell` alert (encoded command) |
| 9 | Account lockout | `brute_force_events.json` | `account_lockout` alert |
| 10 | New user account creation | `privilege_events.json` | `account_creation` alert (outside business hours) |
| 11 | User added to Administrators | `privilege_events.json` | `group_membership_change` alert (privileged group) |
| 12 | Correlated multi-stage identity attack | `correlated_attack.json` | Single high/critical incident spanning brute force -> new host login -> privileged logon -> suspicious PowerShell -> suspicious process |
| 13 | Benign administrator activity | `benign_events.json` | No alert (expected privileged action) |
| 14 | False-positive scenario | `powershell_events.json` | Benign `Get-Service` script produces no alert |

To re-inject the multi-stage scenario live for a demo, run
`scripts/simulate_attack.ps1`.
