# Response Automation Safety Controls

See `assets/diagrams/response_flow.mmd` for the full decision flow.

**Simulation mode is the default and is enforced in `configs/response_policy.yaml`
(`simulation_mode: true`).** In simulation mode, every action is recorded and
audit-logged but no real system, account, or network change occurs.

## Two response paths

| Path | Entry point | When used | Approval needed? |
|---|---|---|---|
| **Simulated** | `automation.response_engine.execute_action(..., real_mode=False)` | Dashboard's primary "Execute Action (Simulated)" button - always this path | No - nothing real happens |
| **Real (approval-gated)** | `automation.response_engine.request_real_action(...)` → `approve_action(...)` | Dashboard's "Request a REAL Response Action" expander, or direct CLI/API use | **Yes - mandatory** |

The dashboard's primary button never sends `real_mode=True` for direct
execution - it's intentionally safe-by-default for demos. A separate,
clearly-labeled section allows *requesting* a real action, which only ever
reaches execution after a full approval workflow.

## Approval workflow (`automation/response_engine.py`)

Response actions move through explicit states:

```
pending_approval -> approved -> executed
pending_approval -> rejected
any              -> failed   (policy violation or execution error)
```

**`request_real_action(...)` policy gates, checked in order:**
1. `response_policy.simulation_mode` must be explicitly disabled
   (`ITRAP_DISABLE_SIMULATION=true`) - otherwise the request fails immediately.
2. Action must be in `action_allowlist`.
3. Incident severity must meet `minimum_severity_threshold` (default: `high`).
4. Target must not be in `protected_users`, `protected_hosts`, or
   `protected_networks`.

If all gates pass, a `ResponseAction` row is created with
`status="pending_approval"` - **nothing executes yet.**

**`approve_action(action_id, approver)`:**
- Rejects the approval if `approver` matches `requested_by` (case-insensitive) -
  **a requester can never approve their own action.**
- Rejects if the action isn't currently `pending_approval` (no double-execution).
- On success: records `approved_by` + `approved_at`, then immediately
  dispatches to the real action handler and records `executed_at` + `result`.
- Re-checks `simulation_mode` at execution time (not just request time) - if
  simulation was re-enabled between request and approval, execution safely
  no-ops instead of running for real.

**`reject_action(action_id, rejector, reason)`:**
- Marks the action `rejected` with `rejected_by`/`rejected_at`/`rejection_reason`.
- No system-changing code ever runs for a rejected action.

Every field (requester, approver, approval timestamp, execution mode,
result) is visible in the Response Center's "Action History" table and
mirrored to `logs/audit.log`.

## Supported actions
| Action | Module | Real-mode behavior |
|---|---|---|
| `block_ip` | `automation/firewall_block.py` | `netsh advfirewall` rule (never for private/localhost IPs) |
| `disable_account` | `automation/disable_account.py` | `net user /active:no` (never for protected/system accounts) |
| `isolate_host` | `automation/isolate_host.py` | Not implemented for real execution in this lab build (requires EDR integration) |
| `kill_process` | `automation/kill_process.py` | `taskkill /F` (never for core system processes) |
| `create_ticket` | `automation/ticket_creator.py` | Always simulated - no ticketing system integrated |
| `email_alert` | `automation/email_alert.py` | SMTP send if `email_enabled: true` and configured |
| `slack_alert` | `automation/slack_alert.py` | Webhook POST if `slack_enabled: true` and configured |
| `flag_for_review` | inline | Always simulated |

Note: the low-level action modules (`disable_account.py`, `kill_process.py`)
no longer contain their own `require_analyst_approval` check - that
responsibility now lives entirely in the approval workflow above, checked
*before* these functions are ever called with `real_mode=True`. Keeping a
second, unconditional check inside those modules previously made approved
actions impossible to execute; this was fixed as part of the approval
workflow implementation.

Every action - simulated, real, pending, approved, rejected, or blocked -
is persisted as a `ResponseAction` row and mirrored to `logs/audit.log`.
