# Incident Workflow

See `assets/diagrams/incident_workflow.mmd` for the full state diagram.

1. **New** - Created automatically when the correlation engine groups one or
   more related alerts (same user/IP/host/device within the correlation
   window, default 30 minutes).
2. **Triaged** - Analyst reviews the incident, MITRE mapping, and threat
   intel enrichment on the Incident Details page.
3. **Investigating** - Analyst generates an AI summary, works through the
   investigation checklist (auto-built from MITRE technique metadata), and
   adds notes.
4. **Contained** - A response action (simulated by default) has been
   executed against the incident via the Response Center.
5. **Resolved** - Root cause addressed, incident closed.
6. **False Positive** - Analyst determines the activity was legitimate
   (e.g. authorized travel, approved admin script).

All status transitions are recorded in the `audit_logs` table with actor,
timestamp, and action for a complete audit trail.
