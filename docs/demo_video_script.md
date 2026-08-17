# Demo Video Script (2-3 minutes)

Record with Windows Game Bar (`Win + G`) or OBS Studio. Run
`.\scripts\start.ps1` first so the app is already seeded and loaded before
you hit record - don't record the setup/pip install, just the product.

Aim for ~2:30. Talk while you click - don't narrate silently then explain
after.

---

**[0:00-0:15] Hook + what it is**
> "This is a SOC identity threat detection platform I built - it ingests
> Windows authentication logs, detects attacks across 11 rule types,
> correlates them into incidents, and maps everything to MITRE ATT&CK.
> Everything you're about to see runs fully offline, no API keys."

Show: Overview page, let the metrics/charts be visible for a beat.

**[0:15-0:45] Detection breadth**
> "It's currently tracking 53 events, which produced 21 alerts across
> 11 detection rules - brute force, impossible travel, privileged logon
> abuse, suspicious PowerShell, and more."

Show: scroll Overview - severity chart, MITRE technique chart, attack
source map (point out a couple of pins).

**[0:45-1:15] The core value: correlation**
> "The interesting part isn't single alerts - it's this: a brute force
> attempt, a login from a brand-new host, a privileged logon, and a
> suspicious PowerShell execution all get correlated into ONE incident
> instead of four disconnected alerts."

Show: Incident Details page → open the critical multi-stage incident →
point at the timeline showing all 4+ stages → risk score gauge.

**[1:15-1:45] MITRE + AI**
> "Every incident maps to MITRE ATT&CK automatically - here's the
> technique breakdown and investigation checklist. I can also generate an
> AI-assisted incident summary on demand."

Show: MITRE expander in the incident panel → click "Generate AI Summary" →
show the output appear. Quick cut to MITRE ATT&CK View heatmap page.

**[1:45-2:15] Safe response automation**
> "Response actions are simulation-mode by default - every action is
> policy-checked and logged, but nothing real happens unless you
> explicitly disable simulation mode in an isolated lab. Here's blocking
> an IP - fully simulated, fully audited."

Show: Response Center → select incident → pick `block_ip` → execute →
show the "[SIMULATION]" success message → scroll the action history table.

**[2:15-2:30] Close**
> "Full source, 159 passing tests, and setup docs are on GitHub - link
> below."

Show: Settings page briefly (simulation mode confirmation), then cut.

---

## Recording checklist
- [ ] Demo data seeded before recording (`python seed_demo.py`)
- [ ] Browser zoomed to ~100-110% so text is readable in the recording
- [ ] Close unrelated tabs/notifications before starting
- [ ] Record in 1080p minimum
- [ ] Trim dead air at start/end before uploading
