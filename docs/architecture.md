# Architecture

## Overview

The Identity Threat Response Automation Platform (ITRAP) is a layered SOC
automation pipeline: raw identity/authentication logs are parsed and
normalized into a common event schema, run through a rule-based detection
engine, correlated into incidents, risk-scored explainably, enriched with
threat intelligence and MITRE ATT&CK context, optionally summarized by an AI
assistant, and exposed through a Streamlit dashboard with simulated (default)
or policy-gated real response actions.

See `assets/diagrams/architecture.mmd` for the full data-flow diagram
(renders natively on GitHub).

## Layers

| Layer | Responsibility | Key modules |
|---|---|---|
| Parsing | Convert raw log formats into a common schema | `parsers/` |
| Detection | Rule-based suspicious activity detection | `detection_engine/rules/` |
| Correlation | Group related alerts into incidents | `detection_engine/correlation.py` |
| Scoring | Explainable 0-100 risk scoring | `detection_engine/risk_scoring.py` |
| Threat Intel | IP reputation enrichment | `threat_intelligence/` |
| MITRE Mapping | Technique/tactic metadata | `mitre/` |
| AI Assistant | Analyst-aid incident summaries | `ai_engine/` |
| Automation | Simulated/real response actions | `automation/` |
| Persistence | SQLite storage | `database/` |
| Presentation | Streamlit dashboard | `app/` |
| Reporting | PDF/HTML/CSV export | `reports/` |

## Design principles

- **Defensive by default.** Every response action defaults to simulation
  mode. Real execution requires explicit configuration changes plus policy
  checks (protected users/hosts/networks, severity thresholds, approval
  flags).
- **Explainability over black-box scoring.** Every alert shows exactly which
  rule fired, which weight it contributed, and why.
- **Offline-first.** The platform runs completely locally with mock threat
  intelligence and AI providers - no API keys required for the full demo
  experience.
- **Config over code.** Detection thresholds, risk weights, and response
  policy all live in YAML so they can be tuned without editing Python.
