# Risk Scoring

Every alert gets an explainable 0-100 risk score via
`detection_engine/risk_scoring.py`, using weights from
`configs/risk_weights.yaml`.

## Severity bands
| Score | Severity |
|---|---|
| 0-29 | Low |
| 30-59 | Medium |
| 60-79 | High |
| 80-100 | Critical |

## Default weights
| Contribution | Points |
|---|---|
| Brute force | +20 |
| Successful login after failures | +25 |
| New source IP | +15 |
| New device | +15 |
| Impossible travel | +35 |
| Privileged logon | +20 |
| Suspicious PowerShell | +30 |
| Account lockout | +15 |
| Account creation | +15 |
| Account creation outside business hours | +20 |
| Group membership change | +20 |
| Group membership change (privileged group) | +35 |
| Suspicious process | +25 |
| Known-malicious source IP (threat intel) | +30 |

Scores are capped at 100. Every `Alert` stores a `contributions` list (each
with a `reason` and `points`) plus a human-readable `explanation` string, so
analysts always see *why* a score was assigned - never a black-box number.

## Incident scoring
An incident's score is a **dampened sum** of the highest contributing alert
score from each *distinct* detection rule in the correlated cluster (not
just the single worst alert), floored at that worst alert's score and capped
at 100. This reflects that a genuine multi-stage attack chain - e.g. brute
force -> new host login -> privileged logon -> suspicious PowerShell -> a
new process spawned - is materially more dangerous than any single stage in
isolation, and should surface as one CRITICAL incident rather than several
disconnected medium-severity alerts. See
`detection_engine/risk_scoring.score_incident` and
`detection_engine/correlation.py`.
