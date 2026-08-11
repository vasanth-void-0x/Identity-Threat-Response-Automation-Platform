# Troubleshooting

**"Python not found on PATH"**
Install Python 3.11+ from python.org and ensure "Add to PATH" is checked
during installation, then restart your terminal.

**Streamlit dashboard shows no data**
Run `python seed_demo.py` first, or just start the dashboard - it auto-seeds
demo data on first load if the `events` table is empty
(`app/utils/session.ensure_demo_data_seeded`).

**`ModuleNotFoundError` when running scripts directly**
Make sure your virtual environment is activated
(`.venv\Scripts\Activate.ps1` on Windows) and dependencies are installed
(`pip install -r requirements.txt`).

**Threat intelligence always shows "mock" as the source**
This is expected default behavior with no API keys configured. Set
`VIRUSTOTAL_API_KEY` or `ABUSEIPDB_API_KEY` in `.env` and set
`threat_intelligence.provider` in `configs/config.yaml` accordingly.

**PDF report generation fails**
Ensure `reportlab` installed correctly (`pip install reportlab`). On some
minimal Linux containers, ensure standard build tools are present.

**Real response actions don't do anything**
This is intentional - `simulation_mode: true` is the default in
`configs/response_policy.yaml`. See `docs/response_automation.md` for the
full opt-in sequence required for real execution.
