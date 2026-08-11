# Deployment (Streamlit Community Cloud - free)

The platform is self-seeding and fully offline-capable, which makes it a
good fit for a free, read-only public demo on Streamlit Community Cloud -
no server, no credit card, no secrets required.

## Steps

1. **Push to GitHub** (if not already):
   ```powershell
   git init
   git add .
   git commit -m "Identity Threat Response Automation Platform"
   git remote add origin https://github.com/vasanth-void-0x/Identity-Threat-Response-Automation-Platform.git
   git branch -M main
   git push -u origin main
   ```

2. Go to **[share.streamlit.io](https://share.streamlit.io)** and sign in
   with your GitHub account.

3. Click **New app**, select:
   - Repository: `vasanth-void-0x/Identity-Threat-Response-Automation-Platform`
   - Branch: `main`
   - Main file path: `app/dashboard.py`

4. Click **Deploy**. First build takes 1-3 minutes (installing
   `requirements.txt`).

5. That's it - **no secrets need to be set**. The app runs entirely on mock
   threat intelligence and mock AI providers by default, and
   `app/utils/session.ensure_demo_data_seeded()` auto-seeds demo data on
   first load since the database starts empty on every fresh deployment.

## Optional: enabling real providers on the deployed demo

If you want the live demo to show real VirusTotal/AbuseIPDB/Groq results:
in the Streamlit Cloud app settings → **Secrets**, add:
```toml
VIRUSTOTAL_API_KEY = "your-key"
GROQ_API_KEY = "your-key"
```
Then update `configs/config.yaml`'s `threat_intelligence.provider` /
`ai.provider` to match before pushing. Not required - the mock providers
already demonstrate the full workflow.

## Notes on Streamlit Cloud's ephemeral filesystem

- The SQLite database (`database/itrap.db`) is **not persisted** across
  app restarts/redeploys on the free tier - this is expected and fine for
  a read-only demo, since the app re-seeds itself automatically.
- Response actions are simulation-mode by default (see
  `configs/response_policy.yaml`) - keep it that way for a public demo.
  There is no reason to set `ITRAP_DISABLE_SIMULATION=true` on a public
  deployment, and doing so would let any visitor request real-looking
  actions (they'd still require a second analyst's approval, but there is
  no real authentication on this dashboard - do not enable real mode on a
  publicly reachable deployment).
- The Wazuh REST API integration is **not applicable to a public demo** -
  it requires network access to a private Wazuh server plus credentials,
  neither of which belong in a public Streamlit Cloud secret store. Leave
  `WAZUH_API_URL`/`WAZUH_API_USERNAME`/`WAZUH_API_PASSWORD` unset; the
  Settings page clearly shows "Not configured" and the rest of the app
  works normally.
- Free-tier apps sleep after a period of inactivity and wake on the next
  visit (~30-60 second cold start) - normal behavior, not a bug.

## Alternative: skip deployment, record a walkthrough instead

If you'd rather not manage a public deployment long-term, a recorded
walkthrough (see `docs/demo_video_script.md`) covers the same ground for a
resume/portfolio audience without an always-on hosted app to maintain.
