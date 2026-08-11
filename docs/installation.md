# Installation

## Prerequisites
- Windows 10/11 (primary target) or any OS with Python 3.11+
- Python 3.11 or newer
- No paid services or external accounts required for default operation

## Windows (recommended)
```powershell
git clone https://github.com/vasanth-void-0x/Identity-Threat-Response-Automation-Platform.git
cd Identity-Threat-Response-Automation-Platform
.\scripts\setup.ps1
.\scripts\seed_demo.ps1
.\scripts\start.ps1
```

## Manual installation (any OS)
```bash
git clone https://github.com/vasanth-void-0x/Identity-Threat-Response-Automation-Platform.git
cd Identity-Threat-Response-Automation-Platform
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env
python seed_demo.py
streamlit run app/dashboard.py
```

The dashboard opens at `http://localhost:8501`. No API keys are required -
threat intelligence and AI analysis default to deterministic mock providers.
