"""
run.py
Convenience entry point: launches the Streamlit dashboard.
Equivalent to running: streamlit run app/dashboard.py
"""

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent


def main() -> None:
    dashboard_path = PROJECT_ROOT / "app" / "dashboard.py"
    cmd = [sys.executable, "-m", "streamlit", "run", str(dashboard_path)]
    subprocess.run(cmd, check=True)


if __name__ == "__main__":
    main()
