"""
seed_demo.py
Convenience CLI entry point for seeding demo data: loads sample users,
known devices, benign events, and all attack scenarios, runs detection +
correlation, and prints summary statistics.

Usage:
    python seed_demo.py            # clears existing demo data first
    python seed_demo.py --no-clear # appends to existing data
"""

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.logger import setup_logging
from database.seed import seed_demo_data


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed ITRAP demo data")
    parser.add_argument("--no-clear", action="store_true", help="Do not clear existing demo data first")
    args = parser.parse_args()

    setup_logging("INFO", "logs")

    summary = seed_demo_data(clear_first=not args.no_clear)

    print("=" * 60)
    print("Identity Threat Response Automation Platform - Demo Seed")
    print("=" * 60)
    print(f"Events ingested   : {summary['events']}")
    print(f"Alerts generated  : {summary['alerts']}")
    print(f"Incidents created : {summary['incidents']}")
    print("=" * 60)
    print("Run 'python run.py' (or 'streamlit run app/dashboard.py') to view the dashboard.")


if __name__ == "__main__":
    main()
