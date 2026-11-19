import os
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
ROOT = SERVER_DIR.parent
REPO = ROOT.parent

EVIDENCE_DIR = Path(os.environ.get("TRACEGUARD_EVIDENCE", REPO / "evidence"))
WEB_DIR = ROOT / "web"
DB_PATH = Path(os.environ.get("TRACEGUARD_DB", ROOT / "traceguard.db"))

CASE_ID = "CR-26-047"
COMPANY = "Harbor & Finch Freight Pvt. Ltd."
TRACK = "CRIMEATHON'26 · Defense Track"
