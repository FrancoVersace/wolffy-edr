import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = Path(os.environ.get("WOLFFY_CONFIG_DIR", ROOT / "config")).resolve()
DATA_DIR = Path(os.environ.get("WOLFFY_DATA_DIR", ROOT / "data")).resolve()
LOG_DIR = DATA_DIR / "logs"
RUN_DIR = DATA_DIR / "run"


def ensure_dirs():
    for directory in (DATA_DIR, LOG_DIR, RUN_DIR):
        directory.mkdir(parents=True, exist_ok=True)
