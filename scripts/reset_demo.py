"""Start a clean demo. Nothing is deleted: the database and ledger are moved
into data/archive/<timestamp>/ so earlier runs stay available for review."""
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import config  # noqa: E402

dest = config.DATA_DIR / "archive" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
moved = []
for p in (config.DB_PATH, config.LEDGER_PATH):
    if p.exists():
        dest.mkdir(parents=True, exist_ok=True)
        shutil.move(str(p), dest / p.name)
        moved.append(p.name)
print(f"Archived {moved} to {dest}" if moved else "Nothing to archive.")
