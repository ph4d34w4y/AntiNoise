"""Check the audit ledger hash chain.   python scripts/verify_ledger.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import ledger  # noqa: E402

result = ledger.verify()
print(result)
sys.exit(0 if result["ok"] else 1)
