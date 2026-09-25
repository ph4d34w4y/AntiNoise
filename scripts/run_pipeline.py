"""Replay every fixture through the full pipeline from the command line.

    python scripts/run_pipeline.py            # with AI assessment (or deterministic fallback)
    python scripts/run_pipeline.py --no-ai
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import pipeline, store  # noqa: E402

results = pipeline.run_all_fixtures(run_ai="--no-ai" not in sys.argv)
for r in results:
    print(f"{r['dataset']:<24} events={r['events']:<3} signals={r['signals']:<3} new incidents={r['incidents_created']}")
    for f in r["normalize_failures"]:
        print("   normalize failure:", f)
print()
for i in store.list_kind("incident"):
    print(f"{i['incident_id']}  {i['severity']['level']:<8} {i['severity']['score']:>3}  "
          f"conf {i['confidence']['level']:<6} {i['confidence']['score']:>3}  {i['title'][:80]}")
