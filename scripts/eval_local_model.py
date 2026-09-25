"""Compare local models on the sample incidents before choosing one.

    python scripts/eval_local_model.py                       # uses LOCAL_LLM_MODEL from .env
    LOCAL_LLM_MODEL=llama3.1:8b python scripts/eval_local_model.py

For each incident: seconds taken, whether the output was usable JSON, and how
many items the validator had to remove. Fewer removals = better grounding.
Runs in a throwaway data directory; your real ledger is not touched.
"""
import os
import sys
import tempfile
import time
from pathlib import Path

os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="ctdip-eval-")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import config, pipeline, store  # noqa: E402
from app.ai import investigator, llm  # noqa: E402

print(llm.status()["text"])
if not config.llm_configured() or not llm.status()["ok"]:
    sys.exit("Model not reachable. See docs/local_llm.md.")
pipeline.run_all_fixtures(run_ai=False)
totals = {"seconds": 0.0, "fallback": 0, "removed": 0}
for inc in store.list_kind("incident"):
    i, events, signals = pipeline.incident_bundle(inc["incident_id"])
    t = time.time()
    out = investigator.investigate(i, events, signals)
    dt = time.time() - t
    removed = [e for e in out["validation_errors"] if "removed" in e.lower() or "unknown" in e.lower()]
    totals["seconds"] += dt
    totals["fallback"] += out["mode"] != "llm"
    totals["removed"] += len(removed)
    print(f"{inc['incident_id']}  {dt:6.1f}s  {'ok      ' if out['mode'] == 'llm' else 'FALLBACK'}  "
          f"findings={len(out['validated']['findings'])}  removed={len(removed)}  {inc['title'][:50]}")
    for e in out["validation_errors"]:
        print("      ", e[:140])
print(f"\n{config.LOCAL_LLM_MODEL}: {totals['seconds']:.0f}s total, {totals['fallback']} unusable outputs, "
      f"{totals['removed']} items removed by the validator")
