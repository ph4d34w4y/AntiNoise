"""Collect from the real tenant, run the pipeline, and optionally save the
raw records as a replayable fixture (do this well before the demo).

    python scripts/collect_live.py --hours 24 --save
"""
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import config, pipeline  # noqa: E402
from app.adapters import azure_live  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("--hours", type=int, default=24)
parser.add_argument("--no-m365", action="store_true", help="skip the Office 365 Management Activity API")
parser.add_argument("--save", action="store_true", help="write a replayable fixture to fixtures/")
args = parser.parse_args()

if not config.collector_configured():
    sys.exit("Set AZURE_TENANT_ID, COLLECTOR_CLIENT_ID and COLLECTOR_CLIENT_SECRET first (see .env.example).")

result = azure_live.collect(hours=args.hours, include_m365=not args.no_m365)
print(f"Collected {len(result['records'])} records. Available: {result['telemetry_available']}")
for e in result["errors"]:
    print("  unavailable:", e)
name = f"live-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
summary = pipeline.run_dataset(name, result["records"], result["directory_obj"], result["telemetry_available"],
                               origin="live")
print(summary)
if args.save:
    path = config.FIXTURES_DIR / f"z_capture_{name}.json"
    azure_live.save_capture(result, path)
    print("Saved replayable capture to", path)
