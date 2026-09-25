"""Wrap exported VM telemetry into a replayable fixture.

Windows (on the VM, PowerShell, Sysmon installed):
    see docs/vm_telemetry.md for the one-liner that writes sysmon.json
Linux: a JSON list in the format described in docs/vm_telemetry.md

    python scripts/import_vm_json.py --kind windows --file sysmon.json \
        --resource-id /subscriptions/.../virtualMachines/win-fin-01 --out fixtures/z_capture_winvm.json
"""
import argparse
import json
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--kind", choices=["windows", "linux"], required=True)
p.add_argument("--file", required=True)
p.add_argument("--resource-id", required=True, help="Azure resource ID of the VM (used for isolation)")
p.add_argument("--out", required=True)
a = p.parse_args()

rows = json.loads(Path(a.file).read_text(encoding="utf-8-sig"))
rows = rows if isinstance(rows, list) else [rows]
source = "windows_vm" if a.kind == "windows" else "linux_vm"
records = [{"source": source, "azure_resource_id": a.resource_id, "raw": r} for r in rows]
Path(a.out).write_text(json.dumps({
    "dataset": Path(a.out).stem, "description": f"Captured {a.kind} VM telemetry", "origin": "captured",
    "telemetry_available": [source], "directory": {}, "records": records}, indent=1))
print(f"Wrote {len(records)} records to {a.out}")
