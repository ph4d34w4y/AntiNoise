"""Adapter registry.

A record handed to the pipeline looks like:
    {"source": "entra_audit", "raw": {...provider JSON...}, ...optional meta...}

To add AWS later: write adapters/aws.py with normalize_cloudtrail(raw, directory)
and register it in NORMALIZERS under a new source name. Nothing downstream changes.
"""
import json
from pathlib import Path

from .. import config
from ..schemas import NormalizedEvent
from . import azure, vm
from .base import Directory, StaticDirectory

NORMALIZERS = {
    "entra_audit": lambda raw, d, meta: azure.normalize_entra_audit(raw, d),
    "entra_signin": lambda raw, d, meta: azure.normalize_entra_signin(raw, d),
    "m365_exchange": lambda raw, d, meta: azure.normalize_m365(raw, d),
    "m365_onedrive": lambda raw, d, meta: azure.normalize_m365(raw, d),
    "windows_vm": vm.normalize_windows,
    "linux_vm": vm.normalize_linux,
}

SOURCE_LABELS = {
    "entra_audit": "Entra ID audit logs",
    "entra_signin": "Entra ID sign-in logs",
    "m365_exchange": "Exchange mailbox audit",
    "m365_onedrive": "OneDrive/SharePoint audit",
    "windows_vm": "Windows VM process telemetry (Sysmon)",
    "linux_vm": "Linux VM process telemetry",
}


def normalize(record: dict, directory: Directory) -> NormalizedEvent:
    source = record["source"]
    meta = {k: v for k, v in record.items() if k not in ("source", "raw")}
    fields = NORMALIZERS[source](record["raw"], directory, meta)
    return NormalizedEvent(**fields)


def list_fixtures() -> list[Path]:
    return sorted(config.FIXTURES_DIR.glob("*.json"))


def load_fixture(path: Path) -> dict:
    """A fixture is one dataset: records + the directory snapshot + which
    telemetry sources the simulated tenant had available."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    data["directory_obj"] = StaticDirectory(data.get("directory", {}))
    return data
