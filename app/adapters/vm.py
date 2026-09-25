"""Normalizers for Azure VM process telemetry.

windows_vm  Sysmon events exported as JSON (Event ID 1 = process create, 11 = file create).
linux_vm    A deliberately simple process-exec JSON format (see docs/telemetry_formats.md).
            auditd/osquery output can be mapped to it with a few lines.

Each fixture/collector record may carry "azure_resource_id" so the event
can be tied to the Azure VM we would isolate.
"""
import re

from .base import Directory, basename, make_event_id, norm_ts

PROVIDER = "azure"


def _sha256_from_sysmon(hashes: str) -> str:
    m = re.search(r"SHA256=([0-9A-Fa-f]{64})", hashes or "")
    return m.group(1).lower() if m else ""


def normalize_windows(raw: dict, directory: Directory, meta: dict) -> dict:
    asset = meta.get("azure_resource_id") or raw.get("Computer", "")
    native = f"{raw.get('Computer')}|{raw.get('EventRecordID')}"
    eid = int(raw.get("EventID", 0))
    common = dict(
        event_id=make_event_id(PROVIDER, "windows_vm", native),
        timestamp=norm_ts(raw["UtcTime"]),
        provider=PROVIDER, source="windows_vm", asset=asset,
        actor={"id": raw.get("User", ""), "name": raw.get("User", ""), "type": "process"},
        raw_event_id=native, raw_event=raw,
    )
    if eid == 1:
        return {**common, "event_type": "process_start", "action": "process.start",
                "target": {"id": str(raw.get("ProcessId", "")), "name": basename(raw.get("Image", "")), "type": "process"},
                "process": {"name": basename(raw.get("Image", "")), "pid": raw.get("ProcessId"),
                            "path": raw.get("Image", ""), "command_line": raw.get("CommandLine", ""),
                            "parent_name": basename(raw.get("ParentImage", "")), "parent_pid": raw.get("ParentProcessId"),
                            "parent_path": raw.get("ParentImage", "")},
                "file_hash": _sha256_from_sysmon(raw.get("Hashes", "")),
                "details": {"host": raw.get("Computer", ""), "sysmon_event_id": 1}}
    if eid == 11:
        return {**common, "event_type": "file_event", "action": "file.create",
                "target": {"id": raw.get("TargetFilename", ""), "name": basename(raw.get("TargetFilename", "")), "type": "file"},
                "process": {"name": basename(raw.get("Image", "")), "pid": raw.get("ProcessId"),
                            "path": raw.get("Image", ""), "command_line": "", "parent_name": "", "parent_pid": None,
                            "parent_path": ""},
                "file_hash": _sha256_from_sysmon(raw.get("Hashes", "")),
                "details": {"host": raw.get("Computer", ""), "sysmon_event_id": 11,
                            "file_path": raw.get("TargetFilename", "")}}
    return {**common, "event_type": "other", "action": f"sysmon.{eid}", "target": {},
            "details": {"host": raw.get("Computer", ""), "sysmon_event_id": eid}}


def normalize_linux(raw: dict, directory: Directory, meta: dict) -> dict:
    asset = meta.get("azure_resource_id") or raw.get("host", "")
    native = f"{raw.get('host')}|{raw.get('event_id')}"
    return dict(
        event_id=make_event_id(PROVIDER, "linux_vm", native),
        timestamp=norm_ts(raw["time"]),
        provider=PROVIDER, source="linux_vm", asset=asset,
        event_type="process_start", action="process.start",
        actor={"id": raw.get("user", ""), "name": raw.get("user", ""), "type": "process"},
        target={"id": str(raw.get("pid", "")), "name": basename(raw.get("exe", "")), "type": "process"},
        process={"name": basename(raw.get("exe", "")), "pid": raw.get("pid"), "path": raw.get("exe", ""),
                 "command_line": raw.get("cmdline", ""), "parent_name": basename(raw.get("parent_exe", "")),
                 "parent_pid": raw.get("ppid"), "parent_path": raw.get("parent_exe", "")},
        file_hash=(raw.get("sha256") or "").lower(),
        details={"host": raw.get("host", "")},
        raw_event_id=native, raw_event=raw,
    )
