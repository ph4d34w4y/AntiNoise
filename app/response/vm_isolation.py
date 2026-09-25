"""VM network isolation by swapping each NIC onto a PRE-BUILT isolation NSG.

Safety rules enforced in code:
  * The code never creates or edits firewall rules. The isolation NSG is built
    once by a human (docs/vm_isolation.md) and referenced by ISOLATION_NSG_ID.
  * The NSG must carry the tag purpose=isolation or the action is refused.
  * The original NSG of every NIC is recorded so Restore network can undo it.

Requires: pip install azure-identity azure-mgmt-network azure-mgmt-compute
and the responder service principal needs Network Contributor + Virtual
Machine Reader on the resource group (Azure RBAC, not Graph permissions).

Caveat: NSGs are stateful. Connections that were already established may
survive until they go idle, so verify isolation by testing, not by assumption.
"""
from .. import config


def _clients(subscription_id: str):
    from azure.identity import ClientSecretCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    cred = ClientSecretCredential(config.TENANT_ID, config.RESPONDER_CLIENT_ID, config.RESPONDER_CLIENT_SECRET)
    return ComputeManagementClient(cred, subscription_id), NetworkManagementClient(cred, subscription_id)


def _parse(resource_id: str) -> dict:
    parts = resource_id.strip("/").split("/")
    d = {parts[i].lower(): parts[i + 1] for i in range(0, len(parts) - 1, 2)}
    return {"subscription": d.get("subscriptions", ""), "rg": d.get("resourcegroups", ""),
            "name": parts[-1]}


def isolate_vm(target: dict):
    log = []
    vm_id = target.get("vm", "")
    if not vm_id.lower().startswith("/subscriptions/"):
        return "FAILED", f"Target '{vm_id}' is not an Azure VM resource ID", log, {}
    if not config.ISOLATION_NSG_ID:
        return "FAILED", "ISOLATION_NSG_ID is not configured", log, {}
    vm_ref, nsg_ref = _parse(vm_id), _parse(config.ISOLATION_NSG_ID)
    compute, network = _clients(vm_ref["subscription"])

    nsg = network.network_security_groups.get(nsg_ref["rg"], nsg_ref["name"])
    log.append({"request": f"GET NSG {nsg_ref['name']}", "status": "ok"})
    if (nsg.tags or {}).get("purpose") != "isolation":
        return "FAILED", "Refused: configured NSG is not tagged purpose=isolation", log, {}

    vm = compute.virtual_machines.get(vm_ref["rg"], vm_ref["name"])
    log.append({"request": f"GET VM {vm_ref['name']}", "status": "ok"})
    originals = []
    for nic_ref in vm.network_profile.network_interfaces:
        nic_parts = _parse(nic_ref.id)
        nic = network.network_interfaces.get(nic_parts["rg"], nic_parts["name"])
        originals.append({"nic_id": nic.id, "original_nsg_id": nic.network_security_group.id
                          if nic.network_security_group else None})
        nic.network_security_group = nsg
        network.network_interfaces.begin_create_or_update(nic_parts["rg"], nic_parts["name"], nic).result()
        log.append({"request": f"PUT NIC {nic_parts['name']} nsg=isolation", "status": "ok"})

    bad = []
    for o in originals:
        p = _parse(o["nic_id"])
        nic = network.network_interfaces.get(p["rg"], p["name"])
        if not nic.network_security_group or nic.network_security_group.id.lower() != nsg.id.lower():
            bad.append(p["name"])
    if bad:
        return "FAILED", f"NIC(s) not on isolation NSG after update: {bad}", log, {"nics": originals}
    return ("SUCCEEDED", f"{len(originals)} NIC(s) read back on isolation NSG '{nsg.name}'. "
                         "Established connections may persist until idle; test before claiming full isolation.",
            log, {"nics": originals})


def restore_vm(rollback: dict):
    log, restored = [], 0
    for o in rollback.get("nics", []):
        p = _parse(o["nic_id"])
        _, network = _clients(p["subscription"])
        nic = network.network_interfaces.get(p["rg"], p["name"])
        if o["original_nsg_id"]:
            op = _parse(o["original_nsg_id"])
            nic.network_security_group = network.network_security_groups.get(op["rg"], op["name"])
        else:
            nic.network_security_group = None
        network.network_interfaces.begin_create_or_update(p["rg"], p["name"], nic).result()
        log.append({"request": f"PUT NIC {p['name']} nsg=original", "status": "ok"})
        restored += 1
    return "SUCCEEDED", f"Restored original NSG on {restored} NIC(s)", log, {}
