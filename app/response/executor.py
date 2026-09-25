"""The only code path that changes anything in the tenant.

approve/reject -> check the action is allowed for THIS incident -> take the
target from the incident (never from the request or the AI) -> run LIVE only
if enabled in LIVE_ACTIONS and credentials exist, otherwise SIMULATE and say so
-> verify -> store -> audit.
"""
import uuid
from datetime import datetime, timezone

from .. import config, ledger, store
from ..schemas import ResponseAction
from . import catalog

SIMULATE_ALWAYS = {"DISABLE_USER", "ESCALATE_INCIDENT", "NO_ACTION"}


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _handler(action_type):
    if action_type == "REVOKE_OAUTH_GRANT":
        from .graph_actions import revoke_oauth_grant
        return revoke_oauth_grant
    if action_type == "DISABLE_APPLICATION":
        from .graph_actions import disable_application
        return disable_application
    if action_type == "REVOKE_USER_SESSIONS":
        from .graph_actions import revoke_user_sessions
        return revoke_user_sessions
    if action_type == "ISOLATE_VM":
        from .vm_isolation import isolate_vm
        return isolate_vm
    return None


def is_live(action_type: str) -> bool:
    return (action_type in config.LIVE_ACTIONS and action_type not in SIMULATE_ALWAYS
            and config.responder_configured())


def decide(incident: dict, action_type: str, decision: str, analyst: str, note: str = "") -> dict:
    if action_type not in catalog.CATALOG:
        raise ValueError(f"Unknown action {action_type}")
    if action_type not in incident["allowed_actions"]:
        raise ValueError(f"{action_type} is not allowed for incident {incident['incident_id']}")
    target = incident["action_targets"].get(action_type, {})
    action_id = "act_" + uuid.uuid4().hex[:12]
    action = ResponseAction(action_id=action_id, incident_id=incident["incident_id"], action_type=action_type,
                            target=target, decision=decision, decided_by=analyst, decided_at=_now(), note=note)

    ledger.append("analyst.decision", {"action_id": action_id, "action_type": action_type, "decision": decision,
                                       "target": target, "note": note},
                  incident_id=incident["incident_id"], actor=analyst)

    if decision != "APPROVED":
        action.status = "NOT_EXECUTED"
    elif is_live(action_type):
        action.mode = "LIVE"
        try:
            status, verification, api_log, rollback = _handler(action_type)(target)
        except Exception as exc:
            status, verification, api_log, rollback = "FAILED", f"{type(exc).__name__}: {str(exc)[:300]}", [], {}
        action.status, action.verification, action.api_log, action.rollback = status, verification, api_log, rollback
    else:
        action.mode = "SIMULATED"
        action.status = "SIMULATED"
        reason = ("always simulated in this MVP" if action_type in SIMULATE_ALWAYS
                  else "live execution not enabled (LIVE_ACTIONS / responder credentials)")
        action.verification = f"No change was made to any system: {reason}."

    store.insert("action", action.action_id, action.to_dict(), incident_id=incident["incident_id"])
    if decision == "APPROVED":
        ledger.append("response.result", {"action_id": action_id, "action_type": action_type, "mode": action.mode,
                                          "status": action.status, "verification": action.verification,
                                          "api_log": action.api_log, "rollback": action.rollback},
                      incident_id=incident["incident_id"], actor="system")
    return action.to_dict()


def restore_vm_network(original: dict, analyst: str) -> dict:
    """Undo a LIVE ISOLATE_VM. Recorded as a new action; the original is untouched."""
    if original["action_type"] != "ISOLATE_VM" or original["mode"] != "LIVE" or original["status"] != "SUCCEEDED":
        raise ValueError("Only a successful live VM isolation can be restored")
    from .vm_isolation import restore_vm
    action = ResponseAction(action_id=original["action_id"] + "_restore", incident_id=original["incident_id"],
                            action_type="RESTORE_VM_NETWORK", target=original["target"], decision="APPROVED",
                            decided_by=analyst, decided_at=_now(), mode="LIVE")
    try:
        action.status, action.verification, action.api_log, _ = restore_vm(original["rollback"])
    except Exception as exc:
        action.status, action.verification = "FAILED", f"{type(exc).__name__}: {str(exc)[:300]}"
    if not store.insert("action", action.action_id, action.to_dict(), incident_id=original["incident_id"]):
        raise ValueError("This isolation has already been restored")
    ledger.append("response.rollback", action.to_dict(), incident_id=original["incident_id"], actor=analyst)
    return action.to_dict()
