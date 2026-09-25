"""Normalizers for Microsoft sources.

entra_audit   Graph /auditLogs/directoryAudits records   (Entra ID Free: yes)
entra_signin  Graph /auditLogs/signIns records           (needs Entra ID P1+ for API access)
m365_*        Office 365 Management Activity API records (needs M365 licences + auditing enabled)
"""
import re

from .base import Directory, make_event_id, norm_ts, strip_port

PROVIDER = "azure"


def _clean(value) -> str:
    """Audit log modifiedProperties values are often JSON-quoted strings like '"Global Administrator"'."""
    if value is None:
        return ""
    return str(value).strip().strip('"').strip()


def _audit_action(activity: str) -> tuple[str, str]:
    a = activity.strip().lower()
    if a == "consent to application":
        return "oauth_consent", "oauth.consent"
    if a == "add delegated permission grant":
        return "permission_change", "oauth.grant_added"
    if a == "add member to role":
        return "permission_change", "role.assign"
    if a == "remove member from role":
        return "permission_change", "role.remove"
    if a == "add service principal credentials":
        return "privileged_operation", "priv.sp_credentials_added"
    if a.startswith("update application") and "certificates and secrets" in a:
        return "privileged_operation", "priv.app_credentials_updated"
    if a == "add owner to application":
        return "privileged_operation", "priv.app_owner_added"
    if a == "add owner to service principal":
        return "privileged_operation", "priv.sp_owner_added"
    if a == "add app role assignment to service principal":
        return "privileged_operation", "priv.app_role_assigned"
    if a == "update conditional access policy":
        return "privileged_operation", "priv.ca_policy_updated"
    if a == "user registered security info":
        return "identity_change", "mfa.register"
    return "other", "directory." + re.sub(r"[^a-z0-9]+", "_", a).strip("_")


def normalize_entra_audit(raw: dict, directory: Directory) -> dict:
    event_type, action = _audit_action(raw.get("activityDisplayName", ""))
    initiated = raw.get("initiatedBy") or {}
    ip = ""
    if initiated.get("user"):
        u = initiated["user"]
        actor = {"id": u.get("id", ""), "name": u.get("userPrincipalName", ""), "type": "user"}
        ip = u.get("ipAddress") or ""
    elif initiated.get("app"):
        a = initiated["app"]
        actor = {"id": a.get("servicePrincipalId", ""), "name": a.get("displayName", ""), "type": "service_principal"}
    else:
        actor = {"id": "", "name": "", "type": "unknown"}

    targets = raw.get("targetResources") or []
    t0 = targets[0] if targets else {}
    target = {
        "id": t0.get("id", ""),
        "name": t0.get("userPrincipalName") or t0.get("displayName") or "",
        "type": (t0.get("type") or "").lower(),
    }
    modified = {}
    for t in targets:
        for m in t.get("modifiedProperties") or []:
            modified[m.get("displayName", "")] = m.get("newValue")
    extra = {kv.get("key"): kv.get("value") for kv in raw.get("additionalDetails") or []}

    details = {"activity": raw.get("activityDisplayName", ""), "result": raw.get("result", "")}
    app_id, permissions = "", []

    if action == "oauth.consent":
        app_id = extra.get("AppId") or ""
        if not app_id:  # fall back to the service principal names property, which contains the appId
            m = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                          str(modified.get("TargetId.ServicePrincipalNames", "")), re.I)
            app_id = m.group(0) if m else ""
        scope_match = re.search(r"Scope:\s*([^,\]]+)", str(modified.get("ConsentAction.Permissions", "")))
        if scope_match:
            permissions = sorted(set(scope_match.group(1).split()))
        details["is_admin_consent"] = _clean(modified.get("ConsentContext.IsAdminConsent")).lower() == "true"
        details["service_principal_id"] = target["id"]
    elif action in ("role.assign", "role.remove"):
        details["role_name"] = _clean(modified.get("Role.DisplayName"))
    elif action == "mfa.register":
        details["method"] = raw.get("resultReason", "")
        if not target["id"]:
            target = {"id": actor["id"], "name": actor["name"], "type": "user"}

    return dict(
        event_id=make_event_id(PROVIDER, "entra_audit", raw["id"]),
        timestamp=norm_ts(raw["activityDateTime"]),
        provider=PROVIDER, source="entra_audit",
        event_type=event_type, action=action, actor=actor, target=target,
        asset="Entra ID", source_ip=ip, application_id=app_id, permissions=permissions,
        details=details, raw_event_id=raw["id"], raw_event=raw,
    )


def normalize_entra_signin(raw: dict, directory: Directory) -> dict:
    loc = raw.get("location") or {}
    geo = loc.get("geoCoordinates") or {}
    status = raw.get("status") or {}
    interactive = raw.get("isInteractive", True)
    return dict(
        event_id=make_event_id(PROVIDER, "entra_signin", raw["id"]),
        timestamp=norm_ts(raw["createdDateTime"]),
        provider=PROVIDER, source="entra_signin",
        event_type="authentication",
        action="signin.interactive" if interactive else "signin.noninteractive",
        actor={"id": raw.get("userId", ""), "name": raw.get("userPrincipalName", ""), "type": "user"},
        target={"id": raw.get("appId", ""), "name": raw.get("appDisplayName", ""), "type": "application"},
        asset="Entra ID", source_ip=raw.get("ipAddress", ""), application_id=raw.get("appId", ""),
        location={"city": loc.get("city", ""), "country": (loc.get("countryOrRegion") or "").upper(),
                  "lat": geo.get("latitude"), "lon": geo.get("longitude")},
        details={"result": "success" if status.get("errorCode", 0) == 0 else "failure",
                 "error_code": status.get("errorCode", 0),
                 "client_app_used": raw.get("clientAppUsed", ""),
                 "user_agent": raw.get("userAgent", "")},
        raw_event_id=raw["id"], raw_event=raw,
    )


def _user_from_upn(upn: str, directory: Directory) -> dict:
    u = directory.user(upn) if directory else None
    return {"id": u["id"] if u else upn, "name": upn, "type": "user"}


def normalize_m365(raw: dict, directory: Directory) -> dict:
    """Office 365 Management Activity API (Unified Audit Log) record."""
    workload = raw.get("Workload", "")
    source = "m365_exchange" if workload == "Exchange" else "m365_onedrive"
    op = raw.get("Operation", "")
    actor = _user_from_upn(raw.get("UserId", ""), directory)
    base = dict(
        event_id=make_event_id(PROVIDER, source, raw["Id"]),
        timestamp=norm_ts(raw["CreationTime"]),
        provider=PROVIDER, source=source, actor=actor,
        raw_event_id=raw["Id"], raw_event=raw,
    )

    if op in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules"):
        params = {p.get("Name"): p.get("Value") for p in raw.get("Parameters") or []}
        return {**base, "event_type": "mailbox_change", "action": "mailbox.inbox_rule",
                "target": {"id": raw.get("ObjectId", ""), "name": params.get("Name", ""), "type": "inbox_rule"},
                "asset": f"Mailbox:{actor['name']}", "source_ip": strip_port(raw.get("ClientIP", "")),
                "details": {"operation": op, "parameters": params}}

    if op == "MailItemsAccessed":
        items = sum(len(f.get("FolderItems") or []) for f in raw.get("Folders") or [])
        folders = [f.get("Path", "") for f in raw.get("Folders") or []]
        return {**base, "event_type": "resource_access", "action": "mail.access",
                "target": {"id": raw.get("MailboxGuid", ""), "name": ", ".join(folders), "type": "mailbox"},
                "asset": f"Mailbox:{actor['name']}",
                "source_ip": strip_port(raw.get("ClientIPAddress") or raw.get("ClientIP", "")),
                "application_id": raw.get("AppId") or raw.get("ClientAppId") or "",
                "details": {"operation": op, "item_count": items, "folders": folders}}

    if op in ("FileAccessed", "FileDownloaded", "FileSyncDownloadedFull", "FilePreviewed"):
        return {**base, "event_type": "resource_access", "action": "file.access",
                "target": {"id": raw.get("ObjectId", ""), "name": raw.get("SourceFileName", ""), "type": "file"},
                "asset": f"OneDrive:{actor['name']}", "source_ip": strip_port(raw.get("ClientIP", "")),
                "application_id": raw.get("ApplicationId") or raw.get("AppId") or "",
                "details": {"operation": op, "item_count": 1}}

    return {**base, "event_type": "other", "action": "m365." + op.lower(),
            "target": {"id": raw.get("ObjectId", ""), "name": raw.get("ObjectId", ""), "type": "object"},
            "source_ip": strip_port(raw.get("ClientIP", "")), "details": {"operation": op}}
