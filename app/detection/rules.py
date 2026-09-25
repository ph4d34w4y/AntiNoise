"""Deterministic detection rules.

Each rule looks at ONE normalized event and either returns nothing or a
signal: which entities it concerns (for correlation) and a factual summary.
Rules never call the LLM and never use per-user history (no baselining).

To add a rule: write a match function and add a Rule(...) to RULES.
"""
from dataclasses import dataclass
from typing import Callable, Optional

from .. import config
from ..schemas import NormalizedEvent

# ---------------------------------------------------------------- policy lists
SENSITIVE_SCOPES = {
    "Mail.Read", "Mail.ReadWrite", "Mail.Send", "MailboxSettings.ReadWrite",
    "Files.Read.All", "Files.ReadWrite.All", "Sites.Read.All", "Sites.ReadWrite.All",
    "Contacts.Read", "EWS.AccessAsUser.All", "full_access_as_user",
    "Directory.ReadWrite.All", "User.ReadWrite.All",
}
HIGH_RISK_SCOPES = {
    "Mail.ReadWrite", "Mail.Send", "MailboxSettings.ReadWrite", "Files.ReadWrite.All",
    "Sites.ReadWrite.All", "EWS.AccessAsUser.All", "full_access_as_user", "Directory.ReadWrite.All",
}
PRIVILEGED_ROLES = {
    "Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
    "Application Administrator", "Cloud Application Administrator", "Exchange Administrator",
    "SharePoint Administrator", "User Administrator", "Authentication Administrator",
    "Security Administrator", "Conditional Access Administrator", "Hybrid Identity Administrator",
}
TENANT_CONTROL_ROLES = {"Global Administrator", "Privileged Role Administrator"}
PRIVILEGED_ACTIONS = {
    "priv.sp_credentials_added", "priv.app_credentials_updated", "priv.app_owner_added",
    "priv.sp_owner_added", "priv.app_role_assigned", "priv.ca_policy_updated", "role.assign",
}
SUSPICIOUS_RULE_FOLDERS = {"rss feeds", "rss subscriptions", "conversation history", "archive"}

OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
                  "w3wp.exe", "sqlservr.exe"}
WINDOWS_SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                  "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}
LINUX_SERVICE_PARENTS = {"nginx", "apache2", "httpd", "php-fpm", "java", "node", "tomcat", "mysqld", "postgres"}
LINUX_SHELLS = {"sh", "bash", "dash", "zsh", "python", "python3", "perl", "curl", "wget", "nc", "ncat", "socat"}
DOWNLOAD_OR_ENCODED_MARKERS = ["-enc ", "-encodedcommand", "frombase64string", "downloadstring",
                               "downloadfile", "invoke-webrequest", "iwr ", "invoke-expression", "iex ",
                               "curl ", "wget ", "| sh", "|sh", "| bash", "base64 -d", "certutil -urlcache"]
TEMP_PATH_MARKERS = ["\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\",
                     "\\programdata\\", "/tmp/", "/dev/shm/", "/var/tmp/"]


def load_ioc_hashes() -> set[str]:
    path = config.IOC_HASH_FILE
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if len(line) == 64:
            out.add(line)
    return out


# ---------------------------------------------------------------- rule type
@dataclass
class Rule:
    rule_id: str
    name: str
    description: str
    severity_points: int
    confidence_points: int
    response_category: str
    match: Callable[[NormalizedEvent, dict], Optional[dict]]  # -> {"entities":..., "summary":...} or None


def _ok(e: NormalizedEvent) -> bool:
    return e.details.get("result", "success") in ("success", "")


# ---------------------------------------------------------------- identity / OAuth
def m_consent(e, ctx):
    if e.action == "oauth.consent" and _ok(e) and e.application_id:
        who = "admin consent (all users)" if e.details.get("is_admin_consent") else "user consent"
        return {"entities": {"user": e.actor["id"], "app": e.application_id},
                "summary": f"{e.actor['name']} granted {who} to application {e.application_id}"}


def m_sensitive_scope(e, ctx):
    if e.action == "oauth.consent" and e.application_id:
        hits = sorted(set(e.permissions) & SENSITIVE_SCOPES)
        if hits:
            return {"entities": {"user": e.actor["id"], "app": e.application_id},
                    "summary": f"Consent included sensitive delegated scopes: {', '.join(hits)}"}


def m_app_token_use(e, ctx):
    if (e.action == "signin.noninteractive" and _ok(e)
            and e.application_id in ctx["consented_apps"]):
        return {"entities": {"user": e.actor["id"], "app": e.application_id},
                "summary": f"Consented app obtained tokens for {e.actor['name']} from {e.source_ip or 'unknown IP'}"}


def m_app_mail(e, ctx):
    if e.action == "mail.access" and e.application_id in ctx["consented_apps"]:
        return {"entities": {"user": e.actor["id"], "app": e.application_id},
                "summary": f"Consented app accessed {e.details.get('item_count', 0)} mail items in {e.asset}"}


def m_app_file(e, ctx):
    if e.action == "file.access" and e.application_id in ctx["consented_apps"]:
        return {"entities": {"user": e.actor["id"], "app": e.application_id},
                "summary": f"Consented app accessed file '{e.target.get('name', '')}' in {e.asset}"}


# ---------------------------------------------------------------- session / credential misuse
def m_mfa_registered(e, ctx):
    if e.action == "mfa.register" and _ok(e):
        return {"entities": {"user": e.actor["id"]},
                "summary": f"{e.actor['name']} registered a new authentication method"}


def m_inbox_rule(e, ctx):
    if e.action != "mailbox.inbox_rule":
        return None
    p = e.details.get("parameters", {})
    reasons = []
    for key in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo"):
        for addr in str(p.get(key) or "").replace(";", ",").split(","):
            addr = addr.strip().lower()
            if "@" in addr and addr.split("@")[-1] not in ctx["tenant_domains"]:
                reasons.append(f"{key} external address {addr}")
    if str(p.get("DeleteMessage", "")).lower() == "true":
        reasons.append("deletes messages")
    if str(p.get("MoveToFolder", "")).lower() in SUSPICIOUS_RULE_FOLDERS:
        reasons.append(f"moves mail to '{p.get('MoveToFolder')}'")
    if reasons:
        return {"entities": {"user": e.actor["id"]},
                "summary": f"Inbox rule '{p.get('Name', '')}' created by {e.actor['name']}: {'; '.join(reasons)}"}


def m_disallowed_country(e, ctx):
    country = (e.location or {}).get("country", "")
    if e.event_type == "authentication" and _ok(e) and country and country not in config.ALLOWED_COUNTRIES:
        return {"entities": {"user": e.actor["id"]},
                "summary": f"Successful sign-in for {e.actor['name']} from {country}, outside the allowed-country policy"}


# ---------------------------------------------------------------- privilege escalation
def m_priv_role(e, ctx):
    role = e.details.get("role_name", "")
    if e.action == "role.assign" and _ok(e) and role in PRIVILEGED_ROLES:
        return {"entities": {"user": e.target["id"]},
                "summary": f"{e.target.get('name')} was assigned '{role}' by {e.actor.get('name')}"}


def m_self_assign(e, ctx):
    role = e.details.get("role_name", "")
    if e.action == "role.assign" and role in PRIVILEGED_ROLES and e.actor["id"] and e.actor["id"] == e.target["id"]:
        return {"entities": {"user": e.target["id"]},
                "summary": f"{e.actor['name']} assigned '{role}' to themselves"}


def m_priv_action(e, ctx):
    if e.action in PRIVILEGED_ACTIONS and e.actor.get("type") == "user" and _ok(e):
        return {"entities": {"user": e.actor["id"]},
                "summary": f"{e.actor['name']} performed privileged operation: {e.details.get('activity')} "
                           f"on {e.target.get('name') or e.target.get('id')}"}


# ---------------------------------------------------------------- VM
def m_parent_child(e, ctx):
    if e.action != "process.start" or not e.process:
        return None
    parent, child = (e.process.get("parent_name") or "").lower(), (e.process.get("name") or "").lower()
    if (parent in OFFICE_PARENTS and child in WINDOWS_SHELLS) or \
       (parent in LINUX_SERVICE_PARENTS and child in LINUX_SHELLS):
        return {"entities": {"vm": e.asset},
                "summary": f"{parent} (pid {e.process.get('parent_pid')}) started {child} (pid {e.process.get('pid')})"}


def m_encoded_download(e, ctx):
    if e.action == "process.start" and e.process:
        cmd = (e.process.get("command_line") or "").lower() + " "
        hits = [m.strip() for m in DOWNLOAD_OR_ENCODED_MARKERS if m in cmd]
        if hits:
            return {"entities": {"vm": e.asset},
                    "summary": f"{e.process.get('name')} command line contains: {', '.join(sorted(set(hits)))}"}


def m_exec_from_temp(e, ctx):
    if e.action == "process.start" and e.process:
        path = (e.process.get("path") or "").lower()
        if any(m in path for m in TEMP_PATH_MARKERS):
            return {"entities": {"vm": e.asset},
                    "summary": f"Process executed from a user-writable/temp location: {e.process.get('path')}"}


def m_bad_hash(e, ctx):
    if e.file_hash and e.file_hash.lower() in ctx["ioc_hashes"]:
        return {"entities": {"vm": e.asset},
                "summary": f"SHA256 {e.file_hash} matches the local IOC list"}


RULES: list[Rule] = [
    Rule("OAUTH_CONSENT_GRANTED", "OAuth consent granted",
         "A user or admin consented to an application.", 0, 20, "oauth", m_consent),
    Rule("OAUTH_SENSITIVE_SCOPE", "Sensitive delegated scopes granted",
         "Consent included scopes that expose mail, files, or directory data.", 15, 15, "oauth", m_sensitive_scope),
    Rule("APP_TOKEN_USE", "Consented app used tokens",
         "Non-interactive sign-in by the consented application on the user's behalf.", 0, 10, "oauth", m_app_token_use),
    Rule("APP_MAIL_ACCESS", "Mail accessed by consented app",
         "Exchange recorded mailbox access by the consented application.", 15, 15, "oauth", m_app_mail),
    Rule("APP_FILE_ACCESS", "Files accessed by consented app",
         "OneDrive/SharePoint recorded file access by the consented application.", 15, 15, "oauth", m_app_file),
    Rule("MFA_METHOD_REGISTERED", "New authentication method registered",
         "A new MFA/security-info method was added to the account.", 10, 20, "session", m_mfa_registered),
    Rule("SUSPICIOUS_INBOX_RULE", "Suspicious inbox rule",
         "Inbox rule forwards externally, deletes mail, or hides mail in a rarely-viewed folder.", 20, 25,
         "session", m_inbox_rule),
    Rule("SIGNIN_DISALLOWED_COUNTRY", "Sign-in outside allowed countries",
         "Successful sign-in from a country not in the static ALLOWED_COUNTRIES policy.", 5, 15,
         "session", m_disallowed_country),
    Rule("PRIV_ROLE_ASSIGNED", "Privileged role assigned",
         "An identity received a privileged directory role.", 20, 25, "privilege", m_priv_role),
    Rule("PRIV_SELF_ASSIGNMENT", "Privileged role self-assigned",
         "The assigner and the assignee are the same identity.", 5, 10, "privilege", m_self_assign),
    Rule("PRIV_ACTION", "Privileged operation performed",
         "Credential, ownership, role, or policy change performed by a user.", 15, 25, "privilege", m_priv_action),
    Rule("VM_SUSPICIOUS_PARENT_CHILD", "Suspicious parent/child process",
         "Office app or web/service process spawned a shell or script host.", 15, 25, "endpoint", m_parent_child),
    Rule("VM_ENCODED_OR_DOWNLOAD", "Encoded or download command line",
         "Command line contains encoding, download, or pipe-to-shell markers.", 10, 15, "endpoint", m_encoded_download),
    Rule("VM_EXEC_FROM_TEMP", "Execution from temp/user-writable path",
         "A binary ran from a temp or world-writable directory.", 5, 10, "endpoint", m_exec_from_temp),
    Rule("VM_KNOWN_BAD_HASH", "Known-bad file hash",
         "File hash matches the local IOC list.", 25, 30, "endpoint", m_bad_hash),
]
RULES_BY_ID = {r.rule_id: r for r in RULES}


def build_context(events: list[NormalizedEvent], tenant_domains: list[str]) -> dict:
    """Facts computed once per dataset that rules may use. Still deterministic."""
    return {
        "consented_apps": {e.application_id for e in events if e.action == "oauth.consent" and e.application_id},
        "tenant_domains": {d.lower() for d in (tenant_domains or config.TENANT_DOMAINS)},
        "ioc_hashes": load_ioc_hashes(),
    }
