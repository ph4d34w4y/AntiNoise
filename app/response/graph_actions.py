"""Live containment through Microsoft Graph, using the RESPONDER app registration.

Each function re-checks the target right now (it may have changed since
detection), performs one bounded change, then verifies the result.
Returns (status, verification_text, api_log, rollback_info).

Required application permissions on the responder app (admin consent needed):
  REVOKE_OAUTH_GRANT    DelegatedPermissionGrant.ReadWrite.All, Application.Read.All
  DISABLE_APPLICATION   Application.ReadWrite.All
  REVOKE_USER_SESSIONS  User.RevokeSessions.All (or User.ReadWrite.All if unavailable)
"""
import msal
import requests

from .. import config

GRAPH = "https://graph.microsoft.com/v1.0"


def _token() -> str:
    app = msal.ConfidentialClientApplication(
        config.RESPONDER_CLIENT_ID, client_credential=config.RESPONDER_CLIENT_SECRET,
        authority=f"https://login.microsoftonline.com/{config.TENANT_ID}")
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in result:
        raise RuntimeError(f"Responder token failed: {result.get('error')}: {result.get('error_description', '')[:200]}")
    return result["access_token"]


class _Graph:
    def __init__(self):
        self.h = {"Authorization": f"Bearer {_token()}", "Content-Type": "application/json"}
        self.log = []

    def call(self, method, path, **kw):
        r = requests.request(method, GRAPH + path, headers=self.h, timeout=30, **kw)
        self.log.append({"request": f"{method} {path.split('?')[0]}", "status": r.status_code})
        return r


def _service_principal_id(g: _Graph, target: dict) -> str:
    if target.get("service_principal_id"):
        return target["service_principal_id"]
    r = g.call("GET", f"/servicePrincipals?$filter=appId eq '{target['app_id']}'&$select=id")
    r.raise_for_status()
    values = r.json().get("value", [])
    return values[0]["id"] if values else ""


def revoke_oauth_grant(target: dict):
    g = _Graph()
    sp_id = _service_principal_id(g, target)
    if not sp_id:
        return "FAILED", "No service principal for this app exists in the tenant (already removed?)", g.log, {}
    r = g.call("GET", f"/oauth2PermissionGrants?$filter=clientId eq '{sp_id}' and principalId eq '{target['user_id']}'")
    r.raise_for_status()
    grants = r.json().get("value", [])
    if not grants:
        return "FAILED", "No matching delegated grant found: it may already have been revoked", g.log, {}
    removed = []
    for grant in grants:
        d = g.call("DELETE", f"/oauth2PermissionGrants/{grant['id']}")
        if d.status_code not in (204, 404):
            return "FAILED", f"Graph refused the delete (HTTP {d.status_code})", g.log, {}
        removed.append({"id": grant["id"], "scope": grant.get("scope", "")})
    still_there = [x["id"] for x in removed if g.call("GET", f"/oauth2PermissionGrants/{x['id']}").status_code != 404]
    if still_there:
        return "FAILED", f"Grant(s) still present after delete: {still_there}", g.log, {}
    return ("SUCCEEDED", f"Deleted {len(removed)} grant(s); follow-up GET returned 404 for each. "
                         f"Scopes removed: {'; '.join(x['scope'] for x in removed)}", g.log, {"removed_grants": removed})


def disable_application(target: dict):
    g = _Graph()
    sp_id = _service_principal_id(g, target)
    if not sp_id:
        return "FAILED", "No service principal for this app exists in the tenant", g.log, {}
    r = g.call("PATCH", f"/servicePrincipals/{sp_id}", json={"accountEnabled": False})
    if r.status_code != 204:
        return "FAILED", f"Graph refused the update (HTTP {r.status_code})", g.log, {}
    check = g.call("GET", f"/servicePrincipals/{sp_id}?$select=accountEnabled")
    if check.ok and check.json().get("accountEnabled") is False:
        return "SUCCEEDED", "Service principal read back with accountEnabled = false", g.log, {"service_principal_id": sp_id}
    return "FAILED", "Update accepted but read-back does not show accountEnabled = false", g.log, {}


def revoke_user_sessions(target: dict):
    g = _Graph()
    r = g.call("POST", f"/users/{target['user_id']}/revokeSignInSessions")
    if r.ok and r.json().get("value") is True:
        return ("ACCEPTED_UNVERIFIED", "Graph accepted the revocation. Token invalidation cannot be read back "
                                       "directly; watch sign-in logs for re-authentication.", g.log, {})
    return "FAILED", f"Graph refused the revocation (HTTP {r.status_code})", g.log, {}
