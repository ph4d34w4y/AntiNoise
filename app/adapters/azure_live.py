"""Live collection from a Microsoft tenant using the read-only COLLECTOR app.

Application permissions (admin consent required):
  Microsoft Graph:            AuditLog.Read.All, Directory.Read.All
  Office 365 Management APIs: ActivityFeed.Read   (only if you collect Exchange/OneDrive)

Licensing reality check:
  * directoryAudits works on Entra ID Free.
  * signIns via the API needs Entra ID P1/P2 (Free tenants get HTTP 403).
  * Exchange/OneDrive records need M365 licences, auditing enabled, and arrive
    with a delay of tens of minutes to hours. Capture them ahead of the demo.

Every source that fails is reported as unavailable, and that flows into the
confidence score as a stated limitation instead of silently disappearing.
"""
import json
from datetime import datetime, timedelta, timezone

import msal
import requests

from .. import config
from .base import Directory

GRAPH = "https://graph.microsoft.com/v1.0"
MANAGE = "https://manage.office.com"


def _token(scope: str) -> str:
    app = msal.ConfidentialClientApplication(
        config.COLLECTOR_CLIENT_ID, client_credential=config.COLLECTOR_CLIENT_SECRET,
        authority=f"https://login.microsoftonline.com/{config.TENANT_ID}")
    result = app.acquire_token_for_client(scopes=[scope])
    if "access_token" not in result:
        raise RuntimeError(f"Token for {scope} failed: {result.get('error_description', result.get('error'))}")
    return result["access_token"]


def _graph_pages(url: str, token: str, max_pages: int = 20) -> list[dict]:
    out, h = [], {"Authorization": f"Bearer {token}"}
    for _ in range(max_pages):
        r = requests.get(url, headers=h, timeout=60)
        r.raise_for_status()
        body = r.json()
        out += body.get("value", [])
        url = body.get("@odata.nextLink")
        if not url:
            break
    return out


class GraphDirectory(Directory):
    PRIV_ROLE_TEMPLATE_LOOKUP = True

    def __init__(self, token: str):
        self.h = {"Authorization": f"Bearer {token}"}
        self._u, self._a = {}, {}
        org = requests.get(f"{GRAPH}/organization?$select=id,verifiedDomains", headers=self.h, timeout=30)
        org.raise_for_status()
        o = org.json()["value"][0]
        self.tenant_id = o["id"]
        self.tenant_domains = [d["name"].lower() for d in o.get("verifiedDomains", [])]

    def user(self, key):
        if not key:
            return None
        if key.lower() in self._u:
            return self._u[key.lower()]
        r = requests.get(f"{GRAPH}/users/{key}?$select=id,userPrincipalName", headers=self.h, timeout=30)
        if not r.ok:
            return None
        u = r.json()
        roles = requests.get(f"{GRAPH}/users/{u['id']}/memberOf/microsoft.graph.directoryRole?$select=displayName",
                             headers=self.h, timeout=30)
        rec = {"id": u["id"], "upn": u["userPrincipalName"],
               "roles": [x["displayName"] for x in roles.json().get("value", [])] if roles.ok else []}
        self._u[u["id"].lower()] = self._u[u["userPrincipalName"].lower()] = rec
        return rec

    def app(self, app_id):
        if app_id in self._a:
            return self._a[app_id]
        r = requests.get(f"{GRAPH}/servicePrincipals?$filter=appId eq '{app_id}'"
                         "&$select=id,appId,displayName,appOwnerOrganizationId,verifiedPublisher,publisherName",
                         headers=self.h, timeout=30)
        values = r.json().get("value", []) if r.ok else []
        if not values:
            return None
        sp = values[0]
        rec = {"app_id": app_id, "service_principal_id": sp["id"], "display_name": sp.get("displayName", ""),
               "publisher": sp.get("publisherName", ""),
               "verified_publisher": bool((sp.get("verifiedPublisher") or {}).get("verifiedPublisherId")),
               "owner_tenant_id": sp.get("appOwnerOrganizationId", ""), "created": ""}
        self._a[app_id] = rec
        return rec


def collect(hours: int = 24, include_m365: bool = True) -> dict:
    """Returns {"records": [...], "telemetry_available": [...], "errors": [...], "directory_obj": ...}."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    records, available, errors = [], [], []
    gtoken = _token("https://graph.microsoft.com/.default")

    try:
        audits = _graph_pages(f"{GRAPH}/auditLogs/directoryAudits?$filter=activityDateTime ge {since}", gtoken)
        records += [{"source": "entra_audit", "raw": r} for r in audits]
        available.append("entra_audit")
    except requests.HTTPError as exc:
        errors.append(f"Entra audit logs: HTTP {exc.response.status_code}")

    try:
        signins = _graph_pages(f"{GRAPH}/auditLogs/signIns?$filter=createdDateTime ge {since}", gtoken)
        records += [{"source": "entra_signin", "raw": r} for r in signins]
        available.append("entra_signin")
    except requests.HTTPError as exc:
        hint = " (sign-in logs via API need Entra ID P1/P2)" if exc.response.status_code == 403 else ""
        errors.append(f"Entra sign-in logs: HTTP {exc.response.status_code}{hint}")

    if include_m365:
        try:
            m365 = _collect_management_activity(hours)
            records += m365
            available += sorted({r["source"] for r in m365}) or ["m365_exchange", "m365_onedrive"]
        except Exception as exc:
            errors.append(f"Microsoft 365 audit: {type(exc).__name__}: {str(exc)[:200]}")

    return {"records": records, "telemetry_available": available, "errors": errors,
            "directory_obj": GraphDirectory(gtoken)}


def _collect_management_activity(hours: int) -> list[dict]:
    token = _token(f"{MANAGE}/.default")
    h = {"Authorization": f"Bearer {token}"}
    base = f"{MANAGE}/api/v1.0/{config.TENANT_ID}/activity/feed"
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=min(hours, 24))  # the API allows at most 24h per content query
    out = []
    for content_type in ("Audit.Exchange", "Audit.SharePoint"):
        # Starting an already-started subscription returns an error we can ignore.
        requests.post(f"{base}/subscriptions/start?contentType={content_type}", headers=h, timeout=30)
        url = (f"{base}/subscriptions/content?contentType={content_type}"
               f"&startTime={start:%Y-%m-%dT%H:%M:%S}&endTime={end:%Y-%m-%dT%H:%M:%S}")
        while url:
            r = requests.get(url, headers=h, timeout=60)
            r.raise_for_status()
            for blob in r.json():
                items = requests.get(blob["contentUri"], headers=h, timeout=60).json()
                for rec in items:
                    wl = rec.get("Workload", "")
                    if wl == "Exchange":
                        out.append({"source": "m365_exchange", "raw": rec})
                    elif wl in ("OneDrive", "SharePoint"):
                        out.append({"source": "m365_onedrive", "raw": rec})
            url = r.headers.get("NextPageUri")
    return out


def save_capture(result: dict, path) -> None:
    """Write a live collection to a fixture-format file so it can be replayed."""
    d = result["directory_obj"]
    users = [u for k, u in d._u.items() if k == u["id"].lower()]
    snapshot = {"tenant_id": d.tenant_id, "tenant_domains": d.tenant_domains, "users": users,
                "apps": list(d._a.values())}
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"dataset": f"capture-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}",
                   "description": "Live capture from the test tenant",
                   "origin": "captured", "telemetry_available": result["telemetry_available"],
                   "directory": snapshot, "records": result["records"]}, f, indent=1)
