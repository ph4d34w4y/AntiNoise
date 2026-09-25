"""Shared helpers for every provider adapter.

An adapter's only job: turn one provider-specific raw record into one
NormalizedEvent. Detection, correlation, scoring and the UI never look at
provider formats directly, which is what lets AWS/GCP adapters be added later.
"""
import hashlib
import re
from datetime import datetime, timezone


def make_event_id(provider: str, source: str, native_id: str) -> str:
    digest = hashlib.sha256(f"{provider}|{source}|{native_id}".encode()).hexdigest()
    return "evt_" + digest[:12]


def parse_ts(value) -> datetime:
    """Accepts ISO strings with or without 'Z', with 0-7 fractional digits,
    with 'T' or a space separator, or unix epoch seconds. Always returns UTC."""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    s = str(value).strip().replace("Z", "+00:00")
    m = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$", s)
    if m:
        frac = (m.group(2) or "")[:7]  # Python accepts up to 6 digits after the dot
        s = m.group(1).replace(" ", "T") + frac + m.group(3)
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)  # Microsoft UAL timestamps are UTC without a suffix
    return dt.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def norm_ts(value) -> str:
    return iso(parse_ts(value))


def strip_port(ip: str) -> str:
    """UAL sometimes records '203.0.113.5:51234' or '[2001:db8::1]:443'."""
    if not ip:
        return ""
    ip = ip.strip()
    if ip.startswith("["):
        return ip[1:ip.index("]")] if "]" in ip else ip
    if ip.count(":") == 1:
        return ip.split(":")[0]
    return ip


def basename(path: str) -> str:
    if not path:
        return ""
    return re.split(r"[\\/]", path)[-1]


class Directory:
    """Looks up identities and applications. Live mode asks Microsoft Graph;
    fixture mode uses a snapshot stored in the fixture file."""

    tenant_id: str = ""
    tenant_domains: list = []

    def user(self, key: str) -> dict | None:  # key = object ID or UPN
        raise NotImplementedError

    def app(self, app_id: str) -> dict | None:
        raise NotImplementedError


class StaticDirectory(Directory):
    def __init__(self, snapshot: dict):
        self.tenant_id = snapshot.get("tenant_id", "")
        self.tenant_domains = [d.lower() for d in snapshot.get("tenant_domains", [])]
        self._users = {}
        for u in snapshot.get("users", []):
            self._users[u["id"]] = u
            self._users[u["upn"].lower()] = u
        self._apps = {a["app_id"]: a for a in snapshot.get("apps", [])}

    def user(self, key: str) -> dict | None:
        if not key:
            return None
        return self._users.get(key) or self._users.get(key.lower())

    def app(self, app_id: str) -> dict | None:
        return self._apps.get(app_id)
