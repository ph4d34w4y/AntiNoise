"""Correlation: turn signals into incidents using explicit, readable chains.

A chain says: start from an ANCHOR signal, group by an entity key (same user,
same app, same VM), look inside a time window, and require at least one
signal from each REQUIRED group. That's the whole engine. No ML, no baselines.

Chains are evaluated in order; a signal used by one incident is not reused by
a later one, which prevents duplicate incidents for the same activity.
"""
import hashlib
from dataclasses import dataclass, field
from datetime import timedelta

from .. import config
from ..adapters.base import Directory, parse_ts
from ..response import catalog
from ..schemas import DetectionSignal, Incident, NormalizedEvent
from .scoring import score_confidence, score_severity


@dataclass
class Chain:
    chain_id: str
    scenario: str
    title: str
    anchor: str
    key_fields: tuple
    required: list                 # list of OR-groups: [["A"], ["B", "C"]] means A and (B or C)
    optional: list
    window_hours: int
    after_anchor: bool             # True: other signals must be at/after the anchor time
    distinct_events: bool          # True: REQUIRED steps must come from different events than the anchor
    base_severity: int
    useful_sources: list           # telemetry that would strengthen this incident if available
    standing_limitations: list = field(default_factory=list)

    @property
    def all_rules(self):
        return {r for group in self.required for r in group} | set(self.optional)


CHAINS = [
    Chain("A_OAUTH", "oauth_consent_abuse", "Possible malicious OAuth consent",
          anchor="OAUTH_CONSENT_GRANTED", key_fields=("user", "app"),
          required=[["OAUTH_SENSITIVE_SCOPE"]],
          optional=["APP_TOKEN_USE", "APP_MAIL_ACCESS", "APP_FILE_ACCESS"],
          window_hours=24, after_anchor=True, distinct_events=False, base_severity=35,
          useful_sources=["entra_signin", "m365_exchange", "m365_onedrive"],
          standing_limitations=["Intent cannot be established: the user may have consented knowingly"]),
    Chain("C_PRIVESC", "privilege_escalation", "Privilege escalation followed by privileged activity",
          anchor="PRIV_ROLE_ASSIGNED", key_fields=("user",),
          required=[["PRIV_ACTION"]], optional=["PRIV_SELF_ASSIGNMENT", "SIGNIN_DISALLOWED_COUNTRY"],
          window_hours=24, after_anchor=True, distinct_events=True, base_severity=45,
          useful_sources=["entra_signin"],
          standing_limitations=["Change-management approval status is not available to this system"]),
    Chain("B_SESSION", "session_misuse", "Possible account takeover: persistence after sign-in",
          anchor="MFA_METHOD_REGISTERED", key_fields=("user",),
          required=[["SUSPICIOUS_INBOX_RULE", "SIGNIN_DISALLOWED_COUNTRY"]],
          optional=["SUSPICIOUS_INBOX_RULE", "SIGNIN_DISALLOWED_COUNTRY"],
          window_hours=6, after_anchor=False, distinct_events=True, base_severity=35,
          useful_sources=["entra_signin", "m365_exchange"],
          standing_limitations=["Whether the user themselves performed these actions cannot be established"]),
    Chain("D_VM", "vm_suspicious_activity", "Suspicious process activity on VM",
          anchor="VM_SUSPICIOUS_PARENT_CHILD", key_fields=("vm",),
          required=[["VM_ENCODED_OR_DOWNLOAD", "VM_EXEC_FROM_TEMP", "VM_KNOWN_BAD_HASH"]],
          optional=["VM_ENCODED_OR_DOWNLOAD", "VM_EXEC_FROM_TEMP", "VM_KNOWN_BAD_HASH"],
          window_hours=1, after_anchor=False, distinct_events=False, base_severity=35,
          useful_sources=[],
          standing_limitations=["Process telemetry shows execution, not whether data left the VM"]),
]


# ---------------------------------------------------------------- helpers
def describe_event(e: NormalizedEvent) -> str:
    a, t, d = e.actor.get("name") or e.actor.get("id"), e.target, e.details
    if e.action == "oauth.consent":
        kind = "admin consent" if d.get("is_admin_consent") else "consent"
        return f"{a} gave {kind} to '{t.get('name')}' for scopes: {' '.join(e.permissions) or 'none recorded'}"
    if e.action == "oauth.grant_added":
        return f"Delegated permission grant created for '{t.get('name')}'"
    if e.action == "role.assign":
        return f"{a} assigned '{d.get('role_name')}' to {t.get('name')}"
    if e.action.startswith("priv."):
        return f"{a}: {d.get('activity')} on {t.get('name') or t.get('id')}"
    if e.action == "mfa.register":
        return f"{a} registered security info ({d.get('method') or 'method not recorded'})"
    if e.action.startswith("signin."):
        kind = "Interactive" if e.action.endswith(".interactive") else "Non-interactive"
        loc = ", ".join(x for x in (e.location.get("city"), e.location.get("country")) if x)
        return f"{kind} sign-in by {a} to {t.get('name') or e.application_id} from {e.source_ip} ({loc or 'location unknown'}), {d.get('result')}"
    if e.action == "mailbox.inbox_rule":
        return f"{a} created inbox rule '{t.get('name')}'"
    if e.action == "mail.access":
        return f"{d.get('item_count')} mail items read in {e.asset} by app {e.application_id} from {e.source_ip}"
    if e.action == "file.access":
        return f"{d.get('operation')}: '{t.get('name')}' in {e.asset} by app {e.application_id} from {e.source_ip}"
    if e.action == "process.start" and e.process:
        p = e.process
        return f"{p.get('parent_name')} ({p.get('parent_pid')}) started {p.get('name')} ({p.get('pid')}): {(p.get('command_line') or '')[:140]}"
    if e.action == "file.create":
        return f"{(e.process or {}).get('name')} created {d.get('file_path')}"
    return f"{a}: {e.action}"


def _event_matches_key(e: NormalizedEvent, key_fields, key) -> bool:
    values = dict(zip(key_fields, key))
    if "vm" in values and e.asset != values["vm"]:
        return False
    if "app" in values and e.application_id != values["app"]:
        return False
    if "user" in values and values["user"] not in (e.actor.get("id"), e.target.get("id")):
        return False
    return True


def _resolve_identities(user_ids, events, directory) -> list[dict]:
    out = []
    for uid in user_ids:
        u = directory.user(uid) if directory else None
        if u:
            out.append({"id": u["id"], "name": u["upn"], "roles": u.get("roles", [])})
        else:
            name = next((e.actor["name"] for e in events if e.actor.get("id") == uid), uid)
            out.append({"id": uid, "name": name, "roles": []})
    return out


def _resolve_apps(app_ids, events, directory) -> list[dict]:
    out = []
    for app_id in app_ids:
        a = directory.app(app_id) if directory else None
        consent = next((e for e in events if e.action == "oauth.consent" and e.application_id == app_id), None)
        out.append({
            "app_id": app_id,
            "name": (a or {}).get("display_name") or (consent.target.get("name") if consent else app_id),
            "publisher": (a or {}).get("publisher", ""),
            "verified": (a or {}).get("verified_publisher"),
            "owner_tenant": (a or {}).get("owner_tenant_id", ""),
            "home_tenant": directory.tenant_id if directory else "",
            "service_principal_id": (a or {}).get("service_principal_id")
                                    or (consent.details.get("service_principal_id") if consent else ""),
            "created": (a or {}).get("created", ""),
        })
    return out


# ---------------------------------------------------------------- main entry
def correlate(signals: list[DetectionSignal], events_by_id: dict, directory: Directory,
              telemetry_available: list[str], now: str) -> list[Incident]:
    incidents, claimed = [], set()
    ordered = sorted(signals, key=lambda s: s.timestamp)

    for chain in CHAINS:
        window = timedelta(hours=chain.window_hours)
        for anchor in [s for s in ordered if s.rule_id == chain.anchor]:
            if anchor.signal_id in claimed:
                continue
            key = tuple(anchor.entities.get(k) for k in chain.key_fields)
            if not all(key):
                continue
            t0 = parse_ts(anchor.timestamp)

            related = []
            for s in ordered:
                if s is anchor or s.signal_id in claimed or s.rule_id not in chain.all_rules:
                    continue
                if tuple(s.entities.get(k) for k in chain.key_fields) != key:
                    continue
                required_rules = {r for group in chain.required for r in group}
                if chain.distinct_events and s.event_id == anchor.event_id and s.rule_id in required_rules:
                    continue  # a required step must be a separate event, not the anchor event itself
                dt = parse_ts(s.timestamp) - t0
                in_window = (timedelta(0) <= dt <= window) if chain.after_anchor else (abs(dt) <= window)
                if in_window:
                    related.append(s)

            present = {s.rule_id for s in related}
            if not all(present & set(group) for group in chain.required):
                continue

            chosen = [anchor] + related
            claimed.update(s.signal_id for s in chosen)
            incidents.append(_build_incident(chain, key, anchor, chosen, events_by_id, directory,
                                             telemetry_available, now))
    return incidents


def _build_incident(chain, key, anchor, chosen, events_by_id, directory, telemetry_available, now) -> Incident:
    evidence_ids = sorted({s.event_id for s in chosen}, key=lambda i: events_by_id[i].timestamp)
    evidence = [events_by_id[i] for i in evidence_ids]
    t_first, t_last = parse_ts(evidence[0].timestamp), parse_ts(evidence[-1].timestamp)
    pad = timedelta(hours=chain.window_hours)
    context = sorted(
        (e for e in events_by_id.values()
         if e.event_id not in evidence_ids and _event_matches_key(e, chain.key_fields, key)
         and t_first - pad <= parse_ts(e.timestamp) <= t_last + pad),
        key=lambda e: e.timestamp)

    keyed = dict(zip(chain.key_fields, key))
    identities = _resolve_identities([keyed["user"]] if "user" in keyed else [], evidence, directory)
    if not identities and chain.scenario == "vm_suspicious_activity":
        identities = [{"id": n, "name": n, "roles": []}
                      for n in sorted({e.actor["name"] for e in evidence if e.actor.get("name")})]
    apps = _resolve_apps([keyed["app"]] if "app" in keyed else [], evidence, directory)
    if "vm" in keyed:
        assets = [keyed["vm"]]
    else:
        assets = sorted({e.asset for e in evidence if e.asset and e.asset != "Entra ID"} |
                        {f"App: {e.target.get('name')}" for e in evidence if e.action.startswith("priv.")})

    rule_ids_by_event = {}
    for s in chosen:
        rule_ids_by_event.setdefault(s.event_id, []).append(s.rule_id)
    timeline = [{"timestamp": e.timestamp, "event_id": e.event_id, "source": e.source,
                 "label": describe_event(e), "rule_ids": sorted(rule_ids_by_event.get(e.event_id, [])),
                 "role": "evidence" if e.event_id in evidence_ids else "context"}
                for e in sorted(evidence + context, key=lambda e: e.timestamp)]

    severity = score_severity(chain, chosen, evidence, identities, apps)
    confidence = score_confidence(chain, chosen, evidence, apps, telemetry_available)

    if apps:
        name = apps[0]["name"]
        subject = name if len(name) <= 60 else name[:57] + "..."
    else:
        subject = identities[0]["name"] if identities else key[0]
    if chain.scenario == "vm_suspicious_activity":
        subject = key[0].rsplit("/", 1)[-1]
    who = identities[0]["name"] if identities and chain.scenario != "vm_suspicious_activity" else ""
    title = f"{chain.title}: {subject}" + (f" ({who})" if who and who != subject else "")

    digest = hashlib.sha256(f"{chain.chain_id}|{'|'.join(key)}|{anchor.event_id}".encode()).hexdigest()
    return Incident(
        incident_id="INC-" + digest[:8].upper(),
        scenario=chain.scenario, title=title, created_at=now,
        first_seen=evidence[0].timestamp, last_seen=evidence[-1].timestamp,
        correlation={"chain_id": chain.chain_id, "key": keyed, "window_hours": chain.window_hours,
                     "anchor_signal": anchor.signal_id, "anchor_rule": anchor.rule_id,
                     "required": chain.required, "matched_rules": sorted({s.rule_id for s in chosen})},
        affected_identities=identities, affected_assets=assets, applications=apps,
        signal_ids=[s.signal_id for s in chosen], evidence_event_ids=evidence_ids,
        context_event_ids=[e.event_id for e in context], timeline=timeline,
        severity=severity, confidence=confidence,
        recommended_actions=catalog.DEFAULT_RECOMMENDATION[chain.scenario],
        allowed_actions=catalog.allowed_actions(chain.scenario, severity["level"], confidence["level"]),
        action_targets=catalog.action_targets(chain.scenario, identities, apps, assets),
        telemetry_available=sorted(telemetry_available),
        detection_version=config.DETECTION_VERSION,
    )
