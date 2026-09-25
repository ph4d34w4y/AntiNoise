"""Severity and confidence: two separate, additive, explainable scores.

Severity   = "how damaging could this be if it is what it looks like?"
Confidence = "how strongly does the evidence we actually have support the conclusion?"

Every point added or removed is recorded as a reason, so the UI (and the AI)
can show exactly where each number came from. Confidence is a 0-100 evidence
score, NOT a calibrated probability, and is capped at 95: telemetry alone never
proves intent.
"""
from datetime import timedelta

from .. import config
from ..adapters import SOURCE_LABELS
from ..adapters.base import parse_ts
from .rules import HIGH_RISK_SCOPES, PRIVILEGED_ROLES, RULES_BY_ID, TENANT_CONTROL_ROLES


def severity_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def confidence_level(score: int) -> str:
    if score >= 75:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"


def _rule_reasons(signals, attr):
    by_rule = {}
    for s in signals:
        by_rule.setdefault(s.rule_id, []).append(s.event_id)
    out = []
    for rule_id, event_ids in by_rule.items():
        pts = getattr(RULES_BY_ID[rule_id], attr)
        if pts:
            out.append({"factor": RULES_BY_ID[rule_id].name, "points": pts, "evidence": sorted(set(event_ids))})
    return out


def score_severity(chain, signals, events, identities, apps) -> dict:
    reasons = [{"factor": f"Scenario base: {chain.title}", "points": chain.base_severity, "evidence": []}]
    reasons += _rule_reasons(signals, "severity_points")

    privileged = sorted({r for i in identities for r in i.get("roles", []) if r in PRIVILEGED_ROLES})
    if privileged:
        reasons.append({"factor": f"Affected identity holds privileged role(s): {', '.join(privileged)}",
                        "points": 20, "evidence": []})

    assigned = {e.details.get("role_name") for e in events if e.action == "role.assign"}
    if assigned & TENANT_CONTROL_ROLES:
        reasons.append({"factor": f"Tenant-control role involved: {', '.join(sorted(assigned & TENANT_CONTROL_ROLES))}",
                        "points": 15, "evidence": [e.event_id for e in events if e.action == "role.assign"]})

    scopes = {p for e in events if e.action == "oauth.consent" for p in e.permissions}
    consent_ids = [e.event_id for e in events if e.action == "oauth.consent"]
    if scopes & HIGH_RISK_SCOPES:
        reasons.append({"factor": f"Write/send scopes granted: {', '.join(sorted(scopes & HIGH_RISK_SCOPES))}",
                        "points": 10, "evidence": consent_ids})
    if "offline_access" in scopes:
        reasons.append({"factor": "offline_access granted (long-lived refresh tokens)", "points": 5,
                        "evidence": consent_ids})

    access = [e for e in events if e.event_type == "resource_access"]
    items = sum(int(e.details.get("item_count", 0) or 0) for e in access)
    if items >= config.HIGH_VOLUME_ITEM_THRESHOLD:
        reasons.append({"factor": f"High-volume access: {items} items (threshold {config.HIGH_VOLUME_ITEM_THRESHOLD})",
                        "points": 10, "evidence": [e.event_id for e in access]})

    score = min(100, sum(r["points"] for r in reasons))
    return {"score": score, "level": severity_level(score), "reasons": reasons}


def score_confidence(chain, signals, events, apps, telemetry_available) -> dict:
    reasons = _rule_reasons(signals, "confidence_points")
    limitations = [{"text": t, "points": 0} for t in chain.standing_limitations]

    consent_times = [parse_ts(e.timestamp) for e in events if e.action == "oauth.consent"]
    for app in apps:
        if app.get("verified") is False:
            reasons.append({"factor": f"Publisher of '{app['name'][:60]}' is not verified", "points": 5, "evidence": []})
        if app.get("owner_tenant") and app.get("owner_tenant") != app.get("home_tenant"):
            reasons.append({"factor": "Application is registered in another tenant", "points": 5, "evidence": []})
        elif app.get("owner_tenant") and app.get("owner_tenant") == app.get("home_tenant"):
            limitations.append({"text": "Mitigating: application is registered in this tenant (internal app)",
                                "points": -15})
        if app.get("created") and consent_times:
            if min(consent_times) - parse_ts(app["created"]) <= timedelta(days=7):
                reasons.append({"factor": "Application was created within 7 days of the consent", "points": 5,
                                "evidence": []})

    for source in chain.useful_sources:
        if source not in telemetry_available:
            limitations.append({"text": f"{SOURCE_LABELS[source]} not available: related activity cannot be observed",
                                "points": -8})

    raw = sum(r["points"] for r in reasons) + sum(l["points"] for l in limitations)
    score = max(5, min(95, raw))
    if raw > 95:
        limitations.append({"text": "Capped at 95: telemetry cannot establish intent", "points": 0})
    return {"score": score, "level": confidence_level(score), "reasons": reasons, "limitations": limitations}
