"""Apply every rule to every event and produce DetectionSignals."""
import hashlib

from .. import config
from ..schemas import DetectionSignal, NormalizedEvent
from .rules import RULES, build_context


def detect(events: list[NormalizedEvent], tenant_domains: list[str]) -> list[DetectionSignal]:
    ctx = build_context(events, tenant_domains)
    signals = []
    for event in events:
        for rule in RULES:
            hit = rule.match(event, ctx)
            if not hit:
                continue
            sid = "sig_" + hashlib.sha256(f"{rule.rule_id}|{event.event_id}".encode()).hexdigest()[:12]
            signals.append(DetectionSignal(
                signal_id=sid, rule_id=rule.rule_id, rule_name=rule.name, event_id=event.event_id,
                timestamp=event.timestamp, entities=hit["entities"],
                severity_points=rule.severity_points, confidence_points=rule.confidence_points,
                summary=hit["summary"], detection_version=config.DETECTION_VERSION,
            ))
    return signals
