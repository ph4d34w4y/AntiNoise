"""AI investigator.

Input:  one Incident (already detected and scored by code) + its events + signals.
Output: an explanation that is validated before anyone sees it.

The model runs on your own server by default (LLM_PROVIDER=local), so incident
data never leaves your network. If no model is configured or it fails, a
deterministic summary is produced instead and clearly labelled as such.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone

from .. import config
from . import llm, prompts, validator

MAX_FIELD_CHARS = 400   # long attacker-controlled strings (app names, command lines) are cut to this


def build_context(incident: dict, events: list[dict], signals: list[dict]) -> dict:
    """The exact data the model sees. Raw provider JSON is left out to keep it
    small; every normalized field that matters is included."""
    def slim(e):
        return {k: e.get(k) for k in ("event_id", "timestamp", "source", "action", "actor", "target", "asset",
                                      "source_ip", "application_id", "permissions", "process", "file_hash",
                                      "location", "details") if e.get(k)}
    evidence_ids = set(incident["evidence_event_ids"])
    return {
        "incident_id": incident["incident_id"],
        "scenario": incident["scenario"],
        "title": incident["title"],
        "first_seen": incident["first_seen"], "last_seen": incident["last_seen"],
        "correlation": incident["correlation"],
        "affected_identities": incident["affected_identities"],
        "affected_assets": incident["affected_assets"],
        "applications": incident["applications"],
        "severity": incident["severity"],
        "confidence": incident["confidence"],
        "telemetry_available": incident["telemetry_available"],
        "allowed_actions": incident["allowed_actions"],
        "signals": [{"rule_id": s["rule_id"], "rule_name": s["rule_name"], "event_id": s["event_id"],
                     "summary": s["summary"]} for s in signals],
        "evidence_events": [slim(e) for e in events if e["event_id"] in evidence_ids],
        "context_events": [slim(e) for e in events if e["event_id"] not in evidence_ids],
    }


def _shorten(value):
    if isinstance(value, str) and len(value) > MAX_FIELD_CHARS:
        return value[:MAX_FIELD_CHARS] + f"...[truncated {len(value) - MAX_FIELD_CHARS} chars]"
    if isinstance(value, dict):
        return {k: _shorten(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_shorten(v) for v in value]
    return value


def fit_to_budget(ctx: dict, budget_tokens: int) -> tuple[dict, list[str]]:
    """Small local models have small context windows. Rather than let the server
    silently cut the prompt, we shrink it ourselves in a known order and record it."""
    notes = []
    est = lambda c: len(json.dumps(c, default=str)) // 3 + 900   # rough tokens incl. system prompt
    ctx = _shorten(ctx)
    if est(ctx) > budget_tokens and ctx["context_events"]:
        notes.append(f"Omitted {len(ctx['context_events'])} context events (no rule matched) to fit the model context")
        ctx = {**ctx, "context_events": []}
    while est(ctx) > budget_tokens and len(ctx["evidence_events"]) > 1:
        ctx = {**ctx, "evidence_events": ctx["evidence_events"][:-1]}
        notes.append("Dropped the latest evidence event to fit the model context")
    if est(ctx) > budget_tokens:
        notes.append("Incident still exceeds the model context; output may be incomplete")
    return ctx, notes


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _data_block(ctx: dict) -> str:
    return "<incident_data>\n" + json.dumps(ctx, indent=1, default=str) + "\n</incident_data>"


def _fallback(incident: dict, signals: list[dict]) -> dict:
    return {
        "summary": (f"{incident['title']}. {len(incident['evidence_event_ids'])} evidence events between "
                    f"{incident['first_seen']} and {incident['last_seen']} matched "
                    f"{len(incident['correlation']['matched_rules'])} detection rules. "
                    f"Severity {incident['severity']['level']} ({incident['severity']['score']}), "
                    f"confidence {incident['confidence']['level']} ({incident['confidence']['score']})."),
        "findings": [{"statement": s["summary"], "evidence_ids": [s["event_id"]]} for s in signals],
        "severity_explanation": "; ".join(f"{r['factor']} (+{r['points']})" for r in incident["severity"]["reasons"]),
        "confidence_explanation": "; ".join(f"{r['factor']} (+{r['points']})" for r in incident["confidence"]["reasons"]),
        "gaps": [l["text"] for l in incident["confidence"]["limitations"]],
        "next_steps": [],
        "recommended_actions": [{"action": a, "rationale": "Default recommendation for this scenario",
                                 "evidence_ids": incident["evidence_event_ids"][:1]}
                                for a in incident["recommended_actions"] if a in incident["allowed_actions"]],
    }


def investigate(incident: dict, events: list[dict], signals: list[dict]) -> dict:
    ctx = build_context(incident, events, signals)
    input_hash = hashlib.sha256(json.dumps(ctx, sort_keys=True, default=str).encode()).hexdigest()
    base = {"assessment_id": f"ai_{uuid.uuid4().hex[:16]}",
            "incident_id": incident["incident_id"], "created_at": _now(),
            "prompt_version": prompts.PROMPT_VERSION, "input_hash": input_hash}

    if not config.llm_configured():
        clean, errors = validator.validate_assessment(_fallback(incident, signals), incident)
        return {**base, "mode": "deterministic_fallback", "model": "none",
                "raw_output": "", "validated": clean, "validation_errors": errors}
    try:
        sent, notes = fit_to_budget(ctx, llm.context_budget_tokens())
        raw = llm.complete(prompts.SYSTEM_INVESTIGATE,
                           [{"role": "user", "content": _data_block(sent) + "\n\nInvestigate this incident."}],
                           json_mode=True)
        clean, errors = validator.validate_assessment(validator.parse_json(raw), incident)
        return {**base, "mode": "llm", "model": config.llm_model_label(), "raw_output": raw,
                "validated": clean, "validation_errors": notes + errors}
    except Exception as exc:  # network error, bad JSON, rate limit: fall back, and say so
        clean, errors = validator.validate_assessment(_fallback(incident, signals), incident)
        return {**base, "mode": "deterministic_fallback", "model": config.llm_model_label(),
                "raw_output": f"LLM call failed: {exc}", "validated": clean,
                "validation_errors": errors + [f"Model unavailable or output unusable, deterministic summary shown "
                                               f"({type(exc).__name__}: {str(exc)[:160]})"]}


def answer_question(incident: dict, events: list[dict], signals: list[dict], question: str,
                    history: list[dict]) -> dict:
    base = {"chat_id": f"chat_{uuid.uuid4().hex[:16]}", "incident_id": incident["incident_id"],
            "created_at": _now(), "question": question, "prompt_version": prompts.PROMPT_VERSION}
    if not config.llm_configured():
        return {**base, "mode": "unavailable", "model": "none",
                "answer": "The AI investigator is not configured (LLM_PROVIDER / model settings). "
                          "The evidence, rules and score reasons on this page are complete without it.",
                "check": {"cited": [], "unknown": [], "warnings": []}}
    ctx, _ = fit_to_budget(build_context(incident, events, signals),
                           llm.context_budget_tokens() - 300 * min(len(history), 6))
    messages = [{"role": "user", "content": _data_block(ctx) + "\n\nI will ask questions about this incident."},
                {"role": "assistant", "content": "Understood. I will answer only from the incident data."}]
    for turn in history[-6:]:
        messages += [{"role": "user", "content": turn["question"]},
                     {"role": "assistant", "content": turn["answer"]}]
    messages.append({"role": "user", "content": question})
    try:
        answer = llm.complete(prompts.SYSTEM_QA, messages)
    except Exception as exc:
        answer = f"The AI investigator could not be reached ({type(exc).__name__}: {str(exc)[:160]}). No answer was generated."
    return {**base, "mode": "llm", "model": config.llm_model_label(), "answer": answer,
            "check": validator.validate_answer(answer, incident)}
