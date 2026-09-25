"""Deterministic checks on everything the LLM returns.

The model's output is never trusted directly. Anything that cites an event
that isn't in the incident, or recommends an action that isn't allowed for
this incident, is removed and the reason is recorded.
"""
import json
import re

EVT_PATTERN = re.compile(r"evt_[0-9a-f]{12}")


def parse_json(text: str) -> dict:
    cleaned = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("No JSON object in model output")
    return json.loads(cleaned[start:end + 1])


def known_event_ids(incident: dict) -> set[str]:
    return set(incident["evidence_event_ids"]) | set(incident.get("context_event_ids", []))


def validate_assessment(parsed: dict, incident: dict) -> tuple[dict, list[str]]:
    known = known_event_ids(incident)
    allowed = set(incident["allowed_actions"])
    errors = []
    clean = {
        "summary": str(parsed.get("summary", "")),
        "severity_explanation": str(parsed.get("severity_explanation", "")),
        "confidence_explanation": str(parsed.get("confidence_explanation", "")),
        "gaps": [str(g) for g in parsed.get("gaps", []) if g],
        "next_steps": [str(s) for s in parsed.get("next_steps", []) if s],
        "findings": [],
        "recommended_actions": [],
    }

    for f in parsed.get("findings", []) or []:
        ids = [i for i in f.get("evidence_ids", []) if isinstance(i, str)]
        unknown = [i for i in ids if i not in known]
        if not ids:
            errors.append(f"Finding removed (no evidence cited): {str(f.get('statement'))[:120]}")
        elif unknown:
            errors.append(f"Finding removed (cites unknown event IDs {unknown}): {str(f.get('statement'))[:120]}")
        else:
            clean["findings"].append({"statement": str(f.get("statement", "")), "evidence_ids": ids})

    for r in parsed.get("recommended_actions", []) or []:
        action = str(r.get("action", ""))
        ids = [i for i in r.get("evidence_ids", []) if isinstance(i, str)]
        if action not in allowed:
            errors.append(f"Recommendation removed: '{action}' is not an allowed action for this incident")
            continue
        unknown = [i for i in ids if i not in known]
        if unknown:
            errors.append(f"Recommendation '{action}' removed (cites unknown event IDs {unknown})")
            continue
        clean["recommended_actions"].append({"action": action, "rationale": str(r.get("rationale", "")),
                                             "evidence_ids": ids})

    # Free-text fields may also mention event IDs; flag any that don't exist.
    for field in ("summary", "severity_explanation", "confidence_explanation"):
        bad = [i for i in EVT_PATTERN.findall(clean[field]) if i not in known]
        if bad:
            errors.append(f"{field} mentions unknown event IDs {sorted(set(bad))}")
    return clean, errors


def validate_answer(answer: str, incident: dict) -> dict:
    known = known_event_ids(incident)
    cited = sorted(set(EVT_PATTERN.findall(answer)))
    unknown = [i for i in cited if i not in known]
    says_unknown = "does not establish" in answer.lower() or "not available" in answer.lower()
    warnings = []
    if unknown:
        warnings.append(f"Answer cites event IDs that are not in this incident: {', '.join(unknown)}")
    if not cited and not says_unknown:
        warnings.append("Answer cites no evidence. Treat it as unverified.")
    return {"cited": [i for i in cited if i in known], "unknown": unknown, "warnings": warnings}
