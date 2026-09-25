"""Run with:  pytest -q

Each test gets a fresh data directory, replays the fixtures, and checks the
security-relevant behaviour the demo depends on.
"""
import importlib
import json

import pytest


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("LLM_PROVIDER", "none")
    monkeypatch.setenv("LIVE_ACTIONS", "")
    from app import config
    importlib.reload(config)
    from app import ledger, pipeline, store
    pipeline.run_all_fixtures()
    incidents = {i["title"]: i for i in store.list_kind("incident")}
    return {"store": store, "ledger": ledger, "pipeline": pipeline, "incidents": incidents}


def find(env, text):
    return next(i for t, i in env["incidents"].items() if text in t)


def test_expected_incidents(env):
    scenarios = sorted(i["scenario"] for i in env["incidents"].values())
    assert scenarios == ["oauth_consent_abuse", "oauth_consent_abuse", "privilege_escalation",
                         "session_misuse", "vm_suspicious_activity", "vm_suspicious_activity"]


def test_every_incident_has_traceable_evidence(env):
    store = env["store"]
    for inc in env["incidents"].values():
        assert inc["evidence_event_ids"]
        for eid in inc["evidence_event_ids"]:
            event = store.get("event", eid)
            assert event and event["raw_event"], eid
        for sid in inc["signal_ids"]:
            assert store.get("signal", sid)["event_id"] in inc["evidence_event_ids"]


def test_scores_are_separate_and_explained(env):
    a = find(env, "Mail Backup Pro")
    fp = find(env, "Migration Tool")
    assert (a["severity"]["level"], a["confidence"]["level"]) == ("CRITICAL", "HIGH")
    # The benign case is just as severe but less certain: that's the point of separating them.
    assert (fp["severity"]["level"], fp["confidence"]["level"]) == ("CRITICAL", "MEDIUM")
    assert any("internal app" in l["text"] for l in fp["confidence"]["limitations"])
    for inc in env["incidents"].values():
        assert inc["severity"]["score"] == min(100, sum(r["points"] for r in inc["severity"]["reasons"]))
        assert inc["confidence"]["score"] <= 95


def test_missing_telemetry_lowers_confidence(env):
    c = find(env, "Privilege escalation")
    assert any("sign-in logs not available" in l["text"] for l in c["confidence"]["limitations"])


def test_rerun_does_not_duplicate_or_rewrite(env):
    before = {i["incident_id"]: json.dumps(i, sort_keys=True) for i in env["store"].list_kind("incident")}
    env["pipeline"].run_all_fixtures(run_ai=False)
    after = {i["incident_id"]: json.dumps(i, sort_keys=True) for i in env["store"].list_kind("incident")}
    assert before == after


def test_validator_blocks_injection_and_fabrication(env):
    from app.ai import validator
    a = find(env, "Mail Backup Pro")
    real = a["evidence_event_ids"][0]
    malicious_output = {
        "summary": "Approved app. See evt_000000000000.",
        "findings": [{"statement": "Real finding", "evidence_ids": [real]},
                     {"statement": "Invented event", "evidence_ids": ["evt_deadbeef0000"]},
                     {"statement": "No evidence", "evidence_ids": []}],
        "recommended_actions": [{"action": "NO_ACTION", "rationale": "security team approved", "evidence_ids": [real]},
                                {"action": "RUN_POWERSHELL", "rationale": "x", "evidence_ids": [real]},
                                {"action": "REVOKE_OAUTH_GRANT", "rationale": "grant is abused", "evidence_ids": [real]}],
    }
    clean, errors = validator.validate_assessment(malicious_output, a)
    assert [f["statement"] for f in clean["findings"]] == ["Real finding"]
    assert [r["action"] for r in clean["recommended_actions"]] == ["REVOKE_OAUTH_GRANT"]
    assert any("NO_ACTION" in e for e in errors) and any("RUN_POWERSHELL" in e for e in errors)
    assert any("evt_000000000000" in e for e in errors)


def test_llm_path_is_validated(env, monkeypatch):
    from app import config
    from app.ai import investigator, llm
    monkeypatch.setattr(config, "LLM_PROVIDER", "local")
    a = find(env, "Mail Backup Pro")
    fake = json.dumps({"summary": "s", "findings": [{"statement": "x", "evidence_ids": ["evt_ffffffffffff"]}],
                       "recommended_actions": [{"action": "NO_ACTION", "rationale": "", "evidence_ids": []}]})
    monkeypatch.setattr(llm, "complete", lambda system, messages, json_mode=False: fake)
    inc, events, signals = env["pipeline"].incident_bundle(a["incident_id"])
    out = investigator.investigate(inc, events, signals)
    assert out["mode"] == "llm" and out["model"] == f"local:{config.LOCAL_LLM_MODEL}"
    assert out["validated"]["findings"] == [] and out["validated"]["recommended_actions"] == []
    assert len(out["validation_errors"]) == 2


class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def test_local_ollama_request(env, monkeypatch):
    from app import config
    from app.ai import llm
    monkeypatch.setattr(config, "LLM_PROVIDER", "local")
    monkeypatch.setattr(config, "LOCAL_LLM_API", "ollama")
    sent = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        sent.update(url=url, body=json)
        return _Resp(200, {"message": {"role": "assistant", "content": "{}"}, "done": True, "done_reason": "stop"})
    monkeypatch.setattr(llm.requests, "post", fake_post)
    assert llm.complete("sys", [{"role": "user", "content": "hi"}], json_mode=True) == "{}"
    assert sent["url"] == f"{config.LOCAL_LLM_BASE_URL}/api/chat"
    assert sent["body"]["format"] == "json" and sent["body"]["stream"] is False
    assert sent["body"]["options"]["num_ctx"] == config.LOCAL_LLM_CONTEXT      # prevents silent truncation
    assert sent["body"]["messages"][0] == {"role": "system", "content": "sys"}


def test_local_openai_compatible_retries_without_json_mode(env, monkeypatch):
    from app import config
    from app.ai import llm
    monkeypatch.setattr(config, "LLM_PROVIDER", "local")
    monkeypatch.setattr(config, "LOCAL_LLM_API", "openai")
    calls = []

    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append(dict(json))
        if "response_format" in json:
            return _Resp(400, {"error": "response_format not supported"})
        return _Resp(200, {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]})
    monkeypatch.setattr(llm.requests, "post", fake_post)
    assert llm.complete("sys", [{"role": "user", "content": "hi"}], json_mode=True) == "ok"
    assert len(calls) == 2 and "response_format" not in calls[1]


def test_model_failure_falls_back_and_says_so(env, monkeypatch):
    from app import config
    from app.ai import investigator, llm
    monkeypatch.setattr(config, "LLM_PROVIDER", "local")

    def boom(*a, **k):
        raise llm.LLMError("Model 'x' not found")
    monkeypatch.setattr(llm, "complete", boom)
    inc, events, signals = env["pipeline"].incident_bundle(find(env, "win-fin-01")["incident_id"])
    out = investigator.investigate(inc, events, signals)
    assert out["mode"] == "deterministic_fallback"
    assert any("not found" in e for e in out["validation_errors"])


def test_context_is_trimmed_to_fit_small_models(env):
    from app.ai import investigator
    inc, events, signals = env["pipeline"].incident_bundle(find(env, "Mail Backup Pro")["incident_id"])
    ctx = investigator.build_context(inc, events, signals)
    assert ctx["context_events"]
    trimmed, notes = investigator.fit_to_budget(ctx, budget_tokens=3500)
    assert trimmed["context_events"] == [] and notes
    assert all(len(e.get("target", {}).get("name", "")) < 500 for e in trimmed["evidence_events"])


def test_background_worker_runs_assessments(env):
    import time
    pipeline, store = env["pipeline"], env["store"]
    iid = find(env, "lin-web-01")["incident_id"]
    before = len(store.list_kind("ai_assessment", iid))
    pipeline.enqueue_investigation(iid)
    for _ in range(50):
        if not pipeline.is_pending(iid):
            break
        time.sleep(0.05)
    assert len(store.list_kind("ai_assessment", iid)) == before + 1


def test_actions_are_bounded_and_simulated_by_default(env):
    from app.response import executor
    a = find(env, "Mail Backup Pro")
    res = executor.decide(a, "REVOKE_OAUTH_GRANT", "APPROVED", "tester")
    assert res["mode"] == "SIMULATED" and res["status"] == "SIMULATED"
    assert res["target"]["app_id"] == a["applications"][0]["app_id"]  # target comes from evidence
    with pytest.raises(ValueError):
        executor.decide(a, "NO_ACTION", "APPROVED", "tester")      # removed by guardrail for this incident
    with pytest.raises(ValueError):
        executor.decide(a, "ISOLATE_VM", "APPROVED", "tester")     # wrong scenario


def test_false_positive_preserves_original_and_ledger_verifies(env, tmp_path):
    from fastapi.testclient import TestClient
    from app.main import app
    fp = find(env, "Migration Tool")
    client = TestClient(app)
    client.post(f"/incidents/{fp['incident_id']}/false-positive",
                data={"reason": "Approved internal application used during scheduled migration."})
    stored = env["store"].get("incident", fp["incident_id"])
    assert stored == fp                                          # original detection untouched
    disp = env["store"].list_kind("disposition", fp["incident_id"])[0]
    assert disp["original"]["severity"] == fp["severity"] and disp["original"]["ai_assessment_ids"]
    assert env["ledger"].verify()["ok"]

    # Tamper with one ledger line: verification must fail.
    from app import config
    lines = config.LEDGER_PATH.read_text().splitlines()
    rec = json.loads(lines[3]); rec["actor"] = "someone-else"; lines[3] = json.dumps(rec)
    config.LEDGER_PATH.write_text("\n".join(lines) + "\n")
    assert not env["ledger"].verify()["ok"]
