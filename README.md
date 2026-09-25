[README.md](https://github.com/user-attachments/files/32672630/README.md)

# AntiNoise

**Turn security noise into actionable evidence.**

AntiNoise is a lightweight, open-source security investigation prototype for SOC analysts and security engineers. It converts Microsoft/Azure identity, cloud, and VM telemetry into evidence-backed incidents using deterministic detection and correlation, calculates severity and confidence with transparent code, uses an optional AI investigator to explain verified incident context, and keeps response authority with the analyst.

> **Hackathon scope:** Microsoft/Azure implementation. The normalized event model is provider-neutral, but AWS and Google Cloud adapters are not implemented in this MVP.

## Why AntiNoise?

Cloud identity attacks can use legitimate credentials, OAuth grants, sessions, and cloud APIs. Individual events can look ordinary when viewed alone. AntiNoise is designed to help an analyst answer:

- What happened?
- Which events support that conclusion?
- How severe could the impact be?
- How strong is the available evidence?
- What defensive actions are allowed?
- What did the analyst and system do afterward?

The core trust model is:

**Code establishes facts → AI explains facts → Human authorizes action → Code executes a bounded action**

## Architecture

```text
Security telemetry
  ├─ Microsoft Entra / Microsoft 365
  └─ Windows / Linux VM telemetry
            │
            ▼
       Normalization
            │
            ▼
 Deterministic detection
            │
            ▼
       Correlation
            │
            ▼
          Incident
     ┌───────────────┐
     │ Severity      │  potential impact
     │ Confidence    │  evidence strength
     └───────────────┘
            │
            ▼
   Verified evidence context
            │
            ▼
     AI investigator
            │
            ▼
       SOC analyst
            │
       approve / reject
            ▼
     Bounded response
            │
            ▼
   Tamper-evident audit ledger
```

The LLM does **not** create incidents or calculate severity/confidence. Structured AI findings and recommendations are validated against incident evidence and allowed actions. The response executor independently enforces the action catalog and derives targets from incident data.

## Demo scenarios

The included fixtures exercise the same downstream pipeline as collector input:

| Fixture | Scenario |
|---|---|
| `a_oauth_malicious_consent.json` | Malicious OAuth consent and subsequent resource access |
| `b_session_misuse.json` | Possible account takeover / persistence sequence |
| `c_privilege_escalation.json` | Privileged role escalation followed by privileged changes |
| `d_vm_suspicious_activity.json` | Suspicious Windows and Linux process activity |
| `e_oauth_migration_benign.json` | Benign migration pattern used for false-positive handling |

Fixtures contain representative test data. They do not inject a pre-written incident; they enter at the telemetry boundary and must pass through normalization, detection, correlation, scoring, investigation, and audit logic.

## Quick start

### Requirements

- Python 3.10+ recommended
- Optional: [Ollama](https://ollama.com/) or another supported local/OpenAI-compatible model server
- Optional: Microsoft tenant credentials for live collectors or enabled response actions

### Run locally

```bash
python -m venv .venv

# macOS / Linux
source .venv/bin/activate

# Windows PowerShell
# .venv\Scripts\Activate.ps1

pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

On Windows, copy `.env.example` to `.env` manually or use:

```powershell
Copy-Item .env.example .env
```

Then open:

```text
http://127.0.0.1:8000
```

Use **Replay sample telemetry** to exercise the sample scenarios.

Without Microsoft credentials, response actions remain simulated. Without a reachable LLM, the deterministic security pipeline continues and the investigator returns a fallback summary.

## Optional local AI

The default configuration targets a local Ollama instance:

```bash
ollama pull qwen2.5:7b
```

See [`docs/local_llm.md`](docs/local_llm.md) for supported local/OpenAI-compatible configurations.

AntiNoise can also be configured for a hosted Anthropic API. **If a hosted provider is enabled, incident context is sent to that provider.** Use a local provider when security data must remain within your controlled AI environment.

## Tests

```bash
pytest -q
```

At the time this repository package was prepared, the included automated suite passed **14/14 tests**.

The suite covers detection/correlation behavior, scoring, AI validation, local-model failure handling, response restrictions, and audit-chain tamper detection.

Useful scripts:

```bash
python scripts/run_pipeline.py
python scripts/eval_local_model.py
python scripts/verify_ledger.py
python scripts/reset_demo.py
```

## Safety boundaries

AntiNoise is intentionally designed so the AI is not the security authority.

- Detection happens before AI investigation.
- Severity and confidence are deterministic.
- Structured findings must cite incident evidence.
- Structured recommendations are restricted to allowed actions.
- Response targets are derived from incident data.
- Potentially disruptive response remains analyst-controlled.
- Live response must be explicitly configured; otherwise actions are simulated.
- The audit ledger is hash-chained and tamper-evident.
- LLM failure does not stop deterministic detection/scoring.

A model can still produce incorrect free-form text. AntiNoise does not claim to eliminate LLM hallucination; it constrains how model output can affect structured findings and response.

## Live integration status

The codebase contains collectors and response integrations for Microsoft services and Azure.

For the hackathon environment, real Microsoft Entra authentication activity was generated successfully, but the test environment returned HTTP 403 when the application attempted programmatic sign-in-log retrieval. The demo therefore uses representative telemetry at that collector boundary.

Live Microsoft behavior depends on tenant configuration, permissions, licensing, auditing, and the specific API being used. Test live integrations with disposable test users/apps before enabling response actions.

See [`docs/azure_setup.md`](docs/azure_setup.md) for setup guidance.

## Response actions

The response catalog includes actions such as:

- `REVOKE_OAUTH_GRANT`
- `REVOKE_USER_SESSIONS`
- `DISABLE_APPLICATION`
- `DISABLE_USER`
- `ISOLATE_VM`
- `ESCALATE_INCIDENT`
- `NO_ACTION`

Not every catalog action has a live executor. Anything not explicitly enabled/configured is simulated and recorded.

**Use disposable test identities, applications, and VMs when testing live containment.**

## Repository map

```text
app/
  adapters/          telemetry normalization + live collectors
  detection/         rules, engine, correlation, scoring
  ai/                model clients, prompts, investigator, validator
  response/          response catalog and bounded executors
  templates/         UI templates
  static/            UI assets
  schemas.py         normalized data structures
  pipeline.py        orchestration
  ledger.py          hash-chained audit ledger
  store.py           incident/event storage
  main.py            FastAPI application

fixtures/            representative demo telemetry
config/              local IOC configuration
docs/                setup, telemetry, AI, demo, and team documentation
scripts/             CLI/demo/support utilities
tests/               automated test suite
```

## Adding a rule or provider

A new detection rule belongs in `app/detection/rules.py` and is registered in `RULES`.

A new correlation scenario belongs in `app/detection/correlation.py`.

A future cloud provider adapter should normalize its native telemetry into the existing `NormalizedEvent` schema so downstream detection, scoring, investigation, and UI logic can remain provider-independent.

## What AntiNoise is not

This MVP is not:

- a full SIEM
- an EDR or antivirus product
- a vulnerability scanner
- a behavioral-ML anomaly platform
- an autonomous SOC
- a replacement for Microsoft Sentinel, Splunk, or similar enterprise platforms

It is a focused prototype demonstrating an explainable security investigation workflow with deterministic evidence handling, optional AI assistance, bounded response, and auditability.

## Security and responsible testing

Never commit `.env`, tenant secrets, access tokens, live captures, private keys, or production security telemetry.

Before publishing a fork or accepting contributions, see [`SECURITY.md`](SECURITY.md).

## License

No open-source license has been selected in this package yet. Before publishing the repository as open source, add the license your team agrees to use (for example MIT or Apache-2.0). Without a license, others can view the public repository but do not automatically receive permission to reuse, modify, or distribute the code.
