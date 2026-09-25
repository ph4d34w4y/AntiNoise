# Contributing

AntiNoise was built as a hackathon prototype. Small, reviewable changes are preferred.

## Local development

1. Create a virtual environment.
2. Install `requirements.txt`.
3. Copy `.env.example` to `.env`.
4. Leave live-response settings disabled unless you are using disposable test resources.
5. Run `pytest -q` before submitting a change.

## Design rules

Contributions should preserve these boundaries:

- deterministic code creates detections and scores;
- AI output is treated as untrusted;
- structured AI claims must remain evidence-grounded;
- response actions must come from a fixed catalog;
- risky actions require explicit enablement and analyst approval;
- important decisions/actions must remain auditable.

Never include real secrets or private tenant telemetry in an issue, fixture, pull request, or test.
