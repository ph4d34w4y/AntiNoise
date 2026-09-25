# 48-hour plan

The interfaces are in `app/schemas.py` and the fixtures already run end to end, so nobody waits on
anybody. Each person owns files, not features, to avoid merge conflicts.

| | Dev 1: identity/cloud | Dev 2: endpoint/VM | Dev 3: platform/AI/UI |
|---|---|---|---|
| Owns | `adapters/azure*.py`, identity rules, `response/graph_actions.py`, `docs/azure_setup.md` | `adapters/vm.py`, VM rules, `response/vm_isolation.py`, `docs/vm_telemetry.md` | `correlation.py`, `scoring.py`, `ai/`, `pipeline.py`, `main.py`, templates, ledger |
| Hours 0–4 | Everyone: run the app and tests, read the schemas, agree the demo story | | |
| Hours 4–12 | Tenant, two app registrations, consent settings; run `collect_live.py` against real audit logs | Deploy Windows + Linux VMs, install Sysmon, build isolation NSG | Stand up Ollama on the demo machine, run `eval_local_model.py` on 2–3 models, pick one |
| Hours 12–24 | Stage scenarios A–C, fix normalizer mismatches against real records, save captures | Stage scenario D safely, export, import, fix mismatches | Tune prompts for the chosen model, scoring weights, UI polish, Q&A quality |
| Hours 24–36 | Live revoke grant, disable app, revoke sessions; verify each | Live isolate + restore; prove with a new connection | Freeze prompts; add a regression test per bug found |
| Hours 36–44 | Re-stage A for the demo; capture fresh data | Stretch only if everything above works: link VM user to identity incidents | Demo rehearsal x3, fallbacks tested with network off |
| Hours 44–48 | Freeze. Rehearse. Sleep. | | |

Cut order if behind: cross-domain correlation, a larger model (stay on the one that works), then live VM isolation (keep simulated), then live
M365 collection (use captures), then chat (keep the summary). Never cut: evidence, two scores,
approval, false positive, audit.
