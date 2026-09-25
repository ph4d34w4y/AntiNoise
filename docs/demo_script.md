# Demo script (about 7 minutes)

Before going on stage: `python scripts/reset_demo.py`, confirm the local model is loaded (the incidents page says so), start the server, and keep a terminal ready for
`python scripts/verify_ledger.py`. If using live actions, re-stage the OAuth consent in the test tenant
shortly beforehand so there is a real grant to revoke.

1. **The problem (30 s).** Attackers abuse consent, sessions and roles; nothing malicious runs on the
   user's laptop. Signals are scattered across identity, mail, files and VMs.
2. **Ingest (30 s).** Click *Replay sample telemetry* (or *Collect from tenant*). Six incidents appear,
   sorted by severity.
3. **Scenario A evidence (90 s).** Open the Mail Backup Pro incident. Walk the evidence chain: consent
   with sensitive scopes, token use from an Amsterdam IP, 75 mail items, three file downloads. Click an
   event ID to show the raw Microsoft record.
4. **Two scores (45 s).** Severity 95 and confidence 90 are separate. Point at the bars: each segment
   is a named reason. Confidence is capped at 95 and lists what it cannot establish.
5. **AI, bounded (60 s).** Point out the app name: it contains instructions telling the AI to recommend
   no action. Note the summary was produced by a model running on this machine. Show it treating the
   name as data, and the validator box listing anything removed.
   Ask: "What evidence are we missing?" Answers cite event IDs.
6. **Response (60 s).** Approve *Revoke OAuth permission grant*. Show the result and verification
   (live: follow-up GET returns 404; otherwise clearly labelled simulated). Mention the one-hour
   access-token caveat, which is why *Disable application* is also offered.
7. **False positive (45 s).** Open the migration-tool incident: equally severe, lower confidence
   because the app is internal. Mark it false positive with a reason. The original detection, scores and
   AI assessment remain on the page.
8. **Endpoint (30 s).** Open win-fin-01: Word spawning encoded PowerShell and an IOC binary. Show
   *Isolate VM* with its effect and restore path.
9. **Audit (30 s).** Open the audit ledger: every step recorded and chain verified. In the terminal, edit
   one line of `data/audit_ledger.jsonl` and run `verify_ledger.py` to show the tamper is detected.

Fallbacks: model down or too slow → AI shows deterministic summaries (labelled); no internet → nothing changes, the model is local; tenant down → everything runs
from fixtures; live action fails → the failure itself is recorded and shown, which is a valid outcome.
