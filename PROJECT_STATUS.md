# PROJECT_STATUS.md — SOC Triage (end-to-end completion)

Last updated: 2026-10-28, revision 2 (reconciled with your live files from `soc_live_delta_20261027-164726.zip`). **Nothing here has been applied to your repository yet; your first dry run found 9 conflicts, which revision 2 resolves inside the package. Run the dry run again to confirm.** Details: `IMPLEMENTATION_STATUS.md` (per requirement) and `TEST_REPORT.md` (commands and results).

## Where things stand
| Phase | Scope | State |
|---|---|---|
| 1 | Audit | Done (on the sandbox copy; live repo not reconciled) |
| 2 | Critical security/correctness (RR-1 veto, RR-2 structure, four evidence classes, strict output validation, versioned policy) | **Built and tested in the sandbox** |
| 3 | Real evidence and ingestion (Suricata EVE adapter, flow store, AbuseIPDB wiring) | **Built; tested with sample events and mocks only** |
| 4 | Case management and console (status, notes, feedback, search, approvals, evaluation and system pages) | **Built; backend tested on memory and PostgreSQL 16; frontend tested in Chromium against the real handlers** |
| 5 | Evaluation, deployment, docs | **Built; Docker never run; no real-traffic metrics** |
| Next | Apply to the live repo, Docker run, live Gemini/Suricata/AbuseIPDB runs, labelled dev-set evaluation | **Yours to run (see below)** |

## What changed (summary)
- Backend: 44 new files and 29 modified files, no Week 1–4 file touched (59 locked hashes verified in the sandbox). Migration `0002_sensor_and_case_management.sql` is additive.
- Frontend: 13 new and 14 modified files over the Phase 2 console, plus `docs/WEEK5_CONSOLE.md`.
- New API routes: `POST /sensors/{sensor}/eve`, `GET /sensors`, `GET /search/cases`, `GET /actions`, `GET /overview`, `GET /cases/{id}/analysis`, case notes/feedback/resolve, `GET /providers`, `GET /diagnostics`, evaluation report list/detail.
- Policy: `risk-policy-v1+evidence-policy-v1` (rules E1–E6 can only raise caution). Sensor alerts are never auto-closed. See `docs/WEEK5_POLICY_CHANGES.md`.
- Deployment: compose overrides `docker-compose.egress.yml` (allow-list proxy: Gemini and AbuseIPDB only) and `docker-compose.reports.yml`; `WITH_GENAI` persistent via compose; `.env.integrations.example` (placeholders only).

## Test status (sandbox only)
Week 5, in a simulated copy of your repo with the package applied: 692 tests OK on PostgreSQL 16 (6 skipped: FastAPI/httpx not installable, lock record absent). Full project offline: 2139 tests, 0 failures, 105 errors that are sandbox limits (103 "LangGraph is not installed", 2 missing parquet library). Frontend: type-check clean, 94 logic tests, 144/144 Chromium checks. Docker, live Gemini, live AbuseIPDB, real Suricata, real npm build: **not run**.

## Unverified claims (do not quote these)
- Any detection accuracy on real traffic. The only metrics are on 56 synthetic scenarios with a scripted model.
- That the Docker stack, egress proxy and backup/restore commands work as containers.
- That Gemini, AbuseIPDB or Suricata integrations work live.
- Production performance. Cost: unavailable until a verified `pricing.json` exists.

## Risks and open items
1. The sandbox is not your live repo. Eight of the nine conflicting files were hand-merged onto the exact files you sent; `payloads.json` was never seen and is not touched (the two new payloads are in `payloads_evidence.json`). Files outside the collector's scope (`src/week4`, `frontend/`, `data`, `reports`) were not examined.
2. Your W5-RR1 vetoes are kept as they are and run before the evidence policy; the two overlap by design (see `docs/WEEK5_POLICY_CHANGES.md` section 9).
3. Your stack uses psycopg 3; the sandbox could only emulate its parameter rules (`tests/pg_strict_driver.py`), not run it. Run the suite on your machine.
3a. The egress override needs Docker Compose 2.24+ and was checked statically, not run.
3b. Sensor alerts will land in `needs_review`/`escalate` only; closing needs a calibrated score that does not exist.
4. AbuseIPDB free-tier quota is budgeted by `WEEK5_TI_DAILY_BUDGET`; confirm the limit on their site.
5. Frozen/holdout sets stay closed until you explicitly authorise.

## Next steps (in order)
1. Dry-run and apply the package (`README_APPLY.md`), keep the backup folder it creates.
2. Run the Week 5 tests on your machine, then `npm install && npm run build && npm test && npm run lint` in `frontend\`.
3. Rebuild the stack with the egress override (never `down -v`) and read `docs/WEEK5_OPERATIONS.md`.
4. Send `samples\eve\eve_mixed.ndjson` through the ingestion endpoint; with a Suricata sensor, point it at the same endpoint.
5. Run the dev-set evaluation (never the frozen set) and record the real numbers.

## Handoff summary (paste into a new conversation)
(Revision 2: the package now also carries your live `runner.py`, `jobs.py`, `worker.py`, `api5.py`, `serve5.py`, security doc and injection test merged with the upgrade; your Gemini compose configuration, JSON fix and RR-1 vetoes are preserved.)
SOC Triage, Windows path `C:\Users\laksh\Downloads\soc-triage-day1\soc-triage`. Weeks 1–5 backend plus Phase 2 React console exist. The end-to-end upgrade package (`soc-e2e-upgrade`: payload, patches, manifest, `APPLY_CHANGES.ps1`, status docs) was built in a sandbox and is not yet applied. It adds an RR-1 evidence veto (evidence-policy-v1), untrusted-text structure, Suricata EVE ingestion, AbuseIPDB enrichment, case notes/feedback/status/search, a four-evidence-class console, an egress allow-list proxy, and a synthetic evaluation suite. Verified only in the sandbox (653 Week 5 tests on PostgreSQL 16, 144 Chromium checks); Docker, live Gemini, real Suricata and real-traffic metrics are unverified. Rules: no secrets, no commit/push/reset/clean/delete, no frozen set, no fabricated results, one PowerShell command at a time.
