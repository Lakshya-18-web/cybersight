# Analyst console: phase 3 upgrade (sensor ingestion, case management, evaluation)

> Layout update: the console is now branded CyberSight and uses a top navigation bar instead of a sidebar. Page content below still applies; see `CYBERSIGHT_FRONTEND.md` for the new routes (Cases, Evidence, Analytics, Threat Intelligence, Playbooks, Reports) and the places the older pages moved to.

This extends the Phase 2 console described in `PHASE2_FRONTEND.md`. Nothing from Phase 2 was removed; routes, the design system, the sign-in and the strict CSP are unchanged. Every number and control comes from a real API route or says it is unavailable.

## Pages and the API behind each

| Page (route) | What it shows | API |
|---|---|---|
| Overview `/` | 12 count tiles and 6 breakdowns (status, source, model severity, routing, risk, verdict health) computed by the server; pending approvals; recent cases; recent jobs | `GET /overview`, `GET /search/cases?limit=8`, `GET /approvals/pending`, `GET /jobs` |
| Alerts `/alerts` | The alert queue. Text search, 10 filters, 5 sorts, paging. All applied by the server across every case, kept in the address bar | `GET /search/cases` |
| Case `/cases/:id` | Tabs: **Analysis** (four labelled kinds of information + provenance), **MITRE**, **Timeline** (plain-words timeline + hash-chained audit trail), **Notes & feedback** (add note, record feedback, resolve), **Raw evidence**, **Memory** | `GET /cases/{id}/analysis`, `/history`, `/evidence`, `/memory`; `POST /cases/{id}/notes`, `/feedback`, `/resolve`; `POST /actions/{id}/decision`, `/simulate-execution` |
| Investigations `/investigations` | Awaiting approval, escalated, needs review, and **Decisions & simulated runs** (every proposal with its decision and its SIMULATED execution) | `GET /approvals/pending`, `GET /cases`, `GET /actions` |
| Jobs `/jobs`, `/jobs/:id` | Unchanged | `GET /jobs[...]` |
| Audit `/audit` | Unchanged (per-case trail; there is no global feed) | `GET /cases/{id}/history` |
| Evaluation `/evaluation` | Report files in the server's report folder; the sensor-suite JSON is summarised (per configuration TP/FP/TN/FN, precision, recall, F1, specificity, FPR, FNR, attacks wrongly closed; provider-failure result); any other JSON or Markdown is shown raw | `GET /evaluation/reports`, `/evaluation/reports/{name}` |
| System `/system` | Providers & queue (model mode, threat-intelligence status and 24-hour outcomes, broker, database, jobs, sensor ingestion) and Diagnostics (versions, policy hashes, audit-chain check, migrations, non-secret settings) | `GET /providers`, `/sensors`, `/diagnostics` |
| Settings `/settings` | Unchanged | `GET /me`, `/health` |

There is no sensor-ingestion form in the browser on purpose: the ingestion endpoint takes a sensor credential, and a browser should not hold one. Events are sent with `python -m week5.eve_send` (see `WEEK5_SENSOR_INGESTION.md`).

## The four kinds of information (case Analysis tab)

Each is its own card with a label in words and a coloured edge; the colour is never the only signal.

1. **Observed**: the sensor record (rule, category, severity, action, linked flow), the alert fields, fields the source did not provide (listed, never filled in), the traffic and command-and-control timing analysts' statements and limits, and the flow queries behind them.
2. **External enrichment**: offline reference tables and, when configured, threat-intelligence lookups with address, role, answer, provider detail and time checked. A missing, failed, skipped or zero answer is described as exactly that, never as "clean". The text states that scores are never shown to the model and can only raise caution.
3. **Model hypothesis**: the model's verdict and rationale (labelled untrusted text), model and prompt version; a banner when the offline fake model produced it.
4. **Policy decision**: the routing decision, the reasons, every evidence rule that fired (with its source class), whether caution was raised and from what to what, safety signals, and the proposed actions with approve/reject controls. The model never proposes or executes actions.

## Case management rules in the UI

- Notes (4000 characters), feedback (assessment required; disposition and comment optional, comment 2000) and resolution (reason required, 1000) are checked in the browser first (`src/lib/caseForms.ts`) and by the API.
- Every write carries an `Idempotency-Key` made once per attempt and reused by retries of that attempt; after a success a fresh key is made, so a double click or a retry after a dropped connection cannot add the item twice.
- Resolve is offered only for escalated or needs-review cases with nothing pending; otherwise the page says why. The API enforces the same rule (409 `pending_actions`).
- Viewers see notes and feedback but get no forms; the API returns 403 regardless.
- The page states on the notes tab that notes, feedback and resolutions are never given to a model and never change the verdict or routing.

## States

Every data section has loading, empty, error-with-retry and "unavailable" states. A failed reload keeps the data on screen with a retry banner. On the Overview and System pages, each section loads independently: one failing request leaves a labelled gap ("Unavailable: ...") and a dash instead of a guess.

## What is not available, and why

- No global audit feed, no worker heartbeat (shown as unavailable on System with the reason), no live probe of the model or the threat-intelligence provider (the API never spends money to test them; outcomes shown come from stored cases).
- No cost figures unless tokens and a verified price configuration exist.
- Evaluation results for real traffic: none exist; the page says so.

## Verification record (what was executed, where)

| Check | Result |
|---|---|
| Type-check of all app sources (TypeScript 6.0.3, strict, no unused locals) | passed. The sandbox has no `@types/react`, so React types come from a verification shim; run `npm run typecheck` on your machine for the real check |
| Pure-logic tests (`src/lib/*.test.ts`, `src/api/*.test.ts`) through a Vitest-compatible shim on `node:test` | 94 passed (includes new `search`, `threatIntel`, `evalReport`, `caseForms`) |
| Browser run in Chromium against the real `Api5` handlers (in-memory stores, fake model), strict CSP | 144 of 144 checks (sign-in, roles, overview totals equal API, server search/sort, case approval with conflict, EVE ingestion over HTTP, replay, analysis, MITRE, notes, feedback, resolve, viewer restrictions, simulated history, system, diagnostics, evaluation, outage and recovery, session expiry, 375 px layout, keyboard, CSP, structural accessibility and WCAG AA contrast audits on the new pages) |
| Production bundle | built with esbuild with lucide-react stubbed; the real `npm run build` (Vite) has not been run here |
| `npm install`, `npm run lint`, `npm test` (Vitest + jsdom + Testing Library), `npm run build`, `npm run e2e` | **not run in the sandbox** (registry unreachable). The new code adds no dependency; run them on your machine |
| Real PostgreSQL, real Docker, real Gemini, real AbuseIPDB, real Suricata | not exercised by the browser run |

The browser run uses in-memory stores. The same API routes are covered on PostgreSQL by the backend test suite (see `TEST_REPORT.md`).
