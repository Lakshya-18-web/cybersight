# Week 5 - Backend reference

Scope: the Week 4 agent system (graph, risk policy, approval, case store) turned into a service. An alert is submitted over HTTP, stored as a **job**, processed by a **worker** that runs the Week 4 graph, and the resulting **case** is read and approved through the unchanged Week 4 endpoints. Nothing here executes a containment action: approval records a decision and "execution" records a simulated row.

Companion documents: `WEEK5_DEPLOYMENT.md` (Docker), `WEEK5_LOAD_TESTING.md`, `WEEK5_SECURITY.md` (prompt injection), `WEEK5_FINAL_EVALUATION.md` (protected-data gate and the three-configuration evaluation), `WEEK5_BACKEND_REPORT.md` (status and evidence), and `WEEK5_BACKEND_PACKAGE_README.md` (how to apply and verify the package).

## 1. Architecture overview
```
 client --HTTPS--> reverse proxy (yours) --> API (FastAPI, week5.api)
                                              |  authenticate -> role -> rate limit -> validate -> store job (202)
                                              v
                                       PostgreSQL  soc.jobs / soc.job_events      <--- source of truth
                                              ^                 ^
                  claim / heartbeat / complete (SECURITY DEFINER functions)      sweeper: republish lost messages,
                                              |                                          requeue jobs of dead workers
                                  worker (week5.worker)  <--- "job X is due" --- queue backend (postgres poll | celery+redis)
                                       |  Week 4 graph (LangGraph or the instrumented loop) + fake or live model
                                       |  response guard -> Week 4 risk policy -> case + proposed actions (pending)
                                       v
                                  soc.cases ... (Week 4 tables, audit chain)  --> approvals (people) --> simulated execution
```
Design rules:
- **PostgreSQL is the queue's truth.** A broker only says "job X is due". A lost message is harmless (the sweeper republishes); a duplicate message is harmless (the claim is atomic).
- **Business outcomes are returned, not raised.** A job always ends in a recorded state; a worker bug is recorded as `worker_exception` with the exception *type* only.
- **Fail closed.** An unusable model reply becomes a `needs_review` case, never an auto-close. A guard signal turns `auto_close` into `needs_review`. The Week 4 policy file and routing code are untouched.
- **Least privilege.** The API logs in as `soc_api_login`, workers as `soc_worker_login`; each may call only its own database functions. The owner connection exists only in the one-shot migrate job.
- **Nothing secret is stored or logged.** Tokens are hashed; DSNs, keys and prompts are never written to logs, job rows or error details.

Code map (all new code is under `src/week5/`; Week 1-4 code is not modified):
| Path | Role |
|---|---|
| `settings.py` | every `WEEK5_*` setting, validated at start-up |
| `intake.py` | strict alert validation (21 exact fields), body limits, idempotency keys |
| `jobs.py`, `db/migrations/0001_jobs.sql` | job store (PostgreSQL and in-memory twins, one contract test) |
| `queues.py`, `celery_app.py` | queue backends and the dispatcher/sweeper |
| `worker.py`, `runner.py`, `engine.py`, `models.py`, `errors.py` | the worker, graph runner, timing engine, model providers, failure classification |
| `security/guard.py`, `security/injection/` | response guard; the prompt-injection suite |
| `api/` | `api5.py` (framework-free handlers), `routes5.py`, `app5.py` (FastAPI), `serve5.py` (entry point) |
| `loadtest/`, `evalrun/`, `release/` | load tester, final-evaluation tooling, package verifier |

## 2. API endpoint reference
Authentication: `Authorization: Bearer <token>`. Tokens are made with `python -m week4.api.auth new-token --analyst <id>`; the service keeps only their hashes (`WEEK4_API_TOKEN_HASHES`). Roles (Week 4): `viewer` (read), `analyst` (read, submit), `approver` and `admin` (also decide and simulate-execute).

New in Week 5:
| Method and path | Role | Purpose |
|---|---|---|
| `POST /alerts` | analyst and up | submit one alert; returns **202** with a job id |
| `GET /jobs/{job_id}` | viewer and up | one job's status, timings, usage and (when done) the case id |
| `GET /jobs?status=&limit=&offset=` | viewer and up | list jobs, newest first |
| `GET /health/live` | public | process is up; checks nothing else |
| `GET /health/ready` | public | database answers (503 if not); broker state reported (`degraded` and still accepting when the broker is down) |

Unchanged from Week 4 (`GET /health`, `GET /cases`, `GET /cases/{id}`, `/evidence`, `/memory`, `/history`, `GET /approvals/pending`, `GET /actions/{id}`, `POST /actions/{id}/decision`, `POST /actions/{id}/simulate-execution`); a test pins the route table.

`POST /alerts`: body `{"alert": {<exactly 21 fields>}, "memory": "off" | "on"}` (`memory` optional). The fields are `alert_id, timestamp, flow_id, src_ip, src_port, dst_ip, dst_port, protocol, detector_score` and twelve numeric flow features (`Flow Duration`, `Total Fwd Packets`, ..., `ACK Flag Count`; the list is in `intake.ALERT_FIELDS`). Unknown, missing, mistyped or out-of-range fields are refused; identifiers must match strict ASCII patterns. Optional `Idempotency-Key` header (8-200 characters of `A-Z a-z 0-9 . _ : -`, matched in full), scoped per user. Without it an identical resubmission is recognised by its content hash.

Order of checks and the status each produces:
| Step | Status |
|---|---|
| no or wrong credential | 401 (does not say which part was wrong) |
| unknown or inactive account; role may not submit | 403 |
| per-user rate limit exceeded | 429 + `Retry-After` |
| content type is not JSON | 415 |
| body larger than `WEEK5_MAX_BODY_BYTES` (checked from the declared length and again while reading) | 413 |
| not JSON, wrong shape, bad `memory` | 400 / 422 |
| field validation or bad `Idempotency-Key` | 422 (code `invalid_alert` + a reason code; the offending value is never echoed) |
| same key, different alert | 409 |
| queue holds `WEEK5_MAX_QUEUE_DEPTH` jobs | 429 + `Retry-After` (nothing stored) |
| database unreachable | 503 (no connection details) |
| new job stored | **202**, `Location: /jobs/<id>` |
| duplicate of an earlier submission | 200 with the original job id, `"duplicate": true` |

Job view (abridged): `job_id, status (queued|running|succeeded|failed|timed_out), attempts, max_attempts, alert_id, submitted_by, enqueued_at, first_started_at, started_at, finished_at, case_id, case_url, error_code, error_detail, result{graph_status, verdict_status, routing_decision, risk_level, proposed_actions, guard_signals, ...}, timings{graph_seconds, nodes{...}}, usage{model_calls, tokens_available, ...}`. For a fake model `usage` states that no token counts exist; none are invented.

Refusals and errors share one shape: `{"error": {"code": "...", "message": "..."}}`. Every refusal at the validation stage is also written to the audit trail (`ingest_rejected`: code, field name, size, body hash - never the content).

## 3. Queue and worker lifecycle
States: `queued -> running -> succeeded | failed | timed_out`, and `running -> queued` for a retry. Terminal states are final (enforced by the database).

1. **Submit.** The API stores the job (`soc.submit_job`), then publishes it: nothing to do for the `postgres` backend (the row is the entry), a Celery message for the `celery` backend. If the broker is down the job stays `queued` and the response says `"dispatch": "pending"`.
2. **Claim.** A worker calls `soc.claim_job` (`FOR UPDATE SKIP LOCKED`): one job, one owner, a lease of `WEEK5_LEASE_SECONDS`, attempts + 1. Two workers cannot run one job at once while its lease holds.
3. **Run.** The runner builds the case input (identifiers are aliased for the model unless `WEEK5_ALIAS_IDS=0`), runs the Week 4 graph with a per-attempt time limit (`WEEK5_JOB_TIMEOUT_SECONDS`), applies the response guard, then the Week 4 policy.
4. **Store.** `repository.ingest_case` is idempotent (same payload hash, same case); `soc.complete_job` records the result and links the case.
5. **Failure.** `errors.classify` decides: *retryable* (model unavailable, timeout, store outage, lost worker, unknown exception) goes back to `queued` with back-off `WEEK5_RETRY_BACKOFF_SECONDS` (default 5, 20, 60 s) until `max_attempts` (default 3); *not retryable* (invalid alert, model refusal, database rule, unusable memory, policy error) ends `failed` at once. A model that fails on the last attempt does **not** drop the alert: a fail-closed `needs_review` case is stored and the job succeeds.
6. **Timeout.** Poll workers run the graph in a thread and stop waiting at the limit (the late result is discarded; the worker exits 75 and the supervisor restarts it). Under Celery the soft limit raises inside the task and the hard limit (`+ WEEK5_CELERY_HARD_LIMIT_SLACK_SECONDS`) kills the child.
7. **Recovery.** The **reaper** returns jobs whose lease expired to `queued` (or fails them when attempts are used up). The **sweeper** republishes due jobs that were never handed over, or whose message is older than `WEEK5_REPUBLISH_AFTER_SECONDS`. A worker that lost its lease changes nothing further.

Delivery is **at least once**, not exactly once: a model call can be repeated after a crash; the case and its proposed actions are stored once.

Processes: `python -m week5.worker --mode poll` (claims jobs itself; used with `WEEK5_QUEUE_BACKEND=postgres`), `python -m week5.worker --mode sweep` (maintenance loop), `celery -A week5.celery_app:app worker -Q soc_triage --concurrency 2` (with `WEEK5_QUEUE_BACKEND=celery`). `python -m week5.worker --health [--max-age 120]` exits 0 only when the heartbeat file is fresh (the container health check). SIGTERM finishes the current job, then exits.

## 4. Environment configuration reference
No value below is a secret unless marked. Defaults come from `settings.py`; invalid values stop the process at start-up with a message that lists the problems without echoing the values.

| Variable | Default | Meaning |
|---|---|---|
| `WEEK5_QUEUE_BACKEND` | `postgres` | `postgres` (poll), `celery`, or `memory` (tests only; refused by API and worker) |
| `WEEK5_ENGINE` | `langgraph` | `langgraph` or `instrumented` (same edges, per-node timing, no LangGraph needed) |
| `WEEK5_MODEL_MODE` | `fake` | `fake` or `gemini` |
| `WEEK5_ALLOW_LIVE_MODEL` | `0` | must be `1` **and** model mode `gemini` for any live call |
| `WEEK5_ALERT_SET` | `synthetic` | label stored on cases: `synthetic` or `dev` (the client cannot choose it) |
| `WEEK5_FLOW_STORE` | `dev` | `dev`, `none`, or `fixture` (small invented traffic table; used by Docker) |
| `WEEK5_ALIAS_IDS` | `1` | show the model aliases instead of client identifiers |
| `WEEK5_DEFAULT_MEMORY`, `WEEK5_MEMORY_DIR`, `WEEK5_MEMORY_K` | `off`, empty, `5` | Week 4 incident memory (default-on needs a directory) |
| `WEEK5_MAX_BODY_BYTES` | `16384` | request size limit |
| `WEEK5_MAX_ATTEMPTS` | `3` | attempts per job (1-10) |
| `WEEK5_JOB_TIMEOUT_SECONDS` | `120` | per-attempt limit |
| `WEEK5_LEASE_SECONDS` | `300` | must exceed the timeout |
| `WEEK5_RETRY_BACKOFF_SECONDS` | `5,20,60` | comma-separated; the last entry repeats |
| `WEEK5_MAX_QUEUE_DEPTH` | `1000` | bounded admission |
| `WEEK5_RATE_LIMIT_PER_MINUTE`, `WEEK5_RATE_BURST` | `120`, `30` | per-user limiter (0 disables) |
| `WEEK5_POLL_INTERVAL_SECONDS`, `WEEK5_REAP_INTERVAL_SECONDS`, `WEEK5_REPUBLISH_AFTER_SECONDS` | `1`, `15`, `60` | worker and sweeper loops |
| `WEEK5_MODEL_RPM` | `10` | client-side model rate gate |
| `WEEK5_CELERY_QUEUE`, `WEEK5_CELERY_HARD_LIMIT_SLACK_SECONDS` | `soc_triage`, `30` | Celery |
| `WEEK5_API_DATABASE_URL` **(secret)** | - | API connection (login `soc_api_login`); falls back to `WEEK4_DATABASE_URL` |
| `WEEK5_WORKER_DATABASE_URL` **(secret)** | - | worker connection (login `soc_worker_login`) |
| `WEEK5_CELERY_BROKER_URL` **(secret)** | - | e.g. `redis://:<password>@redis:6379/0` |
| `WEEK5_HEARTBEAT_FILE` | - | worker liveness file for the health check |
| `WEEK4_DATABASE_URL`, `WEEK4_ADMIN_DATABASE_URL` **(secret)** | - | owner connection for migrations and admin tasks only |
| `WEEK4_API_TOKEN_HASHES` / `_FILE` **(secret hashes)** | - | token hashes for authentication |
| `WEEK4_API_DEV_MODE` | unset | development authentication; loopback only, refused otherwise |
| `WEEK4_API_DB_PASSWORD`, `WEEK5_WORKER_DB_PASSWORD` **(secret)** | - | passwords for the two least-privilege logins (used by the migrate job) |
| `WEEK5_LOADTEST_TOKEN` **(secret)** | - | bearer token for the HTTP load test |

The Docker-only variables (`WEEK5_DB_PASSWORD`, `WEEK5_REDIS_PASSWORD`, ports, names) are listed in `.env.week5.example`.

## 5. Database and migrations
- Week 4 migrations `0001`-`0004` (`src/week4/db/migrations`, locked) must be applied first. Week 5 adds `src/week5/db/migrations/0001_jobs.sql`, tracked in its own table `soc.schema_migrations_week5`, so no locked Week 4 file changes.
- Objects: tables `soc.jobs`, `soc.job_events` (append-only), view `soc.job_stats`, SECURITY DEFINER functions `submit_job`, `claim_job`, `heartbeat_job`, `complete_job`, `fail_job`, `reap_expired`, `mark_dispatched`, `undispatched_jobs`, `record_security_event`, and the NOLOGIN group role `soc_worker`. Constraints enforce: unique idempotency key, status values, a lease exactly while running, a case for every success, `attempts <= max_attempts`, no credential-shaped keys in an alert or result.
- Commands (owner connection in `WEEK4_DATABASE_URL`):
  `python -m week4.db.migrate apply` then `python -m week5.db.migrate apply`, then `python -m week4.db.admin create-api-login`, `python -m week5.db.admin create-worker-login` (passwords from the environment), then `python -m week5.db.migrate verify`. `status` shows what is applied. An applied file is never edited: a changed checksum stops the runner.
- Register an analyst: `python -m week4.db.admin add-analyst --id alice --role approver`.
- In Docker all of this is the `migrate` service (`docker/migrate.sh`).

## 6. Local development setup (Windows PowerShell, repository root)
```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements-week5-dev.txt
$env:PYTHONPATH = "src;."
python -m unittest discover -s tests -t . -p "test_week5_*.py"
```
Without a database the suite runs everything except the PostgreSQL classes (skipped). To run a local API on development authentication (loopback only):
```powershell
$env:WEEK4_API_DEV_MODE = "1"
$env:WEEK5_API_DATABASE_URL = "postgresql://<user>:<password>@127.0.0.1:5432/<db>"
$env:WEEK5_ENGINE = "instrumented"; $env:WEEK5_FLOW_STORE = "fixture"
python -m week5.api.serve5 --check
python -m week5.api.serve5
```
`--check` validates configuration and reaches the database without serving. A smoke body for `POST /alerts`: `python -m week5.fixtures` prints one. Dev mode lets anyone who can reach the port act as any analyst; never use it off loopback.

## 7. Docker Compose
See `WEEK5_DEPLOYMENT.md`: services, the security properties each test asserts, required variables, the step list and a first-run checklist. Short form: `Copy-Item .env.week5.example .env.week5`, fill in values, `docker compose -f docker-compose.week5.yml --env-file .env.week5 config -q`, then `up -d --build`.

## 8. Test commands
| What | Command |
|---|---|
| All Week 5 tests | `python -m unittest discover -s tests -t . -p "test_week5_*.py"` |
| One area | `python -m unittest tests.test_week5_api` (also `_jobs`, `_worker`, `_ops`, `_intake_settings`, `_loadtest`, `_injection`, `_deploy`, `_evalrun`, `_hardening`, `_release`) |
| Whole project (Weeks 1-5) | `python -m unittest discover -s tests -t . -p "test_*.py"` |
| With a real PostgreSQL (opt-in, scratch databases only) | `$env:WEEK4_TEST_PG = "1"` plus `PGHOST PGPORT PGUSER PGPASSWORD`, then the same commands |

Release verification (read-only; standard library only; touches no model, database, network or protected data): `python -m week5.release verify-package|check-conflicts|verify-applied|verify-locks|fingerprint|compare`. `verify-locks` recomputes the SHA-256 of every file the Week 4 lock record names (Week 4 sources, the Week 3 lock, report and locked sources, the Week 1 data and model files as raw bytes, the Week 2 locked sources) and fails if any differs; it refuses to hash any path that looks like protected evaluation data. See `WEEK5_BACKEND_PACKAGE_README.md` for the order to run them.

The PostgreSQL tests clone a migrated template database per class and drop it afterwards; an existing database is never touched. The requirement-to-test matrix is `tests/week5_matrix.py`; `tests.test_week5_hardening` checks that every test it names exists.

## 9. Load-test, security-test and evaluation instructions
- Load test (fake model, JSON/CSV/Markdown output): `WEEK5_LOAD_TESTING.md`.
- Prompt-injection suite (61 payloads, 9 gates): `python -m week5.security.injection run --out-dir runs_tmp\injection`; see `WEEK5_SECURITY.md`.
- Final evaluation (raw detector vs single-LLM baseline vs full system, 3 runs each): `WEEK5_FINAL_EVALUATION.md`. **The protected-data gate is closed by default.** `python -m week5.evalrun rehearse` runs the whole pipeline on synthetic data and never touches protected data; `gate-status` reports the gate without reading anything. Opening it needs the unlock variable, a written authorisation file that matches the frozen plan's hash, and an explicit acknowledgement flag, and writes a ledger line first. None of that has been done.

## 10. Troubleshooting
| Symptom | Likely cause and action |
|---|---|
| `STOPPED: ...` at API start | a `ConfigError`: the message names the variable(s). Fix the environment; the message never contains the value |
| API returns 503 on `/health/ready` | database unreachable or the login is wrong; check `WEEK5_API_DATABASE_URL` and that migrations were applied (`python -m week5.db.migrate verify`) |
| `/health/ready` says `degraded` | the broker is down; submissions are still accepted and the sweeper publishes them when it returns |
| jobs stay `queued` | no worker running; with the `celery` backend check the broker URL and queue name `soc_triage`; with `postgres` start `python -m week5.worker --mode poll` |
| jobs stay `running` past the lease | the worker died; the reaper (sweeper process) will requeue them. Check the sweeper is running |
| `error_code: model_unavailable` repeats | the fake model scenario or the live model is failing; after the last attempt a `needs_review` case is stored |
| `error_code: case_rejected_by_database` | the case violated a database rule (see the SQLSTATE in `error_detail`); not retried |
| 429 `queue_full` | `WEEK5_MAX_QUEUE_DEPTH` reached: add workers or raise the limit; clients should honour `Retry-After` |
| 401 on every call | the token hash is not in `WEEK4_API_TOKEN_HASHES`, or the header is not `Bearer <token>` |
| 403 on submit | the account is inactive or a `viewer` |
| Docker `up` refuses to start | a required `${VAR:?}` is missing in `.env.week5`; run `config -q` |
| worker container restarts after a timeout | expected for poll mode: exit code 75 is the clean restart after an abandoned thread |
| PostgreSQL tests skipped | `WEEK4_TEST_PG` is not `1` or the `PG*` variables are missing |

## 11. Known limitations and operational assumptions
- **Not exactly-once.** A crash can repeat a model call. The case is stored once.
- **Fake model by default.** The live Gemini provider exists but requires `WEEK5_ALLOW_LIVE_MODEL=1` and `WEEK5_MODEL_MODE=gemini` and the `google-genai` package; it was never exercised. Evaluation tooling's live backends are likewise unexercised.
- **RR-1 (declared, not fixed):** a fully compromised model that returns clean "benign" text for a low-score alert is auto-closed by Week 4 rule R9. A deterministic evidence veto was designed but **not** implemented: it would change routing and therefore the evaluation, so it needs your decision before the evaluation plan is frozen.
- **RR-2:** specialist-tool statements reach the model verbatim; safe only while they are template-generated from numbers.
- **Audit gap:** 401/403 denials are logged but not written to the tamper-evident audit chain.
- Alert content is the 21-field schema only; free text is limited to the identifier fields and is aliased before the model sees it.
- The API's unexpected-exception behaviour (an uncaught bug inside a handler) relies on the web framework's default 500 and was not exercised here (FastAPI was not installed in the sandbox).
- Thread-mode timeouts cannot kill a stuck thread; the worker restarts instead. Under Celery the hard limit kills the child.
- Memory-on runs need a built Week 4 memory store; none is created here.
- Single database, single broker, no high-availability configuration; no TLS (put a proxy in front); image tags are pinned by tag, not digest.
- Load-test numbers are from a two-CPU sandbox with a simulated model delay and are not performance claims.
- The React UI phase has not been started.

## 12. What was and was not tested (in the sandbox that produced this package)
Executed and observed: the full Week 5 unit suites (jobs, intake/settings, worker, API handlers, ops, load-test, injection, deploy static checks, evaluation tooling, hardening, release verifier) with the in-memory stores and the stdlib web test double; the PostgreSQL classes against a real PostgreSQL 16 (job store, worker, API handlers, migrations, role privileges); the load tester and injection suite end to end; `docker compose config` on the compose file; a hash comparison of the Week 4 locked files. Exact counts: `release/WEEK5_TEST_SUMMARY.md`.

**Not executed here:** the FastAPI web layer (`app5.py`) and its tests; Celery and Redis (the broker is a test double and the Celery config is checked as data); the `psycopg` driver (PostgreSQL tests use the `psql` driver); real LangGraph (the instrumented engine, which a test proves equal to the Week 4 offline driver, was used); `docker build` and `docker compose up` (no daemon); any live model call; the final evaluation on protected data; the Week 3 and Week 4 test modules that need LangGraph (103 tests error in the sandbox for that reason alone; they are unmodified).
