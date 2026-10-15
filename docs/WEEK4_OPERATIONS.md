# Week 4 operations guide

Everything here runs on your machine. Nothing in Week 4 calls Gemini unless you start a real (non-`--fake-model`) run yourself, and nothing ever executes a containment action.
Commands are PowerShell-friendly: run one at a time, from the repository root, with the virtual environment active.

## 1. What is where

| piece | where |
|---|---|
| database migrations, drivers, repository, admin CLI | `src/week4/db/` (`migrations/0001..0004_*.sql`) |
| incident memory (train-only), seeding | `src/week4/memory/`, `src/week4/seed_memory.py` |
| graph v2 (memory step, switch, memory-aware prompt) | `src/week4/graph/` |
| risk policy and routing | `config/risk_policy.json`, `src/week4/policy.py` |
| approval state machine (proposed vs executed) | `src/week4/approval.py`, SQL functions in `0003_functions.sql` |
| approval API | `src/week4/api/` |
| dev runner (memory off / on) | `src/week4/run_memory_dev.py` |
| case ingest | `src/week4/ingest_cases.py` |
| ablation scoring | `src/week4/evaluate_memory.py` |
| lock, report, artifact manifest | `src/week4_report.py` |
| split-isolation design and tests | `docs/WEEK4_SPLIT_ISOLATION.md` |

Week 1-3 files are not modified. The only edit to an existing file is one line added to `.gitignore` (`.env.week4`).

## 2. Install

```
pip install -r requirements-week4.txt
```
The default memory backend (numpy) and the offline test suite need only numpy/pandas. FastAPI, uvicorn, httpx, psycopg, chromadb and pyarrow are listed as lower bounds; pin exact versions after your own full test run.

## 3. Database (PostgreSQL 16)

Docker Compose:
```
Copy-Item .env.week4.example .env.week4       # then edit .env.week4: set WEEK4_DB_PASSWORD and the two URLs (never commit this file)
docker compose --env-file .env.week4 up -d db
docker compose --env-file .env.week4 ps        # wait until the db service is "healthy"
```
Compose refuses to start without `WEEK4_DB_PASSWORD`; the port is bound to `127.0.0.1` only. Without Docker, any PostgreSQL 16 server works: use its owner connection below.

Migrations (owner connection; `WEEK4_DATABASE_URL` is the variable the migration command reads, so point it at the owner URL for this step):
```
$env:WEEK4_DATABASE_URL = $env:WEEK4_ADMIN_DATABASE_URL        # or paste the owner URL
python -m week4.db.migrate status
python -m week4.db.migrate apply
python -m week4.db.migrate verify
```
`apply` is safe to repeat: it takes an advisory lock, applies only pending files in order, records each file's checksum, and `verify` fails if an applied file was edited. Never edit an applied migration; add `0005_*.sql`.

Analysts and the API login (owner connection):
```
python -m week4.db.admin add-analyst --id alice --role approver --name "Alice"
python -m week4.db.admin add-analyst --id bob --role analyst
$env:WEEK4_API_DB_PASSWORD = "<a long random password>"
python -m week4.db.admin create-api-login            # login role soc_api_login: read access + four SECURITY DEFINER functions only
python -m week4.db.admin verify-audit                # recompute the audit hash chain; exit 0 only when intact
```
Roles: `viewer`/`analyst` read; `approver`/`admin` may approve, reject and record simulated executions. The database enforces this too: the API login cannot write tables directly.
Then set `WEEK4_DATABASE_URL` to the **API login** URL for ingest and the API.

Idempotency and duplicates: ingesting the same run twice is a no-op (`duplicate`); a changed resubmission under the same key is a `conflict` and stores nothing. A decision needs an `Idempotency-Key` header: the same key and decision replays the stored result (HTTP 200, `replayed: true`); a different decision on an already decided action is a `409`. Only one of several simultaneous deciders wins (row lock + one-time state transition).

## 4. Incident memory (train split only)

```
python -m week4.seed_memory seed          # reads data/processed/train.parquet only; stops with exit code 2 if it is missing
python -m week4.seed_memory verify        # exit 0 only if the store matches its manifest and passes the train-only checks
```
Seeding is deterministic (same train file + parameters = byte-identical store, same manifest hash). A changed input replaces the store and keeps the old one as `memory_store.prev-<hash>`. See `docs/WEEK4_SPLIT_ISOLATION.md`. `--backend chroma` builds an optional ChromaDB index over the same verified files.

## 5. Running the agent on the dev set

A smoke test that costs nothing (canned replies, flagged FAKE, never evaluable):
```
python src/week4/run_memory_dev.py --memory on --fake-model --limit 5 --run-name FAKE_smoke
python src/week4/run_memory_dev.py --memory on --dry-run            # tools + memory for the first alert; prints the prompt; no model call
```
The real ablation is two runs over the same 300 dev alerts. **They call Gemini and cost money; run them only when you have decided to.**
```
python src/week4/run_memory_dev.py --memory off --run-name dev_v2_mem_off
python src/week4/run_memory_dev.py --memory on  --run-name dev_v2_mem_on
python src/week4/run_memory_dev.py --memory on  --resume --run-name dev_v2_mem_on     # after an interruption
```
Both are held equal to the locked `baseline_v3` run (model, temperature, seed, token limit, retries); a mismatch stops the run before any call. Memory on stops before any call if the store is missing, damaged, or shares a flow with a dev alert.

Score and compare (dev labels only; no model call):
```
python src/week4/evaluate_memory.py --off-run dev_v2_mem_off --on-run dev_v2_mem_on
```
This writes `reports/week4_eval/<off>_vs_<on>/` (`COMPARISON_REPORT.md`, `comparison.json`, `comparison_metrics.csv`, `per_alert.csv`). It states every denominator, counts no-verdict alerts as such, and makes no significance claim.

Put the cases into the database (proposed actions land as `pending`):
```
python src/week4/ingest_cases.py --run-dir runs/week4_memory/dev_v2_mem_on --dry-run
python src/week4/ingest_cases.py --run-dir runs/week4_memory/dev_v2_mem_on
```

## 6. The approval API

Create a token for each person (printed once; only its hash goes in the server environment):
```
python -m week4.api.auth new-token --analyst alice
$env:WEEK4_API_TOKEN_HASHES = "alice:<hash printed above>"
python -m week4.api.serve --host 127.0.0.1 --port 8000
```
OpenAPI/Swagger UI: `http://127.0.0.1:8000/docs`. Endpoints: `GET /health`, `GET /cases`, `GET /cases/{id}`, `/cases/{id}/evidence`, `/cases/{id}/memory`, `/cases/{id}/history`, `GET /approvals/pending`, `GET /actions/{id}`,
`POST /actions/{id}/decision` (body `{"decision": "approved"|"rejected", "reason": "..."}`, header `Idempotency-Key`), `POST /actions/{id}/simulate-execution`. Lists take `limit` (1-200) and `offset`.
```
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8000/approvals/pending
curl -X POST -H "Authorization: Bearer <token>" -H "Idempotency-Key: alice-2026-10-15-001" -H "Content-Type: application/json" -d '{"decision":"approved","reason":"reviewed flow"}' http://127.0.0.1:8000/actions/<action_id>/decision
```
Authentication is required for everything except `/health`. With no configuration the server does not start. `WEEK4_API_DEV_MODE=1` (header `X-Dev-Analyst`, no secret) exists for a developer's own machine only, cannot be combined with token hashes, and the launcher refuses any address but loopback. Put TLS in front of the API (a reverse proxy) before using it beyond localhost.

## 7. Safety model (what the code guarantees)

- No real containment: no module imports a network, shell or firewall library for actions (a test checks the API/policy/approval/case modules). "Execution" is a database row marked `simulated`.
- An action is `pending` until an authorised approver decides it once. Rejected, pending or unknown actions cannot get a simulated execution (database trigger + function check). Missing policy, unknown or inactive identity, database errors and ambiguous input all fail closed.
- Memory is untrusted reference data. It can raise caution (routing rule R8) but never close a case or create an action; proposals come from the verdict alone.
- Credentials: none in the repository, records or logs (database CHECK constraints reject credential-like keys; connection strings are redacted in errors).

## 8. Locking Week 4 (after the real runs, tests and your review)

```
python -m unittest discover -s tests -t . -v 2>&1 | Out-File -Encoding utf8 reports/week4_day7/full_suite.txt
$env:WEEK4_TEST_PG = "1"        # plus PGHOST / PGPORT / PGUSER / PGPASSWORD for a server where you may CREATE DATABASE
python -m unittest discover -s tests -t . -v 2>&1 | Out-File -Encoding utf8 reports/week4_day7/pg_suite.txt
python src/week4_report.py build --off-run dev_v2_mem_off --on-run dev_v2_mem_on --suite-log reports/week4_day7/full_suite.txt --pg-suite-log reports/week4_day7/pg_suite.txt
python src/week4_report.py verify --recompute
```
UTF-16 logs (Windows PowerShell `>`) are read correctly. `build` writes nothing unless every check passes, never touches the Week 3 lock, and refuses to replace an existing lock without `--force`.
Commit and tag only after you have reviewed the files; the tag name used by the plan is `week4-memory`.

## 9. What was and was not tested (when the code was written)

The development sandbox had Python 3.13, a real PostgreSQL 16 server and no Docker, no FastAPI/uvicorn/httpx, no psycopg, no ChromaDB, no pyarrow and no real LangGraph (a stand-in with the same call surface was used).

| area | status |
|---|---|
| migrations, constraints, triggers, SQL functions, audit chain, concurrency (8 racing deciders: exactly one winner), least-privilege role | **run against real PostgreSQL 16** through the `psql` driver |
| repository contract (in-memory fake and PostgreSQL give the same answers) | run |
| risk policy, approval transitions, rejected/unauthorized never execute | run |
| memory seeding/retrieval, isolation, fail-closed, graph v2, memory on/off, Week 3 equivalence | run offline on synthetic data and a stand-in graph library |
| runner, ingest, ablation scoring, lock/verify | run offline with the fake model on synthetic data |
| API handlers, auth, roles, validation, pagination | run (framework-free layer) |
| **Docker Compose start-up** | **not run** (no Docker); file checked statically only |
| **psycopg driver** | **not run** |
| **FastAPI application wrapper / OpenAPI** | **not run**; `tests/test_week4_api.py` runs its FastAPI section automatically where fastapi and httpx are installed |
| **ChromaDB backend** | **not run**; its results are checked against the exact search by `seed_memory verify` where installed |
| **seeding from the real `train.parquet`**, real LangGraph, any Gemini call | **not run**; no real Week 4 metric exists until you run the two dev runs |

Run the full suite on your machine, with and without `WEEK4_TEST_PG=1`, and read the skipped-test count: every skip names its missing dependency.
