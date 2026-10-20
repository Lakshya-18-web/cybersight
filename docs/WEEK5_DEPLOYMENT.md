# Week 5 - Docker Compose deployment (Day 4)

**Status of verification.** The compose file was validated here with the real `docker compose config` (syntax, required variables, interpolation). The image was **not built** and the stack was **not started**: the sandbox that wrote this has no Docker daemon and no package index. The Dockerfile and compose behaviour are covered by static tests (`tests/test_week5_deploy.py`, 28 tests) that inspect the files. Treat the first `up` on your machine as the first real run, and use the checklist at the end.

## What it starts
| Service | What it is | Reachable from |
|---|---|---|
| `postgres` | PostgreSQL 16, the source of truth for jobs and cases | `backend` network only |
| `redis` | Redis 7, carries "job X is waiting" messages only; not persisted; password required | `backend` network only |
| `migrate` | one-shot: Week 4 schema, Week 5 queue schema, the two least-privilege logins, `verify` | exits when done |
| `api` | FastAPI: ingestion, job status, approvals, health | `127.0.0.1:8000` (loopback only) |
| `worker` | Celery worker (2 processes) running the Week 4 graph with the **fake model** | `backend` only |
| `sweeper` | republishes unsent/lost queue messages, requeues jobs whose worker died | `backend` only |

`backend` is an `internal` network: its containers have no route to the internet, so a live model call is impossible from inside the stack even by mistake. Only the API is also on `edge`, which exists so that one port can be published.

## Security properties (each is asserted by a test)
- No secret in the image, the compose file or the repository. Every secret is a required `${VAR:?message}`; compose refuses to start when one is missing. `.env.week5` is git-ignored.
- Each service gets only the variables it needs: the API never sees the worker password or the owner password; workers never see the token hashes; only `migrate` has the owner connection.
- Application containers: uid 10001, read-only root file system, `/tmp` as tmpfs, all capabilities dropped, `no-new-privileges`, `init`, CPU/memory/PID limits, restart `unless-stopped`.
- One published port, bound to `127.0.0.1`. Put a TLS-terminating reverse proxy in front before exposing it further: bearer tokens travel in a header.
- Dev authentication mode (`WEEK4_API_DEV_MODE`) is not set and cannot be used on a non-loopback bind.
- Images: `postgres:16` and `redis:7-alpine` are pinned to a tag, **not a digest** (I cannot resolve digests offline). Pin digests for a real deployment.
- The model is the fake one; the image does not contain the Gemini client (`WITH_GENAI=0`).

## Required configuration (names only; no value is in the package)
`WEEK5_DB_PASSWORD`, `WEEK4_API_DB_PASSWORD`, `WEEK5_WORKER_DB_PASSWORD`, `WEEK5_REDIS_PASSWORD`, `WEEK4_API_TOKEN_HASHES`. Optional: `WEEK5_DB_OWNER`, `WEEK5_DB_NAME`, `WEEK5_API_PORT`, `WEEK5_MAX_ATTEMPTS`, `WEEK5_JOB_TIMEOUT_SECONDS`, `WEEK5_MAX_QUEUE_DEPTH`, `WEEK5_RATE_LIMIT_PER_MINUTE`. See `.env.week5.example`. Passwords must be URL-safe (they sit inside connection strings): `python -c "import secrets; print(secrets.token_hex(24))"`.

## Steps (Windows PowerShell, from the repository root; one command at a time)
1. Copy the example file, then edit `.env.week5` and fill in every value:
   `Copy-Item .env.week5.example .env.week5`
2. Make a token and its hash (the token is shown once; keep it in a password manager, put only the **hash line** in `.env.week5`):
   `python -m week4.api.auth new-token --analyst alice`
3. Add the ignore rule (see the package README for the exact one-line command), then confirm it works:
   `git check-ignore -v .env.week5`
4. Validate the file and that nothing is missing (no containers start):
   `docker compose -f docker-compose.week5.yml --env-file .env.week5 config -q`
5. Build and start:
   `docker compose -f docker-compose.week5.yml --env-file .env.week5 up -d --build`
6. Watch it become healthy (all of postgres, redis, api, worker, sweeper should say `healthy`; `migrate` should say `Exited (0)`):
   `docker compose -f docker-compose.week5.yml --env-file .env.week5 ps`
7. Register the analyst whose token you made (owner connection, one-shot container):
   `docker compose -f docker-compose.week5.yml --env-file .env.week5 run --rm migrate python -m week4.db.admin add-analyst --id alice --role approver`
8. Readiness:
   `Invoke-RestMethod http://127.0.0.1:8000/health/ready`
9. Fake-model load test against the running API (token in an environment variable, never on the command line):
   `$env:WEEK5_LOADTEST_TOKEN = "<the token from step 2>"`
   `python -m week5.loadtest run --mode http --base-url http://127.0.0.1:8000 --total 100 --concurrency 4 --out-dir runs_tmp\loadtest_http`
10. Stop (data volume kept) or stop and delete the database volume:
    `docker compose -f docker-compose.week5.yml --env-file .env.week5 down`
    `docker compose -f docker-compose.week5.yml --env-file .env.week5 down -v`

## First-run checklist (the things I could not observe)
- [ ] `build` succeeds (all wheels install for Python 3.11; `psycopg[binary]`, `celery`, `redis`, `langgraph` resolve together).
- [ ] `migrate` exits 0 and its log shows both migration sets and `verify`.
- [ ] `api` healthy; `GET /health/ready` returns `"database": true, "broker": true`.
- [ ] `worker` healthy (the `celery inspect ping` check) and a submitted job reaches `succeeded` with a case.
- [ ] `docker compose stop worker` during a job, then start it: the job is requeued after its lease expires and finishes once (no duplicate case).
- [ ] `docker compose stop redis`, submit alerts (HTTP 202, `dispatch` not sent), start redis: the sweeper publishes them and they complete.
- [ ] `docker compose exec api id` shows uid 10001; `docker compose exec api touch /app/x` fails (read-only).
- [ ] From the host, `Test-NetConnection 127.0.0.1 -Port 5432` and `-Port 6379` fail (not published).
- [ ] If any step fails, keep the `docker compose logs <service>` output (it contains no secrets by design) and send it back.

## Known limits
- Single host, single Postgres, single Redis: no high availability.
- Redis has no TLS (it is on a private internal network). Postgres connections inside the network are not TLS either.
- The synthetic flow store (`WEEK5_FLOW_STORE=fixture`) is a small invented table; tool outputs on it are not real traffic analysis. To use the dev flow store instead, mount `eval/flow_store_dev.parquet` read-only into the worker and set `WEEK5_FLOW_STORE=dev` yourself; that is deliberately not the default and the frozen set must never be mounted.
- Log shipping, metrics and alerting are not included.
- If the worker is OOM-killed mid-job, the job is requeued when its lease expires (delivery is at-least-once; the claim and the case idempotency key prevent a duplicate case).
