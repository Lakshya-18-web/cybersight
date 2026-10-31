# Week 5 operations: upgrade, backup and restore, rollback, egress, health checks, troubleshooting

**What was verified.** The database parts (migration 0002 applied on top of an existing database, applying twice, checksum refusal, `pg_dump` -> `pg_restore` into a new database with the audit chain, row counts and privileges intact) are exercised by `tests/test_week5_backup_restore.py` against PostgreSQL 16. The proxy is exercised with local sockets (`tests/test_week5_egress.py`). **Docker commands here were NOT run** (no Docker daemon in the build environment): treat each as the first real run, and read the output.

> **Never run `docker compose down -v`.** `-v` deletes the database volume (`soc_week5_pgdata`). `docker compose down` (no `-v`) keeps it. APPLY_CHANGES.ps1 never runs either.

## 1. Upgrade an existing deployment
1. Back up first (section 2).
2. Apply the package with `APPLY_CHANGES.ps1` (it backs up the files it replaces and stops on conflicts).
3. Rebuild and restart: `docker compose -f docker-compose.week5.yml --env-file .env.week5 up -d --build`. The `migrate` service applies migration `0002` (additive: new tables and functions, widened check constraints) and `verify`; it is idempotent.
4. Check: `docker compose ... ps` (migrate `Exited (0)`, the others healthy), then `Invoke-RestMethod http://127.0.0.1:8000/health/ready` and the dashboard "Diagnostics" page (audit chain ok, migrations applied).

## 2. Backup (database)
One command at a time (PowerShell). The dump is made inside the container and copied out, because redirecting binary output through PowerShell corrupts it.
1. `docker compose -f docker-compose.week5.yml --env-file .env.week5 exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -Fc -f /tmp/soc.dump "$POSTGRES_DB"'`
2. `New-Item -ItemType Directory -Force backups | Out-Null`
3. `docker compose -f docker-compose.week5.yml --env-file .env.week5 cp postgres:/tmp/soc.dump backups\soc-$(Get-Date -Format yyyyMMdd-HHmm).dump`
4. `docker compose -f docker-compose.week5.yml --env-file .env.week5 exec -T postgres rm /tmp/soc.dump`
Keep dumps outside the repository (they contain alert data and the audit trail; `backups/` must be git-ignored). Test a restore at least once before you depend on it.

## 3. Restore into a NEW database, check it, then switch
Restoring into a separate database means a bad dump never touches the live one.
1. Copy the dump in: `docker compose ... cp backups\<file>.dump postgres:/tmp/restore.dump`
2. Create and restore: `docker compose ... exec -T postgres sh -c 'createdb -U "$POSTGRES_USER" soc_restore && pg_restore -U "$POSTGRES_USER" --no-owner -d soc_restore /tmp/restore.dump'`
3. Check the audit chain: `docker compose ... exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d soc_restore -Atc "SELECT ok FROM soc.verify_audit_chain()"'` must print `t`. Compare counts: `psql ... -c "SELECT (SELECT count(*) FROM soc.cases), (SELECT count(*) FROM soc.audit_events)"` on both databases.
4. To switch, stop api, worker and sweeper (`docker compose ... stop api worker sweeper`), rename the databases (`ALTER DATABASE soc RENAME TO soc_old; ALTER DATABASE soc_restore RENAME TO soc;` connected to `postgres`), start them again. Keep `soc_old` until you are sure.
The login roles (`soc_api_login`, `soc_worker_login`) are cluster-level and survive; the NOLOGIN roles' privileges are in the dump (the test checks them).

## 4. Rollback
The change is additive. To return to the previous code: restore the previous files (APPLY_CHANGES.ps1 saved them under `backup_<timestamp>\`), rebuild the image, `up -d`. Leave migration 0002's tables in place; the previous code ignores them. Cases created while the new code ran remain valid. If a migration itself failed, it was rolled back as a whole (each migration is one transaction); fix the cause and run `migrate` again. To go back to a database state from before the upgrade, use section 3 with a pre-upgrade dump.

## 5. Gemini and AbuseIPDB (optional), with the egress proxy
Files: `docker-compose.egress.yml`, `.env.integrations.example`, `requirements-genai.txt`, `Dockerfile.week5`.
1. `Copy-Item .env.integrations.example .env.integrations`, then edit it. Put the AbuseIPDB key in `SOC_REPUTATION_API_KEY` **in that file only** (git-ignored, never in a compose file). Your Gemini key stays where it is today (`.env.week5`). `.env.integrations` deliberately does not define `GEMINI_API_KEY`, `WEEK5_MODEL_MODE` or `WEEK5_ALLOW_LIVE_MODEL`: when two `--env-file` options define the same name the LATER one wins, so such a line would silently replace your real key or switch.
2. Persist the Gemini client in the image: `WEEK5_WITH_GENAI=1` (the template sets it). Every service builds with the same argument, so the image cannot lose the library on a rebuild; the build **fails** if `google.genai` cannot be imported. If you leave it unset the default is `0` and the worker image will have no Gemini library.
3. The live-mode switches stay exactly as your base compose file sets them (a base that already runs `WEEK5_MODEL_MODE: gemini` keeps doing so; a base that runs the fake model keeps doing so). The override never touches them.
4. Check your Compose version: `docker compose version` must be 2.24 or newer (the override uses the `!override` tag). Then validate: `docker compose -f docker-compose.week5.yml -f docker-compose.egress.yml --env-file .env.week5 --env-file .env.integrations config -q`, and read the rendered `config` output: the `worker` must be on the `backend` network only, with `HTTPS_PROXY` set. On an older Compose, delete the line `networks: !override [backend]` from `docker-compose.egress.yml` and remove `model-egress` from the worker's `networks:` in your base file by hand.
5. Start: `docker compose -f docker-compose.week5.yml -f docker-compose.egress.yml --env-file .env.week5 --env-file .env.integrations up -d --build`
How it is contained: `backend` stays `internal` (no route out). Only `egress-proxy` is also on `soc-egress-out`. The worker gets `HTTPS_PROXY=http://egress-proxy:3128`; the proxy allows CONNECT only to the hosts in `WEEK5_EGRESS_ALLOW` (default `generativelanguage.googleapis.com`, `api.abuseipdb.com`) on port 443, refuses IP literals and private/loopback/link-local addresses, and never sees request content (TLS is end to end). Only the worker receives the keys. If the proxy is down the worker's calls fail; a failed model call retries and ends in a stored `needs_review` case, a failed threat-intel lookup is recorded `unavailable` and changes nothing.
**Your live base file and `model-egress`.** A base file that puts the worker on a direct-internet network such as `model-egress` would let the worker bypass the proxy (Compose unites network lists). The override therefore REPLACES the worker's network list with `[backend]`, which removes `model-egress` from the worker; the `model-egress` network stays defined and unused. If you prefer to keep `model-egress` instead of the proxy, do not use this override at all (use one design, not both). `tests/test_week5_egress_deploy.py` checks these properties against whichever base file is in the repository, including that the model switches of the base survive the merge.
Live verification checklist (nothing here has been run; the worker reaching Gemini THROUGH the proxy is the first thing to confirm, because it is a change from your working direct route): [ ] worker can reach Gemini through the proxy and a job ends with `model: gemini...` provenance; [ ] `docker compose exec api python -c "import urllib.request;urllib.request.urlopen('https://example.com',timeout=5)"` FAILS; [ ] the same from the worker FAILS for example.com and works for the two allowed hosts only via the proxy; [ ] `docker compose logs egress-proxy` shows host names and counts and no keys.

## 6. Health checks
| What | How |
|---|---|
| API alive / ready | `GET /health/live`, `GET /health/ready` (database, broker) |
| Dashboard | the Providers page (queue, database, jobs, model mode, threat-intel outcomes from stored cases) and Diagnostics (versions, policy hashes, audit chain, migrations) |
| Containers | `docker compose ... ps` (all `healthy`; `migrate` `Exited (0)`) |
| Proxy | healthcheck in the override file (`GET /healthz` on the proxy port, inside the network) |
| Audit chain | `GET /diagnostics` -> `audit_chain.ok` |
The API cannot read worker heartbeat files; the Providers page says so instead of guessing.

## 7. Troubleshooting
| Symptom | Likely cause and action |
|---|---|
| `config -q` complains about a missing variable | a required `${VAR:?}` is empty in `.env.week5`; set it |
| `migrate` exits non-zero | read `docker compose logs migrate` (no secrets are printed); a failed migration was rolled back; fix and re-run |
| Sensor upload returns 401 / 403 | token wrong, or the account is a viewer / inactive / unknown |
| Sensor upload returns 422 `no_valid_events` | none of the events were usable; the response lists reason codes per index |
| Alerts appear but cases stay `queued` | worker not running or not healthy; check `ps` and `logs worker` |
| Case shows `model_error` | the model was unreachable on every attempt; the case is `needs_review` by design. With live mode: check the key, `WEEK5_ALLOW_LIVE_MODEL`, the proxy log |
| Threat intel says `disabled` | no `SOC_REPUTATION_API_KEY` in the worker's environment |
| Threat intel says `unavailable (budget)` | daily budget used; raise `WEEK5_TI_DAILY_BUDGET` deliberately |
| Threat intel says `skipped` | the alert's set is not in `WEEK5_TI_ALERT_SETS` |
| Proxy log shows `host_not_allowed` | something tried to reach a host outside the allow-list; that is the design working. Add a host to `WEEK5_EGRESS_ALLOW` only if you intend that destination |
| Proxy log shows `non_public_address` | the allowed host resolved to a private address (DNS issue or rebinding attempt) |
| Dashboard shows "unavailable" for a panel | the API said so on purpose (a provider or a store was unreachable); the reason is on the panel |
| Cases after the upgrade have the old policy hash | by design: a case keeps the policy it was decided under |
