# CyberSight sign-in (username and password)

People sign in to the console with a **username and a password**. The browser never sees an API token, an analyst id field or a "remember me" box. The server checks the password, opens a **server-side session** and hands the browser one `HttpOnly` cookie. Every request after that is checked against the session row in PostgreSQL, and the role comes from `soc.analysts`.

The old Bearer API tokens still exist for **machines** (sensor ingestion, the load tester, scripts). They are not used by the console. When you no longer need them, set `WEEK5_ALLOW_BEARER_TOKENS=0` (see "Retiring the machine tokens").

Week 4 migrations, the Week 4 lock files and the Week 4 code were not touched. All of this is Week 5 (`src/week5/auth/`, migration `0003_auth_sessions.sql`).

## What it does

| Topic | How |
|---|---|
| Passwords | Argon2id (`argon2-cffi`) with a unique random salt per password. Parameters are configurable (`WEEK5_ARGON2_*`). A scrypt fallback exists for machines where Argon2 cannot be installed. Minimum 12 characters (max 128), must not contain the username, weak/common passwords refused. Plaintext is never stored or logged. Verification is constant time, and an unknown username still costs one hash, so timing does not reveal which usernames exist. Hashes are upgraded to the current parameters at the next successful sign-in. |
| Usernames | 3 to 32 characters: lower-case letters, digits, `.`, `_`, `-`; must start with a letter or digit. The username **is** the analyst id (`soc.analysts.analyst_id`), so audit history, approvals and notes stay attached to the same person. |
| Errors | One generic message for "wrong username", "wrong password", "inactive account". No account enumeration. |
| Sessions | 256-bit random token, only its SHA-256 is stored (`soc.web_sessions`). Cookie: `HttpOnly`, `Secure`, `SameSite=None` (needed because Vercel and Render are different sites), `Path=/`, named `__Host-cybersight_session`. Idle expiry 12 h (sliding), absolute expiry 7 days, at most 10 live sessions per person (the oldest is ended). Logout, deactivation, a password change or reset, and "end sessions" all revoke on the server immediately. A refresh restores the session from the cookie. Nothing is kept in `localStorage` or `sessionStorage`. |
| CSRF | Every state-changing request needs (1) an `Origin` header that is exactly one of `WEEK5_ALLOWED_ORIGINS` and (2) an `X-CSRF-Token` header. The token is an HMAC derived from the session token; the page gets it from `POST /auth/login` or `GET /auth/session` and keeps it in memory only. |
| CORS | Credentialed CORS for the exact origins in `WEEK5_ALLOWED_ORIGINS`. No wildcard is ever sent. |
| Throttling | Stored in PostgreSQL (`soc.auth_attempts`, keys are salted hashes, not raw usernames or IPs), so it survives restarts and works across instances. Limits per (username + address), per address and per username, default 5 / 40 / 20 failures per 15 minutes. A successful sign-in clears that pair's failures. Throttled requests record nothing, so an attacker cannot keep a real user locked out by hammering the endpoint: the lock expires 15 minutes after the **last counted** failure, and the per-username limit is skipped for an address that signed in successfully in the last 30 days, so a person on their usual address is not locked out by someone guessing their name from elsewhere. |
| Database access | The API login role (`soc_api`) has **no privilege on the three new tables**. It can only call `SECURITY DEFINER` functions (`soc.auth_*`) that pin `search_path = soc, pg_temp`, have `EXECUTE` revoked from `PUBLIC` and granted to `soc_api` only. Account changes take an advisory lock, are written to the hash-chained audit log, and the audit payloads never contain passwords or tokens. |
| Roles | `viewer`, `analyst`, `approver`, `admin` (unchanged). Every Week 4 and Week 5 route keeps its role rule. New routes: `session` (any signed-in person) and `admin`. |

## Endpoints

| Method and path | Who | Purpose |
|---|---|---|
| `GET /auth/status` | anyone | `{"web_auth": true, "bootstrap_available": bool}` (drives the "first-time setup" link) |
| `POST /auth/login` | anyone (throttled) | `{username, password}` -> sets the cookie; returns `{user, csrf_token, idle_expires_at, absolute_expires_at}` |
| `GET /auth/session` | session | Who am I, permissions, a fresh CSRF token (used on page load) |
| `POST /auth/logout` | anyone | Revokes the session and clears the cookie (idempotent) |
| `POST /auth/change-password` | session | `{current_password, new_password}`; ends the person's **other** sessions |
| `POST /auth/bootstrap` | anyone with the setup secret | Creates the first administrator, once (see below) |
| `GET /auth/users` | admin | List accounts (never hashes or tokens) with role, status, last sign-in, live sessions |
| `POST /auth/users` | admin | Create an account `{username, role, password, display_name?}` (409 if it exists; attaches a password to an existing token-only analyst) |
| `PATCH /auth/users/{username}` | admin | Change `role` and/or `active`. An administrator cannot demote or deactivate themselves, and the last administrator cannot be removed. Deactivation ends the person's sessions. |
| `POST /auth/users/{username}/reset-password` | admin | `{new_password}`; ends all of that person's sessions |
| `POST /auth/users/{username}/revoke-sessions` | admin | Ends every session of the account; returns the count |

There is no public registration. The OpenAPI document (`/openapi.json`) describes these under a `sessionCookie` security scheme.

## Environment variables

None of these hold a secret except `WEEK5_BOOTSTRAP_TOKEN` (set it only in the host's secret store, never in Git).

| Variable | Default | Meaning |
|---|---|---|
| `WEEK5_WEB_AUTH` | on | `0` turns browser sign-in off (legacy behaviour; only for rollback) |
| `WEEK5_ALLOWED_ORIGINS` | `https://cybersight-nine.vercel.app` | Comma-separated exact origins (`https://host[:port]`, no path). `http://` only for `localhost` / `127.0.0.1`. **Set this on Render.** |
| `WEEK5_COOKIE_SECURE` | `1` | `0` only for local development over plain `http` |
| `WEEK5_COOKIE_SAMESITE` | `None` | `Lax` for same-site local development (`None` needs `Secure`) |
| `WEEK5_SESSION_IDLE_SECONDS` | `43200` (12 h) | Sliding idle expiry |
| `WEEK5_SESSION_ABSOLUTE_SECONDS` | `604800` (7 d) | Hard limit |
| `WEEK5_SESSION_MAX_PER_USER` | `10` | Live sessions per person |
| `WEEK5_PASSWORD_HASH` | `argon2id` | `scrypt` only if Argon2 cannot be installed |
| `WEEK5_ARGON2_TIME_COST` / `_MEMORY_KIB` / `_PARALLELISM` | `3` / `19456` / `1` | Argon2id cost (about 19 MiB, fits Render's free 512 MB) |
| `WEEK5_LOGIN_LIMIT_PAIR` / `_IP` / `_SUBJECT` | `5` / `40` / `20` | Failures allowed per window |
| `WEEK5_LOGIN_LIMIT_WINDOW_SECONDS` | `900` | Window |
| `WEEK5_BOOTSTRAP_TOKEN` | unset (bootstrap off) | One-time setup secret, at least 32 characters. Only its SHA-256 digest is kept in memory. **Remove it after the first administrator exists.** |
| `WEEK5_TRUSTED_PROXY_HOPS` | `1` | How many reverse proxies in front of the API append to `X-Forwarded-For` (used, hashed, for throttling). **Use `2` behind the Vercel `/api` proxy** (Vercel, then Render); `1` for a browser talking to Render directly or through nginx. |
| `WEEK5_AUTH_ATTEMPT_SALT` | derived | Optional salt for the stored attempt hashes |
| `WEEK5_ALLOW_BEARER_TOKENS` | `1` | `0` makes the API accept sessions only |

A bad value stops the API at start-up with a message (no stack trace, no value echoed). `python -m week5.api.serve5 --check` reports whether web sign-in is on, whether bootstrap is available, and whether migration 0003 is missing.

## Deploying to Render and Vercel (free tiers, no shell)

Render's free web service has no shell, and the API's database login (`soc_api`) is deliberately not allowed to change the schema. So **migration 0003 is applied from your own computer** against the Render PostgreSQL **external** URL (owner connection). Do this once, in this order. In PowerShell each line below is one command; run them one at a time.

### 1. Back up first

Render dashboard -> your PostgreSQL -> Backups (or create a manual backup). The migration only adds objects; it does not touch existing tables, but a backup costs nothing.

### 2. Apply migration 0003 from your computer

Open PowerShell in the repository folder (the branch `cybersight`, with these changes).

```powershell
$env:PYTHONPATH = "src;."
```

Type the owner database URL without it ever being printed or saved (copy "External Database URL" from the Render database page; it must end with `?sslmode=require` or you add it):

```powershell
$env:WEEK4_DATABASE_URL = Read-Host "Render external owner database URL"
```

Check what is applied (needs either the `psql` client on your PATH, or `pip install "psycopg[binary]"` and `--driver psycopg`):

```powershell
python -m week5.db.migrate status
```

Apply:

```powershell
python -m week5.db.migrate apply
```

Verify:

```powershell
python -m week5.db.migrate verify
```

Forget the URL:

```powershell
Remove-Item Env:WEEK4_DATABASE_URL
```

The runner applies the whole file in one transaction and records `0003` in `soc.schema_migrations_week5`. It refuses to run if the Week 4 migrations are not in place. If something fails nothing is half-applied.

### 3. Render environment (API service)

Render -> your web service -> Environment:

| Key | Value |
|---|---|
| `WEEK5_ALLOWED_ORIGINS` | `https://cybersight-nine.vercel.app` (add other origins with commas if you use a custom domain) |
| `WEEK5_BOOTSTRAP_TOKEN` | a long random value you generate yourself (at least 32 characters). See below. |
| `WEEK5_TRUSTED_PROXY_HOPS` | `2` (Vercel proxy in front of Render; see section 5) |

Leave `WEEK5_COOKIE_SECURE` and `WEEK5_COOKIE_SAMESITE` at their defaults on Render. Make sure `argon2-cffi` gets installed (it is in `requirements-week5.txt`; the Docker build uses that file). Deploy. Check `https://cybersight-api.onrender.com/health/live` still answers, and the logs show no `ConfigError`.

To generate the setup secret, use the operating system's cryptographically secure random generator (`System.Security.Cryptography.RandomNumberGenerator`, not `Get-Random`, which is not meant for secrets). This works in Windows PowerShell 5.1 and PowerShell 7 and puts the secret on the clipboard instead of printing it (URL-safe, 64 characters, 384 bits):

```powershell
$b = [byte[]]::new(48); $g = [System.Security.Cryptography.RandomNumberGenerator]::Create(); $g.GetBytes($b); $g.Dispose(); [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_') | Set-Clipboard
```

Paste it into Render's value field (never into chat or Git), then clear the clipboard:

```powershell
Set-Clipboard -Value " "
```

If Python is easier: `python -c "import secrets; print(secrets.token_urlsafe(48))"` (the `secrets` module is also cryptographically secure).

### 4. Create the first administrator (`lakshya`) without a shell

1. Open `https://cybersight-nine.vercel.app/`. Because no administrator exists and the setup secret is set, the sign-in page shows **First-time setup: create the administrator account**. (You can also go to `/setup`.)
2. Enter the setup secret (from Render), the username (`lakshya`), and a password of your choice **twice**. You type the password in this page only.
3. The page returns to sign-in. Sign in with the username and password.
4. **Remove `WEEK5_BOOTSTRAP_TOKEN` from the Render environment and redeploy.** Bootstrap is already closed (it only works while no administrator with a password exists, it is serialised by a database lock so two requests cannot both succeed, and a second attempt gets 409), but an unused secret should not be left around.

Why this is safe: the endpoint answers 404 unless the secret is configured; a wrong secret is throttled and compared in constant time; the secret and the password are never logged and never put in the URL; and the endpoint needs the exact production Origin.

### 5. Vercel: proxy `/api` so the cookie is first-party (recommended, and what the repository now does)

Vercel and Render are different sites. Called directly, the session cookie would be a **third-party cookie**, and Safari, Brave, Firefox strict mode and Chrome with third-party cookies blocked refuse it (you would be signed out at once). So the console calls `/api/...` on its **own** origin and Vercel forwards those calls to Render. The browser only ever sees `https://cybersight-nine.vercel.app`, the cookie is first-party and host-only, and the browser never contacts the API host.

What is in the repository (`frontend/vercel.json`, no secret in it):

- `rewrites`: `/api/:path*` -> `https://cybersight-api.onrender.com/:path*` (the `/api` prefix is removed, the query string is kept), then every other path that is not a file and not under `/api/` -> `/index.html` (single-page app deep links such as `/admin/users` and `/setup`).
- `headers`: the same security headers as the Docker front end (CSP with `connect-src 'self'`, `nosniff`, `X-Frame-Options: DENY`, no referrer, restricted permissions) on every page, and `Cache-Control: no-store` on `/api/...`.
- `build.env.VITE_API_BASE_URL = /api`.

What you do in the Vercel dashboard (I have not touched your project):

1. **Project -> Settings -> General -> Root Directory** must be `frontend` (that is where `vercel.json` lives). If your project's root is the repository root, copy `frontend/vercel.json` to the repository root instead.
2. **Project -> Settings -> Environment Variables**: if `VITE_API_BASE_URL` exists with `https://cybersight-api.onrender.com`, **change it to `/api` or delete it** (the code default is `/api`). A dashboard value takes precedence over the one in `vercel.json`, so a stale value would silently send the browser straight to Render again.
3. Redeploy the frontend from the `cybersight` branch.

On Render keep `WEEK5_ALLOWED_ORIGINS=https://cybersight-nine.vercel.app` (the browser's `Origin` is still the Vercel origin) and set **`WEEK5_TRUSTED_PROXY_HOPS=2`**: Vercel is expected to put the visitor's address in `X-Forwarded-For` (check 5 below confirms it), and Render appends the address of the proxy it sees (Vercel). With `1` the API would take Vercel's address for everyone and all visitors would share one per-address sign-in allowance (40 failures per 15 minutes), which is a way to lock everyone out briefly. Cookie settings stay at their defaults (`Secure`, `SameSite=None`, `__Host-`); with the proxy the cookie is first-party anyway.

**Checks to make after the first deployment** (I could not run these: they need your real Vercel and Render projects):

1. Open the site in a private window with third-party cookies blocked (Chrome: Settings -> Privacy -> Block third-party cookies), sign in, refresh. You must stay signed in.
2. In the browser's developer tools, Network tab: every request goes to `https://cybersight-nine.vercel.app/api/...`, none to `onrender.com`; Application -> Cookies shows `__Host-cybersight_session` with HttpOnly, Secure, SameSite=None, Path=/ on the Vercel host only.
3. `https://cybersight-nine.vercel.app/api/health/live` answers `{"status": ...}`; `https://cybersight-nine.vercel.app/admin/users` (typed into the address bar) shows the console, not a 404.
4. Origin forwarding: signing in works (a missing or altered `Origin` would give "This site is not allowed to sign in").
5. Proxy hops: sign in once from your computer and once from your phone on mobile data, then, with the owner connection (same `Read-Host` method as in step 2, then `psql`), run `SELECT count(DISTINCT ip_hash) FROM soc.auth_attempts WHERE success;`. You should get **2**. If you get 1, the API is seeing one address for everyone: change `WEEK5_TRUSTED_PROXY_HOPS` (1 or 2) and repeat.
6. Render's free instance sleeps: after idle time the first request can take about a minute, and Vercel may answer 502/504 for that first call. Reload; the console shows "Cannot reach the server" in that case. Calling `/api/health/live` first wakes it.

Limits of what was tested offline: `frontend/vercel.json` is checked by `tests/test_week5_vercel_rewrite.py` and by a browser run through an emulator of these rewrite rules (`frontend/e2e/vercel_emulator.py`, `E2E_MODE=vercel`), with the production cookie settings and Chromium's third-party-cookie blocking switched on. The emulator is not Vercel: which headers Vercel forwards, its timeouts and its handling of cookies from rewritten responses are exactly the points the checks above cover.

If you ever need to call the API directly from another site (not recommended), set `VITE_API_BASE_URL` to the Render URL, keep that site's origin in `WEEK5_ALLOWED_ORIGINS`, and accept that browsers that block third-party cookies will not work.

### Rollback

Switching the feature off without touching the data: set `WEEK5_WEB_AUTH=0` (the old token behaviour returns; the old console build would be needed too, so prefer rolling forward).

Removing the schema (destructive for accounts and sessions, nothing else): from your computer, with the owner URL set as above,

```powershell
psql $env:WEEK4_DATABASE_URL -v ON_ERROR_STOP=1 -f src/week5/db/rollback/0003_auth_sessions_rollback.sql
```

That drops the 16 `soc.auth_*` functions and 3 tables and deletes the `0003` row, so `apply` can run again. It was tested: apply, rollback, apply.

## Managing people

Sign in as an administrator, open the account menu -> **Manage users**. You can create accounts (username, role, initial password), change roles, activate and deactivate, reset a password (the person's sessions all end), and end a person's sessions. Hand the initial password over privately; people change it under **Settings**. Existing token-only analysts show as "API token only (no password)"; **Give a password…** attaches a password to the same analyst id so their history stays theirs.

Passwords cannot be read back. A forgotten password is replaced by an administrator.

## Retiring the machine tokens

Once sensors and scripts have moved (or you have none), remove the token hashes (`WEEK4_API_TOKEN_HASHES` / `WEEK4_API_TOKEN_HASHES_FILE`) and set `WEEK5_ALLOW_BEARER_TOKENS=0`. If no token is configured at all, the API starts in sessions-only mode by itself. Ingestion endpoints then need a signed-in analyst session; for unattended sensors keep one machine token and a dedicated low-role analyst.

## Local development with Docker

The compose default (`SameSite=None; Secure`) is for HTTPS. For `http://127.0.0.1:8080` set, in `.env.week5` (the file is not committed):

```
WEEK5_ALLOWED_ORIGINS=http://127.0.0.1:8080
WEEK5_COOKIE_SECURE=0
WEEK5_COOKIE_SAMESITE=Lax
WEEK5_BOOTSTRAP_TOKEN=<a long random value, local only>
```

Then bring the stack up as before, apply migrations (the `migrate` service does Week 4 + Week 5), open the UI and use **First-time setup**. `nginx` forwards `/api/` to the API and sets `X-Forwarded-For`, so `WEEK5_TRUSTED_PROXY_HOPS=1` is right.

## Tests: what they cover and how to run them

Backend (needs PostgreSQL for the database tests; they are opt-in exactly like the Week 4 ones):

```powershell
$env:PYTHONPATH = "src;."
python -m unittest tests.test_week5_auth -v
```

With a scratch PostgreSQL server (user needs `CREATEDB`):

```powershell
$env:WEEK4_TEST_PG = "1"; $env:PGHOST = "127.0.0.1"; $env:PGPORT = "5432"; $env:PGUSER = "postgres"; $env:PGPASSWORD = Read-Host "PG password"
python -m unittest tests.test_week5_auth tests.test_week5_api tests.test_week5_hardening tests.test_week5_authorization tests.test_week5_ops tests.test_week5_backup_restore tests.test_week5_deploy -v
```

Argon2 itself (needs `pip install -r requirements-week5.txt`):

```powershell
python -m week5.auth.passwords
```

Frontend:

```powershell
cd frontend
npm ci
npm run typecheck
npm run lint
npm test
npm run build
```

Whole flow in a real browser (bootstrap through the setup page, sign in, refresh, create an analyst, role checks, logout, old cookie rejected). It starts the real request handlers on a scratch PostgreSQL, so it needs the same `WEEK4_TEST_PG`/`PG*` variables as above, Python with the project requirements, and Playwright's Chromium:

```powershell
npx playwright install chromium
npm run e2e
```

See "Test results" in the final report for what has actually been run and what has not.

## Known limits

- Without the Vercel `/api` proxy the cookie is third-party and many browsers refuse it. The proxy (section 5) removes that dependency, but it has only been tested against an emulator of Vercel's rewrite rules, so run the post-deployment checks in section 5.
- Throttling can only count addresses the API can see, which depends on `WEEK5_TRUSTED_PROXY_HOPS` (section 5, check 5). A wrong value makes all visitors share one allowance: it can lock sign-in for everyone for up to 15 minutes after enough failed attempts, so verify it after deployment.
- There is no email, so there is no self-service "forgot password"; an administrator resets it.
- No multi-factor authentication.
