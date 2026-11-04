# Authentication: test report (pre-deployment review)

Every number below comes from a command that was run on the tree this report ships with. Nothing was run against production, no migration was applied anywhere but scratch databases, and nothing was pushed. Test environment: Linux sandbox, Python 3.13, PostgreSQL 16 (scratch databases cloned from a migrated template), Node 22, Chromium via Playwright.

## What could and could not be run (read this first)

The sandbox's egress policy blocks PyPI and npm (HTTP 403 from the proxy; I did not route around it), and there is no Docker daemon. So:

| Requested check | What ran | What did **not** run |
|---|---|---|
| Real Argon2 (`argon2-cffi`) | The Argon2id **primitive** from `cryptography` 50.0.1, which reproduces the RFC 9106 Argon2id test vector (`0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659`). Our `PasswordHasher`, the self-test and an end-to-end sign-in ran on a small `argon2` **stand-in module** built on that primitive (not shipped, lives outside the repository). | `argon2-cffi` itself. Its exact exception types and parameter validation are what the real run must confirm. |
| FastAPI / CORS | The real `create_app5` and `week4.api.app.create_app` served by the real `uvicorn` over real HTTP, with Starlette's real `CORSMiddleware` (the class FastAPI re-exports), on a **~20-line FastAPI stand-in** over Starlette 1.7 (not shipped). | FastAPI itself (route registration, OpenAPI generation, request validation handlers). |
| Frontend typecheck | `tsc` (project's strict config) over all of `src` except tests, with hand-written stand-in typings for `react`, `react-dom` and `lucide-react` (real `@types/react` unavailable). | Real typings. Errors that depend on real React prop types would not show. |
| Frontend lint | Not run (`eslint` unavailable). | Everything. |
| Frontend tests | The 17 pure-logic test files (122 tests, including the rewritten API-client tests) under a ~60-line **stand-in** for vitest. | Real vitest, jsdom, the component tests (`DecisionDialog`, `SubmitAlertPage`), Testing Library. |
| Frontend build | `esbuild` bundle with `lucide-react` replaced by a stub, used by the browser runs. | `vite build`, `tsc -p tsconfig.build.json`. |
| Docker | `docker compose config -q` (client only, dummy values, no real secrets) for `week5`, `week5 + frontend`, `week5 + egress`: all exit 0. | `docker build`, `docker compose up`, image start-up. The new `argon2` import check in `Dockerfile.week5` has therefore **not been built**. |
| Vercel | An emulator of the rewrite rules (`frontend/e2e/vercel_emulator.py`) and a browser run through it. | Real Vercel: which headers its proxy forwards, timeouts, cookie handling of rewritten responses. See `docs/AUTHENTICATION.md` section 5 for the post-deployment checks. |

Please run these yourself: `python -m week5.auth.passwords`, then `python -m unittest tests.test_week5_app5_http` (it uses real FastAPI automatically when installed), then in `frontend`: `npm ci`, `npm run typecheck`, `npm run lint`, `npm test`, `npm run build`, and `docker build -f Dockerfile.week5 .`.

A correction to an earlier progress note: I said a browser control proved that third-party cookies were being refused. It did not: the Chromium flag I used did not block anything, and the control was vacuous. It was removed. The replacement is structural and stronger: in the Vercel-mode browser run, **no request in the whole run goes to any origin other than the page's own**, so there is no third-party cookie to block. Whether a given browser would accept a cross-site cookie was **not** tested.

## 1. Cookie attributes (new)

`tests.test_week5_auth.ProductionCookieTests` (7 tests) parses the `Set-Cookie` header (no substring matching) and asserts the production cookie is exactly: name `__Host-cybersight_session`, flags `HttpOnly` and `Secure` and nothing else, `SameSite=None`, `Path=/`, no `Domain`, `Max-Age` equal to the configured absolute lifetime; the clearing cookie has the same attributes plus `Max-Age=0`; production defaults (empty environment, and the Render-shaped environment) produce it; `SameSite=None` without `Secure` is refused at start-up; plain-http local development never gets a `__Host-` name. One PostgreSQL test (`test_the_production_cookie_comes_out_of_a_real_sign_in_and_sign_out`) checks the same on a real sign-in and sign-out. `tests.test_week5_app5_http` checks it again as it leaves a real uvicorn server (exactly one `Set-Cookie`). The browser run reads it back from Chromium's cookie jar: HttpOnly, Secure, SameSite=None, Path=/, host-only on the front-end origin, nothing stored for the API origin.

Sensitivity check: deleting `HttpOnly`, deleting `Path=/`, deleting `Secure`, or changing `SameSite` in `web.py` each made the new tests fail (3, 4, 4 and 3 failing tests); the file was restored afterwards.

## 2. Vercel `/api` rewrite (new)

* `frontend/vercel.json`: rewrite `/api/:path*` -> `https://cybersight-api.onrender.com/:path*`, SPA fallback for everything that is not a file and not under `/api/`, the same security headers as `nginx.conf` (CSP with `connect-src 'self'`), `Cache-Control: no-store` on `/api/...`, `build.env.VITE_API_BASE_URL=/api`. The code default and `.env.example` were already `/api`.
* `tests.test_week5_vercel_rewrite` (8 tests): file shape; the routing table (`/api/auth/login` -> `.../auth/login`, query string kept, prefix removed, only ever to the Render host); console deep links (`/admin/users`, `/setup`, ...) fall back to the SPA; built files win over rewrites; look-alike paths (`/apix/...`, `/apiary`) are not proxied; headers equal nginx's CSP.
* Browser run through the emulator (`E2E_MODE=vercel`: a "Vercel" front on one port proxying `/api` to a separate "Render" API on another, production cookie settings, i.e. `__Host-`, `Secure`, `SameSite=None`): full scenario passes, 293/293, including cookie in the browser, refresh restore, API calls reaching the API without the prefix, every API request same-origin, the API origin blocked by CSP, a state-changing request without `Origin`/CSRF refused through the proxy, deep link served by the SPA with security headers, API responses `no-store`, and "no request in the whole run left the front-end origin".
* `WEEK5_TRUSTED_PROXY_HOPS=2` is recommended behind Vercel (documented with a database check to confirm it after deployment). This is an assumption about how Vercel and Render add `X-Forwarded-For`; it is **not verified**.

## 3. Bootstrap secret generator (docs)

`Get-Random` removed. The runbook now uses `System.Security.Cryptography.RandomNumberGenerator` (works in Windows PowerShell 5.1 and 7), URL-safe 64 characters, copied to the clipboard rather than printed, with a clipboard-clearing step and a `secrets.token_urlsafe(48)` alternative. A value of that shape (64 characters) was confirmed to be accepted by `AuthSettings`. The PowerShell command itself was not executed here (no PowerShell in the sandbox).

## 4. Package hygiene

The previous ZIP contained 11 `__pycache__`/`.pyc` entries (a directory copy). The new ZIP is built from an explicit list of changed and new source files (`git ls-files -m -o --exclude-standard`, filtered), and the final check on the finished archive is part of the build: it counts `__pycache__`, `.pyc`, `.pyo`, `node_modules`, `.env`, `.git` entries and must find 0.

## 5. Results

| Suite | Result |
|---|---|
| Targeted: `test_week5_auth`, `_vercel_rewrite`, `_app5_http`, `_api`, `_ops`, repo as-is (no stand-ins on the path) | 180 tests, OK, 13 skipped (real-FastAPI tests and Argon2 tests skip without the packages) |
| Targeted with the Argon2 and FastAPI stand-ins on the path: `test_week5_auth`, `_app5_http`, `_vercel_rewrite` | 96 tests, OK, 1 skipped (the "library missing" test) |
| Full repository suite, changed tree (`python -m unittest discover -s tests -t .`, PostgreSQL on) | 2243 tests: 2 failures, 107 errors, 43 skipped |
| Same suite on a pristine copy of HEAD `c947db7` | 2143 tests: 3 failures, 107 errors, 35 skipped |
| Failing-test sets compared | **No test fails on the changed tree that did not fail on HEAD.** One HEAD failure is fixed (`test_every_required_variable_fails_loudly_and_is_documented`: the `# WITH_GENAI=0` line added to `.env.week5.example`). The remaining 109 are identical on both and unrelated to this work: Week 2-4 lock and manifest checks that need files this checkout does not have (`memory_store/`, frozen Week 1 files), LangGraph not installed, and the missing `.gitignore.week5-additions`. |
| Browser, same origin (real request handlers on PostgreSQL) | 283 / 283 |
| Browser, through the Vercel rewrite emulator | 293 / 293 |
| Frontend logic tests, stand-in runner | 122 passed, 0 failed (17 files) |
| Frontend `tsc` (stand-in typings) | no errors apart from artefacts of the stand-in typings (`key` props, implicitly-any event handlers) |
| `docker compose config -q` (3 combinations, dummy values) | exit 0 |
| Argon2 self-test (stand-in module on a genuine primitive) | `argon2id OK`, `scrypt OK`, exit 0 |

Evidence files are in `test-evidence/` inside the ZIP (browser logs, full-suite summaries and failing-test lists for both trees, frontend logic-test log).

## 6. Defects found by this review

* The earlier ZIP contained bytecode (fixed by building the archive from an explicit file list).
* A browser control I had added was vacuous (described above) and was replaced.
* The test harness's own CSP probe leaked into the console-error check; fixed in the test, not in the product.
* Documentation gap: behind a proxy the right hop count is 2, not 1; with 1 all visitors would share one per-address sign-in allowance. Documented, with a database query to confirm after deployment.
* `docker-compose.week5.yml` did not pass `WEEK5_TRUSTED_PROXY_HOPS` through; it does now (default 1).
