# Phase 2 verification record

Written so that nothing is claimed that was not observed. The build environment used to produce this change could not reach the npm registry and had no Docker daemon, so part of the stack has **not** been run. Those items are listed under "Not yet executed"; please run them on your machine (commands in section 3).

## 1. Executed and observed

| Check | Result |
|---|---|
| Strict TypeScript type-check of all app sources (`strict`, `noUncheckedIndexedAccess`, `verbatimModuleSyntax`) | 0 errors, against **minimal stand-in type declarations** for React/lucide (not the real `@types/react`) |
| Type-check of the 9 logic test files | 0 errors, against a Vitest stand-in |
| 75 pure-logic tests (router, format, severity, ids, caseSort, alertSchema, poll, client, errors), run with Node's test runner through a Vitest-compatible shim | 75 pass, 0 fail (a deliberately planted bug made one fail, so the tests do detect regressions) |
| Production-style bundle of the real sources (esbuild; lucide-react replaced by a stub that draws circles) | builds |
| End-to-end in Chromium (Playwright) through the shipped `e2e/` runner, final sources: sign-in 401/403 cases, viewer vs approver controls, approve/reject/simulate, 409 conflict, dialog focus trap, alert submission with duplicate detection, polling that stops, Jobs/Audit/Settings, outage and recovery, mid-session 401, 375 px layout without horizontal scroll, skip link, per-page structural accessibility and WCAG-AA contrast audits, no CSP violations or console errors, no token in the bundle | 98 of 98 checks pass. The API side was the project's real `Api5` handlers over an in-memory backend behind a stdlib server with the strict CSP |
| Backend: `tests/test_week5_api.py` + `tests/test_week5_hardening.py` (includes the 4 new `MeTests` and the updated route/role pins) | 70 run, OK, 8 skipped (the skips are the tests that need PostgreSQL) |
| `docker compose ... config -q` on `docker-compose.week5.yml` + `docker-compose.frontend.yml` with placeholder variables | no errors reported |

## 2. Not yet executed (unverified)

- `npm install` and the real `vite build` (Vite 8, `@vitejs/plugin-react`), including the `tsc` step against the real `@types/react`.
- Vitest itself, including the 3 component tests (`Badge`, `DecisionDialog`, `SubmitAlertPage`). They are written but never run.
- `npm run lint`: `eslint.config.js` has not been loaded by ESLint, and rule violations are unknown.
- Real Lucide icon names and rendering. All icons were circles in the browser run. A wrong icon name would show up as a type error or missing icon in your build.
- The Docker image build, nginx (`nginx.conf` has never been parsed by nginx), the container healthcheck and the proxy path `/api/*` -> `api:8000`.
- `npm run e2e` on Windows (the runner uses `path.delimiter` and `E2E_PYTHON`, but has only run on Linux).
- The 8 PostgreSQL-backed backend tests, and any behaviour against a real PostgreSQL/Celery stack.
- Phase 1's full suite was not rerun (baseline stays 1,863 tests / 110 skipped / 0 failures; only the two touched test files were run).
- Real-user evaluation, production performance and screen-reader testing: outstanding. The accessibility audits are structural and contrast checks, not assistive-technology testing.

## 3. Commands to verify on your machine

```
git status                                   # before: expect your 39 preserved entries
python -m pytest tests/test_week5_api.py tests/test_week5_hardening.py -q
cd frontend
npm install                                  # creates package-lock.json
npm run build
npm test
npm run lint
npx playwright install chromium
npm run e2e
cd ..
docker compose -f docker-compose.week5.yml -f docker-compose.frontend.yml --env-file .env.week5 up -d --build
git status                                   # after: only the files listed in the change manifest differ
```

Report any failure verbatim; typical first-run fixes are an icon name or a type error surfaced by the real `@types/react`.

## 4. Deliberate deviations

- **Router.** The Phase 2 brief named React Router; a ~150-line History-API router (`src/lib/router.tsx`, unit-tested) is used instead to reduce dependencies. Swapping is mechanical if you prefer React Router.
- **TypeScript 6.0.x** rather than 6.1: typescript-eslint 8 does not yet accept 6.1.
- **No chart library.** The one chart (severity bars) is SVG so the strict CSP needs no inline styles.
- **Filters.** Severity, search and sort are client-side on the loaded page because the API has no such parameters; labelled in the UI.
- **Settings and Audit pages** are limited to what the API supports (readiness details and per-case history).
