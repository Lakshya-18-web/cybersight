# CyberSight (frontend): AI-powered security operations console

CyberSight is the product name of this console (see [`docs/CYBERSIGHT_FRONTEND.md`](../docs/CYBERSIGHT_FRONTEND.md) for the redesign: top navigation, routes, brand assets, themes, what each page does and does not claim). The pages and API behind the older phase documents below still apply; the layout is now a top bar rather than a sidebar.

React 19 + TypeScript + Vite analyst console for the Week 5 FastAPI backend. It shows only what the API returns: no mock data, no invented numbers. Full design and decisions: [`docs/PHASE2_FRONTEND.md`](../docs/PHASE2_FRONTEND.md); the phase 3 pages (alert search, four-class case analysis, notes/feedback/resolve, simulated history, System, Evaluation) are in [`docs/WEEK5_CONSOLE.md`](../docs/WEEK5_CONSOLE.md). What has and has not been verified: [`docs/PHASE2_VERIFICATION.md`](../docs/PHASE2_VERIFICATION.md).

## Run it locally (development)

Requires Node >= 22.12.

1. Start the backend (see `docs/WEEK5_DEPLOYMENT.md`); the API listens on `http://127.0.0.1:8000`.
2. In this folder:
   ```
   npm install
   copy .env.example .env.local      # PowerShell; use cp on macOS/Linux. No secrets belong in it.
   npm run dev
   ```
3. Open http://localhost:5173. Vite forwards `/api/*` to `DEV_API_TARGET` (default `http://127.0.0.1:8000`) with the `/api` prefix removed, so the backend needs no CORS configuration.
4. Sign in with an analyst bearer token. (A development build also offers the `X-Dev-Analyst` header sign-in, only when the backend runs in its dev auth mode; production builds never show it.)

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Vite dev server with the `/api` proxy |
| `npm run build` | Type-check (`tsconfig.build.json`, tests excluded) then production build into `dist/` |
| `npm run typecheck` | Type-check everything including tests |
| `npm run lint` | ESLint (typescript-eslint + react-hooks) |
| `npm test` | Vitest (jsdom): unit tests plus 3 component tests |
| `npm run e2e` | Real-browser run (Chromium) against the real API handlers; see below |
| `npm run preview` | Serve `dist/` on 127.0.0.1:4173 |

### End-to-end run

`npm run e2e` starts a stdlib HTTP server (`e2e/server.py`) that wraps the project's real `Api5` handlers over an in-memory backend, serves `dist/` with a strict Content-Security-Policy, and drives Chromium through every workflow. It needs a built `dist/`, Playwright's browser, and the project's Python environment:

```
npm run build
npx playwright install chromium
$env:E2E_PYTHON = "..\.venv\Scripts\python.exe"     # PowerShell; omit to use `python` from PATH
npm run e2e
```

Run it from `frontend/` with the repository root as the parent folder. Optional: `E2E_DIST`, `E2E_CHROMIUM`, `E2E_REPORT_DIR` (the evaluation report folder the harness serves; default `docs/evalrun/sensor_sample_run`). The scenario also posts the sample EVE batch (`samples/eve/eve_mixed.ndjson`) to the ingestion endpoint, so the repository root must contain `samples/`. It writes screenshots to `e2e/shots/` and a result file to `e2e/e2e_results.json` (both git-ignored).

## Run it in Docker

From the repository root (the existing compose file is not modified):

```
docker compose -f docker-compose.week5.yml -f docker-compose.frontend.yml --env-file .env.week5 config -q
docker compose -f docker-compose.week5.yml -f docker-compose.frontend.yml --env-file .env.week5 up -d --build
```

Open http://127.0.0.1:8080 (change with `WEEK5_UI_PORT`). nginx serves the build and forwards `/api/*` to the `api` service. The UI image holds no secret; the token is typed at sign-in.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `VITE_API_BASE_URL` | `/api` | Where the browser sends API calls. Keep it a same-origin path. |
| `DEV_API_TARGET` | `http://127.0.0.1:8000` | Dev server only; not in the bundle. |
| `VITE_JOB_POLL_MS` | `2000` | 500 to 60000 |
| `VITE_HEALTH_POLL_MS` | `30000` | 5000 to 600000 |

Everything prefixed `VITE_` is public by design. Never put a token or password in it.
