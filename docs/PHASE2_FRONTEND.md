# Phase 2: analyst console (frontend)

> Layout update: the console is now branded CyberSight and uses a top navigation bar instead of a sidebar; colours moved to the CyberSight tokens. See `CYBERSIGHT_FRONTEND.md`. The decisions below about data and honesty are unchanged.

Status: implemented; see `PHASE2_VERIFICATION.md` for exactly what has been executed and what has not.

## 1. What it is

A single-page React console in `frontend/` for the existing Week 5 FastAPI backend. Phase 1 behaviour is unchanged. The only backend change is one new read-only endpoint, `GET /me` (section 5).

## 2. Architecture

```
browser ── same-origin /api/* ──> Vite dev proxy | nginx ──(prefix stripped)──> FastAPI (api:8000)
```

- `src/api/`: typed client. `HttpClient` builds URLs, sets `Authorization: Bearer`, uses `credentials: 'omit'` and `cache: 'no-store'`, enforces a 20 s timeout, supports `AbortSignal` cancellation, and converts every failure into one `ApiError` (`kind`, `status`, `code`, `reason`, `field`, `retryAfter`). `endpoints.ts` has one function per backend route.
- `src/auth/`: credential held in memory only; optional "keep for this tab" uses `sessionStorage`. A credentialed 401 signs the user out with an explanation.
- `src/hooks/`: `useResource` (load, reload, abort on unmount), `usePolling`, `useHealth`.
- `src/lib/poll.ts`: the poller never overlaps requests, backs off on errors, pauses while the tab is hidden, and stops on a terminal job state, a fatal error, a timeout, or repeated errors.
- `src/lib/router.tsx`: a small History-API router (about 150 lines). It replaces `react-router-dom` to keep the dependency surface small; the routes are plain (`/`, `/alerts`, `/alerts/new`, `/cases/:id`, `/investigations`, `/jobs`, `/jobs/:id`, `/audit`, `/settings`).
- `src/features/`, `src/pages/`, `src/components/`: feature widgets, pages, shared UI primitives. `src/components/icons.ts` is the only file that imports `lucide-react`.

## 3. Design system

All values are CSS custom properties in `src/styles/tokens.css`; components reference variables only. Dark first, flat surfaces: no gradients, glow or blur. Icons are Lucide.

| Token | Value | Contrast on card |
|---|---|---|
| bg / sidebar / card / elevated | `#0B1020` / `#10182B` / `#151F33` / `#1B2940` | n/a |
| border / border-strong | `#293750` / `#62779A` (form controls) | 3.6:1 (strong) |
| text / secondary | `#F1F5F9` / `#9AAAC0` | 15:1 / 7.0:1 |
| accent / hover | `#22D3EE` / `#67E8F9` | 9.1:1 |
| success / warning / critical / info | `#34D399` / `#FBBF24` / `#FB7185` / `#60A5FA` | 8.6 / 9.9 / 6.1 / 6.5 :1 |

Severity and status are never colour-only: every badge carries a text label and icon. Focus rings are always visible; there is a skip link; dialogs trap focus and close on Escape; tables restack as labelled cards under 48rem; no horizontal page scroll at 375 px. The strict CSP (no inline style or script) is respected, so the severity bars are SVG.

## 4. API-to-UI map

| UI | Endpoint(s) |
|---|---|
| Health indicator (top bar) | `GET /health/ready` (polled, visibility-aware) |
| Sign-in / role-aware controls | `GET /me` |
| Overview | `GET /cases` (`total` with `limit=1` per status; latest 200 for the severity breakdown), `GET /approvals/pending`, `GET /jobs` |
| Alerts | `GET /cases` (paginated; status filter is server-side) |
| Submit alert | `POST /alerts` (21-field schema, `memory` off/on) then `GET /jobs/{id}` polling |
| Case detail | `GET /cases/{id}`, `/evidence`, `/memory`, `/history`, `GET /actions/{id}` |
| Approve / reject | `POST /actions/{id}/decision` with a fresh `Idempotency-Key` |
| Simulate execution | `POST /actions/{id}/simulate-execution` (approver/admin; always labelled simulated) |
| Investigations | `GET /approvals/pending`, `GET /cases?status=escalated|needs_review` |
| Jobs | `GET /jobs`, `GET /jobs/{id}` |
| Audit | `GET /cases/{id}/history` (per case) |
| Settings | `GET /me`, `GET /health/ready` |

## 5. API gaps and how they are handled

Nothing is fabricated on the client. Where the API cannot answer, the UI says so.

| Gap | Handling |
|---|---|
| No endpoint says who the caller is or what the role may do | **Added `GET /me`** (read role; no audit row, no job, no case; never echoes the credential). Returns `{analyst_id, role, active, permissions:{read, submit, decide}}`. The UI hides controls the API would refuse; the server still enforces everything. Files: `src/week5/api/routes5.py`, `src/week5/api/api5.py`; tests in `tests/test_week5_api.py` (`MeTests`) and `tests/test_week5_hardening.py` (route and role pins). |
| No severity, verdict or risk filter; no search or sort | Severity, search and sort apply client-side to the loaded page only; the UI labels this. |
| No aggregate endpoints | Totals come from `total` with `limit=1`. The severity breakdown covers the latest 200 cases and says so. |
| No global audit feed | The Audit page works per case and says so. (A global feed would need a new endpoint; the hash chain is global, so one is feasible later.) |
| Detector score only on case detail | Shown there only. |
| No CORS on the backend | Not needed: browser and API share an origin through the proxy. |

## 6. Security notes

- No secret in the bundle, image or compose override. The e2e run greps the built bundle for token-looking values.
- Token lives in memory (optionally `sessionStorage` for the tab); never `localStorage`; never in a URL; never logged.
- Strict CSP set by nginx: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`, plus nosniff, no-referrer, frame denial.
- nginx container: unprivileged, read-only root, all capabilities dropped, no-new-privileges, loopback-only port.
- The dev-header sign-in exists only when `import.meta.env.DEV` is true.
- Submit sends no client Idempotency-Key: the server recognises an identical alert by content, so a retry cannot create a duplicate. Decisions send a key because the API requires one.
- The API rate limit (default 120 requests/minute per the compose file) applies to the console too. Polling is conservative (2 s jobs while active, 30 s health); a 429 is shown with its retry time.

## 7. Test strategy

1. Unit tests (Vitest): router, formatting, severity, id rules, case sorting, alert schema validation and JSON import, poller behaviour, HTTP client, error normalisation.
2. Component tests (Vitest + Testing Library): Badge, DecisionDialog, SubmitAlertPage.
3. End-to-end (`npm run e2e`): Chromium against the real `Api5` handlers; covers sign-in failures, role differences, approve/reject/simulate and a 409 conflict, submission with duplicate detection, polling that stops, outage and recovery, mid-session 401, mobile layout, keyboard, CSP, and per-page accessibility and contrast audits.
4. Backend: `MeTests` and the updated hardening pins.

## 8. Files

New: everything under `frontend/`, `docker-compose.frontend.yml`, `docs/PHASE2_FRONTEND.md`, `docs/PHASE2_VERIFICATION.md`.
Modified: `src/week5/api/routes5.py`, `src/week5/api/api5.py`, `tests/test_week5_api.py`, `tests/test_week5_hardening.py`.
Untouched: `app5.py`, `serve5.py`, `docker-compose.week5.yml`, all Phase 1 code.
