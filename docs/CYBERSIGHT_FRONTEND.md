# CyberSight frontend

CyberSight is the product name of the analyst console. Tagline: **See threats sooner. Respond smarter.** This document describes the redesign of the existing React console. Only the user-facing name, layout, styling and a set of new read-only pages changed. The backend, the API contracts, the 21-field alert schema, the JSON import parser, the request envelope, validation, job polling, authentication, the Docker files, the database, the Python package names, environment variables and service names were **not** renamed or changed.

## Brand assets (original artwork)

| File | Use |
|---|---|
| `frontend/public/favicon.svg` | Browser tab icon (same artwork as the icon below) |
| `frontend/public/brand/cybersight-icon.svg` | Stand-alone mark: a geometric shield with an eye/lens cut-out and a detection iris, electric-blue to deep-blue gradient |
| `frontend/public/brand/cybersight-icon-mono.svg` | Single-colour mark (`currentColor`) for print, stamps and one-colour contexts |
| `frontend/public/brand/cybersight-logo.svg` | Horizontal logo, wordmark in light text for dark backgrounds |
| `frontend/public/brand/cybersight-logo-light.svg` | Horizontal logo for light backgrounds |
| `frontend/public/brand/cybersight-logo-mono.svg` | Single-colour horizontal logo |

In the application the logo is `src/components/brand/Logo.tsx` (`LogoMark`, `Logo`); the wordmark there is live text in the theme colours, so it reads on both themes. The logo is used in the top bar, the sign-in page and the favicon. The SVG wordmark files use a generic sans-serif font stack and no external font. The artwork was drawn for this project; it does not copy another company's mark.

## Layout

A sticky horizontal top bar; there is no permanent left sidebar. Left: logo, wordmark, "Security Operations". Centre: Dashboard, Alerts, Cases, Evidence, Analytics, Threat Intelligence, Playbooks, Reports, Audit Log. Right: Submit alert (only for roles with the submit permission), API health, notification bell, theme toggle, account menu. Below 72rem the destinations collapse into a menu panel (button with `aria-expanded`, Escape closes it, focus returns to the button). At 40rem and below, the theme switch moves into the account menu so the bar fits a 320px phone. A skip link and focus-to-main on navigation are kept.

The account menu holds Settings, System status, Jobs and Review queues (the pages that were reachable from the old sidebar but are not among the nine primary destinations), the theme switch on narrow screens, and Sign out.

## Routes

| Route | Page | Backed by |
|---|---|---|
| `/` | Dashboard ("Security Operations Overview") | `/overview`, `/search/cases`, `/approvals/pending`, `/jobs`, `/providers` |
| `/alerts`, `/alerts/new` | Alert queue; submit alert (form or JSON, "Insert example") | `/search/cases`, `POST /alerts` |
| `/cases`, `/cases/:id` | Case list; case detail (Summary, MITRE, History, Notes & feedback, Evidence, Memory) | `/search/cases`, `/cases/{id}/analysis|evidence|memory|history` |
| `/evidence` | Evidence for one chosen case | `/cases/{id}/analysis`, `/cases/{id}/evidence` |
| `/analytics` | Distributions and processing statistics | `/overview`, `/search/cases`, `/jobs` |
| `/threat-intel` | Provider status, lookup outcomes, indicators per case | `/providers`, `/cases/{id}/analysis` |
| `/playbooks` | Pending approvals, decisions and simulated runs, About | `/approvals/pending`, `/actions` |
| `/reports` | Exports built in the browser (CSV and JSON) and the stored evaluation reports | `/search/cases`, `/jobs`, `/overview`; links to `/evaluation` (which lists `/evaluation/reports`) |
| `/audit` | Audit trail for one chosen case | `/cases/{id}/history` |
| `/jobs`, `/jobs/:id` | Jobs and job detail with polling | `/jobs`, `/jobs/{id}` |
| `/system`, `/evaluation`, `/investigations`, `/settings` | Kept as before (reached from the account menu, Reports and Playbooks) | as before |

Old URLs keep working. No new API endpoint is called, and no endpoint was changed.

## What the pages do and do not claim

* Every number on the Dashboard tiles and the "exact" charts is computed by the API. Charts built from a page of rows say "among the newest N of M". The Alerts page searches the server; the filters on the Dashboard table apply only to the rows already loaded, and say so.
* The notification bell counts only real items from `/overview` (pending actions, escalated, needing review, failed or timed-out jobs). If `/overview` fails the bell says it is unavailable; it never shows an invented count.
* System health rows show healthy, degraded, unavailable or **unknown**. The API does not expose worker, sweeper or model health, so those rows say "Unknown" and why.
* The API has no cross-case evidence, audit or indicator feed and no playbook catalogue. Evidence, Audit Log and Threat Intelligence therefore read one case at a time through a case picker, and Playbooks says that none are defined. Nothing is fabricated to fill the space.
* The AI verdict (a hypothesis from the model) is shown separately from the deterministic policy routing and risk. The console does not assert command-and-control or beaconing: it shows the deterministic timing statistics and states that regular timing alone does not show that traffic is malicious.
* Audit chain: "verified" appears only where the server's diagnostics say it verified.
* Playbooks: approving records a person's decision. "Simulated" means an audit record was written. No button runs, blocks, isolates or deletes anything.
* Settings shows only the real session (from `/me`), the appearance switch and the API state. It has no invented settings and shows no token or secret.

## Design system

Tokens live in `src/styles/tokens.css` and no component hard-codes a colour. Dark theme is the default: background `#081426`, secondary `#0B1220`, panel `#111F35`, elevated `#17263D`, border `#263750`, text `#E8F0FC`, secondary text `#9FB1CB`, electric blue `#38BDF8`, deep blue `#2563EB`, teal `#10B981`, red `#F43F5E`, amber `#F59E0B`, slate `#64748B`, violet `#8B5CF6`. Where a colour is used as text on a panel, a text-safe variant is used (`--critical-fg`, `--violet-fg`) so contrast stays at or above 4.5:1. Severity and status always print their name; colour is never the only signal. A light theme is `[data-theme='light']`. The choice is kept for the browser tab only (`sessionStorage`, key `cybersight.theme`), matching how the session token is handled; nothing is written to `localStorage`.

Charts are plain SVG (bar list, donut, column chart). Each has an accessible name and the numbers in text; the column chart repeats them in a visually hidden table. There is no charting library and no inline style, so the strict Content-Security-Policy in `nginx` (`style-src 'self'`) is unchanged and still satisfied.

## Run, build, test

```
cd frontend
npm install
npm run dev        # http://localhost:5173 (Vite proxies /api to DEV_API_TARGET)
npm run build
npm test           # unit tests, including the new chart, analytics, CSV, service-health and example-alert tests
npm run lint
npm run e2e        # Playwright against the real API handlers (see frontend/README.md)
```

Deploy exactly as before (`docker compose` with the existing frontend service). No new environment variable, port or volume is needed.

## Known limits

* Charts built from rows use at most the newest 100 cases or jobs and say so.
* The time-range selector on Analytics applies to those sampled charts only; exact totals are all-time.
* Reports are generated in the browser from loaded data; there is no server-side report service.
* The example alert on the submit page uses reserved documentation addresses and invented values. It is not real traffic.
* Real accuracy or production performance is not measured by any of this.

## Verification record (what was executed, and where)

Run in the build sandbox (Linux, Node 22, Chromium via Playwright, the real Week 5 API handlers in-process, a synthetic database). **Not** run on your machine.

| Check | Result |
|---|---|
| TypeScript type check of the whole `src/` tree (`tsc --noEmit`, strict) | exit 0 |
| Unit tests of the pure logic (117 tests, including the new chart, analytics, CSV, service-health and example-alert tests) | 117 pass, 0 fail |
| Browser run (`e2e/scenario.mjs`, 229 checks, all sections below) | 229 pass, 0 fail |
| Built bundle contains no token or secret-looking value; no Content-Security-Policy violation; no unexpected console error or warning | pass (part of the 229) |

The 229 browser checks by section: sign-in 7, viewer 8, dashboard 7, alerts 8, case and approval 24, submit alert 14, jobs/audit/settings 12, sensor path 45, outage 4, session 1, 375px phone 20, CyberSight shell, pages and themes 73 (nine routes in dark and light with structural-accessibility and WCAG AA text-contrast audits, nav order and keyboard use, sticky top bar, logo/favicon/brand files served, theme persistence in the tab only, account menu, notification bell, example alert, no horizontal scroll at 320, 375, 768, 1024 and 1180px, nav inline only above 72rem), keyboard and CSP 6.

Defects these runs found and that are fixed in this version: a low-contrast notification badge, `aria-controls` pointing at panels that were not rendered, empty states that skipped heading levels, a top bar that overflowed a 375px phone, a hidden table cell that widened the page at tablet widths, a donut chart drawn as a solid disc, and a dashboard table too wide for its card.

**Not executed in the sandbox** (the package registry and Docker are unreachable from it): `npm install`, the real Vite build (`npm run build`), ESLint (`npm run lint`), Vitest itself (the same test files ran on Node's built-in test runner with a small shim), a real `lucide-react` (a stub with the same export names stood in; the icons were therefore checked by name, not by eye), and Docker/nginx. The screenshots were taken from an esbuild bundle of the same sources. Please run `npm install`, `npm run lint`, `npm run build` and `npm test` once on your machine; the e2e suite also runs there with `npm run e2e`.
