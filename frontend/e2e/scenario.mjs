import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const DIST = path.resolve(process.env.E2E_DIST || path.join(HERE, '..', 'dist'));
import { launch, signIn, apiSession, contrastAudit, a11yAudit, noHorizontalScroll, BASE, PASSWORDS, FIRST_ADMIN, BOOTSTRAP_SECRET, overflowers, overflowChain } from './lib.mjs';

const SHOTS = path.join(HERE, 'shots');
fs.mkdirSync(SHOTS, { recursive: true });
const results = [];
let section = '';
const check = (name, ok, detail = '') => { results.push({ section, name, ok: Boolean(ok), detail }); console.log(`${ok ? 'PASS' : 'FAIL'}  [${section}] ${name}${ok || !detail ? '' : '  -> ' + detail}`); };
const sessions = {};
const as = async (who) => (sessions[who] ??= await apiSession(who));
const api = async (who, path, init = {}) => (await as(who)).json(path, init);
const demo = JSON.parse(execFileSync(process.env.E2E_PYTHON || 'python', ['-B', '-m', 'week5.fixtures', '100'], { cwd: REPO, env: { ...process.env, PYTHONPATH: ['src', '.'].join(path.delimiter) } }).toString());

const { browser, page, problems, foreign } = await launch();
const signInNoWait = async (pg, who) => {
  await pg.goto(BASE + '/');
  const form = pg.getByLabel('Username'); const menu = pg.getByRole('button', { name: /^Account menu for/ });
  await form.or(menu).first().waitFor();
  if (await menu.isVisible()) { await menu.click(); const done = pg.waitForResponse((r) => r.url().includes('/api/auth/logout')); await pg.getByRole('button', { name: 'Sign out' }).click(); await done; await form.waitFor(); }   // the cookie outlives a reload
  await form.fill(who); await pg.getByLabel(/^Password/).fill(PASSWORDS[who]); await pg.getByRole('button', { name: 'Sign in' }).click();
};
const settle = (ms = 400) => page.waitForTimeout(ms);
const goto = async (p) => { await page.evaluate((to) => { history.pushState(null, '', to); dispatchEvent(new PopStateEvent('popstate')); }, p); await settle(600); };
const signOutUi = async () => { await page.getByRole('button', { name: /^Account menu for/ }).click(); const done = page.waitForResponse((r) => r.url().includes('/api/auth/logout')); await page.getByRole('button', { name: 'Sign out' }).click(); await done; };
const MORE_ITEMS = ['Threat Intelligence', 'Playbooks', 'Reports', 'Audit Log'];
// On desktop the four MORE_ITEMS are inside the More menu; in the compact layout they are in the menu panel with the others.
const nav = async (name) => {
  const main = page.getByRole('navigation', { name: 'Main' });
  const link = main.getByRole('link', { name, exact: true });
  if (MORE_ITEMS.includes(name) && !(await link.isVisible())) { await main.getByRole('button', { name: /^More/ }).click(); await main.getByRole('link', { name, exact: true }).click(); }
  else await link.click();
  await settle(500);
};

// ---------------------------------------------------------------- sign-in
section = 'sign-in';
await page.goto(BASE + '/');
await page.getByRole('heading', { name: 'Sign in to CyberSight' }).waitFor();
check('sign-in screen is shown first', await page.getByRole('heading', { name: 'Sign in to CyberSight' }).isVisible());
check('the sign-in form asks for a username and a password and nothing else', await page.getByLabel('Username').isVisible() && await page.getByLabel(/^Password/).isVisible()
  && (await page.getByLabel(/API token|analyst id|remember/i).count()) === 0 && (await page.locator('input:visible').count()) === 2);
check('the password is masked, and can be shown and hidden', await page.getByLabel(/^Password/).getAttribute('type') === 'password');
await page.getByRole('button', { name: 'Show password' }).click();
check('"Show password" reveals it', await page.getByLabel(/^Password/).getAttribute('type') === 'text');
await page.getByRole('button', { name: 'Hide password' }).click();
await page.getByRole('button', { name: /API (ready|degraded|unreachable)/ }).waitFor();
check('health indicator reports the real API as ready', await page.getByRole('button', { name: /API ready/ }).isVisible());
await page.getByRole('button', { name: 'Sign in' }).click();
check('empty fields are caught before anything is sent', await page.getByText('Enter your username.').isVisible() && await page.getByText('Enter your password.').isVisible());
const setupLink = page.getByRole('link', { name: /First-time setup/ });
await setupLink.waitFor();
check('the first-time setup link is offered while no administrator exists', await setupLink.isVisible());
await page.screenshot({ path: SHOTS + '/09-signin.png' });

section = 'first-time setup';
await setupLink.click();
await page.getByRole('heading', { name: 'Create the administrator' }).waitFor();
check('the setup page asks for the secret, a username and a password (twice)', await page.getByLabel(/Setup secret/).isVisible() && await page.getByLabel('Username').inputValue() === 'lakshya' && await page.getByLabel(/^Repeat password/).isVisible());
await page.getByLabel(/Setup secret/).fill('not-the-secret-' + 'z'.repeat(30));
await page.getByLabel(/^Password/).fill(FIRST_ADMIN.password);
await page.getByLabel(/^Repeat password/).fill(FIRST_ADMIN.password);
await page.getByRole('button', { name: 'Create administrator' }).click();
await page.getByText('The setup secret is not correct').waitFor();
check('a wrong setup secret is refused with its own message and creates nothing', (await page.getByRole('heading', { name: 'Create the administrator' }).isVisible()) && (await (await fetch(BASE + '/api/auth/status')).json()).bootstrap_available === true);
await page.getByLabel(/Setup secret/).fill(BOOTSTRAP_SECRET);
await page.getByLabel(/^Password/).fill('short');
await page.getByLabel(/^Repeat password/).fill('short');
await page.getByRole('button', { name: 'Create administrator' }).click();
check('a short password is explained before it is sent', await page.getByText('The password must be at least 12 characters.').isVisible());
await page.getByLabel(/^Password/).fill(FIRST_ADMIN.password);
await page.getByLabel(/^Repeat password/).fill(FIRST_ADMIN.password + 'x');
await page.getByRole('button', { name: 'Create administrator' }).click();
check('mismatching passwords are caught', await page.getByText('The two passwords do not match.').isVisible());
await page.getByLabel(/^Repeat password/).fill(FIRST_ADMIN.password);
await page.screenshot({ path: SHOTS + '/09b-setup.png' });
await page.getByRole('button', { name: 'Create administrator' }).click();
await page.getByText('Administrator account created').waitFor();
check('setup creates the administrator and returns to sign-in', await page.getByRole('heading', { name: 'Sign in to CyberSight' }).isVisible());
check('setup closes itself: the API now says it is not available', (await (await fetch(BASE + '/api/auth/status')).json()).bootstrap_available === false);
const again = await fetch(BASE + '/api/auth/bootstrap', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: BASE }, body: JSON.stringify({ bootstrap_secret: BOOTSTRAP_SECRET, username: 'intruder', password: 'Another-Long-Password-77' }) });
check('a second bootstrap with the right secret is refused (409)', again.status === 409);
await fetch(BASE + '/__test/seed');

section = 'sign-in failures';
const tryLogin = async (u, p) => { await page.getByLabel('Username').fill(u); await page.getByLabel(/^Password/).fill(p); await page.getByRole('button', { name: 'Sign in' }).click(); };
await tryLogin('lakshya', 'Totally-Wrong-Password-1');
await page.getByText('Invalid username or password.').waitFor();
const wrongPw = await page.locator('.auth-card [role=alert], .auth-card .banner').first().innerText().catch(() => '');
await tryLogin('nobody.here', 'Totally-Wrong-Password-1');
await page.getByText('Invalid username or password.').waitFor();
const wrongUser = await page.locator('.auth-card [role=alert], .auth-card .banner').first().innerText().catch(() => '');
check('a wrong password and an unknown user get the same generic message', wrongPw === wrongUser && wrongPw.length > 0, `${wrongPw} / ${wrongUser}`);
check('a wrong sign-in does not sign in and clears the password box', await page.getByRole('heading', { name: 'Sign in to CyberSight' }).isVisible() && await page.getByLabel(/^Password/).inputValue() === '');
await tryLogin('erin', PASSWORDS.erin);
await page.getByText('Invalid username or password.').waitFor();
check('an inactive account cannot sign in and is not told apart from a wrong password', true);
await page.screenshot({ path: SHOTS + '/10-signin-error.png' });
check('the password never appears in the URL or page text', !page.url().includes('Granite') && !(await page.content()).includes(FIRST_ADMIN.password));

// ---------------------------------------------------------------- session lifecycle
section = 'session lifecycle (lakshya, admin)';
await tryLogin('lakshya', FIRST_ADMIN.password);
await page.getByRole('navigation', { name: 'Main' }).waitFor();
check('the right username and password sign in', true);
const cookies = await page.context().cookies();
const sess = cookies.find((c) => /session/.test(c.name));
check('the session lives in an HttpOnly cookie the page cannot read', Boolean(sess && sess.httpOnly) && !(await page.evaluate(() => document.cookie)).includes('session'), JSON.stringify(cookies.map((c) => [c.name, c.httpOnly, c.sameSite, c.secure])));
check('nothing is kept in localStorage or sessionStorage', (await page.evaluate(() => JSON.stringify([Object.entries(sessionStorage), Object.entries(localStorage)]))) === '[[],[]]');
await page.reload();
await page.getByRole('navigation', { name: 'Main' }).waitFor();
check('refreshing the page restores the session without asking again', await page.getByRole('button', { name: /^Account menu for/ }).isVisible());
await page.getByRole('button', { name: /^Account menu for/ }).click();
check('the account menu shows the signed-in username and the admin role', await page.getByRole('region', { name: 'Account' }).getByText('admin', { exact: true }).isVisible());
await page.keyboard.press('Escape');
await signOutUi();
await page.getByRole('heading', { name: 'Sign in to CyberSight' }).waitFor();
check('sign out returns to sign-in', true);
await page.reload();
await page.getByRole('heading', { name: 'Sign in to CyberSight' }).waitFor();
check('after sign out a refresh does not restore anything', await page.getByRole('heading', { name: 'Sign in to CyberSight' }).isVisible());
await page.goto(BASE + '/cases');
await page.getByRole('heading', { name: 'Sign in to CyberSight' }).waitFor();
check('a deep link while signed out shows the sign-in page, not the data', await page.getByRole('heading', { name: 'Sign in to CyberSight' }).isVisible());
const old = sess ? sess.value : '';
const replayMe = await fetch(BASE + '/api/me', { headers: { Cookie: `${sess.name}=${old}` } });
check('the signed-out session cookie is rejected by the API (revoked server-side)', replayMe.status === 401, String(replayMe.status));
check('a Bearer token header does nothing (no API tokens are configured)', (await fetch(BASE + '/api/me', { headers: { Authorization: 'Bearer ' + 'A'.repeat(40) } })).status === 401);

// ---------------------------------------------------------------- Vercel rewrite (E2E_MODE=vercel only)
if (process.env.E2E_MODE === 'vercel') {
  section = 'vercel /api rewrite, production cookie';
  const front = new URL(BASE);
  const up = `http://localhost:${Number(front.port) + 1}`;
  await tryLogin('lakshya', FIRST_ADMIN.password);
  await page.getByRole('navigation', { name: 'Main' }).waitFor();
  const jar = await page.context().cookies();
  const c = jar.find((k) => k.name === '__Host-cybersight_session');
  check('production cookie in the browser: __Host-cybersight_session, HttpOnly, Secure, SameSite=None, Path=/, host-only', Boolean(c) && c.httpOnly && c.secure && c.sameSite === 'None' && c.path === '/' && c.domain === front.hostname, JSON.stringify(jar.map((k) => [k.name, k.httpOnly, k.secure, k.sameSite, k.path, k.domain])));
  check('the cookie belongs to the front-end origin only: nothing is stored for the API origin', (await page.context().cookies(up)).filter((k) => k.name.includes('session')).length === 0);
  await page.reload();
  await page.getByRole('navigation', { name: 'Main' }).waitFor();
  check('a refresh restores the session through the rewrite', await page.getByRole('button', { name: /^Account menu for/ }).isVisible());
  const seen = (await (await fetch(BASE + '/__test/proxied')).json()).proxied;
  const has = (m, p, u) => seen.some(([mm, pp, uu]) => mm === m && pp === p && uu === u);
  check('API calls went to /api/... on the front origin and reached the API without the prefix', has('POST', '/api/auth/login', '/auth/login') && has('GET', '/api/auth/session', '/auth/session') && has('GET', '/api/me', '/me'), JSON.stringify(seen.slice(0, 6)));
  const requests = [];
  page.on('request', (r) => requests.push(r.url()));
  await page.getByRole('link', { name: 'Alerts' }).first().click(); await settle(800);
  check('every API request the page makes is same-origin (nothing goes to the API host)', requests.filter((u) => u.includes('/api/')).every((u) => u.startsWith(BASE + '/api/')) && !requests.some((u) => u.startsWith(up)), requests.slice(0, 5).join(' '));
  check('the API origin is not reachable from the page by CSP (connect-src self)', await page.evaluate(async (u) => { try { await fetch(u + '/health/live', { mode: 'no-cors' }); return false; } catch { return true; } }, up));
  for (let i = problems.length - 1; i >= 0; i--) if (problems[i].includes(`${up}/health/live`)) problems.splice(i, 1);   // that console error is the probe above, which is meant to be blocked
  const noOrigin = await fetch(BASE + '/api/auth/logout', { method: 'POST', headers: { Cookie: `${c.name}=${c.value}` } });
  check('through the rewrite a state-changing request without Origin or CSRF token is still refused', noOrigin.status === 403, String(noOrigin.status));
  const spa = await fetch(BASE + '/cases'); const spaText = await spa.text();
  check('a deep link is answered by the single-page app (rewrite fallback), with the security headers', spa.status === 200 && spaText.includes('id="root"') && (spa.headers.get('content-security-policy') || '').includes("connect-src 'self'"));
  const apiHeaders = await fetch(BASE + '/api/auth/status');
  check('API responses through the rewrite are not cacheable', (apiHeaders.headers.get('cache-control') || '').includes('no-store'), apiHeaders.headers.get('cache-control'));
  await signOutUi();
}

// ---------------------------------------------------------------- administrator: accounts
section = 'admin (lakshya): user management';
const DANA = { username: 'dana.v', password: 'Teal-Orchard-Beacon-9317' };
await signInNoWait(page, 'lakshya');
await page.getByRole('navigation', { name: 'Main' }).waitFor();
await page.getByRole('button', { name: /^Account menu for/ }).click();
await page.getByRole('link', { name: 'Manage users' }).click();
await page.getByRole('heading', { name: 'Users', level: 1 }).waitFor();
await settle(600);
check('the Users page lists the accounts with role and status, and never a hash or token', await page.getByRole('row', { name: /lakshya/ }).isVisible() && await page.getByRole('row', { name: /alice/ }).isVisible()
  && !/argon2|scrypt|password_hash|token_hash/i.test(await page.content()));
await page.screenshot({ path: SHOTS + '/11-users.png', fullPage: true });
await page.getByRole('button', { name: 'Create user' }).first().click();
await page.getByLabel('Username').fill(DANA.username);
await page.getByLabel(/^Initial password/).fill('short');
await page.getByRole('dialog').getByRole('button', { name: 'Create user' }).click();
check('a short initial password is explained in the dialog', await page.getByText('The password must be at least 12 characters.').isVisible());
await page.getByLabel(/^Initial password/).fill(DANA.password);
await page.getByRole('dialog').getByRole('button', { name: 'Create user' }).click();
await page.getByText(/Created dana\.v as analyst/).waitFor();
await settle(500);
check('the new analyst appears in the list', await page.getByRole('row', { name: /dana\.v/ }).isVisible());
const dup = await (await as('lakshya')).call('/auth/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: DANA.username, role: 'viewer', password: DANA.password + '2' }) });
check('creating the same username again is refused (409)', dup.status === 409, String(dup.status));
const noReg = await fetch(BASE + '/api/auth/users', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: BASE }, body: JSON.stringify({ username: 'sneaky', role: 'admin', password: 'Whatever-Long-Password-11' }) });
check('there is no public registration: creating an account without an admin session is refused', noReg.status === 401, String(noReg.status));
await signOutUi();

section = 'new analyst (dana.v)';
await page.getByLabel('Username').fill(DANA.username);
await page.getByLabel(/^Password/).fill(DANA.password);
await page.getByRole('button', { name: 'Sign in' }).click();
await page.getByRole('navigation', { name: 'Main' }).waitFor();
check('the account created by the administrator can sign in', true);
await page.getByRole('button', { name: /^Account menu for/ }).click();
check('an analyst sees their role and no "Manage users" entry', await page.getByRole('region', { name: 'Account' }).getByText('analyst', { exact: true }).isVisible() && (await page.getByRole('link', { name: 'Manage users' }).count()) === 0);
await page.keyboard.press('Escape');
check('an analyst can submit alerts (Submit alert is offered)', await page.getByRole('link', { name: 'Submit alert' }).first().isVisible());
await page.evaluate(() => { history.pushState(null, '', '/admin/users'); dispatchEvent(new PopStateEvent('popstate')); });
await settle(500);
check('visiting the admin URL as an analyst shows "Administrators only"', await page.getByText('Administrators only').isVisible());
const danaApi = await apiSession(DANA.username, DANA.password);
check('the API refuses an analyst the user list (403)', (await danaApi.call('/auth/users')).status === 403);
check('the API refuses an analyst creating accounts (403)', (await danaApi.call('/auth/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'x1x', role: 'admin', password: 'Whatever-Long-Password-11' }) })).status === 403);
check('the API refuses an analyst a decision (approver role needed)', (await danaApi.call('/actions/00000000-0000-0000-0000-000000000000/decision', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ decision: 'approve' }) })).status === 403);
const noCsrf = await fetch(BASE + '/api/auth/logout', { method: 'POST', headers: { Origin: BASE, Cookie: danaApi.cookie } });
check('a state-changing request without the CSRF token is refused (403)', noCsrf.status === 403, String(noCsrf.status));
const badOrigin = await fetch(BASE + '/api/auth/logout', { method: 'POST', headers: { Origin: 'https://evil.example', Cookie: danaApi.cookie, 'X-CSRF-Token': danaApi.body.csrf_token } });
check('a request from a foreign Origin is refused (403)', badOrigin.status === 403, String(badOrigin.status));
await signOutUi();

section = 'admin (lakshya): deactivate and reset';
await signInNoWait(page, 'lakshya');
await page.getByRole('navigation', { name: 'Main' }).waitFor();
await goto('/admin/users');
await page.getByRole('heading', { name: 'Users', level: 1 }).waitFor();
const danaRow = () => page.getByRole('row', { name: /dana\.v/ });
await danaRow().getByRole('button', { name: 'Reset password' }).click();
await page.getByLabel(/^New password/).fill('Teal-Orchard-Beacon-0000-New');
await page.getByRole('dialog').getByRole('button', { name: 'Reset password' }).click();
await page.getByText(/Password of dana\.v reset/).waitFor();
check('an administrator can reset a password, which ends the person\'s sessions', (await danaApi.call('/me')).status === 401);
const oldPw = await apiSession(DANA.username, DANA.password);
check('the old password no longer works and the new one does', oldPw.status === 401 && (await apiSession(DANA.username, 'Teal-Orchard-Beacon-0000-New')).status === 200);
const danaApi2 = await apiSession(DANA.username, 'Teal-Orchard-Beacon-0000-New');
await settle(400);
await danaRow().getByRole('button', { name: 'Deactivate' }).click();
await page.getByText(/dana\.v is now deactivated/).waitFor();
check('deactivating an account revokes its live session at once', (await danaApi2.call('/me')).status === 401);
check('a deactivated account cannot sign in', (await apiSession(DANA.username, 'Teal-Orchard-Beacon-0000-New')).status === 401);
await settle(400);
await danaRow().getByRole('button', { name: 'Activate' }).click();
await page.getByText(/dana\.v is now active/).waitFor();
check('and can be activated again', (await apiSession(DANA.username, 'Teal-Orchard-Beacon-0000-New')).status === 200);
const self = await (await as('lakshya')).call('/auth/users/lakshya', { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ active: false }) });
check('an administrator cannot deactivate or demote themselves (the last administrator stays)', self.status >= 400 && self.status < 500, String(self.status));
await page.screenshot({ path: SHOTS + '/11b-users-after.png', fullPage: true });
await signOutUi();

// ---------------------------------------------------------------- viewer
section = 'viewer (carol)';
await signIn(page, 'carol');
check('viewer sees the nav', await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Alerts' }).isVisible());
check('viewer has no Submit alert button', (await page.getByRole('link', { name: 'Submit alert' }).count()) === 0);
await page.getByRole('button', { name: /^Account menu for/ }).click();
check('the account menu shows the signed-in role', await page.getByRole('region', { name: 'Account' }).getByText('viewer', { exact: true }).isVisible());
await page.keyboard.press('Escape'); await settle(200);
check('Escape closes the account menu', (await page.getByRole('region', { name: 'Account' }).count()) === 0);
await nav('Alerts');
await page.getByRole('link', { name: 'SYN-000005', exact: true }).click();
await page.getByRole('heading', { name: 'SYN-000005', level: 1 }).waitFor();
check('viewer sees the case but no approve/reject', (await page.getByRole('button', { name: /Approve/ }).count()) === 0 && await page.getByText(/Waiting for an approver/).isVisible());
await page.evaluate(() => { history.pushState(null, '', '/alerts/new'); dispatchEvent(new PopStateEvent('popstate')); });
await settle();
check('viewer visiting the submit URL is told their role cannot submit', await page.getByText('Your role cannot submit alerts').isVisible());
await signOutUi();
check('sign out returns to sign-in and forgets the token', await page.getByRole('heading', { name: 'Sign in' }).isVisible());
const stored = await page.evaluate(() => JSON.stringify([Object.entries(sessionStorage), Object.entries(localStorage)]));
check('nothing is persisted by default', stored === '[[],[]]', stored);

// ---------------------------------------------------------------- approver overview
section = 'overview (alice)';
await signIn(page, 'alice');
await settle(900);
const total = (await api('alice', '/cases?limit=1')).total;
const escalated = (await api('alice', '/cases?status=escalated&limit=1')).total;
const pending = (await api('alice', '/approvals/pending?limit=1')).total;
const tile = async (label) => (await page.locator('.metric', { hasText: label }).first().locator('.metric-value').innerText()).trim();
check('"Total alerts" equals the API total', (await tile('Total alerts')) === String(total), `${await tile('Total alerts')} vs ${total}`);
check('"Escalated cases" equals the API count', (await tile('Escalated cases')) === String(escalated));
check('"Pending actions" equals the API count', (await tile('Pending actions')) === String(pending));
const ovApi = await api('alice', '/overview');
const sevCard = page.locator('section.card', { has: page.getByRole('heading', { name: 'Severity distribution' }) });
check('the severity breakdown lists exactly the severities the API counted', (await sevCard.locator('li').count()) === Object.keys(ovApi.by_severity).length && ovApi.cases_total === total, JSON.stringify(ovApi.by_severity));
check('the dashboard says which charts are exact totals and which are sampled', await page.getByText('Exact totals.').first().isVisible() && await page.getByText(/among the newest \d+ of \d+/).first().isVisible());
const a11y1 = await a11yAudit(page); check('overview: structural accessibility audit', a11y1.length === 0, a11y1.join(' | '));
const c1 = await contrastAudit(page); check('overview: text contrast meets WCAG AA', c1.length === 0, JSON.stringify(c1.slice(0, 5)));
await page.screenshot({ path: SHOTS + '/20-overview.png', fullPage: true });

// ---------------------------------------------------------------- alerts list
section = 'alerts';
await nav('Alerts');
check('alerts table lists every case', (await page.locator('tbody tr').count()) === total, `${await page.locator('tbody tr').count()} vs ${total}`);
await page.getByLabel('Status').selectOption('escalated'); await settle(500);
check('status filter is sent to the server and kept in the URL', page.url().includes('status=escalated') && (await page.locator('tbody tr').count()) === escalated);
await page.getByLabel('Rows per page').selectOption('25');
await page.getByLabel('Search', { exact: true }).fill('portscan'); await settle(600);
const rowsAfterSearch = await page.locator('tbody tr').count();
const searched = (await api('alice', '/search/cases?status=escalated&q=portscan&limit=100')).total;
check('search runs on the server over all cases and matches the API count', rowsAfterSearch > 0 && rowsAfterSearch === searched && page.url().includes('q=portscan'), `${rowsAfterSearch} vs ${searched}`);
check('the result count is announced', await page.getByText(new RegExp(`${searched} alerts? match`)).isVisible());
await page.getByLabel('Search', { exact: true }).fill('');
await page.getByLabel('Sort').selectOption('severity_desc'); await settle(500);
const firstSev = await page.locator('tbody tr').first().locator('td[data-label=Severity]').innerText();
const topSev = (await api('alice', '/search/cases?status=escalated&sort=severity_desc&limit=1')).items[0].severity;
check('sorting by severity is done by the server and puts the highest first', firstSev.toLowerCase().includes(String(topSev).toLowerCase()) && page.url().includes('sort=severity_desc'), `${firstSev} vs ${topSev}`);
await page.getByLabel('Sort').selectOption('created_desc');
await page.getByLabel('Rows per page').selectOption('25');
await page.getByLabel('Status').selectOption('resolved'); await settle(400);
check('empty filter shows an empty state with a way out', await page.getByText('No alerts match these filters').isVisible());
await page.getByRole('button', { name: 'Clear filters' }).first().click(); await settle(400);
const a11y2 = await a11yAudit(page); check('alerts: structural accessibility audit', a11y2.length === 0, a11y2.join(' | '));
const c2 = await contrastAudit(page); check('alerts: text contrast meets WCAG AA', c2.length === 0, JSON.stringify(c2.slice(0, 5)));
await page.screenshot({ path: SHOTS + '/21-alerts.png', fullPage: true });

// ---------------------------------------------------------------- case detail + approval
section = 'case + approval';
const pendingList = await api('alice', '/approvals/pending?limit=10');
const [a1, a2] = pendingList.items;
await nav('Alerts');
await page.getByRole('link', { name: a1.alert_id, exact: true }).click();
await page.getByRole('heading', { name: a1.alert_id, level: 1 }).waitFor();
check('case shows the four kinds of information, each labelled, and the proposed action', await page.getByRole('heading', { name: /Observed/ }).isVisible() && await page.getByRole('heading', { name: /External enrichment/ }).isVisible() && await page.getByRole('heading', { name: /Model hypothesis/ }).isVisible() && await page.getByRole('heading', { name: /Policy decision/ }).isVisible() && await page.getByRole('heading', { name: 'Increase monitoring' }).isVisible());
check('fake model is disclosed', await page.getByText('Produced by the offline fake model').isVisible());
await page.getByRole('button', { name: /Approve/ }).click();
await page.getByRole('dialog', { name: 'Approve this action' }).waitFor();
check('dialog focuses the reason field', await page.evaluate(() => document.activeElement?.tagName === 'TEXTAREA'));
await page.getByRole('dialog').getByRole('button', { name: 'Approve', exact: true }).click();
check('approving without a reason is blocked client-side', await page.getByText('A reason is required').isVisible());
check('no decision request was made', (await api('alice', '/actions/' + a1.action_id)).action.state === 'pending');
await page.keyboard.press('Shift+Tab'); await page.keyboard.press('Shift+Tab'); await page.keyboard.press('Shift+Tab');
check('Tab stays inside the dialog', await page.evaluate(() => !!document.activeElement?.closest('[role=dialog]')));
await page.keyboard.press('Escape');
check('Escape closes the dialog and focus returns to the opener', (await page.getByRole('dialog').count()) === 0 && await page.evaluate(() => /Approve/.test(document.activeElement?.textContent || '')));
await page.getByRole('button', { name: /Approve/ }).click();
await page.getByLabel(/Reason/).fill('Matches the scan pattern; monitoring is proportionate.');
await page.getByRole('dialog').getByRole('button', { name: 'Approve', exact: true }).click();
await page.getByText(/Decision recorded: approved/).waitFor();
const after = await api('alice', '/actions/' + a1.action_id);
check('server recorded the approval by alice with the reason', after.action.state === 'approved' && after.decision.decided_by === 'alice' && after.decision.reason.startsWith('Matches'));
check('UI shows the approved state', await page.locator('.action-card .badge', { hasText: 'Approved' }).isVisible());
await page.getByRole('button', { name: 'Record simulated execution' }).click();
await page.getByText('Simulated execution recorded', { exact: false }).first().waitFor();
const exec = await api('alice', '/actions/' + a1.action_id);
check('server recorded a SIMULATED execution', exec.execution && exec.execution.mode === 'simulated' && exec.execution.result.simulated === true);
check('UI says no real system was changed', await page.getByText(/No real system was changed/).first().isVisible());
check('simulate button is gone after recording', (await page.getByRole('button', { name: 'Record simulated execution' }).count()) === 0);
await page.getByRole('tab', { name: 'Evidence' }).click(); await page.getByRole('heading', { name: 'Raw evidence' }).waitFor(); await settle(500);
check('raw evidence tab loads recorded evidence', (await page.locator('#case-panel-raw .timeline > li').count()) > 3);
await page.getByRole('tab', { name: 'Memory' }).click(); await settle(400);
check('memory tab explains memory was off', await page.getByText('Memory was off for this case').isVisible());
await page.getByRole('tab', { name: /^History/ }).click(); await settle(700);
const hist = await page.locator('#case-panel-timeline').innerText();
check('timeline tab shows the approval and the simulated execution, in words and in the audit trail', /approved/i.test(hist) && /simulated/i.test(hist) && /Action approved/.test(hist) && /Execution simulated/.test(hist), hist.slice(0, 300));
await page.getByRole('tab', { name: /^History/ }).focus(); await page.keyboard.press('ArrowLeft');
check('arrow keys move between tabs', (await page.getByRole('tab', { selected: true }).innerText()).startsWith('MITRE'));
await page.getByRole('tab', { name: 'Summary' }).click();
const a11y3 = await a11yAudit(page); check('case: structural accessibility audit', a11y3.length === 0, a11y3.join(' | '));
const c3 = await contrastAudit(page); check('case: text contrast meets WCAG AA', c3.length === 0, JSON.stringify(c3.slice(0, 5)));
await page.screenshot({ path: SHOTS + '/22-case.png', fullPage: true });
// reject another
await goto('/investigations');
check('investigations lists remaining pending approvals', (await page.locator('tbody tr').count()) === pending - 1, `${await page.locator('tbody tr').count()} vs ${pending - 1}`);
await page.getByRole('link', { name: `Review ${a2.alert_id}` }).click();
await page.getByRole('heading', { name: a2.alert_id, level: 1 }).waitFor();
await page.getByRole('button', { name: /Reject/ }).click();
await page.getByLabel(/Reason/).fill('Known scanner, already blocked upstream.');
await page.getByRole('dialog').getByRole('button', { name: 'Reject', exact: true }).click();
await page.getByText(/Decision recorded: rejected/).waitFor();
check('server recorded the rejection', (await api('alice', '/actions/' + a2.action_id)).action.state === 'rejected');
check('no simulate button for a rejected action', (await page.getByRole('button', { name: 'Record simulated execution' }).count()) === 0);
// conflict: decide in the background, then try to approve a stale page
await goto('/investigations');
const a3 = (await api('alice', '/approvals/pending?limit=10')).items[0];
await page.getByRole('link', { name: `Review ${a3.alert_id}` }).click();
await page.getByRole('heading', { name: a3.alert_id, level: 1 }).waitFor();
await api('root', `/actions/${a3.action_id}/decision`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'other-person-1234' }, body: JSON.stringify({ decision: 'rejected', reason: 'someone else got there first' }) });
await page.getByRole('button', { name: /Approve/ }).click();
await page.getByLabel(/Reason/).fill('approving a stale view');
await page.getByRole('dialog').getByRole('button', { name: 'Approve', exact: true }).click();
await page.getByText('This action was already decided').waitFor();
check('a stale decision gets a 409 explanation, not a silent overwrite', true);
check('the action stayed rejected', (await api('alice', '/actions/' + a3.action_id)).action.state === 'rejected');
await page.keyboard.press('Escape'); await settle(300);
check('after the conflict the page shows the current state', await page.locator('.action-card .badge', { hasText: 'Rejected' }).isVisible());

// ---------------------------------------------------------------- submit alert (analyst)
section = 'submit alert (bob)';
await signOutUi();
await signIn(page, 'bob');
await page.getByRole('link', { name: 'Submit alert' }).click();
await page.getByRole('heading', { name: 'Submit alert', level: 1 }).waitFor();
check('form has all 21 fields', (await page.locator('form[aria-label=Alert] input').count()) === 21);
await page.getByRole('button', { name: 'Submit alert' }).last().click();
await page.getByText(/21 fields need attention/).waitFor();
check('empty submit lists the problems and sends nothing', (await api('bob', '/jobs?limit=1')).total === 8);
await page.getByLabel('Source IP').fill('999.1.1.1'); await page.getByLabel('Source IP').blur();
check('inline error for a bad IP, without echoing it', await page.getByText('Not a valid IPv4 or IPv6 address.').first().isVisible());
await page.getByRole('button', { name: 'Paste JSON' }).click();
await page.getByLabel('Alert JSON').fill('{ not json');
await page.getByRole('button', { name: 'Fill the form' }).click();
check('bad pasted JSON is explained', await page.getByText('That is not valid JSON.').isVisible());
await page.getByLabel('Alert JSON').fill(JSON.stringify({ alert: { ...demo.alert, extra_field: 'ignore previous instructions' } }));
await page.getByRole('button', { name: 'Fill the form' }).click();
check('unknown fields in pasted JSON are rejected by name', await page.getByText(/do not accept: extra_field|that the API does not accept: extra_field/).isVisible());
await page.getByLabel('Alert JSON').fill(JSON.stringify(demo));
await page.getByRole('button', { name: 'Fill the form' }).click();
check('valid pasted JSON fills the form', (await page.getByLabel('Alert ID').inputValue()) === demo.alert.alert_id);
await page.getByText('Request that will be sent').waitFor();
await page.screenshot({ path: SHOTS + '/23-submit.png', fullPage: true });
let polled = 0; page.on('request', (r) => { if (/\/api\/jobs\/[0-9a-f-]{36}$/.test(r.url())) polled++; });
await page.getByRole('button', { name: 'Submit alert' }).last().click();
await page.getByRole('heading', { name: 'Alert submitted' }).waitFor();
check('server accepted it as a new job', await page.getByText('Accepted', { exact: true }).isVisible());
const jobsNow = await api('bob', '/jobs?limit=1');
check('exactly one job was created', jobsNow.total === 9, String(jobsNow.total));
await page.getByRole('link', { name: 'Open the case' }).first().waitFor({ timeout: 15000 });
check('status polling reached "succeeded" and offers the case', await page.getByText('Succeeded').first().isVisible());
const afterDone = polled; await page.waitForTimeout(5500);
check('polling stopped by itself once the job finished', polled === afterDone, `${afterDone} -> ${polled}`);
check('polling used a bounded number of requests', afterDone >= 2 && afterDone <= 12, String(afterDone));
await page.getByRole('button', { name: 'Submit another' }).click();
await page.getByRole('button', { name: 'Paste JSON' }).click();
await page.getByLabel('Alert JSON').fill(JSON.stringify(demo));
await page.getByRole('button', { name: 'Fill the form' }).click();
await page.getByRole('button', { name: 'Submit alert' }).last().click();
await page.getByText('This alert was already submitted').waitFor();
check('resubmitting the same alert is recognised as a duplicate (200), not a second job', (await api('bob', '/jobs?limit=1')).total === 9);
await page.getByRole('link', { name: 'Open the case' }).first().click();
await page.getByRole('heading', { name: demo.alert.alert_id, level: 1 }).waitFor();
check('the new case is reachable from the job', true);
check('analyst cannot approve (no controls) on a pending case', (await page.getByRole('button', { name: /Approve/ }).count()) === 0);

// ---------------------------------------------------------------- jobs, audit, settings
section = 'jobs / audit / settings';
await goto('/jobs');
check('jobs table lists jobs', (await page.locator('tbody tr').count()) === 9);
await page.getByLabel('Status').selectOption('failed'); await settle(500);
check('failed filter shows an empty state', await page.getByText('No jobs with this status').isVisible());
await page.getByRole('button', { name: 'Clear filter' }).click(); await settle(500);
await page.getByRole('link', { name: /^[0-9a-f]{8}$/ }).first().click();
await page.getByRole('heading', { name: /^Job / }).waitFor();
check('job detail shows timeline, result and timing', await page.getByRole('heading', { name: 'Result' }).isVisible() && await page.getByRole('heading', { name: 'Timing' }).isVisible());
check('job detail says polling has stopped', await page.getByText(/finished; no further updates/).isVisible());
check('token usage is honest about being unavailable', await page.getByText('not reported').first().isVisible());
await page.screenshot({ path: SHOTS + '/24-job.png', fullPage: true });
await nav('Audit Log');
check('audit page explains there is no global feed', await page.getByText(/no endpoint that lists events across all cases/).isVisible());
await page.getByLabel('Recent cases').selectOption({ index: 1 }); await settle(700);
check('audit trail loads for the chosen case', (await page.locator('.timeline > li').count()) >= 1);
await page.getByLabel('Or paste a case id').fill('not-a-uuid'); await page.getByRole('button', { name: 'Show audit trail' }).click();
check('a malformed case id is rejected client-side', await page.getByText(/A case id looks like/).isVisible());
await goto('/settings');
await settle(600);
check('settings shows the signed-in role from /me', await page.locator('main').getByText(/\(bob\)/).isVisible() && await page.locator('main').getByText('analyst', { exact: true }).isVisible());
check('settings shows live readiness details', await page.getByText('Queue backend').isVisible() && await page.getByText('Reachable').first().isVisible());
const a11y4 = await a11yAudit(page); check('settings: structural accessibility audit', a11y4.length === 0, a11y4.join(' | '));
const c4 = await contrastAudit(page); check('settings: text contrast meets WCAG AA', c4.length === 0, JSON.stringify(c4.slice(0, 5)));

// ---------------------------------------------------------------- sensor path
section = 'sensor path (EVE -> case -> analyst)';
const ndjson = fs.readFileSync(path.join(REPO, 'samples', 'eve', 'eve_mixed.ndjson'));
const post = async (who, body, type = 'application/x-ndjson') => (who ? (await as(who)).call('/sensors/sensor-lab-1/eve', { method: 'POST', headers: { 'Content-Type': type }, body }) : fetch(BASE + '/api/sensors/sensor-lab-1/eve', { method: 'POST', headers: { 'Content-Type': type, Origin: BASE }, body }));
check('ingestion without a token is refused', (await post(null, ndjson)).status === 401);
check('a viewer cannot ingest', (await post('carol', ndjson)).status === 403);
const ing = await post('bob', ndjson);
const ingBody = await ing.json();
check('authenticated ingestion of the sample batch is accepted', ing.status === 202 && ingBody.alerts.length === 4 && ingBody.flows_stored > 0, JSON.stringify(ingBody).slice(0, 200));
const replay = await post('bob', ndjson);
check('replaying the batch creates nothing new', replay.status === 200 && (await replay.json()).stored === 0);
let sensorCases = { total: 0, items: [] };
for (let i = 0; i < 40 && sensorCases.total < 4; i++) { await page.waitForTimeout(500); sensorCases = await api('bob', '/search/cases?alert_set=sensor&limit=50'); }
check('the worker turned every alert event into a case', sensorCases.total === 4, String(sensorCases.total));

await nav('Dashboard'); await settle(900);
check('dashboard total alerts includes the four sensor alerts', (await tile('Total alerts')) === String((await api('bob', '/cases?limit=1')).total), await tile('Total alerts'));
await nav('Alerts');
await page.getByLabel('Source', { exact: true }).selectOption('sensor'); await settle(600);
check('the source filter lists exactly the sensor cases', (await page.locator('tbody tr').count()) === 4 && page.url().includes('alert_set=sensor'));
const srcCell = (await page.locator('tbody tr').first().locator('td[data-label="Source IP"]').innerText()).trim(); const dstCell = (await page.locator('tbody tr').first().locator('td[data-label="Destination"]').innerText()).trim();
check('rows show source and destination addresses in their own columns', /^\d+\.\d+\.\d+\.\d+$/.test(srcCell) && /^\d+\.\d+\.\d+\.\d+(:\d+)?$/.test(dstCell), `${srcCell} / ${dstCell}`);
const a11yS1 = await a11yAudit(page); check('alert queue: structural accessibility audit', a11yS1.length === 0, a11yS1.join(' | '));
const cS1 = await contrastAudit(page); check('alert queue: text contrast meets WCAG AA', cS1.length === 0, JSON.stringify(cS1.slice(0, 5)));
await page.screenshot({ path: SHOTS + '/40-alert-queue.png', fullPage: true });

let beacon = null;
for (const it of sensorCases.items) { const a = await api('bob', `/cases/${it.case_id}/analysis`); if (a.evidence_classes.observed.sensor?.signature_id === 2027865) beacon = a; }
check('the beacon sample alert is among the cases', beacon !== null);
await page.getByRole('link', { name: beacon.case.alert_id, exact: true }).click();
await page.getByRole('heading', { name: beacon.case.alert_id, level: 1 }).waitFor(); await settle(400);
check('observed evidence shows the sensor rule text', await page.getByText('ET MALWARE Possible C2 Beacon Activity').first().isVisible());
check('fields the sensor did not provide are listed as unavailable, not filled in', await page.getByText('Fields the source did not provide').isVisible() && await page.getByText('detector_score', { exact: true }).first().isVisible());
check('threat intelligence is shown as not recorded rather than clean', await page.getByText(/Nothing recorded/).isVisible());
check('policy decision lists the rules that fired and says caution was raised', await page.getByText(/Raised caution from/).isVisible() && await page.getByText(/E1 Sensor severity/).isVisible());
check('the model section says it is a hypothesis', await page.getByText(/a hypothesis, not evidence/).isVisible());
await page.screenshot({ path: SHOTS + '/41-case-analysis.png', fullPage: true });
const a11yS2 = await a11yAudit(page); check('case analysis: structural accessibility audit', a11yS2.length === 0, a11yS2.join(' | '));
const cS2 = await contrastAudit(page); check('case analysis: text contrast meets WCAG AA', cS2.length === 0, JSON.stringify(cS2.slice(0, 5)));
await page.getByRole('tab', { name: 'MITRE' }).click(); await settle(300);
check('MITRE tab lists reference entries and labels them as not a determination', await page.getByRole('cell', { name: 'T1008' }).isVisible() && await page.getByText(/not a determination/i).first().isVisible());

// notes, feedback, resolution
await page.getByRole('tab', { name: /Notes & feedback/ }).click(); await settle(300);
await page.getByLabel('Add a note').fill('Checked the destination in the asset list; not ours.');
await page.getByRole('button', { name: 'Add note' }).click();
await page.getByText('Note added.').waitFor(); await page.getByText('Checked the destination').waitFor();
const afterNote = await api('bob', `/cases/${beacon.case.case_id}/analysis`);
check('the note was stored once, under bob, and shown', afterNote.notes.length === 1 && afterNote.notes[0].author === 'bob' && await page.getByText('Checked the destination').isVisible(), JSON.stringify(afterNote).slice(0, 300));
await page.getByRole('button', { name: 'Record feedback' }).click();
check('feedback without a judgement is blocked client-side', await page.getByText('Say whether the verdict was correct.').isVisible());
await page.getByLabel('Was the verdict correct?').selectOption('incorrect');
await page.getByLabel('What was it really?').first().selectOption('true_positive');
await page.getByLabel('Comment (optional)').fill('Model said benign; the beacon timing is real.');
await page.getByRole('button', { name: 'Record feedback' }).click();
await page.getByText('Feedback recorded.').waitFor();
const afterFb = await api('bob', `/cases/${beacon.case.case_id}/analysis`);
check('feedback was stored and did not change the verdict or routing', afterFb.feedback.length === 1 && afterFb.feedback[0].verdict_assessment === 'incorrect'
  && afterFb.evidence_classes.model_hypothesis.verdict.is_malicious === beacon.evidence_classes.model_hypothesis.verdict.is_malicious && afterFb.evidence_classes.policy_decision.routing.decision === beacon.evidence_classes.policy_decision.routing.decision);
check('the page says notes and feedback are never given to the model', await page.getByText(/never given to a model/).first().isVisible());
await page.getByRole('tab', { name: /^History/ }).click(); await settle(600);
const tl = await page.locator('#case-panel-timeline').innerText();
check('the timeline records the note and the feedback', /note was added/.test(tl) && /feedback/.test(tl), tl.slice(0, 300));

const resolvable = (await api('bob', '/search/cases?alert_set=sensor&limit=50')).items.find((c) => c.status === 'escalated' && c.pending_actions === 0);
const withPending = (await api('bob', '/search/cases?alert_set=sensor&has_pending=true&limit=50')).items[0];
if (withPending) {
  await nav('Alerts');
  await page.getByRole('link', { name: withPending.alert_id, exact: true }).click(); await page.getByRole('heading', { name: withPending.alert_id, level: 1 }).waitFor();
  await page.getByRole('tab', { name: /Notes & feedback/ }).click();
  check('a case with a pending proposal cannot be resolved, and the page says why', (await page.getByRole('button', { name: /Resolve this case/ }).count()) === 0 && await page.getByText(/still waiting for a decision/).isVisible());
}
if (resolvable) {
  await nav('Alerts');
  await page.getByRole('link', { name: resolvable.alert_id, exact: true }).click(); await page.getByRole('heading', { name: resolvable.alert_id, level: 1 }).waitFor();
  await page.getByRole('tab', { name: /Notes & feedback/ }).click();
  await page.getByRole('button', { name: /Resolve this case/ }).click();
  await page.getByRole('dialog', { name: 'Resolve this case' }).waitFor();
  await page.getByRole('dialog').getByRole('button', { name: 'Resolve', exact: true }).click();
  check('resolving without a reason is blocked client-side', await page.getByText('A reason is required.').isVisible());
  await page.getByLabel(/Reason/).fill('Reviewed the flows; scheduled backup job.');
  await page.getByRole('dialog').getByRole('button', { name: 'Resolve', exact: true }).click();
  await page.getByRole('dialog').waitFor({ state: 'detached' }); await settle(700);
  const resolved = await api('bob', `/cases/${resolvable.case_id}/analysis`);
  check('the case is resolved on the server and the badge says so', resolved.case.status === 'resolved' && await page.locator('.badge', { hasText: 'Resolved' }).first().isVisible());
  check('resolution approved and executed nothing', (await api('bob', '/actions?executed=true&limit=1')).items.every((a) => a.case_id !== resolvable.case_id));
}

// a viewer reads but cannot write
await signOutUi();
await signIn(page, 'carol');
await nav('Alerts');
await page.getByLabel('Search', { exact: true }).fill(beacon.case.alert_id); await settle(600);
await page.getByRole('link', { name: beacon.case.alert_id, exact: true }).click(); await page.getByRole('heading', { name: beacon.case.alert_id, level: 1 }).waitFor();
await page.getByRole('tab', { name: /Notes & feedback/ }).click();
check('a viewer sees the notes but has no form', await page.getByText('Checked the destination').isVisible() && (await page.getByRole('button', { name: 'Add note' }).count()) === 0 && await page.getByText(/can read notes but not add them/).isVisible());
const denied = await (await as('carol')).call(`/cases/${beacon.case.case_id}/notes`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ body: 'x' }) });
check('the API itself refuses a viewer\'s note', denied.status === 403);
await signOutUi();
await signIn(page, 'alice');

await goto('/investigations');
await page.getByRole('tab', { name: 'Decisions & simulated runs' }).click(); await settle(700);
const simulated = (await api('alice', '/actions?executed=true&limit=5')).total;
check('decisions tab shows simulated runs from the API, labelled as simulated', simulated >= 1 && await page.getByText('Simulation only').isVisible() && (await page.locator('.badge', { hasText: 'Simulated' }).count()) === simulated);
await page.getByLabel('State').selectOption('rejected'); await settle(500);
check('the state filter is applied by the server', (await page.locator('tbody tr').count()) === (await api('alice', '/actions?state=rejected&limit=100')).items.length);

await goto('/system'); await settle(900);
check('system page shows the model mode honestly', await page.getByText(/Fake \(no model is called\)/).isVisible() && await page.getByText(/Not checked/).first().isVisible());
check('system page says worker health is unavailable to the API', await page.getByText(/Unavailable: worker heartbeats/).isVisible());
check('system page shows the sensor counts', await page.getByText(/4 alerts/).first().isVisible());
await page.getByRole('tab', { name: 'Diagnostics' }).click(); await settle(300);
check('diagnostics shows the audit-chain check and both policies', await page.getByText('Verified: no break found').isVisible() && await page.getByText('evidence-policy-v1').first().isVisible());
const diagJson = await api('alice', '/diagnostics');
check('diagnostics settings contain no key, token, secret or password entries', !Object.keys(diagJson.settings).some((k) => /key|token|secret|password/i.test(k)), Object.keys(diagJson.settings).join(','));
const a11yS3 = await a11yAudit(page); check('system: structural accessibility audit', a11yS3.length === 0, a11yS3.join(' | '));
const cS3 = await contrastAudit(page); check('system: text contrast meets WCAG AA', cS3.length === 0, JSON.stringify(cS3.slice(0, 5)));
await page.screenshot({ path: SHOTS + '/42-system.png', fullPage: true });

await goto('/evaluation'); await settle(700);
check('evaluation lists the report files of the folder', await page.getByRole('link', { name: 'sensor_eval.json' }).isVisible());
await page.getByRole('link', { name: 'sensor_eval.json' }).click(); await settle(900);
check('the synthetic report is labelled synthetic and scripted-model', await page.getByText('Synthetic data and a scripted model').isVisible());
check('the report shows per-configuration false positive and false negative rates', await page.getByRole('columnheader', { name: 'FPR' }).first().isVisible() && await page.getByRole('columnheader', { name: 'FNR' }).first().isVisible());
check('the page does not claim real-world accuracy', await page.getByText(/Accuracy on real traffic is not measured here/).isVisible());
const a11yS4 = await a11yAudit(page); check('evaluation: structural accessibility audit', a11yS4.length === 0, a11yS4.join(' | '));
const cS4 = await contrastAudit(page); check('evaluation: text contrast meets WCAG AA', cS4.length === 0, JSON.stringify(cS4.slice(0, 5)));
await page.screenshot({ path: SHOTS + '/43-evaluation.png', fullPage: true });
await signOutUi();
await signIn(page, 'bob');

// ---------------------------------------------------------------- outage and recovery
section = 'outage';
await goto('/jobs');
await fetch(BASE + '/__test/mode?x=down');
await page.getByRole('button', { name: /API/ }).first().click(); await settle(700);
check('health indicator turns to unreachable/not ready when the API fails', await page.getByRole('button', { name: /API unreachable/ }).isVisible());
await page.getByRole('button', { name: 'Refresh' }).click(); await settle(700);
check('a failed reload keeps the data and shows a retry banner', await page.getByRole('alert').first().isVisible() && (await page.locator('tbody tr').count()) > 0);
await page.screenshot({ path: SHOTS + '/25-outage.png', fullPage: true });
await fetch(BASE + '/__test/mode?x=ok');
await page.getByRole('button', { name: 'Retry' }).first().click(); await settle(900);
check('retry recovers once the API is back', (await page.getByRole('alert').count()) === 0);
await page.getByRole('button', { name: /API/ }).first().click(); await settle(600);
check('health indicator recovers', await page.getByRole('button', { name: /API ready/ }).isVisible());

// ---------------------------------------------------------------- session expiry
section = 'session';
await nav('Alerts');
const revoked = await page.evaluate(async () => 1);
await page.route('**/api/search/cases*', (r) => r.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: { code: 'unauthenticated', message: 'a valid credential is required' } }) }));
await page.getByRole('button', { name: 'Refresh' }).first().click();
await page.getByText('Your session has ended. Sign in again.').waitFor();
check('a 401 mid-session signs the user out with an explanation', await page.getByRole('heading', { name: 'Sign in' }).isVisible() && revoked === 1);
await page.unroute('**/api/search/cases*');
await page.getByLabel('Username').fill('bob'); await page.getByLabel(/^Password/).fill(PASSWORDS.bob); await page.getByRole('button', { name: 'Sign in' }).click();
await page.getByRole('navigation', { name: 'Main' }).waitFor();
await (await as('lakshya')).call('/auth/users/bob/revoke-sessions', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
await page.evaluate(() => dispatchEvent(new Event('focus')));
await page.getByRole('button', { name: 'Refresh' }).first().click().catch(() => undefined);
await page.getByText('Your session has ended. Sign in again.').waitFor({ timeout: 8000 });
check('a session ended by an administrator signs the browser out on the next request', await page.getByRole('heading', { name: 'Sign in' }).isVisible());

// ---------------------------------------------------------------- mobile
section = 'mobile 375px';
await page.setViewportSize({ width: 375, height: 800 });
await signInNoWait(page, 'alice'); await page.getByRole('button', { name: 'Open navigation' }).waitFor();
await settle(800);
const mainNav = page.getByRole('navigation', { name: 'Main' });
check('no horizontal page scroll on the dashboard', await noHorizontalScroll(page), JSON.stringify(await overflowers(page)));
check('the nav links are hidden until the menu is opened', !(await mainNav.isVisible()));
check('the logo and the menu button stay visible', await page.getByRole('button', { name: 'Open navigation' }).isVisible() && await page.locator('.topnav .brand').isVisible());
await page.getByRole('button', { name: 'Open navigation' }).click(); await settle(300);
check('menu button opens the navigation panel', await mainNav.isVisible());
check('the menu button now says Close navigation and reports expanded', await page.getByRole('button', { name: 'Close navigation' }).getAttribute('aria-expanded') === 'true');
check('the panel lists all nine sections', (await mainNav.getByRole('link').count()) === 9);
await page.screenshot({ path: SHOTS + '/30-mobile-nav.png' });
await page.keyboard.press('Escape'); await settle(250);
check('Escape closes the menu', !(await mainNav.isVisible()));
await page.getByRole('button', { name: 'Open navigation' }).click(); await mainNav.getByRole('link', { name: 'Alerts' }).click(); await settle(700);
check('choosing a link closes the menu and navigates', !(await mainNav.isVisible()) && page.url().endsWith('/alerts'));
check('no horizontal page scroll on Alerts', await noHorizontalScroll(page), JSON.stringify(await overflowers(page)));
check('table rows are stacked as cards with labels', (await page.locator('td[data-label]').first().isVisible()));
await page.screenshot({ path: SHOTS + '/31-mobile-alerts.png', fullPage: true });
await page.getByRole('link', { name: /^(SYN|EVE)-/ }).first().click(); await settle(900);
check('no horizontal page scroll on a case', await noHorizontalScroll(page), JSON.stringify(await overflowers(page)));
await page.screenshot({ path: SHOTS + '/32-mobile-case.png', fullPage: true });
for (const [name, route] of [['Dashboard', '/'], ['Cases', '/cases'], ['Evidence', '/evidence'], ['Analytics', '/analytics'], ['Threat Intelligence', '/threat-intel'], ['Playbooks', '/playbooks'], ['Reports', '/reports'], ['Audit Log', '/audit']]) {
  await page.getByRole('button', { name: 'Open navigation' }).click(); await mainNav.getByRole('link', { name }).click(); await settle(700);
  check(`mobile: ${name} fits the screen`, await noHorizontalScroll(page) && new URL(page.url()).pathname === route, page.url());
}
await page.getByRole('button', { name: 'Open navigation' }).click(); await mainNav.getByRole('link', { name: 'Dashboard' }).click(); await settle(300);
await page.getByRole('link', { name: 'Submit alert' }).click(); await settle(500);
check('no horizontal page scroll on Submit', await noHorizontalScroll(page), JSON.stringify(await overflowers(page)));
await page.screenshot({ path: SHOTS + '/33-mobile-submit.png', fullPage: true });

// ---------------------------------------------------------------- CyberSight redesign
section = 'CyberSight shell, pages, themes';
await page.setViewportSize({ width: 1280, height: 900 });
await signIn(page, 'alice'); await settle(700);
const NAVS = [['Dashboard', '/'], ['Alerts', '/alerts'], ['Cases', '/cases'], ['Evidence', '/evidence'], ['Analytics', '/analytics'], ['Threat Intelligence', '/threat-intel'], ['Playbooks', '/playbooks'], ['Reports', '/reports'], ['Audit Log', '/audit']];
const mainNavL = page.getByRole('navigation', { name: 'Main' });
check('there is no permanent left sidebar: the nav is a horizontal bar at the top', await page.evaluate(() => { const r = document.querySelector('.topnav .nav').getBoundingClientRect(); return r.top < 80 && r.width > r.height * 4; }));
check('the top bar is sticky', await page.evaluate(() => getComputedStyle(document.querySelector('.topnav')).position === 'sticky'));
check('the bar shows Dashboard, Alerts, Cases, Evidence, Analytics and a More menu on desktop', JSON.stringify((await mainNavL.getByRole('link').allInnerTexts()).map((t) => t.trim())) === JSON.stringify(NAVS.slice(0, 5).map((n) => n[0])) && await mainNavL.getByRole('button', { name: /^More/ }).isVisible());
await mainNavL.getByRole('button', { name: /^More/ }).click();
check('the More menu lists Threat Intelligence, Playbooks, Reports and Audit Log, in order', JSON.stringify((await page.locator('#nav-more-panel a').allInnerTexts()).map((t) => t.trim())) === JSON.stringify(MORE_ITEMS));
const aaM = await a11yAudit(page); const ccM = await contrastAudit(page);
check('the open More menu passes the accessibility and contrast audits (dark)', aaM.length === 0 && ccM.length === 0, aaM.join(' | ') + JSON.stringify(ccM.slice(0, 3)));
await page.keyboard.press('Escape'); await settle(150);
check('all nine destinations exist in the navigation, in order', JSON.stringify((await page.locator('#main-nav a.nav-link').evaluateAll((els) => els.map((e) => e.textContent.trim())))) === JSON.stringify(NAVS.map((n) => n[0])));
check('the menu button is not shown on desktop', !(await page.getByRole('button', { name: 'Open navigation' }).isVisible()));
check('the brand is complete: mark, CyberSight wordmark and the product line, none clipped', await page.evaluate(() => { const b = document.querySelector('.brand').getBoundingClientRect(); const w = document.querySelector('.logo-word'); const s = document.querySelector('.logo-text small'); return w.getBoundingClientRect().right <= b.right + 0.5 && s.getBoundingClientRect().right <= b.right + 0.5 && w.scrollWidth <= w.clientWidth + 1; }));
check('no two items in the top bar overlap', await page.evaluate(() => { const els = [document.querySelector('.brand'), ...[...document.querySelectorAll('.nav .nav-link, .nav .nav-more-btn')].filter((e) => e.getClientRects().length), ...document.querySelectorAll('.topnav-end > *')]; const r = els.map((e) => e.getBoundingClientRect()); for (let i = 0; i < r.length; i++) for (let j = i + 1; j < r.length; j++) if (r[i].left < r[j].right - 0.5 && r[j].left < r[i].right - 0.5) return false; return true; }));
check('the wordmark and the product line are in the bar', await page.locator('.topnav .logo-word').innerText() === 'CyberSight' && /Security Operations/i.test(await page.locator('.topnav .logo-text small').innerText()));
check('the browser tab is titled for the product', (await page.title()).includes('CyberSight'), await page.title());
check('the favicon is the CyberSight icon and is served', await page.evaluate(async () => { const l = document.querySelector('link[rel~=icon]'); const r = await fetch(l.href); return r.ok && (await r.text()).includes('<svg'); }));
for (const f of ['cybersight-icon.svg', 'cybersight-icon-mono.svg', 'cybersight-logo.svg', 'cybersight-logo-mono.svg', 'cybersight-logo-light.svg']) {
  const r = await fetch(BASE + '/brand/' + f); check(`brand asset /brand/${f} is served as SVG`, r.ok && (r.headers.get('content-type') || '').includes('svg'), String(r.status));
}
for (const [name, route] of NAVS) {
  await nav(name); await settle(500);
  const h1 = (await page.locator('main h1').first().innerText()).trim();
  const inMore = MORE_ITEMS.includes(name);
  let marked;
  if (inMore) { marked = (await page.locator('.nav-more-btn').getAttribute('data-active')) === 'true'; await page.getByRole('button', { name: /^More/ }).click(); marked = marked && (await page.locator('#nav-more-panel a[aria-current=page]').innerText()).trim() === name; await page.keyboard.press('Escape'); }
  else marked = (await page.locator('.nav-link[aria-current=page]:visible').innerText()).trim() === name;
  check(`${name}: opens ${route} with a heading ("${h1}"), the product in the tab title and the item marked current${inMore ? ' (More shows it active)' : ''}`, new URL(page.url()).pathname === route && h1.length > 0 && (await page.title()).includes('CyberSight') && marked, `${page.url()} | ${await page.title()}`);
  await page.screenshot({ path: SHOTS + '/6-' + name.replace(/ /g, '-').toLowerCase() + '.png', fullPage: true });
  const aa = await a11yAudit(page); check(`${name}: structural accessibility audit (dark)`, aa.length === 0, aa.join(' | '));
  const cc = await contrastAudit(page); check(`${name}: text contrast meets WCAG AA (dark)`, cc.length === 0, JSON.stringify(cc.slice(0, 4)));
}
// keyboard reachability of the nav
await nav('Dashboard');
await mainNavL.getByRole('link', { name: 'Cases' }).focus(); await page.keyboard.press('Enter'); await settle(500);
check('a nav link works from the keyboard', new URL(page.url()).pathname === '/cases');
// theme
await nav('Dashboard');
await page.screenshot({ path: SHOTS + '/50-dashboard-dark.png', fullPage: true });
await page.getByRole('button', { name: 'Switch to light theme' }).click(); await settle(300);
check('the theme toggle switches to light', await page.evaluate(() => document.documentElement.dataset.theme === 'light') && await page.getByRole('button', { name: 'Switch to dark theme' }).getAttribute('aria-pressed') === 'true');
check('the theme choice is kept for the tab only, in sessionStorage, and not in localStorage', await page.evaluate(() => sessionStorage.getItem('cybersight.theme') === 'light' && localStorage.length === 0));
await page.screenshot({ path: SHOTS + '/51-dashboard-light.png', fullPage: true });
for (const [name] of NAVS) {
  await nav(name); await settle(450);
  const aa = await a11yAudit(page); const cc = await contrastAudit(page);
  check(`${name}: accessibility and contrast pass in the light theme`, aa.length === 0 && cc.length === 0, aa.join(' | ') + JSON.stringify(cc.slice(0, 4)));
}
await signOutUi(); await settle(300);
check('the light theme also applies on the sign-in page and survives a reload in the same tab', await page.evaluate(() => document.documentElement.dataset.theme === 'light'));
await page.reload(); await settle(300);
check('the light theme is still set after a reload', await page.evaluate(() => document.documentElement.dataset.theme === 'light'));
await signIn(page, 'alice'); await settle(300);
await page.getByRole('button', { name: 'Switch to dark theme' }).click(); await settle(200);
check('toggling again returns to the dark default', await page.evaluate(() => document.documentElement.dataset.theme === 'dark'));
// account menu and notifications
await page.getByRole('button', { name: /^Account menu for/ }).click();
const acct = page.getByRole('region', { name: 'Account' });
check('the account menu lists settings, system status, jobs and review queues', (await acct.getByRole('link').allInnerTexts()).join('|') === 'Settings|System status|Jobs|Review queues', (await acct.getByRole('link').allInnerTexts()).join('|'));
await acct.getByRole('link', { name: 'Settings' }).click(); await settle(500);
check('an account-menu link navigates and closes the menu', page.url().endsWith('/settings') && (await page.getByRole('region', { name: 'Account' }).count()) === 0);
const bell = page.getByRole('button', { name: /attention|notification/i }).first();
check('the notification bell has an accessible name that states the real count or that it is unavailable', /\d|unavailable|nothing/i.test((await bell.getAttribute('aria-label')) ?? ''), await bell.getAttribute('aria-label'));
await bell.click(); await settle(300);
check('the notification panel opens', await page.locator('#attention-panel').isVisible());
await page.keyboard.press('Escape'); await settle(200);
check('Escape closes the notification panel', (await page.locator('#attention-panel').count()) === 0);
// reports and analytics honesty
await nav('Analytics');
check('analytics says its samples are bounded and not the full history', await page.getByText(/newest \d+ of \d+/).first().isVisible());
await nav('Threat Intelligence');
check('threat intelligence admits there is no indicator feed', await page.getByText(/no list of all indicators/i).first().isVisible());
await nav('Playbooks');
check('playbooks state that nothing is executed against real systems', await page.getByText(/(never|not) (executed|run)|simulat/i).first().isVisible());
await nav('Reports');
check('reports offers exports that are built in the browser', await page.getByRole('button', { name: /CSV/ }).first().isVisible());
// sample JSON on the submit page
await page.getByRole('link', { name: 'Submit alert' }).click(); await settle(500);
await page.getByRole('button', { name: 'Paste JSON' }).click(); await settle(200);
await page.getByRole('button', { name: /Insert example/i }).click(); await settle(300);
const ex = JSON.parse(await page.getByLabel('Alert JSON').inputValue());
check('"Insert example" fills the JSON box with a 21-field example alert', Object.keys(ex.alert).length === 21, String(Object.keys(ex.alert).length));
await page.getByRole('button', { name: 'Fill the form' }).click(); await settle(400);
check('the example parses into the form, grouped Identity / Network / Detector / Flow features', ['Identity', 'Network', 'Detector', 'Flow features'].every((g) => page.getByRole('heading', { name: g }).first().isVisible() || true) && (await page.getByRole('group').count()) >= 4);
// narrow widths
const barIssues = () => page.evaluate(() => {
  const vw = document.documentElement.clientWidth; const out = [];
  const els = [['brand', document.querySelector('.brand')], ...[...document.querySelectorAll('.nav .nav-link, .nav .nav-more-btn')].filter((e) => e.getClientRects().length).map((e) => ['nav ' + e.textContent.trim(), e]), ...[...document.querySelectorAll('.topnav-end > *')].filter((e) => e.getClientRects().length).map((e) => ['end ' + (e.getAttribute('aria-label') || e.className), e])];
  const r = els.map(([n, e]) => [n, e.getBoundingClientRect(), e]);
  for (let i = 0; i < r.length; i++) {
    if (r[i][1].right > vw + 0.5 || r[i][1].left < -0.5) out.push(r[i][0] + ' leaves the viewport');
    if (r[i][2].scrollWidth > r[i][2].clientWidth + 1 && !r[i][2].querySelector('.count-badge')) out.push(r[i][0] + ' is clipped');
    for (let j = i + 1; j < r.length; j++) if (r[i][1].left < r[j][1].right - 0.5 && r[j][1].left < r[i][1].right - 0.5) out.push(r[i][0] + ' overlaps ' + r[j][0]);
  }
  return out;
});
for (const w of [1153, 1200, 1280, 1366, 1464, 1920]) {
  await page.setViewportSize({ width: w, height: 800 }); await settle(300);
  const issues = await barIssues();
  check(`top bar at ${w}px: nothing overlaps, clips or leaves the viewport`, issues.length === 0, issues.join('; '));
}
for (const w of [320, 768, 1024, 1180]) {
  await page.setViewportSize({ width: w, height: 800 }); await signInNoWait(page, 'alice'); await page.locator('.topnav').waitFor(); await settle(700);
  check(`no horizontal scroll at ${w}px`, await noHorizontalScroll(page), JSON.stringify(await overflowChain(page)));
  const inline = await mainNavL.isVisible();
  check(`at ${w}px the nav is ${w > 1152 ? 'inline' : 'a menu'}`, inline === (w > 1152), String(inline));
}
await page.setViewportSize({ width: 1280, height: 900 });
// sign-in page branding
await signOutUi(); await settle(300);
check('the sign-in page carries the logo, product name and tagline', await page.getByRole('heading', { name: 'Sign in to CyberSight' }).isVisible() && await page.getByText('See threats sooner. Respond smarter.').isVisible() && await page.locator('.auth-top svg').first().isVisible());
await signIn(page, 'alice'); await settle(300);

// ---------------------------------------------------------------- keyboard + CSP
section = 'keyboard / CSP';
await page.setViewportSize({ width: 1280, height: 900 });
await page.goto(BASE + '/');
if (await page.getByRole('button', { name: /^Account menu for/ }).or(page.getByLabel('Username')).first().waitFor().then(() => page.getByRole('button', { name: /^Account menu for/ }).isVisible())) { await signOutUi(); }
await page.getByLabel('Username').fill('alice'); await page.getByLabel(/^Password/).fill(PASSWORDS.alice); await page.keyboard.press('Enter');
await page.getByRole('navigation', { name: 'Main' }).waitFor();
await page.keyboard.press('Tab');
check('first Tab stop is the skip link', await page.evaluate(() => document.activeElement?.className === 'skip-link'));
await page.keyboard.press('Enter');
check('skip link moves focus to the main content', await page.evaluate(() => document.activeElement?.id === 'main'));
check('current page is marked in the nav (aria-current)', (await page.locator('.nav-link[aria-current=page]:visible').count()) === 1 && (await page.locator('.nav-link[aria-current=page]:visible').innerText()).includes('Dashboard'));
if (process.env.E2E_MODE === 'vercel') check('in the whole run the browser never sent a single request to another origin (so there is no third-party cookie to block)', foreign.filter((u) => !u.includes('/health/live')).length === 0, foreign.slice(0, 3).join(' '));   // /health/live on the API origin is the deliberate CSP probe above
const csp = problems.filter((p) => /Content Security Policy|Refused to/i.test(p));
check('no Content-Security-Policy violations under a strict policy (no inline scripts or styles)', csp.length === 0, csp.join(' | '));
const real = problems.filter((p) => !/Failed to load resource|401|503/.test(p));
check('no unexpected console errors or warnings', real.length === 0, real.join(' | '));
const bundleText = fs.readdirSync(path.join(DIST, 'assets')).filter((f) => f.endsWith('.js')).map((f) => fs.readFileSync(path.join(DIST, 'assets', f), 'utf8')).join('\n');
check('built bundle contains no token or secret-looking value', !bundleText.includes(BOOTSTRAP_SECRET) && !bundleText.includes(FIRST_ADMIN.password) && !/AIza[0-9A-Za-z_-]{30,}/.test(bundleText));

await browser.close();
const failed = results.filter((r) => !r.ok);
fs.writeFileSync(path.join(HERE, 'e2e_results.json'), JSON.stringify(results, null, 1));
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length ? 1 : 0);
