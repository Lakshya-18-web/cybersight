import { chromium } from 'playwright';
export { chromium };
export const BASE = process.env.BASE || 'http://127.0.0.1:18080';
export const TOKENS = { alice: 'A'.repeat(40), bob: 'B'.repeat(40), carol: 'C'.repeat(40), root: 'R'.repeat(40), erin: 'E'.repeat(40), ghost: 'G'.repeat(40) };

export async function launch(viewport = { width: 1280, height: 900 }) {
  const browser = await chromium.launch(process.env.E2E_CHROMIUM ? { executablePath: process.env.E2E_CHROMIUM, args: ['--no-sandbox'] } : {});
  const context = await browser.newContext({ viewport });
  const page = await context.newPage();
  const problems = [];
  page.on('console', (m) => { if (['error', 'warning'].includes(m.type())) problems.push(`console.${m.type()}: ${m.text()}`); });
  page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
  return { browser, context, page, problems };
}

export async function signIn(page, who) {
  await page.goto(BASE + '/');
  await page.getByLabel(/API token/).fill(TOKENS[who]);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('navigation', { name: 'Main' }).waitFor();
}

/** Colour-contrast audit: every visible text node against the nearest non-transparent background. Returns offenders below the WCAG AA ratio. */
export async function contrastAudit(page) {
  return page.evaluate(() => {
    const parse = (s) => {
      let m = s.match(/^rgba?\(([^)]+)\)/);
      if (m) { const p = m[1].split(/[ ,/]+/).filter(Boolean).map(Number); return { r: p[0], g: p[1], b: p[2], a: p[3] ?? 1 }; }
      m = s.match(/^color\(srgb ([^)]+)\)/);
      if (m) { const p = m[1].split(/[ /]+/).filter(Boolean).map(Number); return { r: p[0] * 255, g: p[1] * 255, b: p[2] * 255, a: p[3] ?? 1 }; }
      return null;
    };
    const lin = (c) => { c /= 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; };
    const lum = (c) => 0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b);
    const over = (f, b) => ({ r: f.r * f.a + b.r * (1 - f.a), g: f.g * f.a + b.g * (1 - f.a), b: f.b * f.a + b.b * (1 - f.a), a: 1 });
    const bgOf = (el) => {
      const stack = [];
      for (let e = el; e; e = e.parentElement) { const c = parse(getComputedStyle(e).backgroundColor); if (c && c.a > 0) { stack.push(c); if (c.a >= 1) break; } }
      let base = { r: 11, g: 16, b: 32, a: 1 };
      for (const c of stack.reverse()) base = over(c, base);
      return base;
    };
    const out = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const seen = new Set();
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const text = n.textContent.trim(); const el = n.parentElement;
      if (!text || !el || seen.has(el)) continue;
      const cs = getComputedStyle(el);
      if (cs.visibility === 'hidden' || cs.display === 'none' || el.closest('[hidden]') || el.closest('.visually-hidden')) continue;
      const r = el.getBoundingClientRect(); if (r.width === 0 || r.height === 0) continue;
      seen.add(el);
      const fg = parse(cs.color); if (!fg) continue;
      const bg = bgOf(el); const f = over(fg, bg);
      const L1 = lum(f), L2 = lum(bg); const ratio = (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05);
      const size = parseFloat(cs.fontSize); const bold = parseInt(cs.fontWeight, 10) >= 700;
      const need = size >= 24 || (size >= 18.66 && bold) ? 3 : 4.5;
      if (ratio < need) out.push({ text: text.slice(0, 40), ratio: Math.round(ratio * 100) / 100, need, tag: el.tagName, cls: el.className });
    }
    return out;
  });
}

/** Structural accessibility audit of the current page. */
export async function a11yAudit(page) {
  return page.evaluate(() => {
    const issues = [];
    const name = (el) => (el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') && el.getAttribute('aria-labelledby').split(' ').map((i) => document.getElementById(i)?.textContent).join(' ') || el.textContent || el.getAttribute('title') || '').trim();
    document.querySelectorAll('button, a[href], [role=button], [role=tab]').forEach((el) => { if (!el.closest('[hidden]') && !name(el)) issues.push('no accessible name: ' + el.outerHTML.slice(0, 90)); });
    document.querySelectorAll('input:not([type=hidden]), select, textarea').forEach((el) => {
      const labelled = el.id && document.querySelector(`label[for="${CSS.escape(el.id)}"]`) || el.closest('label') || el.getAttribute('aria-label') || el.getAttribute('aria-labelledby');
      if (!labelled) issues.push('unlabelled control: ' + el.outerHTML.slice(0, 90));
    });
    const h1 = document.querySelectorAll('h1'); if (h1.length !== 1) issues.push(`expected 1 h1, found ${h1.length}`);
    const levels = [...document.querySelectorAll('h1,h2,h3,h4')].map((h) => +h.tagName[1]);
    levels.forEach((l, i) => { if (i && l - levels[i - 1] > 1) issues.push(`heading level jumps h${levels[i - 1]} -> h${l}`); });
    if (!document.documentElement.lang) issues.push('missing html lang');
    if (!document.querySelector('main')) issues.push('no <main>');
    const ids = [...document.querySelectorAll('[id]')].map((e) => e.id); const dup = ids.filter((x, i) => ids.indexOf(x) !== i); if (dup.length) issues.push('duplicate ids: ' + [...new Set(dup)].join(','));
    document.querySelectorAll('table').forEach((t) => { if (!t.querySelector('th')) issues.push('table without headers'); });
    document.querySelectorAll('img').forEach((i) => { if (!i.hasAttribute('alt')) issues.push('img without alt'); });
    document.querySelectorAll('[aria-controls]').forEach((e) => { const t = e.getAttribute('aria-controls'); if (t && !document.getElementById(t)) issues.push('aria-controls target missing: ' + t); });
    return issues;
  });
}

export async function noHorizontalScroll(page) {
  return page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1);
}

/** Diagnostic for a failed overflow check: the elements that stick out past the right edge of the viewport. */
export async function overflowers(page) {
  return page.evaluate(() => {
    const w = document.documentElement.clientWidth;
    return [...document.querySelectorAll('body *')].filter((e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.right > w + 1; })
      .slice(0, 3).map((e) => `${e.tagName.toLowerCase()}.${String(e.className).slice(0, 40)} right=${Math.round(e.getBoundingClientRect().right)} w=${w}`);
  });
}

export async function overflowChain(page) {
  return page.evaluate(() => {
    const w = document.documentElement.clientWidth;
    const clipped = (e) => { for (let a = e.parentElement; a && a !== document.documentElement; a = a.parentElement) if (getComputedStyle(a).overflowX !== 'visible') return true; return false; };
    const d = [`doc ${document.documentElement.scrollWidth}/${w}`, ...[...document.querySelectorAll('body, body *')].filter((e) => e.scrollWidth > e.clientWidth + 1 && getComputedStyle(e).overflowX === 'visible').slice(0, 4).map((e) => `sw ${e.tagName.toLowerCase()}.${String(e.className).slice(0, 24)} ${e.scrollWidth}/${e.clientWidth}`)];
    return d.concat([...document.querySelectorAll('body *')].filter((e) => e.getBoundingClientRect().width > 0 && e.getBoundingClientRect().right > w + 1 && !clipped(e))
      .slice(0, 4).map((e) => `${e.tagName.toLowerCase()}.${String(e.className).slice(0, 30)} r=${Math.round(e.getBoundingClientRect().right)} w=${Math.round(e.getBoundingClientRect().width)} parent=${e.parentElement.tagName.toLowerCase()}.${String(e.parentElement.className).slice(0, 30)}`));
  });
}
