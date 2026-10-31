// Starts the API harness (the real Api5 request handlers on in-memory stores with the fake model, behind a stdlib server that behaves like the nginx container),
// then runs the browser scenario against the built UI in frontend/dist.
//   npm run build && npm run e2e
// Needs: the project's Python environment (E2E_PYTHON, default "python"), and Playwright with Chromium (npx playwright install chromium).
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const DIST = path.resolve(process.env.E2E_DIST || path.join(HERE, '..', 'dist'));
const PORT = process.env.E2E_PORT || '18080';
const python = process.env.E2E_PYTHON || 'python';

const server = spawn(python, ['-B', path.join(HERE, 'server.py'), DIST, PORT], {
  cwd: REPO,
  env: { ...process.env, PYTHONPATH: ['src', '.'].join(path.delimiter), PYTHONDONTWRITEBYTECODE: '1' },
  stdio: ['ignore', 'pipe', 'inherit'],
});
const stop = () => { if (!server.killed) server.kill(); };
process.on('exit', stop);
process.on('SIGINT', () => { stop(); process.exit(130); });

await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('the API harness did not start within 60 s')), 60_000);
  server.stdout.on('data', (chunk) => { if (String(chunk).includes('ready')) { clearTimeout(timer); resolve(); } });
  server.on('exit', (code) => reject(new Error(`the API harness exited early (code ${code}); run it from the repository root with the project's Python environment`)));
});
process.env.BASE = `http://127.0.0.1:${PORT}`;
process.env.E2E_DIST = DIST;
await import('./scenario.mjs');
