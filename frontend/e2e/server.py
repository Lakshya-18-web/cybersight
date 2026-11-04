"""End-to-end harness: the real Api5 handlers (in-memory stores, fake model) behind a stdlib HTTP server that behaves like the nginx container:
serves the built UI with a strict CSP, strips /api and forwards to Api5.dispatch (query strings included). A background worker triages queued jobs after a short delay so polling is observable.
Sign-in is the real thing: web authentication (username + password, server-side sessions, CSRF, Origin checks) on a scratch PostgreSQL database that carries the Week 4 + Week 5 migrations
(0003 included); the case data stays in the in-memory rig. No API token is configured, so a Bearer header does nothing here.
E2E_MODE=vercel puts the UI and the API on two different origins the way production does: a "Vercel" front (frontend/vercel.json applied by vercel_emulator.py) on PORT, proxying /api/* to a separate "Render" API
server on PORT+1 with the production cookie settings (__Host-, Secure, SameSite=None). The browser only ever talks to the front origin.
Needs the PG* variables and WEEK4_TEST_PG=1 (the same opt-in as the repository's PostgreSQL tests).
Test-only control: GET /__test/mode?x=down|ok makes every /api call answer 503; GET /__test/state dumps counts; POST /__test/seed creates the persona accounts (after the setup page has made the first administrator).
"""
import http.client, http.server, json, os, re, sys, threading, time, mimetypes
# Run from the repository root with PYTHONPATH=src:.  (use ; instead of : on Windows)
sys.path[:0] = ["src", "."]
from urllib.parse import urlsplit, parse_qsl
from tests import week5_support as W5
from week4.api import routes as w4
from week5.api import routes5
from week5.auth import passwords, service as auth_service, settings as auth_settings, web as auth_web
from week5.auth.store import PgAuthStore
from week4.db.repository import PgRepository

DIST = sys.argv[1]
PORT = int(sys.argv[2])
WORKER_DELAY = float(os.environ.get("WORKER_DELAY", "1.5"))
SEED = int(os.environ.get("SEED", "8"))

E2E_MODE = os.environ.get("E2E_MODE", "same")
UPSTREAM_PORT = PORT + 1
ORIGIN = "http://127.0.0.1:%d" % PORT
BOOTSTRAP_SECRET = "e2e-bootstrap-secret-" + "q" * 24
FIRST_ADMIN = "lakshya"
PERSONAS = {"alice": ("approver", "Violet-Harbor-Quartz-4271"), "bob": ("analyst", "Maple-Lantern-Orbit-5832"), "carol": ("viewer", "Cedar-Falcon-Prism-6943"),
            "root": ("admin", "Amber-Willow-Comet-7054"), "erin": ("approver", "Slate-Meadow-Ember-8165")}
DB_NAME = W5.PgHarness5.new_database()
pg = W5.W4.driver_for(DB_NAME)
pg_repo = PgRepository(pg)
rig = W5.ApiRig(sensor=True)        # sensor=True: the Week 5 repository layer (sensor events, search, notes, feedback) is what the new console pages read
rig.api.eval_report_dir = os.environ.get("E2E_REPORT_DIR", os.path.join("docs", "evalrun", "sensor_sample_run"))
for i in range(SEED):
    rig.post_alert(i, who="bob")
while rig.worker.run_once():
    pass
_memory_get_analyst = rig.repo.get_analyst
rig.repo.get_analyst = lambda aid: _memory_get_analyst(aid) or pg_repo.get_analyst(aid)   # accounts created through the Users page live in PostgreSQL
_cookie = {"WEEK5_COOKIE_SECURE": "1", "WEEK5_COOKIE_SAMESITE": "None"} if E2E_MODE == "vercel" else {"WEEK5_COOKIE_SECURE": "0", "WEEK5_COOKIE_SAMESITE": "Lax"}
web_settings = auth_settings.from_env({"WEEK5_PASSWORD_HASH": "scrypt", "WEEK5_ALLOWED_ORIGINS": ORIGIN, **_cookie,
                                        "WEEK5_BOOTSTRAP_TOKEN": BOOTSTRAP_SECRET, "WEEK5_LOGIN_LIMIT_IP": "1000", "WEEK5_LOGIN_LIMIT_SUBJECT": "1000", "WEEK5_TRUSTED_PROXY_HOPS": "1"})
hasher = passwords.PasswordHasher(scheme="scrypt", scrypt_n=4096)
web_service = auth_service.AuthService(PgAuthStore(pg), web_settings, hasher)
rig.api.web_auth = web_service
rig.api.auth = auth_web.SessionAuth(auth_web.NoBearer(), web_service)
mode = {"down": False}
table = [(r.method, re.compile("^" + re.sub(r"{(\w+)}", r"(?P<\1>[^/]+)", r.path) + "$"), r.name) for r in list(w4.ROUTES) + list(routes5.ROUTES5)]
CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

def worker_loop():
    while True:
        time.sleep(WORKER_DELAY)
        try:
            rig.worker.run_once()
        except Exception as e:  # keep the harness alive
            print("worker error", e, flush=True)
threading.Thread(target=worker_loop, daemon=True).start()

class H(http.server.BaseHTTPRequestHandler):
    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):      # the browser cancelled a request (polling, navigation); nothing to report
            pass
    def log_message(self, *a): pass
    def _send(self, status, body, headers=None, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(data)))
        if "Content-Security-Policy" not in (headers or {}): self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(data)
    def _api(self, method, path, query):
        if mode["down"]:
            return self._send(503, {"error": {"code": "store_unavailable", "message": "the case store is not available right now; nothing was changed by this request"}})
        for m, rx, name in table:
            hit = rx.match(path) if m == method else None
            if hit:
                raw = None; body = None
                if method in ("POST", "PATCH"):
                    n = int(self.headers.get("Content-Length") or 0); raw = self.rfile.read(n)
                    try: body = json.loads(raw) if raw else None
                    except ValueError: body = None
                headers = {k: v for k, v in self.headers.items() if k.lower() != auth_web.CLIENT_IP_HEADER.lower()}
                headers[auth_web.CLIENT_IP_HEADER] = self.client_address[0]
                res = rig.api.dispatch(name, headers, query, hit.groupdict(), body, raw) if name in routes5.BY_NAME5 else rig.api.dispatch(name, headers, query, hit.groupdict(), body)
                return self._send(res.status, res.body, res.headers)
        return self._send(404, {"error": {"code": "not_found", "message": "no such route"}})
    def _do(self, method):
        u = urlsplit(self.path); query = dict(parse_qsl(u.query))
        if u.path == "/__test/seed":
            for who, (role, pw) in PERSONAS.items():
                pg.run_script("INSERT INTO soc.analysts (analyst_id, display_name, role, active) VALUES ('%s', '%s', '%s', %s) ON CONFLICT DO NOTHING;" % (who, who.title(), role, "false" if who == "erin" else "true")
                              + "INSERT INTO soc.auth_credentials (analyst_id, username, password_hash, created_by) VALUES ('%s', '%s', '%s', 'e2e-seed') ON CONFLICT DO NOTHING;" % (who, who, hasher.hash(pw).replace("'", "''")))
            return self._send(200, {"seeded": sorted(PERSONAS)})
        if u.path.startswith("/__test/"):
            if u.path == "/__test/mode": mode["down"] = query.get("x") == "down"
            if u.path == "/__test/proxied": return self._send(200, {"proxied": globals().get("PROXIED", [])})
            return self._send(200, {"down": mode["down"], "jobs": rig.store.list_jobs()["total"], "cases": rig.repo.list_cases()["total"]})
        if u.path == "/api" or u.path.startswith("/api/"):
            return self._api(method, u.path[4:] or "/", query)
        if method != "GET": return self._send(405, {"error": {"code": "method"}})
        rel = u.path.lstrip("/")
        fp = os.path.join(DIST, rel)
        if rel and os.path.isfile(fp) and os.path.realpath(fp).startswith(os.path.realpath(DIST)):
            ctype = mimetypes.guess_type(fp)[0] or "application/octet-stream"
            if fp.endswith(".js"): ctype = "text/javascript"
            return self._send(200, open(fp, "rb").read(), ctype=ctype)
        return self._send(200, open(os.path.join(DIST, "index.html"), "rb").read(), ctype="text/html; charset=utf-8")
    def do_GET(self): self._do("GET")
    def do_POST(self): self._do("POST")
    def do_PATCH(self): self._do("PATCH")

class Upstream(H):
    """The 'Render' side: the API at the root, no UI, no /api prefix, no CSP."""
    def _do(self, method):
        u = urlsplit(self.path); query = dict(parse_qsl(u.query))
        return self._api(method, u.path or "/", query)


if E2E_MODE == "vercel":
    from vercel_emulator import VercelConfig
    VERCEL = VercelConfig(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vercel.json"))
    UPSTREAM_BASE = "https://cybersight-api.onrender.com"       # what vercel.json names; the emulator sends it to the local API server instead
    PROXIED = []                                                # (method, path, upstream path) for the scenario to inspect

    class Front(H):
        """The 'Vercel' side: serves the build, applies vercel.json, proxies /api/* to the API server. The browser never sees the API's origin."""
        def _proxy(self, method, target_path_query):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else None
            headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection", "content-length", "x-forwarded-for", auth_web.CLIENT_IP_HEADER.lower())}
            headers["X-Forwarded-For"] = self.client_address[0]
            conn = http.client.HTTPConnection("127.0.0.1", UPSTREAM_PORT, timeout=30)
            conn.request(method, target_path_query, body=body, headers=headers)
            r = conn.getresponse(); data = r.read()
            self.send_response(r.status)
            for k, v in r.getheaders():
                if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                    self.send_header(k, v)                       # Set-Cookie included: the cookie is stored against the FRONT origin
            self.send_header("Content-Length", str(len(data)))
            for k, v in VERCEL.headers_for(self.path.split("?")[0]).items():
                self.send_header(k, v)
            self.end_headers(); self.wfile.write(data)
            conn.close()
        def _do(self, method):
            u = urlsplit(self.path)
            if u.path.startswith("/__test/"):
                return H._do(self, method)           # seed / mode / state are shared control endpoints
            def exists(p):
                fp = os.path.join(DIST, p.lstrip("/"))
                return p != "/" and os.path.isfile(fp) and os.path.realpath(fp).startswith(os.path.realpath(DIST))
            kind, target = VERCEL.route(u.path, u.query, exists)
            if kind == "proxy":
                upstream = target[len(UPSTREAM_BASE):]
                PROXIED.append((method, u.path, upstream))
                return self._proxy(method, upstream)
            if kind == "file" or kind == "spa" or u.path == "/":
                if method != "GET": return self._send(405, {"error": {"code": "method"}})
                fp = os.path.join(DIST, u.path.lstrip("/")) if kind == "file" else os.path.join(DIST, "index.html")
                ctype = "text/html; charset=utf-8" if fp.endswith("index.html") else (mimetypes.guess_type(fp)[0] or "application/octet-stream")
                if fp.endswith(".js"): ctype = "text/javascript"
                body = open(fp, "rb").read()
                self.send_response(200); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body)))
                for k, v in VERCEL.headers_for(u.path).items(): self.send_header(k, v)
                self.end_headers(); self.wfile.write(body); return
            return self._send(404, {"error": {"code": "not_found"}})

    upstream_srv = http.server.ThreadingHTTPServer(("127.0.0.1", UPSTREAM_PORT), Upstream)
    threading.Thread(target=upstream_srv.serve_forever, daemon=True).start()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Front)
else:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H)
print("ready", PORT, flush=True)
import atexit
atexit.register(lambda: W5.PgHarness5.drop(DB_NAME))
try:
    srv.serve_forever()
except KeyboardInterrupt:
    pass
