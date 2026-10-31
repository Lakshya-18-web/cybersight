"""End-to-end harness: the real Api5 handlers (in-memory stores, fake model) behind a stdlib HTTP server that behaves like the nginx container:
serves the built UI with a strict CSP, strips /api and forwards to Api5.dispatch (query strings included). A background worker triages queued jobs after a short delay so polling is observable.
Test-only control: GET /__test/mode?x=down|ok makes every /api call answer 503; GET /__test/state dumps counts.
"""
import http.server, json, os, re, sys, threading, time, mimetypes
# Run from the repository root with PYTHONPATH=src:.  (use ; instead of : on Windows)
sys.path[:0] = ["src", "."]
from urllib.parse import urlsplit, parse_qsl
from tests import week5_support as W5
from week4.api import routes as w4
from week5.api import routes5

DIST = sys.argv[1]
PORT = int(sys.argv[2])
WORKER_DELAY = float(os.environ.get("WORKER_DELAY", "1.5"))
SEED = int(os.environ.get("SEED", "8"))

rig = W5.ApiRig(sensor=True)        # sensor=True: the Week 5 repository layer (sensor events, search, notes, feedback) is what the new console pages read
rig.api.eval_report_dir = os.environ.get("E2E_REPORT_DIR", os.path.join("docs", "evalrun", "sensor_sample_run"))
for i in range(SEED):
    rig.post_alert(i, who="bob")
while rig.worker.run_once():
    pass
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
    def log_message(self, *a): pass
    def _send(self, status, body, headers=None, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy", CSP); self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(data)
    def _api(self, method, path, query):
        if mode["down"]:
            return self._send(503, {"error": {"code": "store_unavailable", "message": "the case store is not available right now; nothing was changed by this request"}})
        for m, rx, name in table:
            hit = rx.match(path) if m == method else None
            if hit:
                raw = None; body = None
                if method == "POST":
                    n = int(self.headers.get("Content-Length") or 0); raw = self.rfile.read(n)
                    try: body = json.loads(raw) if raw else None
                    except ValueError: body = None
                res = rig.api.dispatch(name, dict(self.headers), query, hit.groupdict(), body, raw) if name in routes5.BY_NAME5 else rig.api.dispatch(name, dict(self.headers), query, hit.groupdict(), body)
                return self._send(res.status, res.body, res.headers)
        return self._send(404, {"error": {"code": "not_found", "message": "no such route"}})
    def _do(self, method):
        u = urlsplit(self.path); query = dict(parse_qsl(u.query))
        if u.path.startswith("/__test/"):
            if u.path == "/__test/mode": mode["down"] = query.get("x") == "down"
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

srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H)
print("ready", PORT, flush=True)
srv.serve_forever()
