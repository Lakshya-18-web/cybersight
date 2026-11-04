"""The real FastAPI wrapper (create_app5) served by uvicorn over real HTTP, with sign-in on a scratch PostgreSQL: CORS preflight and credentialed responses, the production Set-Cookie header as it
leaves the server, PATCH bodies, the body-size limit, and the rule that a caller can never supply the address the rate limit uses.

Skipped unless fastapi and uvicorn are installed (requirements-week5.txt) AND the PostgreSQL opt-in is on (WEEK4_TEST_PG=1 and the PG* variables). Uses only the standard library as the HTTP client.
"""
import http.client
import json
import socket
import threading
import time
import unittest

from tests import week5_support as W5

try:
    import fastapi  # noqa: F401
    import uvicorn
    _APP_OK, _APP_WHY = True, ""
except ImportError as error_:                      # pragma: no cover - depends on the environment
    _APP_OK, _APP_WHY = False, "fastapi / uvicorn not installed (%s)" % error_
_PG_OK, _PG_WHY = W5.pg_enabled()

ORIGIN = "https://cybersight-nine.vercel.app"
STRONG = "Correct-Horse-Battery-9"
BOOT = "bootstrap-secret-" + "x" * 30


@unittest.skipUnless(_APP_OK and _PG_OK, _APP_WHY or _PG_WHY)
class RealAppOverHttp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_week5_auth import AuthRig
        from week5.api.app5 import create_app5
        cls.rig = AuthRig(WEEK5_ALLOWED_ORIGINS=ORIGIN, WEEK5_TRUSTED_PROXY_HOPS="2", WEEK5_LOGIN_LIMIT_IP="3", WEEK5_LOGIN_LIMIT_PAIR="50", WEEK5_LOGIN_LIMIT_SUBJECT="50")
        made = cls.rig.bootstrap(origin=ORIGIN)
        assert made.status in (200, 201), made.body
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]
        cls.server = uvicorn.Server(uvicorn.Config(create_app5(cls.rig.api), host="127.0.0.1", port=cls.port, log_level="warning"))
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        for _ in range(100):
            if cls.server.started:
                break
            time.sleep(0.05)
        assert cls.server.started, "uvicorn did not start"

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(10)
        cls.rig.drop()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        data = json.dumps(body).encode() if body is not None else None
        h = dict(headers or {})
        if data is not None:
            h.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=data, headers=h)
        r = conn.getresponse()
        raw = r.read()
        out = (r.status, {k.lower(): v for k, v in r.getheaders()}, r.getheaders(), raw)
        conn.close()
        return out

    def login(self, username="lakshya", password=STRONG, extra=None):
        status, headers, all_headers, raw = self.request("POST", "/auth/login", {"username": username, "password": password}, dict({"Origin": ORIGIN}, **(extra or {})))
        return status, headers, all_headers, (json.loads(raw) if raw else None)

    def test_preflight_allows_only_the_console_origin_with_credentials(self):
        ask = {"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type,x-csrf-token"}
        status, h, _, _ = self.request("OPTIONS", "/auth/login", headers=dict(ask, Origin=ORIGIN))
        self.assertEqual(status, 200)
        self.assertEqual(h["access-control-allow-origin"], ORIGIN)                 # the exact origin, never "*"
        self.assertEqual(h["access-control-allow-credentials"], "true")
        self.assertIn("x-csrf-token", h["access-control-allow-headers"].lower())
        self.assertIn("PATCH", h["access-control-allow-methods"])
        status, h, _, _ = self.request("OPTIONS", "/auth/login", headers=dict(ask, Origin="https://evil.example"))
        self.assertEqual(status, 400)
        self.assertNotIn("access-control-allow-origin", h)
        status, h, _, _ = self.request("OPTIONS", "/auth/login", headers=dict(ask, Origin="https://cybersight-nine.vercel.app.evil.example"))
        self.assertNotIn("access-control-allow-origin", h)

    def test_the_login_response_carries_the_production_cookie_exactly_once_and_credentialed_cors(self):
        status, h, all_headers, body = self.login()
        self.assertEqual(status, 200, body)
        cookies = [v for k, v in all_headers if k.lower() == "set-cookie"]
        self.assertEqual(len(cookies), 1)
        first, *attrs = [p.strip() for p in cookies[0].split(";")]
        self.assertTrue(first.startswith("__Host-cybersight_session="))
        self.assertEqual(sorted(a for a in attrs if "=" not in a), ["HttpOnly", "Secure"])
        pairs = dict(a.split("=", 1) for a in attrs if "=" in a)
        self.assertEqual((pairs["SameSite"], pairs["Path"]), ("None", "/"))
        self.assertNotIn("Domain", pairs)
        self.assertEqual(h["access-control-allow-origin"], ORIGIN)
        self.assertEqual(h["access-control-allow-credentials"], "true")
        self.assertEqual(h["cache-control"], "no-store")
        self.assertNotIn(first.split("=", 1)[1], json.dumps(body))

    def test_session_patch_and_csrf_over_http(self):
        status, _, all_headers, body = self.login()
        cookie = [v for k, v in all_headers if k.lower() == "set-cookie"][0].split(";")[0]
        csrf = body["csrf_token"]
        send = {"Cookie": cookie, "Origin": ORIGIN}
        self.assertEqual(self.request("GET", "/auth/session", headers=send)[0], 200)
        make = {"username": "bob.http", "role": "analyst", "password": "Maple-Lantern-Orbit-5832"}
        self.assertEqual(self.request("POST", "/auth/users", make, send)[0], 403)                       # no CSRF token
        self.assertEqual(self.request("POST", "/auth/users", make, dict(send, **{"X-CSRF-Token": csrf}))[0], 201)
        self.assertEqual(self.request("PATCH", "/auth/users/bob.http", {"role": "viewer"}, dict(send, **{"X-CSRF-Token": csrf}))[0], 200)   # the PATCH body reaches the handler
        rows = json.loads(self.request("GET", "/auth/users", headers=send)[3])["items"]
        self.assertEqual([r["role"] for r in rows if r["analyst_id"] == "bob.http"], ["viewer"])
        self.assertEqual(self.request("POST", "/auth/users", make, dict(send, **{"X-CSRF-Token": csrf, "Origin": "https://evil.example"}))[0], 403)

    def test_an_oversized_body_is_refused_before_it_is_read(self):
        status, _, _, raw = self.request("POST", "/auth/login", {"username": "a" * 100000, "password": "b"}, {"Origin": ORIGIN})
        self.assertEqual(status, 413, raw)

    def test_a_caller_cannot_choose_the_address_the_rate_limit_uses(self):
        """Three failures from one address are allowed (limit 3); the fourth is refused no matter what X-CS-Client-IP the caller invents."""
        codes = []
        for n in range(5):
            codes.append(self.login("nobody", "Wrong-Password-%d-xx" % n, {"X-CS-Client-IP": "198.51.100.%d" % n, "X-Forwarded-For": "203.0.113.77, 10.0.0.1"})[0])
        self.assertEqual(codes[:3], [401, 401, 401])
        self.assertEqual(codes[3:], [429, 429])

    def test_the_proxy_hop_count_picks_the_visitor_address_from_x_forwarded_for(self):
        """hops=2 (Vercel then Render): 'visitor, vercel' -> the visitor. A different visitor behind the same proxy has a separate allowance."""
        def fail(visitor, n):
            return self.login("someone-else", "Wrong-Password-%d-xx" % n, {"X-Forwarded-For": "%s, 10.9.9.9" % visitor})[0]
        self.assertEqual([fail("192.0.2.10", n) for n in range(4)], [401, 401, 401, 429])
        self.assertEqual(fail("192.0.2.11", 9), 401)


if __name__ == "__main__":
    unittest.main()
