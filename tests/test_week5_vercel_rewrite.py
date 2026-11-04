"""frontend/vercel.json: the /api rewrite that makes the session cookie first-party, checked offline with a small emulator of the rewrite rules (frontend/e2e/vercel_emulator.py).
This checks OUR configuration and routing. It does not prove Vercel's behaviour; docs/AUTHENTICATION.md lists the post-deployment checks for that."""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "frontend", "e2e"))
import vercel_emulator as ve  # noqa: E402

CONFIG = os.path.join(ROOT, "frontend", "vercel.json")
API = "https://cybersight-api.onrender.com"
BUILD_FILES = {"/index.html", "/favicon.svg", "/assets/main-abc123.js", "/assets/main-abc123.css", "/brand/cybersight-icon.svg"}


class VercelRewriteTests(unittest.TestCase):
    def setUp(self):
        self.cfg = ve.VercelConfig(CONFIG)
        self.route = lambda p, q="": self.cfg.route(p, q, BUILD_FILES.__contains__)

    def test_the_file_is_valid_json_with_the_expected_shape(self):
        with open(CONFIG, encoding="utf-8") as fh:
            raw = json.load(fh)
        self.assertEqual(raw["build"]["env"]["VITE_API_BASE_URL"], "/api")
        self.assertEqual(raw["rewrites"][0], {"source": "/api/:path*", "destination": API + "/:path*"})       # the proxy rule comes first
        self.assertNotIn("*", json.dumps(raw["headers"]).replace("/(.*)", "").replace(":path*", ""))        # no wildcard CORS header anywhere

    def test_api_calls_are_proxied_to_the_render_api_with_the_prefix_removed_and_the_query_kept(self):
        cases = {
            ("/api/auth/login", ""): API + "/auth/login",
            ("/api/auth/session", ""): API + "/auth/session",
            ("/api/auth/users/bob/revoke-sessions", ""): API + "/auth/users/bob/revoke-sessions",
            ("/api/cases", "limit=25&status=escalated"): API + "/cases?limit=25&status=escalated",
            ("/api/health/ready", ""): API + "/health/ready",
            ("/api/sensors/sensor-lab-1/eve", ""): API + "/sensors/sensor-lab-1/eve",
        }
        for (path, query), expected in cases.items():
            self.assertEqual(self.route(path, query), ("proxy", expected), path)

    def test_the_proxy_never_points_anywhere_else(self):
        for path in ("/api/x", "/api/auth/login", "/api/a/b/c"):
            kind, target = self.route(path)
            self.assertEqual(kind, "proxy")
            self.assertTrue(target.startswith(API + "/"))

    def test_console_pages_fall_back_to_the_single_page_app_and_never_reach_the_api(self):
        for path in ("/", "/cases", "/cases/1b2c", "/admin/users", "/setup", "/settings", "/alerts/new"):
            kind, target = self.route(path) if path != "/" else ("file", "/index.html")
            self.assertIn(kind, ("spa", "file"), path)
            if kind == "spa":
                self.assertEqual(target, "/index.html")

    def test_built_files_are_served_as_files_not_rewritten(self):
        for path in BUILD_FILES:
            self.assertEqual(self.route(path)[0], "file", path)

    def test_a_missing_asset_or_a_look_alike_path_is_not_sent_to_the_api(self):
        self.assertEqual(self.route("/apix/cases")[0], "spa")             # not under /api/
        self.assertEqual(self.route("/apiary")[0], "spa")

    def test_security_headers_match_the_nginx_container_and_the_api_is_never_cached(self):
        page = self.cfg.headers_for("/cases")
        csp = page["Content-Security-Policy"]
        self.assertIn("connect-src 'self'", csp)                       # everything the page calls is its own origin, which is the point of the rewrite
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("onrender.com", csp)
        self.assertEqual(page["X-Content-Type-Options"], "nosniff")
        self.assertEqual(page["X-Frame-Options"], "DENY")
        self.assertEqual(self.cfg.headers_for("/api/cases")["Cache-Control"], "no-store")
        with open(os.path.join(ROOT, "frontend", "nginx.conf"), encoding="utf-8") as fh:
            self.assertIn(csp, fh.read())                              # the same policy as the Docker front end

    def test_the_browser_side_default_is_the_same_origin_path(self):
        with open(os.path.join(ROOT, "frontend", "src", "config.ts"), encoding="utf-8") as fh:
            self.assertIn("?? '/api'", fh.read())
        with open(os.path.join(ROOT, "frontend", ".env.example"), encoding="utf-8") as fh:
            self.assertIn("VITE_API_BASE_URL=/api", fh.read())


if __name__ == "__main__":
    unittest.main()
