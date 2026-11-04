"""Username + password sign-in (Week 5, migration 0003).

Two parts. The first needs no database: password policy and hashing, settings, cookie / origin / CSRF helpers, route table. The second runs against a real PostgreSQL scratch database and is OPT-IN
exactly like the other PostgreSQL tests (WEEK4_TEST_PG=1 and the PG* variables): migration, privileges, bootstrap, sign-in, sessions, CSRF and Origin, throttling, administration, role enforcement on
the existing Week 4/5 routes, and the whole flow. Password hashing in these tests uses scrypt with a small cost for speed; the Argon2id path runs only when argon2-cffi is installed (skipped otherwise).
"""
import json
import unittest

from tests import week4_support as W4
from tests import week5_support as W5
from week4.db.drivers import DbError
from week5 import fixtures
from week5.api import routes5
from week5 import settings as week5_settings
from week5.auth import passwords, service, settings as auth_settings, web
from week5.auth.routes_auth import AUTH_NAMES

ConfigError = week5_settings.ConfigError
ORIGIN = "https://console.test"
BOOT = "bootstrap-secret-" + "x" * 30
STRONG = "Correct-Horse-Battery-9"
FAST = dict(scheme="scrypt", scrypt_n=4096)


def env(**over):
    base = {"WEEK5_PASSWORD_HASH": "scrypt", "WEEK5_ALLOWED_ORIGINS": ORIGIN, "WEEK5_BOOTSTRAP_TOKEN": BOOT, "WEEK5_TRUSTED_PROXY_HOPS": "1"}
    base.update(over)
    return base


# =========================================================================================== no database
class PasswordPolicyTests(unittest.TestCase):
    def test_length_and_obvious_choices(self):
        for bad in ("short1!", "a" * 129, "password123456", "aaaaaaaaaaaaaa", "has\x00nul-char-123", 12345):
            with self.assertRaises(passwords.PasswordError, msg=str(bad)[:20]):
                passwords.check_password(bad)
        self.assertEqual(passwords.check_password(STRONG), STRONG)
        self.assertEqual(passwords.check_password("a long passphrase with spaces ok"), "a long passphrase with spaces ok")

    def test_password_may_not_contain_the_username(self):
        with self.assertRaises(passwords.PasswordError):
            passwords.check_password("my-lakshya-password-1", "lakshya")
        passwords.check_password("my-other-password-1", "lakshya")

    def test_username_format(self):
        self.assertEqual(passwords.check_username("  Lakshya "), "lakshya")
        for bad in ("ab", "-abc", "a b c", "ünï", "x" * 33, "a/b", "", None, 5):
            with self.assertRaises(passwords.PasswordError, msg=str(bad)):
                passwords.check_username(bad)

    def test_the_error_text_never_contains_the_password(self):
        try:
            passwords.check_password("password123456")
        except passwords.PasswordError as error:
            self.assertNotIn("password123456", str(error))


class HasherTests(unittest.TestCase):
    def setUp(self):
        self.h = passwords.PasswordHasher(**FAST)

    def test_round_trip_unique_salts_and_format(self):
        a, b = self.h.hash(STRONG), self.h.hash(STRONG)
        self.assertNotEqual(a, b)
        self.assertTrue(a.startswith("$scrypt$n=4096,r=8,p=1$"))
        self.assertNotIn(STRONG, a)
        self.assertTrue(self.h.verify(STRONG, a) and self.h.verify(STRONG, b))
        self.assertFalse(self.h.verify(STRONG + "x", a))
        self.assertFalse(self.h.verify("", a))

    def test_unicode_is_normalised(self):
        self.assertTrue(self.h.verify("Pässwörd-ünïcode-12", self.h.hash("Pässwörd-ünı̈code-12".replace("ı", "i"))))

    def test_malformed_or_unknown_hashes_do_not_verify_and_do_not_raise(self):
        for stored in ("", "plain", "$scrypt$", "$scrypt$n=1,r=1,p=1$AA$AA", "$scrypt$n=x$AA$AA", "$md5$abc", None, "$argon2id$garbage", "$scrypt$n=4096,r=8,p=1$!!$!!"):
            self.assertFalse(self.h.verify(STRONG, stored), str(stored))

    def test_parameters_are_read_from_the_hash_so_old_hashes_still_verify(self):
        old = passwords.PasswordHasher(scheme="scrypt", scrypt_n=4096).hash(STRONG)
        newer = passwords.PasswordHasher(scheme="scrypt", scrypt_n=8192)
        self.assertTrue(newer.verify(STRONG, old))
        self.assertTrue(newer.needs_rehash(old))
        self.assertFalse(newer.needs_rehash(newer.hash(STRONG)))

    def test_unknown_scheme_is_refused(self):
        with self.assertRaises(ValueError):
            passwords.PasswordHasher(scheme="md5")

    def test_argon2id_when_installed(self):
        try:
            import argon2  # noqa: F401
        except ImportError:
            self.skipTest("argon2-cffi is not installed here")
        h = passwords.PasswordHasher("argon2id")
        stored = h.hash(STRONG)
        self.assertTrue(stored.startswith("$argon2id$"))
        self.assertTrue(h.verify(STRONG, stored) and not h.verify("nope", stored))
        self.assertFalse(h.needs_rehash(stored))
        self.assertTrue(h.needs_rehash(self.h.hash(STRONG)))

    def test_argon2id_without_the_library_stops_at_start_up_with_a_clear_message(self):
        try:
            import argon2  # noqa: F401
        except ImportError:
            with self.assertRaises(RuntimeError) as ctx:
                passwords.PasswordHasher("argon2id")
            self.assertIn("argon2-cffi", str(ctx.exception))
        else:
            self.skipTest("argon2-cffi is installed here")


class SettingsTests(unittest.TestCase):
    def test_defaults_are_the_production_ones(self):
        s = auth_settings.from_env({})
        self.assertEqual((s.allowed_origins, s.cookie_secure, s.cookie_samesite, s.idle_seconds, s.absolute_seconds), (("https://cybersight-nine.vercel.app",), True, "None", 43200, 604800))
        self.assertEqual(s.cookie_name, "__Host-cybersight_session")
        self.assertEqual(s.password_scheme, "argon2id")
        self.assertFalse(s.bootstrap_enabled)

    def test_origins_must_be_exact(self):
        for bad in ("*", "https://*.vercel.app", "https://a.com/path", "http://evil.example", "ftp://a.com", "https://user@a.com", "a.com"):
            with self.assertRaises(auth_settings.ConfigError, msg=bad):
                auth_settings.from_env({"WEEK5_ALLOWED_ORIGINS": bad})
        s = auth_settings.from_env({"WEEK5_ALLOWED_ORIGINS": "https://A.com/, http://localhost:5173,http://127.0.0.1:5173"})
        self.assertEqual(s.allowed_origins, ("https://a.com", "http://localhost:5173", "http://127.0.0.1:5173"))

    def test_samesite_none_needs_secure(self):
        with self.assertRaises(auth_settings.ConfigError):
            auth_settings.from_env({"WEEK5_COOKIE_SECURE": "0"})
        s = auth_settings.from_env({"WEEK5_COOKIE_SECURE": "0", "WEEK5_COOKIE_SAMESITE": "Lax"})
        self.assertEqual(s.cookie_name, "cybersight_session")

    def test_bootstrap_token_must_be_long_and_only_its_digest_is_kept(self):
        with self.assertRaises(auth_settings.ConfigError):
            auth_settings.from_env({"WEEK5_BOOTSTRAP_TOKEN": "short"})
        s = auth_settings.from_env({"WEEK5_BOOTSTRAP_TOKEN": BOOT})
        self.assertTrue(s.bootstrap_enabled)
        self.assertNotIn(BOOT, repr(s))

    def test_bad_values_are_listed_together_without_secrets(self):
        with self.assertRaises(auth_settings.ConfigError) as ctx:
            auth_settings.from_env({"WEEK5_SESSION_IDLE_SECONDS": "x", "WEEK5_PASSWORD_HASH": "md5", "WEEK5_BOOTSTRAP_TOKEN": "tiny-secret-value"})
        text = str(ctx.exception)
        self.assertIn("WEEK5_SESSION_IDLE_SECONDS", text)
        self.assertIn("WEEK5_PASSWORD_HASH", text)
        self.assertNotIn("tiny-secret-value", text)

    def test_idle_cannot_exceed_absolute(self):
        with self.assertRaises(auth_settings.ConfigError):
            auth_settings.from_env({"WEEK5_SESSION_IDLE_SECONDS": "7200", "WEEK5_SESSION_ABSOLUTE_SECONDS": "3600"})

    def test_web_auth_switch(self):
        self.assertTrue(auth_settings.enabled({}))
        self.assertFalse(auth_settings.enabled({"WEEK5_WEB_AUTH": "0"}))


class ProductionCookieTests(unittest.TestCase):
    """The session cookie exactly as production emits it. The header is parsed, not searched for substrings, so a stray attribute, a missing one or a Domain would fail."""
    NAME = "__Host-cybersight_session"
    RENDER_ENV = {"WEEK5_ALLOWED_ORIGINS": "https://cybersight-nine.vercel.app", "WEEK5_BOOTSTRAP_TOKEN": "b" * 40}      # what the runbook sets on Render: nothing about cookies

    @staticmethod
    def parse(header):
        first, *attrs = [p.strip() for p in header.split(";")]
        name, _, value = first.partition("=")
        return name, value, attrs

    def settings(self, source):
        return auth_settings.from_env(source)

    def check_production_attributes(self, header, value=None):
        name, got, attrs = self.parse(header)
        self.assertEqual(name, self.NAME)
        if value is not None:
            self.assertEqual(got, value)
        flags = sorted(a for a in attrs if "=" not in a)
        pairs = dict(a.split("=", 1) for a in attrs if "=" in a)
        self.assertEqual(flags, ["HttpOnly", "Secure"])
        self.assertEqual(pairs["SameSite"], "None")
        self.assertEqual(pairs["Path"], "/")
        self.assertNotIn("Domain", pairs)                                  # a __Host- cookie must not carry one
        self.assertEqual(set(pairs), {"SameSite", "Path", "Max-Age"} | ({"Expires"} if "Expires" in pairs else set()))
        return pairs

    def test_default_settings_give_the_production_cookie(self):
        for source in ({}, self.RENDER_ENV):
            s = self.settings(source)
            self.assertEqual((s.cookie_name, s.cookie_secure, s.cookie_samesite), (self.NAME, True, "None"))

    def test_the_session_cookie_has_exactly_the_production_attributes(self):
        pairs = self.check_production_attributes(web.session_cookie(self.settings(self.RENDER_ENV), "T" * 43), "T" * 43)
        self.assertEqual(pairs["Max-Age"], "604800")

    def test_the_cookie_that_clears_a_session_has_the_same_attributes(self):
        """A browser only replaces or deletes a __Host- cookie when the replacement carries the same Secure/Path/no-Domain attributes."""
        pairs = self.check_production_attributes(web.clear_cookie(self.settings(self.RENDER_ENV)), "")
        self.assertEqual(pairs["Max-Age"], "0")
        self.assertTrue(pairs["Expires"].startswith("Thu, 01 Jan 1970"))

    def test_the_lifetime_follows_the_configured_absolute_limit(self):
        s = self.settings(dict(self.RENDER_ENV, WEEK5_SESSION_ABSOLUTE_SECONDS="86400", WEEK5_SESSION_IDLE_SECONDS="3600"))
        self.assertEqual(self.check_production_attributes(web.session_cookie(s, "x" * 43))["Max-Age"], "86400")

    def test_the_cookie_value_never_contains_characters_that_would_end_the_header(self):
        import secrets
        for _ in range(50):
            value = secrets.token_urlsafe(32)
            self.assertEqual(len(self.parse(web.session_cookie(self.settings({}), value))), 3)
            self.assertRegex(value, r"^[A-Za-z0-9_-]+$")

    def test_a_cookie_that_a_browser_would_drop_cannot_be_configured(self):
        with self.assertRaises(ConfigError):
            self.settings({"WEEK5_COOKIE_SECURE": "0"})                    # SameSite=None without Secure
        local = self.settings({"WEEK5_COOKIE_SECURE": "0", "WEEK5_COOKIE_SAMESITE": "Lax", "WEEK5_ALLOWED_ORIGINS": "http://localhost:5173"})
        self.assertFalse(local.cookie_name.startswith("__Host-"))          # __Host- needs Secure, so local http development never uses it
        self.assertNotIn("Secure", web.session_cookie(local, "x" * 43).split("; "))

    def test_a_browser_would_accept_the_cookie_by_the_prefix_rules(self):
        """The __Host- rules from the cookie spec, applied to what we send: Secure, Path=/, no Domain."""
        header = web.session_cookie(self.settings({}), "x" * 43)
        self.assertTrue(header.startswith("__Host-"))
        lowered = [a.lower() for a in header.split("; ")]
        self.assertIn("secure", lowered)
        self.assertIn("path=/", lowered)
        self.assertFalse(any(a.startswith("domain") for a in lowered))


class WebHelperTests(unittest.TestCase):
    def setUp(self):
        self.s = auth_settings.from_env(env())

    def test_cookie_attributes(self):
        c = web.session_cookie(self.s, "T" * 43)
        for part in ("__Host-cybersight_session=" + "T" * 43, "HttpOnly", "Secure", "SameSite=None", "Path=/", "Max-Age=604800"):
            self.assertIn(part, c)
        self.assertNotIn("Domain", c)
        gone = web.clear_cookie(self.s)
        self.assertIn("Max-Age=0", gone)
        self.assertIn("HttpOnly", gone)

    def test_cookie_parsing(self):
        self.assertEqual(web.cookie_value({"cookie": "a=1; __Host-cybersight_session=abc; b=2"}, "__Host-cybersight_session"), "abc")
        self.assertIsNone(web.cookie_value({"cookie": "a=1"}, "__Host-cybersight_session"))
        self.assertIsNone(web.cookie_value({"cookie": "\x00\xff=;;;"}, "x"))
        self.assertIsNone(web.cookie_value({"cookie": "a=" + "b" * 9000}, "a"))
        self.assertIsNone(web.cookie_value({}, "a"))

    def test_origin_check_is_exact(self):
        self.assertTrue(web.origin_allowed(self.s, {"origin": ORIGIN}))
        self.assertTrue(web.origin_allowed(self.s, {"origin": ORIGIN.upper()}))
        for bad in (None, "", "null", "https://evil.test", ORIGIN + ".evil.test", "http://console.test", ORIGIN + "/", "https://sub.console.test"):
            self.assertFalse(web.origin_allowed(self.s, {"origin": bad} if bad is not None else {}), str(bad))

    def test_csrf_token_is_bound_to_the_session(self):
        t1, t2 = "A" * 43, "B" * 43
        self.assertTrue(web.csrf_ok(t1, {"x-csrf-token": service.csrf_token(t1)}))
        self.assertFalse(web.csrf_ok(t1, {"x-csrf-token": service.csrf_token(t2)}))
        self.assertFalse(web.csrf_ok(t1, {}))
        self.assertFalse(web.csrf_ok(t1, {"x-csrf-token": ""}))
        self.assertFalse(web.csrf_ok("", {"x-csrf-token": "x"}))
        self.assertNotEqual(service.csrf_token(t1), t1)

    def test_client_address_comes_from_the_trusted_end_of_the_header(self):
        self.assertEqual(web.client_ip("6.6.6.6, 203.0.113.7", "10.0.0.1", 1), "203.0.113.7")
        self.assertEqual(web.client_ip("6.6.6.6, 203.0.113.7, 10.1.1.1", "10.0.0.1", 2), "203.0.113.7")
        self.assertEqual(web.client_ip("203.0.113.7", "10.0.0.1", 0), "10.0.0.1")
        self.assertEqual(web.client_ip(None, "10.0.0.1", 1), "10.0.0.1")
        self.assertEqual(web.client_ip("203.0.113.7", "10.0.0.1", 3), "10.0.0.1")
        self.assertEqual(web.client_ip(None, None, 1), "unknown")


class RouteTableTests(unittest.TestCase):
    def test_the_auth_routes_are_in_the_table_with_the_right_roles(self):
        by = routes5.BY_NAME5
        self.assertEqual(AUTH_NAMES, {n for n in by if n.startswith("auth_")})
        self.assertEqual(len(AUTH_NAMES), 11)
        for public in ("auth_login", "auth_logout", "auth_status", "auth_bootstrap"):
            self.assertIsNone(by[public].role)
        for n in ("auth_session", "auth_change_password"):
            self.assertEqual(by[n].role, "session")
        for n in ("auth_users", "auth_create_user", "auth_update_user", "auth_reset_password", "auth_revoke_sessions"):
            self.assertEqual(by[n].role, "admin")

    def test_the_existing_routes_are_unchanged(self):
        for n in ("submit_alert", "get_job", "get_me", "health_live", "health_ready"):
            self.assertIn(n, routes5.BY_NAME5)


# =========================================================================================== PostgreSQL
_PG_OK, _PG_WHY = W5.pg_enabled()


class AuthRig:
    """An Api5 on a scratch PostgreSQL database with web sign-in on and the legacy bearer tokens still configured."""

    def __init__(self, **env_over):
        from week4.db.repository import PgRepository
        from week5 import jobs
        from week5.auth.store import PgAuthStore
        self.name = W5.PgHarness5.new_database()
        self.driver = W4.driver_for(self.name)
        self.rig = W5.ApiRig(store=jobs.PgJobStore(self.driver), repo=PgRepository(self.driver))
        self.api = self.rig.api
        self.settings = auth_settings.from_env(env(**env_over))
        self.web = service.AuthService(PgAuthStore(self.driver), self.settings, passwords.PasswordHasher(**FAST))
        self.api.web_auth = self.web
        self.api.auth = web.SessionAuth(self.api.auth, self.web)
        self.cookie_name = self.settings.cookie_name

    def drop(self):
        W5.PgHarness5.drop(self.name)

    def call(self, name, body=None, token=None, csrf="auto", origin=ORIGIN, ip="203.0.113.5", path=None, bearer=None, extra=None, query=None):
        headers = {web.CLIENT_IP_HEADER: ip, "User-Agent": "unit-test"}
        if origin:
            headers["Origin"] = origin
        if token:
            headers["Cookie"] = "%s=%s" % (self.cookie_name, token)
            if csrf == "auto":
                csrf = service.csrf_token(token)
        if csrf and csrf != "auto":
            headers["X-CSRF-Token"] = csrf
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        headers.update(extra or {})
        raw = None
        if body is not None:
            raw = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        return self.api.dispatch(name, headers, query, path, None, raw)

    @staticmethod
    def token_of(response):
        cookie = response.headers.get("Set-Cookie", "")
        return cookie.split(";")[0].split("=", 1)[1] if "=" in cookie else None

    def bootstrap(self, username="lakshya", password=STRONG, secret=BOOT, **kw):
        return self.call("auth_bootstrap", {"bootstrap_secret": secret, "username": username, "password": password}, **kw)

    def login(self, username, password, **kw):
        r = self.call("auth_login", {"username": username, "password": password}, **kw)
        return r, self.token_of(r)

    def admin_token(self):
        self.bootstrap()
        r, tok = self.login("lakshya", STRONG)
        assert r.status == 200, r.body
        return tok

    def make_user(self, admin_token, username, role, password=STRONG + "-" + "u"):
        r = self.call("auth_create_user", {"username": username, "role": role, "password": password}, token=admin_token)
        assert r.status == 201, r.body
        return password

    def sql(self, text):
        return self.driver.query(text)

    def scalar(self, text):
        return self.driver.scalar(text)


@unittest.skipUnless(_PG_OK, _PG_WHY)
class AuthOnPostgres(unittest.TestCase):
    def setUp(self):
        self.t = AuthRig()
        self.addCleanup(self.t.drop)

    # ---------------------------------------------------------------- migration and privileges
    def test_migration_is_recorded_and_the_tables_exist(self):
        self.assertEqual(self.t.scalar("SELECT count(*) FROM soc.schema_migrations_week5 WHERE version = '0003'"), "1")
        for table in ("auth_credentials", "web_sessions", "auth_attempts"):
            self.assertEqual(self.t.scalar("SELECT to_regclass('soc.%s') IS NOT NULL" % table), "t")

    def test_the_api_role_has_no_table_privilege_and_only_execute_on_the_functions(self):
        for table in ("auth_credentials", "web_sessions", "auth_attempts"):
            for priv in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                self.assertEqual(self.t.scalar("SELECT has_table_privilege('soc_api', 'soc.%s', '%s')" % (table, priv)), "f", (table, priv))
            self.assertEqual(self.t.scalar("SELECT has_table_privilege('public', 'soc.%s', 'SELECT')" % table), "f")
        fns = self.t.sql("SELECT p.oid::regprocedure::text, p.prosecdef, has_function_privilege('soc_api', p.oid, 'EXECUTE'), has_function_privilege('public', p.oid, 'EXECUTE'), "
                         "array_to_string(p.proconfig, ',') FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'soc' AND p.proname LIKE 'auth\\_%'")
        self.assertGreaterEqual(len(fns), 15)
        for name, definer, api_ok, public_ok, config in fns:
            self.assertEqual((definer, api_ok, public_ok), ("t", "t", "f"), name)
            self.assertIn("search_path=soc, pg_temp", config, name)

    def test_the_credential_table_refuses_a_bad_hash_and_a_bad_username(self):
        self.t.driver.run_script("INSERT INTO soc.analysts (analyst_id, role) VALUES ('zed', 'viewer'), ('Up', 'viewer')")
        for bad in ("INSERT INTO soc.auth_credentials (analyst_id, username, password_hash, created_by) VALUES ('zed', 'zed', 'plaintext-password-value-here-1234567890', 'x')",
                    "INSERT INTO soc.auth_credentials (analyst_id, username, password_hash, created_by) VALUES ('Up', 'up', '$scrypt$n=1$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$bbbbbbbb', 'x')"):
            with self.assertRaises(DbError):
                self.t.driver.run_script(bad)

    def test_the_rollback_removes_everything_and_the_migration_can_be_applied_again(self):
        import os
        from week5.db import migrate
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "src/week5/db/rollback/0003_auth_sessions_rollback.sql"), encoding="utf-8") as fh:
            self.t.driver.run_script(fh.read())
        self.assertEqual(self.t.scalar("SELECT to_regclass('soc.web_sessions') IS NULL"), "t")
        self.assertEqual(self.t.scalar("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'soc' AND p.proname LIKE 'auth\\_%'"), "0")
        self.assertEqual(self.t.scalar("SELECT count(*) FROM soc.schema_migrations_week5 WHERE version = '0003'"), "0")
        migrate.apply(self.t.driver, say=lambda *_: None)
        self.assertEqual(self.t.scalar("SELECT to_regclass('soc.web_sessions') IS NOT NULL"), "t")
        self.assertEqual(migrate.plan(self.t.driver)[2], [])

    # ---------------------------------------------------------------- bootstrap
    def test_status_before_and_after_bootstrap(self):
        self.assertEqual(self.t.call("auth_status").body, {"web_auth": True, "bootstrap_available": True})
        self.assertEqual(self.t.bootstrap().status, 201)
        self.assertEqual(self.t.call("auth_status").body["bootstrap_available"], False)

    def test_bootstrap_creates_one_admin_once_and_never_again(self):
        r = self.t.bootstrap()
        self.assertEqual((r.status, r.body), (201, {"username": "lakshya", "role": "admin"}))
        again = self.t.bootstrap(username="intruder", password=STRONG + "2")
        self.assertEqual((again.status, again.body["error"]["code"]), (409, "already_bootstrapped"))
        self.assertEqual(self.t.scalar("SELECT count(*) FROM soc.analysts WHERE role = 'admin' AND analyst_id = 'intruder'"), "0")
        self.assertEqual(self.t.scalar("SELECT role FROM soc.analysts WHERE analyst_id = 'lakshya'"), "admin")

    def test_bootstrap_with_a_wrong_secret_is_refused_and_throttled(self):
        for _ in range(5):
            r = self.t.bootstrap(secret="w" * 40)
            self.assertEqual((r.status, r.body["error"]["code"]), (403, "bootstrap_forbidden"))
        blocked = self.t.bootstrap(secret=BOOT)                 # even the right secret waits once the limit is hit
        self.assertEqual(blocked.status, 429)
        self.assertIn("Retry-After", blocked.headers)
        self.assertEqual(self.t.scalar("SELECT count(*) FROM soc.auth_credentials"), "0")

    def test_bootstrap_is_off_without_the_environment_secret(self):
        t = AuthRig(WEEK5_BOOTSTRAP_TOKEN="")
        self.addCleanup(t.drop)
        r = t.bootstrap()
        self.assertEqual(r.status, 404)
        self.assertEqual(t.call("auth_status").body["bootstrap_available"], False)

    def test_bootstrap_needs_an_allowed_origin_a_strong_password_and_a_valid_username(self):
        self.assertEqual(self.t.bootstrap(origin="https://evil.test").status, 403)
        self.assertEqual(self.t.bootstrap(origin=None).status, 403)
        self.assertEqual(self.t.bootstrap(password="short").status, 422)
        self.assertEqual(self.t.bootstrap(password="lakshya-lakshya-lakshya").status, 422)
        self.assertEqual(self.t.bootstrap(username="Bad Name!").status, 422)
        self.assertEqual(self.t.scalar("SELECT count(*) FROM soc.auth_credentials"), "0")
        self.assertEqual(self.t.bootstrap().status, 201)

    def test_concurrent_bootstrap_creates_exactly_one_administrator(self):
        import threading
        results = []

        def go(name):
            results.append(self.t.bootstrap(username=name, password="Horse-Staple-Battery-%s-Z" % name[-1]).status)
        threads = [threading.Thread(target=go, args=("admin%d" % i,)) for i in range(4)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertEqual(sorted(results), [201, 409, 409, 409])
        self.assertEqual(self.t.scalar("SELECT count(*) FROM soc.auth_credentials"), "1")

    def test_bootstrap_promotes_an_existing_legacy_analyst(self):
        self.t.driver.run_script("INSERT INTO soc.analysts (analyst_id, role, display_name) VALUES ('legacyboss', 'analyst', 'Legacy Boss')")
        self.assertEqual(self.t.bootstrap(username="legacyboss").status, 201)
        self.assertEqual(self.t.sql("SELECT role, active, display_name FROM soc.analysts WHERE analyst_id = 'legacyboss'"), [["admin", "t", "Legacy Boss"]])

    # ---------------------------------------------------------------- sign in
    def test_sign_in_sets_a_hardened_cookie_and_returns_no_token_in_the_body(self):
        self.t.bootstrap()
        r, tok = self.t.login("Lakshya", STRONG)                # the username is case-insensitive
        self.assertEqual(r.status, 200)
        cookie = r.headers["Set-Cookie"]
        for part in ("HttpOnly", "Secure", "SameSite=None", "Path=/"):
            self.assertIn(part, cookie)
        self.assertRegex(tok, r"^[A-Za-z0-9_-]{43}$")
        self.assertNotIn(tok, json.dumps(r.body))
        self.assertEqual(r.body["user"]["role"], "admin")
        self.assertTrue(r.body["user"]["permissions"]["admin"])
        self.assertEqual(r.body["csrf_token"], service.csrf_token(tok))
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertNotIn("hash", json.dumps(r.body).lower())

    def test_the_production_cookie_comes_out_of_a_real_sign_in_and_sign_out(self):
        cookies = ProductionCookieTests()
        self.t.bootstrap()
        r, tok = self.t.login("lakshya", STRONG)
        cookies.check_production_attributes(r.headers["Set-Cookie"], tok)
        self.assertEqual(self.t.cookie_name, "__Host-cybersight_session")
        out = self.t.call("auth_logout", token=tok)
        cookies.check_production_attributes(out.headers["Set-Cookie"], "")
        self.assertEqual(len([h for h in r.headers if h.lower() == "set-cookie"]), 1)

    def test_only_a_hash_of_the_session_token_and_of_the_password_is_stored(self):
        self.t.bootstrap()
        r, tok = self.t.login("lakshya", STRONG)
        dump = json.dumps({t: self.t.sql("SELECT * FROM soc.%s" % t) for t in ("auth_credentials", "web_sessions", "auth_attempts", "analysts", "audit_events")})
        self.assertNotIn(tok, dump)
        self.assertNotIn(STRONG, dump)
        self.assertNotIn(BOOT, dump)
        self.assertEqual(self.t.scalar("SELECT token_hash FROM soc.web_sessions"), service.token_hash(tok))
        self.assertTrue(self.t.scalar("SELECT password_hash FROM soc.auth_credentials").startswith("$scrypt$"))

    def test_every_kind_of_failure_gives_the_same_answer(self):
        self.t.bootstrap()
        admin = self.t.login("lakshya", STRONG)[1]
        self.t.make_user(admin, "dormant", "analyst")
        self.t.call("auth_update_user", {"active": False}, token=admin, path={"username": "dormant"})
        answers = []
        for user, pw in (("nobody", STRONG), ("lakshya", "wrong-password-123"), ("dormant", STRONG + "-u"), ("", "x"), ("a" * 80, "x"), ("bad name", "x")):
            r, tok = self.t.login(user, pw, ip="198.51.100.%d" % (len(answers) + 1))
            self.assertIsNone(tok)
            answers.append((r.status, json.dumps(r.body, sort_keys=True), "Set-Cookie" in r.headers))
        self.assertEqual(len(set(answers)), 1, answers)
        self.assertEqual(answers[0][0], 401)
        self.assertNotIn("Set-Cookie", self.t.call("auth_login", {"username": "x"}).headers)

    def test_login_body_must_be_json_with_exactly_the_two_fields(self):
        self.t.bootstrap()
        self.assertEqual(self.t.call("auth_login", {"username": "lakshya", "password": STRONG, "role": "admin"}).status, 422)
        self.assertEqual(self.t.call("auth_login", {"username": "lakshya"}).status, 422)
        r = self.t.api.dispatch("auth_login", {"Origin": ORIGIN, "Content-Type": "text/plain"}, None, None, None, b"username=a")
        self.assertEqual(r.status, 415)

    def test_session_restore_and_logout(self):
        self.t.bootstrap()
        _, tok = self.t.login("lakshya", STRONG)
        s = self.t.call("auth_session", token=tok)
        self.assertEqual((s.status, s.body["user"]["username"], s.body["csrf_token"]), (200, "lakshya", service.csrf_token(tok)))
        self.assertEqual(self.t.call("auth_session").status, 401)
        self.assertEqual(self.t.call("auth_session", token="x" * 43).status, 401)
        out = self.t.call("auth_logout", token=tok)
        self.assertEqual(out.status, 200)
        self.assertIn("Max-Age=0", out.headers["Set-Cookie"])
        self.assertEqual(self.t.call("auth_session", token=tok).status, 401)           # the old cookie is dead on the server
        self.assertEqual(self.t.call("auth_logout").status, 200)                       # signing out when not signed in is harmless
        self.assertEqual(self.t.scalar("SELECT revoked_reason FROM soc.web_sessions"), "logout")

    def test_logout_needs_the_csrf_token_when_a_cookie_is_present(self):
        self.t.bootstrap()
        _, tok = self.t.login("lakshya", STRONG)
        self.assertEqual(self.t.call("auth_logout", token=tok, csrf="wrong").status, 403)
        self.assertEqual(self.t.call("auth_session", token=tok).status, 200)

    def test_two_devices_are_two_sessions_and_signing_out_one_keeps_the_other(self):
        self.t.bootstrap()
        _, a = self.t.login("lakshya", STRONG)
        _, b = self.t.login("lakshya", STRONG, ip="198.51.100.9")
        self.assertNotEqual(a, b)
        self.t.call("auth_logout", token=a)
        self.assertEqual(self.t.call("auth_session", token=a).status, 401)
        self.assertEqual(self.t.call("auth_session", token=b).status, 200)

    def test_the_oldest_sessions_are_revoked_beyond_the_limit(self):
        t = AuthRig(WEEK5_SESSION_MAX_PER_USER="2")
        self.addCleanup(t.drop)
        t.bootstrap()
        toks = [t.login("lakshya", STRONG)[1] for _ in range(3)]
        self.assertEqual([t.call("auth_session", token=x).status for x in toks], [401, 200, 200])

    def test_idle_and_absolute_expiry_and_sliding(self):
        self.t.bootstrap()
        _, tok = self.t.login("lakshya", STRONG)
        self.t.driver.run_script("UPDATE soc.web_sessions SET last_seen_at = clock_timestamp() - interval '2 minutes', idle_expires_at = clock_timestamp() + interval '1 hour'")
        before = self.t.scalar("SELECT idle_expires_at FROM soc.web_sessions")
        self.assertEqual(self.t.call("auth_session", token=tok).status, 200)
        self.assertEqual(self.t.scalar("SELECT idle_expires_at > '%s'::timestamptz FROM soc.web_sessions" % before), "t")             # sliding: pushed out
        self.assertEqual(self.t.scalar("SELECT idle_expires_at <= absolute_expires_at FROM soc.web_sessions"), "t")   # never past the absolute limit
        self.t.driver.run_script("UPDATE soc.web_sessions SET created_at = created_at - interval '1 day', idle_expires_at = clock_timestamp() - interval '1 second'")
        self.assertEqual(self.t.call("auth_session", token=tok).status, 401)
        _, tok2 = self.t.login("lakshya", STRONG, ip="198.51.100.9")
        self.t.driver.run_script("UPDATE soc.web_sessions SET created_at = created_at - interval '8 days', last_seen_at = last_seen_at - interval '8 days', absolute_expires_at = clock_timestamp() - interval '1 second', "
                                 "idle_expires_at = clock_timestamp() - interval '2 seconds' WHERE token_hash = '%s'" % service.token_hash(tok2))
        self.assertEqual(self.t.call("auth_session", token=tok2).status, 401)

    def test_an_active_session_cannot_outlive_the_absolute_limit_by_sliding(self):
        self.t.bootstrap()
        _, tok = self.t.login("lakshya", STRONG)
        self.t.driver.run_script("UPDATE soc.web_sessions SET absolute_expires_at = clock_timestamp() + interval '10 minutes', idle_expires_at = clock_timestamp() + interval '5 minutes', last_seen_at = clock_timestamp() - interval '1 hour'")
        self.assertEqual(self.t.call("auth_session", token=tok).status, 200)
        self.assertEqual(self.t.scalar("SELECT idle_expires_at = absolute_expires_at FROM soc.web_sessions"), "t")

    def test_deactivating_an_account_ends_its_sessions_at_once(self):
        admin = self.t.admin_token()
        pw = self.t.make_user(admin, "bobby", "analyst")
        _, bt = self.t.login("bobby", pw)
        self.assertEqual(self.t.call("auth_session", token=bt).status, 200)
        r = self.t.call("auth_update_user", {"active": False}, token=admin, path={"username": "bobby"})
        self.assertEqual(r.status, 200)
        self.assertEqual(self.t.call("auth_session", token=bt).status, 401)
        self.assertEqual(self.t.login("bobby", pw)[0].status, 401)
        self.t.call("auth_update_user", {"active": True}, token=admin, path={"username": "bobby"})
        self.assertEqual(self.t.login("bobby", pw)[0].status, 200)

    # ---------------------------------------------------------------- origin and CSRF
    def test_state_changing_requests_need_an_allowed_origin_and_the_csrf_token(self):
        self.t.bootstrap()
        _, tok = self.t.login("lakshya", STRONG)
        body = {"username": "viewer1", "role": "viewer", "password": STRONG + "-v"}
        self.assertEqual(self.t.call("auth_create_user", body, token=tok, origin="https://evil.test").status, 403)
        self.assertEqual(self.t.call("auth_create_user", body, token=tok, origin=None).status, 403)
        self.assertEqual(self.t.call("auth_create_user", body, token=tok, csrf=None).status, 403)
        self.assertEqual(self.t.call("auth_create_user", body, token=tok, csrf="0" * 64).status, 403)
        _, other = self.t.login("lakshya", STRONG, ip="198.51.100.9")
        self.assertEqual(self.t.call("auth_create_user", body, token=tok, csrf=service.csrf_token(other)).status, 403)   # another session's token
        self.assertEqual(self.t.scalar("SELECT count(*) FROM soc.auth_credentials"), "1")
        self.assertEqual(self.t.call("auth_create_user", body, token=tok).status, 201)

    def test_origin_and_csrf_failures_are_reported_with_codes_the_console_can_use(self):
        self.t.bootstrap()
        _, tok = self.t.login("lakshya", STRONG)
        body = {"username": "viewer1", "role": "viewer", "password": STRONG + "-v"}
        self.assertEqual(self.t.call("auth_create_user", body, token=tok, origin="https://evil.test").body["error"]["code"], "origin_not_allowed")
        self.assertEqual(self.t.call("auth_create_user", body, token=tok, csrf=None).body["error"]["code"], "csrf_failed")

    def test_the_existing_state_changing_routes_are_protected_the_same_way(self):
        admin = self.t.admin_token()
        pw = self.t.make_user(admin, "ann", "analyst")
        _, tok = self.t.login("ann", pw)
        alert = {"alert": fixtures.make_alert(0)}
        self.assertEqual(self.t.call("submit_alert", alert, token=tok, csrf=None).status, 403)
        self.assertEqual(self.t.call("submit_alert", alert, token=tok, origin="https://evil.test").status, 403)
        self.assertEqual(self.t.call("submit_alert", alert, token=tok, origin=None).status, 403)
        ok = self.t.call("submit_alert", alert, token=tok)
        self.assertEqual(ok.status, 202, ok.body)
        self.assertEqual(self.t.scalar("SELECT submitted_by FROM soc.jobs"), "ann")           # the identity is the signed-in person, not anything in the body
        self.assertEqual(self.t.call("get_job", token=tok, path={"job_id": ok.body["job_id"]}, origin=None).status, 200)   # reads need no Origin

    def test_bearer_tokens_for_machines_still_work_without_csrf_and_can_be_switched_off(self):
        r = self.t.call("submit_alert", {"alert": fixtures.make_alert(1)}, bearer=W5.TOKENS["bob"], origin=None, csrf=None)
        self.assertEqual(r.status, 202, r.body)
        t = AuthRig(WEEK5_ALLOW_BEARER_TOKENS="0")
        self.addCleanup(t.drop)
        self.assertEqual(t.call("get_me", bearer=W5.TOKENS["bob"], origin=None).status, 401)

    def test_a_cookie_cannot_be_replaced_by_a_forged_identity(self):
        self.t.bootstrap()
        r = self.t.call("get_me", extra={"X-Dev-Analyst": "root"})
        self.assertEqual(r.status, 401)
        self.assertEqual(self.t.call("get_me", token="A" * 43).status, 401)

    # ---------------------------------------------------------------- throttling
    def _failures(self, user, n, ip):
        return [self.t.login(user, "wrong-password-%d" % i, ip=ip)[0].status for i in range(n)]

    def test_five_failures_for_one_account_from_one_address_block_the_sixth_even_with_the_right_password(self):
        self.t.bootstrap()
        self.assertEqual(self._failures("lakshya", 5, "198.51.100.1"), [401] * 5)
        r, tok = self.t.login("lakshya", STRONG, ip="198.51.100.1")
        self.assertEqual((r.status, r.body["error"]["code"]), (429, "rate_limited"))
        self.assertIsNone(tok)
        self.assertTrue(1 <= int(r.headers["Retry-After"]) <= 900)
        self.assertEqual(self.t.login("lakshya", STRONG, ip="198.51.100.2")[0].status, 200)      # someone else is not locked out

    def test_a_blocked_request_records_nothing_so_it_cannot_extend_the_block(self):
        self.t.bootstrap()
        self._failures("lakshya", 5, "198.51.100.1")
        rows = self.t.scalar("SELECT count(*) FROM soc.auth_attempts")
        wait = int(self.t.login("lakshya", "x" * 14, ip="198.51.100.1")[0].headers["Retry-After"])
        for _ in range(5):
            self.assertEqual(self.t.login("lakshya", "x" * 14, ip="198.51.100.1")[0].status, 429)
        self.assertEqual(self.t.scalar("SELECT count(*) FROM soc.auth_attempts"), rows)
        self.assertLessEqual(int(self.t.login("lakshya", "x" * 14, ip="198.51.100.1")[0].headers["Retry-After"]), wait)

    def test_the_block_expires_by_itself_there_is_no_permanent_lockout(self):
        self.t.bootstrap()
        self._failures("lakshya", 5, "198.51.100.1")
        self.assertEqual(self.t.login("lakshya", STRONG, ip="198.51.100.1")[0].status, 429)
        self.t.driver.run_script("UPDATE soc.auth_attempts SET attempted_at = attempted_at - interval '16 minutes'")
        self.assertEqual(self.t.login("lakshya", STRONG, ip="198.51.100.1")[0].status, 200)

    def test_a_successful_sign_in_clears_the_pairs_failures(self):
        self.t.bootstrap()
        self._failures("lakshya", 4, "198.51.100.1")
        self.assertEqual(self.t.login("lakshya", STRONG, ip="198.51.100.1")[0].status, 200)
        self.assertEqual(self._failures("lakshya", 4, "198.51.100.1"), [401] * 4)

    def test_password_spraying_from_one_address_is_stopped(self):
        t = AuthRig(WEEK5_LOGIN_LIMIT_IP="4")
        self.addCleanup(t.drop)
        t.bootstrap()
        codes = [t.login("user%d" % i, "wrong-password-xx", ip="198.51.100.7")[0].status for i in range(5)]
        self.assertEqual(codes, [401, 401, 401, 401, 429])
        self.assertEqual(t.login("lakshya", STRONG, ip="198.51.100.7")[0].status, 429)
        self.assertEqual(t.login("lakshya", STRONG, ip="198.51.100.8")[0].status, 200)

    def test_guessing_one_account_from_many_addresses_is_slowed_but_the_owner_on_a_known_address_gets_in(self):
        t = AuthRig(WEEK5_LOGIN_LIMIT_SUBJECT="4")
        self.addCleanup(t.drop)
        t.bootstrap()
        self.assertEqual(t.login("lakshya", STRONG, ip="192.0.2.10")[0].status, 200)           # the owner's usual address
        for i in range(4):
            self.assertEqual(t.login("lakshya", "wrong-password-xx", ip="198.51.100.%d" % (20 + i))[0].status, 401)
        self.assertEqual(t.login("lakshya", STRONG, ip="198.51.100.99")[0].status, 429)       # a new address is held back
        self.assertEqual(t.login("lakshya", STRONG, ip="192.0.2.10")[0].status, 200)           # the owner is not locked out by the attacker

    def test_the_failures_are_stored_only_as_hashes(self):
        self.t.bootstrap()
        self.t.login("lakshya", "wrong-password-xx", ip="198.51.100.77")
        dump = json.dumps(self.t.sql("SELECT * FROM soc.auth_attempts"))
        self.assertNotIn("198.51.100.77", dump)
        self.assertNotIn("lakshya", dump)

    # ---------------------------------------------------------------- administration and roles
    def test_only_an_administrator_can_manage_accounts(self):
        admin = self.t.admin_token()
        pw = {r: self.t.make_user(admin, r + "x", r) for r in ("viewer", "analyst", "approver")}
        for role in ("viewer", "analyst", "approver"):
            _, tok = self.t.login(role + "x", pw[role])
            self.assertEqual(self.t.call("auth_users", token=tok).status, 403, role)
            self.assertEqual(self.t.call("auth_create_user", {"username": "evil", "role": "admin", "password": STRONG + "-e"}, token=tok).status, 403, role)
            self.assertEqual(self.t.call("auth_update_user", {"role": "admin"}, token=tok, path={"username": role + "x"}).status, 403, role)
            self.assertEqual(self.t.call("auth_reset_password", {"password": STRONG + "-e"}, token=tok, path={"username": "lakshya"}).status, 403, role)
            self.assertEqual(self.t.call("auth_revoke_sessions", token=tok, path={"username": "lakshya"}).status, 403, role)
            self.assertEqual(self.t.call("auth_session", token=tok).status, 200, role)
        self.assertEqual(self.t.call("auth_users").status, 401)
        self.assertEqual(self.t.scalar("SELECT count(*) FROM soc.analysts WHERE analyst_id = 'evil'"), "0")

    def test_the_database_functions_also_refuse_a_non_admin_caller(self):
        admin = self.t.admin_token()
        self.t.make_user(admin, "viewerx", "viewer")
        self.assertEqual(self.t.scalar("SELECT soc.auth_admin_create_user('viewerx', 'evil', NULL, 'admin', '$scrypt$n=4096,r=8,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')"), "forbidden")
        self.assertEqual(self.t.scalar("SELECT soc.auth_admin_update_user('viewerx', 'lakshya', 'viewer', NULL, NULL)"), "forbidden")
        self.assertEqual(self.t.scalar("SELECT soc.auth_admin_revoke_sessions('viewerx', 'lakshya')"), "-1")
        with self.assertRaises(DbError) as ctx:
            self.t.sql("SELECT * FROM soc.auth_admin_list_users('viewerx')")
        self.assertEqual(ctx.exception.sqlstate, "42501")

    def test_create_list_update_reset_revoke(self):
        admin = self.t.admin_token()
        r = self.t.call("auth_create_user", {"username": "Dana", "display_name": "  Dana   Scully ", "role": "analyst", "password": STRONG + "-d"}, token=admin)
        self.assertEqual((r.status, r.body), (201, {"username": "dana", "role": "analyst", "status": "created"}))
        dup = self.t.call("auth_create_user", {"username": "dana", "role": "viewer", "password": STRONG + "-d"}, token=admin)
        self.assertEqual((dup.status, dup.body["error"]["code"]), (409, "exists"))
        self.assertEqual(self.t.call("auth_create_user", {"username": "eve", "role": "root", "password": STRONG + "-d"}, token=admin).status, 422)
        self.assertEqual(self.t.call("auth_create_user", {"username": "eve", "role": "viewer", "password": "short"}, token=admin).status, 422)
        users = self.t.call("auth_users", token=admin)
        self.assertEqual(users.status, 200)
        by = {u["username"]: u for u in users.body["items"]}
        self.assertEqual((by["dana"]["role"], by["dana"]["display_name"], by["dana"]["has_password"], by["dana"]["active"]), ("analyst", "Dana Scully", True, True))
        self.assertEqual(by["lakshya"]["active_sessions"], 1)
        text = json.dumps(users.body).lower()
        for forbidden in ("hash", "$scrypt", "token", "secret", STRONG.lower()):
            self.assertNotIn(forbidden, text)
        self.assertEqual(self.t.call("auth_update_user", {"role": "approver", "display_name": "D. Scully"}, token=admin, path={"username": "dana"}).status, 200)
        self.assertEqual(self.t.sql("SELECT role, display_name FROM soc.analysts WHERE analyst_id = 'dana'"), [["approver", "D. Scully"]])
        self.assertEqual(self.t.call("auth_update_user", {}, token=admin, path={"username": "dana"}).status, 422)
        self.assertEqual(self.t.call("auth_update_user", {"role": "king"}, token=admin, path={"username": "dana"}).status, 422)
        self.assertEqual(self.t.call("auth_update_user", {"active": "no"}, token=admin, path={"username": "dana"}).status, 422)
        self.assertEqual(self.t.call("auth_update_user", {"role": "viewer"}, token=admin, path={"username": "ghost"}).status, 404)
        _, dt = self.t.login("dana", STRONG + "-d")
        n = self.t.call("auth_revoke_sessions", token=admin, path={"username": "dana"})
        self.assertEqual((n.status, n.body["revoked"]), (200, 1))
        self.assertEqual(self.t.call("auth_session", token=dt).status, 401)
        self.assertEqual(self.t.call("auth_revoke_sessions", token=admin, path={"username": "ghost"}).status, 404)
        _, dt2 = self.t.login("dana", STRONG + "-d")
        reset = self.t.call("auth_reset_password", {"password": "A-brand-new-passphrase-1"}, token=admin, path={"username": "dana"})
        self.assertEqual(reset.status, 200)
        self.assertEqual(self.t.call("auth_session", token=dt2).status, 401)
        self.assertEqual(self.t.login("dana", STRONG + "-d")[0].status, 401)
        self.assertEqual(self.t.login("dana", "A-brand-new-passphrase-1")[0].status, 200)
        self.assertEqual(self.t.call("auth_reset_password", {"password": "A-brand-new-passphrase-1"}, token=admin, path={"username": "ghost"}).status, 404)
        self.assertEqual(self.t.call("auth_reset_password", {"password": "dana-dana-dana-dana"}, token=admin, path={"username": "dana"}).status, 422)

    def test_an_administrator_cannot_demote_or_deactivate_themselves(self):
        admin = self.t.admin_token()
        for body in ({"role": "viewer"}, {"active": False}):
            r = self.t.call("auth_update_user", body, token=admin, path={"username": "lakshya"})
            self.assertEqual((r.status, r.body["error"]["code"]), (409, "self_change"))
        self.assertEqual(self.t.call("auth_update_user", {"display_name": "Lakshya M"}, token=admin, path={"username": "lakshya"}).status, 200)
        self.assertEqual(self.t.call("auth_session", token=admin).status, 200)

    def test_a_second_administrator_can_be_made_and_unmade(self):
        admin = self.t.admin_token()
        pw = self.t.make_user(admin, "second", "admin")
        _, st = self.t.login("second", pw)
        self.assertEqual(self.t.call("auth_users", token=st).status, 200)
        self.assertEqual(self.t.call("auth_update_user", {"role": "viewer"}, token=admin, path={"username": "second"}).status, 200)
        self.assertEqual(self.t.call("auth_users", token=st).status, 403)                       # the role is read from the database on every request

    def test_an_existing_token_analyst_can_be_given_a_password_and_keeps_their_history(self):
        admin = self.t.admin_token()
        self.t.rig.repo.upsert_analyst("legacyuser", "approver")
        r = self.t.call("auth_create_user", {"username": "legacyuser", "role": "approver", "password": STRONG + "-l"}, token=admin)
        self.assertEqual((r.status, r.body["status"]), (201, "attached"))
        by = {u["analyst_id"]: u for u in self.t.call("auth_users", token=admin).body["items"]}
        self.assertFalse(by["alice"]["has_password"])
        self.assertIsNone(by["alice"]["username"])
        self.assertTrue(by["legacyuser"]["has_password"])

    def test_change_own_password(self):
        admin = self.t.admin_token()
        pw = self.t.make_user(admin, "carl", "analyst")
        _, a = self.t.login("carl", pw)
        _, b = self.t.login("carl", pw, ip="198.51.100.9")
        wrong = self.t.call("auth_change_password", {"current_password": "not-the-password-1", "new_password": "Another-Good-Passphrase-2"}, token=a)
        self.assertEqual((wrong.status, wrong.body["error"]["code"]), (403, "invalid_credentials"))
        self.assertEqual(self.t.call("auth_change_password", {"current_password": pw, "new_password": pw}, token=a).status, 422)
        self.assertEqual(self.t.call("auth_change_password", {"current_password": pw, "new_password": "carl-carl-carl-carl"}, token=a).status, 422)
        ok = self.t.call("auth_change_password", {"current_password": pw, "new_password": "Another-Good-Passphrase-2"}, token=a)
        self.assertEqual(ok.status, 200)
        self.assertEqual(self.t.call("auth_session", token=a).status, 200)
        self.assertEqual(self.t.call("auth_session", token=b).status, 401)
        self.assertEqual(self.t.login("carl", pw)[0].status, 401)
        self.assertEqual(self.t.login("carl", "Another-Good-Passphrase-2")[0].status, 200)

    # ---------------------------------------------------------------- roles on the existing routes
    def test_roles_are_enforced_on_the_existing_routes_for_signed_in_people(self):
        admin = self.t.admin_token()
        toks = {}
        for role in ("viewer", "analyst", "approver"):
            toks[role] = self.t.login(role + "x", self.t.make_user(admin, role + "x", role))[1]
        alert = {"alert": fixtures.make_alert(2)}
        me = {r: self.t.call("get_me", token=t) for r, t in toks.items()}
        self.assertEqual({r: x.body["role"] for r, x in me.items()}, {"viewer": "viewer", "analyst": "analyst", "approver": "approver"})
        self.assertEqual(self.t.call("submit_alert", alert, token=toks["viewer"]).status, 403)
        self.assertEqual(self.t.call("submit_alert", alert, token=toks["analyst"]).status, 202)
        self.assertEqual(self.t.call("list_jobs", token=toks["viewer"]).status, 200)
        self.assertEqual(self.t.call("list_cases", token=toks["viewer"]).status, 200)
        self.assertEqual(self.t.call("health_live").status, 200)
        self.assertEqual(self.t.call("health_ready").status, 200)
        self.assertEqual(self.t.call("list_jobs").status, 401)

    def test_audit_records_sign_ins_and_account_changes_without_secrets(self):
        admin = self.t.admin_token()
        pw = self.t.make_user(admin, "audited", "viewer")
        self.t.login("audited", pw)
        self.t.call("auth_reset_password", {"password": "Fresh-Passphrase-Value-3"}, token=admin, path={"username": "audited"})
        kinds = {r[0] for r in self.t.sql("SELECT event_type FROM soc.audit_events")}
        for k in ("bootstrap_admin_created", "login_succeeded", "account_created", "password_reset"):
            self.assertIn(k, kinds)
        self.assertEqual(self.t.sql("SELECT ok FROM soc.verify_audit_chain()"), [["t"]])           # the hash chain is still intact after all these writes
        dump = json.dumps(self.t.sql("SELECT actor, event_type, entity_id, payload::text FROM soc.audit_events"))
        for secret in (STRONG, pw, "Fresh-Passphrase-Value-3", BOOT, "$scrypt"):
            self.assertNotIn(secret, dump)

    # ---------------------------------------------------------------- failures
    def test_a_database_outage_gives_a_plain_503_without_details(self):
        self.t.bootstrap()

        class Down:
            def __getattr__(self, name):
                def boom(*a, **k):
                    raise DbError('connection to "db.internal.example" password=hunter2 failed', "08006")
                return boom
        self.t.web.store = Down()
        for name, body in (("auth_login", {"username": "lakshya", "password": STRONG}), ("auth_status", None)):
            r = self.t.call(name, body)
            self.assertEqual(r.status, 503, name)
            text = json.dumps(r.body)
            self.assertNotIn("hunter2", text)
            self.assertNotIn("db.internal", text)
        self.assertEqual(self.t.call("auth_session", token="A" * 43).status, 503)

    def test_a_missing_migration_is_reported_as_unavailable_not_as_a_crash(self):
        self.t.driver.run_script("DROP FUNCTION soc.auth_bootstrap_open()")
        self.assertEqual(self.t.call("auth_status").status, 503)

    def test_every_route_that_needs_a_session_refuses_an_anonymous_caller_and_every_admin_route_refuses_a_non_admin(self):
        admin = self.t.admin_token()
        viewer = self.t.login("vw1", self.t.make_user(admin, "vw1", "viewer"))[1]
        for r in routes5.ROUTES5:
            if r.name not in AUTH_NAMES or r.role not in ("session", "admin"):
                continue
            path = {"username": "lakshya"}
            body = {} if r.method in ("POST", "PATCH") else None
            with self.subTest(r.name):
                self.assertEqual(self.t.call(r.name, body, path=path).status, 401)
                self.assertEqual(self.t.call(r.name, body, token="Q" * 43, path=path).status, 401)
                if r.role == "admin":
                    self.assertEqual(self.t.call(r.name, body, token=viewer, path=path).status, 403)

    # ---------------------------------------------------------------- the whole flow
    def test_the_whole_flow(self):
        t = self.t
        self.assertTrue(t.call("auth_status").body["bootstrap_available"])                             # 1 first-time setup is open
        self.assertEqual(t.bootstrap().status, 201)                                                    # 2 bootstrap the first admin
        self.assertFalse(t.call("auth_status").body["bootstrap_available"])
        r, admin = t.login("lakshya", STRONG)                                                          # 3 sign in as lakshya
        self.assertEqual((r.status, r.body["user"]["role"]), (200, "admin"))
        self.assertEqual(t.call("auth_session", token=admin).body["user"]["username"], "lakshya")      # 4 refresh restores the session
        self.assertEqual(t.call("list_jobs", token=admin).status, 200)                                 # 5 the dashboard's data loads
        self.assertEqual(t.call("list_cases", token=admin).status, 200)
        pw = t.make_user(admin, "analyst1", "analyst")                                                 # 6 create an analyst
        r, an = t.login("analyst1", pw)                                                                # 7 the analyst signs in
        self.assertEqual((r.status, r.body["user"]["permissions"]), (200, {"read": True, "submit": True, "decide": False, "admin": False}))
        self.assertEqual(t.call("submit_alert", {"alert": fixtures.make_alert(3)}, token=an).status, 202)   # 8 analyst permissions work ...
        self.assertEqual(t.call("auth_users", token=an).status, 403)                                   # 9 ... and the admin area is closed to them
        self.assertEqual(t.call("auth_create_user", {"username": "x1x", "role": "admin", "password": STRONG + "-x"}, token=an).status, 403)
        self.assertEqual(t.call("auth_logout", token=an).status, 200)                                  # 10 sign out
        self.assertEqual(t.call("auth_session", token=an).status, 401)                                 # 11 the old session is rejected
        self.assertEqual(t.call("list_jobs", token=an).status, 401)
        self.assertEqual(t.call("auth_session", token=admin).status, 200)                              # the admin's own session is unaffected


@unittest.skipUnless(_PG_OK, _PG_WHY)
class HashUpgradeOnPostgres(unittest.TestCase):
    def test_a_weaker_hash_is_upgraded_after_a_successful_sign_in(self):
        t = AuthRig()
        self.addCleanup(t.drop)
        t.bootstrap()
        old = t.scalar("SELECT password_hash FROM soc.auth_credentials")
        t.web.hasher = passwords.PasswordHasher(scheme="scrypt", scrypt_n=8192)
        self.assertEqual(t.login("lakshya", STRONG)[0].status, 200)
        new = t.scalar("SELECT password_hash FROM soc.auth_credentials")
        self.assertNotEqual(old, new)
        self.assertIn("n=8192", new)
        self.assertEqual(t.login("lakshya", STRONG)[0].status, 200)
        self.assertEqual(t.login("lakshya", "wrong-password-xx")[0].status, 401)

    def test_argon2id_end_to_end_when_installed(self):
        """Bootstrap and sign-in with Argon2id (small cost for speed), and an account first hashed with scrypt moves to Argon2id at its next sign-in."""
        try:
            import argon2  # noqa: F401
        except ImportError:
            self.skipTest("argon2-cffi is not installed here")
        t = AuthRig()
        self.addCleanup(t.drop)
        t.bootstrap()
        self.assertTrue(t.scalar("SELECT password_hash FROM soc.auth_credentials").startswith("$scrypt$"))            # this rig hashes with scrypt
        t.web.hasher = passwords.PasswordHasher(scheme="argon2id", time_cost=1, memory_kib=8192, parallelism=1)
        r, tok = t.login("lakshya", STRONG)
        self.assertEqual(r.status, 200)
        stored = t.scalar("SELECT password_hash FROM soc.auth_credentials")
        self.assertRegex(stored, r"^\$argon2id\$v=19\$m=8192,t=1,p=1\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$")
        self.assertNotIn(STRONG, stored)
        self.assertEqual(t.login("lakshya", STRONG)[0].status, 200)
        self.assertEqual(t.login("lakshya", "wrong-password-xx")[0].status, 401)
        t.make_user(tok, "dana", "analyst")                                                                      # a new account is hashed with Argon2id straight away
        self.assertTrue(t.scalar("SELECT password_hash FROM soc.auth_credentials WHERE username = 'dana'").startswith("$argon2id$"))
        self.assertEqual(t.login("dana", STRONG + "-u")[0].status, 200)


if __name__ == "__main__":
    unittest.main()
