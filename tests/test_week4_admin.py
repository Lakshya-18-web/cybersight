"""Week 4 operations files and the admin CLI: Docker Compose / env / requirements / .gitignore (static checks: Docker itself is not run here), admin commands (offline + PostgreSQL opt-in)."""
import io
import os
import re
import unittest
import uuid
from contextlib import redirect_stdout
from unittest import mock

from week4.db import admin, drivers

from tests.week4_support import PgHarness, driver_for, pg_enabled
from tests.test_week4_runner import read_text, SRC

ROOT = os.path.dirname(SRC)
_PG_OK, _PG_WHY = pg_enabled()


class OperationsFileTests(unittest.TestCase):
    def test_compose_has_no_credential_requires_a_password_and_binds_to_loopback(self):
        text = read_text(os.path.join(ROOT, "docker-compose.yml"))
        self.assertIn("${WEEK4_DB_PASSWORD:?", text)
        self.assertIn('"127.0.0.1:${WEEK4_DB_PORT:-5432}:5432"', text)
        self.assertIn("healthcheck:", text)
        self.assertIn("image: postgres:16", text)
        for line in text.splitlines():
            if "PASSWORD" in line and not line.lstrip().startswith("#"):
                self.assertIn("${", line, line)
        self.assertNotRegex(text, r"(?i)password:\s*[A-Za-z0-9]")

    def test_the_env_example_holds_only_placeholders(self):
        text = read_text(os.path.join(ROOT, ".env.week4.example"))
        for line in text.splitlines():
            if line.strip() and not line.startswith("#") and re.search(r"(?i)password|token_hashes", line.split("=")[0]):
                value = line.split("=", 1)[1]
                self.assertTrue(value == "" or value.startswith("<"), line)
        self.assertNotRegex(text, r"postgresql://[^:\s]+:(?!<)[^@\s]+@")

    def test_the_real_env_file_is_git_ignored(self):
        self.assertIn(".env.week4", read_text(os.path.join(ROOT, ".gitignore")).splitlines())

    def test_requirements_name_the_new_dependencies_and_leave_the_old_files_alone(self):
        text = read_text(os.path.join(ROOT, "requirements-week4.txt"))
        for pkg in ("fastapi", "uvicorn", "httpx", "psycopg", "chromadb", "pyarrow"):
            self.assertRegex(text, r"(?m)^" + re.escape(pkg))
        self.assertNotIn("langgraph", text)

    def test_docs_exist_and_say_what_was_not_tested(self):
        text = read_text(os.path.join(ROOT, "docs", "WEEK4_OPERATIONS.md"))
        for needle in ("What was and was not tested", "Docker Compose", "python -m week4.db.migrate apply", "python -m week4.seed_memory seed", "idempotency", "WEEK4_API_DEV_MODE"):
            self.assertTrue(needle.lower() in text.lower(), "missing from the operations guide: " + needle)
        iso = read_text(os.path.join(ROOT, "docs", "WEEK4_SPLIT_ISOLATION.md"))
        self.assertIn("frozen", iso.lower())
        self.assertIn("tests/test_week4_memory.py", iso)


class ApiLoginScriptTests(unittest.TestCase):
    def test_the_script_grants_soc_api_and_quotes_the_password(self):
        sql = admin.api_login_script("soc_api_login", "a'b" + "x" * 20)
        self.assertIn("GRANT soc_api TO soc_api_login", sql)
        self.assertIn("PASSWORD 'a''b", sql)
        self.assertIn("NOSUPERUSER NOCREATEDB NOCREATEROLE", sql)

    def test_bad_names_and_short_passwords_are_refused(self):
        for name in ("Robert'; DROP ROLE x;--", "1abc", "", "a" * 64, "has space"):
            with self.subTest(name), self.assertRaises(admin.AdminError):
                admin.api_login_script(name, "x" * 20)
        for pw in ("", None, "short"):
            with self.subTest(pw), self.assertRaises(admin.AdminError):
                admin.api_login_script("soc_api_login", pw)

    def test_the_password_is_never_printed(self):
        out = io.StringIO()
        fake = mock.Mock()
        with mock.patch.object(admin, "make_repo", return_value=fake), mock.patch.dict(os.environ, {admin.ENV_API_PASSWORD: "S3cretPasswordValue!"}), redirect_stdout(out):
            self.assertEqual(admin.main(["create-api-login"]), 0)
        self.assertNotIn("S3cretPasswordValue", out.getvalue())
        self.assertIn("S3cretPasswordValue!", fake.db.run_script.call_args[0][0])

    def test_a_missing_password_stops_the_command_without_touching_the_database(self):
        fake = mock.Mock()
        env = {k: v for k, v in os.environ.items() if k != admin.ENV_API_PASSWORD}
        with mock.patch.object(admin, "make_repo", return_value=fake), mock.patch.dict(os.environ, env, clear=True), redirect_stdout(io.StringIO()):
            self.assertEqual(admin.main(["create-api-login"]), 2)
        fake.db.run_script.assert_not_called()

    def test_argument_rules(self):
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            admin.main(["add-analyst", "--id", "x", "--role", "root"])

    def test_database_errors_are_reported_without_the_password(self):
        fake = mock.Mock()
        fake.upsert_analyst.side_effect = drivers.DbError("could not connect: postgresql://soc:hunter2@db/soc")
        out = io.StringIO()
        with mock.patch.object(admin, "make_repo", return_value=fake), redirect_stdout(out):
            self.assertEqual(admin.main(["add-analyst", "--id", "alice", "--role", "approver"]), 2)
        self.assertNotIn("hunter2", out.getvalue())


@unittest.skipUnless(_PG_OK, _PG_WHY)
class AdminPgTests(unittest.TestCase):
    def setUp(self):
        self.dbname = PgHarness.new_database()
        self.addCleanup(PgHarness.drop, self.dbname)
        self.db = driver_for(self.dbname)
        from week4.db.repository import PgRepository
        self.repo = PgRepository(self.db)
        self.run_cli = lambda *a: self.cli(*a)

    def cli(self, *argv):
        out = io.StringIO()
        with mock.patch.object(admin, "make_repo", return_value=self.repo), redirect_stdout(out):
            code = admin.main(list(argv))
        return code, out.getvalue()

    def test_add_get_and_deactivate_an_analyst(self):
        self.assertEqual(self.cli("add-analyst", "--id", "alice", "--role", "approver", "--name", "Alice A.")[0], 0)
        code, out = self.cli("get-analyst", "--id", "alice")
        self.assertEqual((code, out.strip()), (0, "analyst alice: role approver, active"))
        self.cli("add-analyst", "--id", "alice", "--role", "viewer", "--inactive")
        self.assertIn("role viewer, inactive", self.cli("get-analyst", "--id", "alice")[1])
        self.assertEqual(self.cli("get-analyst", "--id", "nobody")[0], 1)

    def test_analyst_changes_are_audited_and_the_chain_verifies(self):
        self.cli("add-analyst", "--id", "alice", "--role", "approver")
        self.assertIn("audit chain intact", self.cli("verify-audit")[1])
        self.assertEqual(self.cli("verify-audit")[0], 0)
        n = self.db.scalar("SELECT count(*) FROM soc.audit_events WHERE event_type = 'analyst_upserted'")
        self.assertEqual(n, "1")

    def test_create_api_login_makes_a_member_of_soc_api_that_cannot_write_tables(self):
        name = "w4_login_" + uuid.uuid4().hex[:8]
        self.addCleanup(lambda: driver_for("postgres").run_script("DROP ROLE IF EXISTS " + name))
        with mock.patch.dict(os.environ, {admin.ENV_API_PASSWORD: "a-long-throwaway-password-123"}):
            code, out = self.cli("create-api-login", "--name", name)
        self.assertEqual(code, 0)
        self.assertNotIn("throwaway", out)
        self.assertEqual(self.db.scalar("SELECT pg_has_role('%s', 'soc_api', 'member')" % name), "t")
        self.assertEqual(self.db.scalar("SELECT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole FROM pg_roles WHERE rolname = '%s'" % name), "t")
        self.assertEqual(self.db.scalar("SELECT has_table_privilege('%s', 'soc.cases', 'INSERT')" % name), "f")
        self.assertEqual(self.db.scalar("SELECT has_function_privilege('%s', 'soc.decide_action(uuid, text, text, text, text)', 'EXECUTE')" % name), "t")
        # a second run only changes the password
        with mock.patch.dict(os.environ, {admin.ENV_API_PASSWORD: "another-long-throwaway-pw-456"}):
            self.assertEqual(self.cli("create-api-login", "--name", name)[0], 0)


if __name__ == "__main__":
    unittest.main()
