"""Week 5 operations code: the resilient driver, admin commands, server/worker start-up checks, Celery configuration. Offline; the PostgreSQL part is opt-in."""
import io
import contextlib
import os
import unittest
import unittest.mock

from tests import week5_support as W5
from week4.db.drivers import DbError
from week5 import celery_app, queues, settings as S, worker as worker_module
from week5.api import serve5
from week5.db import admin
from week5.db.driver import ResilientDriver, is_connection_failure


class FlakyDriver:
    def __init__(self):
        self.calls, self.closed, self.fail_with = 0, False, None

    def query(self, sql, params=()):
        self.calls += 1
        if self.fail_with:
            raise self.fail_with
        return [["1"]]

    def scalar(self, sql, params=()):
        return self.query(sql, params)[0][0]

    run_script = query_json = query

    def close(self):
        self.closed = True


class ResilientDriverTests(unittest.TestCase):
    def make(self, kind="psycopg"):
        self.built = []

        def factory(k, dsn):
            d = FlakyDriver()
            self.built.append(d)
            return d
        return ResilientDriver(kind, "postgresql://x", factory)

    def test_built_lazily_and_reused(self):
        d = self.make()
        self.assertEqual(self.built, [])
        d.scalar("select 1")
        d.scalar("select 1")
        self.assertEqual(len(self.built), 1)

    def test_a_connection_failure_discards_the_connection_and_the_next_call_reconnects(self):
        d = self.make()
        d.scalar("select 1")
        self.built[0].fail_with = DbError("server closed the connection")
        with self.assertRaises(DbError):
            d.scalar("select 1")
        self.assertTrue(self.built[0].closed)
        self.assertEqual(d.scalar("select 1"), "1")
        self.assertEqual(len(self.built), 2)

    def test_a_failed_call_is_not_retried(self):
        d = self.make()
        d.scalar("select 1")
        self.built[0].fail_with = DbError("boom", "08006")
        with self.assertRaises(DbError):
            d.scalar("select 1")
        self.assertEqual(self.built[0].calls, 2)
        self.assertEqual(len(self.built), 1)

    def test_a_rule_violation_keeps_the_connection(self):
        d = self.make()
        d.scalar("select 1")
        self.built[0].fail_with = DbError("check failed", "23514")
        with self.assertRaises(DbError):
            d.scalar("select 1")
        self.assertFalse(self.built[0].closed)
        self.assertEqual(len(self.built), 1)

    def test_connection_failure_classifier(self):
        for state, expected in ((None, True), ("08006", True), ("57P01", True), ("53300", True), ("23514", False), ("22023", False), ("42501", False)):
            self.assertEqual(is_connection_failure(DbError("x", state)), expected, state)

    def test_psql_kind_is_not_serialised_by_the_lock(self):
        d = self.make("psql")
        d.scalar("select 1")
        self.assertEqual(len(self.built), 1)

    def test_close(self):
        d = self.make()
        d.scalar("select 1")
        d.close()
        self.assertTrue(self.built[0].closed)


class AdminTests(unittest.TestCase):
    def test_worker_login_script(self):
        sql = admin.worker_login_script("soc_worker_login", "a-long-enough-password-1")
        self.assertIn("GRANT soc_worker TO soc_worker_login", sql)
        self.assertIn("NOSUPERUSER", sql)
        self.assertIn("'a-long-enough-password-1'", sql)

    def test_password_quoting_survives_a_quote(self):
        self.assertIn("'it''s-a-long-password-ok'", admin.worker_login_script("soc_worker_login", "it's-a-long-password-ok"))

    def test_weak_password_and_bad_names_are_refused_without_echoing_the_password(self):
        with self.assertRaises(admin.AdminError) as ctx:
            admin.worker_login_script("soc_worker_login", "short")
        self.assertNotIn("short", str(ctx.exception).replace("short ", ""))
        with self.assertRaises(admin.AdminError):
            admin.worker_login_script("x; DROP TABLE soc.jobs", "a-long-enough-password-1")
        with self.assertRaises(admin.AdminError):
            admin.worker_login_script("Upper", "a-long-enough-password-1")

    def test_cli_refuses_a_missing_password_before_connecting(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), unittest.mock.patch.dict(os.environ, {"WEEK5_WORKER_DB_PASSWORD": ""}), unittest.mock.patch.object(admin.drivers, "make_driver", return_value=FlakyDriver()):
            code = admin.main(["create-worker-login"])
        self.assertEqual(code, 2)
        self.assertIn("WEEK5_WORKER_DB_PASSWORD", out.getvalue())


class CeleryConfigTests(unittest.TestCase):
    def test_reliability_settings(self):
        s = S.from_env({"WEEK5_JOB_TIMEOUT_SECONDS": "100", "WEEK5_LEASE_SECONDS": "200"})
        c = celery_app.celery_config(s, "redis://redis:6379/0")
        self.assertTrue(c["task_acks_late"])
        self.assertTrue(c["task_reject_on_worker_lost"])
        self.assertEqual(c["worker_prefetch_multiplier"], 1)
        self.assertEqual((c["task_soft_time_limit"], c["task_time_limit"]), (100, 130))
        self.assertTrue(c["task_ignore_result"])
        self.assertEqual(c["task_serializer"], "json")
        self.assertEqual(c["accept_content"], ["json"])
        self.assertGreater(c["broker_transport_options"]["visibility_timeout"], c["task_time_limit"], "or a long job is redelivered while it still runs")
        self.assertEqual(c["task_default_queue"], "soc_triage")

    def test_the_broker_url_comes_from_the_environment_only(self):
        with self.assertRaises(RuntimeError) as ctx:
            celery_app.make_app(S.Settings(), {})
        self.assertIn("WEEK5_CELERY_BROKER_URL", str(ctx.exception))

    def test_a_missing_celery_package_gives_a_clear_error_without_the_url(self):
        try:
            import celery  # noqa: F401
            self.skipTest("celery is installed here")
        except ImportError:
            pass
        with self.assertRaises(RuntimeError) as ctx:
            celery_app.make_app(S.Settings(), {"WEEK5_CELERY_BROKER_URL": "redis://:topsecret@host:6379/0"})
        self.assertNotIn("topsecret", str(ctx.exception))

    def test_importing_the_module_needs_no_celery_and_no_broker(self):
        import importlib
        importlib.reload(celery_app)
        self.assertTrue(hasattr(celery_app, "make_app"))

    def test_task_registration_runs_the_worker_lazily(self):
        made, ran = [], []

        class App:
            def task(self, **kw):
                def deco(fn):
                    self.fn = fn
                    return fn
                return deco

        class FakeWorker:
            def process_job_id(self, job_id):
                ran.append(job_id)
                return "ok"
        app = App()
        celery_app.register_tasks(app, lambda: made.append(1) or FakeWorker())
        self.assertEqual(made, [])
        self.assertEqual(app.fn("j1"), "ok")
        self.assertEqual(app.fn("j2"), "ok")
        self.assertEqual((made, ran), ([1], ["j1", "j2"]))
        self.assertEqual(queues.TASK_NAME, "week5.process_job")


class StartupTests(unittest.TestCase):
    def test_api_refuses_to_build_without_authentication(self):
        from week4.api import auth
        with self.assertRaises(auth.ConfigError):
            serve5.build({"WEEK5_API_DATABASE_URL": "postgresql://x/y"}, driver=FlakyDriver())

    def test_api_needs_a_database_url(self):
        with self.assertRaises(S.ConfigError):
            serve5.build({"WEEK4_API_DEV_MODE": "1"})

    def test_api_refuses_the_memory_backend_and_bad_settings(self):
        with self.assertRaises(S.ConfigError):
            serve5.build({"WEEK4_API_DEV_MODE": "1", "WEEK5_QUEUE_BACKEND": "memory"}, driver=FlakyDriver())
        with self.assertRaises(S.ConfigError):
            serve5.build({"WEEK4_API_DEV_MODE": "1", "WEEK5_MODEL_MODE": "gemini"}, driver=FlakyDriver())

    def test_api_builds_with_a_driver_and_dev_mode(self):
        config, api = serve5.build({"WEEK4_API_DEV_MODE": "1"}, driver=FlakyDriver())
        self.assertEqual(config.mode, "dev")
        self.assertEqual(api.dispatcher.queue.name, "postgres")

    def test_dev_mode_is_refused_off_loopback(self):
        out = io.StringIO()
        env = {"WEEK4_API_DEV_MODE": "1", "WEEK5_API_DATABASE_URL": "postgresql://x/y"}
        with contextlib.redirect_stdout(out), unittest.mock.patch.dict(os.environ, env, clear=False), unittest.mock.patch.object(serve5, "ResilientDriver", lambda *a, **k: FlakyDriver()):
            self.assertEqual(serve5.main(["--host", "0.0.0.0"]), 2)
        self.assertIn("loopback", out.getvalue())

    def test_a_worker_refuses_to_build_without_a_database_url_or_with_the_memory_backend(self):
        with self.assertRaises(S.ConfigError):
            worker_module.build_worker(S.Settings(), {})
        with unittest.mock.patch.object(worker_module, "_driver", return_value=FlakyDriver()):
            with self.assertRaises(S.ConfigError):
                worker_module.build_worker(S.Settings(queue_backend="memory"), {"WEEK5_WORKER_DATABASE_URL": "x"})

    def test_celery_worker_process_does_not_run_in_poll_mode(self):
        err = io.StringIO()

        class W:
            settings = S.Settings(queue_backend="celery")
        with contextlib.redirect_stderr(err), unittest.mock.patch.object(worker_module, "build_worker", return_value=W()):
            self.assertEqual(worker_module.main(["--mode", "poll"]), 2)
        self.assertIn("celery", err.getvalue())

    def test_worker_error_messages_never_contain_the_connection_string(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), unittest.mock.patch.object(worker_module, "build_worker", side_effect=DbError("could not connect to postgresql://u:pw@h/d")):
            code = worker_module.main([])
        self.assertEqual(code, 2)
        self.assertNotIn(":pw@", err.getvalue())


_PG_OK, _PG_WHY = W5.pg_enabled()


@unittest.skipUnless(_PG_OK, _PG_WHY)
class RealPostgres(unittest.TestCase):
    def setUp(self):
        from tests import week4_support as W4
        self.name = W5.PgHarness5.new_database()
        self.addCleanup(W5.PgHarness5.drop, self.name)
        self.owner = W4.driver_for(self.name)

    def test_worker_login_script_creates_a_least_privilege_login(self):
        self.owner.run_script(admin.worker_login_script("w5_test_login", "a-long-enough-password-1"))
        self.assertEqual(self.owner.scalar("SELECT pg_has_role('w5_test_login', 'soc_worker', 'member')"), "t")
        self.assertEqual(self.owner.scalar("SELECT rolsuper OR rolcreatedb OR rolcreaterole FROM pg_roles WHERE rolname = 'w5_test_login'"), "f")
        self.owner.run_script("DROP ROLE w5_test_login")

    def test_migration_verify_passes_for_both_runners(self):
        from week4.db import migrate as w4
        from week5.db import migrate as w5
        self.assertTrue(w4.verify(self.owner)[0])
        self.assertTrue(w5.verify(self.owner)[0])


class HeartbeatAndStop(unittest.TestCase):
    """Container health check and graceful stop for the poll worker and the sweeper."""

    def test_health_check_needs_a_fresh_heartbeat_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "hb")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(worker_module.health_check(path, 60), 1)         # missing
                self.assertEqual(worker_module.health_check(None, 60), 1)
                with open(path, "w") as fh:
                    fh.write("1")
                self.assertEqual(worker_module.health_check(path, 60), 0)
                self.assertEqual(worker_module.health_check(path, 60, now=lambda: os.stat(path).st_mtime + 500), 1)     # stale

    def test_beat_writes_the_file_and_never_raises(self):
        import tempfile
        rig = W5.Rig()
        with tempfile.TemporaryDirectory() as d:
            rig.worker.heartbeat_path = os.path.join(d, "hb")
            rig.worker.beat()
            self.assertTrue(os.path.exists(rig.worker.heartbeat_path))
            rig.worker.heartbeat_path = os.path.join(d, "missing_dir", "hb")
            rig.worker.beat()                                                   # unwritable: silently ignored
        rig.worker.heartbeat_path = None
        rig.worker.beat()

    def test_sweeper_and_poll_loops_beat_and_stop_on_request(self):
        import tempfile
        rig = W5.Rig()
        with tempfile.TemporaryDirectory() as d:
            rig.worker.heartbeat_path = os.path.join(d, "hb")
            rig.worker.sleep = lambda _s: rig.worker.stop.set()
            self.assertEqual(rig.worker.run_sweeper_forever(), 0)
            self.assertTrue(os.path.exists(rig.worker.heartbeat_path))
            os.remove(rig.worker.heartbeat_path)
            rig.worker.stop.clear()
            self.assertEqual(rig.worker.run_forever(), 0)
            self.assertTrue(os.path.exists(rig.worker.heartbeat_path))

    def test_stop_handler_sets_the_event(self):
        import signal
        rig = W5.Rig()
        old = signal.getsignal(signal.SIGTERM)
        try:
            worker_module.install_stop_handlers(rig.worker)
            handler = signal.getsignal(signal.SIGTERM)
            self.assertTrue(callable(handler))
            handler(signal.SIGTERM, None)
            self.assertTrue(rig.worker.stop.is_set())
        finally:
            signal.signal(signal.SIGTERM, old)

    def test_health_flag_through_main(self):
        with unittest.mock.patch.dict(os.environ, {"WEEK5_HEARTBEAT_FILE": "/nonexistent/hb"}), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(worker_module.main(["--health"]), 1)


class SmokeBodyCli(unittest.TestCase):
    def test_fixtures_cli_prints_a_body_the_intake_accepts(self):
        import json
        from week5 import fixtures, intake
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(fixtures.main(["3"]), 0)
        body = json.loads(buf.getvalue())
        parsed = intake.parse_body(buf.getvalue().encode("utf-8"), 16384)
        sub = intake.validate_submission(parsed, "off", memory_allowed=False)
        self.assertEqual(sub.alert["alert_id"], "DEMO-000003")
        self.assertEqual(list(body), ["alert"])


if __name__ == "__main__":
    import unittest.mock  # noqa: F401
    unittest.main()
