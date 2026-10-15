"""Week 4 database layer: drivers (offline), migration runner (offline + PostgreSQL), and the schema's own guards (PostgreSQL, opt-in: WEEK4_TEST_PG=1)."""
import os
import shutil
import tempfile
import unittest
import uuid

from week4.db import drivers, migrate
from week4.db.drivers import DbError, bind, redact_dsn, sql_literal
from week4.db.repository import PgRepository

from tests.week4_support import PgHarness, driver_for, make_payload, pg_enabled, seed_analysts

_PG_OK, _PG_WHY = pg_enabled()


class DriverTests(unittest.TestCase):
    def test_literals_are_quoted(self):
        self.assertEqual(sql_literal("it's"), "'it''s'")
        self.assertEqual(sql_literal("'; DROP TABLE soc.cases; --"), "'''; DROP TABLE soc.cases; --'")
        self.assertEqual(sql_literal(None), "NULL")
        self.assertEqual(sql_literal(True), "TRUE")
        self.assertEqual(sql_literal(5), "5")
        self.assertEqual(sql_literal({"a": "x'y"}), "'{\"a\": \"x''y\"}'::jsonb")

    def test_refuses_unsafe_values(self):
        for bad in ("a\x00b", float("nan"), float("inf"), object()):
            with self.subTest(bad):
                with self.assertRaises(DbError):
                    sql_literal(bad)
        with self.assertRaises(DbError):
            sql_literal({"x": float("nan")})

    def test_bind_counts_placeholders(self):
        self.assertEqual(bind("SELECT %s, %s", [1, "a"]), "SELECT 1, 'a'")
        self.assertEqual(bind("SELECT 100 %% 7, %s", [1]), "SELECT 100 % 7, 1")
        for sql, params in (("SELECT %s", []), ("SELECT 1", [1])):
            with self.assertRaises(DbError):
                bind(sql, params)

    def test_a_placeholder_inside_a_value_is_not_rebound(self):
        self.assertEqual(bind("SELECT %s, %s", ["%s", "x"]), "SELECT '%s', 'x'")

    def test_dsn_passwords_are_redacted(self):
        self.assertNotIn("hunter2", redact_dsn("postgresql://soc:hunter2@db:5432/soc"))
        self.assertNotIn("hunter2", redact_dsn("host=db user=soc password=hunter2 dbname=soc"))
        self.assertNotIn("hunter2", redact_dsn("host=db password='hunter2'"))

    def test_make_driver_rejects_unknown_kind(self):
        with self.assertRaises(Exception):
            drivers.make_driver("mysql", None)


class MigrationFileTests(unittest.TestCase):
    def test_shipped_migrations_are_contiguous_and_checksummed(self):
        files = migrate.discover()
        self.assertGreaterEqual(len(files), 4)
        self.assertEqual([f["version"] for f in files], ["%04d" % i for i in range(1, len(files) + 1)])
        for f in files:
            self.assertRegex(f["checksum"], r"^[0-9a-f]{64}$")

    def test_checksum_ignores_line_endings(self):
        self.assertEqual(migrate.checksum_of("a\nb\n"), migrate.checksum_of("a\r\nb\r\n"))
        self.assertNotEqual(migrate.checksum_of("a\nb\n"), migrate.checksum_of("a\nc\n"))

    def _dir(self, names):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for n in names:
            with open(os.path.join(d, n), "w", encoding="utf-8") as fh:
                fh.write("SELECT 1;\n")
        return d

    def test_gaps_duplicates_and_bad_names_are_refused(self):
        for names in (["0001_a.sql", "0003_c.sql"], ["0002_b.sql"], ["0001_a.sql", "0001_b.sql"], ["0001_A.sql"], ["1_a.sql"]):
            with self.subTest(names):
                with self.assertRaises(migrate.MigrationError):
                    migrate.discover(self._dir(names))

    def test_no_secrets_in_migrations(self):
        for f in migrate.discover():
            text = f["sql"].lower()
            for word in ("password '", "password=", "create role soc_api login", "alter role"):
                self.assertNotIn(word, text, f["name"])

    def test_api_role_cannot_log_in_by_default(self):
        sql = [f for f in migrate.discover() if f["name"] == "roles_and_views"][0]["sql"]
        self.assertIn("CREATE ROLE soc_api NOLOGIN", sql)


@unittest.skipUnless(_PG_OK, _PG_WHY)
class PgCase(unittest.TestCase):
    def setUp(self):
        self.dbname = PgHarness.new_database()
        self.addCleanup(PgHarness.drop, self.dbname)
        self.db = driver_for(self.dbname)
        self.repo = PgRepository(self.db)
        seed_analysts(self.repo)

    def fails(self, sql, state=None, contains=None):
        with self.assertRaises(DbError) as ctx:
            self.db.run_script(sql)
        if state:
            self.assertEqual(ctx.exception.sqlstate, state, str(ctx.exception))
        if contains:
            self.assertIn(contains, str(ctx.exception))
        return ctx.exception

    def case_with_action(self):
        out = self.repo.ingest_case(make_payload())
        case = self.repo.get_case(out["case_id"])
        return case, case["actions"][0]["action_id"]


class MigrationRunnerTests(unittest.TestCase):
    def setUp(self):
        self.blank = "w4_blank_" + uuid.uuid4().hex[:10]
        driver_for("postgres").run_script('CREATE DATABASE "%s"' % self.blank)
        self.addCleanup(PgHarness.drop, self.blank)
        self.db = driver_for(self.blank)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def copy_migrations(self):
        for f in migrate.discover():
            with open(os.path.join(self.tmp, "%s_%s.sql" % (f["version"], f["name"])), "w", encoding="utf-8") as fh:
                fh.write(f["sql"])
        return self.tmp

    def test_apply_is_idempotent_and_verifiable(self):
        self.assertEqual(len(migrate.apply(self.db, say=lambda *_: None)), len(migrate.discover()))
        self.assertEqual(migrate.apply(self.db, say=lambda *_: None), [])
        self.assertEqual(migrate.verify(self.db), (True, []))

    def test_pending_migrations_fail_verification(self):
        ok, problems = migrate.verify(self.db)
        self.assertFalse(ok)
        self.assertTrue(all(p.startswith("pending") for p in problems))

    def test_an_edited_applied_migration_is_refused(self):
        d = self.copy_migrations()
        migrate.apply(self.db, d, say=lambda *_: None)
        first = os.path.join(d, sorted(os.listdir(d))[0])
        with open(first, "a", encoding="utf-8") as fh:
            fh.write("\n-- tampered\n")
        ok, problems = migrate.verify(self.db, d)
        self.assertFalse(ok)
        self.assertIn("changed after it was applied", problems[0])
        with self.assertRaises(migrate.MigrationError):
            migrate.apply(self.db, d, say=lambda *_: None)

    def test_a_new_migration_is_applied_on_top(self):
        d = self.copy_migrations()
        migrate.apply(self.db, d, say=lambda *_: None)
        n = len(os.listdir(d)) + 1
        with open(os.path.join(d, "%04d_extra.sql" % n), "w", encoding="utf-8") as fh:
            fh.write("CREATE TABLE soc.extra_probe (x integer);\n")
        self.assertEqual(migrate.apply(self.db, d, say=lambda *_: None), ["%04d" % n])
        self.assertEqual(self.db.scalar("SELECT to_regclass('soc.extra_probe') IS NOT NULL"), "t")

    def test_a_failing_migration_rolls_back_completely(self):
        d = self.copy_migrations()
        migrate.apply(self.db, d, say=lambda *_: None)
        n = len(os.listdir(d)) + 1
        with open(os.path.join(d, "%04d_bad.sql" % n), "w", encoding="utf-8") as fh:
            fh.write("CREATE TABLE soc.half_done (x integer);\nSELECT 1/0;\n")
        with self.assertRaises(migrate.MigrationError):
            migrate.apply(self.db, d, say=lambda *_: None)
        self.assertEqual(self.db.scalar("SELECT to_regclass('soc.half_done') IS NULL"), "t")
        self.assertEqual(len(migrate.applied(self.db)), n - 1)

    def test_an_applied_migration_whose_file_vanished_is_refused(self):
        d = self.copy_migrations()
        migrate.apply(self.db, d, say=lambda *_: None)
        os.remove(os.path.join(d, sorted(os.listdir(d))[-1]))
        ok, problems = migrate.verify(self.db, d)
        self.assertFalse(ok)


MigrationRunnerTests = unittest.skipUnless(_PG_OK, _PG_WHY)(MigrationRunnerTests)


class SchemaGuardTests(PgCase):
    def test_tables_have_primary_keys_foreign_keys_and_indexes(self):
        tables = {r[0] for r in self.db.query("SELECT table_name FROM information_schema.tables WHERE table_schema = 'soc' AND table_type = 'BASE TABLE'")}
        self.assertTrue({"analysts", "cases", "verdicts", "evidence_items", "memory_hits", "routing_decisions", "proposed_actions", "approval_decisions", "executed_actions",
                         "audit_events", "schema_migrations"} <= tables)
        for t in tables:
            self.assertEqual(self.db.scalar("SELECT count(*) FROM information_schema.table_constraints WHERE table_schema='soc' AND table_name=%s AND constraint_type='PRIMARY KEY'", [t]), "1", t)
        fks = int(self.db.scalar("SELECT count(*) FROM information_schema.table_constraints WHERE table_schema='soc' AND constraint_type='FOREIGN KEY'"))
        self.assertGreaterEqual(fks, 8)
        idx = {r[0] for r in self.db.query("SELECT indexname FROM pg_indexes WHERE schemaname='soc'")}
        self.assertTrue({"cases_status_created_idx", "proposed_actions_state_idx", "audit_events_case_idx", "cases_idempotency_key_key"} <= idx)

    def test_evidence_is_append_only(self):
        self.case_with_action()
        for sql in ("UPDATE soc.verdicts SET severity = 'low'", "DELETE FROM soc.verdicts", "UPDATE soc.evidence_items SET source = 'x'", "DELETE FROM soc.evidence_items",
                    "UPDATE soc.memory_hits SET label = 'x'", "UPDATE soc.routing_decisions SET decision = 'auto_close'", "DELETE FROM soc.routing_decisions",
                    "TRUNCATE soc.verdicts", "TRUNCATE soc.evidence_items"):
            with self.subTest(sql):
                self.fails(sql, "23000")

    def test_audit_trail_is_append_only(self):
        self.case_with_action()
        for sql in ("UPDATE soc.audit_events SET actor = 'x'", "DELETE FROM soc.audit_events", "TRUNCATE soc.audit_events"):
            with self.subTest(sql):
                self.fails(sql, "23000")

    def test_cases_only_change_status_and_never_vanish(self):
        case, _ = self.case_with_action()
        cid = case["case_id"]
        self.fails("UPDATE soc.cases SET alert_id = 'other' WHERE case_id = '%s'" % cid, "23000", "only the status")
        self.fails("UPDATE soc.cases SET alert = '{}'::jsonb WHERE case_id = '%s'" % cid, "23000")
        self.fails("UPDATE soc.cases SET status = 'auto_closed' WHERE case_id = '%s'" % cid, "23000", "illegal case status")
        self.fails("DELETE FROM soc.cases WHERE case_id = '%s'" % cid, "23000")
        self.fails("TRUNCATE soc.cases CASCADE", "23000")

    def test_proposed_action_rules_hold_even_for_the_table_owner(self):
        case, aid = self.case_with_action()
        self.fails("UPDATE soc.proposed_actions SET target = 'elsewhere' WHERE action_id = '%s'" % aid, "23000", "cannot be edited")
        self.fails("UPDATE soc.proposed_actions SET state = 'approved' WHERE action_id = '%s'" % aid, "23514")      # no decider recorded
        self.fails("UPDATE soc.proposed_actions SET state = 'executed' WHERE action_id = '%s'" % aid, "23000", "illegal state change")
        self.fails("DELETE FROM soc.proposed_actions WHERE action_id = '%s'" % aid, "23000")
        self.fails("INSERT INTO soc.proposed_actions (case_id, action_type, target, rationale, proposed_by, requires_approval) VALUES ('%s', 'isolate_host', 'h', 'r', 'x', false)" % case["case_id"], "23514")
        self.repo.decide_action(aid, "approved", "alice", "ok", "key-guard-0001")
        self.fails("UPDATE soc.proposed_actions SET state = 'pending', decided_at = NULL, decided_by = NULL, decision_reason = NULL WHERE action_id = '%s'" % aid, "23000")
        self.fails("UPDATE soc.proposed_actions SET state = 'rejected' WHERE action_id = '%s'" % aid, "23000")

    def test_decision_rows_must_agree_with_the_proposal_and_come_from_an_approver(self):
        _, aid = self.case_with_action()
        self.fails("INSERT INTO soc.approval_decisions (action_id, decision, decided_by, reason, idempotency_key) VALUES ('%s', 'approved', 'alice', 'x', 'key-forged-001')" % aid, "23000",
                   "does not match")
        self.repo.decide_action(aid, "approved", "alice", "ok", "key-guard-0002")
        self.fails("INSERT INTO soc.approval_decisions (action_id, decision, decided_by, reason, idempotency_key) VALUES ('%s', 'approved', 'alice', 'x', 'key-forged-002')" % aid, "23505")

    def test_execution_guard_requires_approval_and_simulation_mode(self):
        _, aid = self.case_with_action()
        self.fails("INSERT INTO soc.executed_actions (action_id, mode, executed_by) VALUES ('%s', 'simulated', 'alice')" % aid, "23000", "cannot be executed")
        self.repo.decide_action(aid, "approved", "alice", "ok", "key-guard-0003")
        self.fails("INSERT INTO soc.executed_actions (action_id, mode, executed_by) VALUES ('%s', 'live', 'alice')" % aid, "23514")
        self.fails("INSERT INTO soc.executed_actions (action_id, mode, executed_by) VALUES ('00000000-0000-4000-8000-000000000000', 'simulated', 'alice')", "23000")

    def test_a_forged_approved_state_without_a_decision_row_still_cannot_execute(self):
        _, aid = self.case_with_action()
        # the table owner bypasses decide_action and flips the state directly; the execution guard still insists on the decision row
        self.db.run_script("UPDATE soc.proposed_actions SET state = 'approved', decided_at = now(), decided_by = 'alice', decision_reason = 'forged' WHERE action_id = '%s'" % aid)
        self.fails("INSERT INTO soc.executed_actions (action_id, mode, executed_by) VALUES ('%s', 'simulated', 'alice')" % aid, "23000", "cannot be executed")

    def test_audit_chain_detects_tampering(self):
        case, aid = self.case_with_action()
        self.repo.decide_action(aid, "approved", "alice", "ok", "key-chain-0001")
        self.assertTrue(self.repo.verify_audit_chain()["ok"])
        # an administrator who switches the triggers off can edit history, but the chain no longer verifies and names the first broken event
        self.db.run_script("ALTER TABLE soc.audit_events DISABLE TRIGGER USER;\nUPDATE soc.audit_events SET actor = 'someone-else' WHERE event_id = 2;\nALTER TABLE soc.audit_events ENABLE TRIGGER USER;")
        res = self.repo.verify_audit_chain()
        self.assertFalse(res["ok"])
        self.assertEqual(res["first_bad_event_id"], 2)

    def test_deleting_an_audit_row_breaks_the_chain(self):
        case, aid = self.case_with_action()
        self.db.run_script("ALTER TABLE soc.audit_events DISABLE TRIGGER USER;\nDELETE FROM soc.audit_events WHERE event_id = 1;\nALTER TABLE soc.audit_events ENABLE TRIGGER USER;")
        self.assertFalse(self.repo.verify_audit_chain()["ok"])

    def test_credential_like_payloads_are_refused_by_the_database(self):
        case, _ = self.case_with_action()
        for sql in ("SELECT soc.audit('x', 'e', 'case', 'c', NULL, '{\"api_key\": \"abc\"}'::jsonb)",
                    "SELECT soc.audit('x', 'e', 'case', 'c', NULL, '{\"nested\": {\"Authorization\": \"Bearer abc\"}}'::jsonb)"):
            with self.subTest(sql):
                self.fails(sql, "23514")
        self.assertEqual(self.db.scalar("SELECT soc.contains_secret_key('{\"flow_duration\": 5}'::jsonb)"), "f")
        self.assertEqual(self.db.scalar("SELECT soc.contains_secret_key('{\"x\": {\"client_secret\": 1}}'::jsonb)"), "t")

    def test_the_api_role_can_read_and_call_functions_but_not_write(self):
        case, aid = self.case_with_action()
        as_api = "SET ROLE soc_api;\n"
        self.assertEqual(self.db.scalar(as_api + "SELECT count(*) FROM soc.cases"), "1")
        for sql in ("INSERT INTO soc.analysts VALUES ('eve', 'x', 'admin', true, now())", "UPDATE soc.analysts SET role = 'admin' WHERE analyst_id = 'bob'",
                    "UPDATE soc.proposed_actions SET state = 'approved'", "DELETE FROM soc.audit_events", "SELECT soc.audit('x', 'e', 'case', 'c', NULL, '{}'::jsonb)",
                    "INSERT INTO soc.executed_actions (action_id, mode, executed_by) VALUES (gen_random_uuid(), 'simulated', 'x')"):
            with self.subTest(sql):
                self.fails(as_api + sql, "42501")
        out = self.db.query(as_api + "SELECT outcome FROM soc.decide_action('%s', 'approved', 'alice', 'ok', 'key-api-role-1')" % aid)
        self.assertEqual(out[0][0], "applied")
        self.assertEqual(self.db.query(as_api + "SELECT outcome FROM soc.simulate_execution('%s', 'alice')" % aid)[0][0], "simulated")

    def test_cases_cannot_be_stored_for_the_frozen_set(self):
        self.fails("INSERT INTO soc.cases (idempotency_key, payload_sha256, alert_set, alert_id, run_name, graph_version, memory_mode, alert, status) "
                   "VALUES ('frozen-key-01', repeat('a', 64), 'frozen', 'f1', 'r', 'g', 'off', '{}'::jsonb, 'escalated')", "23514")

    def test_timestamps_and_provenance_are_recorded(self):
        case, _ = self.case_with_action()
        self.assertIsNotNone(case["created_at"])
        self.assertEqual(case["provenance"], {"note": "unit test"})
        hist = self.repo.case_history(case["case_id"])
        self.assertTrue(all(e["occurred_at"] for e in hist))
        self.assertTrue(all(len(e["event_hash"]) == 64 for e in hist))


if __name__ == "__main__":
    unittest.main()
