"""Sensor events, case search, notes, feedback and resolution: one set of tests for the in-memory stand-in (always) and PostgreSQL (opt-in, WEEK4_TEST_PG=1)."""
import json
import os
import threading
import unittest

from week4.db.drivers import DbError
from week4.db.fake import MemoryRepository
from week4.db.repository import PgRepository
from week5 import eve, repo5

from tests.week4_support import driver_for, make_payload, seed_analysts, variant
from tests.week5_support import PgHarness5, pg_enabled

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "eve")


def sample_records(name="eve_mixed.ndjson", sensor="sensor-lab-1"):
    with open(os.path.join(SAMPLES, name), "rb") as f:
        records, ignored, rejected = eve.normalise_batch(eve.parse_ndjson(f.read(), 10 ** 7), sensor)
    return [r for _, r in records]


class Repo5Contract:
    repo = None

    def ingest(self, **kw):
        out = self.repo.ingest_case(make_payload(**kw))
        self.assertEqual(out["outcome"], "created", out)
        return out["case_id"]

    # ------------------------------------------------------------------ sensor events
    def test_sensor_batch_is_stored_and_duplicates_are_recognised(self):
        recs = sample_records()
        first = self.repo.ingest_sensor_batch("bob", "sensor-lab-1", recs)
        self.assertEqual((first["stored"], first["duplicates"]), (len(recs), 0))
        self.assertEqual([r["outcome"] for r in first["results"]], ["stored"] * len(recs))
        again = self.repo.ingest_sensor_batch("bob", "sensor-lab-1", recs)
        self.assertEqual((again["stored"], again["duplicates"]), (0, len(recs)))
        stats = self.repo.sensor_stats()
        self.assertEqual((stats["events"], stats["flows"], stats["alerts"], stats["sensors"]), (len(recs), 16, 4, 1))
        self.assertIsNotNone(stats["last_received_at"])

    def test_partial_overlap_stores_only_the_new_events(self):
        recs = sample_records()
        self.repo.ingest_sensor_batch("bob", "sensor-lab-1", recs[:5])
        out = self.repo.ingest_sensor_batch("bob", "sensor-lab-1", recs[3:9])
        self.assertEqual((out["stored"], out["duplicates"]), (4, 2))
        self.assertEqual([r["outcome"] for r in out["results"]], ["duplicate", "duplicate", "stored", "stored", "stored", "stored"])

    def test_same_event_from_two_sensors_is_two_events(self):
        a = sample_records(sensor="sensor-a")
        b = sample_records(sensor="sensor-b")
        self.repo.ingest_sensor_batch("bob", "sensor-a", a)
        out = self.repo.ingest_sensor_batch("bob", "sensor-b", b)
        self.assertEqual(out["stored"], len(b))
        self.assertEqual(self.repo.sensor_stats()["sensors"], 2)

    def test_sensor_ingest_requires_an_active_writer(self):
        recs = sample_records()[:2]
        for who in ("carol", "erin", "ghost"):          # viewer, inactive, inactive viewer
            out = self.repo.ingest_sensor_batch(who, "sensor-lab-1", recs)
            self.assertEqual((out["outcome"], out["stored"]), ("unauthorized", 0), who)
        self.assertEqual(self.repo.sensor_stats()["events"], 0)
        refused = [e for e in self.repo.audit_tail(50) if e["event_type"] == "sensor_batch_refused"]
        self.assertEqual(len(refused), 3)          # the refusal is audited (and the audit row survives)

    def test_batch_is_audited_once(self):
        self.repo.ingest_sensor_batch("bob", "sensor-lab-1", sample_records())
        events = [e for e in self.repo.audit_tail(50) if e["event_type"] == "sensor_batch_ingested"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["actor"], "bob")
        self.assertEqual(events[0]["payload"]["stored"], 20)

    def test_alert_lookup_and_flow_link(self):
        recs = sample_records()
        self.repo.ingest_sensor_batch("bob", "sensor-lab-1", recs)
        ssh = next(r for r in recs if r["event_type"] == "alert" and r["record"]["signature_id"] == 2001219)
        got = self.repo.sensor_alert(ssh["record"]["alert_id"])
        self.assertEqual(got["signature_id"], 2001219)
        self.assertIsNone(self.repo.sensor_alert("EVE-" + "0" * 24))
        flow = self.repo.sensor_flow_for("sensor-lab-1", ssh["record"]["flow_ref"])
        self.assertEqual((flow["event_type"], flow["dst_port"]), ("flow", 22))
        self.assertIsNone(self.repo.sensor_flow_for("other-sensor", ssh["record"]["flow_ref"]))
        self.assertIsNone(self.repo.sensor_flow_for("sensor-lab-1", "999"))

    def test_flows_near_selects_by_address_and_time(self):
        self.repo.ingest_sensor_batch("bob", "sensor-lab-1", sample_records())
        around = "2026-10-20T10:00:30+00:00"
        ssh = self.repo.flows_near(["203.0.113.50"], around, 10)
        self.assertEqual(len(ssh), 8)
        self.assertEqual([f["src_port"] for f in ssh], sorted(f["src_port"] for f in ssh))          # oldest first
        self.assertEqual(self.repo.flows_near(["203.0.113.50"], "2026-10-20T20:00:00+00:00", 10), [])
        self.assertEqual(len(self.repo.flows_near(["10.0.0.5"], around, 10)), 8)          # either end of the flow
        self.assertEqual(self.repo.flows_near([], around, 10), [])
        self.assertLessEqual(len(self.repo.flows_near(["203.0.113.50"], around, 10, limit=3)), 3)
        with self.assertRaises(ValueError):
            self.repo.flows_near(["not an ip"], around, 10)

    def test_stored_records_hold_no_secret_looking_keys(self):
        recs = sample_records()
        self.repo.ingest_sensor_batch("bob", "sensor-lab-1", recs)
        blob = json.dumps([self.repo.sensor_alert(r["record"]["alert_id"]) for r in recs if r["event_type"] == "alert"])
        for word in ("api_key", "password", "token", "secret"):
            self.assertNotIn(word, blob.lower())

    # ------------------------------------------------------------------ search
    def seed_cases(self):
        a = self.ingest(decision="escalate")
        b = self.ingest(decision="auto_close", verdict="benign")
        c = self.ingest(decision="needs_review", verdict="failed")
        return a, b, c

    def test_filters(self):
        a, b, c = self.seed_cases()
        s = self.repo.search_cases
        self.assertEqual(s()["total"], 3)
        self.assertEqual([x["case_id"] for x in s({"status": "escalated"})["items"]], [a])
        self.assertEqual([x["case_id"] for x in s({"routing_decision": "auto_close"})["items"]], [b])
        self.assertEqual([x["case_id"] for x in s({"verdict_status": "parse_failed"})["items"]], [c])
        self.assertEqual([x["case_id"] for x in s({"severity": "high"})["items"]], [a])
        self.assertEqual([x["case_id"] for x in s({"risk_level": "unknown"})["items"]], [c])
        self.assertEqual([x["case_id"] for x in s({"is_malicious": "true"})["items"]], [a])
        self.assertEqual([x["case_id"] for x in s({"is_malicious": False})["items"]], [b])
        self.assertEqual([x["case_id"] for x in s({"has_pending": "true"})["items"]], [a])
        self.assertEqual({x["case_id"] for x in s({"has_pending": "false"})["items"]}, {b, c})
        self.assertEqual(s({"status": "escalated", "severity": "low"})["total"], 0)
        self.assertEqual(s({"created_from": "2999-01-01"})["total"], 0)
        self.assertEqual(s({"created_to": "2999-01-01"})["total"], 3)
        self.assertEqual(s({"created_to": "2000-01-01"})["total"], 0)

    def test_text_search_and_wildcards_are_literal(self):
        a, b, c = self.seed_cases()
        s = self.repo.search_cases
        self.assertEqual(s({"q": "dos hulk"})["total"], 1)
        self.assertEqual(s({"q": "BENIGN"})["total"], 1)
        self.assertEqual(s({"q": a[:8]})["total"], 1)
        self.assertEqual(s({"q": "198.51.100"})["total"], 0)          # the payload alert has no src_ip
        for q in ("%", "_", "\\", "' OR 1=1 --", "a%b"):
            self.assertEqual(s({"q": q})["total"], 0, q)
        self.assertEqual(s({"q": "dev-0001"})["total"], 3)

    def test_bad_filters_are_refused_without_echoing_values(self):
        for bad in ({"status": "nope"}, {"severity": "urgent"}, {"sort": "random"}, {"alert_set": "x"}, {"is_malicious": "maybe"}, {"created_from": "yesterday"},
                    {"created_to": "2026-13-45"}, {"q": "x" * 101}, {"q": "a\x00b"}, {"has_pending": "2"}):
            with self.assertRaises(ValueError) as ctx:
                self.repo.search_cases(bad)
            for v in bad.values():
                if isinstance(v, str) and len(v) > 4:
                    self.assertNotIn(v, str(ctx.exception))

    def test_sorting_and_paging(self):
        a, b, c = self.seed_cases()
        s = self.repo.search_cases
        newest = [x["case_id"] for x in s({"sort": "created_desc"})["items"]]
        self.assertEqual(newest, [c, b, a])
        self.assertEqual([x["case_id"] for x in s({"sort": "created_asc"})["items"]], [a, b, c])
        self.assertEqual(s({"sort": "severity_desc"})["items"][0]["case_id"], a)
        self.assertEqual(s({"sort": "risk_desc"})["items"][0]["case_id"], a)
        page = s({"sort": "created_asc"}, limit=2, offset=1)
        self.assertEqual(([x["case_id"] for x in page["items"]], page["total"]), ([b, c], 3))
        with self.assertRaises(ValueError):
            s(None, limit=0)
        with self.assertRaises(ValueError):
            s(None, limit=10 ** 6)

    def test_summary_shape(self):
        a, _, _ = self.seed_cases()
        item = self.repo.search_cases({"status": "escalated"})["items"][0]
        for key in ("case_id", "alert_id", "status", "severity", "risk_level", "routing_decision", "verdict_status", "pending_actions", "notes_count", "latest_feedback", "alert_set", "created_at"):
            self.assertIn(key, item)
        self.assertEqual((item["pending_actions"], item["notes_count"], item["latest_feedback"]), (1, 0, None))

    # ------------------------------------------------------------------ notes
    def test_note_lifecycle(self):
        a = self.ingest()
        out = self.repo.add_note(a, "bob", "checked the firewall log; matches a scan", "note-key-0001")
        self.assertEqual(out["outcome"], "created")
        self.assertEqual(self.repo.add_note(a, "bob", "checked the firewall log; matches a scan", "note-key-0001")["outcome"], "replayed")
        self.assertEqual(self.repo.add_note(a, "bob", "a different body", "note-key-0001")["outcome"], "conflict")
        self.assertEqual(self.repo.add_note(a, "alice", "second analyst note")["outcome"], "created")
        notes = self.repo.case_notes(a)
        self.assertEqual([n["author"] for n in notes], ["bob", "alice"])
        self.assertEqual(self.repo.search_cases()["items"][0]["notes_count"], 2)
        added = [e for e in self.repo.case_history(a) if e["event_type"] == "case_note_added"]
        self.assertEqual(len(added), 2)
        self.assertNotIn("firewall", json.dumps(added))          # the audit row records the length, not the text

    def test_note_authorisation_and_validation(self):
        a = self.ingest()
        for who in ("carol", "erin", "ghost"):
            self.assertEqual(self.repo.add_note(a, who, "x")["outcome"], "unauthorized", who)
        self.assertEqual(self.repo.add_note("11111111-1111-4111-8111-111111111111", "bob", "x")["outcome"], "not_found")
        for bad in ("", "   ", "x" * 4001, "a\x00b", None, 5):
            with self.assertRaises(ValueError):
                self.repo.add_note(a, "bob", bad)
        with self.assertRaises(ValueError):
            self.repo.add_note(a, "bob", "ok", "short")
        with self.assertRaises(ValueError):
            self.repo.add_note("not-a-uuid", "bob", "ok")
        with self.assertRaises(ValueError):
            self.repo.add_note(a, "bad actor!", "ok")
        self.assertEqual(self.repo.case_notes(a), [])
        self.assertTrue(any(e["event_type"] == "case_note_refused" for e in self.repo.case_history(a)))

    def test_note_text_is_stored_verbatim_including_markup(self):
        a = self.ingest()
        body = "<script>alert(1)</script> ' ; DROP TABLE soc.cases; -- é中"
        self.repo.add_note(a, "bob", body)
        self.assertEqual(self.repo.case_notes(a)[0]["body"], body)
        self.assertEqual(self.repo.search_cases()["total"], 1)

    # ------------------------------------------------------------------ feedback
    def test_feedback(self):
        a = self.ingest()
        out = self.repo.add_feedback(a, "bob", "incorrect", "false_positive", "benign scanner", "fb-key-00001")
        self.assertEqual(out["outcome"], "created")
        self.assertEqual(self.repo.add_feedback(a, "bob", "incorrect", "false_positive", "benign scanner", "fb-key-00001")["outcome"], "replayed")
        self.assertEqual(self.repo.add_feedback(a, "bob", "correct", None, None, "fb-key-00001")["outcome"], "conflict")
        self.assertEqual(self.repo.add_feedback(a, "alice", "correct")["outcome"], "created")
        rows = self.repo.case_feedback(a)
        self.assertEqual([(r["author"], r["verdict_assessment"]) for r in rows], [("bob", "incorrect"), ("alice", "correct")])
        self.assertEqual(self.repo.search_cases()["items"][0]["latest_feedback"], "correct")
        self.assertEqual(self.repo.add_feedback(a, "carol", "correct")["outcome"], "unauthorized")
        self.assertEqual(self.repo.add_feedback("11111111-1111-4111-8111-111111111111", "bob", "correct")["outcome"], "not_found")
        for args in (("maybe",), ("correct", "weird"), (None,), ("correct", None, "x" * 2001), ("correct", None, "a\x01b")):
            with self.assertRaises(ValueError):
                self.repo.add_feedback(a, "bob", *args)
        self.assertEqual(len(self.repo.case_feedback(a)), 2)

    def test_feedback_does_not_change_the_verdict_or_routing(self):
        a = self.ingest()
        before = self.repo.get_case(a)
        self.repo.add_feedback(a, "bob", "incorrect", "false_negative", "should have been critical")
        after = self.repo.get_case(a)
        self.assertEqual((before["verdict"], before["routing"], before["status"]), (after["verdict"], after["routing"], after["status"]))

    # ------------------------------------------------------------------ resolve
    def test_resolve_requires_no_pending_actions(self):
        a = self.ingest()
        out = self.repo.resolve_case(a, "bob", "false_positive", "scanner is ours", "res-key-00001")
        self.assertEqual((out["outcome"], out["status"]), ("pending_actions", "escalated"))
        self.assertEqual(self.repo.get_case(a)["status"], "escalated")
        self.assertIn("case_resolve_refused", [e["event_type"] for e in self.repo.case_history(a)])
        action = self.repo.get_case(a)["actions"][0]["action_id"]
        self.assertEqual(self.repo.decide_action(action, "rejected", "alice", "not needed", "decide-key-001")["outcome"], "applied")
        self.assertEqual(self.repo.get_case(a)["status"], "resolved")          # Week 4: deciding the last proposal resolves the case
        self.assertEqual(self.repo.resolve_case(a, "bob", "false_positive", "late")["outcome"], "conflict")

    def test_resolve_happy_path_replay_and_conflict(self):
        a = self.ingest(decision="escalate", actions=[])
        out = self.repo.resolve_case(a, "bob", "false_positive", "scanner is ours", "res-key-00001")
        self.assertEqual((out["outcome"], out["status"]), ("resolved", "resolved"))
        self.assertEqual(self.repo.get_case(a)["status"], "resolved")
        self.assertEqual(self.repo.resolve_case(a, "bob", "false_positive", "scanner is ours", "res-key-00001")["outcome"], "replayed")
        self.assertEqual(self.repo.resolve_case(a, "alice", "true_positive", "other reason")["outcome"], "conflict")
        self.assertEqual(self.repo.case_notes(a)[-1]["kind"], "resolution")
        self.assertEqual(self.repo.case_feedback(a)[-1]["disposition"], "false_positive")
        self.assertEqual(self.repo.search_cases({"status": "resolved"})["total"], 1)
        kinds = [e["event_type"] for e in self.repo.case_history(a)]
        self.assertIn("case_resolved", kinds)

    def test_resolve_does_not_touch_auto_closed_or_unknown_cases_and_checks_roles(self):
        b = self.ingest(decision="auto_close", verdict="benign")
        self.assertEqual(self.repo.resolve_case(b, "bob", "true_negative", "fine")["outcome"], "conflict")
        self.assertEqual(self.repo.get_case(b)["status"], "auto_closed")
        c = self.ingest(decision="needs_review", verdict="failed")
        for who in ("carol", "erin", "ghost"):
            self.assertEqual(self.repo.resolve_case(c, who, "inconclusive", "x")["outcome"], "unauthorized")
        self.assertEqual(self.repo.resolve_case("11111111-1111-4111-8111-111111111111", "bob", "inconclusive", "x")["outcome"], "not_found")
        for args in (("weird", "r"), ("inconclusive", ""), ("inconclusive", "x" * 1001)):
            with self.assertRaises(ValueError):
                self.repo.resolve_case(c, "bob", *args)
        self.assertEqual(self.repo.resolve_case(c, "bob", "inconclusive", "reviewed by hand")["outcome"], "resolved")

    def test_resolving_never_executes_anything(self):
        a = self.ingest(decision="escalate", actions=[])
        self.repo.resolve_case(a, "bob", "true_positive", "confirmed")
        o = self.repo.overview()
        self.assertEqual((o["simulated_executions"], o["pending_actions"], o["actions_by_state"]), (0, 0, {}))

    def test_concurrent_resolves_have_one_winner(self):
        c = self.ingest(decision="needs_review", verdict="failed")
        results = []

        def go(who):
            results.append(self.repo.resolve_case(c, who, "inconclusive", "by " + who)["outcome"])
        threads = [threading.Thread(target=go, args=(w,)) for w in ("bob", "alice", "dave", "root")]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(sorted(results), ["conflict", "conflict", "conflict", "resolved"])
        self.assertEqual(len([n for n in self.repo.case_notes(c) if n["kind"] == "resolution"]), 1)

    # ------------------------------------------------------------------ numbers
    def test_overview(self):
        a, b, c = self.seed_cases()
        self.repo.add_note(a, "bob", "n")
        self.repo.add_feedback(a, "bob", "correct")
        o = self.repo.overview()
        self.assertEqual(o["cases_total"], 3)
        self.assertEqual(o["cases_last_24h"], 3)
        self.assertEqual(o["by_status"], {"escalated": 1, "auto_closed": 1, "needs_review": 1})
        self.assertEqual(o["by_routing"], {"escalate": 1, "auto_close": 1, "needs_review": 1})
        self.assertEqual(o["by_severity"].get("high"), 1)
        self.assertEqual(o["by_severity"].get("unavailable"), 1)          # the failed verdict has no severity, and is not invented
        self.assertEqual(o["pending_actions"], 1)
        self.assertEqual(o["actions_by_state"], {"pending": 1})
        self.assertEqual(o["feedback_by_assessment"], {"correct": 1})
        self.assertEqual(o["notes_total"], 1)

    def test_overview_of_an_empty_store_has_zeros_not_errors(self):
        o = self.repo.overview()
        self.assertEqual((o["cases_total"], o["pending_actions"], o["notes_total"]), (0, 0, 0))
        self.assertEqual(o["by_status"], {})

    def test_provider_outcomes_come_from_stored_evidence(self):
        self.assertEqual(self.repo.provider_outcomes(24)["by_status"], {})
        ev = [{"kind": "tool_call", "ordinal": 0, "source": "reputation_lookup", "payload": {"data": {"status": "ok", "score": 5}}, "payload_sha256": "a" * 64},
              {"kind": "tool_call", "ordinal": 1, "source": "reputation_lookup", "payload": {"error": {"code": "timeout"}}, "payload_sha256": "b" * 64}]
        p = make_payload()
        p["evidence"] = ev
        self.assertEqual(self.repo.ingest_case(p)["outcome"], "created")
        out = self.repo.provider_outcomes(24)
        self.assertEqual(out["by_status"], {"ok": 1, "timeout": 1})
        self.assertIsNotNone(out["last_lookup_at"])


class MemoryRepo5Tests(Repo5Contract, unittest.TestCase):
    def setUp(self):
        self.repo = repo5.wrap(MemoryRepository())
        seed_analysts(self.repo)
        self.repo.upsert_analyst("ghost", "viewer", active=False)

    def test_wrap_is_idempotent(self):
        self.assertIs(repo5.wrap(self.repo), self.repo)

    def test_sensor_alert_set_is_accepted_for_cases(self):
        p = make_payload(alert_set="sensor")
        out = self.repo.ingest_case(p)
        self.assertEqual(out["outcome"], "created")
        self.assertEqual(self.repo.get_case(out["case_id"])["alert_set"], "sensor")


@unittest.skipUnless(pg_enabled()[0], pg_enabled()[1])
class PgRepo5Tests(Repo5Contract, unittest.TestCase):
    def setUp(self):
        self.dbname = PgHarness5.new_database()
        self.addCleanup(PgHarness5.drop, self.dbname)
        self.repo = repo5.wrap(PgRepository(driver_for(self.dbname)))
        seed_analysts(self.repo)

    def test_sensor_alert_set_is_accepted_for_cases(self):
        p = make_payload(alert_set="sensor")
        out = self.repo.ingest_case(p)
        self.assertEqual(out["outcome"], "created")
        self.assertEqual(self.repo.get_case(out["case_id"])["alert_set"], "sensor")

    def test_sensor_events_are_append_only(self):
        self.repo.ingest_sensor_batch("bob", "sensor-lab-1", sample_records()[:2])
        for sql in ("UPDATE soc.sensor_events SET sensor = 'x'", "DELETE FROM soc.sensor_events"):
            with self.assertRaises(DbError):
                self.repo.db.run_script(sql)
        a = self.ingest()
        self.repo.add_note(a, "bob", "n")
        self.repo.add_feedback(a, "bob", "correct")
        for sql in ("TRUNCATE soc.sensor_events", "TRUNCATE soc.case_notes", "UPDATE soc.case_notes SET body = 'x'", "DELETE FROM soc.case_notes", "UPDATE soc.case_feedback SET comment = 'x'", "DELETE FROM soc.case_feedback"):
            with self.assertRaises(DbError):
                self.repo.db.run_script(sql)

    def test_a_secret_key_cannot_be_smuggled_into_a_sensor_record(self):
        r = sample_records()[0]
        bad = dict(r, record=dict(r["record"], api_key="x" * 30))
        with self.assertRaises(DbError):
            self.repo.ingest_sensor_batch("bob", "sensor-lab-1", [bad])
        self.assertEqual(self.repo.sensor_stats()["events"], 0)

    def test_a_bad_event_in_a_batch_rolls_the_whole_batch_back(self):
        recs = sample_records()[:3]
        bad = dict(recs[2], event_type="dns")
        with self.assertRaises(DbError):
            self.repo.ingest_sensor_batch("bob", "sensor-lab-1", recs[:2] + [bad])
        self.assertEqual(self.repo.sensor_stats()["events"], 0)

    def test_database_enforces_the_case_status_rules_even_for_a_direct_caller(self):
        a = self.ingest(decision="auto_close", verdict="benign")
        out = self.repo.db.query_json("SELECT to_jsonb(t) FROM (SELECT * FROM soc.w5_resolve_case(%s::uuid, 'bob', 'true_negative', 'x', NULL)) t", [a])
        self.assertEqual(out["outcome"], "conflict")


@unittest.skipUnless(pg_enabled()[0], pg_enabled()[1])
class RolePrivileges(unittest.TestCase):
    """The database, not the application, is what stops the API role writing evidence directly and the worker role writing anything new."""

    def setUp(self):
        self.dbname = PgHarness5.new_database()
        self.addCleanup(PgHarness5.drop, self.dbname)
        self.db = driver_for(self.dbname)
        self.repo = repo5.wrap(PgRepository(self.db))
        seed_analysts(self.repo)
        self.case = self.repo.ingest_case(make_payload())["case_id"]
        self.repo.ingest_sensor_batch("bob", "sensor-lab-1", sample_records()[:2])

    def denied(self, role, sql):
        with self.assertRaises(DbError) as ctx:
            self.db.run_script("SET ROLE %s;\n%s" % (role, sql))
        self.assertEqual(ctx.exception.sqlstate, "42501", "%s: %s" % (role, ctx.exception))

    def test_the_api_role_reads_but_cannot_write_the_new_tables(self):
        for t in ("sensor_events", "case_notes", "case_feedback"):
            self.assertIsNotNone(self.db.scalar("SET ROLE soc_api;\nSELECT count(*) FROM soc.%s" % t))
        for sql in ("INSERT INTO soc.case_notes (case_id, author, body) VALUES ('%s', 'x', 'y')" % self.case, "UPDATE soc.sensor_events SET sensor = 'x'", "DELETE FROM soc.case_feedback",
                    "TRUNCATE soc.sensor_events"):
            with self.subTest(sql):
                self.denied("soc_api", sql)

    def test_the_worker_role_reads_sensor_events_only(self):
        self.assertEqual(self.db.scalar("SET ROLE soc_worker;\nSELECT count(*) FROM soc.sensor_events"), "2")
        for sql in ("SELECT count(*) FROM soc.case_notes", "SELECT count(*) FROM soc.case_feedback", "INSERT INTO soc.sensor_events (sensor) VALUES ('x')", "UPDATE soc.sensor_events SET sensor = 'x'",
                    "SELECT * FROM soc.w5_add_note('%s', 'bob', 'n', NULL)" % self.case, "SELECT * FROM soc.w5_ingest_sensor_batch('{}'::jsonb)",
                    "SELECT * FROM soc.w5_resolve_case('%s', 'bob', 'true_negative', 'x', NULL)" % self.case):
            with self.subTest(sql):
                self.denied("soc_worker", sql)

    def test_the_write_functions_are_not_callable_by_public_or_the_worker(self):
        for fn in ("soc.w5_ingest_sensor_batch(jsonb)", "soc.w5_add_note(uuid,text,text,text)", "soc.w5_add_feedback(uuid,text,text,text,text,text)", "soc.w5_resolve_case(uuid,text,text,text,text)", "soc.w5_writer_role(text)"):
            self.assertEqual(self.db.scalar("SELECT has_function_privilege('public', '%s', 'EXECUTE')" % fn), "f", fn)
            self.assertEqual(self.db.scalar("SELECT has_function_privilege('soc_worker', '%s', 'EXECUTE')" % fn), "f", fn)
        self.assertEqual(self.db.scalar("SELECT has_function_privilege('soc_api', 'soc.w5_add_note(uuid,text,text,text)', 'EXECUTE')"), "t")

    def test_an_api_session_can_use_the_functions_and_the_function_checks_the_analyst_role(self):
        out = self.db.query("SET ROLE soc_api;\nSELECT outcome FROM soc.w5_add_note('%s', 'bob', 'seen in the lab', 'k-role-1')" % self.case)
        self.assertEqual(out[0][0], "created")
        out = self.db.query("SET ROLE soc_api;\nSELECT outcome FROM soc.w5_add_note('%s', 'carol', 'viewer may not', 'k-role-2')" % self.case)
        self.assertNotEqual(out[0][0], "created")          # carol is a viewer
        self.assertEqual(self.db.scalar("SELECT count(*) FROM soc.case_notes"), "1")


if __name__ == "__main__":
    unittest.main()
