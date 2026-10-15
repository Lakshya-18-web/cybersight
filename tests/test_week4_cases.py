"""Case payloads built from real graph-v2 states, ingested into the in-memory repository (always) and PostgreSQL (opt-in)."""
import copy
import json
import unittest

from week4 import cases as C, policy as P
from week4.db.drivers import DbError
from week4.db.fake import MemoryRepository
from week4.db.repository import PgRepository

from tests.test_week3_day5 import GOOD, GOOD_BENIGN, Script, reply
from tests.test_week4_graph import Base, alert_with
from tests.week4_support import PgHarness, driver_for, pg_enabled, seed_analysts

_PG_OK, _PG_WHY = pg_enabled()


class PayloadMaker:
    def make(self, obj=GOOD, memory_enabled=True, run="run-a", **alert_kw):
        final = self.v2(Script(reply(obj)), alert=alert_with(**alert_kw), memory_enabled=memory_enabled)
        routed = P.route_case(self.policy, final)
        return final, routed, C.build_case_payload(final, routed, run, model="mock-model")


class CaseBuildTests(PayloadMaker, Base):

    def test_payload_shape_and_content(self):
        final, routed, p = self.make()
        self.assertEqual((p["alert_set"], p["memory_mode"], p["graph_version"], p["run_name"]), ("dev", "on", "v2.0", "run-a"))
        self.assertEqual(p["idempotency_key"], "run-a:dev:%s:on" % final["alert_id"])
        self.assertEqual(p["routing"]["decision"], "escalate")
        self.assertEqual(p["verdict"]["status"], "ok")
        self.assertEqual(p["verdict"]["prompt_version"], "agent_v2_memory")
        self.assertEqual(p["verdict"]["model"], "mock-model")
        self.assertEqual(len(p["memory_hits"]), 5)
        self.assertEqual(p["actions"][0]["action_type"], "increase_monitoring")
        kinds = {e["kind"] for e in p["evidence"]}
        self.assertTrue({"tool_call", "specialist_finding", "memory_summary", "routing_step"} <= kinds)
        self.assertEqual(len({(e["kind"], e["ordinal"]) for e in p["evidence"]}), len(p["evidence"]))
        self.assertEqual(p["provenance"]["memory"]["manifest_sha256"], self.memory_store.manifest_sha256)
        self.assertEqual(p["provenance"]["policy_sha256"], self.policy.sha256)

    def test_alert_is_label_free_and_nothing_credential_like_is_present(self):
        _, _, p = self.make()
        self.assertFalse({"label", "Label", "is_attack", "source_file", "original_row"} & set(p["alert"]))
        text = json.dumps(p).lower()
        for word in ("password", "api_key", "apikey", "secret", "authorization", "bearer"):
            self.assertNotIn(word, text)

    def test_hash_is_stable_and_content_sensitive_and_ignores_the_operator(self):
        final, routed, p = self.make()
        again = C.build_case_payload(final, routed, "run-a", model="mock-model", ingested_by="someone-else")
        self.assertEqual(p["payload_sha256"], again["payload_sha256"])
        changed = C.build_case_payload(final, routed, "run-a", model="another-model")
        self.assertNotEqual(p["payload_sha256"], changed["payload_sha256"])

    def test_memory_off_case_has_no_memory_evidence(self):
        _, _, p = self.make(memory_enabled=False)
        self.assertEqual((p["memory_mode"], p["memory_hits"]), ("off", []))
        self.assertNotIn("memory_summary", {e["kind"] for e in p["evidence"]})

    def test_auto_close_and_review_cases(self):
        _, _, p = self.make(GOOD_BENIGN, memory_enabled=False, detector_score=0.1)
        self.assertEqual((p["routing"]["decision"], p["actions"]), ("auto_close", []))
        final = self.v2(Script("not json"), memory_enabled=True)
        p2 = C.build_case_payload(final, P.route_case(self.policy, final), "run-a")
        self.assertEqual((p2["routing"]["decision"], p2["verdict"]["status"], p2["actions"]), ("needs_review", "parse_failed", []))
        self.assertNotIn("is_malicious", p2["verdict"])

    def test_bad_inputs_fail_before_anything_is_stored(self):
        final, routed, _ = self.make()
        with self.assertRaises(C.CaseBuildError):
            C.build_case_payload(final, routed, "run-a", alert_set="frozen")
        with self.assertRaises(C.CaseBuildError):
            C.build_case_payload(final, {}, "run-a")
        bad = copy.deepcopy(final)
        bad["evidence"][0]["data"] = {"x": float("nan")}
        with self.assertRaises(C.CaseBuildError):
            C.build_case_payload(bad, routed, "run-a")

    def test_long_keys_are_shortened_deterministically(self):
        k = C.idempotency_key("r" * 300, "dev", "DEV-1", "on")
        self.assertLessEqual(len(k), 200)
        self.assertEqual(k, C.idempotency_key("r" * 300, "dev", "DEV-1", "on"))

    def test_ingest_into_the_in_memory_repository_and_replay(self):
        repo = MemoryRepository()
        seed_analysts(repo)
        _, _, p = self.make()
        first = repo.ingest_case(p)
        self.assertEqual(first["outcome"], "created")
        self.assertEqual(repo.ingest_case(p)["outcome"], "duplicate")
        case = repo.get_case(first["case_id"])
        self.assertEqual((case["status"], len(case["actions"]), len(repo.case_memory_hits(first["case_id"]))), ("escalated", 1, 5))


@unittest.skipUnless(_PG_OK, _PG_WHY)
class CasePgTests(PayloadMaker, Base):
    def test_payloads_from_real_states_are_accepted_by_postgresql(self):
        dbname = PgHarness.new_database()
        self.addCleanup(PgHarness.drop, dbname)
        repo = PgRepository(driver_for(dbname))
        seed_analysts(repo)
        for obj, kw in ((GOOD, {}), (GOOD_BENIGN, {"detector_score": 0.1}), (GOOD_BENIGN, {"detector_score": 0.9})):
            for mem in (True, False):
                _, _, p = self.make(obj, memory_enabled=mem, run="pg-run", **kw)
                p["idempotency_key"] += ":%s:%s" % (obj["is_malicious"], kw.get("detector_score"))
                out = repo.ingest_case(p)
                self.assertEqual(out["outcome"], "created", out)
        self.assertEqual(repo.list_cases()["total"], 6)
        self.assertTrue(repo.verify_audit_chain()["ok"])



if __name__ == "__main__":
    unittest.main()
