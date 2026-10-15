"""One set of behavioural tests, run against the in-memory repository (always) and PostgreSQL (opt-in: WEEK4_TEST_PG=1).

If both pass, the in-memory double used by the API and graph tests is faithful to the database rules that matter:
idempotent ingest, atomic rejection of bad payloads, the approval state machine, authorisation, simulated-only execution, and concurrency.
"""
import threading
import unittest

from week4.db.drivers import DbError
from week4.db.fake import MemoryRepository
from week4.db.repository import PgRepository

from tests.week4_support import PgHarness, driver_for, make_payload, pg_enabled, seed_analysts, variant

CASE_KEYS = {"case_id", "idempotency_key", "payload_sha256", "alert_set", "alert_id", "run_name", "graph_version", "memory_mode", "alert", "provenance", "status",
             "created_at", "updated_at", "verdict", "routing", "actions"}
ACTION_KEYS = {"action_id", "case_id", "action_type", "target", "parameters", "rationale", "requires_approval", "state", "proposed_by", "created_at", "decided_at",
               "decided_by", "decision_reason"}
VERDICT_KEYS = {"case_id", "status", "is_malicious", "attack_type", "mitre_technique", "severity", "evidence_text", "prompt_version", "prompt_sha256", "model", "error_code", "created_at"}
ROUTING_KEYS = {"case_id", "decision", "risk_level", "reasons", "policy_version", "policy_sha256", "memory_raised_risk", "decided_at"}
AUDIT_KEYS = {"event_id", "occurred_at", "actor", "event_type", "entity_type", "entity_id", "case_id", "payload", "prev_hash", "event_hash"}


class RepositoryContract:
    """Mixin. Subclasses provide self.repo (a Repository with the standard analysts seeded)."""
    repo = None

    # ------------------------------------------------------------------ helpers
    def ingest(self, **kw):
        p = make_payload(**kw)
        out = self.repo.ingest_case(p)
        self.assertEqual(out["outcome"], "created", out)
        return p, out["case_id"]

    def pending_action(self, **kw):
        p, case_id = self.ingest(**kw)
        case = self.repo.get_case(case_id)
        return case, case["actions"][0]["action_id"]

    def count(self):
        return self.repo.list_cases(limit=1)["total"]

    def events(self, case_id, kind):
        return [e for e in self.repo.case_history(case_id) if e["event_type"] == kind]

    # ------------------------------------------------------------------ ingest
    def test_create_and_read_back(self):
        p, case_id = self.ingest()
        case = self.repo.get_case(case_id)
        self.assertEqual(set(case), CASE_KEYS)
        self.assertEqual(case["status"], "escalated")
        self.assertEqual(case["alert"], p["alert"])
        self.assertEqual(set(case["verdict"]), VERDICT_KEYS)
        self.assertEqual(case["verdict"]["attack_type"], "DoS Hulk")
        self.assertEqual(set(case["routing"]), ROUTING_KEYS)
        self.assertEqual(case["routing"]["reasons"], ["R1: test"])
        self.assertEqual(len(case["actions"]), 1)
        a = case["actions"][0]
        self.assertEqual(set(a), ACTION_KEYS)
        self.assertEqual((a["state"], a["requires_approval"], a["decided_by"]), ("pending", True, None))
        ev = self.repo.case_evidence(case_id)
        self.assertEqual([(e["kind"], e["ordinal"]) for e in ev], [("tool_call", 0)])
        hits = self.repo.case_memory_hits(case_id)
        self.assertEqual([(h["rank"], h["source_split"]) for h in hits], [(1, "train")])
        self.assertEqual(len(self.events(case_id, "case_ingested")), 1)
        self.assertEqual(len(self.events(case_id, "action_proposed")), 1)

    def test_status_follows_routing(self):
        _, a = self.ingest(decision="auto_close", verdict="benign")
        _, b = self.ingest(decision="needs_review", verdict="failed")
        _, c = self.ingest(decision="needs_review", verdict=None)
        self.assertEqual(self.repo.get_case(a)["status"], "auto_closed")
        self.assertEqual(self.repo.get_case(b)["status"], "needs_review")
        self.assertEqual(self.repo.get_case(c)["verdict"]["status"], "missing")
        self.assertEqual(self.repo.get_case(a)["actions"], [])

    def test_duplicate_submission_is_idempotent(self):
        p, case_id = self.ingest()
        again = self.repo.ingest_case(p)
        self.assertEqual((again["outcome"], again["case_id"]), ("duplicate", case_id))
        self.assertEqual(self.count(), 1)
        self.assertEqual(len(self.repo.get_case(case_id)["actions"]), 1)
        self.assertEqual(len(self.events(case_id, "case_duplicate")), 1)

    def test_same_key_different_payload_conflicts_and_changes_nothing(self):
        p, case_id = self.ingest()
        other = variant(p, run_name="a different run")
        out = self.repo.ingest_case(other)
        self.assertEqual((out["outcome"], out["case_id"]), ("conflict", case_id))
        self.assertEqual(self.repo.get_case(case_id)["run_name"], "unit")
        self.assertEqual(self.count(), 1)

    def test_invalid_payloads_are_reported_not_stored(self):
        base = make_payload()
        cases = {
            "missing key": {k: v for k, v in base.items() if k != "routing"},
            "unknown decision": variant(base, routing=dict(base["routing"], decision="shrug")),
            "auto_close with a malicious verdict": make_payload(decision="auto_close", verdict="malicious"),
            "auto_close with no verdict": make_payload(decision="auto_close", verdict=None),
            "auto_close with a failed verdict": make_payload(decision="auto_close", verdict="failed"),
            "actions on needs_review": make_payload(decision="needs_review", actions=[{"action_type": "isolate_host", "target": "h1", "rationale": "x"}]),
        }
        for name, payload in cases.items():
            with self.subTest(name):
                self.assertEqual(self.repo.ingest_case(payload)["outcome"], "invalid")
        self.assertEqual(self.count(), 0)

    def test_database_level_rejections_are_atomic(self):
        base = make_payload()
        bad = {
            "answer-bearing key in the alert": variant(base, alert=dict(base["alert"], label="DoS Hulk")),
            "credential-like key in the alert": variant(base, alert=dict(base["alert"], api_key="x")),
            "frozen alert set": variant(base, alert_set="frozen"),
            "ok verdict with a missing field": variant(base, verdict=dict(base["verdict"], severity=None)),
            "failed verdict carrying a field": variant(base, verdict={"status": "parse_failed", "severity": "high"}),
            "memory hit from the dev split": variant(base, memory_hits=[dict(base["memory_hits"][0], source_split="dev")]),
            "bad manifest hash": variant(base, memory_hits=[dict(base["memory_hits"][0], manifest_sha256="zz")]),
            "duplicate proposed action": variant(base, actions=base["actions"] * 2),
            "unknown action type": variant(base, actions=[dict(base["actions"][0], action_type="wipe_disk")]),
            "short idempotency key": variant(base, idempotency_key="short"),
            "empty routing reasons": variant(base, routing=dict(base["routing"], reasons=[])),
            "credential in an action": variant(base, actions=[dict(base["actions"][0], parameters={"password": "x"})]),
        }
        for name, payload in bad.items():
            with self.subTest(name):
                with self.assertRaises(DbError):
                    self.repo.ingest_case(payload)
                self.assertEqual(self.count(), 0, "a rejected payload left a case behind")
        self.assertEqual(self.repo.list_pending_actions()["total"], 0)

    # ------------------------------------------------------------------ approval
    def test_approve_applies_once_and_resolves_the_case(self):
        case, aid = self.pending_action()
        out = self.repo.decide_action(aid, "approved", "alice", "looks right", "key-approve-1")
        self.assertEqual((out["outcome"], out["state"], out["decided_by"]), ("applied", "approved", "alice"))
        got = self.repo.get_action(aid)
        self.assertEqual(got["action"]["state"], "approved")
        self.assertEqual(got["decision"]["decided_by"], "alice")
        self.assertIsNone(got["execution"])
        self.assertEqual(self.repo.get_case(case["case_id"])["status"], "resolved")
        self.assertEqual(self.repo.list_pending_actions()["total"], 0)
        self.assertEqual(len(self.events(case["case_id"], "action_approved")), 1)

    def test_reject_is_recorded_and_terminal(self):
        case, aid = self.pending_action()
        self.assertEqual(self.repo.decide_action(aid, "rejected", "alice", "false positive", "key-reject-1")["outcome"], "applied")
        self.assertEqual(self.repo.get_action(aid)["action"]["state"], "rejected")
        late = self.repo.decide_action(aid, "approved", "dave", "changed my mind", "key-approve-2")
        self.assertEqual((late["outcome"], late["state"]), ("conflict", "rejected"))
        self.assertEqual(self.repo.get_action(aid)["action"]["state"], "rejected")

    def test_replay_returns_the_stored_result_without_a_second_decision(self):
        case, aid = self.pending_action()
        first = self.repo.decide_action(aid, "approved", "alice", "ok", "key-same-0001")
        again = self.repo.decide_action(aid, "approved", "alice", "ok", "key-same-0001")
        self.assertEqual((first["outcome"], again["outcome"]), ("applied", "replayed"))
        self.assertEqual(again["state"], "approved")
        self.assertEqual(len(self.events(case["case_id"], "action_approved")), 1)

    def test_conflicting_attempts_never_change_a_decided_action(self):
        case, aid = self.pending_action()
        self.repo.decide_action(aid, "approved", "alice", "ok", "key-first-001")
        for who, decision, key in (("alice", "rejected", "key-first-001"), ("alice", "rejected", "key-other-002"), ("dave", "approved", "key-first-001"), ("dave", "approved", "key-dave-0003")):
            with self.subTest((who, decision, key)):
                out = self.repo.decide_action(aid, decision, who, "again", key)
                self.assertEqual(out["outcome"], "conflict")
                self.assertEqual(self.repo.get_action(aid)["action"]["state"], "approved")
                self.assertEqual(self.repo.get_action(aid)["action"]["decided_by"], "alice")
        self.assertEqual(len(self.events(case["case_id"], "action_approved")), 1)

    def test_key_reused_for_a_different_action_conflicts(self):
        _, a1 = self.pending_action()
        _, a2 = self.pending_action()
        self.assertEqual(self.repo.decide_action(a1, "approved", "alice", "ok", "key-shared-01")["outcome"], "applied")
        self.assertEqual(self.repo.decide_action(a2, "approved", "alice", "ok", "key-shared-01")["outcome"], "conflict")
        self.assertEqual(self.repo.get_action(a2)["action"]["state"], "pending")

    def test_only_active_approvers_can_decide(self):
        case, aid = self.pending_action()
        for who in ("bob", "carol", "erin", "mallory", "", None):
            with self.subTest(who):
                out = self.repo.decide_action(aid, "approved", who, "please", "key-%s-0001" % (who or "none"))
                self.assertIn(out["outcome"], ("unauthorized", "invalid"))
                self.assertEqual(self.repo.get_action(aid)["action"]["state"], "pending")
        self.assertGreaterEqual(len(self.events(case["case_id"], "approval_denied")), 4)
        self.assertEqual(self.repo.decide_action(aid, "approved", "root", "admin ok", "key-root-0001")["outcome"], "applied")

    def test_invalid_decisions_and_missing_actions(self):
        _, aid = self.pending_action()
        for decision, who, reason, key in (("maybe", "alice", "r", "key-12345678"), ("approved", "alice", "  ", "key-12345678"), ("approved", "alice", None, "key-12345678"),
                                           ("approved", "alice", "r", "short")):
            with self.subTest((decision, reason, key)):
                self.assertEqual(self.repo.decide_action(aid, decision, who, reason, key)["outcome"], "invalid")
        self.assertEqual(self.repo.get_action(aid)["action"]["state"], "pending")
        self.assertEqual(self.repo.decide_action("00000000-0000-4000-8000-000000000000", "approved", "alice", "r", "key-12345678")["outcome"], "not_found")
        with self.assertRaises(ValueError):
            self.repo.decide_action("not-a-uuid", "approved", "alice", "r", "key-12345678")
        self.assertIsNone(self.repo.get_action("00000000-0000-4000-8000-000000000000"))
        self.assertIsNone(self.repo.get_case("00000000-0000-4000-8000-000000000000"))

    def test_case_resolves_only_when_every_proposal_is_decided(self):
        acts = [{"action_type": "block_source_ip", "target": "198.51.100.7", "rationale": "r"}, {"action_type": "increase_monitoring", "target": "198.51.100.7", "rationale": "r"}]
        _, case_id = self.ingest(actions=acts)
        ids = [a["action_id"] for a in self.repo.get_case(case_id)["actions"]]
        self.repo.decide_action(ids[0], "approved", "alice", "ok", "key-multi-001")
        self.assertEqual(self.repo.get_case(case_id)["status"], "escalated")
        self.repo.decide_action(ids[1], "rejected", "alice", "no", "key-multi-002")
        self.assertEqual(self.repo.get_case(case_id)["status"], "resolved")

    # ------------------------------------------------------------------ execution (simulated only)
    def test_rejected_and_pending_actions_never_execute(self):
        case, aid = self.pending_action()
        out = self.repo.simulate_execution(aid, "alice")
        self.assertEqual((out["outcome"], out["state"]), ("not_approved", "pending"))
        self.repo.decide_action(aid, "rejected", "alice", "no", "key-reject-ex1")
        out = self.repo.simulate_execution(aid, "alice")
        self.assertEqual((out["outcome"], out["state"]), ("not_approved", "rejected"))
        self.assertIsNone(self.repo.get_action(aid)["execution"])
        self.assertEqual(len(self.events(case["case_id"], "execution_blocked")), 2)

    def test_approved_action_is_executed_in_simulation_only_and_once(self):
        case, aid = self.pending_action()
        self.repo.decide_action(aid, "approved", "alice", "ok", "key-approve-ex")
        first = self.repo.simulate_execution(aid, "alice")
        second = self.repo.simulate_execution(aid, "dave")
        self.assertEqual(first["outcome"], "simulated")
        self.assertEqual((second["outcome"], second["execution_id"]), ("already_simulated", first["execution_id"]))
        ex = self.repo.get_action(aid)["execution"]
        self.assertEqual(ex["mode"], "simulated")
        self.assertTrue(ex["result"]["simulated"])
        self.assertEqual(len(self.events(case["case_id"], "execution_simulated")), 1)

    def test_unauthorized_callers_cannot_execute_even_an_approved_action(self):
        _, aid = self.pending_action()
        self.repo.decide_action(aid, "approved", "alice", "ok", "key-approve-ux")
        for who in ("bob", "carol", "erin", "mallory", None):
            with self.subTest(who):
                self.assertEqual(self.repo.simulate_execution(aid, who)["outcome"], "unauthorized")
        self.assertIsNone(self.repo.get_action(aid)["execution"])
        self.assertEqual(self.repo.simulate_execution("00000000-0000-4000-8000-000000000000", "alice")["outcome"], "not_found")

    # ------------------------------------------------------------------ queries
    def test_pagination_filters_and_totals(self):
        ids = [self.ingest(decision="escalate")[1] for _ in range(3)] + [self.ingest(decision="auto_close", verdict="benign")[1] for _ in range(2)]
        page = self.repo.list_cases(limit=2, offset=0)
        self.assertEqual((page["total"], len(page["items"]), page["limit"], page["offset"]), (5, 2, 2, 0))
        seen = [c["case_id"] for c in self.repo.list_cases(limit=2, offset=0)["items"] + self.repo.list_cases(limit=2, offset=2)["items"] + self.repo.list_cases(limit=2, offset=4)["items"]]
        self.assertEqual(sorted(seen), sorted(ids))
        self.assertEqual(len(set(seen)), 5)
        self.assertEqual(self.repo.list_cases(status="auto_closed")["total"], 2)
        self.assertEqual(self.repo.list_cases(status="escalated")["items"][0]["pending_actions"], 1)
        self.assertEqual(self.repo.list_cases(memory_mode="on")["total"], 0)
        self.assertEqual(self.repo.list_cases(offset=99)["items"], [])
        self.assertEqual(self.repo.list_pending_actions(limit=2)["total"], 3)
        for bad in ({"limit": 0}, {"limit": 201}, {"limit": -1}, {"offset": -1}, {"limit": "5"}, {"status": "weird"}, {"memory_mode": "maybe"}, {"alert_set": "frozen"}):
            with self.subTest(bad):
                with self.assertRaises(ValueError):
                    self.repo.list_cases(**bad)

    def test_audit_history_and_chain(self):
        case, aid = self.pending_action()
        self.repo.decide_action(aid, "approved", "alice", "ok", "key-audit-001")
        self.repo.simulate_execution(aid, "alice")
        hist = self.repo.case_history(case["case_id"])
        self.assertEqual([e["event_type"] for e in hist], ["action_proposed", "case_ingested", "action_approved", "execution_simulated"])
        self.assertEqual(set(hist[0]), AUDIT_KEYS)
        self.assertEqual([e["event_type"] for e in self.repo.action_history(aid)], ["action_approved", "execution_simulated"])
        self.assertEqual(self.repo.verify_audit_chain(), {"ok": True, "first_bad_event_id": None})
        text = repr(hist).lower()
        for word in ("password", "secret", "token"):
            self.assertNotIn(word, text)

    # ------------------------------------------------------------------ concurrency
    def _race(self, jobs):
        results, barrier = [None] * len(jobs), threading.Barrier(len(jobs))

        def run(i, job):
            barrier.wait()
            try:
                results[i] = job()
            except Exception as error:   # surfaced by the assertions below
                results[i] = error
        threads = [threading.Thread(target=run, args=(i, j)) for i, j in enumerate(jobs)]
        [t.start() for t in threads]
        [t.join(60) for t in threads]
        return results

    def test_concurrent_conflicting_decisions_have_exactly_one_winner(self):
        case, aid = self.pending_action()
        jobs = [(lambda i=i: self.repo.decide_action(aid, "approved" if i % 2 == 0 else "rejected", "alice" if i % 3 else "dave", "race %d" % i, "key-race-%04d" % i)) for i in range(8)]
        results = self._race(jobs)
        for r in results:
            self.assertIsInstance(r, dict, r)
        outcomes = sorted(r["outcome"] for r in results)
        self.assertEqual(outcomes.count("applied"), 1, outcomes)
        self.assertEqual(outcomes.count("conflict"), 7, outcomes)
        winner = next(r for r in results if r["outcome"] == "applied")
        final = self.repo.get_action(aid)
        self.assertEqual((final["action"]["state"], final["action"]["decided_by"]), (winner["state"], winner["decided_by"]))
        self.assertEqual(len(self.events(case["case_id"], "action_approved")) + len(self.events(case["case_id"], "action_rejected")), 1)
        self.assertEqual(self.repo.verify_audit_chain()["ok"], True)

    def test_concurrent_identical_requests_apply_once_and_replay_the_rest(self):
        _, aid = self.pending_action()
        results = self._race([(lambda: self.repo.decide_action(aid, "approved", "alice", "same", "key-same-race")) for _ in range(5)])
        for r in results:
            self.assertIsInstance(r, dict, r)
        self.assertEqual(sorted(r["outcome"] for r in results), ["applied", "replayed", "replayed", "replayed", "replayed"])

    def test_concurrent_duplicate_ingest_creates_one_case(self):
        p = make_payload()
        results = self._race([(lambda: self.repo.ingest_case(p)) for _ in range(6)])
        for r in results:
            self.assertIsInstance(r, dict, r)
        self.assertEqual(sorted(r["outcome"] for r in results), ["created"] + ["duplicate"] * 5)
        self.assertEqual(len({r["case_id"] for r in results}), 1)
        self.assertEqual(self.count(), 1)


class MemoryRepositoryContract(RepositoryContract, unittest.TestCase):
    def setUp(self):
        self.repo = MemoryRepository()
        seed_analysts(self.repo)


_PG_OK, _PG_WHY = pg_enabled()


@unittest.skipUnless(_PG_OK, _PG_WHY)
class PgRepositoryContract(RepositoryContract, unittest.TestCase):
    def setUp(self):
        self.dbname = PgHarness.new_database()
        self.addCleanup(PgHarness.drop, self.dbname)
        self.repo = PgRepository(driver_for(self.dbname))
        seed_analysts(self.repo)


if __name__ == "__main__":
    unittest.main()
