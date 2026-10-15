"""Risk policy (pure) and approval service (in-memory repository)."""
import copy
import itertools
import json
import os
import shutil
import tempfile
import unittest

from week4 import policy as P
from week4.approval import ApprovalService, AuthorizationError, Principal, SimulatedExecutor
from week4.db.fake import MemoryRepository

from tests.week4_support import make_payload, seed_analysts


def inputs(**kw):
    x = {"verdict_status": "ok", "is_malicious": False, "attack_type": "BENIGN", "severity": "none", "detector_score": 0.1,
         "upstream": {"traffic": "ok", "beacon": "not_run", "enrichment": "ok"}, "graph_errors": 0, "memory_enabled": False, "memory": None,
         "src_ip": "192.0.2.9", "dst_ip": "198.51.100.1", "dst_port": 80}
    x.update(kw)
    return x


def memory(counts, status="ok"):
    return {"status": status, "label_counts": counts}


class PolicyFileTests(unittest.TestCase):
    def setUp(self):
        self.policy = P.load_policy()

    def test_shipped_policy_loads_and_is_hashed(self):
        self.assertEqual(self.policy.version, "risk-policy-v1")
        self.assertRegex(self.policy.sha256, r"^[0-9a-f]{64}$")

    def test_hash_ignores_line_endings(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "p.json")
        text = json.dumps(self.policy.data, indent=2)
        with open(path, "wb") as fh:
            fh.write(text.replace("\n", "\r\n").encode())
        crlf = P.load_policy(path).sha256
        with open(path, "wb") as fh:
            fh.write(text.encode())
        self.assertEqual(crlf, P.load_policy(path).sha256)

    def test_missing_unreadable_or_invalid_policies_fail_closed(self):
        with self.assertRaises(P.PolicyError):
            P.load_policy("/nonexistent/policy.json")
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)

        def write(obj, raw=None):
            path = os.path.join(d, "p.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(raw if raw is not None else json.dumps(obj))
            return path
        with self.assertRaises(P.PolicyError):
            P.load_policy(write(None, raw="{not json"))
        base = copy.deepcopy(self.policy.data)
        cases = {}
        for name, edit in {
            "extra key": lambda p: p.update(surprise=1),
            "missing section": lambda p: p.pop("memory"),
            "ceiling above 1": lambda p: p["auto_close"].update(max_detector_score=1.5),
            "ceiling is bool": lambda p: p["auto_close"].update(max_detector_score=True),
            "failed traffic allowed": lambda p: p["auto_close"].update(require_traffic_status=["ok", "failed"]),
            "memory may lower": lambda p: p["memory"].update(can_only_raise_risk=False),
            "unknown action": lambda p: p["containment_proposals"]["by_attack_type"].update(PortScan="format_disk"),
            "unknown attack": lambda p: p["containment_proposals"]["by_attack_type"].update(Nonsense="block_source_ip"),
            "benign mapped": lambda p: p["containment_proposals"]["by_attack_type"].update(BENIGN="block_source_ip"),
            "negative errors": lambda p: p["auto_close"].update(max_graph_errors=-1),
        }.items():
            p = copy.deepcopy(base)
            edit(p)
            cases[name] = p
        for name, p in cases.items():
            with self.subTest(name):
                with self.assertRaises(P.PolicyError):
                    P.load_policy(write(p))

    def test_routing_without_a_policy_is_refused(self):
        with self.assertRaises(P.PolicyError):
            P.decide(None, inputs())


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.policy = P.load_policy()

    def route(self, **kw):
        return P.decide(self.policy, inputs(**kw))

    def test_clean_benign_case_is_auto_closed_with_reasons(self):
        r = self.route()
        self.assertEqual((r["decision"], r["risk_level"], r["memory_raised_risk"]), ("auto_close", "low", False))
        self.assertTrue(r["reasons"] and r["reasons"][0].startswith("R9"))
        self.assertEqual((r["policy_version"], r["policy_sha256"]), (self.policy.version, self.policy.sha256))

    def test_malicious_verdicts_escalate_with_risk_from_severity(self):
        for sev, risk in (("critical", "high"), ("high", "high"), ("medium", "medium"), ("low", "low")):
            r = self.route(is_malicious=True, attack_type="PortScan", severity=sev)
            self.assertEqual((r["decision"], r["risk_level"]), ("escalate", risk), sev)

    def test_unusable_verdicts_go_to_a_person_never_auto_close(self):
        for status in ("parse_failed", "model_error", "missing"):
            r = self.route(verdict_status=status, is_malicious=None, attack_type=None, severity=None)
            self.assertEqual((r["decision"], r["risk_level"]), ("needs_review", "unknown"), status)
            self.assertTrue(r["reasons"][0].startswith("R1"))

    def test_each_blocker_prevents_auto_close(self):
        blockers = {
            "no score": dict(detector_score=None), "nan score": dict(detector_score=float("nan")), "bool score": dict(detector_score=True),
            "score above ceiling": dict(detector_score=0.9),
            "traffic failed": dict(upstream={"traffic": "failed", "beacon": "not_run", "enrichment": "ok"}),
            "traffic partial": dict(upstream={"traffic": "partial", "beacon": "not_run", "enrichment": "ok"}),
            "beacon failed": dict(upstream={"traffic": "ok", "beacon": "failed", "enrichment": "ok"}),
            "enrichment partial": dict(upstream={"traffic": "ok", "beacon": "ok", "enrichment": "partial"}),
            "unknown upstream": dict(upstream={}),
            "graph errors": dict(graph_errors=1),
            "memory on but failed": dict(memory_enabled=True, memory={"status": "error"}),
            "memory on but absent": dict(memory_enabled=True, memory=None),
        }
        for name, kw in blockers.items():
            with self.subTest(name):
                self.assertNotEqual(self.route(**kw)["decision"], "auto_close")

    def test_ceiling_is_inclusive(self):
        self.assertEqual(self.route(detector_score=self.policy["auto_close"]["max_detector_score"])["decision"], "auto_close")

    def test_memory_neighbours_that_are_attacks_escalate_a_benign_verdict(self):
        r = self.route(memory_enabled=True, memory=memory({"PortScan": 4, "BENIGN": 1}))
        self.assertEqual((r["decision"], r["risk_level"], r["memory_raised_risk"]), ("escalate", "medium", True))
        self.assertTrue(any(x.startswith("R8 ") for x in r["reasons"]) and any(x.startswith("R8b") for x in r["reasons"]))

    def test_memory_thresholds_are_respected(self):
        few = self.route(memory_enabled=True, memory=memory({"PortScan": 2}))     # fewer hits than min_hits
        split = self.route(memory_enabled=True, memory=memory({"PortScan": 2, "BENIGN": 3}))   # 40% attacks < 60%
        for r in (few, split):
            self.assertEqual((r["decision"], r["memory_raised_risk"]), ("auto_close", False))

    def test_memory_never_lowers_a_decision_or_closes_a_case(self):
        """Over a grid of inputs, adding a memory result (any content) never produces LESS caution than the same case without memory, and never turns a non-auto_close into auto_close."""
        verdicts = [dict(verdict_status="ok", is_malicious=False, attack_type="BENIGN", severity="none"),
                    dict(verdict_status="ok", is_malicious=True, attack_type="DoS Hulk", severity="high"),
                    dict(verdict_status="parse_failed", is_malicious=None, attack_type=None, severity=None)]
        scores = [0.1, 0.9, None]
        ups = [{"traffic": "ok", "beacon": "not_run", "enrichment": "ok"}, {"traffic": "failed", "beacon": "not_run", "enrichment": "ok"}]
        mems = [None, {"status": "error"}, {"status": "ok", "label_counts": {"BENIGN": 5}}, {"status": "ok", "label_counts": {"Bot": 5}}, {"status": "empty", "label_counts": {}}]
        for v, s, u, m in itertools.product(verdicts, scores, ups, mems):
            base = P.decide(self.policy, inputs(detector_score=s, upstream=u, **v))
            with_memory = P.decide(self.policy, inputs(detector_score=s, upstream=u, memory_enabled=True, memory=m, **v))
            self.assertGreaterEqual(P.CAUTION[with_memory["decision"]], P.CAUTION[base["decision"]], (v, s, u, m))
            if base["decision"] != "auto_close":
                self.assertNotEqual(with_memory["decision"], "auto_close")

    def test_memory_unavailable_blocks_auto_close_only_when_memory_is_on(self):
        self.assertEqual(self.route(memory_enabled=False, memory={"status": "error"})["decision"], "auto_close")
        self.assertEqual(self.route(memory_enabled=True, memory={"status": "error"})["decision"], "needs_review")

    def test_memory_cannot_change_a_malicious_verdict(self):
        a = self.route(is_malicious=True, attack_type="Bot", severity="high")
        b = self.route(is_malicious=True, attack_type="Bot", severity="high", memory_enabled=True, memory=memory({"BENIGN": 9}))
        self.assertEqual((a["decision"], a["risk_level"]), (b["decision"], b["risk_level"]))

    def test_conflicting_escalation_and_gap_reasons_are_all_listed(self):
        r = self.route(detector_score=0.9, graph_errors=2)
        self.assertEqual(r["decision"], "escalate")
        codes = {x.split()[0] for x in r["reasons"]}
        self.assertTrue({"R4", "R6"} <= codes)


class ProposalTests(unittest.TestCase):
    def setUp(self):
        self.policy = P.load_policy()

    def propose(self, **kw):
        x = inputs(is_malicious=True, attack_type="DoS Hulk", severity="high", **kw)
        return P.propose_actions(self.policy, x, P.decide(self.policy, x))

    def test_high_severity_proposes_the_mapped_containment(self):
        acts = self.propose()
        self.assertEqual([(a["action_type"], a["target"]) for a in acts], [("rate_limit_source", "192.0.2.9")])
        self.assertIn("never executed", acts[0]["rationale"])

    def test_lower_severity_proposes_monitoring_only(self):
        x = inputs(is_malicious=True, attack_type="PortScan", severity="medium")
        self.assertEqual(P.propose_actions(self.policy, x, P.decide(self.policy, x))[0]["action_type"], "increase_monitoring")

    def test_no_proposals_unless_escalated_and_malicious_and_complete(self):
        benign = inputs()
        self.assertEqual(P.propose_actions(self.policy, benign, P.decide(self.policy, benign)), [])
        raised = inputs(memory_enabled=True, memory=memory({"Bot": 5}))
        self.assertEqual(P.decide(self.policy, raised)["decision"], "escalate")
        self.assertEqual(P.propose_actions(self.policy, raised, P.decide(self.policy, raised)), [], "memory alone must never create a containment proposal")
        failed = inputs(verdict_status="parse_failed", is_malicious=None, attack_type=None, severity=None)
        self.assertEqual(P.propose_actions(self.policy, failed, P.decide(self.policy, failed)), [])
        nosrc = inputs(is_malicious=True, attack_type="Bot", severity="high", src_ip=None)
        self.assertEqual(P.propose_actions(self.policy, nosrc, P.decide(self.policy, nosrc)), [])

    def test_every_proposal_is_an_allowed_action_type(self):
        for attack in self.policy["containment_proposals"]["by_attack_type"]:
            for sev in ("low", "high", "critical"):
                x = inputs(is_malicious=True, attack_type=attack, severity=sev)
                for a in P.propose_actions(self.policy, x, P.decide(self.policy, x)):
                    self.assertIn(a["action_type"], P.ACTION_TYPES)


class StateInputTests(unittest.TestCase):
    def test_inputs_from_a_state_and_route_case(self):
        policy = P.load_policy()
        state = {"alert": {"alert_id": "DEV-1", "src_ip": "192.0.2.9", "dst_ip": "198.51.100.1", "dst_port": 80, "detector_score": 0.2},
                 "verdict": {"status": "ok", "verdict": {"is_malicious": False, "attack_type": "BENIGN", "mitre_technique": "NONE", "severity": "none", "evidence": "x"},
                             "upstream": {"traffic": "ok", "beacon": "not_run", "enrichment": "ok", "errors": 0}},
                 "errors": [], "memory_enabled": False, "memory": None}
        out = P.route_case(policy, state)
        self.assertEqual(out["routing"]["decision"], "auto_close")
        state["verdict"] = None
        self.assertEqual(P.route_case(policy, state)["routing"]["decision"], "needs_review")
        state = {"alert": {}, "errors": None}
        self.assertEqual(P.route_case(policy, state)["routing"]["decision"], "needs_review")


class ApprovalServiceTests(unittest.TestCase):
    def setUp(self):
        self.repo = MemoryRepository()
        seed_analysts(self.repo)
        self.svc = ApprovalService(self.repo)
        out = self.repo.ingest_case(make_payload())
        self.aid = self.repo.get_case(out["case_id"])["actions"][0]["action_id"]

    def test_principal_comes_from_the_store(self):
        self.assertTrue(self.svc.principal("alice").can_decide())
        self.assertFalse(self.svc.principal("bob").can_decide())
        self.assertTrue(self.svc.principal("carol").can_read())
        self.assertFalse(self.svc.principal("erin").can_decide())
        for bad in ("nobody", "", None, "x" * 100, "a b"):
            self.assertIsNone(self.svc.principal(bad))

    def test_unauthorised_callers_are_stopped_before_the_store(self):
        before = len(self.repo.audit_events)
        for who in (self.svc.principal("bob"), self.svc.principal("carol"), self.svc.principal("erin"), None, "alice", Principal("alice", "approver", active=False)):
            with self.assertRaises(AuthorizationError):
                self.svc.decide(who, self.aid, "approved", "ok", "key-12345678")
            with self.assertRaises(AuthorizationError):
                self.svc.execute_simulated(who, self.aid)
        self.assertEqual(len(self.repo.audit_events), before)
        self.assertEqual(self.repo.get_action(self.aid)["action"]["state"], "pending")

    def test_approve_then_simulate_and_reject_blocks_execution(self):
        alice = self.svc.principal("alice")
        self.assertEqual(self.svc.decide(alice, self.aid, "approved", "ok", "key-12345678")["outcome"], "applied")
        self.assertEqual(self.svc.execute_simulated(alice, self.aid)["outcome"], "simulated")
        out = self.repo.ingest_case(make_payload())
        other = self.repo.get_case(out["case_id"])["actions"][0]["action_id"]
        self.svc.decide(alice, other, "rejected", "no", "key-87654321")
        self.assertEqual(self.svc.execute_simulated(alice, other)["outcome"], "not_approved")

    def test_overlong_reason_is_refused(self):
        with self.assertRaises(ValueError):
            self.svc.decide(self.svc.principal("alice"), self.aid, "approved", "x" * 1001, "key-12345678")

    def test_only_a_simulated_executor_is_accepted(self):
        class Live:
            mode = "live"
        with self.assertRaises(ValueError):
            ApprovalService(self.repo, executor=Live())
        self.assertEqual(SimulatedExecutor.mode, "simulated")


if __name__ == "__main__":
    unittest.main()
