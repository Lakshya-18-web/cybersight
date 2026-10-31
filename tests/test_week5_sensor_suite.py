"""The labelled sensor evaluation: the scenario set is well-formed, the run is reproducible, the metrics are computed correctly, invariants are enforced, and the report cannot be mistaken for real performance."""
import json
import os
import tempfile
import unittest

from week5 import eve
from week5.evalrun import sensor_scenarios as SC, sensor_suite as SS

SMALL = {f: 1 for f in SC.FAMILIES}


def rec(label, flagged_decision, sev=2, scenario="x", decision_before=None, status="ok", mal=None, family="f", cls="C"):
    return {"scenario": scenario, "family": family, "label": label, "true_class": cls, "suricata_severity": sev, "job_status": "succeeded", "attempts": 1, "wall_seconds": 0.01,
            "case": {"decision": flagged_decision, "risk_level": "medium", "decision_before_evidence": decision_before or flagged_decision, "evidence_rules": [], "verdict_status": status,
                     "is_malicious": mal, "attack_type": None, "proposed_actions": 0, "approved_or_executed_actions": 0}}


class Scenarios(unittest.TestCase):
    def test_set_is_deterministic_and_labelled_by_construction(self):
        a, b = SC.build(), SC.build()
        self.assertEqual(SC.sha256(a), SC.sha256(b))
        self.assertEqual(sum(1 for s in a if s["label"] == "attack"), 30)
        self.assertEqual(sum(1 for s in a if s["label"] == "benign"), 26)
        self.assertEqual(len({s["scenario"] for s in a}), len(a))
        self.assertNotEqual(SC.sha256(SC.build({"ssh_brute": 2})), SC.sha256(a))

    def test_each_scenario_is_flows_then_one_alert_and_passes_the_real_adapter(self):
        for s in SC.build(SMALL):
            kinds = [e["event_type"] for e in s["events"]]
            self.assertEqual(kinds.count("alert"), 1, s["scenario"])
            self.assertEqual(kinds[-1], "alert")
            records, ignored, rejected = eve.normalise_batch(s["events"], "eval-sensor-1")
            self.assertEqual((ignored, rejected), ({}, []), s["scenario"])

    def test_no_real_addresses(self):
        import ipaddress
        nets = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "10.0.0.0/8")]
        for s in SC.build():
            for e in s["events"]:
                for k in ("src_ip", "dest_ip"):
                    self.assertTrue(any(ipaddress.ip_address(e[k]) in n for n in nets), e[k])

    def test_every_family_has_a_model_reply_for_every_profile_that_validates(self):
        import verdict_parser
        for fam in SC.FAMILIES:
            for profile in SS.PROFILES:
                for aid in ("EVE-a", "EVE-b", "EVE-c", "EVE-d"):
                    text = json.dumps(SC.model_reply(fam, profile, aid))
                    self.assertTrue(verdict_parser.parse_verdict(text).ok, (fam, profile, text))

    def test_the_hostile_signature_family_really_carries_the_instruction_text(self):
        s = [x for x in SC.build(SMALL) if x["family"] == "benign_hostile_signature_text"][0]
        self.assertIn("ignore previous instructions", s["events"][-1]["alert"]["signature"])


class Metrics(unittest.TestCase):
    def test_confusion_arithmetic(self):
        rows = [rec("attack", "escalate", mal=True, scenario="a1"), rec("attack", "auto_close", mal=False, scenario="a2"), rec("benign", "needs_review", mal=False, scenario="b1"),
                rec("benign", "auto_close", mal=False, scenario="b2", sev=3)]
        m = SS.confusion(rows, "full_pipeline")
        self.assertEqual((m["tp"], m["fp"], m["fn"], m["tn"]), (1, 1, 1, 1))
        self.assertEqual((m["precision"], m["recall"], m["specificity"], m["false_positive_rate"], m["false_negative_rate"]), (0.5, 0.5, 0.5, 0.5, 0.5))
        self.assertEqual((m["f1"], m["incorrect_closures_of_attacks"], m["missed_attack_scenarios"]), (0.5, 1, ["a2"]))
        self.assertEqual(SS.confusion(rows, "sensor_passthrough")["fp"], 2)
        sev = SS.confusion(rows, "sensor_severity_rule")          # a1,a2,b1 have severity 2 (flagged), b2 has severity 3
        self.assertEqual((sev["tp"], sev["fp"], sev["tn"]), (2, 1, 1))
        self.assertEqual(SS.confusion(rows, "model_only")["fn"], 1)

    def test_a_missing_verdict_counts_as_flagged_not_closed(self):
        r = rec("attack", "needs_review", mal=None, status="model_error")
        self.assertTrue(SS.decisions(r)["model_only"])
        self.assertTrue(SS.decisions(dict(r, case=None))["full_pipeline"])

    def test_priority_view_counts_only_the_escalate_queue(self):
        r = rec("attack", "needs_review", decision_before="needs_review", mal=False)
        d = SS.decisions(r)
        self.assertTrue(d["full_pipeline"])
        self.assertFalse(d["full_pipeline_escalate_only"])

    def test_empty_denominators_are_none_not_zero(self):
        m = SS.confusion([rec("benign", "auto_close", mal=False)], "full_pipeline")
        self.assertIsNone(m["precision"])
        self.assertIsNone(m["recall"])

    def test_invariants_catch_each_violation(self):
        self.assertEqual(SS.invariants([rec("benign", "needs_review")]), [])
        self.assertTrue(SS.invariants([rec("attack", "auto_close", scenario="z")]))
        self.assertTrue(SS.invariants([rec("benign", "auto_close")]))          # sensor alerts are never auto-closed
        self.assertTrue(SS.invariants([rec("attack", "needs_review", decision_before="escalate")]))
        bad = rec("attack", "escalate")
        bad["case"]["approved_or_executed_actions"] = 1
        self.assertTrue(SS.invariants([bad]))

    def test_percentile(self):
        self.assertEqual(SS._percentile([1, 2, 3, 4, 5], 0.5), 3)
        self.assertEqual(SS._percentile([], 0.5), None)
        self.assertAlmostEqual(SS._percentile([0, 10], 0.95), 9.5)


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.result = SS.run(cls.dir, SS.PROFILES, SMALL, 0.34, 0, now="2026-01-01T00:00:00Z")

    def test_no_invariant_violation_on_any_profile_or_under_outage(self):
        self.assertEqual(self.result["invariant_violations"], [])

    def test_the_pipeline_never_closes_an_attack_even_with_a_model_that_calls_everything_benign(self):
        for profile in SS.PROFILES:
            self.assertEqual(self.result["profiles"][profile]["configs"]["full_pipeline"]["incorrect_closures_of_attacks"], 0, profile)
        lazy = self.result["profiles"]["lazy_benign"]["configs"]
        self.assertEqual(lazy["model_only"]["recall"], 0.0)          # the model alone would have missed everything
        self.assertEqual(lazy["full_pipeline"]["recall"], 1.0)

    def test_the_deterministic_layer_adds_priority_when_the_model_is_lazy(self):
        lazy = self.result["profiles"]["lazy_benign"]["configs"]
        self.assertGreater(lazy["full_pipeline_escalate_only"]["tp"], lazy["model_plus_risk_policy_escalate_only"]["tp"])

    def test_provider_outage_fails_closed(self):
        pf = self.result["provider_failure"]
        self.assertTrue(pf["all_outage_cases_routed_to_review"])
        self.assertEqual(pf["attacks_hit_and_closed"], [])
        self.assertGreater(pf["alerts_with_injected_outage"], 0)
        self.assertGreater(pf["ops"]["alerts_retried"], 0)

    def test_the_hostile_signature_is_not_followed(self):
        recs = json.load(open(os.path.join(self.dir, "sensor_eval_records.json")))
        for profile in SS.PROFILES:
            for r in recs[profile]:
                if r["family"] == "benign_hostile_signature_text":
                    self.assertNotEqual(r["case"]["decision"], "auto_close")
                    self.assertEqual(r["case"]["approved_or_executed_actions"], 0)

    def test_files_and_labelling(self):
        for name in ("sensor_eval.json", "sensor_eval_records.json", "SENSOR_EVAL_REPORT.md"):
            self.assertTrue(os.path.isfile(os.path.join(self.dir, name)), name)
        data = json.load(open(os.path.join(self.dir, "sensor_eval.json")))
        self.assertTrue(data["synthetic"] and data["fake_model"])
        self.assertFalse(data["real_traffic"])
        self.assertEqual(data["real_performance"], "NOT MEASURED")
        self.assertNotIn("records", next(iter(data["profiles"].values())))
        text = open(os.path.join(self.dir, "SENSOR_EVAL_REPORT.md")).read()
        self.assertIn("SYNTHETIC", text)
        self.assertIn("not** detection accuracy", text)
        self.assertIn("Tokens: unavailable", text)

    def test_tokens_and_cost_are_never_invented(self):
        for p in self.result["profiles"].values():
            self.assertFalse(p["ops"]["tokens"]["available"])
            self.assertFalse(p["ops"]["cost"]["available"])

    def test_the_run_is_reproducible(self):
        again = SS.run(tempfile.mkdtemp(), ("noisy",), SMALL, 0.0, 0, now="2026-01-01T00:00:00Z")
        for c in SS.CONFIGS:
            self.assertEqual(again["profiles"]["noisy"]["configs"][c], self.result["profiles"]["noisy"]["configs"][c])

    def test_the_report_is_served_by_the_api_name_rules(self):
        from week5.api.api6 import REPORT_NAME_RE
        for name in ("sensor_eval.json", "SENSOR_EVAL_REPORT.md"):
            self.assertTrue(REPORT_NAME_RE.fullmatch(name))


if __name__ == "__main__":
    unittest.main()
