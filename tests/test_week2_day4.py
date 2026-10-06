"""Week 2, Day 4 checks: evaluation metrics and harness on a small canned fixture whose numbers are worked out by hand.

No model call, no network, no real labels, no frozen files. Run from the project root:
  python -m unittest tests.test_week2_day4 -v
"""
import ast
import os
import sys
import json
import shutil
import hashlib
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import pandas as pd

import eval_metrics as em
import evaluate as ev

def slurp(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


CLASSES = ev.CLASSES
ACCEPTED = {"PortScan": "T1046", "Bot": "T1071;T1071.001", "DDoS": "T1498;T1498.001;T1499;T1499.002", "BENIGN": "NONE"}
PRIMARY = {"PortScan": "T1046", "Bot": "T1071.001", "DDoS": "T1498", "BENIGN": "NONE"}

# id, true label, status, predicted attack type, predicted technique, attempts, model_calls, first-try malformed, latency
CASES = [
    ("A1", "PortScan", "ok", "PortScan", "T1046", 1, 1, False, 900.0),   # synthetic recorded-latency outlier
    ("A2", "PortScan", "ok", "PortScan", "T1595", 2, 2, True, 4.0),
    ("A3", "PortScan", "ok", "BENIGN", "NONE", 1, 1, False, 2.0),
    ("A4", "PortScan", "parse_failed", None, None, 3, 3, True, 6.0),
    ("B1", "Bot", "ok", "Bot", "T1071.001", 1, 1, False, 2.0),
    ("B2", "Bot", "ok", "Bot", "T1071", 1, 1, False, 2.0),
    ("B3", "Bot", "ok", "DDoS", "T1498", 2, 2, True, 4.0),
    ("B4", "Bot", "model_error", None, None, 0, 4, None, 8.0),
    ("D1", "DDoS", "ok", "DDoS", "T1498", 1, 1, False, 2.0),
    ("D2", "DDoS", "ok", "DoS Hulk", "T1499.002", 1, 1, False, 2.0),
    ("D3", "DDoS", "ok", "BENIGN", "NONE", 1, 1, False, 2.0),
    ("D4", "DDoS", "parse_failed", None, None, 3, 3, True, 6.0),
    ("N1", "BENIGN", "ok", "BENIGN", "NONE", 1, 1, False, 2.0),
    ("N2", "BENIGN", "ok", "BENIGN", "NONE", 1, 1, False, 2.0),
    ("N3", "BENIGN", "ok", "BENIGN", "NONE", 1, 1, False, 2.0),
    ("N4", "BENIGN", "ok", "PortScan", "T1046", 1, 1, False, 2.0),
    ("N5", "BENIGN", "ok", "Bot", "T1071", 2, 2, True, 4.0),
    ("N6", "BENIGN", "parse_failed", None, None, 3, 3, True, 6.0),
    ("N7", "BENIGN", "parse_failed", None, None, 3, 3, True, 6.0),
    ("N8", "BENIGN", "ok", "BENIGN", "NONE", 1, 1, False, 2.0),
]


def make_results():
    latest = {}
    for alert_id, label, status, atype, tech, attempts, calls, first_bad, latency in CASES:
        r = {"alert_id": alert_id, "status": status, "verdict": None, "attempts": attempts, "model_calls": calls, "malformed_first_try": first_bad,
             "error_code": "no_json" if status == "parse_failed" else ("model_unavailable" if status == "model_error" else None),
             "attempt_log": [{"error_code": "invalid_json" if first_bad else None}] if attempts else [], "latency_seconds": latency,
             "finish_reasons": ["STOP"] * calls}
        if status == "ok":
            mal = atype != "BENIGN"
            r["verdict"] = {"is_malicious": mal, "attack_type": atype, "mitre_technique": tech, "severity": "high" if mal else "none", "evidence": "x"}
        if status != "model_error":
            r.update({"prompt_tokens": 100 * calls, "output_tokens": 20 * calls, "thinking_tokens": 5 * calls, "total_tokens": 125 * calls})
        else:
            r.update({"prompt_tokens": None, "output_tokens": None, "thinking_tokens": None, "total_tokens": None})
        latest[alert_id] = r
    return latest


def make_alerts_labels():
    ids = [c[0] for c in CASES]
    alerts = pd.DataFrame({"alert_id": ids, "detector_score": [0.5] * len(ids)})
    labels = pd.DataFrame({"alert_id": ids, "label": [c[1] for c in CASES], "is_attack": [0 if c[1] == "BENIGN" else 1 for c in CASES],
                           "mitre_technique_id": [PRIMARY[c[1]] for c in CASES], "mitre_accepted_ids": [ACCEPTED[c[1]] for c in CASES]})
    return alerts, labels


def table():
    alerts, labels = make_alerts_labels()
    return ev.build_table(alerts, labels, make_results())


class Population(unittest.TestCase):
    def test_counts(self):
        p = em.population_counts(table())
        self.assertEqual(p, {"alerts": 20, "ok": 15, "parse_failed": 4, "model_error": 1, "not_run": 0, "true_attacks": 12, "true_benign": 8})


class VerdictMetrics(unittest.TestCase):
    def setUp(self):
        self.v = em.verdict_metrics(table())

    def test_valid_only(self):
        v = self.v["valid_only"]
        self.assertEqual(v["alerts_in_population"], 15)
        self.assertEqual(v["llm_confusion"], {"tp": 7, "fp": 2, "fn": 2, "tn": 4})
        self.assertAlmostEqual(v["llm"]["precision"]["value"], 7 / 9)
        self.assertAlmostEqual(v["llm"]["recall"]["value"], 7 / 9)
        self.assertAlmostEqual(v["llm"]["f1"], 7 / 9)
        self.assertAlmostEqual(v["llm"]["specificity"]["value"], 4 / 6)
        self.assertEqual((v["llm"]["precision"]["numerator"], v["llm"]["precision"]["denominator"]), (7, 9))
        self.assertEqual(v["detector_confusion"], {"tp": 9, "fp": 6, "fn": 0, "tn": 0})
        self.assertAlmostEqual(v["detector"]["precision"]["value"], 9 / 15)
        self.assertEqual(v["detector"]["recall"]["value"], 1.0)

    def test_failures_escalated(self):
        v = self.v["failures_escalated"]
        self.assertEqual(v["alerts_in_population"], 20)
        self.assertEqual(v["llm_confusion"], {"tp": 10, "fp": 4, "fn": 2, "tn": 4})
        self.assertAlmostEqual(v["llm"]["precision"]["value"], 10 / 14)
        self.assertAlmostEqual(v["llm"]["recall"]["value"], 10 / 12)
        self.assertEqual(v["detector_confusion"], {"tp": 12, "fp": 8, "fn": 0, "tn": 0})

    def test_failures_wrong(self):
        v = self.v["failures_wrong"]
        self.assertEqual(v["llm_confusion"], {"tp": 7, "fp": 4, "fn": 5, "tn": 4})
        self.assertAlmostEqual(v["llm"]["precision"]["value"], 7 / 11)
        self.assertAlmostEqual(v["llm"]["recall"]["value"], 7 / 12)

    def test_every_policy_has_a_definition(self):
        for p in self.v.values():
            self.assertTrue(len(p["definition"]) > 20)

    def test_division_by_zero_gives_none(self):
        df = table()
        df = df[df["label"] == "BENIGN"]
        v = em.verdict_metrics(df)["valid_only"]
        self.assertIsNotNone(v["llm"]["precision"]["value"])
        self.assertIsNone(v["llm"]["recall"]["value"])
        self.assertIsNone(em.verdict_metrics(df[~df["has_verdict"]].iloc[0:0])["valid_only"]["llm"]["f1"])


class DecisionAndFalsePositives(unittest.TestCase):
    def test_decision_table(self):
        d = em.decision_table(table())
        self.assertEqual(d["true_attacks"], {"kept_as_malicious": 7, "dismissed_as_benign": 2, "no_verdict": 3, "total": 12})
        self.assertEqual(d["true_benign_false_positives"], {"kept_as_malicious": 2, "dismissed_as_benign": 4, "no_verdict": 2, "total": 8})

    def test_every_alert_in_exactly_one_cell(self):
        d = em.decision_table(table())
        total = sum(c["kept_as_malicious"] + c["dismissed_as_benign"] + c["no_verdict"] for c in d.values())
        self.assertEqual(total, 20)

    def test_fp_reduction_valid_only_uses_comparable_alerts(self):
        f = em.fp_reduction(table())["valid_only"]
        self.assertEqual((f["detector_fp"], f["llm_fp"], f["fp_removed"]), (6, 2, 4))
        self.assertAlmostEqual(f["fp_reduction_pct"], 100 * 4 / 6)
        self.assertEqual(f["attacks_missed_by_llm"], 2)
        self.assertAlmostEqual(f["detector_fp_share_of_alerts"], 6 / 15)
        self.assertAlmostEqual(f["llm_fp_share_of_alerts"], 2 / 9)
        self.assertEqual((f["alerts_raised_detector"], f["alerts_raised_llm"]), (15, 9))
        self.assertAlmostEqual(f["alert_volume_reduction_pct"], 100 * 6 / 15)
        self.assertEqual(f["detector_fp_rate_among_benign_alerts"], 1.0)
        self.assertAlmostEqual(f["llm_fp_rate_among_benign_alerts"], 2 / 6)

    def test_fp_reduction_all_alerts_keeps_failures_visible(self):
        f = em.fp_reduction(table())["failures_escalated"]
        self.assertEqual((f["detector_fp"], f["llm_fp"], f["fp_removed"]), (8, 4, 4))
        self.assertAlmostEqual(f["fp_reduction_pct"], 50.0)
        self.assertEqual(f["benign_dismissal_rate"]["denominator"], 8)
        w = em.fp_reduction(table())["failures_wrong"]
        self.assertEqual(w["attacks_missed_by_llm"], 5)
        self.assertEqual(w["llm_fp"], 4)


class AttackTypeAndMitre(unittest.TestCase):
    def test_attack_type(self):
        a = em.attack_type_metrics(table())
        self.assertEqual((a["on_attacks_with_valid_verdict"]["numerator"], a["on_attacks_with_valid_verdict"]["denominator"]), (5, 9))
        self.assertEqual((a["on_attacks_flagged_malicious"]["numerator"], a["on_attacks_flagged_malicious"]["denominator"]), (5, 7))
        self.assertEqual((a["all_attacks_failures_wrong"]["numerator"], a["all_attacks_failures_wrong"]["denominator"]), (5, 12))
        self.assertEqual((a["coverage"]["numerator"], a["coverage"]["denominator"]), (9, 12))

    def test_mitre_accepted_ids(self):
        m = em.mitre_metrics(table())
        self.assertEqual((m["accepted_on_attacks_with_valid_verdict"]["numerator"], m["accepted_on_attacks_with_valid_verdict"]["denominator"]), (5, 9))
        self.assertEqual((m["accepted_on_attacks_flagged_malicious"]["numerator"], m["accepted_on_attacks_flagged_malicious"]["denominator"]), (5, 7))
        self.assertEqual((m["accepted_all_attacks_failures_wrong"]["numerator"], m["accepted_all_attacks_failures_wrong"]["denominator"]), (5, 12))
        self.assertEqual(m["coverage"]["denominator"], 12)

    def test_mitre_primary_is_stricter(self):
        m = em.mitre_metrics(table())
        self.assertEqual((m["primary_on_attacks_with_valid_verdict"]["numerator"], m["primary_on_attacks_with_valid_verdict"]["denominator"]), (3, 9))

    def test_benign_none_is_reported_apart(self):
        m = em.mitre_metrics(table())
        self.assertEqual((m["benign_alerts_given_NONE"]["numerator"], m["benign_alerts_given_NONE"]["denominator"]), (4, 6))
        self.assertEqual(m["accepted_on_attacks_with_valid_verdict"]["denominator"], 9)   # benign alerts are not in the MITRE denominator

    def test_none_is_never_accepted_for_an_attack(self):
        df = table()
        a3 = df[df["alert_id"] == "A3"].iloc[0]
        self.assertFalse(em._in_accepted(a3))

    def test_sub_technique_not_inferred_from_parent(self):
        df = table()
        row = df[df["alert_id"] == "B2"].iloc[0].copy()
        row["pred_technique"] = "T1071.002"
        self.assertFalse(em._in_accepted(row))
        row["pred_technique"] = "T1071"
        self.assertTrue(em._in_accepted(row))


class PerClassAndConfusion(unittest.TestCase):
    def test_per_class(self):
        rows = {r["label"]: r for r in em.per_class(table(), CLASSES)}
        ps = rows["PortScan"]
        self.assertEqual((ps["alerts"], ps["valid_verdicts"], ps["no_verdict"], ps["hits"]), (4, 3, 1, 2))
        self.assertAlmostEqual(ps["rate"], 2 / 3)
        self.assertEqual(ps["attack_type_correct"], 2)
        self.assertEqual(ps["mitre_accepted"], 1)
        b = rows["BENIGN"]
        self.assertEqual((b["alerts"], b["valid_verdicts"], b["hits"]), (8, 6, 4))
        self.assertNotIn("mitre_accuracy", b)
        self.assertEqual(rows["Bot"]["no_verdict"], 1)
        self.assertEqual(rows["DoS Hulk"]["alerts"], 0)

    def test_confusion_matrix(self):
        c = em.attack_type_confusion(table(), CLASSES)
        self.assertEqual(c.loc["DDoS", "DoS Hulk"], 1)
        self.assertEqual(c.loc["DDoS", "BENIGN"], 1)
        self.assertEqual(c.loc["DDoS", "no verdict"], 1)
        self.assertEqual(int(c.values.sum()), 20)


class Reliability(unittest.TestCase):
    def test_rates_and_denominators(self):
        r = em.reliability(table())
        self.assertEqual((r["first_try_malformed"]["numerator"], r["first_try_malformed"]["denominator"]), (7, 19))
        self.assertEqual((r["first_try_malformed_of_all_alerts"]["numerator"], r["first_try_malformed_of_all_alerts"]["denominator"]), (7, 20))
        self.assertEqual((r["retry_needed"]["numerator"], r["retry_needed"]["denominator"]), (7, 19))
        self.assertEqual((r["final_parse_failure"]["numerator"], r["final_parse_failure"]["denominator"]), (4, 20))
        self.assertEqual((r["successful_verdict_coverage"]["numerator"], r["successful_verdict_coverage"]["denominator"]), (15, 20))
        self.assertEqual((r["recovered_by_retry"]["numerator"], r["recovered_by_retry"]["denominator"]), (3, 7))
        self.assertEqual(r["model_calls_total"], 34)
        self.assertEqual(r["first_try_error_codes"], {"invalid_json": 7})
        self.assertEqual(r["final_error_codes"], {"no_json": 4})
        self.assertEqual(r["no_verdict_by_true_label"], {"BENIGN": 2, "PortScan": 1, "Bot": 1, "DDoS": 1})


class TokensAndCost(unittest.TestCase):
    PRICING = {"currency": "USD", "per_million_input_tokens": 1.0, "per_million_output_tokens": 2.0, "thinking_tokens_billed_as": "output",
               "source": "test fixture", "as_of": "2000-01-01"}

    def test_token_totals_skip_missing(self):
        t = em.token_totals(table())
        self.assertEqual((t["prompt_tokens"], t["output_tokens"], t["thinking_tokens"], t["total_tokens"]), (3000, 600, 150, 3750))
        self.assertEqual((t["alerts_with_token_counts"], t["alerts_without_token_counts"]), (19, 1))
        self.assertTrue(t["parts_add_up_to_total"])

    def test_cost_unavailable_without_pricing(self):
        c = em.cost(em.token_totals(table()), None)
        self.assertFalse(c["available"])
        self.assertIn("No price is assumed", c["reason"])

    def test_cost_with_documented_pricing(self):
        c = em.cost(em.token_totals(table()), self.PRICING)
        self.assertTrue(c["available"])
        self.assertAlmostEqual(c["total"], 0.003 + 0.0015)

    def test_thinking_billed_as_input(self):
        c = em.cost(em.token_totals(table()), dict(self.PRICING, thinking_tokens_billed_as="input"))
        self.assertAlmostEqual(c["total"], 3150 / 1e6 * 1.0 + 600 / 1e6 * 2.0)

    def test_incomplete_pricing_is_refused(self):
        for key in em.PRICING_REQUIRED:
            bad = dict(self.PRICING)
            bad[key] = None
            with self.assertRaises(ValueError, msg=key):
                em.cost(em.token_totals(table()), bad)


class Latency(unittest.TestCase):
    def test_anomaly_found_and_excluded_only_by_value(self):
        df = table()
        self.assertEqual(em.find_latency_anomaly(df, 900.0), ["A1"])
        self.assertEqual(em.find_latency_anomaly(df, 123.0), [])

    def test_statistics_with_and_without_the_anomaly(self):
        la = em.latency_stats(table(), ["A1"])
        everything, kept = la["per_alert_all_observations"], la["per_alert_excluding_anomaly"]
        self.assertEqual((everything["n"], kept["n"]), (20, 19))
        self.assertAlmostEqual(everything["mean"], (66 + 900.0) / 20)
        self.assertAlmostEqual(kept["mean"], 66 / 19)
        self.assertEqual(kept["median"], 2.0)
        self.assertAlmostEqual(kept["p95"], 6.2)
        self.assertEqual(everything["max"], 900.0)
        self.assertEqual(la["excluded_alert_ids"], ["A1"])
        self.assertEqual(la["excluded_values"], [900.0])

    def test_neighbouring_alerts_are_not_excluded(self):
        la = em.latency_stats(table(), ["A1"])
        self.assertEqual(la["per_alert_excluding_anomaly"]["n"], 19)

    def test_per_call_exclusion_drops_only_the_dominant_call(self):
        calls = pd.DataFrame({"alert_id": ["A1", "A1", "A2"], "latency_seconds": [899.9, 0.1, 3.0]})
        la = em.latency_stats(table(), ["A1"], calls)
        self.assertEqual(la["excluded_call_count"], 1)
        self.assertEqual(la["per_call_excluding_anomaly"]["n"], 2)
        self.assertEqual(la["per_call_all_observations"]["n"], 3)

    def test_no_exclusion_by_default(self):
        la = em.latency_stats(table(), [])
        self.assertEqual(la["per_alert_all_observations"], la["per_alert_excluding_anomaly"])


class Wilson(unittest.TestCase):
    def test_interval(self):
        lo, hi = em.wilson(7, 9)
        self.assertTrue(0 < lo < 7 / 9 < hi < 1)
        self.assertIsNone(em.wilson(0, 0))
        lo, hi = em.wilson(0, 10)
        self.assertEqual(lo, 0.0)


class Harness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.run_dir = os.path.join(self.tmp, "runs", "r1")
        os.makedirs(self.run_dir)
        with open(os.path.join(self.run_dir, "results.jsonl"), "w") as f:
            for r in make_results().values():
                f.write(json.dumps(r, sort_keys=True) + "\n")
        with open(os.path.join(self.run_dir, "raw_responses.jsonl"), "w") as f:
            for alert_id, label, status, _, _, attempts, calls, _, latency in CASES:
                for i in range(calls):
                    f.write(json.dumps({"alert_id": alert_id, "call_index": i, "latency_seconds": latency / calls}) + "\n")
        with open(os.path.join(self.run_dir, "run_meta.json"), "w") as f:
            json.dump({"run_name": "r1", "model": "fake", "prompt_sha256": "abc", "sessions": [1, 2]}, f)
        self.protected = os.path.join(self.tmp, "protected.txt")
        with open(self.protected, "w") as f:
            f.write("week 1")
        self.log = os.path.join(self.tmp, "frozen_access.log")
        with open(self.log, "w") as f:
            f.write("one line\n")
        self.alerts, self.labels = make_alerts_labels()
        self.out = os.path.join(self.tmp, "out")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def go(self, **kw):
        kw.setdefault("threshold", 0.1)
        return ev.run_evaluation(self.run_dir, self.alerts, self.labels, self.out, protected=[self.protected], frozen_log=self.log, log=lambda *_: None, **kw)

    def run_hashes(self):
        return {n: hashlib.sha256(slurp(os.path.join(self.run_dir, n), "rb")).hexdigest() for n in sorted(os.listdir(self.run_dir))}

    def test_end_to_end_writes_all_outputs_and_leaves_the_run_alone(self):
        before = self.run_hashes()
        metrics, ok = self.go(exclude_latency=900.0)
        self.assertTrue(ok)
        self.assertEqual(self.run_hashes(), before)
        for name in ["evaluation.json", "evaluation_metrics.csv", "per_class.csv", "attack_type_confusion.csv", "per_alert.csv", "EVALUATION_REPORT.md"]:
            self.assertTrue(os.path.exists(os.path.join(self.out, name)), name)
        data = json.loads(slurp(os.path.join(self.out, "evaluation.json")))
        self.assertEqual(data["metrics"]["population"]["parse_failed"], 4)
        self.assertEqual(data["latency_exclusion"]["alert_ids"], ["A1"])
        self.assertTrue(data["integrity"]["run_unchanged"])

    def test_report_keeps_failures_and_denominators_visible(self):
        self.go(exclude_latency=900.0)
        text = slurp(os.path.join(self.out, "EVALUATION_REPORT.md"))
        self.assertIn("parse_failed (no valid verdict after retries) | 4", text)
        for policy in em.POLICIES:
            self.assertIn(policy, text)
        self.assertIn("(7/9", text)
        self.assertIn("Cost: **unavailable.**", text)
        self.assertIn("900.0", text)
        self.assertIn("documented recorded-latency exclusion", text)
        self.assertNotIn("accuracy of", text.lower())

    def test_per_alert_csv_keeps_every_alert_and_flags_the_exclusion(self):
        self.go(exclude_latency=900.0)
        t = pd.read_csv(os.path.join(self.out, "per_alert.csv"))
        self.assertEqual(len(t), 20)
        self.assertEqual(list(t[t["latency_excluded"]]["alert_id"]), ["A1"])
        self.assertEqual(float(t[t["alert_id"] == "A1"]["latency_seconds"].iloc[0]), 900.0)
        self.assertEqual(set(t["detector_prediction"]), {"malicious"})

    def test_flat_csv_has_denominators(self):
        self.go()
        t = pd.read_csv(os.path.join(self.out, "evaluation_metrics.csv"))
        row = t[t["metric"] == "verdict.valid_only.llm.precision"].iloc[0]
        self.assertEqual((row["numerator"], row["denominator"]), (7, 9))

    def test_exclusion_must_match_exactly_one_alert(self):
        with self.assertRaises(ev.EvaluationInputError):
            self.go(exclude_latency=123.0)
        self.assertFalse(os.path.exists(os.path.join(self.out, "evaluation.json")))

    def test_warns_about_a_large_latency_when_nothing_is_excluded(self):
        self.go()
        self.assertIn("looks like an interruption", slurp(os.path.join(self.out, "EVALUATION_REPORT.md")))

    def test_existing_output_is_not_replaced_without_force(self):
        self.go()
        with self.assertRaises(ev.EvaluationInputError):
            self.go()
        self.go(force=True)

    def test_pricing_flows_into_the_report(self):
        self.go(pricing=TokensAndCost.PRICING)
        self.assertIn("Estimated cost", slurp(os.path.join(self.out, "EVALUATION_REPORT.md")))

    def test_detects_a_changed_protected_file_or_log(self):
        original = ev.snapshot

        def tampering(run_dir, protected, frozen_log):
            result = original(run_dir, protected, frozen_log)
            if not hasattr(tampering, "done"):
                tampering.done = True
            else:
                with open(self.log, "a") as f:
                    f.write("new line\n")
                result = original(run_dir, protected, frozen_log)
            return result
        ev.snapshot = tampering
        try:
            _, ok = self.go()
        finally:
            ev.snapshot = original
        self.assertFalse(ok)

    def test_missing_results_stop_the_evaluation(self):
        lines = slurp(os.path.join(self.run_dir, "results.jsonl")).splitlines()
        with open(os.path.join(self.run_dir, "results.jsonl"), "w") as f:
            f.write("\n".join(lines[:-3]) + "\n")
        with self.assertRaises(ev.EvaluationInputError) as ctx:
            self.go()
        self.assertIn("3 dev alerts have no result", str(ctx.exception))
        metrics, _ = self.go(allow_partial=True)
        self.assertEqual(metrics["population"]["alerts"], 17)

    def test_run_with_foreign_ids_is_refused(self):
        with open(os.path.join(self.run_dir, "results.jsonl"), "a") as f:
            f.write(json.dumps({"alert_id": "FRZ-0001", "status": "ok", "verdict": None}) + "\n")
        with self.assertRaises(ev.EvaluationInputError) as ctx:
            self.go()
        self.assertIn("not dev alert ids", str(ctx.exception))

    def test_missing_mitre_mapping_is_named_exactly(self):
        self.labels = self.labels.drop(columns=["mitre_accepted_ids"])
        with self.assertRaises(ev.EvaluationInputError) as ctx:
            self.go()
        self.assertIn("mitre_accepted_ids", str(ctx.exception))

    def test_attack_without_accepted_ids_is_named(self):
        self.labels.loc[self.labels["label"] == "Bot", "mitre_accepted_ids"] = "NONE"
        with self.assertRaises(ev.EvaluationInputError) as ctx:
            self.go()
        self.assertIn("Bot", str(ctx.exception))

    def test_alerts_below_threshold_are_refused(self):
        with self.assertRaises(ev.EvaluationInputError) as ctx:
            self.go(threshold=0.9)
        self.assertIn("below the accepted detector threshold", str(ctx.exception))

    def test_unknown_label_is_refused(self):
        self.labels.loc[0, "label"] = "Infiltration"
        with self.assertRaises(ev.EvaluationInputError):
            self.go()

    def test_duplicate_result_lines_last_one_wins(self):
        first = make_results()["A3"]
        first["status"], first["verdict"] = "model_error", None
        body = slurp(os.path.join(self.run_dir, "results.jsonl"))
        with open(os.path.join(self.run_dir, "results.jsonl"), "w") as f:
            f.write(json.dumps(first) + "\n" + body)
        metrics, _ = self.go()
        self.assertEqual(metrics["population"]["ok"], 15)


class Separation(unittest.TestCase):
    EVAL_FILES = ["eval_metrics.py", "evaluate.py"]
    FORBIDDEN_IN_EVAL = {"FROZEN_ALERTS_PATH", "FROZEN_LABELS_PATH", "FLOW_STORE_FROZEN_PATH", "FLOW_STORE_DEV_PATH", "FROZEN_UNLOCK_ENV", "FROZEN_UNLOCK_VALUE",
                         "anthropic", "openai", "genai", "langsmith", "langgraph", "langchain", "GeminiClient", "GeminiCaller"}
    EVAL_ONLY_MODULES = {"evaluate", "eval_metrics", "eval_labels"}
    AGENT_SIDE = ["baseline_prompt.py", "baseline_store.py", "gemini_client.py", "run_baseline_dev.py", "triage_inputs.py", "triage_schema.py",
                  "llm_config.py", "verdict_schema.py", "verdict_parser.py"]

    def names(self, name):
        with open(os.path.join(ROOT, "src", name), encoding="utf-8") as f:
            tree = ast.parse(f.read())
        used, imported = set(), set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used.add(node.id)
            elif isinstance(node, ast.Attribute):
                used.add(node.attr)
            elif isinstance(node, ast.Import):
                for a in node.names:
                    imported.add(a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
                for a in node.names:
                    imported.add(a.name)
        return used, imported

    def test_evaluation_code_cannot_reach_frozen_files_or_a_model(self):
        for name in self.EVAL_FILES:
            used, imported = self.names(name)
            self.assertEqual(sorted((used | imported) & self.FORBIDDEN_IN_EVAL), [], name)
            with open(os.path.join(ROOT, "src", name), encoding="utf-8") as f:
                text = f.read()
            self.assertNotIn('"frozen"', text)
            self.assertNotIn("SOC_FROZEN_UNLOCK", text)

    def test_no_agent_side_module_imports_the_evaluation_code(self):
        for name in self.AGENT_SIDE:
            if not os.path.exists(os.path.join(ROOT, "src", name)):
                continue
            used, imported = self.names(name)
            self.assertEqual(sorted(imported & self.EVAL_ONLY_MODULES), [], name)
            self.assertEqual(sorted(used & {"load_labels", "load_mitre_map", "load_dev_labels", "load_answer_key", "MITRE_MAP"}), [], name)

    def test_evaluation_reads_only_dev_labels_through_the_harness_module(self):
        with open(os.path.join(ROOT, "src", "evaluate.py"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("eval_labels.load_dev_labels()", text)
        self.assertIn("triage_inputs.load_dev_alerts()", text)

    def test_no_pricing_numbers_are_built_in(self):
        with open(os.path.join(ROOT, "src", "eval_metrics.py"), encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn("0.075", text)
        self.assertIn("No price is assumed", text)


if __name__ == "__main__":
    unittest.main()
