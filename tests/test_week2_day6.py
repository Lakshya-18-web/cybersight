import io
import os
import re
import sys
import ast
import json
import math
import shutil
import hashlib
import tempfile
import unittest
import contextlib
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

import pandas as pd

import config
import llm_config
import baseline_prompt
import baseline_store as store
import prompt_registry as registry
import run_baseline_dev as runner
import day6_aggregate as agg
import day6_replicates as rep

from tests import test_week2_day3 as d3
from tests import test_week2_day5 as d5

LOCKED_V3_SHA256 = "9403e7ea1937ff0f0f4b4fba548b58efa93bcc6296daa7326970adbaed1b61b7"
V1_SHA256 = "0208c856dc1063ef5e249fcffdb28af803bd2899fa87977dde0ac4a23b06f172"
DAY6_MODULES = ["day6_aggregate.py", "day6_replicates.py"]
NAMES = agg.DEFAULT_RUNS


def jload(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def jdump(obj, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f)


def text_of(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def sha_of(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def read_source(name):
    with open(os.path.join(ROOT, "src", name), encoding="utf-8") as f:
        return f.read()


# ------------------------------------------------------------------------------------------------ synthetic evaluated runs
# alert -> (true label, is_attack, outcome in run 1, 2, 3). outcome = ("ok", is_malicious, type, technique, mitre_accepted) or ("fail",)
def ok(mal, typ, tech, acc):
    return ("ok", mal, typ, tech, acc)


FAIL = ("fail",)
ALERTS = collections = None
ALERTS = [
    ("DEV-0001", "Bot", True, [ok(True, "PortScan", "T1046", False)] * 3),
    ("DEV-0002", "Bot", True, [ok(True, "Bot", "T1071.001", True), ok(True, "PortScan", "T1046", False), ok(True, "PortScan", "T1046", False)]),
    ("DEV-0003", "DDoS", True, [ok(True, "Bot", "T1071.001", False), ok(True, "DDoS", "T1498", True), ok(True, "DDoS", "T1498", True)]),
    ("DEV-0004", "DDoS", True, [ok(True, "DDoS", "T1498", True)] * 3),
    ("DEV-0005", "DoS Hulk", True, [FAIL, ok(True, "DoS slowloris", "T1499", False), ok(True, "DoS Slowhttptest", "T1498", False)]),
    ("DEV-0006", "DoS Hulk", True, [FAIL, FAIL, ok(True, "DoS slowloris", "T1499", False)]),
    ("DEV-0007", "Bot", True, [ok(False, "BENIGN", "NONE", False)] * 3),
    ("DEV-0008", "BENIGN", False, [ok(True, "PortScan", "T1046", None)] * 3),
    ("DEV-0009", "BENIGN", False, [ok(True, "PortScan", "T1046", None), ok(False, "BENIGN", "NONE", None), ok(False, "BENIGN", "NONE", None)]),
    ("DEV-0010", "BENIGN", False, [ok(False, "BENIGN", "NONE", None)] * 3),
    ("DEV-0011", "BENIGN", False, [ok(False, "BENIGN", "NONE", None), FAIL, ok(False, "BENIGN", "NONE", None)]),
]
PRECISIONS = [0.8, 0.9, 1.0]
SETTINGS = {"temperature": 0.0, "max_output_tokens": 1024, "seed": 42, "parse_retries": 2, "requests_per_minute": 10}


def per_alert_frame(run_index):
    rows = []
    for alert_id, label, is_attack, outcomes in ALERTS:
        o = outcomes[run_index]
        failed = o[0] == "fail"
        rows.append({
            "alert_id": alert_id, "label": label, "is_attack": str(is_attack), "status": "parse_failed" if failed else "ok",
            "has_verdict": str(not failed), "pred_malicious": "" if failed else str(o[1]), "pred_attack_type": "" if failed else o[2],
            "pred_technique": "" if failed else o[3], "first_try_error": "invalid_json" if failed else "", "error_code": "invalid_json" if failed else "",
            "mitre_accepted": "" if (failed or not is_attack) else str(o[4]),
        })
    return pd.DataFrame(rows)


def make_eval(name, precision, calls=10, tokens=1000):
    return {
        "run": name, "allow_partial": False,
        "integrity": {"run_unchanged": True, "protected_unchanged": True, "frozen_log_unchanged": True},
        "protected_file_sha256": {"eval/MANIFEST.json": "m1", "eval/dev_labels.parquet": "l1"},
        "metrics": {
            "population": {"alerts": len(ALERTS), "true_attacks": 7, "true_benign": 4},
            "reliability": {"successful_verdict_coverage": {"value": 0.8}, "final_parse_failure": {"value": 0.2, "numerator": 2},
                            "model_calls_total": calls},
            "verdict": {"valid_only": {"llm": {"precision": {"value": precision}, "recall": {"value": 0.5}, "f1": 0.6, "specificity": {"value": 0.4}}}},
            "tokens": {"total_tokens": tokens},
            "latency": {"per_alert_all_observations": {"mean": 1.5, "max": 8.0}},
        },
    }


def make_meta(name, **over):
    meta = {"run_name": name, "status": "complete", "set": "dev", "prompt_version": "baseline_v3", "prompt_sha256": LOCKED_V3_SHA256,
            "model": "gemini-test", "settings": dict(SETTINGS), "inputs": {"dev_alerts_sha256": "a", "flow_store_dev_sha256": "b"},
            "selected_alert_ids": [a[0] for a in ALERTS], "frozen_access_log_unchanged": True, "week1_files_unchanged": True,
            "langsmith": {"enabled": False}}
    meta.update(over)
    return meta


def write_fixture(tmp, names=NAMES, precisions=PRECISIONS, tweak=None):
    eval_root = os.path.join(tmp, "reports", "week2_eval")
    runs_root = os.path.join(tmp, "runs", "week2_baseline_v1")
    for i, name in enumerate(names):
        ev = make_eval(name, precisions[i], calls=10 + i, tokens=1000 + 100 * i)
        meta = make_meta(name)
        if tweak:
            tweak(i, ev, meta)
        os.makedirs(os.path.join(eval_root, name), exist_ok=True)
        os.makedirs(os.path.join(runs_root, name), exist_ok=True)
        with open(os.path.join(eval_root, name, "evaluation.json"), "w") as f:
            json.dump(ev, f)
        per_alert_frame(i % 3).to_csv(os.path.join(eval_root, name, "per_alert.csv"), index=False)
        with open(os.path.join(runs_root, name, "run_meta.json"), "w") as f:
            json.dump(meta, f)
    return eval_root, runs_root


def load_all(eval_root, runs_root, names=NAMES):
    return [agg.load_run(n, eval_root, runs_root) for n in names]


class FixtureCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.eval_root, self.runs_root = write_fixture(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def runs(self):
        return load_all(self.eval_root, self.runs_root)

    def analysis(self):
        return agg.analyze(self.runs())


# ------------------------------------------------------------------------------------------------ mean and spread
class SpreadTests(unittest.TestCase):
    def test_mean_and_sample_sd_with_n_minus_1(self):
        s = agg.stats_for([0.8, 0.9, 1.0])
        self.assertAlmostEqual(s["mean"], 0.9)
        self.assertAlmostEqual(s["sd"], 0.1)
        self.assertEqual((s["min"], s["max"]), (0.8, 1.0))
        self.assertAlmostEqual(s["range"], 0.2)
        self.assertEqual(s["n_present"], 3)

    def test_sd_matches_the_textbook_formula(self):
        values = [3.0, 7.0, 8.0]
        mean = sum(values) / 3
        expected = math.sqrt(sum((v - mean) ** 2 for v in values) / 2)
        self.assertAlmostEqual(agg.stats_for(values)["sd"], expected)

    def test_identical_values_have_zero_spread(self):
        s = agg.stats_for([5, 5, 5])
        self.assertEqual((s["sd"], s["range"], s["mean"]), (0.0, 0, 5))

    def test_missing_values_are_left_out_and_counted(self):
        s = agg.stats_for([1.0, None, 3.0])
        self.assertEqual(s["n_present"], 2)
        self.assertAlmostEqual(s["mean"], 2.0)
        none = agg.stats_for([None, None, None])
        self.assertIsNone(none["mean"])
        self.assertIsNone(none["sd"])

    def test_one_value_has_no_sd(self):
        s = agg.stats_for([4.0])
        self.assertEqual(s["mean"], 4.0)
        self.assertIsNone(s["sd"])

    def test_display_units(self):
        self.assertEqual(agg.display_value(0.8986, "frac"), "89.86%")
        self.assertEqual(agg.display_value(79.61, "pct"), "79.61%")
        self.assertEqual(agg.display_value(673476, "tokens"), "673,476")
        self.assertEqual(agg.display_value(None, "frac"), "n/a")
        self.assertEqual(agg.display_spread(0.0125, "frac"), "1.25 pp")


class HeadlineTests(FixtureCase):
    def test_headline_values_come_from_each_runs_evaluation_json(self):
        a = self.analysis()
        row = {r["key"]: r for r in a["headline"]}["precision_valid_only"]
        self.assertEqual(row["values"], PRECISIONS)
        self.assertAlmostEqual(row["mean"], 0.9)
        self.assertAlmostEqual(row["sd"], 0.1)
        calls = {r["key"]: r for r in a["headline"]}["model_calls_total"]
        self.assertEqual(calls["values"], [10, 11, 12])
        tokens = {r["key"]: r for r in a["headline"]}["total_tokens"]
        self.assertEqual(tokens["values"], [1000, 1100, 1200])

    def test_the_required_baseline_metrics_are_all_present(self):
        keys = {r["key"] for r in agg.headline_table([make_eval("x", 0.9)])}
        for needed in ["coverage", "final_parse_failure", "precision_valid_only", "recall_valid_only", "f1_valid_only", "specificity_valid_only",
                       "fp_reduction_valid_only", "attack_type_valid", "mitre_valid", "model_calls_total", "total_tokens", "latency_alert_mean",
                       "latency_alert_p95", "precision_failures_escalated", "f1_failures_wrong"]:
            self.assertIn(needed, keys)

    def test_a_metric_absent_from_the_evaluation_is_n_a_and_not_zero(self):
        row = {r["key"]: r for r in agg.headline_table([make_eval("x", 0.9)])}["mitre_valid"]
        self.assertEqual(row["values"], [None])
        self.assertIsNone(row["mean"])


# ------------------------------------------------------------------------------------------------ comparability checks
class CheckRunsTests(FixtureCase):
    def problems(self, tweak):
        shutil.rmtree(self.tmp, ignore_errors=True)
        self.tmp = tempfile.mkdtemp()
        self.eval_root, self.runs_root = write_fixture(self.tmp, tweak=tweak)
        return agg.check_runs(self.runs())

    def test_clean_runs_have_no_problems(self):
        self.assertEqual(agg.check_runs(self.runs()), [])
        self.assertEqual(agg.check_runs(self.runs(), expected_sha=LOCKED_V3_SHA256), [])

    def test_wrong_expected_hash_is_refused(self):
        self.assertTrue(agg.check_runs(self.runs(), expected_sha="0" * 64))

    def test_different_prompt_hash_between_runs_is_refused(self):
        p = self.problems(lambda i, ev, meta: meta.update(prompt_sha256="f" * 64) if i == 1 else None)
        self.assertTrue(any("prompt hash differs" in x for x in p))

    def test_not_baseline_v3_is_refused(self):
        p = self.problems(lambda i, ev, meta: meta.update(prompt_version="baseline_v2"))
        self.assertTrue(any("not baseline_v3" in x for x in p))

    def test_failed_integrity_flags_are_refused(self):
        for key in ["run_unchanged", "protected_unchanged", "frozen_log_unchanged"]:
            p = self.problems(lambda i, ev, meta, key=key: ev["integrity"].update({key: False}) if i == 2 else None)
            self.assertTrue(any(key in x for x in p), key)

    def test_partial_or_incomplete_runs_are_refused(self):
        self.assertTrue(any("allow-partial" in x for x in self.problems(lambda i, ev, meta: ev.update(allow_partial=True) if i == 0 else None)))
        self.assertTrue(any("not complete" in x for x in self.problems(lambda i, ev, meta: meta.update(status="incomplete") if i == 0 else None)))

    def test_run_that_recorded_a_frozen_or_week1_change_is_refused(self):
        self.assertTrue(self.problems(lambda i, ev, meta: meta.update(frozen_access_log_unchanged=False) if i == 1 else None))
        self.assertTrue(self.problems(lambda i, ev, meta: meta.update(week1_files_unchanged=False) if i == 1 else None))

    def test_not_dev_is_refused(self):
        self.assertTrue(self.problems(lambda i, ev, meta: meta.update(set="frozen") if i == 0 else None))

    def test_different_settings_model_inputs_or_alert_list_are_refused(self):
        self.assertTrue(any("settings differs" in x for x in self.problems(lambda i, ev, meta: meta["settings"].update(seed=7) if i == 1 else None)))
        self.assertTrue(any("model differs" in x for x in self.problems(lambda i, ev, meta: meta.update(model="other") if i == 1 else None)))
        self.assertTrue(any("inputs differs" in x for x in self.problems(lambda i, ev, meta: meta.update(inputs={"x": "1"}) if i == 1 else None)))
        self.assertTrue(any("alert list differs" in x for x in self.problems(lambda i, ev, meta: meta.update(selected_alert_ids=["DEV-0001"]) if i == 1 else None)))

    def test_requests_per_minute_may_differ(self):
        p = self.problems(lambda i, ev, meta: meta["settings"].update(requests_per_minute=99) if i == 1 else None)
        self.assertEqual(p, [])

    def test_different_protected_files_or_labels_are_refused(self):
        self.assertTrue(self.problems(lambda i, ev, meta: ev["protected_file_sha256"].update({"eval/dev_labels.parquet": "zzz"}) if i == 1 else None))

    def test_same_run_twice_is_refused(self):
        runs = self.runs()
        self.assertTrue(any("twice" in x for x in agg.check_runs([runs[0], runs[0]])))

    def test_population_mismatch_is_refused(self):
        self.assertTrue(self.problems(lambda i, ev, meta: ev["metrics"]["population"].update(alerts=5) if i == 0 else None))

    def test_analyze_raises_with_the_problem_list(self):
        runs = self.runs()
        runs[1]["meta"]["prompt_sha256"] = "f" * 64
        with self.assertRaises(agg.AggregateError) as ctx:
            agg.analyze(runs)
        self.assertIn("prompt hash differs", str(ctx.exception))


class ReconcileTests(FixtureCase):
    def test_counts_rebuilt_from_per_alert_match_the_evaluators_numbers(self):
        run = self.runs()[0]
        ev = run["evaluation"]["metrics"]
        ev["verdict"]["valid_only"]["llm_confusion"] = {"fp": 2, "fn": 1, "tp": 4, "tn": 2}
        ev["attack_type"] = {"on_attacks_with_valid_verdict": {"denominator": 5, "numerator": 2}}
        ev["mitre"] = {"accepted_on_attacks_with_valid_verdict": {"numerator": 2}}
        ev["population"]["ok"] = 9
        self.assertEqual(agg.reconcile(run), [])

    def test_a_disagreement_stops_the_analysis(self):
        runs = self.runs()
        runs[0]["evaluation"]["metrics"]["verdict"]["valid_only"]["llm_confusion"] = {"fp": 99}
        self.assertTrue(any("per_alert.csv gives" in x for x in agg.reconcile(runs[0])))
        with self.assertRaises(agg.AggregateError):
            agg.analyze(runs)

    def test_values_the_evaluation_lacks_are_skipped(self):
        self.assertEqual(agg.reconcile(self.runs()[0]), [])


# ------------------------------------------------------------------------------------------------ error analysis
class ErrorAnalysisTests(FixtureCase):
    def test_categorize(self):
        self.assertEqual(agg.categorize(0, 3), "never")
        self.assertEqual(agg.categorize(3, 3), "persistent")
        self.assertEqual(agg.categorize(2, 2), "persistent")
        self.assertEqual(agg.categorize(1, 3), "one_off")
        self.assertEqual(agg.categorize(1, 2), "one_off")
        self.assertEqual(agg.categorize(2, 3), "recurring")
        self.assertEqual(agg.categorize(1, 1), "insufficient")
        self.assertEqual(agg.categorize(0, 1), "insufficient")
        self.assertEqual(agg.categorize(0, 0), "insufficient")

    def test_attack_type_categories(self):
        c = self.analysis()["categories"]["attack_type_error"]
        self.assertEqual(c["applicable_alerts"], 7)
        self.assertEqual((c["persistent"], c["recurring"], c["one_off"], c["never"], c["insufficient"]), (3, 1, 1, 1, 1))
        self.assertEqual(c["any_error"], 5)

    def test_mitre_categories(self):
        c = self.analysis()["categories"]["mitre_error"]
        self.assertEqual((c["persistent"], c["recurring"], c["one_off"], c["never"], c["insufficient"]), (3, 1, 1, 1, 1))

    def test_missed_attack_and_false_positive_categories(self):
        cats = self.analysis()["categories"]
        m, f = cats["missed_attack"], cats["false_positive"]
        self.assertEqual((m["applicable_alerts"], m["persistent"], m["never"], m["insufficient"]), (7, 1, 5, 1))
        self.assertEqual((f["applicable_alerts"], f["persistent"], f["one_off"], f["never"]), (4, 1, 1, 2))

    def test_no_verdict_categories_keep_parse_failures_visible(self):
        c = self.analysis()["categories"]["no_verdict"]
        self.assertEqual(c["applicable_alerts"], 11)
        self.assertEqual((c["persistent"], c["recurring"], c["one_off"], c["never"]), (0, 1, 2, 8))
        pf = self.analysis()["parse_failures"]
        self.assertEqual(pf["alerts_failed_in_at_least_one_run"], 3)
        self.assertEqual(pf["failed_in_k_runs"], {1: 2, 2: 1})
        self.assertEqual(pf["final_error_codes"], {"invalid_json": 4})

    def test_a_failed_run_is_not_counted_as_a_wrong_answer(self):
        rows = {r["alert_id"]: r for r in self.analysis()["rows"]}
        flag = rows["DEV-0006"]["flags"]["attack_type_error"]
        self.assertEqual((flag["k"], flag["m"]), (1, 1))
        flag = rows["DEV-0005"]["flags"]["attack_type_error"]
        self.assertEqual((flag["k"], flag["m"]), (2, 2))

    def test_persistent_detail(self):
        d = self.analysis()["persistent"]
        self.assertEqual(d["persistent_confusions"][("Bot", "PortScan")], 1)
        self.assertEqual(d["persistent_confusions"][("Bot", "BENIGN")], 1)
        self.assertEqual(d["persistent_confusions"][("DoS Hulk", "DoS slowloris")], 1)
        self.assertEqual(d["persistent_type_consistency"]["same wrong type every run"], 2)
        self.assertEqual(d["persistent_type_consistency"]["different wrong types across runs"], 1)
        self.assertEqual(d["persistent_mitre_split"]["technique wrong and attack type wrong in at least one run"], 3)
        self.assertEqual(d["per_class"]["Bot"], {"attacks": 3, "never": 0, "persistent": 2, "recurring": 1, "one_off": 0, "insufficient": 0})

    def test_stochastic_variation_counts(self):
        v = self.analysis()["variation"]
        self.assertEqual(v["alerts_with_2plus_valid"], 10)
        self.assertEqual(v["decision_differs"], 1)
        self.assertEqual(v["attack_type_differs"], 4)
        self.assertEqual(v["technique_differs"], 4)
        self.assertEqual(v["any_field_differs"], 4)
        self.assertEqual(v["status_differs"], 3)
        for value in v["pairwise_agreement"].values():
            self.assertTrue(0.0 <= value <= 1.0)

    def test_persistent_and_one_off_are_separated_in_the_patterns_file(self):
        rows = agg.error_pattern_rows(self.analysis()["rows"])
        by = {(r["alert_id"], r["kind"]): r for r in rows}
        self.assertEqual(by[("DEV-0001", "attack_type_error")]["category"], "persistent")
        self.assertEqual(by[("DEV-0002", "attack_type_error")]["category"], "recurring")
        self.assertEqual(by[("DEV-0003", "attack_type_error")]["category"], "one_off")
        self.assertNotIn(("DEV-0004", "attack_type_error"), by)
        self.assertEqual(by[("DEV-0008", "false_positive")]["category"], "persistent")
        self.assertEqual(by[("DEV-0009", "false_positive")]["category"], "one_off")
        self.assertEqual(by[("DEV-0001", "attack_type_error")]["run1_attack_type"], "PortScan")

    def test_per_alert_table_has_one_row_per_alert_with_every_run(self):
        rows = agg.per_alert_table(self.analysis()["rows"])
        self.assertEqual(len(rows), 11)
        for key in ["run1_attack_type", "run2_attack_type", "run3_attack_type", "attack_type_error_category", "attack_type_error_k_of_m", "no_verdict_category"]:
            self.assertIn(key, rows[0])
        self.assertEqual(rows[0]["attack_type_error_k_of_m"], "3/3")
        self.assertEqual(rows[7]["attack_type_error_category"], "n/a")

    def test_benign_alerts_are_not_scored_for_attack_type_or_mitre(self):
        rows = {r["alert_id"]: r for r in self.analysis()["rows"]}
        for kind in ["attack_type_error", "mitre_error", "missed_attack"]:
            self.assertIsNone(rows["DEV-0008"]["flags"][kind])
        for kind in ["false_positive"]:
            self.assertIsNone(rows["DEV-0001"]["flags"][kind])

    def test_conclusions_are_built_from_the_numbers_and_say_nothing_about_tuning(self):
        text = "\n".join(self.analysis()["conclusions"])
        self.assertIn("persistent", text)
        self.assertIn("not a reason to edit baseline_v3", text)
        self.assertIn("precision (valid verdicts only) averaged 90.00%", text)
        self.assertIn("an attack-type error", text)
        self.assertNotIn("a attack", text)
        self.assertNotIn("(0 of", text)

    def test_metrics_missing_from_an_evaluation_are_called_out_in_the_report(self):
        a = self.analysis()
        self.assertIn("mitre_valid", a["missing_metrics"])
        self.assertNotIn("precision_valid_only", a["missing_metrics"])
        self.assertIn("could not be read from at least one evaluation.json", agg.render_report(a))


# ------------------------------------------------------------------------------------------------ outputs and the aggregate command
class OutputTests(FixtureCase):
    def run_main(self, *extra):
        out = os.path.join(self.tmp, "out")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = agg.main(["--eval-root", self.eval_root, "--runs-root", self.runs_root, "--out-dir", out, "--no-reference"] + list(extra))
        return code, out, buf.getvalue()

    def test_writes_the_report_and_data_files(self):
        code, out, text = self.run_main()
        self.assertEqual(code, 0)
        self.assertEqual(sorted(os.listdir(out)), sorted(agg.OUTPUT_FILES))
        self.assertIn("Inputs unchanged: True", text)
        report = text_of(os.path.join(out, agg.REPORT_NAME))
        for heading in ["## 1. What was run", "## 2. Results per run, mean and spread", "## 3. Variation between the runs (stochastic)",
                        "## 4. Persistent, recurring and one-off errors", "## 5. Conclusions", "## 6. Limits"]:
            self.assertIn(heading, report)
        for name in NAMES:
            self.assertIn(name, report)
        self.assertIn(LOCKED_V3_SHA256, report)
        self.assertIn("sample standard deviation (n-1)", report)

    def test_the_metrics_csv_has_each_run_mean_sd_min_max_range(self):
        code, out, _ = self.run_main()
        frame = pd.read_csv(os.path.join(out, "three_run_metrics.csv"))
        row = frame[frame["metric"] == "precision_valid_only"].iloc[0]
        for name in NAMES:
            self.assertIn(name, frame.columns)
        self.assertAlmostEqual(row["mean"], 0.9)
        self.assertAlmostEqual(row["sd"], 0.1)
        self.assertAlmostEqual(row["range"], 0.2)

    def test_summary_json_records_method_hashes_and_conclusions(self):
        code, out, _ = self.run_main()
        s = jload(os.path.join(out, "three_run_summary.json"))
        self.assertEqual(s["runs"], NAMES)
        self.assertTrue(s["inputs_unchanged"])
        self.assertIn("n-1", s["spread_method"])
        self.assertEqual(s["error_categories"]["attack_type_error"]["persistent"], 3)
        self.assertEqual(len(s["input_file_sha256"]), 9)
        self.assertTrue(s["conclusions"])

    def test_inputs_are_not_modified(self):
        def digest():
            out = {}
            for root in (self.eval_root, self.runs_root):
                for folder, _, files in os.walk(root):
                    for n in files:
                        p = os.path.join(folder, n)
                        out[p] = sha_of(p)
            return out

        before = digest()
        self.run_main()
        self.assertEqual(digest(), before)

    def test_existing_outputs_are_not_overwritten_without_force(self):
        self.run_main()
        code, out, text = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("already exist", text)
        code, out, text = self.run_main("--force")
        self.assertEqual(code, 0)

    def test_incomparable_runs_stop_the_command_and_write_nothing(self):
        path = os.path.join(self.runs_root, NAMES[1], "run_meta.json")
        meta = jload(path)
        meta["prompt_sha256"] = "f" * 64
        jdump(meta, path)
        code, out, text = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("cannot be compared", text)
        self.assertFalse(os.path.exists(out))

    def test_a_missing_evaluation_names_the_command_to_run(self):
        os.remove(os.path.join(self.eval_root, NAMES[2], "evaluation.json"))
        code, out, text = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("python src/evaluate.py --run-name " + NAMES[2], text)

    def test_reference_run_is_shown_but_not_in_the_mean(self):
        ref = "dev_flash_lite_v3_final"
        shutil.copytree(os.path.join(self.eval_root, NAMES[0]), os.path.join(self.eval_root, ref))
        shutil.copytree(os.path.join(self.runs_root, NAMES[0]), os.path.join(self.runs_root, ref))
        ev_path = os.path.join(self.eval_root, ref, "evaluation.json")
        ev = jload(ev_path)
        ev["metrics"]["verdict"]["valid_only"]["llm"]["precision"]["value"] = 0.1234
        jdump(ev, ev_path)
        out = os.path.join(self.tmp, "out2")
        with contextlib.redirect_stdout(io.StringIO()):
            code = agg.main(["--eval-root", self.eval_root, "--runs-root", self.runs_root, "--out-dir", out])
        self.assertEqual(code, 0)
        s = jload(os.path.join(out, "three_run_summary.json"))
        row = [r for r in s["headline"] if r["key"] == "precision_valid_only"][0]
        self.assertAlmostEqual(row["mean"], 0.9)
        self.assertAlmostEqual(row["ref"], 0.1234)
        self.assertEqual(s["reference_run_not_in_mean"], ref)
        report = text_of(os.path.join(out, agg.REPORT_NAME))
        self.assertIn("not** in the mean or spread", report)

    def test_no_day_7_artifact_is_created(self):
        code, out, _ = self.run_main()
        names = os.listdir(out)
        self.assertNotIn("WEEK2_REPORT.md", names)
        self.assertEqual(agg.REPORT_NAME, "DAY6_THREE_RUN_REPORT.md")


# ------------------------------------------------------------------------------------------------ the replicate runner
class ReplicateCase(d5.RunnerDay5Case):
    def setUp(self):
        d5.RunnerDay5Case.setUp(self)
        self.go("--run-name", "dev_flash_lite_v1")
        self.go("--run-name", "dev_flash_lite_v3_final", "--prompt-version", "baseline_v3")
        self.client.prompts.clear()
        self.specs.clear()

    def d6(self, *args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                code = rep.main(["--runs-dir", self.runs_dir, "--rpm", "600", "--expected-alerts", "5"] + list(args))
            except SystemExit as stop:
                code = stop.code
        self.out = buf.getvalue()
        return code

    def meta(self, name):
        return store.read_json(self.dir_of(name).meta)

    def digest(self, name):
        return rep.folder_digest(os.path.join(self.runs_dir, name))


class PreflightTests(ReplicateCase):
    def test_check_passes_calls_nothing_and_writes_nothing(self):
        before = (self.digest("dev_flash_lite_v1"), self.digest("dev_flash_lite_v3_final"), sorted(os.listdir(self.runs_dir)))
        with mock.patch.object(runner, "make_client_for", side_effect=AssertionError("must not create a client")):
            code = self.d6("check")
        self.assertEqual(code, 0)
        self.assertIn("Preflight OK", self.out)
        self.assertIn(registry.get_prompt("baseline_v3").sha256, self.out)
        self.assertEqual((self.digest("dev_flash_lite_v1"), self.digest("dev_flash_lite_v3_final"), sorted(os.listdir(self.runs_dir))), before)
        self.assertFalse(os.path.exists(rep.manifest_path(self.runs_dir)))
        self.assertEqual(self.client.prompts, [])

    def test_the_locked_prompt_hash_is_the_one_in_the_repo(self):
        self.assertEqual(registry.get_prompt("baseline_v3").sha256, LOCKED_V3_SHA256)
        self.assertEqual(registry.get_prompt("baseline_v1").sha256, V1_SHA256)
        self.assertEqual(self.meta("dev_flash_lite_v3_final")["prompt_sha256"], LOCKED_V3_SHA256)

    def edit_reference(self, **changes):
        path = self.dir_of("dev_flash_lite_v3_final").meta
        meta = store.read_json(path)
        for k, v in changes.items():
            meta[k] = v
        store.write_json_atomic(path, meta)

    def test_a_changed_prompt_is_refused(self):
        self.edit_reference(prompt_sha256="0" * 64)
        self.assertEqual(self.d6("check"), 1)
        self.assertIn("not the one the reference run used", self.out)
        self.assertEqual(self.d6("run", "--replicate", "1"), 1)
        self.assertFalse(os.path.exists(self.dir_of(rep.REPLICATES[1]).path))
        self.assertEqual(self.client.prompts, [])

    def test_expected_sha_is_enforced_when_given(self):
        self.assertEqual(self.d6("check", "--expected-sha256", "0" * 64), 1)
        self.assertEqual(self.d6("check", "--expected-sha256", LOCKED_V3_SHA256), 0)

    def test_missing_reference_run_is_refused(self):
        shutil.rmtree(self.dir_of("dev_flash_lite_v3_final").path)
        self.assertEqual(self.d6("check"), 1)
        self.assertIn("no run_meta.json", self.out)

    def test_a_different_model_setting_or_input_is_refused(self):
        self.edit_reference(model="another-model")
        self.assertEqual(self.d6("check"), 1)
        self.edit_reference(model="gemini-2.5-flash-lite")
        self.assertEqual(self.d6("check"), 0)
        with mock.patch.object(llm_config, "TEMPERATURE", 0.7):
            self.assertEqual(self.d6("check"), 1)
            self.assertIn("setting temperature differs", self.out)
        self.edit_reference(inputs={"dev_alerts_sha256": "x", "flow_store_dev_sha256": "y"})
        self.assertEqual(self.d6("check"), 1)

    def test_a_different_alert_list_or_count_is_refused(self):
        self.edit_reference(selected_alert_ids=["DEV-0001"])
        self.assertEqual(self.d6("check"), 1)
        self.assertEqual(self.d6("check", "--expected-alerts", "300"), 1)

    def test_the_frozen_unlock_variable_is_refused(self):
        with mock.patch.dict(os.environ, {config.FROZEN_UNLOCK_ENV: config.FROZEN_UNLOCK_VALUE}):
            self.assertEqual(self.d6("check"), 1)
            self.assertIn("Unset it", self.out)
            self.assertEqual(self.d6("run", "--replicate", "1"), 1)
        self.assertFalse(os.path.exists(self.dir_of(rep.REPLICATES[1]).path))


class ReplicateRunTests(ReplicateCase):
    def test_one_replicate_makes_its_own_folder_with_the_locked_prompt(self):
        protected = (self.digest("dev_flash_lite_v1"), self.digest("dev_flash_lite_v3_final"))
        self.assertEqual(self.d6("run", "--replicate", "1"), 0)
        name = rep.REPLICATES[1]
        meta = self.meta(name)
        self.assertEqual((meta["prompt_version"], meta["prompt_sha256"], meta["set"], meta["status"]), ("baseline_v3", LOCKED_V3_SHA256, "dev", "complete"))
        self.assertEqual(meta["counts"], {"ok": 5, "parse_failed": 0, "model_error": 0})
        self.assertEqual(meta["selected_alert_ids"], list(self.alerts["alert_id"]))
        self.assertEqual(len(self.client.prompts), 5)
        self.assertEqual([s.version for s in self.specs], ["baseline_v3"])
        self.assertEqual((self.digest("dev_flash_lite_v1"), self.digest("dev_flash_lite_v3_final")), protected)
        self.assertFalse(os.path.exists(self.dir_of(rep.REPLICATES[2]).path))
        self.assertIn("python src/evaluate.py --run-name " + name, self.out)

    def test_all_three_are_separate_runs_with_the_same_alerts(self):
        self.assertEqual(self.d6("run", "--all"), 0)
        metas = [self.meta(rep.REPLICATES[n]) for n in (1, 2, 3)]
        self.assertEqual(len({m["run_name"] for m in metas}), 3)
        self.assertEqual(len({os.path.abspath(m["run_dir"]) for m in metas}), 3)
        self.assertEqual(len({m["prompt_sha256"] for m in metas}), 1)
        self.assertEqual(len({json.dumps(m["selected_alert_ids"]) for m in metas}), 1)
        self.assertEqual(len({json.dumps(m["settings"], sort_keys=True) for m in metas}), 1)
        self.assertEqual(len(self.client.prompts), 15)
        for m in metas:
            self.assertEqual(len(m["sessions"]), 1)
            self.assertTrue(m["frozen_access_log_unchanged"])
            self.assertTrue(m["week1_files_unchanged"])
            self.assertEqual(len(store.read_jsonl(os.path.join(m["run_dir"], "results.jsonl"))), 5)
            self.assertEqual(len(store.read_jsonl(os.path.join(m["run_dir"], "raw_responses.jsonl"))), 5)

    def test_every_replicate_gets_a_fresh_client(self):
        self.d6("run", "--all")
        self.assertEqual(len(self.specs), 3)

    def test_a_complete_replicate_is_never_run_again_or_changed(self):
        self.d6("run", "--replicate", "1")
        before = self.digest(rep.REPLICATES[1])
        calls = len(self.client.prompts)
        self.assertEqual(self.d6("run", "--replicate", "1"), 0)
        self.assertIn("already complete", self.out)
        self.assertEqual(len(self.client.prompts), calls)
        self.assertEqual(self.digest(rep.REPLICATES[1]), before)
        self.assertEqual(self.d6("run", "--all"), 0)
        self.assertEqual(len(self.client.prompts), calls + 10)
        self.assertEqual(self.digest(rep.REPLICATES[1]), before)

    def test_interrupted_replicate_needs_resume_and_keeps_its_prompt(self):
        self.client.script = [d3.GOOD, d3.GOOD, d3.gemini_client.PermanentModelError("quota", 403)]
        self.assertEqual(self.d6("run", "--replicate", "1"), 2)
        name = rep.REPLICATES[1]
        self.assertEqual(self.meta(name)["status"], "incomplete")
        self.assertEqual(self.d6("run", "--replicate", "1"), 1)
        self.assertIn("--resume", self.out)
        self.client.script = []
        self.assertEqual(self.d6("run", "--replicate", "1", "--resume"), 0)
        meta = self.meta(name)
        self.assertEqual(meta["status"], "complete")
        self.assertEqual(len(meta["sessions"]), 2)
        self.assertEqual(meta["prompt_sha256"], LOCKED_V3_SHA256)
        self.assertEqual(len(store.read_jsonl(self.dir_of(name).results)), 5)

    def test_resume_of_a_replicate_that_does_not_exist_is_refused(self):
        self.assertEqual(self.d6("run", "--replicate", "2", "--resume"), 1)
        self.assertFalse(os.path.exists(self.dir_of(rep.REPLICATES[2]).path))

    def test_all_stops_at_the_first_replicate_that_needs_attention(self):
        self.client.script = [d3.gemini_client.PermanentModelError("quota", 403)]
        self.assertEqual(self.d6("run", "--all"), 2)
        self.assertFalse(os.path.exists(self.dir_of(rep.REPLICATES[2]).path))
        self.assertFalse(os.path.exists(self.dir_of(rep.REPLICATES[3]).path))

    def test_a_replicate_with_parse_failures_is_complete_and_the_failures_stay_visible(self):
        self.client.script = ["not json"] * 3
        self.assertEqual(self.d6("run", "--replicate", "1"), 0)
        meta = self.meta(rep.REPLICATES[1])
        self.assertEqual(meta["counts"]["parse_failed"], 1)
        self.assertEqual(meta["counts"]["ok"], 4)

    def test_the_manifest_records_the_lock_and_the_replicates(self):
        self.d6("run", "--replicate", "1")
        m = rep.load_manifest(self.runs_dir)
        self.assertEqual(m["prompt_sha256"], LOCKED_V3_SHA256)
        self.assertEqual(m["prompt_version"], "baseline_v3")
        self.assertEqual(set(m["protected_runs"]), {"dev_flash_lite_v1", "dev_flash_lite_v3_final"})
        self.assertEqual(m["replicates"]["1"]["status"], "complete")
        self.assertIn("results.jsonl", m["replicates"]["1"]["run_file_sha256"])
        self.assertEqual(m["replicates"]["1"]["sessions"][0]["runner_exit_code"], 0)
        with open(rep.manifest_path(self.runs_dir), encoding="utf-8") as f:
            self.assertNotIn(d3.FAKE_KEY, f.read())

    def test_a_prompt_changed_since_the_first_replicate_is_refused(self):
        self.d6("run", "--replicate", "1")
        path = rep.manifest_path(self.runs_dir)
        m = store.read_json(path)
        m["prompt_sha256"] = "0" * 64
        store.write_json_atomic(path, m)
        self.assertEqual(self.d6("run", "--replicate", "2"), 1)
        self.assertIn("not locked", self.out)
        self.assertFalse(os.path.exists(self.dir_of(rep.REPLICATES[2]).path))

    def test_langsmith_without_a_key_stops_cleanly(self):
        self.assertEqual(self.d6("run", "--replicate", "1", "--langsmith"), 1)
        self.assertIn("LANGSMITH_API_KEY", self.out)
        self.assertEqual(self.client.prompts, [])

    def test_langsmith_traces_stay_metadata_only_in_replicates(self):
        os.environ["LANGSMITH_API_KEY"] = "k"
        with mock.patch.object(d5.tracing, "make_client", lambda environ=None: self.fake_ls):
            self.assertEqual(self.d6("run", "--replicate", "1", "--langsmith"), 0)
        blob = json.dumps(self.fake_ls.calls, default=str)
        for secret in ["10.0.0.1", "Alert:", "PortScan", "T1046", "GUIDANCE ON THE ATTACK CLASSES", "label"]:
            self.assertNotIn(secret, blob)
        for call in self.fake_ls.calls:
            self.assertTrue(set(call["extra"]["metadata"]) <= d5.tracing.ALLOWED_KEYS)

    def test_run_argument_rules(self):
        for argv in (["run"], ["run", "--replicate", "1", "--all"], ["check", "--replicate", "1"], ["run", "--all", "--resume"]):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    rep.parse_args(argv)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                rep.parse_args(["run", "--replicate", "4"])


class StatusTests(ReplicateCase):
    def test_status_is_clean_after_runs_and_detects_tampering(self):
        self.d6("run", "--all")
        self.assertEqual(self.d6("status"), 0)
        self.assertIn("baseline_v3 hash unchanged since the first replicate: True", self.out)
        self.assertIn("frozen access log unchanged", self.out)
        # the Day 3 reference run changes -> status fails
        with open(self.dir_of("dev_flash_lite_v1").results, "a") as f:
            f.write("\n")
        self.assertEqual(self.d6("status"), 1)
        self.assertIn("protected run dev_flash_lite_v1 unchanged: False", self.out)

    def test_status_detects_a_change_to_the_frozen_access_log(self):
        self.d6("run", "--replicate", "1")
        with open(self.log_path, "a") as f:
            f.write("2026-10-08T00:00:00Z\tframe\t-c\tunexpected\n")
        self.assertEqual(self.d6("status"), 1)
        self.assertIn("frozen access log unchanged", self.out)
        self.assertIn("False", self.out)

    def test_status_before_any_replicate_is_quiet(self):
        self.assertEqual(self.d6("status"), 0)
        self.assertIn("No Day 6 manifest yet", self.out)


class NamesTests(unittest.TestCase):
    def test_default_names_agree_between_the_two_modules(self):
        self.assertEqual(agg.DEFAULT_RUNS, [rep.REPLICATES[n] for n in (1, 2, 3)])
        self.assertEqual(agg.DEFAULT_REFERENCE, rep.REFERENCE_RUN)
        self.assertEqual(agg.POLICIES, ["valid_only", "failures_escalated", "failures_wrong"])

    def test_replicate_names_are_distinct_from_earlier_runs(self):
        for name in rep.REPLICATES.values():
            self.assertNotIn(name, rep.PROTECTED_RUNS)
            self.assertNotEqual(name, "dev_flash_lite_v1")


# ------------------------------------------------------------------------------------------------ separation
class Day6SeparationTests(unittest.TestCase):
    ALLOWED_TOP_LEVEL = {"os", "sys", "json", "math", "hashlib", "argparse", "datetime", "itertools", "collections", "pandas",
                         "config", "prompt_registry", "baseline_store", "run_baseline_dev"}
    FORBIDDEN_IMPORTS = ["eval_io", "eval_labels", "eval_metrics", "evaluate", "triage_inputs", "llm_config", "gemini_client", "langsmith",
                         "langchain", "langgraph", "chromadb", "requests", "urllib", "socket", "http", "anthropic", "openai", "numpy", "scipy", "sklearn"]

    def names(self, module):
        return d3.SeparationTests.names_used(d3.SeparationTests(), module)

    def test_day6_modules_never_touch_labels_answer_key_or_frozen_paths(self):
        for name in DAY6_MODULES:
            used, modules = self.names(name)
            self.assertEqual(sorted(used & d3.SeparationTests.FORBIDDEN_NAMES), [], name)
            self.assertEqual(sorted(modules & set(self.FORBIDDEN_IMPORTS)), [], name)
            text = read_source(name)
            self.assertNotIn('"frozen"', text)
            self.assertNotIn("'frozen'", text)
            self.assertNotIn(config.FROZEN_UNLOCK_VALUE, text)
            self.assertNotIn("AIza", text)

    def test_no_new_dependency_is_introduced(self):
        for name in DAY6_MODULES:
            tree = ast.parse(read_source(name))
            tops = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    tops.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    tops.add((node.module or "").split(".")[0])
            self.assertTrue(tops <= self.ALLOWED_TOP_LEVEL, name + ": " + str(sorted(tops - self.ALLOWED_TOP_LEVEL)))

    def test_the_aggregator_reads_only_day_4_outputs_and_run_metas(self):
        text = read_source("day6_aggregate.py")
        for forbidden in ["dev_labels.parquet", "mitre_map.csv", "frozen_alerts", "frozen_labels", "flow_store_frozen", "labels.parquet", "eval/MANIFEST"]:
            self.assertNotIn(forbidden, text)
        self.assertNotIn("import config", text)

    def test_day6_adds_no_week_3_or_day_7_artifacts(self):
        for name in DAY6_MODULES:
            text = read_source(name).lower()
            for forbidden in ["langgraph", "chromadb", "week2_report.md", "week2-baseline", "git tag", "\"tag\""]:
                self.assertNotIn(forbidden, text, name + ": " + forbidden)

    def test_neither_module_writes_to_the_baseline_or_earlier_runs(self):
        text = read_source("day6_aggregate.py")
        self.assertNotIn("runs_root, name", text.split("def write_outputs")[1])
        agg_writes = re.findall(r"open\(([^)]*), \"w\"", text)
        for target in agg_writes:
            self.assertIn("out_dir", target)

    def test_baseline_v3_and_v1_text_are_unchanged(self):
        self.assertEqual(registry.get_prompt("baseline_v3").sha256, LOCKED_V3_SHA256)
        self.assertEqual(baseline_prompt.prompt_sha256(), V1_SHA256)
        self.assertEqual(registry.get_prompt("baseline_v1").sha256, V1_SHA256)


if __name__ == "__main__":
    unittest.main()
