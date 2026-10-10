"""Week 3 Day 5 audit additions: the comparison against the baseline's Day 6 three-run spread. Offline: no model, no labels, no frozen set."""
import os
import sys
import json
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

import compare_agent_vs_baseline as compare
from tests import test_week3_day5 as d5

SETTINGS = {"temperature": 0.0, "max_output_tokens": 1024, "seed": 42, "parse_retries": 2, "timeout_seconds": 60, "transport_retries": 4}


def summary(**over):
    data = {"runs": ["rep1", "rep2", "rep3"], "prompt_version": "baseline_v3", "prompt_sha256": d5.BASELINE_V3_SHA, "model": "gemini-test", "settings": dict(SETTINGS),
            "n_alerts": 3, "inputs_unchanged": True,
            "headline": [{"key": "coverage", "mean": 0.99, "min": 0.98, "max": 1.0, "n_present": 3},
                         {"key": "attack_type_valid", "mean": 0.5, "min": 0.4, "max": 0.6, "n_present": 3},
                         {"key": "thinking_tokens", "mean": None, "min": None, "max": None, "n_present": 0}]}
    data.update(over)
    return data


class SpreadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        ev, br, ar = d5.make_runs(self.tmp.name)
        self.ev, self.br, self.ar = ev, br, ar
        self.baseline = compare.load_run("base", ev, br)
        self.agent = compare.load_run("agent", ev, ar)

    def write(self, **over):
        path = os.path.join(self.tmp.name, "three_run_summary.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(summary(**over), f)
        return path

    def test_position_is_inside_above_below_or_not_available(self):
        s = {"min": 0.4, "max": 0.6, "n_present": 3}
        self.assertEqual(compare.position(0.5, s), "inside range")
        self.assertEqual(compare.position(0.4, s), "inside range")
        self.assertEqual(compare.position(0.6, s), "inside range")
        self.assertEqual(compare.position(0.61, s), "above range")
        self.assertEqual(compare.position(0.39, s), "below range")
        self.assertEqual(compare.position(None, s), "n/a")
        self.assertEqual(compare.position(0.5, None), "n/a")
        self.assertEqual(compare.position(0.5, {"min": None, "max": None, "n_present": 0}), "n/a")

    def test_a_matching_summary_loads(self):
        spread = compare.load_spread(self.write(), self.agent)
        self.assertEqual(spread["runs"], ["rep1", "rep2", "rep3"])
        self.assertEqual(spread["metrics"]["coverage"]["max"], 1.0)
        self.assertEqual(len(spread["file_sha256"]), 64)

    def test_each_kind_of_mismatch_is_refused(self):
        cases = {"prompt_sha256": "0" * 64, "prompt_version": "baseline_v2", "model": "gemini-other", "n_alerts": 300, "inputs_unchanged": False, "headline": None,
                 "settings": dict(SETTINGS, seed=7)}
        for key, value in cases.items():
            with self.assertRaises(compare.ComparisonError, msg=key):
                compare.load_spread(self.write(**{key: value}), self.agent)

    def test_a_missing_file_is_refused(self):
        with self.assertRaises(compare.ComparisonError):
            compare.load_spread(os.path.join(self.tmp.name, "nope.json"), self.agent)

    def test_rows_carry_the_baseline_mean_range_and_position(self):
        spread = compare.load_spread(self.write(), self.agent)
        rows = {r["key"]: r for r in compare.metric_rows(self.baseline, self.agent, spread)}
        self.assertEqual(rows["coverage"]["agent_vs_baseline_range"], "inside range")
        self.assertEqual(rows["attack_type_valid"]["agent_vs_baseline_range"], "above range")
        self.assertEqual(rows["attack_type_valid"]["baseline_3run_range_display"], "40.00% to 60.00%")
        self.assertEqual(rows["total_tokens"]["agent_vs_baseline_range"], "n/a")
        self.assertEqual(rows["total_tokens"]["baseline_3run_range_display"], "n/a")

    def test_without_a_summary_the_rows_and_files_are_unchanged(self):
        rows = compare.metric_rows(self.baseline, self.agent)
        self.assertNotIn("agent_vs_baseline_range", rows[0])
        out = os.path.join(self.tmp.name, "plain")
        compare.write_outputs(out, self.baseline, self.agent, rows)
        with open(os.path.join(out, "comparison_metrics.csv"), encoding="utf-8") as f:
            self.assertEqual(f.readline().strip(), "key,metric,unit,baseline,agent,agent_minus_baseline")
        with open(os.path.join(out, "COMPARISON_REPORT.md"), encoding="utf-8") as f:
            self.assertNotIn("three-run spread", f.read())

    def test_the_report_shows_the_spread_and_does_not_judge(self):
        spread = compare.load_spread(self.write(), self.agent)
        rows = compare.metric_rows(self.baseline, self.agent, spread)
        out = os.path.join(self.tmp.name, "with_spread")
        compare.write_outputs(out, self.baseline, self.agent, rows, spread=spread)
        with open(os.path.join(out, "COMPARISON_REPORT.md"), encoding="utf-8") as f:
            text = f.read()
        for needle in ("three-run spread", "rep1, rep2, rep3", "Baseline 3-run range", "40.00% to 60.00%", "above range", "not a significance test", spread["file_sha256"]):
            self.assertIn(needle, text)
        for word in ("improved", "improvement", "better", "worse", "outperform", "beats"):
            self.assertNotIn(word, text.lower(), word)
        with open(os.path.join(out, "comparison_metrics.csv"), encoding="utf-8") as f:
            self.assertIn("agent_vs_baseline_range", f.readline())
        with open(os.path.join(out, "comparison.json"), encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["baseline_three_run_spread"]["runs"], ["rep1", "rep2", "rep3"])
        self.assertFalse(data["labels_read"])

    def test_main_uses_the_summary_and_refuses_a_bad_one_without_writing(self):
        out = os.path.join(self.tmp.name, "report")
        argv = ["--agent-run", "agent", "--baseline-run", "base", "--eval-root", self.ev, "--baseline-runs-root", self.br, "--agent-runs-root", self.ar, "--out-dir", out]
        with mock.patch("sys.stdout"):
            self.assertEqual(compare.main(argv + ["--three-run-summary", self.write(model="gemini-other")]), 2)
            self.assertFalse(os.path.exists(out))
            self.assertEqual(compare.main(argv + ["--three-run-summary", self.write()]), 0)
        self.assertTrue(os.path.exists(os.path.join(out, "COMPARISON_REPORT.md")))


if __name__ == "__main__":
    unittest.main()
