"""Week 2, Day 1 checks. No network, no API calls, no labels, no frozen set.

Run from the project root:  python -m unittest tests.test_week2_day1 -v
(or: python tests/test_week2_day1.py)
"""
import ast
import os
import sys
import json
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import pandas as pd
from pydantic import ValidationError

import triage_schema
import llm_config
import triage_inputs
from triage_schema import TriageVerdict, ATTACK_TYPES

GOOD = dict(alert_id="DEV-0001", verdict="true_positive", attack_type="PortScan", mitre_technique="T1046", confidence=0.9,
            reasoning="Many tiny flows to many ports.", recommended_action="Block the source and review.")


def read_source(name):
    with open(os.path.join(ROOT, "src", name), encoding="utf-8") as f:
        return f.read()


AGENT_SIDE = ["triage_schema.py", "llm_config.py", "triage_inputs.py"]
FORBIDDEN_NAMES = {"load_labels", "load_mitre_map", "MITRE_MAP", "eval_labels", "DEV_LABELS_PATH", "FROZEN_LABELS_PATH",
                   "FROZEN_ALERTS_PATH", "FLOW_STORE_FROZEN_PATH", "MITRE_MAP_PATH", "load_dev_labels", "load_answer_key"}


class SchemaTests(unittest.TestCase):
    def test_valid_true_and_false_positive(self):
        TriageVerdict(**GOOD)
        TriageVerdict(**{**GOOD, "verdict": "false_positive", "attack_type": "BENIGN", "mitre_technique": "NONE"})

    def test_exactly_seven_fields(self):
        self.assertEqual(sorted(TriageVerdict.model_fields),
                         sorted(["alert_id", "verdict", "attack_type", "mitre_technique", "confidence", "reasoning", "recommended_action"]))

    def test_twelve_attack_types_with_benign(self):
        self.assertEqual(len(ATTACK_TYPES), 12)
        self.assertIn("BENIGN", ATTACK_TYPES)
        self.assertNotIn("Infiltration", ATTACK_TYPES)
        self.assertNotIn("Heartbleed", ATTACK_TYPES)

    def test_bad_outputs_rejected(self):
        bad = [{**GOOD, "verdict": "false_positive"},
               {**GOOD, "attack_type": "Infiltration"},
               {**GOOD, "mitre_technique": "1046"},
               {**GOOD, "verdict": "false_positive", "attack_type": "BENIGN"},
               {**GOOD, "attack_type": "BENIGN", "mitre_technique": "NONE"},
               {**GOOD, "mitre_technique": "NONE"},
               {**GOOD, "confidence": 1.5},
               {**GOOD, "confidence": -0.1},
               {**GOOD, "label": "PortScan"},
               {**GOOD, "reasoning": ""},
               {k: v for k, v in GOOD.items() if k != "reasoning"}]
        for item in bad:
            with self.assertRaises(ValidationError, msg=str(item)):
                TriageVerdict(**item)

    def test_subtechnique_accepted(self):
        TriageVerdict(**{**GOOD, "attack_type": "Bot", "mitre_technique": "T1071.001"})

    def test_json_round_trip(self):
        v = TriageVerdict(**GOOD)
        self.assertEqual(TriageVerdict.model_validate_json(v.model_dump_json()), v)


class ConfigTests(unittest.TestCase):
    def test_models_and_no_key_leak(self):
        old = os.environ.pop("GEMINI_API_KEY", None)
        try:
            os.environ["GEMINI_API_KEY"] = "AIza-test-not-real"
            info = llm_config.describe()
            self.assertTrue(info["api_key_present"])
            self.assertNotIn("AIza-test-not-real", json.dumps(info))
        finally:
            os.environ.pop("GEMINI_API_KEY", None)
            if old is not None:
                os.environ["GEMINI_API_KEY"] = old
        self.assertEqual(set(llm_config.models()), {"small", "strong"})

    def test_missing_key_message_has_no_secret(self):
        old = os.environ.pop("GEMINI_API_KEY", None)
        try:
            if not os.path.exists(llm_config.ENV_PATH):
                with self.assertRaises(RuntimeError):
                    llm_config.get_api_key()
        finally:
            if old is not None:
                os.environ["GEMINI_API_KEY"] = old

    def test_no_key_like_string_in_sources(self):
        for name in AGENT_SIDE + ["eval_labels.py"]:
            text = read_source(name)
            self.assertNotIn("AIza", text)

    def test_env_file_is_not_shipped_and_is_ignored(self):
        self.assertTrue(os.path.exists(os.path.join(ROOT, ".env.example")))
        gitignore = os.path.join(ROOT, ".gitignore")
        if os.path.exists(gitignore):
            lines = [l.strip() for l in open(gitignore, encoding="utf-8")]
            self.assertIn(".env", lines, "add a line '.env' to .gitignore before creating your .env")


class InputTests(unittest.TestCase):
    def setUp(self):
        t0 = pd.Timestamp("2017-07-05 10:00:00")
        self.store = pd.DataFrame({
            "flow_row": range(6),
            "timestamp": [t0, t0 + pd.Timedelta(minutes=1), t0 + pd.Timedelta(minutes=2), t0 + pd.Timedelta(minutes=30), t0, t0],
            "src_ip": ["10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.1"],
            "dst_ip": ["a", "b", "b", "c", "a", "a"],
            "dst_port": [80, 81, 82, 80, 80, 80],
        })
        self.alert = pd.Series({"alert_id": "DEV-0001", "flow_row": 0, "timestamp": t0, "src_ip": "10.0.0.1", "dst_ip": "a",
                                "dst_port": 80, "detector_score": 0.7})

    def test_context_counts(self):
        out = triage_inputs.build_model_input(self.alert, self.store)
        self.assertEqual(out["context"]["flows_from_same_source"], 4)
        self.assertEqual(out["context"]["distinct_destination_ports"], 3)
        self.assertEqual(out["context"]["distinct_destination_ips"], 2)

    def test_input_is_json_and_has_no_link_column(self):
        out = triage_inputs.build_model_input(self.alert, self.store)
        text = triage_inputs.to_prompt_json(out)
        self.assertIn("DEV-0001", text)
        self.assertNotIn("flow_row", out["alert"])
        json.loads(text)

    def test_label_columns_are_rejected(self):
        for column in ["label", "Label", "is_attack", "source_file", "original_row", "mitre_technique_id"]:
            frame = pd.DataFrame({"alert_id": ["x"], column: [1]})
            with self.assertRaises(ValueError, msg=column):
                triage_inputs.assert_label_free(frame)

    def test_label_column_never_reaches_model_input(self):
        row = self.alert.copy()
        row["label"] = "PortScan"
        out = triage_inputs.build_model_input(row, self.store)
        self.assertNotIn("label", out["alert"])


class SeparationTests(unittest.TestCase):
    """Agent-side modules must not reach labels, the answer key or the frozen set."""

    def test_agent_side_sources_do_not_touch_labels(self):
        for name in AGENT_SIDE:
            tree = ast.parse(read_source(name))
            used = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    used.add(node.id)
                elif isinstance(node, ast.Attribute):
                    used.add(node.attr)
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    for alias in node.names:
                        used.add(alias.name.split(".")[-1])
                    if isinstance(node, ast.ImportFrom) and node.module:
                        used.add(node.module.split(".")[-1])
            self.assertEqual(sorted(used & FORBIDDEN_NAMES), [], name)

    def test_agent_side_never_selects_the_frozen_set(self):
        text = read_source("triage_inputs.py")
        self.assertNotIn('"frozen"', text)
        self.assertNotIn("'frozen'", text)
        self.assertNotIn("SOC_FROZEN_UNLOCK", text)

    def test_eval_labels_reads_dev_only(self):
        text = read_source("eval_labels.py")
        self.assertNotIn('"frozen"', text)


@unittest.skipUnless(os.path.exists(os.path.join(ROOT, "eval", "dev_alerts.parquet")) and os.path.exists(os.path.join(ROOT, "eval", "flow_store_dev.parquet")),
                     "dev files not present")
class RealDevTests(unittest.TestCase):
    """Reads only the dev alerts and dev flow store. Opens no labels and no frozen file."""

    def test_dev_alerts_and_context(self):
        alerts = triage_inputs.load_dev_alerts()
        store = triage_inputs.load_dev_flow_store()
        self.assertEqual(len(alerts), 300)
        self.assertTrue(alerts["alert_id"].is_unique)
        self.assertTrue(all(a.startswith("DEV-") for a in alerts["alert_id"]))
        for i in (0, 150, 299):
            out = triage_inputs.build_model_input(alerts.iloc[i], store)
            json.loads(triage_inputs.to_prompt_json(out))
            self.assertGreaterEqual(out["context"]["flows_from_same_source"], 1)


if __name__ == "__main__":
        unittest.main()
