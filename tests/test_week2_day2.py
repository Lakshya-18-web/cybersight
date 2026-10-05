"""Week 2, Day 2 checks: verdict schema, parser, validation and retries.

Canned reply strings only. No network, no model call, no labels, no evaluation files.
Run from the project root:  python -m unittest tests.test_week2_day2 -v
"""
import ast
import os
import sys
import json
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import verdict_schema
import verdict_parser
from verdict_parser import parse_verdict, parse_with_retries, build_repair_prompt, ERROR_CODES

MALICIOUS = {"is_malicious": True, "attack_type": "PortScan", "mitre_technique": "T1046", "severity": "medium",
             "evidence": "One source sent 800 tiny flows to 790 different destination ports within two minutes."}
BENIGN = {"is_malicious": False, "attack_type": "BENIGN", "mitre_technique": "NONE", "severity": "none",
          "evidence": "Single short HTTPS flow with normal packet sizes; no repeated targets nearby."}


def j(**changes):
    data = dict(MALICIOUS)
    data.update(changes)
    return json.dumps(data)


def without(key, base=MALICIOUS):
    return json.dumps({k: v for k, v in base.items() if k != key})


def read_source(name):
    with open(os.path.join(ROOT, "src", name), encoding="utf-8") as f:
        return f.read()


class ValidReplies(unittest.TestCase):
    def test_valid_malicious_json(self):
        r = parse_verdict(json.dumps(MALICIOUS))
        self.assertTrue(r.ok)
        self.assertEqual(r.verdict.attack_type, "PortScan")
        self.assertEqual(r.repairs, [])

    def test_valid_benign_json(self):
        r = parse_verdict(json.dumps(BENIGN))
        self.assertTrue(r.ok)
        self.assertFalse(r.verdict.is_malicious)

    def test_subtechnique_ok(self):
        self.assertTrue(parse_verdict(j(attack_type="Bot", mitre_technique="T1071.001", severity="high")).ok)

    def test_every_attack_class_and_severity_accepted(self):
        for name in verdict_schema.ATTACK_TYPES:
            data = dict(BENIGN) if name == "BENIGN" else dict(MALICIOUS, attack_type=name)
            self.assertTrue(parse_verdict(json.dumps(data)).ok, name)
        for severity in ["low", "medium", "high", "critical"]:
            self.assertTrue(parse_verdict(j(severity=severity)).ok, severity)

    def test_code_fence_is_removed(self):
        r = parse_verdict("```json\n" + json.dumps(MALICIOUS, indent=2) + "\n```")
        self.assertTrue(r.ok)
        self.assertIn("removed_code_fence", r.repairs)

    def test_prose_around_json_is_ignored(self):
        r = parse_verdict("Here is my verdict:\n" + json.dumps(MALICIOUS) + "\nHope that helps.")
        self.assertTrue(r.ok)
        self.assertIn("ignored_text_around_json", r.repairs)

    def test_trailing_comma_is_removed(self):
        text = json.dumps(MALICIOUS)[:-1] + ",}"
        r = parse_verdict(text)
        self.assertTrue(r.ok)
        self.assertIn("removed_trailing_comma", r.repairs)

    def test_braces_inside_evidence_do_not_break_extraction(self):
        r = parse_verdict(j(evidence='Payload looked like {"a": 1} and a } character.'))
        self.assertTrue(r.ok)

    def test_evidence_whitespace_is_trimmed(self):
        self.assertEqual(parse_verdict(j(evidence="  padded  ")).verdict.evidence, "padded")


class MalformedReplies(unittest.TestCase):
    def code(self, text):
        r = parse_verdict(text)
        self.assertFalse(r.ok, text)
        self.assertIn(r.error_code, ERROR_CODES)
        return r.error_code

    def test_empty_and_none(self):
        self.assertEqual(self.code(""), "empty_response")
        self.assertEqual(self.code("   \n"), "empty_response")
        self.assertEqual(self.code(None), "empty_response")

    def test_no_json(self):
        self.assertEqual(self.code("I think this is a port scan."), "no_json")

    def test_truncated_json(self):
        self.assertEqual(self.code(json.dumps(MALICIOUS)[:-25]), "invalid_json")

    def test_broken_json(self):
        self.assertEqual(self.code("{'is_malicious': true}"), "invalid_json")
        self.assertEqual(self.code('{"is_malicious": true "attack_type": "Bot"}'), "invalid_json")

    def test_duplicate_keys(self):
        text = json.dumps(MALICIOUS)[:-1] + ', "severity": "low"}'
        self.assertEqual(self.code(text), "invalid_json")

    def test_list_instead_of_object(self):
        self.assertEqual(self.code("[" + json.dumps(MALICIOUS) + "]"), "not_an_object")

    def test_two_objects(self):
        self.assertEqual(self.code(json.dumps(MALICIOUS) + "\n" + json.dumps(BENIGN)), "multiple_json_objects")

    def test_each_missing_field(self):
        for key in verdict_schema.FIELDS:
            r = parse_verdict(without(key))
            self.assertFalse(r.ok, key)
            self.assertEqual(r.error_code, "missing_fields", key)
            self.assertIn(key, r.error_detail)

    def test_empty_object(self):
        self.assertEqual(self.code("{}"), "missing_fields")


class InvalidValues(unittest.TestCase):
    def code(self, text):
        r = parse_verdict(text)
        self.assertFalse(r.ok, text)
        return r.error_code

    def test_invalid_attack_type(self):
        for bad in ["Infiltration", "Heartbleed", "portscan", "Port Scan", "Web Attack - XSS", "Web Attack - SQL Injection", "unknown", "", None]:
            self.assertEqual(self.code(j(attack_type=bad)), "invalid_field", str(bad))

    def test_invalid_mitre_technique(self):
        for bad in ["1046", "T46", "T10466", "t1046", "T1046.1", "T1046.0011", "T1046 ", "TA0007", "none", "", None, 1046, "T1046, T1595"]:
            data = dict(MALICIOUS, mitre_technique=bad)
            r = parse_verdict(json.dumps(data))
            if bad == "T1046 ":
                self.assertTrue(r.ok)  # surrounding spaces are trimmed, the id itself is valid
                continue
            self.assertFalse(r.ok, repr(bad))
            self.assertEqual(r.error_code, "invalid_field", repr(bad))

    def test_invalid_severity(self):
        for bad in ["urgent", "Medium", "HIGH", "moderate", "", None, 3]:
            self.assertEqual(self.code(j(severity=bad)), "invalid_field", str(bad))

    def test_is_malicious_must_be_a_real_boolean(self):
        for bad in ["true", "True", "yes", 1, 0, None, "false"]:
            self.assertEqual(self.code(j(is_malicious=bad)), "invalid_field", repr(bad))

    def test_evidence_required(self):
        for bad in ["", "   ", None, 5, ["a"]]:
            self.assertEqual(self.code(j(evidence=bad)), "invalid_field", repr(bad))

    def test_evidence_too_long(self):
        self.assertEqual(self.code(j(evidence="x" * (verdict_schema.EVIDENCE_MAX_CHARS + 1))), "invalid_field")
        self.assertTrue(parse_verdict(j(evidence="x" * verdict_schema.EVIDENCE_MAX_CHARS)).ok)


class ContradictoryAndExtra(unittest.TestCase):
    def code(self, data):
        r = parse_verdict(json.dumps(data))
        self.assertFalse(r.ok, str(data))
        return r.error_code

    def test_contradictions(self):
        cases = [
            dict(MALICIOUS, is_malicious=False),                                  # attack class but not malicious
            dict(BENIGN, is_malicious=True),                                      # BENIGN but malicious
            dict(BENIGN, mitre_technique="T1046"),                                # benign with a technique
            dict(MALICIOUS, mitre_technique="NONE"),                              # attack without a technique
            dict(BENIGN, severity="high"),                                        # benign with severity
            dict(MALICIOUS, severity="none"),                                     # attack without severity
        ]
        for data in cases:
            self.assertEqual(self.code(data), "contradictory", str(data))

    def test_extra_fields(self):
        for extra in [{"confidence": 0.9}, {"label": "PortScan"}, {"reasoning": "x"}, {"alert_id": "DEV-0001"}]:
            self.assertEqual(self.code(dict(MALICIOUS, **extra)), "extra_fields", str(extra))

    def test_wrong_field_name_counts_as_missing_and_extra(self):
        data = {k: v for k, v in MALICIOUS.items() if k != "severity"}
        data["risk"] = "medium"
        r = parse_verdict(json.dumps(data))
        self.assertFalse(r.ok)
        self.assertEqual(r.error_code, "missing_fields")
        self.assertIn("risk", r.error_detail)


class Replies:
    """A fake model that returns canned replies in order and remembers the prompts it was given."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.prompts = []

    def __call__(self, prompt):
        self.prompts.append(prompt)
        return self.replies[len(self.prompts) - 1]


class RetryTests(unittest.TestCase):
    PROMPT = "ALERT: {...}"

    def test_valid_first_try_makes_one_call(self):
        model = Replies(json.dumps(MALICIOUS))
        out = parse_with_retries(model, self.PROMPT, max_retries=2)
        self.assertEqual(out.attempts, 1)
        self.assertFalse(out.malformed_final)
        self.assertFalse(out.malformed_first_try)
        self.assertEqual(len(model.prompts), 1)
        self.assertEqual(model.prompts[0], self.PROMPT)

    def test_repairs_after_malformed_json(self):
        model = Replies(json.dumps(MALICIOUS)[:-30], json.dumps(MALICIOUS))
        out = parse_with_retries(model, self.PROMPT, max_retries=2)
        self.assertEqual(out.attempts, 2)
        self.assertIsNotNone(out.verdict)
        self.assertTrue(out.malformed_first_try)
        self.assertFalse(out.malformed_final)
        self.assertEqual(out.attempt_log[0]["error_code"], "invalid_json")
        self.assertIsNone(out.attempt_log[1]["error_code"])

    def test_repair_prompt_contains_the_problem_and_the_previous_reply(self):
        bad = j(severity="urgent")
        model = Replies(bad, json.dumps(MALICIOUS))
        parse_with_retries(model, self.PROMPT, max_retries=2)
        second = model.prompts[1]
        self.assertTrue(second.startswith(self.PROMPT))
        self.assertIn("invalid_field", second)
        self.assertIn("severity", second)
        self.assertIn("urgent", second)
        self.assertIn("is_malicious", second)

    def test_repairs_a_contradiction(self):
        model = Replies(json.dumps(dict(MALICIOUS, is_malicious=False)), json.dumps(MALICIOUS))
        out = parse_with_retries(model, self.PROMPT, max_retries=1)
        self.assertEqual(out.attempt_log[0]["error_code"], "contradictory")
        self.assertEqual(out.attempts, 2)

    def test_two_failures_then_success(self):
        model = Replies("no idea", j(attack_type="Infiltration"), json.dumps(BENIGN))
        out = parse_with_retries(model, self.PROMPT, max_retries=2)
        self.assertEqual([e["error_code"] for e in out.attempt_log], ["no_json", "invalid_field", None])
        self.assertEqual(out.attempts, 3)
        self.assertFalse(out.verdict.is_malicious)

    def test_gives_up_after_the_retry_limit(self):
        model = Replies("a", "b", "c", "d")
        out = parse_with_retries(model, self.PROMPT, max_retries=2)
        self.assertEqual(len(model.prompts), 3)
        self.assertTrue(out.malformed_final)
        self.assertIsNone(out.verdict)
        self.assertEqual(out.attempts, 3)

    def test_zero_retries_means_one_call(self):
        model = Replies("garbage", json.dumps(MALICIOUS))
        out = parse_with_retries(model, self.PROMPT, max_retries=0)
        self.assertEqual(len(model.prompts), 1)
        self.assertTrue(out.malformed_final)

    def test_default_retry_count_comes_from_llm_config(self):
        import llm_config
        model = Replies(*["bad"] * 10)
        out = parse_with_retries(model, self.PROMPT)
        self.assertEqual(out.attempts, llm_config.MAX_RETRIES + 1)

    def test_negative_retries_rejected(self):
        with self.assertRaises(ValueError):
            parse_with_retries(Replies("x"), self.PROMPT, max_retries=-1)

    def test_model_errors_are_not_swallowed(self):
        def broken(prompt):
            raise ConnectionError("network down")
        with self.assertRaises(ConnectionError):
            parse_with_retries(broken, self.PROMPT, max_retries=2)

    def test_local_repair_does_not_use_up_a_retry(self):
        model = Replies("```json\n" + json.dumps(MALICIOUS) + "\n```")
        out = parse_with_retries(model, self.PROMPT, max_retries=2)
        self.assertEqual(out.attempts, 1)
        self.assertIn("removed_code_fence", out.repairs)

    def test_long_previous_reply_is_cut_in_the_repair_prompt(self):
        r = parse_verdict("x" * 5000 + " {")
        prompt = build_repair_prompt(self.PROMPT, "x" * 5000, r)
        self.assertLess(len(prompt), 5000)
        self.assertIn("[cut]", prompt)


class Consistency(unittest.TestCase):
    def test_exactly_the_five_blueprint_fields(self):
        self.assertEqual(sorted(verdict_schema.Verdict.model_fields), sorted(["is_malicious", "attack_type", "mitre_technique", "severity", "evidence"]))
        self.assertEqual(verdict_schema.FIELDS, ["is_malicious", "attack_type", "mitre_technique", "severity", "evidence"])

    def test_classes_match_day1_and_week1(self):
        import triage_schema
        self.assertEqual(sorted(verdict_schema.ATTACK_TYPES), sorted(triage_schema.ATTACK_TYPES))
        self.assertEqual(len(verdict_schema.ATTACK_TYPES), 12)
        for dropped in ["Infiltration", "Heartbleed"]:
            self.assertNotIn(dropped, verdict_schema.ATTACK_TYPES)

    def test_every_error_code_is_produced_by_some_reply(self):
        samples = ["", "plain words", "{'a': 1}", json.dumps(MALICIOUS) + json.dumps(BENIGN), "[1]", "{}",
                   json.dumps(dict(MALICIOUS, label="x")), j(severity="urgent"), json.dumps(dict(MALICIOUS, is_malicious=False))]
        produced = {parse_verdict(s).error_code for s in samples}
        self.assertEqual(produced, set(ERROR_CODES))
        self.assertEqual(len(ERROR_CODES), len(set(ERROR_CODES)))


class Separation(unittest.TestCase):
    FORBIDDEN = {"load_labels", "load_mitre_map", "MITRE_MAP", "eval_labels", "eval_io", "DEV_LABELS_PATH", "FROZEN_LABELS_PATH",
                 "FROZEN_ALERTS_PATH", "FLOW_STORE_FROZEN_PATH", "MITRE_MAP_PATH", "load_dev_labels", "load_answer_key", "config"}

    def test_day2_sources_do_not_touch_labels_answer_key_or_frozen_files(self):
        for name in ["verdict_schema.py", "verdict_parser.py"]:
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
            self.assertEqual(sorted(used & self.FORBIDDEN), [], name)

    def test_no_model_sdk_imported(self):
        for name in ["verdict_schema.py", "verdict_parser.py"]:
            text = read_source(name)
            for sdk in ["google", "genai", "requests", "urllib", "http", "socket", "langsmith", "langchain"]:
                self.assertNotIn("import " + sdk, text, name)
                self.assertNotIn("from " + sdk, text, name)

    def test_no_key_like_string(self):
        for name in ["verdict_schema.py", "verdict_parser.py"]:
            self.assertNotIn("AIza", read_source(name))


if __name__ == "__main__":
    unittest.main()
