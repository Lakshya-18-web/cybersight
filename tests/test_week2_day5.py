import io
import ast
import os
import re
import sys
import json
import shutil
import hashlib
import tempfile
import unittest
import contextlib
import importlib
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

import config
import llm_config
import verdict_schema
import baseline_prompt
import baseline_store as store
import gemini_client
import run_baseline_dev as runner
import prompt_registry as registry
import cost_tracking
import langsmith_tracing as tracing

from tests import test_week2_day3 as d3

PINNED_V1_SHA256 = "0208c856dc1063ef5e249fcffdb28af803bd2899fa87977dde0ac4a23b06f172"
DAY5_MODULES = ["prompt_registry.py", "cost_tracking.py", "langsmith_tracing.py"]
FIVE = ["is_malicious", "attack_type", "mitre_technique", "severity", "evidence"]
CLASS_NAMES = [name for name in verdict_schema.ATTACK_TYPES]
TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?")

# Fixture prices for tests only. They are not provider prices and appear in no source file.
FIXTURE_PRICING = {"currency": "TEST", "per_million_input_tokens": 2.0, "per_million_output_tokens": 4.0,
                   "thinking_tokens_billed_as": "output", "source": "unit-test fixture", "as_of": "2000-01-01"}


def read_source(name):
    with open(os.path.join(ROOT, "src", name), encoding="utf-8") as f:
        return f.read()


def contract_block():
    return registry.OUTPUT_CONTRACT_BLOCK


def guidance_block():
    return registry.CLASS_GUIDANCE_BLOCK


# ------------------------------------------------------------------------------------------------ prompts
class RegistryTests(unittest.TestCase):
    def test_baseline_v1_hash_is_unchanged(self):
        self.assertEqual(baseline_prompt.prompt_sha256(), PINNED_V1_SHA256)
        self.assertEqual(registry.get_prompt("baseline_v1").sha256, PINNED_V1_SHA256)
        self.assertEqual(registry.compute_sha256("baseline_v1", baseline_prompt.SYSTEM_PROMPT, baseline_prompt.USER_TEMPLATE), PINNED_V1_SHA256)

    def test_baseline_v1_in_the_registry_is_the_day_3_text(self):
        spec = registry.get_prompt("baseline_v1")
        self.assertEqual(spec.version, baseline_prompt.PROMPT_VERSION)
        self.assertEqual(spec.system_prompt, baseline_prompt.SYSTEM_PROMPT)
        self.assertEqual(spec.user_template, baseline_prompt.USER_TEMPLATE)

    def test_exactly_three_versions_are_registered(self):
        self.assertEqual(registry.list_versions(), ["baseline_v1", "baseline_v2", "baseline_v3"])

    def test_v2_and_v3_resolve_and_each_exposes_the_four_parts(self):
        for version in ["baseline_v2", "baseline_v3"]:
            spec = registry.get_prompt(version)
            self.assertEqual(spec.version, version)
            self.assertTrue(len(spec.system_prompt) > 1000)
            self.assertIn("{alert_json}", spec.user_template)
            self.assertRegex(spec.sha256, r"^[0-9a-f]{64}$")

    def test_default_is_v1_and_unknown_versions_are_refused(self):
        self.assertEqual(registry.get_prompt().version, "baseline_v1")
        self.assertEqual(registry.get_prompt(None).version, "baseline_v1")
        with self.assertRaises(KeyError):
            registry.get_prompt("baseline_v4")

    def test_hashes_are_deterministic_and_distinct(self):
        hashes = {}
        for version in registry.list_versions():
            spec = registry.get_prompt(version)
            again = registry.compute_sha256(spec.version, spec.system_prompt, spec.user_template)
            self.assertEqual(spec.sha256, again)
            self.assertEqual(spec.sha256, registry.get_prompt(version).sha256)
            hashes[version] = spec.sha256
        self.assertEqual(len(set(hashes.values())), 3)
        reloaded = importlib.reload(registry)
        try:
            for version in hashes:
                self.assertEqual(reloaded.get_prompt(version).sha256, hashes[version])
        finally:
            importlib.reload(registry)

    def test_the_hash_formula_is_the_one_baseline_v1_uses(self):
        spec = registry.get_prompt("baseline_v2")
        text = "baseline_v2" + "\n" + spec.system_prompt + "\n----\n" + spec.user_template
        self.assertEqual(spec.sha256, hashlib.sha256(text.encode("utf-8")).hexdigest())

    def test_v2_and_v3_keep_the_v1_text_as_a_prefix(self):
        v1 = registry.get_prompt("baseline_v1").system_prompt
        for version in ["baseline_v2", "baseline_v3"]:
            self.assertTrue(registry.get_prompt(version).system_prompt.startswith(v1), version)

    def test_v3_is_v2_plus_guidance_with_the_same_output_contract(self):
        v2 = registry.get_prompt("baseline_v2")
        v3 = registry.get_prompt("baseline_v3")
        self.assertEqual(v2.user_template, v3.user_template)
        self.assertTrue(v2.system_prompt.endswith(contract_block()))
        self.assertTrue(v3.system_prompt.endswith(contract_block()))
        self.assertIn(guidance_block(), v3.system_prompt)
        self.assertNotIn(guidance_block(), v2.system_prompt)

    def test_the_classification_vocabulary_is_the_schema_vocabulary_in_every_version(self):
        for version in registry.list_versions():
            text = registry.get_prompt(version).system_prompt
            for name in verdict_schema.ATTACK_TYPES:
                self.assertIn(name, text, version)
            for severity in verdict_schema.SEVERITIES:
                self.assertIn(severity, text, version)
            for dropped in ["Infiltration", "Heartbleed", "SQL Injection", "Web Attack - Brute"[:0] + "Port Scan"]:
                self.assertNotIn(dropped, text, version)

    def test_prompts_carry_no_label_or_answer_key_wording(self):
        for version in registry.list_versions():
            lowered = registry.get_prompt(version).system_prompt.lower()
            for word in ["ground truth", "answer key", "frozen", "label", "accepted id", "accepted_id"]:
                self.assertNotIn(word, lowered, version + ": " + word)
            self.assertIn("no tools", lowered)


class V2ContractTests(unittest.TestCase):
    def test_v2_states_the_five_field_contract_and_nothing_else(self):
        text = contract_block()
        self.assertIn("exactly ONE JSON object", text)
        self.assertIn("exactly these five keys and no others: " + ", ".join(FIVE), text)
        self.assertIn("Any other key makes the whole reply invalid", text)
        for field in FIVE:
            self.assertIn(field, text)

    def test_v2_forbids_the_observed_extra_field_patterns(self):
        text = contract_block()
        self.assertIn("Do not add MITRE tactic, name, url, version or any other MITRE metadata as keys", text)
        self.assertIn("Do not copy alert or context fields", text)
        self.assertIn("goes only in mitre_technique", text)
        self.assertIn("goes only inside evidence", text)
        self.assertIn("no markdown fences", text)
        self.assertIn("no text before or after it", text)
        self.assertIn("no second object", text)

    def test_v2_evidence_limit_is_inside_the_schema_limit(self):
        match = re.search(r"under (\d+) characters", contract_block())
        self.assertIsNotNone(match)
        self.assertLessEqual(int(match.group(1)), verdict_schema.EVIDENCE_MAX_CHARS)

    def test_v2_has_one_structural_example(self):
        text = contract_block()
        self.assertEqual(text.count("Shape of a valid reply"), 1)
        example = text.split("Shape of a valid reply (placeholders only, not a real answer):\n", 1)[1]
        self.assertEqual(example.count("{"), 1)
        self.assertEqual(example.count("}"), 1)
        keys = re.findall(r'"([a-z_]+)":', example)
        self.assertEqual(keys, FIVE)

    def test_v2_example_holds_only_placeholders(self):
        example = contract_block().split("placeholders only, not a real answer):\n", 1)[1]
        values = re.findall(r'"[a-z_]+": ("<[^<>"]+>"|<[^<>"]+>)', example)
        self.assertEqual(len(values), 5)
        stripped = re.sub(r'"[a-z_]+": ("<[^<>"]+>"|<[^<>"]+>)', "", example)
        self.assertEqual(re.sub(r"[\s{},]", "", stripped), "")
        for name in CLASS_NAMES + ["none", "low", "medium", "high", "critical"]:
            self.assertNotIn('"' + name + '"', example)
            self.assertNotIn(name, re.sub(r"<[^<>]*>", "", example))
        self.assertIsNone(TECHNIQUE_ID.search(example))
        self.assertEqual(re.findall(r"\d", example), [])

    def test_v2_changes_no_classification_wording(self):
        v1 = registry.get_prompt("baseline_v1").system_prompt
        v2 = registry.get_prompt("baseline_v2").system_prompt
        self.assertEqual(v2[:len(v1)], v1)
        self.assertEqual(v2[len(v1):], contract_block())
        self.assertEqual(sorted(set(TECHNIQUE_ID.findall(v2))), ["T1059", "T1059.001"])


class V3GuidanceTests(unittest.TestCase):
    def test_v3_describes_every_class_including_benign(self):
        block = guidance_block()
        for name in CLASS_NAMES:
            self.assertRegex(block, r"(?m)^- " + re.escape(name) + r": ", name)

    def test_v3_targets_the_three_observed_confusions_in_general_terms(self):
        block = guidance_block()
        self.assertIn("not by itself a denial-of-service attack", block)
        self.assertIn("Separate floods", block)
        self.assertIn("It looks much like slowloris", block)
        self.assertIn("does not sweep many ports", block)

    def test_v3_explains_network_versus_endpoint_dos_without_a_mapping(self):
        block = guidance_block()
        self.assertIn("Network denial of service (T1498)", block)
        self.assertIn("Endpoint denial of service (T1499)", block)
        self.assertIn("matches the behavior you observe in the flow, not the name of the class", block)

    def test_v3_has_no_class_to_technique_table(self):
        text = registry.get_prompt("baseline_v3").system_prompt
        self.assertEqual(sorted(set(TECHNIQUE_ID.findall(guidance_block()))), ["T1498", "T1499"])
        for line in text.split("\n"):
            if TECHNIQUE_ID.search(line):
                for name in CLASS_NAMES:
                    if name != "BENIGN":
                        self.assertNotIn(name, line, "a technique id shares a line with the class " + name)
        self.assertNotIn("->", text)
        self.assertNotIn("=>", text)

    def test_v3_does_not_force_a_technique_and_keeps_none_for_benign_only(self):
        block = guidance_block()
        self.assertIn("Use NONE only together with BENIGN", block)
        self.assertIn("do not invent a technique", block)
        self.assertNotIn("always use", block.lower())

    def test_v3_holds_no_dev_alert_values(self):
        text = registry.get_prompt("baseline_v3").system_prompt
        self.assertNotIn("DEV-", text)
        self.assertIsNone(re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text))
        alerts = d3.make_alerts(5)
        for column in ["flow_id", "src_ip", "dst_ip"]:
            for value in alerts[column]:
                self.assertNotIn(str(value), text)
        for pattern in [r"detector_score\s*[:=]\s*\d", r"Flow Duration\s*[:=]\s*\d", r"\b\d{5,}\b"]:
            self.assertIsNone(re.search(pattern, text), pattern)


class UserPromptTests(unittest.TestCase):
    def model_input(self):
        alerts = d3.make_alerts(2)
        flows = d3.make_flows(2)
        flows["timestamp"] = flows["timestamp"]
        import triage_inputs
        return triage_inputs.build_model_input(alerts.iloc[0], flows)

    def test_v1_user_prompt_is_identical_to_the_day_3_builder(self):
        mi = self.model_input()
        self.assertEqual(registry.build_user_prompt(registry.get_prompt("baseline_v1"), mi), baseline_prompt.build_user_prompt(mi))

    def test_every_version_sends_only_the_alert_and_the_instruction(self):
        mi = self.model_input()
        for version in registry.list_versions():
            prompt = registry.build_user_prompt(registry.get_prompt(version), mi)
            self.assertTrue(prompt.startswith("Alert:\n"), version)
            self.assertIn("\n\nReply with the JSON object only", prompt)
            body = prompt.split("Alert:\n", 1)[1].rsplit("\n\nReply with", 1)[0]
            self.assertEqual(json.loads(body)["alert"]["alert_id"], "DEV-0001")
            for word in ["label", "is_attack", "source_file", "original_row", "mitre", "frozen"]:
                self.assertNotIn(word, prompt.lower(), version + ": " + word)
            for name in CLASS_NAMES:
                self.assertNotIn(name, prompt)

    def test_the_alert_checks_still_apply(self):
        mi = self.model_input()
        mi["alert"]["label"] = "BENIGN"
        with self.assertRaises(ValueError):
            registry.build_user_prompt(registry.get_prompt("baseline_v2"), mi)

    def test_v1_snapshot_keeps_the_day_3_format(self):
        spec = registry.get_prompt("baseline_v1")
        text = registry.snapshot_text(spec, "DEV-0001", "USERPROMPT")
        expected = ("PROMPT baseline_v1 sha256 " + PINNED_V1_SHA256 + "\n\n=== system prompt ===\n" + baseline_prompt.SYSTEM_PROMPT
                    + "\n\n=== user prompt for DEV-0001 ===\nUSERPROMPT\n")
        self.assertEqual(text, expected)

    def test_v2_snapshot_names_version_hash_and_template(self):
        spec = registry.get_prompt("baseline_v2")
        text = registry.snapshot_text(spec, "DEV-0001", "USERPROMPT")
        self.assertTrue(text.startswith("PROMPT baseline_v2 sha256 " + spec.sha256))
        self.assertIn(contract_block(), text)
        self.assertIn("=== user template ===", text)


# ------------------------------------------------------------------------------------------------ cost
class CostTests(unittest.TestCase):
    def tokens(self, **kw):
        base = {"prompt_tokens": 1000000, "output_tokens": 500000, "thinking_tokens": None, "total_tokens": 1500000,
                "alerts_with_token_counts": 10, "alerts_without_token_counts": 0}
        base.update(kw)
        return base

    def test_without_pricing_cost_is_unavailable_and_nothing_is_assumed(self):
        result = cost_tracking.cost(self.tokens(), None)
        self.assertEqual(result["available"], False)
        self.assertIn("No price is assumed", result["reason"])
        self.assertNotIn("total", result)
        self.assertIsNone(cost_tracking.load_pricing(None))

    def test_pricing_file_calculation(self):
        result = cost_tracking.cost(self.tokens(), FIXTURE_PRICING)
        self.assertTrue(result["available"])
        self.assertAlmostEqual(result["input_cost"], 2.0)
        self.assertAlmostEqual(result["output_cost"], 2.0)
        self.assertAlmostEqual(result["total"], 4.0)
        self.assertAlmostEqual(result["per_alert_mean"], 0.4)
        self.assertEqual(result["currency"], "TEST")

    def test_thinking_tokens_follow_the_stated_billing_policy(self):
        t = self.tokens(thinking_tokens=1000000)
        self.assertAlmostEqual(cost_tracking.cost(t, dict(FIXTURE_PRICING, thinking_tokens_billed_as="output"))["total"], 8.0)
        self.assertAlmostEqual(cost_tracking.cost(t, dict(FIXTURE_PRICING, thinking_tokens_billed_as="input"))["total"], 6.0)
        self.assertAlmostEqual(cost_tracking.cost(t, dict(FIXTURE_PRICING, thinking_tokens_billed_as="not_billed"))["total"], 4.0)

    def test_the_result_matches_the_day_4_evaluator(self):
        import eval_metrics
        t = self.tokens(thinking_tokens=250000)
        mine = cost_tracking.cost(t, FIXTURE_PRICING)
        theirs = eval_metrics.cost(t, FIXTURE_PRICING)
        self.assertAlmostEqual(mine["total"], theirs["total"])
        self.assertAlmostEqual(mine["per_alert_mean"], theirs["per_alert_mean"])
        self.assertEqual(mine["input_tokens_billed"], theirs["input_tokens_billed"])
        self.assertEqual(mine["output_tokens_billed"], theirs["output_tokens_billed"])
        self.assertEqual(cost_tracking.PRICING_REQUIRED, eval_metrics.PRICING_REQUIRED)
        self.assertEqual(cost_tracking.cost(t, None)["available"], eval_metrics.cost(t, None)["available"])

    def test_bad_pricing_is_refused(self):
        bad = [
            {},
            dict(FIXTURE_PRICING, per_million_input_tokens=None),
            dict(FIXTURE_PRICING, source=""),
            dict(FIXTURE_PRICING, as_of=None),
            dict(FIXTURE_PRICING, per_million_output_tokens=-1),
            dict(FIXTURE_PRICING, per_million_input_tokens=True),
            dict(FIXTURE_PRICING, per_million_input_tokens="2.0"),
            dict(FIXTURE_PRICING, thinking_tokens_billed_as="sometimes"),
        ]
        for pricing in bad:
            with self.assertRaises(cost_tracking.PricingError, msg=str(pricing)):
                cost_tracking.cost(self.tokens(), pricing)
        with self.assertRaises(cost_tracking.PricingError):
            cost_tracking.validate_pricing([1, 2])

    def test_the_shipped_template_is_refused_until_it_is_filled_in(self):
        path = os.path.join(ROOT, "pricing.template.json")
        with open(path, encoding="utf-8") as f:
            template = json.load(f)
        self.assertIsNone(template["per_million_input_tokens"])
        self.assertIsNone(template["per_million_output_tokens"])
        with self.assertRaises(cost_tracking.PricingError):
            cost_tracking.load_pricing(path)

    def test_load_pricing_reads_a_valid_file_and_refuses_bad_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = os.path.join(tmp, "p.json")
            with open(good, "w") as f:
                json.dump(FIXTURE_PRICING, f)
            self.assertEqual(cost_tracking.load_pricing(good)["currency"], "TEST")
            broken = os.path.join(tmp, "b.json")
            with open(broken, "w") as f:
                f.write("{not json")
            with self.assertRaises(cost_tracking.PricingError):
                cost_tracking.load_pricing(broken)

    def test_source_holds_no_provider_price(self):
        tree = ast.parse(read_source("cost_tracking.py"))
        numbers = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
                numbers.add(node.value)
        self.assertTrue(numbers <= {0, 1, 1e6}, "unexpected numeric constants in cost_tracking.py: " + str(sorted(numbers)))

    def test_token_totals_use_the_latest_record_per_alert_and_keep_alerts_without_counts_apart(self):
        records = [
            {"alert_id": "A", "prompt_tokens": 10, "output_tokens": 5, "thinking_tokens": None, "total_tokens": 15},
            {"alert_id": "A", "prompt_tokens": 20, "output_tokens": 6, "thinking_tokens": None, "total_tokens": 26},
            {"alert_id": "B", "prompt_tokens": None, "output_tokens": None, "thinking_tokens": None, "total_tokens": None},
            {"alert_id": "C", "prompt_tokens": 1, "output_tokens": 1, "thinking_tokens": 3, "total_tokens": 5},
        ]
        out = cost_tracking.cost_for_run(records, None)
        t = out["tokens"]
        self.assertEqual((t["prompt_tokens"], t["output_tokens"], t["thinking_tokens"], t["total_tokens"]), (21, 7, 3, 31))
        self.assertEqual((t["alerts_with_token_counts"], t["alerts_without_token_counts"]), (2, 1))
        self.assertFalse(out["cost"]["available"])

    def test_token_accounting_matches_what_the_day_3_runner_stores(self):
        tmp = tempfile.mkdtemp()
        try:
            time = d3.FakeTime()
            with mock.patch.object(runner, "SLEEP", time.sleep), mock.patch.object(runner, "CLOCK", time.clock):
                run_dir = store.RunDir(os.path.join(tmp, "run"))
                os.makedirs(run_dir.path)
                client = d3.FakeClient(["not json", d3.GOOD])
                caller = runner.RecordingCaller(client, runner.Throttle(600), run_dir, 1, "gemini-test")
                record = runner.process_alert("DEV-0001", "PROMPT", caller, 1, 2)
            self.assertEqual(record["model_calls"], 2)
            out = cost_tracking.cost_for_run([record], FIXTURE_PRICING)
            self.assertEqual(out["tokens"]["prompt_tokens"], 200)
            self.assertEqual(out["tokens"]["output_tokens"], 100)
            self.assertAlmostEqual(out["cost"]["total"], 200 / 1e6 * 2.0 + 100 / 1e6 * 4.0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_cli_is_read_only_and_reports_unavailable_without_pricing(self):
        tmp = tempfile.mkdtemp()
        try:
            run = os.path.join(tmp, "runs", "r")
            os.makedirs(run)
            with open(os.path.join(run, "results.jsonl"), "w") as f:
                f.write(json.dumps({"alert_id": "A", "prompt_tokens": 1000, "output_tokens": 500, "thinking_tokens": None, "total_tokens": 1500}) + "\n")
            with open(os.path.join(run, "results.jsonl"), "rb") as f:
                before = hashlib.sha256(f.read()).hexdigest()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = cost_tracking.main(["--run-name", "r", "--runs-dir", os.path.join(tmp, "runs")])
            self.assertEqual(code, 0)
            self.assertIn("Cost: unavailable", buf.getvalue())
            self.assertIn("total tokens: 1500", buf.getvalue())
            pricing = os.path.join(tmp, "p.json")
            with open(pricing, "w") as f:
                json.dump(FIXTURE_PRICING, f)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = cost_tracking.main(["--run-name", "r", "--runs-dir", os.path.join(tmp, "runs"), "--pricing-file", pricing])
            self.assertEqual(code, 0)
            self.assertIn("Cost: 0.004000 TEST", buf.getvalue())
            self.assertEqual(os.listdir(run), ["results.jsonl"])
            with open(os.path.join(run, "results.jsonl"), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), before)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = cost_tracking.main(["--run-name", "r", "--runs-dir", os.path.join(tmp, "runs"), "--pricing-file", os.path.join(ROOT, "pricing.template.json")])
            self.assertEqual(code, 1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------------------------------------ tracing
class FakeLangSmith:
    def __init__(self, fail=False):
        self.calls = []
        self.flushed = 0
        self.fail = fail

    def create_run(self, **kwargs):
        if self.fail:
            raise RuntimeError("network down")
        self.calls.append(kwargs)

    def flush(self):
        self.flushed += 1


class SanitizeTests(unittest.TestCase):
    def test_metadata_passes(self):
        payload = {"run_name": "r", "alert_id": "DEV-0001", "prompt_version": "baseline_v2", "prompt_sha256": "a" * 64, "model": "m",
                   "attempt": 1, "latency_seconds": 1.5, "total_tokens": 150, "parse_status": "valid", "error_code": None,
                   "malformed_first_try": False}
        self.assertEqual(tracing.sanitize(payload), payload)

    def test_content_keys_are_refused(self):
        for key in ["prompt", "reply", "alert", "alert_json", "features", "label", "labels", "mitre_answer_key", "verdict", "evidence",
                    "error_detail", "attempt_log", "raw", "frozen", "src_ip", "text"]:
            with self.assertRaises(tracing.TracingPayloadError, msg=key):
                tracing.sanitize({"alert_id": "DEV-0001", key: "x"})

    def test_content_shaped_values_are_refused(self):
        for value in [{"a": 1}, ["x"], "x" * 500, '{"is_malicious": true}', "line one\nline two"]:
            with self.assertRaises(tracing.TracingPayloadError):
                tracing.sanitize({"error_code": value})
        with self.assertRaises(tracing.TracingPayloadError):
            tracing.sanitize(["not", "a", "dict"])

    def test_alert_and_attempt_payloads_leave_out_replies_prompts_verdicts_and_error_details(self):
        record = {"alert_id": "DEV-0001", "session": 1, "status": "ok", "error_code": None, "attempts": 2, "model_calls": 2,
                  "malformed_first_try": True, "latency_seconds": 3.0, "prompt_tokens": 200, "output_tokens": 100, "thinking_tokens": None,
                  "total_tokens": 300, "verdict": d3.GOOD_MALICIOUS, "error_detail": "extra keys: secret_field", "repairs": ["x"],
                  "attempt_log": [{"error_code": "extra_fields", "error_detail": "d"}, {"error_code": None, "error_detail": None}]}
        calls = [{"latency_seconds": 1.0, "finish_reason": "STOP", "prompt_tokens": 100, "output_tokens": 50, "thinking_tokens": None,
                  "total_tokens": 150, "prompt": "PROMPT TEXT 10.0.0.1", "reply": d3.GOOD},
                 {"latency_seconds": 2.0, "finish_reason": "STOP", "prompt_tokens": 100, "output_tokens": 50, "thinking_tokens": None,
                  "total_tokens": 150, "prompt": "PROMPT TEXT 10.0.0.1", "reply": d3.GOOD}]
        base = {"run_name": "r", "prompt_version": "baseline_v2", "prompt_sha256": "b" * 64, "model": "m", "set": "dev"}
        parent = tracing.alert_payload(base, record)
        children = tracing.attempt_payloads(base, record, calls)
        self.assertEqual([c["attempt"] for c in children], [1, 2])
        self.assertEqual([c["parse_status"] for c in children], ["extra_fields", "valid"])
        blob = json.dumps([parent, children])
        for secret in ["PROMPT TEXT", "10.0.0.1", "PortScan", "T1046", "tiny flows", "secret_field", "evidence", "verdict", "reply"]:
            self.assertNotIn(secret, blob)
        self.assertTrue(set(parent) <= tracing.ALLOWED_KEYS)
        for c in children:
            self.assertTrue(set(c) <= tracing.ALLOWED_KEYS)


class TracerTests(unittest.TestCase):
    def test_disabled_tracing_is_a_no_op_and_never_creates_a_client(self):
        with mock.patch.object(tracing, "make_client", side_effect=AssertionError("must not build a client")):
            tracer = tracing.create_tracer(False, "r", "baseline_v1", PINNED_V1_SHA256, "m")
        self.assertIsInstance(tracer, tracing.NullTracer)
        self.assertIsNone(tracer.record_alert({"alert_id": "A"}, []))
        self.assertIsNone(tracer.close())
        self.assertEqual(tracer.describe(), {"enabled": False})

    def test_enabled_tracer_sends_one_parent_and_one_child_per_call(self):
        fake = FakeLangSmith()
        tracer = tracing.create_tracer(True, "r1", "baseline_v2", "c" * 64, "gemini-x", client=fake, environ={"LANGSMITH_PROJECT": "my-proj"})
        record = {"alert_id": "DEV-0001", "session": 1, "status": "ok", "error_code": None, "attempts": 2, "model_calls": 2,
                  "latency_seconds": 3.0, "attempt_log": [{"error_code": "invalid_json"}, {"error_code": None}]}
        calls = [{"latency_seconds": 1.0, "finish_reason": "STOP"}, {"latency_seconds": 2.0, "finish_reason": "STOP"}]
        tracer.record_alert(record, calls)
        tracer.close()
        self.assertEqual(len(fake.calls), 3)
        parent, c1, c2 = fake.calls
        self.assertEqual(parent["project_name"], "my-proj")
        self.assertNotIn("parent_run_id", parent)
        self.assertEqual(c1["parent_run_id"], parent["id"])
        self.assertEqual(c2["parent_run_id"], parent["id"])
        self.assertEqual(c1["extra"]["metadata"]["parse_status"], "invalid_json")
        self.assertEqual(c2["extra"]["metadata"]["parse_status"], "valid")
        self.assertEqual(parent["extra"]["metadata"]["prompt_version"], "baseline_v2")
        self.assertEqual(parent["extra"]["metadata"]["prompt_sha256"], "c" * 64)
        self.assertEqual(fake.flushed, 1)
        self.assertEqual(tracer.describe()["payload_policy"], "metadata_only")

    def test_missing_key_or_package_stops_before_any_client_is_made(self):
        with self.assertRaises(tracing.TracingConfigError):
            tracing.make_client({})
        with mock.patch.dict(sys.modules, {"langsmith": None}):
            with self.assertRaises(tracing.TracingConfigError):
                tracing.make_client({"LANGSMITH_API_KEY": "k"})

    def test_client_is_built_from_the_environment_only(self):
        seen = {}

        class Client:
            def __init__(self, **kwargs):
                seen.update(kwargs)

        module = mock.Mock()
        module.Client = Client
        with mock.patch.dict(sys.modules, {"langsmith": module}):
            tracing.make_client({"LANGSMITH_API_KEY": "env-key", "LANGSMITH_ENDPOINT": "https://example.invalid"})
        self.assertEqual(seen, {"api_key": "env-key", "api_url": "https://example.invalid"})
        self.assertEqual(tracing.project_name({}), "soc-triage-week2")

    def test_the_langsmith_package_is_imported_only_inside_a_function(self):
        tree = ast.parse(read_source("langsmith_tracing.py"))
        for node in tree.body:
            if isinstance(node, ast.Import):
                self.assertNotIn("langsmith", [a.name.split(".")[0] for a in node.names])
            if isinstance(node, ast.ImportFrom):
                self.assertNotEqual((node.module or "").split(".")[0], "langsmith")
        self.assertIn("from langsmith import Client", read_source("langsmith_tracing.py"))

    def test_no_key_like_string_in_the_tracing_source(self):
        text = read_source("langsmith_tracing.py")
        self.assertNotIn("lsv2_", text)
        self.assertNotIn("ls__", text)


# ------------------------------------------------------------------------------------------------ runner
class RunnerDay5Case(d3.RunnerCase):
    def setUp(self):
        d3.RunnerCase.setUp(self)
        self.alerts = d3.make_alerts(5)
        self.flows = d3.make_flows(5)
        self.log_path = os.path.join(self.tmp, "frozen_access.log")
        with open(self.log_path, "w") as f:
            f.write("2026-10-03T18:40:50Z\talerts\t-c\tQA read\n")
        self.runs_dir = os.path.join(self.tmp, "runs")
        self.client = d3.FakeClient()
        self.specs = []
        self.fake_ls = FakeLangSmith()

        def fake_client_for(model, key, timeout, spec):
            self.specs.append(spec)
            return self.client

        self.patches2 = [
            mock.patch.object(runner, "load_inputs", lambda: (self.alerts, self.flows, {"dev_alerts_sha256": "a", "flow_store_dev_sha256": "b"})),
            mock.patch.object(runner, "check_llm_config", lambda: {"small": "gemini-2.5-flash-lite", "strong": "gemini-2.5-pro"}),
            mock.patch.object(runner, "make_client_for", fake_client_for),
            mock.patch.object(runner, "week1_snapshot", lambda: {"x": "1"}),
            mock.patch.object(runner, "git_info", lambda: {"commit": "abc1234", "dirty": False}),
            mock.patch.object(runner, "package_versions", lambda: {}),
            mock.patch.object(config, "FROZEN_ACCESS_LOG", self.log_path),
            mock.patch.object(llm_config, "get_api_key", lambda: d3.FAKE_KEY),
            mock.patch.dict(os.environ, {}, clear=False),
        ]
        os.environ.pop(config.FROZEN_UNLOCK_ENV, None)
        os.environ.pop("LANGSMITH_API_KEY", None)
        for p in self.patches2:
            p.start()

    def tearDown(self):
        for p in self.patches2:
            p.stop()
        d3.RunnerCase.tearDown(self)

    def go(self, *extra):
        with contextlib.redirect_stdout(io.StringIO()):
            return runner.main(["--runs-dir", self.runs_dir, "--rpm", "600"] + list(extra))

    def dir_of(self, name):
        return store.RunDir(os.path.join(self.runs_dir, name))


class PromptSelectionTests(RunnerDay5Case):
    def test_default_is_baseline_v1_exactly_as_in_day_3(self):
        self.assertEqual(self.go("--run-name", "r1"), 0)
        meta = store.read_json(self.dir_of("r1").meta)
        self.assertEqual(meta["prompt_version"], "baseline_v1")
        self.assertEqual(meta["prompt_sha256"], PINNED_V1_SHA256)
        self.assertEqual(self.specs[0].version, "baseline_v1")
        with open(self.dir_of("r1").prompt_snapshot, encoding="utf-8") as f:
            self.assertTrue(f.read().startswith("PROMPT baseline_v1 sha256 " + PINNED_V1_SHA256))
        for prompt in self.client.prompts:
            self.assertTrue(prompt.endswith("\n\nReply with the JSON object only."))

    def test_v1_prompts_are_byte_identical_to_the_day_3_prompts(self):
        flows = self.flows.copy()
        old = {}
        import triage_inputs
        flows["timestamp"] = flows["timestamp"]
        for i in range(len(self.alerts)):
            row = self.alerts.iloc[i]
            mi = triage_inputs.build_model_input(row, flows)
            old[row["alert_id"]] = baseline_prompt.build_user_prompt(mi)
        self.assertEqual(runner.build_all_prompts(self.alerts, self.flows), old)
        self.assertEqual(runner.build_all_prompts(self.alerts, self.flows, registry.get_prompt("baseline_v1")), old)

    def test_runner_can_select_v2(self):
        self.assertEqual(self.go("--run-name", "r2", "--prompt-version", "baseline_v2"), 0)
        spec = registry.get_prompt("baseline_v2")
        meta = store.read_json(self.dir_of("r2").meta)
        self.assertEqual((meta["prompt_version"], meta["prompt_sha256"]), ("baseline_v2", spec.sha256))
        self.assertEqual(self.specs[0].version, "baseline_v2")
        with open(self.dir_of("r2").prompt_snapshot, encoding="utf-8") as f:
            snap = f.read()
        self.assertTrue(snap.startswith("PROMPT baseline_v2 sha256 " + spec.sha256))
        self.assertIn(contract_block(), snap)
        for prompt in self.client.prompts:
            self.assertTrue(prompt.endswith("Reply with the JSON object only: exactly the five keys, nothing else."))

    def test_runner_can_select_v3(self):
        self.assertEqual(self.go("--run-name", "r3", "--prompt-version", "baseline_v3"), 0)
        spec = registry.get_prompt("baseline_v3")
        meta = store.read_json(self.dir_of("r3").meta)
        self.assertEqual((meta["prompt_version"], meta["prompt_sha256"]), ("baseline_v3", spec.sha256))
        with open(self.dir_of("r3").prompt_snapshot, encoding="utf-8") as f:
            self.assertIn(guidance_block(), f.read())

    def test_every_result_carries_the_hash_of_the_prompt_it_was_sent(self):
        self.go("--run-name", "r2", "--prompt-version", "baseline_v2")
        for record in store.read_jsonl(self.dir_of("r2").results):
            self.assertRegex(record["prompt_sha256"], r"^[0-9a-f]{64}$")

    def test_what_the_model_received_holds_no_label_or_answer_key_in_any_version(self):
        for version in registry.list_versions():
            self.client.prompts.clear()
            self.go("--run-name", "run_" + version, "--prompt-version", version)
            self.assertEqual(len(self.client.prompts), 5)
            for prompt in self.client.prompts:
                self.assertTrue(prompt.startswith("Alert:\n"))
                for word in ["label", "is_attack", "source_file", "original_row", "mitre", "frozen"]:
                    self.assertNotIn(word, prompt.lower())

    def test_dry_run_prints_the_selected_prompt_and_writes_nothing(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = runner.main(["--runs-dir", self.runs_dir, "--dry-run", "--run-name", "d", "--prompt-version", "baseline_v3"])
        self.assertEqual(code, 0)
        self.assertIn("baseline_v3", buf.getvalue())
        self.assertIn("GUIDANCE ON THE ATTACK CLASSES", buf.getvalue())
        self.assertFalse(os.path.exists(self.runs_dir))
        self.assertEqual(self.specs, [])

    def test_unknown_version_is_refused_by_the_parser(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                runner.parse_args(["--prompt-version", "baseline_v9"])

    def test_resume_without_a_flag_keeps_the_runs_own_version(self):
        self.client = d3.FakeClient([d3.GOOD, d3.GOOD, gemini_client.PermanentModelError("quota", 403)])
        self.assertEqual(self.go("--run-name", "r2", "--prompt-version", "baseline_v2"), 2)
        self.assertEqual(len(store.read_jsonl(self.dir_of("r2").results)), 2)
        self.specs.clear()
        self.client = d3.FakeClient()
        self.assertEqual(self.go("--resume", "--run-name", "r2"), 0)
        self.assertEqual([s.version for s in self.specs], ["baseline_v2"])
        self.assertEqual(len(store.read_jsonl(self.dir_of("r2").results)), 5)
        self.assertEqual(len(self.client.prompts), 3)
        for prompt in self.client.prompts:
            self.assertTrue(prompt.endswith("exactly the five keys, nothing else."))
        meta = store.read_json(self.dir_of("r2").meta)
        self.assertEqual((meta["prompt_version"], meta["prompt_sha256"]), ("baseline_v2", registry.get_prompt("baseline_v2").sha256))

    def test_resume_with_a_different_version_is_refused(self):
        self.go("--run-name", "r2", "--prompt-version", "baseline_v2", "--limit", "1")
        with self.assertRaises(SystemExit):
            self.go("--resume", "--run-name", "r2", "--prompt-version", "baseline_v3")

    def test_resume_of_a_v1_run_still_refuses_a_changed_v1_prompt(self):
        self.go("--run-name", "r1", "--limit", "1")
        with mock.patch.object(baseline_prompt, "prompt_sha256", lambda: "different"):
            with self.assertRaises(SystemExit):
                self.go("--resume", "--run-name", "r1")

    def test_a_new_run_never_touches_an_existing_run_folder(self):
        old = os.path.join(self.runs_dir, "dev_flash_lite_v1")
        os.makedirs(old)
        for name, text in [("results.jsonl", "a\n"), ("raw_responses.jsonl", "b\n"), ("run_meta.json", "{}"), ("prompt_snapshot.txt", "c")]:
            with open(os.path.join(old, name), "w") as f:
                f.write(text)

        def digest():
            out = {}
            for n in sorted(os.listdir(old)):
                with open(os.path.join(old, n), "rb") as f:
                    out[n] = hashlib.sha256(f.read()).hexdigest()
            return out

        before = digest()
        self.go("--run-name", "dev_flash_lite_v2", "--prompt-version", "baseline_v2")
        self.assertEqual(digest(), before)
        with self.assertRaises(SystemExit):
            self.go("--run-name", "dev_flash_lite_v1", "--prompt-version", "baseline_v2")
        self.assertEqual(digest(), before)

    def test_the_guard_flags_stay_true_for_v2_and_v3_runs(self):
        for version in ["baseline_v2", "baseline_v3"]:
            self.go("--run-name", "g_" + version, "--prompt-version", version)
            meta = store.read_json(self.dir_of("g_" + version).meta)
            self.assertEqual(meta["set"], "dev")
            self.assertTrue(meta["frozen_access_log_unchanged"])
            self.assertTrue(meta["week1_files_unchanged"])
            self.assertEqual(meta["counts"], {"ok": 5, "parse_failed": 0, "model_error": 0})

    def test_make_client_for_uses_the_selected_system_prompt(self):
        seen = {}

        class FakeGemini:
            def __init__(self, model, system_prompt, temperature, max_output_tokens, seed, api_key=None, timeout_seconds=60, sdk_client=None):
                seen["system_prompt"] = system_prompt
                seen["model"] = model

        self.patches2[2].stop()
        try:
            with mock.patch.object(gemini_client, "GeminiClient", FakeGemini):
                runner.make_client_for("m", "k", 60, registry.get_prompt("baseline_v3"))
                self.assertEqual(seen["system_prompt"], registry.get_prompt("baseline_v3").system_prompt)
                with mock.patch.object(runner, "make_client", lambda model, key, timeout: "V1PATH"):
                    self.assertEqual(runner.make_client_for("m", "k", 60, registry.get_prompt("baseline_v1")), "V1PATH")
        finally:
            self.patches2[2].start()


class RunnerTracingTests(RunnerDay5Case):
    def test_tracing_is_off_by_default_and_touches_nothing(self):
        with mock.patch.object(tracing, "make_client", side_effect=AssertionError("must not build a client")):
            self.assertEqual(self.go("--run-name", "r1"), 0)
        meta = store.read_json(self.dir_of("r1").meta)
        self.assertEqual(meta["langsmith"], {"enabled": False})
        self.assertEqual(meta["counts"], {"ok": 5, "parse_failed": 0, "model_error": 0})

    def test_a_run_with_tracing_gives_the_same_results_as_a_run_without(self):
        self.go("--run-name", "plain", "--prompt-version", "baseline_v2")
        with mock.patch.object(tracing, "make_client", lambda environ=None: self.fake_ls):
            os.environ["LANGSMITH_API_KEY"] = "k"
            self.go("--run-name", "traced", "--prompt-version", "baseline_v2", "--langsmith")

        def core(name):
            rows = store.read_jsonl(self.dir_of(name).results)
            return [{k: r[k] for k in ["alert_id", "status", "verdict", "error_code", "attempts", "model_calls", "total_tokens"]} for r in rows]

        self.assertEqual(core("plain"), core("traced"))

    def test_enabled_tracing_sends_metadata_only(self):
        os.environ["LANGSMITH_API_KEY"] = "k"
        with mock.patch.object(tracing, "make_client", lambda environ=None: self.fake_ls):
            self.go("--run-name", "traced", "--prompt-version", "baseline_v3", "--langsmith")
        self.assertEqual(len(self.fake_ls.calls), 10)
        self.assertEqual(self.fake_ls.flushed, 1)
        blob = json.dumps(self.fake_ls.calls, default=str)
        spec = registry.get_prompt("baseline_v3")
        for secret in ["10.0.0.1", "Alert:", "PortScan", "T1046", "tiny flows", d3.FAKE_KEY, "GUIDANCE ON THE ATTACK CLASSES",
                       "OUTPUT CONTRACT", spec.system_prompt[:60], "flow_id", "Flow Duration", "detector_score"]:
            self.assertNotIn(secret, blob, secret)
        for call in self.fake_ls.calls:
            self.assertTrue(set(call["extra"]["metadata"]) <= tracing.ALLOWED_KEYS)
            self.assertEqual(call["extra"]["metadata"]["prompt_version"], "baseline_v3")
            self.assertEqual(call["extra"]["metadata"]["prompt_sha256"], spec.sha256)
            self.assertEqual(call["extra"]["metadata"]["set"], "dev")
        parents = [c for c in self.fake_ls.calls if "parent_run_id" not in c]
        self.assertEqual(len(parents), 5)
        meta = store.read_json(self.dir_of("traced").meta)
        self.assertEqual(meta["langsmith"]["payload_policy"], "metadata_only")
        self.assertTrue(meta["langsmith"]["enabled"])
        with open(self.dir_of("traced").meta, encoding="utf-8") as f:
            self.assertNotIn("\"k\"", f.read())

    def test_retries_show_up_as_attempts(self):
        os.environ["LANGSMITH_API_KEY"] = "k"
        self.client.script = ["not json", d3.GOOD]
        with mock.patch.object(tracing, "make_client", lambda environ=None: self.fake_ls):
            self.go("--run-name", "traced", "--limit", "1", "--langsmith")
        kids = [c for c in self.fake_ls.calls if "parent_run_id" in c]
        self.assertEqual([k["extra"]["metadata"]["attempt"] for k in kids], [1, 2])
        stored = store.read_jsonl(self.dir_of("traced").results)[0]["attempt_log"]
        self.assertIsNotNone(stored[0]["error_code"])
        self.assertEqual(kids[0]["extra"]["metadata"]["parse_status"], stored[0]["error_code"])
        self.assertEqual(kids[0]["extra"]["metadata"]["error_code"], stored[0]["error_code"])
        self.assertEqual(kids[1]["extra"]["metadata"]["parse_status"], "valid")

    def test_langsmith_without_a_key_stops_before_anything_is_written(self):
        with self.assertRaises(SystemExit):
            self.go("--run-name", "r1", "--langsmith")
        self.assertFalse(os.path.exists(os.path.join(self.runs_dir, "r1")))
        self.assertEqual(self.client.prompts, [])

    def test_a_failing_tracer_never_changes_the_run(self):
        os.environ["LANGSMITH_API_KEY"] = "k"
        broken = FakeLangSmith(fail=True)
        with mock.patch.object(tracing, "make_client", lambda environ=None: broken):
            code = self.go("--run-name", "traced", "--langsmith")
        self.assertEqual(code, 0)
        meta = store.read_json(self.dir_of("traced").meta)
        self.assertEqual(meta["counts"], {"ok": 5, "parse_failed": 0, "model_error": 0})
        self.assertEqual(meta["langsmith"]["errors"], 5)
        self.assertEqual(len(store.read_jsonl(self.dir_of("traced").results)), 5)

    def test_a_tracing_payload_error_is_contained_too(self):
        os.environ["LANGSMITH_API_KEY"] = "k"
        with mock.patch.object(tracing, "make_client", lambda environ=None: self.fake_ls):
            with mock.patch.object(tracing, "alert_payload", side_effect=tracing.TracingPayloadError("blocked")):
                code = self.go("--run-name", "traced", "--langsmith")
        self.assertEqual(code, 0)
        self.assertEqual(self.fake_ls.calls, [])
        self.assertEqual(store.read_json(self.dir_of("traced").meta)["counts"]["ok"], 5)


# ------------------------------------------------------------------------------------------------ separation
class Day5SeparationTests(unittest.TestCase):
    FORBIDDEN_IMPORTS = ["anthropic", "openai", "langchain", "langgraph", "chromadb", "requests", "urllib", "socket", "http", "eval_io", "eval_labels"]

    def used(self, name):
        names, modules = d3.SeparationTests.names_used(d3.SeparationTests(), name)
        return names, modules

    def test_day5_modules_never_touch_labels_answer_key_or_frozen_paths(self):
        for name in DAY5_MODULES:
            used, modules = self.used(name)
            self.assertEqual(sorted(used & d3.SeparationTests.FORBIDDEN_NAMES), [], name)
            self.assertEqual(sorted(modules & set(self.FORBIDDEN_IMPORTS)), [], name)

    def test_day5_modules_never_select_the_frozen_set_or_hold_a_key(self):
        for name in DAY5_MODULES + ["run_baseline_dev.py"]:
            text = read_source(name)
            self.assertNotIn('"frozen"', text, name)
            self.assertNotIn("'frozen'", text, name)
            self.assertNotIn(config.FROZEN_UNLOCK_VALUE, text, name)
            self.assertNotIn("AIza", text)
            self.assertNotIn("sk-ant-", text)
        self.assertEqual(read_source("run_baseline_dev.py").count("FROZEN_UNLOCK_ENV"), 2)

    def test_the_runner_still_reads_only_the_dev_loader(self):
        text = read_source("run_baseline_dev.py")
        self.assertIn("load_dev_alerts", text)
        self.assertIn("load_dev_flow_store", text)
        used, modules = self.used("run_baseline_dev.py")
        self.assertEqual(sorted(used & d3.SeparationTests.FORBIDDEN_NAMES), [], "runner")

    def test_the_runner_imports_langsmith_only_through_the_tracing_module(self):
        used, modules = self.used("run_baseline_dev.py")
        self.assertNotIn("langsmith", modules)
        self.assertIn("langsmith_tracing", modules)

    def test_the_registry_does_not_import_the_label_or_evaluation_modules(self):
        used, modules = self.used("prompt_registry.py")
        for name in ["eval_labels", "eval_io", "eval_metrics", "evaluate"]:
            self.assertNotIn(name, modules)
            self.assertNotIn(name, used)

    def test_baseline_prompt_module_is_unchanged_in_behavior(self):
        self.assertEqual(baseline_prompt.PROMPT_VERSION, "baseline_v1")
        self.assertEqual(baseline_prompt.prompt_sha256(), PINNED_V1_SHA256)


if __name__ == "__main__":
    unittest.main()
