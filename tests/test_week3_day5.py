"""Week 3 Day 5: the verdict prompt and node, the optional verdict route, the agent dev runner and the agent-vs-baseline comparison.

Offline. Every model call here is a fake: a scripted function or the runner's FakeClient. These tests prove the plumbing (prompt assembly, parsing, retries,
failure recording, routing, run folders, comparison checks). They say nothing about how well the model judges alerts; that needs the real dev run (see WEEK3_DAY5_HANDOFF.md).
No network, no labels, no frozen set. Tests that need the LangGraph package are skipped when it is not installed.
"""
import os
import ast
import sys
import copy
import json
import itertools
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

import pandas as pd

import config
import baseline_prompt
import gemini_client
import llm_config
import prompt_registry
import triage_inputs
import verdict_parser
import baseline_store as store
import run_baseline_dev as base
import run_agent_dev as runner
import compare_agent_vs_baseline as compare
from agents import state as S
from agents import supervisor, traffic_analyst, verdict_node as VN, verdict_prompt as VP, graph as graph_module
from tools import FlowStore, build_registry

from tests import test_week3_day1 as d1
from tests import test_week3_day3 as d3
from tests import test_week3_day4 as d4

HAVE_LANGGRAPH = d3.HAVE_LANGGRAPH
BASELINE_V3_SHA = "9403e7ea1937ff0f0f4b4fba548b58efa93bcc6296daa7326970adbaed1b61b7"
BASELINE_V1_SHA_PREFIX = "0208c856"

GOOD = {"is_malicious": True, "attack_type": "PortScan", "mitre_technique": "T1046", "severity": "medium", "evidence": "Many one-packet flows to many ports."}
GOOD_BENIGN = {"is_malicious": False, "attack_type": "BENIGN", "mitre_technique": "NONE", "severity": "none", "evidence": "Ordinary exchange on a common port."}


def reply(obj=None):
    return json.dumps(obj or GOOD)


def full_alert(**kw):
    """A label-free alert with exactly the Week 2 alert fields."""
    alert = d3.make_alert(**kw)
    for name in baseline_prompt.ALERT_FIELDS:
        alert.setdefault(name, 1.0)
    return alert


def full_alerts_frame():
    frame = d3.alerts_frame()
    for name in baseline_prompt.ALERT_FIELDS:
        if name not in frame.columns:
            frame[name] = 1.0
    return frame


class Script:
    """A scripted model: each call returns the next item, or raises it if it is an exception. Records every prompt."""

    def __init__(self, *items):
        self.items, self.prompts = list(items), []

    def __call__(self, prompt):
        self.prompts.append(prompt)
        item = self.items.pop(0) if len(self.items) > 1 else self.items[0]
        if isinstance(item, BaseException):
            raise item
        return item


class Offline(d3.Offline):
    def specialist_state(self, alert=None, enabled=True):
        """A real state after the three specialists ran on the fixture store (verdict not run yet)."""
        final, _ = d3.drive(S.new_state(alert or full_alert()), traffic_analyst.make_traffic_analyst(self.registry), others=d3.all_nodes(self.registry))
        return dict(final, status=S.STATUS_RUNNING, verdict_enabled=enabled)

    def node(self, call, **kw):
        return VN.make_verdict_node(call, max_retries=2, **kw)


# ------------------------------------------------------------------------------------------------ the prompt
class PromptTests(Offline):
    def test_registered_under_its_own_version_and_hash(self):
        spec = VP.get_prompt()
        self.assertEqual((spec.version, VP.list_versions()), ("agent_v1", ["agent_v1"]))
        self.assertEqual(spec.sha256, prompt_registry.compute_sha256("agent_v1", VP.SYSTEM_PROMPT, VP.USER_TEMPLATE))
        self.assertEqual(spec.sha256, VP.prompt_sha256())
        self.assertEqual(len(spec.sha256), 64)
        self.assertNotIn(spec.sha256, [p.sha256 for p in prompt_registry.REGISTRY.values()])

    def test_the_hash_changes_when_the_prompt_changes(self):
        base_hash = VP.prompt_sha256()
        self.assertNotEqual(base_hash, prompt_registry.compute_sha256("agent_v1", VP.SYSTEM_PROMPT + " ", VP.USER_TEMPLATE))
        self.assertNotEqual(base_hash, prompt_registry.compute_sha256("agent_v1", VP.SYSTEM_PROMPT, VP.USER_TEMPLATE + " "))
        self.assertNotEqual(base_hash, prompt_registry.compute_sha256("agent_v2", VP.SYSTEM_PROMPT, VP.USER_TEMPLATE))

    def test_the_locked_baseline_prompts_are_untouched(self):
        self.assertEqual(prompt_registry.list_versions(), ["baseline_v1", "baseline_v2", "baseline_v3"])
        self.assertEqual(prompt_registry.get_prompt("baseline_v3").sha256, BASELINE_V3_SHA)
        self.assertTrue(prompt_registry.get_prompt("baseline_v1").sha256.startswith(BASELINE_V1_SHA_PREFIX))
        with self.assertRaises(KeyError):
            prompt_registry.get_prompt("agent_v1")
        with self.assertRaises(KeyError):
            VP.get_prompt("baseline_v3")

    def test_it_reuses_the_baseline_v3_guidance_and_output_contract_word_for_word(self):
        self.assertIn(prompt_registry.CLASS_GUIDANCE_BLOCK, VP.SYSTEM_PROMPT)
        self.assertTrue(VP.SYSTEM_PROMPT.endswith(prompt_registry.OUTPUT_CONTRACT_BLOCK))

    def test_it_names_the_week2_vocabulary_and_no_other(self):
        import verdict_schema
        for name in verdict_schema.ATTACK_TYPES:
            self.assertIn(name, VP.SYSTEM_PROMPT)
        for field in verdict_schema.FIELDS:
            self.assertIn(field, VP.SYSTEM_PROMPT)

    def test_it_carries_no_technique_ids_beyond_the_baseline_v3_prompt_and_no_class_to_technique_table(self):
        import re
        ids = lambda text: set(re.findall(r"T\d{4}(?:\.\d{3})?", text))
        self.assertLessEqual(ids(VP.SYSTEM_PROMPT), ids(prompt_registry.get_prompt("baseline_v3").system_prompt) | ids(baseline_prompt.SYSTEM_PROMPT))
        self.assertEqual(ids(VP.USER_TEMPLATE), set())

    def test_it_says_findings_are_measurements_and_reference_entries_are_not_evidence(self):
        text = VP.SYSTEM_PROMPT
        for phrase in ("not_run", "Reference material only", "Reputation lookup was not consulted", "Regular timing alone is not proof", "gap in the evidence", "neither a verdict nor a hint"):
            self.assertIn(phrase, text.replace("ATT&CK entries here are reference material only", "Reference material only"))

    def test_it_holds_no_dev_values_or_labels(self):
        for word in ("DEV-", "dev_labels", "frozen", "label"):
            self.assertNotIn(word, VP.SYSTEM_PROMPT + VP.USER_TEMPLATE)

    def test_user_prompt_has_the_alert_and_the_findings_and_nothing_else(self):
        state = self.specialist_state()
        prompt = VP.build_user_prompt(state)
        self.assertTrue(prompt.startswith("Alert:\n{") and "\n\nSpecialist findings:\n{" in prompt and prompt.endswith("exactly the five keys, nothing else."))
        alert_part = prompt.split("\n\nSpecialist findings:\n")[0][len("Alert:\n"):]
        self.assertEqual(sorted(json.loads(alert_part)["alert"]), sorted(baseline_prompt.ALERT_FIELDS))
        findings = json.loads(prompt.split("Specialist findings:\n")[1].split("\n\nReply with")[0])
        self.assertEqual(sorted(findings), ["c2_beacon_analyst", "enrichment_agent", "errors", "traffic_analyst"])
        self.assertEqual(findings["traffic_analyst"]["status"], "ok")
        self.assertTrue(all(set(f) == {"kind", "statement"} for f in findings["traffic_analyst"]["findings"]))

    def test_user_prompt_is_deterministic_and_does_not_change_the_state(self):
        state = self.specialist_state()
        before = copy.deepcopy(state)
        self.assertEqual(VP.build_user_prompt(state), VP.build_user_prompt(copy.deepcopy(state)))
        self.assertEqual(state, before)

    def test_user_prompt_never_contains_raw_evidence_or_tool_arguments(self):
        state = self.specialist_state()
        prompt = VP.build_user_prompt(state)
        self.assertNotIn("evidence_index", prompt)
        self.assertNotIn("\"arguments\"", prompt)
        self.assertNotIn("window_minutes", prompt.split("Specialist findings:")[1])

    def test_extra_or_missing_alert_fields_are_refused(self):
        state = self.specialist_state()
        for extra in ("label", "is_attack", "mitre_technique_id", "anything"):
            with self.assertRaises(ValueError, msg=extra):
                VP.build_user_prompt(dict(state, alert=dict(state["alert"], **{extra: "x"})))
        missing = dict(state["alert"])
        missing.pop("Flow Duration")
        with self.assertRaises(ValueError):
            VP.build_user_prompt(dict(state, alert=missing))

    def test_a_missing_or_infinite_number_is_refused(self):
        state = self.specialist_state()
        for bad in (float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                VP.build_user_prompt(dict(state, alert=dict(state["alert"], **{"Flow Duration": bad})))

    def test_a_skipped_beacon_analyst_is_reported_as_not_run_with_the_supervisors_reason(self):
        state = self.specialist_state(full_alert(src="203.0.113.7", dst="203.0.113.8"))
        payload = VP.findings_payload(state)
        self.assertEqual(payload["c2_beacon_analyst"]["status"], "not_run")
        self.assertIn("flow", payload["c2_beacon_analyst"]["reason"])
        self.assertNotIn("C2 beaconing analyst skipped", payload["c2_beacon_analyst"]["reason"])

    def test_a_beacon_analyst_that_ran_reports_its_assessment_and_limits(self):
        payload = VP.findings_payload(self.specialist_state())
        beacon = payload["c2_beacon_analyst"]
        self.assertIn(beacon["status"], ("ok", "partial"))
        self.assertIn("assessment", beacon)
        self.assertIsInstance(beacon["beacon_candidate"], bool)
        self.assertTrue(len(beacon["limits"]) >= 1)

    def test_enrichment_reports_what_was_not_consulted(self):
        payload = VP.findings_payload(self.specialist_state())
        self.assertIn("reputation_lookup", [n["source"] for n in payload["enrichment_agent"]["not_consulted"]])

    def test_failed_and_missing_specialists_and_errors_are_shown_as_gaps(self):
        state = S.new_state(full_alert())
        state = dict(state, traffic_findings={"status": "failed", "findings": [], "tool_errors": 2}, errors=[{"node": "traffic_analyst", "code": "tool_exception", "message": "x", "tool": "summarize_flows"}])
        payload = VP.findings_payload(state)
        self.assertEqual(payload["traffic_analyst"], {"status": "failed", "findings": [], "failed_tool_calls": 2})
        self.assertEqual(payload["enrichment_agent"]["status"], "not_run")
        self.assertEqual(payload["errors"], [{"node": "traffic_analyst", "code": "tool_exception", "message": "x"}])
        VP.build_user_prompt(state)

    def test_snapshot_text_uses_the_registered_layout(self):
        text = VP.snapshot_text(VP.get_prompt(), "DEV-0001", "USER")
        self.assertTrue(text.startswith("PROMPT agent_v1 sha256 " + VP.prompt_sha256()))
        self.assertIn("=== user template ===", text)
        self.assertIn("=== user prompt for DEV-0001 ===\nUSER", text)


# ------------------------------------------------------------------------------------------------ the node
class NodeTests(Offline):
    def run_node(self, call, **kw):
        state = self.specialist_state()
        before = copy.deepcopy(state)
        update = self.node(call, **kw)(state)
        self.assertEqual(state, before, "the node changed the state it was given")
        return state, update

    def test_a_valid_reply_becomes_an_ok_verdict_with_the_five_fields(self):
        script = Script(reply())
        state, update = self.run_node(script)
        v = update["verdict"]
        self.assertEqual((v["status"], v["error_code"], v["attempts"], v["malformed_first_try"]), ("ok", None, 1, False))
        self.assertEqual(v["verdict"], GOOD)
        self.assertEqual(sorted(v["verdict"]), sorted(["is_malicious", "attack_type", "mitre_technique", "severity", "evidence"]))
        self.assertEqual((v["prompt_version"], v["agent_prompt_sha256"]), ("agent_v1", VP.prompt_sha256()))
        self.assertEqual(len(script.prompts), 1)
        self.assertEqual(v["prompt_sha256"], __import__("hashlib").sha256(script.prompts[0].encode("utf-8")).hexdigest())
        self.assertEqual(script.prompts[0], VP.build_user_prompt(state))

    def test_the_update_has_only_verdict_errors_and_trace(self):
        _, update = self.run_node(Script(reply()))
        self.assertEqual(set(update), {"verdict", "trace"})
        self.assertEqual(update["trace"][-1], "verdict_node")
        _, failed = self.run_node(Script("nope"))
        self.assertEqual(set(failed), {"verdict", "errors", "trace"})

    def test_a_benign_verdict_is_accepted(self):
        _, update = self.run_node(Script(reply(GOOD_BENIGN)))
        self.assertEqual((update["verdict"]["status"], update["verdict"]["verdict"]["attack_type"]), ("ok", "BENIGN"))

    def test_formatting_only_repairs_are_recorded(self):
        _, update = self.run_node(Script("Here you go:\n```json\n" + reply() + "\n```"))
        self.assertEqual(update["verdict"]["status"], "ok")
        self.assertIn("removed_code_fence", update["verdict"]["repairs"])

    def test_a_malformed_reply_is_retried_with_feedback_and_can_recover(self):
        script = Script("this is not json", reply())
        state, update = self.run_node(script)
        v = update["verdict"]
        self.assertEqual((v["status"], v["attempts"], v["malformed_first_try"]), ("ok", 2, True))
        self.assertEqual([a["error_code"] for a in v["attempt_log"]], ["no_json", None])
        self.assertEqual(len(script.prompts), 2)
        retry = script.prompts[1]
        self.assertTrue(retry.startswith(script.prompts[0].rstrip()))
        self.assertIn("Your previous reply could not be used.", retry)
        self.assertIn("this is not json", retry)
        self.assertIn("no_json", retry)
        self.assertNotIn("errors", update)

    def test_retry_prompt_explicitly_forbids_duplicate_and_unapproved_keys(self):
        script = Script('{"is_malicious": true, "attack_type": "PortScan", "attack_type": "Bot"}')
        self.run_node(script)
        retry = script.prompts[1]
        self.assertIn("Generate a fresh answer from scratch", retry)
        self.assertIn("Include each of the five permitted keys exactly once", retry)
        self.assertIn("Remove every unapproved field", retry)
        self.assertIn("do not repeat duplicate keys", retry)

    def test_attempt_prompt_hashes_match_the_exact_prompts_sent_to_the_model(self):
        script = Script("this is not json", reply())
        _, update = self.run_node(script)
        recorded = update["verdict"]["attempt_prompt_sha256"]
        expected = [__import__("hashlib").sha256(prompt.encode("utf-8")).hexdigest() for prompt in script.prompts]
        self.assertEqual(recorded, expected)
        self.assertEqual(len(recorded), update["verdict"]["attempts"])
        self.assertNotEqual(recorded[0], recorded[1])

    def test_retries_run_out_after_the_initial_call_plus_two_retries(self):
        script = Script("bad one", "bad two", "bad three", reply())
        state, update = self.run_node(script)
        v = update["verdict"]
        self.assertEqual(len(script.prompts), 3)
        self.assertEqual((v["status"], v["verdict"], v["attempts"], v["error_code"]), ("parse_failed", None, 3, "no_json"))
        self.assertEqual([a["error_code"] for a in v["attempt_log"]], ["no_json"] * 3)
        self.assertTrue(v["malformed_first_try"])

    def test_the_failure_is_recorded_in_errors_and_never_fabricated_into_a_verdict(self):
        state, update = self.run_node(Script("bad"))
        self.assertIsNone(update["verdict"]["verdict"])
        self.assertEqual(len(update["errors"]), len(state["errors"]) + 1)
        self.assertEqual((update["errors"][-1]["node"], update["errors"][-1]["code"]), ("verdict_node", "no_json"))
        self.assertIn("parse_failed", update["errors"][-1]["message"])

    def test_every_parser_error_kind_ends_as_parse_failed_with_its_own_code(self):
        cases = {"": "empty_response", "[1]": "not_an_object", "{": "invalid_json", "{} {}": "multiple_json_objects",
                 json.dumps({"is_malicious": True}): "missing_fields", json.dumps(dict(GOOD, extra=1)): "extra_fields",
                 json.dumps(dict(GOOD, severity="huge")): "invalid_field", json.dumps(dict(GOOD, is_malicious="true")): "invalid_field",
                 json.dumps(dict(GOOD, is_malicious=False)): "contradictory", json.dumps(dict(GOOD, mitre_technique="NONE")): "contradictory"}
        for text, code in cases.items():
            _, update = self.run_node(Script(text))
            self.assertEqual((update["verdict"]["status"], update["verdict"]["error_code"]), ("parse_failed", code), repr(text))

    def test_max_retries_zero_makes_one_call(self):
        script = Script("bad", reply())
        _, update = (lambda s: (s, VN.make_verdict_node(script, max_retries=0)(s)))(self.specialist_state())
        self.assertEqual((len(script.prompts), update["verdict"]["status"], update["verdict"]["attempts"]), (1, "parse_failed", 1))

    def test_the_default_retry_rule_is_the_week2_one(self):
        script = Script("bad")
        VN.make_verdict_node(script)(self.specialist_state())
        self.assertEqual(len(script.prompts), 1 + llm_config.MAX_RETRIES)

    def test_an_unavailable_model_is_a_model_error_with_its_own_code(self):
        class Unreachable(Exception):
            pass
        state = self.specialist_state()
        update = self.node(Script(Unreachable("down for good")), unavailable=(Unreachable,))(state)
        v = update["verdict"]
        self.assertEqual((v["status"], v["error_code"], v["verdict"], v["attempts"]), ("model_error", "model_unavailable", None, 0))
        self.assertIn("down for good", v["error_detail"])
        self.assertEqual(update["errors"][-1]["code"], "model_unavailable")

    def test_an_unavailable_model_after_a_bad_reply_keeps_the_attempt_log(self):
        class Unreachable(Exception):
            pass
        update = self.node(Script("bad", Unreachable("gone")), unavailable=(Unreachable,))(self.specialist_state())
        v = update["verdict"]
        self.assertEqual((v["status"], v["attempts"], [a["error_code"] for a in v["attempt_log"]]), ("model_error", 1, ["no_json"]))

    def test_a_fatal_exception_is_not_swallowed(self):
        class Refused(Exception):
            pass
        with self.assertRaises(Refused):
            self.node(Script(Refused("bad key")), fatal=(Refused,))(self.specialist_state())

    def test_fatal_wins_over_unavailable_and_over_the_generic_catch(self):
        class Both(Exception):
            pass
        with self.assertRaises(Both):
            self.node(Script(Both("x")), fatal=(Both,), unavailable=(Both,))(self.specialist_state())

    def test_any_other_exception_becomes_a_model_error_and_keeps_only_the_type_name(self):
        update = self.node(Script(KeyError("secret-looking-text")))(self.specialist_state())
        v = update["verdict"]
        self.assertEqual((v["status"], v["error_code"], v["verdict"]), ("model_error", "model_exception", None))
        self.assertIn("KeyError", v["error_detail"])
        self.assertNotIn("secret-looking-text", json.dumps(update))

    def test_a_prompt_that_cannot_be_built_makes_no_call_and_is_recorded(self):
        script = Script(reply())
        state = self.specialist_state()
        update = self.node(script)(dict(state, alert=dict(state["alert"], label="x")))
        v = update["verdict"]
        self.assertEqual((v["status"], v["error_code"], v["attempts"], len(script.prompts)), ("model_error", "prompt_build_failed", 0, 0))
        self.assertIsNone(v["prompt_sha256"])
        self.assertEqual(update["errors"][-1]["code"], "prompt_build_failed")

    def test_upstream_health_is_recorded(self):
        _, update = self.run_node(Script(reply()))
        up = update["verdict"]["upstream"]
        self.assertEqual((up["traffic"], up["enrichment"], up["errors"]), ("ok", "ok", 0))
        self.assertIn(up["beacon"], ("ok", "partial", "not_run"))
        state = dict(self.specialist_state(), traffic_findings={"status": "failed", "findings": [], "tool_errors": 1}, enrichment_findings=None, beacon_findings=None)
        self.assertEqual(VN.upstream_health(state), {"traffic": "failed", "beacon": "not_run", "enrichment": "not_run", "errors": len(state["errors"])})

    def test_the_node_still_runs_when_upstream_failed_and_the_prompt_says_so(self):
        script = Script(reply(GOOD_BENIGN))
        state = dict(S.new_state(full_alert()), traffic_findings={"status": "failed", "findings": [], "tool_errors": 3}, verdict_enabled=True)
        update = self.node(script)(state)
        self.assertEqual(update["verdict"]["status"], "ok")
        self.assertIn('"status": "failed"', script.prompts[0])
        self.assertEqual(update["verdict"]["upstream"]["traffic"], "failed")

    def test_the_replies_cannot_change_the_alert_in_the_prompt(self):
        script = Script("bad", reply())
        state = self.specialist_state()
        self.node(script)(state)
        self.assertIn(VP.build_user_prompt(state), script.prompts[1])

    def test_call_model_must_be_a_function(self):
        with self.assertRaises(ValueError):
            VN.make_verdict_node("not callable")

    def test_not_configured_node_records_a_failure_and_makes_no_verdict(self):
        state = self.specialist_state()
        update = VN.verdict_not_configured_node(state)
        v = update["verdict"]
        self.assertEqual((v["status"], v["error_code"], v["verdict"]), ("model_error", "verdict_not_configured", None))
        self.assertEqual(update["errors"][-1]["code"], "verdict_not_configured")

    def test_model_error_codes_cover_the_call_failures_only(self):
        self.assertEqual(VN.MODEL_ERROR_CODES, ("model_unavailable", "model_exception"))

    def test_the_node_module_imports_no_model_sdk_client_key_or_network_code(self):
        tree = ast.parse(d3.read_text(os.path.join(ROOT, "src", "agents", "verdict_node.py")))
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                modules.add((node.module or "").split(".")[0])
        self.assertEqual(modules, {"hashlib", "verdict_parser"})


# ------------------------------------------------------------------------------------------------ state and routing
class StateDay5Tests(unittest.TestCase):
    def test_defaults_and_flag(self):
        s = S.new_state(d3.make_alert())
        self.assertEqual((s["verdict_enabled"], s["verdict"]), (False, None))
        S.validate_state(s)
        e = S.new_state(d3.make_alert(), verdict_enabled=True)
        self.assertTrue(e["verdict_enabled"])
        S.validate_state(e)

    def test_the_flag_must_be_a_real_boolean(self):
        for bad in (1, "yes", None, 0):
            with self.assertRaises(ValueError, msg=str(bad)):
                S.new_state(d3.make_alert(), verdict_enabled=bad)
            with self.assertRaises(ValueError, msg=str(bad)):
                S.validate_state(dict(S.new_state(d3.make_alert()), verdict_enabled=bad))

    def test_verdict_must_be_none_or_a_dict(self):
        with self.assertRaises(ValueError):
            S.validate_state(dict(S.new_state(d3.make_alert()), verdict="ok"))

    def test_routes_and_constants(self):
        self.assertEqual(S.NODE_VERDICT, "verdict_node")
        self.assertEqual(S.ROUTES[-2:], ("verdict_node", "end"))
        self.assertEqual((S.GRAPH_VERSION, S.MAX_SUPERVISOR_VISITS), ("v0.1", 5))
        S.validate_state(dict(S.new_state(d3.make_alert()), next_node="verdict_node"))

    def test_the_new_state_has_exactly_the_documented_fields(self):
        self.assertEqual(set(S.new_state(d3.make_alert())), set(S.STATE_KEYS))
        self.assertIn("verdict_enabled", S.STATE_KEYS)
        self.assertIn("verdict", S.STATE_KEYS)


def drive5(state, traffic, others=None, verdict=None, limit=60):
    nodes = {S.NODE_TRAFFIC_ANALYST: traffic, S.NODE_C2_BEACON_ANALYST: (others or {}).get(S.NODE_C2_BEACON_ANALYST, lambda st: {}),
             S.NODE_ENRICHMENT_AGENT: (others or {}).get(S.NODE_ENRICHMENT_AGENT, lambda st: {}), S.NODE_VERDICT: verdict or (lambda st: {})}
    steps = 0
    while True:
        steps += 1
        assert steps <= limit, "runaway loop"
        state = {**state, **supervisor.supervisor_node(state)}
        route = supervisor.route_from_supervisor(state)
        if route == "end":
            return state, steps
        steps += 1
        state = {**state, **nodes[route](state)}


class RoutingDay5Tests(Offline):
    def real(self, alert, enabled, call=None):
        node = VN.make_verdict_node(call or Script(reply()), max_retries=2)
        return drive5(S.new_state(alert, verdict_enabled=enabled), traffic_analyst.make_traffic_analyst(self.registry), others=d3.all_nodes(self.registry), verdict=node)

    def test_disabled_runs_exactly_the_day4_paths_and_never_calls_the_model(self):
        script = Script(reply())
        for alert in (full_alert(), full_alert(src="203.0.113.7", dst="203.0.113.8")):
            final, _ = self.real(alert, False, script)
            self.assertNotIn("verdict_node", final["trace"])
            self.assertIsNone(final["verdict"])
            self.assertEqual(final["status"], "completed")
        self.assertEqual(script.prompts, [])

    def test_enabled_the_verdict_runs_once_after_the_specialists_then_the_graph_ends(self):
        final, steps = self.real(full_alert(), True)
        self.assertEqual(final["trace"], ["supervisor", "traffic_analyst", "supervisor", "c2_beacon_analyst", "supervisor", "enrichment_agent", "supervisor", "verdict_node", "supervisor"])
        self.assertEqual((final["status"], final["supervisor_visits"], steps), ("completed", 5, 9))
        self.assertEqual(final["verdict"]["status"], "ok")
        self.assertEqual([r["route"] for r in final["routing"]], ["traffic_analyst", "c2_beacon_analyst", "enrichment_agent", "verdict_node", "end"])
        S.validate_state(final)

    def test_enabled_without_repeat_contact_the_beacon_analyst_is_skipped_and_the_verdict_still_runs(self):
        final, _ = self.real(full_alert(src="203.0.113.7", dst="203.0.113.8"), True)
        self.assertEqual([n for n in final["trace"] if n != "supervisor"], ["traffic_analyst", "enrichment_agent", "verdict_node"])
        self.assertEqual(final["supervisor_visits"], 4)
        self.assertIn("C2 beaconing analyst skipped", final["routing"][-2]["reason"])
        self.assertEqual(final["status"], "completed")

    def test_the_verdict_prompt_gets_the_findings_that_are_in_the_state(self):
        script = Script(reply())
        final, _ = self.real(full_alert(), True, script)
        sent = script.prompts[0]
        for finding in final["traffic_findings"]["findings"][:1] + final["beacon_findings"]["findings"][:1] + final["enrichment_findings"]["findings"][:1]:
            self.assertIn(json.dumps(finding["statement"])[1:-1], sent)

    def test_a_failed_traffic_analysis_still_gets_a_recorded_verdict_step_and_the_run_stays_failed(self):
        registry = build_registry()   # no flow store: every flow tool fails
        node = VN.make_verdict_node(Script(reply(GOOD_BENIGN)), max_retries=2)
        final, _ = drive5(S.new_state(full_alert(), verdict_enabled=True), traffic_analyst.make_traffic_analyst(registry), verdict=node)
        self.assertEqual(final["status"], "failed")
        self.assertEqual([n for n in final["trace"] if n != "supervisor"], ["traffic_analyst", "verdict_node"])
        self.assertEqual(final["verdict"]["upstream"]["traffic"], "failed")
        self.assertEqual(final["routing"][-1]["route"], "end")

    def test_a_failed_traffic_analysis_with_the_verdict_off_is_the_day4_path(self):
        final, _ = drive5(S.new_state(full_alert()), traffic_analyst.make_traffic_analyst(build_registry()))
        self.assertEqual((final["status"], final["trace"]), ("failed", d4.FAILED_PATH))

    def test_a_failed_verdict_step_makes_the_run_completed_with_errors(self):
        for text, status in (("bad", "parse_failed"),):
            final, _ = self.real(full_alert(), True, Script(text))
            self.assertEqual((final["status"], final["verdict"]["status"]), ("completed_with_errors", status))
            self.assertIn("verdict_node", [e["node"] for e in final["errors"]])
        final, _ = self.real(full_alert(), True, Script(RuntimeError("boom")))
        self.assertEqual((final["status"], final["verdict"]["status"], final["verdict"]["error_code"]), ("completed_with_errors", "model_error", "model_exception"))

    def test_a_verdict_node_that_returns_nothing_is_recorded_and_not_rerun(self):
        final, _ = drive5(S.new_state(d3.make_alert(), verdict_enabled=True), d4.stub("traffic_findings", "traffic_analyst", "ok"),
                          others={S.NODE_C2_BEACON_ANALYST: d4.stub("beacon_findings", "c2_beacon_analyst", "ok"), S.NODE_ENRICHMENT_AGENT: d4.stub("enrichment_findings", "enrichment_agent", "ok")},
                          verdict=d4.stub("verdict", "verdict_node", "nothing"))
        self.assertEqual((final["status"], final["trace"].count("verdict_node")), ("completed_with_errors", 1))
        self.assertIn("no_findings", [e["code"] for e in final["errors"]])
        self.assertIsNone(final["verdict"])

    def test_a_verdict_node_that_never_reports_is_stopped_by_the_loop_guard_without_a_verdict(self):
        final, _ = drive5(S.new_state(d3.make_alert(), verdict_enabled=True), d4.stub("traffic_findings", "traffic_analyst", "ok"),
                          others={S.NODE_C2_BEACON_ANALYST: d4.stub("beacon_findings", "c2_beacon_analyst", "ok"), S.NODE_ENRICHMENT_AGENT: d4.stub("enrichment_findings", "enrichment_agent", "ok")},
                          verdict=d4.stub("verdict", "verdict_node", "silent"))
        self.assertEqual(final["status"], "failed")
        self.assertIn("loop_guard", [e["code"] for e in final["errors"]])
        self.assertIsNone(final["verdict"])
        self.assertLessEqual(final["supervisor_visits"], S.MAX_SUPERVISOR_VISITS + 1)

    def test_a_traffic_analyst_that_leaves_no_findings_ends_the_run_before_the_verdict_step(self):
        final, _ = drive5(S.new_state(d3.make_alert(), verdict_enabled=True), d4.stub("traffic_findings", "traffic_analyst", "nothing"), verdict=d4.stub("verdict", "verdict_node", "ok"))
        self.assertEqual(final["status"], "failed")
        self.assertNotIn("verdict_node", final["trace"])

    def test_the_verdict_step_is_never_routed_to_twice(self):
        for alert in (full_alert(), full_alert(src="203.0.113.7", dst="203.0.113.8")):
            final, _ = self.real(alert, True)
            self.assertEqual(final["trace"].count("verdict_node"), 1)

    def test_the_decision_is_a_pure_function_of_the_state(self):
        state = dict(S.new_state(d3.make_alert(), verdict_enabled=True), traffic_findings={"status": "ok"}, beacon_findings={"status": "ok"}, enrichment_findings={"status": "ok"},
                     trace=["supervisor", "traffic_analyst", "supervisor", "c2_beacon_analyst", "supervisor", "enrichment_agent"], supervisor_visits=3)
        before = copy.deepcopy(state)
        a, b = supervisor.decide(state), supervisor.decide(copy.deepcopy(state))
        self.assertEqual(a, b)
        self.assertEqual(a["route"], "verdict_node")
        self.assertEqual(state, before)


class TerminationDay5Tests(Offline):
    OUTCOMES = ("ok", "partial", "failed", "nothing", "silent")
    VERDICT_OUTCOMES = ("ok", "parse_failed", "model_error", "nothing", "silent")

    def test_every_combination_with_the_verdict_step_terminates_runs_nothing_twice_and_ends_with_the_right_status(self):
        count = 0
        for repeat, t, b, e, v in itertools.product((True, False), self.OUTCOMES, self.OUTCOMES, self.OUTCOMES, self.VERDICT_OUTCOMES):
            traffic_node = d4.stub("traffic_findings", "traffic_analyst", t)
            if repeat:
                inner = traffic_node
                traffic_node = lambda state, inner=inner: dict(inner(state), evidence=[d4.src_summary_evidence(3)])
            others = {S.NODE_C2_BEACON_ANALYST: d4.stub("beacon_findings", "c2_beacon_analyst", b), S.NODE_ENRICHMENT_AGENT: d4.stub("enrichment_findings", "enrichment_agent", e)}
            final, steps = drive5(S.new_state(d3.make_alert(), verdict_enabled=True), traffic_node, others=others, verdict=d4.stub("verdict", "verdict_node", v))
            label = (repeat, t, b, e, v)
            self.assertIn(final["status"], S.TERMINAL_STATUSES, label)
            self.assertLessEqual(final["supervisor_visits"], S.MAX_SUPERVISOR_VISITS + 1, label)
            self.assertEqual(final["routing"][-1]["route"], "end", label)
            if "silent" in (t, b, e, v):
                self.assertIn(final["status"], ("failed", "completed", "completed_with_errors"), label)
                if final["supervisor_visits"] > S.MAX_SUPERVISOR_VISITS:
                    self.assertIn("loop_guard", [x["code"] for x in final["errors"]], label)
            else:
                for agent in ("traffic_analyst", "c2_beacon_analyst", "enrichment_agent", "verdict_node"):
                    self.assertLessEqual(final["trace"].count(agent), 1, label)
                self.assertLessEqual(final["supervisor_visits"], S.MAX_SUPERVISOR_VISITS, label)
                if t == "nothing":
                    self.assertNotIn("verdict_node", final["trace"], label)
                    self.assertEqual(final["status"], "failed", label)
                else:
                    self.assertEqual(final["trace"].count("verdict_node"), 1, label)
                    ran = [t] + ([b] if repeat else []) + [e, v]
                    expected = "failed" if t == "failed" else ("completed" if all(o == "ok" for o in ran) else "completed_with_errors")
                    self.assertEqual(final["status"], expected, label)
            count += 1
        self.assertEqual(count, 2 * 5 ** 3 * 5)

    def test_the_verdict_step_off_never_routes_to_the_verdict_node_in_any_combination(self):
        for repeat, t, b, e in itertools.product((True, False), self.OUTCOMES, self.OUTCOMES, self.OUTCOMES):
            traffic_node = d4.stub("traffic_findings", "traffic_analyst", t)
            if repeat:
                inner = traffic_node
                traffic_node = lambda state, inner=inner: dict(inner(state), evidence=[d4.src_summary_evidence(3)])
            others = {S.NODE_C2_BEACON_ANALYST: d4.stub("beacon_findings", "c2_beacon_analyst", b), S.NODE_ENRICHMENT_AGENT: d4.stub("enrichment_findings", "enrichment_agent", e)}
            final, _ = drive5(S.new_state(d3.make_alert()), traffic_node, others=others, verdict=lambda st: self.fail("the verdict node ran with the step off"))
            self.assertNotIn("verdict_node", final["trace"])
            self.assertNotIn("verdict_node", [r["route"] for r in final["routing"]])

    def test_the_longest_path_is_exactly_the_visit_limit(self):
        final, _ = drive5(S.new_state(d3.make_alert(), verdict_enabled=True), lambda st: dict(d4.stub("traffic_findings", "traffic_analyst", "ok")(st), evidence=[d4.src_summary_evidence(3)]),
                          others={S.NODE_C2_BEACON_ANALYST: d4.stub("beacon_findings", "c2_beacon_analyst", "ok"), S.NODE_ENRICHMENT_AGENT: d4.stub("enrichment_findings", "enrichment_agent", "ok")},
                          verdict=d4.stub("verdict", "verdict_node", "ok"))
        self.assertEqual((final["supervisor_visits"], final["status"]), (S.MAX_SUPERVISOR_VISITS, "completed"))


# ------------------------------------------------------------------------------------------------ the compiled graph
@unittest.skipUnless(HAVE_LANGGRAPH, "LangGraph is not installed")
class GraphDay5Tests(Offline):
    def test_the_compiled_graph_matches_the_hand_driven_loop_with_the_verdict_step(self):
        for alert in (full_alert(), full_alert(src="203.0.113.7", dst="203.0.113.8")):
            node_a = VN.make_verdict_node(Script(reply()), max_retries=2)
            node_b = VN.make_verdict_node(Script(reply()), max_retries=2)
            a = graph_module.run_alert(graph_module.build_graph(self.registry, verdict_node=node_a), alert, verdict_enabled=True)
            b, _ = drive5(S.new_state(alert, verdict_enabled=True), traffic_analyst.make_traffic_analyst(self.registry), others=d3.all_nodes(self.registry), verdict=node_b)
            self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_with_the_step_off_the_graph_never_calls_the_model(self):
        script = Script(reply())
        final = graph_module.run_alert(graph_module.build_graph(self.registry, verdict_node=VN.make_verdict_node(script)), full_alert())
        self.assertEqual((script.prompts, final["verdict"], final["status"]), ([], None, "completed"))

    def test_a_graph_built_without_a_model_records_an_explicit_failure_when_asked_for_a_verdict(self):
        final = graph_module.run_alert(graph_module.build_graph(self.registry), full_alert(), verdict_enabled=True)
        self.assertEqual((final["verdict"]["status"], final["verdict"]["error_code"], final["status"]), ("model_error", "verdict_not_configured", "completed_with_errors"))

    def test_a_fatal_model_error_propagates_out_of_the_graph(self):
        node = VN.make_verdict_node(Script(gemini_client.PermanentModelError("refused", 403)), fatal=(gemini_client.PermanentModelError,))
        with self.assertRaises(gemini_client.PermanentModelError):
            graph_module.run_alert(graph_module.build_graph(self.registry, verdict_node=node), full_alert(), verdict_enabled=True)

    def test_the_recursion_limit_covers_the_longest_path_with_the_verdict_step(self):
        self.assertGreaterEqual(graph_module.RECURSION_LIMIT, 9)


# ------------------------------------------------------------------------------------------------ the runner
class RunnerBase(Offline):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.runs = os.path.join(self.tmp.name, "agent_runs")
        self.base_runs = os.path.join(self.tmp.name, "baseline_runs")
        patches = [mock.patch.object(base, "load_inputs", return_value=(full_alerts_frame(), pd.DataFrame(), {"dev_alerts_sha256": "a", "flow_store_dev_sha256": "b"})),
                   mock.patch.object(FlowStore, "from_dev", return_value=self.store),
                   mock.patch.object(base, "check_llm_config", return_value={"small": "gemini-test-lite", "strong": "gemini-test-pro"}),
                   mock.patch.object(base, "git_info", return_value={"commit": "abc1234", "dirty": False}),
                   mock.patch.object(base, "package_versions", return_value={}),
                   mock.patch.object(base, "week1_snapshot", return_value={}),
                   mock.patch.object(base, "count_lines", return_value=0)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.out = mock.patch("sys.stdout")
        self.out.start()
        self.addCleanup(self.out.stop)

    def run_main(self, *args):
        return runner.main(["--runs-dir", self.runs, "--baseline-runs-dir", self.base_runs, *args])

    def write_baseline(self, name="dev_flash_lite_v3_final", **changes):
        meta = {"run_name": name, "set": "dev", "prompt_version": "baseline_v3", "prompt_sha256": BASELINE_V3_SHA, "model": "gemini-test-lite", "provider": "gemini", "status": "complete",
                "settings": {"temperature": llm_config.TEMPERATURE, "max_output_tokens": llm_config.MAX_OUTPUT_TOKENS, "seed": base.GENERATION_SEED, "parse_retries": llm_config.MAX_RETRIES,
                             "timeout_seconds": 60, "transport_retries": 4, "requests_per_minute": 10.0}}
        meta.update(changes)
        os.makedirs(os.path.join(self.base_runs, name))
        store.write_json_atomic(os.path.join(self.base_runs, name, "run_meta.json"), meta)
        return meta

    def results(self, name):
        return store.read_jsonl(os.path.join(self.runs, name, "results.jsonl"))

    def meta(self, name):
        return store.read_json(os.path.join(self.runs, name, "run_meta.json"))


class FakeRunTests(RunnerBase):
    def test_a_fake_run_writes_the_week2_run_folder_and_flags_itself(self):
        code = self.run_main("--fake-model", "--run-name", "FAKE_a")
        self.assertEqual(sorted(os.listdir(os.path.join(self.runs, "FAKE_a"))), ["prompt_snapshot.txt", "raw_responses.jsonl", "results.jsonl", "run_meta.json", "verdicts.csv"])
        m = self.meta("FAKE_a")
        self.assertEqual((m["fake_model"], m["runner"], m["set"], m["prompt_version"], m["prompt_sha256"], m["model"]), (True, "run_agent_dev", "dev", "agent_v1", VP.prompt_sha256(), "gemini-test-lite"))
        self.assertEqual((m["agent"]["graph_version"], m["agent"]["verdict_enabled"], m["agent"]["reputation_lookup"]), ("v0.1", True, "not_consulted"))
        self.assertEqual(m["n_selected"], 4)
        self.assertEqual(len(self.results("FAKE_a")), 4)
        self.assertEqual(code, 0)

    def test_the_fake_scenarios_exercise_success_retry_exhaustion_and_unavailability(self):
        self.run_main("--fake-model", "--run-name", "FAKE_b", "--limit", "4")
        by = {r["alert_id"]: r for r in self.results("FAKE_b")}
        # alerts are taken in dev file order; the fake script is: ok_benign, ok_attack, malformed_then_ok, always_malformed
        order = list(full_alerts_frame()["alert_id"])
        self.assertEqual([by[a]["status"] for a in order], ["ok", "ok", "ok", "parse_failed"])
        self.assertEqual([by[a]["attempts"] for a in order], [1, 1, 2, 3])
        self.assertEqual(by[order[2]]["malformed_first_try"], True)
        self.assertEqual(by[order[3]]["error_code"], "no_json")
        self.assertIsNone(by[order[3]]["verdict"])

    def test_the_fake_script_also_covers_transport_recovery_and_unavailability(self):
        client = runner.FakeClient()
        client.begin(4)
        with self.assertRaises(gemini_client.TransientModelError):
            client.generate("p")
        self.assertEqual(client.generate("p").text, runner.VALID_BENIGN)
        client.begin(5)
        for _ in range(5):
            with self.assertRaises(gemini_client.TransientModelError):
                client.generate("p")
        client.begin(6)    # the script wraps around
        self.assertEqual(client.scenario, "ok_benign")

    def test_an_unavailable_model_is_recorded_as_model_error_and_does_not_stop_the_run(self):
        frame = pd.concat([full_alerts_frame()] * 2).iloc[:6].copy()
        frame["alert_id"] = ["DEV-000" + str(i) for i in range(1, 7)]
        with mock.patch.object(base, "load_inputs", return_value=(frame, pd.DataFrame(), {"dev_alerts_sha256": "a", "flow_store_dev_sha256": "b"})):
            self.run_main("--fake-model", "--run-name", "FAKE_c")
        by = {r["alert_id"]: r for r in self.results("FAKE_c")}
        self.assertEqual(by["DEV-0006"]["status"], "model_error")
        self.assertEqual((by["DEV-0006"]["error_code"], by["DEV-0006"]["verdict"], by["DEV-0006"]["model_calls"]), ("model_unavailable", None, 0))
        self.assertEqual(by["DEV-0005"]["status"], "ok")    # transient error, then recovered
        self.assertEqual(self.meta("FAKE_c")["status"], "incomplete")

    def test_every_result_line_is_what_the_week2_evaluator_reads(self):
        self.run_main("--fake-model", "--run-name", "FAKE_d")
        for r in self.results("FAKE_d"):
            self.assertIn(r["status"], ("ok", "parse_failed", "model_error"))
            if r["status"] == "ok":
                self.assertEqual(sorted(r["verdict"]), sorted(store.VERDICT_FIELDS))
            else:
                self.assertIsNone(r["verdict"])
            for key in ("alert_id", "attempts", "malformed_first_try", "model_calls", "latency_seconds", "finish_reasons", "prompt_tokens", "output_tokens", "total_tokens", "prompt_sha256"):
                self.assertIn(key, r)
            self.assertEqual(r["agent_prompt_sha256"], VP.prompt_sha256())
            self.assertEqual(r["graph_version"], "v0.1")
            self.assertIn("verdict_node", r["trace"])
        import evaluate
        latest, n, calls, meta = evaluate.load_run(os.path.join(self.runs, "FAKE_d"))
        self.assertEqual((len(latest), n, meta["prompt_version"], meta["model"]), (4, 4, "agent_v1", "gemini-test-lite"))
        self.assertIsNotNone(calls)

    def test_the_result_records_the_agent_context(self):
        self.run_main("--fake-model", "--run-name", "FAKE_e", "--limit", "1")
        r = self.results("FAKE_e")[0]
        self.assertEqual(r["graph_status"], "completed")
        self.assertEqual(r["routing"][-1]["route"], "end")
        self.assertEqual(sorted(r["upstream"]), ["beacon", "enrichment", "errors", "traffic"])
        self.assertGreater(r["tool_calls"], 0)
        self.assertGreaterEqual(r["graph_seconds"], 0)
        self.assertEqual(r["graph_errors"], [])

    def test_raw_responses_hold_the_prompt_and_reply_of_every_call(self):
        self.run_main("--fake-model", "--run-name", "FAKE_f", "--limit", "3")
        raw = store.read_jsonl(os.path.join(self.runs, "FAKE_f", "raw_responses.jsonl"))
        self.assertEqual(len(raw), sum(r["model_calls"] for r in self.results("FAKE_f")))
        self.assertTrue(all("Specialist findings:" in line["prompt"] for line in raw))
        self.assertTrue(raw[3]["prompt"].count("Your previous reply could not be used.") == 1)    # the retry in the third alert

    def test_the_prompt_snapshot_is_the_agent_prompt_and_the_first_alerts_user_prompt(self):
        self.run_main("--fake-model", "--run-name", "FAKE_g", "--limit", "2")
        text = d3.read_text(os.path.join(self.runs, "FAKE_g", "prompt_snapshot.txt"))
        self.assertTrue(text.startswith("PROMPT agent_v1 sha256 " + VP.prompt_sha256()))
        self.assertIn("=== user prompt for DEV-0004 ===", text)
        self.assertIn("Specialist findings:", text)

    def test_a_new_run_never_overwrites_an_existing_folder(self):
        self.run_main("--fake-model", "--run-name", "FAKE_h", "--limit", "1")
        before = d3.read_text(os.path.join(self.runs, "FAKE_h", "results.jsonl"))
        with self.assertRaises(SystemExit) as cm:
            self.run_main("--fake-model", "--run-name", "FAKE_h", "--limit", "1")
        self.assertIn("already exists", str(cm.exception))
        self.assertEqual(d3.read_text(os.path.join(self.runs, "FAKE_h", "results.jsonl")), before)

    def test_resume_runs_only_the_alerts_that_are_not_done(self):
        self.run_main("--fake-model", "--run-name", "FAKE_i", "--limit", "2")
        # simulate an interruption: keep only the first result line
        path = os.path.join(self.runs, "FAKE_i", "results.jsonl")
        lines = d3.read_text(path).splitlines()
        with open(path, "w", encoding="utf-8") as f:
            f.write(lines[0] + "\n")
        self.run_main("--fake-model", "--resume", "--run-name", "FAKE_i")
        rs = self.results("FAKE_i")
        self.assertEqual([r["alert_id"] for r in rs], ["DEV-0004", "DEV-0003"])
        self.assertEqual([r["session"] for r in rs], [1, 2])
        self.assertEqual(len(self.meta("FAKE_i")["sessions"]), 2)
        self.assertEqual(self.meta("FAKE_i")["n_selected"], 2)

    def test_resume_with_nothing_to_do_changes_no_result(self):
        self.run_main("--fake-model", "--run-name", "FAKE_j", "--limit", "2")
        before = d3.read_text(os.path.join(self.runs, "FAKE_j", "results.jsonl"))
        self.run_main("--fake-model", "--resume", "--run-name", "FAKE_j")
        self.assertEqual(d3.read_text(os.path.join(self.runs, "FAKE_j", "results.jsonl")), before)

    def test_retry_model_errors_runs_again_only_those_alerts(self):
        frame = full_alerts_frame().copy()
        frame = pd.concat([frame] * 2).iloc[:6].copy()
        frame["alert_id"] = ["DEV-000" + str(i) for i in range(1, 7)]
        with mock.patch.object(base, "load_inputs", return_value=(frame, pd.DataFrame(), {"dev_alerts_sha256": "a", "flow_store_dev_sha256": "b"})):
            self.run_main("--fake-model", "--run-name", "FAKE_k")
            self.run_main("--fake-model", "--resume", "--run-name", "FAKE_k", "--retry-model-errors")
        rs = self.results("FAKE_k")
        self.assertEqual([r["alert_id"] for r in rs][-1], "DEV-0006")
        self.assertEqual(len(rs), 7)

    def test_resume_refuses_when_things_changed_or_the_run_is_missing(self):
        self.run_main("--fake-model", "--run-name", "FAKE_l", "--limit", "1")
        with self.assertRaises(SystemExit):
            self.run_main("--fake-model", "--resume", "--run-name", "FAKE_missing")
        with mock.patch.object(base, "check_llm_config", return_value={"small": "other-lite", "strong": "gemini-x"}):
            with self.assertRaises(SystemExit) as cm:
                self.run_main("--fake-model", "--resume", "--run-name", "FAKE_l")
        self.assertIn("differ from the run being resumed", str(cm.exception))
        with mock.patch.object(base, "load_inputs", return_value=(full_alerts_frame(), pd.DataFrame(), {"dev_alerts_sha256": "CHANGED", "flow_store_dev_sha256": "b"})):
            with self.assertRaises(SystemExit):
                self.run_main("--fake-model", "--resume", "--run-name", "FAKE_l")
        with mock.patch.object(S, "GRAPH_VERSION", "v9"):
            with self.assertRaises(SystemExit):
                self.run_main("--fake-model", "--resume", "--run-name", "FAKE_l")

    def test_fake_and_real_runs_cannot_be_mixed_up(self):
        self.run_main("--fake-model", "--run-name", "FAKE_m", "--limit", "1")
        self.write_baseline()
        with self.assertRaises(SystemExit):
            self.run_main("--resume", "--run-name", "FAKE_m")
        for argv in (["--fake-model", "--run-name", "real_name"], ["--run-name", "FAKE_x"]):
            with self.assertRaises(SystemExit):
                with mock.patch("sys.stderr"):
                    self.run_main(*argv)

    def test_argument_rules(self):
        for argv in (["--resume"], ["--limit", "0"], ["--rpm", "0"], ["--retry-model-errors"], ["--resume", "--run-name", "x", "--limit", "2"]):
            with self.assertRaises(SystemExit, msg=str(argv)):
                with mock.patch("sys.stderr"):
                    runner.parse_args(argv)
        self.assertEqual(runner.parse_args(["--fake-model"]).runs_dir, runner.FAKE_RUNS_ROOT)
        self.assertEqual(runner.parse_args([]).runs_dir, runner.RUNS_ROOT)
        self.assertNotEqual(runner.FAKE_RUNS_ROOT, runner.RUNS_ROOT)

    def test_the_frozen_unlock_variable_stops_the_run(self):
        with mock.patch.dict(os.environ, {config.FROZEN_UNLOCK_ENV: "1"}):
            with self.assertRaises(SystemExit):
                self.run_main("--fake-model", "--run-name", "FAKE_n")

    def test_dry_run_calls_no_model_and_writes_nothing(self):
        with mock.patch.object(runner, "FakeClient", side_effect=AssertionError("a client was built")):
            self.assertEqual(self.run_main("--fake-model", "--dry-run", "--limit", "1"), 0)
        self.assertFalse(os.path.exists(self.runs))

    def test_sleep_is_restored_after_a_fake_run(self):
        original = base.SLEEP
        self.run_main("--fake-model", "--run-name", "FAKE_o", "--limit", "1")
        self.assertIs(base.SLEEP, original)

    def test_the_meta_summary_counts_what_happened(self):
        self.run_main("--fake-model", "--run-name", "FAKE_p")
        m = self.meta("FAKE_p")
        self.assertEqual(m["counts"], {"ok": 3, "parse_failed": 1, "model_error": 0})
        self.assertEqual(m["agent"]["summary"]["graph_status_counts"], {"completed": 3, "completed_with_errors": 1})
        self.assertEqual(m["agent"]["summary"]["error_code_counts"], {"no_json": 1})
        self.assertTrue(m["frozen_access_log_unchanged"] and m["week1_files_unchanged"])
        self.assertEqual(m["status"], "complete")


class RealModeTests(RunnerBase):
    """The real-model code path with a scripted client in place of Gemini: no network, no key."""

    def setUp(self):
        super().setUp()
        self.client = Script()
        patches = [mock.patch.object(llm_config, "get_api_key", return_value="k"),
                   mock.patch.object(base, "make_client_for", side_effect=lambda *a, **k: self.client_wrapper())]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def client_wrapper(self):
        outer = self

        class C:
            def generate(self, prompt):
                text = outer.client(prompt)
                return gemini_client.CallRecord(text=text, finish_reason="STOP", block_reason=None, prompt_tokens=1, output_tokens=1, thinking_tokens=0, total_tokens=2)
        return C()

    def test_a_real_mode_run_is_held_equal_to_the_baseline_and_records_it(self):
        baseline = self.write_baseline()
        self.client.items = [reply()]
        self.assertEqual(self.run_main("--run-name", "dev_agent_t", "--limit", "2"), 0)
        m = self.meta("dev_agent_t")
        self.assertFalse(m["fake_model"])
        self.assertEqual(m["agent"]["baseline"], {"run_name": "dev_flash_lite_v3_final", "prompt_version": "baseline_v3", "prompt_sha256": BASELINE_V3_SHA, "model": baseline["model"],
                                                  "settings": {k: baseline["settings"][k] for k in runner.SETTING_KEYS}, "status": "complete"})
        self.assertEqual(m["settings"]["temperature"], llm_config.TEMPERATURE)
        self.assertEqual([r["status"] for r in self.results("dev_agent_t")], ["ok", "ok"])
        self.assertEqual(len(self.client.prompts), 2)

    def test_it_refuses_to_start_without_the_baseline_run(self):
        with self.assertRaises(SystemExit) as cm:
            self.run_main("--run-name", "dev_agent_u", "--limit", "1")
        self.assertIn("no run_meta.json", str(cm.exception))
        self.assertEqual(self.client.prompts, [])

    def test_it_refuses_a_baseline_that_is_not_baseline_v3_with_the_registered_hash(self):
        self.write_baseline(prompt_sha256="0" * 64)
        with self.assertRaises(SystemExit) as cm:
            self.run_main("--run-name", "dev_agent_v", "--limit", "1")
        self.assertIn("registered prompt hash", str(cm.exception))
        self.write_baseline("other", prompt_version="baseline_v2")
        with self.assertRaises(SystemExit):
            self.run_main("--baseline-run", "other", "--run-name", "dev_agent_w", "--limit", "1")

    def test_it_refuses_a_different_model_or_setting_than_the_baseline(self):
        self.write_baseline("m", model="gemini-other")
        with self.assertRaises(SystemExit) as cm:
            self.run_main("--baseline-run", "m", "--run-name", "dev_agent_x", "--limit", "1")
        self.assertIn("model", str(cm.exception))
        self.write_baseline("s", settings={"temperature": 0.7, "max_output_tokens": llm_config.MAX_OUTPUT_TOKENS, "seed": base.GENERATION_SEED, "parse_retries": llm_config.MAX_RETRIES})
        with self.assertRaises(SystemExit) as cm:
            self.run_main("--baseline-run", "s", "--run-name", "dev_agent_y", "--limit", "1")
        self.assertIn("temperature", str(cm.exception))
        self.assertFalse(os.path.exists(os.path.join(self.runs, "dev_agent_x")))

    def test_a_permanent_model_error_stops_the_run_and_keeps_finished_alerts(self):
        self.write_baseline()
        self.client.items = [reply(), gemini_client.PermanentModelError("API key not valid", 400)]
        code = self.run_main("--run-name", "dev_agent_z", "--limit", "3")
        self.assertEqual(code, 2)
        self.assertEqual([r["alert_id"] for r in self.results("dev_agent_z")], ["DEV-0004"])
        m = self.meta("dev_agent_z")
        self.assertEqual((m["status"], m["sessions"][-1]["ended_because"], m["not_run"]), ("incomplete", "permanent_error", 2))
        self.assertEqual(len(store.read_jsonl(os.path.join(self.runs, "dev_agent_z", "raw_responses.jsonl"))), 2)

    def test_five_model_call_failures_in_a_row_stop_the_run(self):
        self.write_baseline()
        frame = pd.concat([full_alerts_frame()] * 2).iloc[:7].copy()
        frame["alert_id"] = ["DEV-000" + str(i) for i in range(1, 8)]
        self.client.items = [gemini_client.TransientModelError("503", 503)]
        with mock.patch.object(base, "load_inputs", return_value=(frame, pd.DataFrame(), {"dev_alerts_sha256": "a", "flow_store_dev_sha256": "b"})), mock.patch.object(base, "SLEEP", lambda s: None):
            code = self.run_main("--run-name", "dev_agent_q")
        self.assertEqual(code, 2)
        self.assertEqual(len(self.results("dev_agent_q")), 5)
        self.assertTrue(all(r["error_code"] == "model_unavailable" for r in self.results("dev_agent_q")))
        self.assertEqual(self.meta("dev_agent_q")["sessions"][-1]["ended_because"], "stopped_after_model_errors")

    def test_graph_errors_do_not_count_toward_the_model_failure_stop_and_are_recorded(self):
        self.write_baseline()
        self.client.items = [reply()]
        with mock.patch.object(runner, "run_alert", side_effect=RuntimeError("boom")):
            code = self.run_main("--run-name", "dev_agent_r")
        self.assertEqual(code, 0)
        rs = self.results("dev_agent_r")
        self.assertEqual(len(rs), 4)
        self.assertTrue(all((r["status"], r["error_code"]) == ("model_error", "graph_error") for r in rs))
        self.assertIn("RuntimeError", rs[0]["error_detail"])
        self.assertEqual(rs[0]["graph_status"], "error")

    def test_a_graph_that_ends_before_the_verdict_step_is_a_graph_error_record_never_a_verdict(self):
        self.write_baseline()
        self.client.items = [reply()]
        state = dict(S.new_state(full_alert(), verdict_enabled=True), status="failed", trace=["supervisor", "traffic_analyst", "supervisor"])
        caller = mock.Mock(calls=[])
        record = runner.make_record("DEV-0004", state, caller, 1, 0.5, VP.get_prompt())
        self.assertEqual((record["status"], record["error_code"], record["verdict"], record["model_calls"]), ("model_error", "graph_error", None, 0))
        self.assertIn("failed", record["error_detail"])

    def test_the_api_key_is_never_written_to_the_run_folder(self):
        self.write_baseline()
        self.client.items = [reply()]
        with mock.patch.object(llm_config, "get_api_key", return_value="SECRET-KEY-VALUE"):
            self.run_main("--run-name", "dev_agent_s", "--limit", "1")
        for name in os.listdir(os.path.join(self.runs, "dev_agent_s")):
            self.assertNotIn("SECRET-KEY-VALUE", d3.read_text(os.path.join(self.runs, "dev_agent_s", name)))


# ------------------------------------------------------------------------------------------------ the comparison
def metric_block(coverage=1.0, parse_fail=0, attack=0.5):
    return {"population": {"alerts": 3},
            "reliability": {"successful_verdict_coverage": {"value": coverage}, "final_parse_failure": {"value": parse_fail, "numerator": 0}, "model_calls_total": 3, "model_calls_per_alert_mean": 1.0},
            "attack_type": {"on_attacks_with_valid_verdict": {"value": attack}}, "tokens": {"total_tokens": 300}}


def make_runs(tmp, **over):
    ids = ["DEV-0001", "DEV-0002", "DEV-0003"]
    prot = {"eval/dev_labels.parquet": "h1"}
    settings = {"temperature": 0.0, "max_output_tokens": 1024, "seed": 42, "parse_retries": 2, "timeout_seconds": 60, "transport_retries": 4, "requests_per_minute": 10.0}
    bm = {"run_name": "base", "set": "dev", "prompt_version": "baseline_v3", "prompt_sha256": BASELINE_V3_SHA, "model": "gemini-test", "provider": "gemini", "status": "complete", "settings": dict(settings),
          "inputs": {"dev_alerts_sha256": "a"}, "selected_alert_ids": ids, "frozen_access_log_unchanged": True, "week1_files_unchanged": True, "git": {"commit": "c1", "dirty": False}, "sessions": [{}]}
    am = dict(bm, run_name="agent", runner="run_agent_dev", fake_model=False, prompt_version="agent_v1", prompt_sha256=VP.prompt_sha256(), settings=dict(settings, requests_per_minute=8.0),
              agent={"summary": {"graph_status_counts": {"completed": 3}, "error_code_counts": {}, "path_counts": {"traffic_analyst>enrichment_agent>verdict_node": 3}, "tool_calls": 15, "graph_seconds_total": 1.5}})
    be = {"integrity": {"run_unchanged": True, "protected_unchanged": True, "frozen_log_unchanged": True}, "allow_partial": False, "protected_file_sha256": prot, "metrics": metric_block()}
    ae = dict(be, metrics=metric_block(attack=0.75))
    for key, value in over.items():
        target = {"bm": bm, "am": am, "be": be, "ae": ae}[key[:2]]
        target[key[3:]] = value
    paths = {}
    for name, meta, ev, root in (("base", bm, be, "base_runs"), ("agent", am, ae, "agent_runs")):
        os.makedirs(os.path.join(tmp, "eval", name), exist_ok=True)
        os.makedirs(os.path.join(tmp, root, name), exist_ok=True)
        store.write_json_atomic(os.path.join(tmp, "eval", name, "evaluation.json"), ev)
        store.write_json_atomic(os.path.join(tmp, root, name, "run_meta.json"), meta)
    return (os.path.join(tmp, "eval"), os.path.join(tmp, "base_runs"), os.path.join(tmp, "agent_runs"))


class CompareTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def load(self, **over):
        ev, br, ar = make_runs(self.tmp.name, **over)
        return compare.load_run("base", ev, br), compare.load_run("agent", ev, ar), (ev, br, ar)

    def problems(self, **over):
        b, a, _ = self.load(**over)
        return compare.check_pair(b, a)

    def test_matching_runs_have_no_problems(self):
        self.assertEqual(self.problems(), [])

    def test_each_kind_of_mismatch_is_refused(self):
        cases = {
            "am_fake_model": True, "am_runner": "run_baseline_dev", "am_status": "running", "bm_status": "incomplete", "am_set": "frozen",
            "am_model": "gemini-other", "am_provider": "other", "am_inputs": {"dev_alerts_sha256": "z"}, "am_selected_alert_ids": ["DEV-0001"],
            "bm_prompt_sha256": "0" * 64, "bm_prompt_version": "baseline_v2", "am_prompt_sha256": "0" * 64, "am_prompt_version": "baseline_v3",
            "am_frozen_access_log_unchanged": False, "bm_week1_files_unchanged": False,
            "ae_allow_partial": True, "be_allow_partial": True, "ae_protected_file_sha256": {"x": "y"},
            "ae_integrity": {"run_unchanged": True, "protected_unchanged": False, "frozen_log_unchanged": True},
        }
        for key, value in cases.items():
            self.assertTrue(self.problems(**{key: value}), key)

    def test_a_setting_difference_is_refused_but_the_request_rate_is_not(self):
        for key, value in (("temperature", 0.5), ("max_output_tokens", 512), ("seed", 7), ("parse_retries", 1)):
            settings = {"temperature": 0.0, "max_output_tokens": 1024, "seed": 42, "parse_retries": 2, "timeout_seconds": 60, "transport_retries": 4, "requests_per_minute": 8.0}
            settings[key] = value
            self.assertTrue(any(key in p for p in self.problems(am_settings=settings)), key)
        self.assertEqual(self.problems(), [])    # the fixture already has different rates

    def test_the_population_must_match_the_alert_list(self):
        self.assertTrue(self.problems(ae_metrics=dict(metric_block(), population={"alerts": 2})))

    def test_the_same_run_twice_is_refused(self):
        b, a, _ = self.load()
        self.assertIn("the same run was given twice", compare.check_pair(b, dict(b)))

    def test_missing_files_are_reported_with_the_fix(self):
        ev, br, ar = make_runs(self.tmp.name)
        with self.assertRaises(compare.ComparisonError) as cm:
            compare.load_run("nope", ev, br)
        self.assertIn("evaluate.py", str(cm.exception))

    def test_deltas_are_agent_minus_baseline_in_the_evaluators_numbers(self):
        b, a, _ = self.load()
        rows = {r["key"]: r for r in compare.metric_rows(b, a)}
        self.assertAlmostEqual(rows["attack_type_valid"]["agent_minus_baseline"], 0.25)
        self.assertEqual(rows["attack_type_valid"]["delta_display"], "+25.00 pp")
        self.assertEqual((rows["coverage"]["baseline_display"], rows["coverage"]["agent_display"], rows["coverage"]["delta_display"]), ("100.00%", "100.00%", "0.00 pp"))
        self.assertEqual(rows["mitre_valid"]["delta_display"], "n/a")
        self.assertEqual(rows["total_tokens"]["delta_display"], "0")

    def test_display_delta_units(self):
        self.assertEqual(compare.display_delta("frac", -0.0123), "-1.23 pp")
        self.assertEqual(compare.display_delta("count", 5.0), "+5")
        self.assertEqual(compare.display_delta("seconds", 1.5), "+1.500")
        self.assertEqual(compare.display_delta("number", None), "n/a")

    def test_the_report_names_both_runs_hashes_model_and_settings_and_does_not_judge(self):
        b, a, (ev, br, ar) = self.load()
        out = os.path.join(self.tmp.name, "out")
        compare.write_outputs(out, b, a, compare.metric_rows(b, a))
        text = d3.read_text(os.path.join(out, "COMPARISON_REPORT.md"))
        for needle in (BASELINE_V3_SHA, VP.prompt_sha256(), "gemini-test", "base", "agent", "agent_v1", "baseline_v3", "Agent minus baseline", "one run of each", "Requests per minute"):
            self.assertIn(needle, text)
        for word in ("improved", "improvement", "better", "worse", "outperform", "beats"):
            self.assertNotIn(word, text.lower())
        self.assertIn("traffic_analyst>enrichment_agent>verdict_node", text)
        data = json.loads(d3.read_text(os.path.join(out, "comparison.json")))
        self.assertEqual((data["labels_read"], data["model_called"], data["frozen_set_opened"]), (False, False, False))
        self.assertEqual(data["baseline"]["prompt_sha256"], BASELINE_V3_SHA)
        self.assertEqual(data["agent"]["prompt_sha256"], VP.prompt_sha256())
        self.assertEqual(sorted(os.listdir(out)), sorted(compare.OUTPUT_FILES))

    def test_outputs_are_never_overwritten_without_force(self):
        b, a, _ = self.load()
        out = os.path.join(self.tmp.name, "out")
        rows = compare.metric_rows(b, a)
        compare.write_outputs(out, b, a, rows)
        with self.assertRaises(compare.ComparisonError):
            compare.write_outputs(out, b, a, rows)
        compare.write_outputs(out, b, a, rows, force=True)

    def test_main_compares_and_refuses_cleanly(self):
        ev, br, ar = make_runs(self.tmp.name)
        out = os.path.join(self.tmp.name, "report")
        argv = ["--agent-run", "agent", "--baseline-run", "base", "--eval-root", ev, "--baseline-runs-root", br, "--agent-runs-root", ar, "--out-dir", out]
        with mock.patch("sys.stdout"):
            self.assertEqual(compare.main(argv), 0)
            self.assertEqual(compare.main(argv), 2)           # exists, no --force
            self.assertEqual(compare.main(argv + ["--force"]), 0)
        second = os.path.join(self.tmp.name, "second")
        os.makedirs(second)
        ev2, br2, ar2 = make_runs(second, am_fake_model=True)
        with mock.patch("sys.stdout"):
            self.assertEqual(compare.main(["--agent-run", "agent", "--baseline-run", "base", "--eval-root", ev2, "--baseline-runs-root", br2, "--agent-runs-root", ar2,
                                           "--out-dir", os.path.join(self.tmp.name, "r2")]), 2)
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "r2")))

    def test_a_fake_run_from_the_runner_is_never_comparable(self):
        b, a, _ = self.load(am_fake_model=True)
        self.assertTrue(any("fake" in p for p in compare.check_pair(b, a)))

    def test_default_names_and_paths(self):
        self.assertEqual(compare.DEFAULT_BASELINE_RUN, "dev_flash_lite_v3_final")
        self.assertEqual(os.path.basename(compare.EVAL_ROOT), "week2_eval")
        self.assertEqual(os.path.basename(compare.AGENT_RUNS_ROOT), "week3_agent_v1")
        self.assertEqual(runner.DEFAULT_BASELINE_RUN, compare.DEFAULT_BASELINE_RUN)


# ------------------------------------------------------------------------------------------------ boundaries
class BoundaryDay5Tests(unittest.TestCase):
    NEW_SCRIPTS = ("run_agent_dev.py", "compare_agent_vs_baseline.py")
    BANNED_MODULES = {"eval_io", "eval_labels", "evaluate", "eval_metrics", "urllib", "requests", "http", "socket"}

    def modules(self, path):
        tree = ast.parse(d3.read_text(path))
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                found.add((node.module or "").split(".")[0])
        return found, tree

    def test_the_new_scripts_do_not_import_label_evaluation_or_network_modules(self):
        for name in self.NEW_SCRIPTS:
            mods, _ = self.modules(os.path.join(ROOT, "src", name))
            self.assertEqual(mods & self.BANNED_MODULES, set(), name)

    def test_the_comparison_reads_no_per_alert_file_and_no_label_file(self):
        text = d3.read_text(os.path.join(ROOT, "src", "compare_agent_vs_baseline.py"))
        tree = ast.parse(text)
        strings = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        for needle in ("per_alert.csv", "dev_labels.parquet", "mitre_map.csv", "frozen"):
            self.assertFalse([s for s in strings if s == needle or s.endswith(needle) and "/" in s], needle)
        calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        self.assertNotIn("read_csv", calls)
        self.assertNotIn("read_parquet", calls)
        self.assertNotIn("load_labels", text.replace("labels_read", ""))

    def test_the_runner_reads_only_the_dev_set(self):
        text = d3.read_text(os.path.join(ROOT, "src", "run_agent_dev.py"))
        for word in ("load_labels", "frozen_alerts", "eval_io", "ReputationTool", "from_env", "load_alerts(\"frozen\")"):
            self.assertNotIn(word, text)
        self.assertIn("FlowStore.from_dev()", text)
        self.assertIn("build_registry(flow_store=store_)", text)

    def test_the_offline_day3_day4_runner_stays_llm_free(self):
        mods, _ = self.modules(os.path.join(ROOT, "src", "run_graph_dev.py"))
        for banned in ("gemini_client", "llm_config", "run_baseline_dev", "run_agent_dev", "google"):
            self.assertNotIn(banned, mods)
        text = d3.read_text(os.path.join(ROOT, "src", "run_graph_dev.py"))
        self.assertNotIn("verdict_enabled=True", text)
        self.assertNotIn("verdict_node", text)

    def test_the_tools_and_the_four_earlier_agents_do_not_know_about_the_verdict(self):
        for name in ("traffic_analyst.py", "c2_beacon_analyst.py", "enrichment_agent.py", "common.py"):
            text = d3.read_text(os.path.join(ROOT, "src", "agents", name))
            self.assertNotIn("verdict_node", text, name)
            self.assertNotIn("NODE_VERDICT", text, name)
        for name in os.listdir(os.path.join(ROOT, "src", "tools")):
            if name.endswith(".py"):
                self.assertNotIn("verdict_node", d3.read_text(os.path.join(ROOT, "src", "tools", name)), name)

    def test_no_reputation_tool_is_built_by_the_runner_or_the_graph(self):
        for path in (os.path.join(ROOT, "src", "run_agent_dev.py"), os.path.join(ROOT, "src", "agents", "graph.py")):
            self.assertNotIn("Reputation", d3.read_text(path))

    def test_the_verdict_schema_and_parser_are_the_week2_ones(self):
        import verdict_schema
        self.assertEqual(verdict_schema.FIELDS, ["is_malicious", "attack_type", "mitre_technique", "severity", "evidence"])
        self.assertIs(VN.verdict_parser, verdict_parser)

    def test_no_attack_class_to_technique_table_in_the_new_source(self):
        import re
        for path in (os.path.join(ROOT, "src", "agents", "verdict_node.py"), os.path.join(ROOT, "src", "agents", "verdict_prompt.py"), os.path.join(ROOT, "src", "compare_agent_vs_baseline.py")):
            text = d3.read_text(path)
            self.assertEqual([m for m in re.findall(r"T\d{4}(?:\.\d{3})?", text) if m not in ("T1498", "T1499", "T1059", "T1059.001")], [], path)
        runner_text = d3.read_text(os.path.join(ROOT, "src", "run_agent_dev.py"))
        self.assertEqual(sorted(set(re.findall(r"T\d{4}(?:\.\d{3})?", runner_text))), ["T1046"])    # the FAKE canned reply only

    def test_the_agent_tests_and_the_runner_use_no_real_model(self):
        # the runner builds a real client only through base.make_client_for, which the real-mode tests replace
        self.assertTrue(hasattr(base, "make_client_for"))
        self.assertEqual(gemini_client.GeminiClient.__init__.__code__.co_varnames[:2], ("self", "model"))


if __name__ == "__main__":
    unittest.main()
