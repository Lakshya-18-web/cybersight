"""Week 3 Day 6: the specialist-ablation switch, the arm runner flag, the offline audits, the ablation table, and the pinned current behaviour of timeouts and failures.

Offline. No model call, no network, no labels, no frozen set. Every model call is the runner's FakeClient or a scripted function. These tests prove plumbing and bookkeeping
(routing per arm, prompts per arm, run folders, audits, table arithmetic, refusals). They say nothing about how well any arm judges alerts; that needs the real dev runs.
This file only adds tests. No existing test was edited. Tests that need the LangGraph package are skipped when it is not installed.
"""
import os
import ast
import sys
import copy
import json
import hashlib
import shutil
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

import numpy as np
import pandas as pd

import config
import gemini_client
import baseline_store as store
import run_baseline_dev as base
import run_agent_dev as runner
import ablation_config as ablation
import week3_day6_audit as audit
import ablation_table as table
from agents import state as S
from agents import supervisor, traffic_analyst, c2_beacon_analyst, enrichment_agent, verdict_node as VN, verdict_prompt as VP, graph as graph_module
from tools import FlowStore, build_registry

from tests import test_week3_day1 as d1
from tests import test_week3_day3 as d3
from tests import test_week3_day5 as d5

HAVE_LANGGRAPH = d3.HAVE_LANGGRAPH
AGENT_V1_SHA = "8df5e3fee15280d6b409e2a1fd1d01a505cfbe449421d9dafa1f8a30ee99f4c7"   # the agent_v1 hash recorded by the Day 5 real run
DAY5_STATE_KEYS = ("alert_id", "alert", "status", "verdict_enabled", "next_node", "supervisor_visits", "routing", "evidence", "traffic_findings", "beacon_findings",
                   "enrichment_findings", "verdict", "errors", "trace", "graph_version")
T, B, E = S.NODE_TRAFFIC_ANALYST, S.NODE_C2_BEACON_ANALYST, S.NODE_ENRICHMENT_AGENT
DISABLED_TEXT = "disabled in this configuration"


def fake_verdict(state):
    """A stand-in verdict node: no model, no verdict content. Marks the step as done and ok."""
    return {"verdict": {"status": "ok", "verdict": None, "upstream": VN.upstream_health(state)}, "trace": list(state["trace"]) + [S.NODE_VERDICT]}


def drive_arm(registry, alert, disabled=(), verdict=True, limit=50):
    """Run the graph's edges by hand (no LangGraph): supervisor, then the routed node, until 'end'."""
    nodes = {S.NODE_TRAFFIC_ANALYST: traffic_analyst.make_traffic_analyst(registry), S.NODE_C2_BEACON_ANALYST: c2_beacon_analyst.make_c2_beacon_analyst(registry),
             S.NODE_ENRICHMENT_AGENT: enrichment_agent.make_enrichment_agent(registry), S.NODE_VERDICT: fake_verdict}
    sup = supervisor.make_supervisor_node(disabled)
    state = S.new_state(alert, verdict_enabled=verdict)
    steps = 0
    while True:
        steps += 1
        assert steps <= limit, "runaway loop"
        state = {**state, **sup(state)}
        route = supervisor.route_from_supervisor(state)
        if route == "end":
            return state
        state = {**state, **nodes[route](state)}


def path(state):
    return [n for n in state["trace"] if n != S.NODE_SUPERVISOR]


def alerts_under_test():
    return {"beacon": d5.full_alert(alert_id="T-B"),
            "scan": d5.full_alert(alert_id="T-S", src=d1.SCAN_SRC, dst=d1.SCAN_DST, dport=22, ts="2017-07-05 10:00:10"),
            "irregular": d5.full_alert(alert_id="T-I", src=d1.IRREG_SRC, dst=d1.IRREG_DST, dport=443, ts="2017-07-05 10:03:00"),
            "lone": d5.full_alert(alert_id="T-L", src="203.0.113.7", dst="203.0.113.8")}


def sha_file(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def folder_hashes(folder):
    out = {}
    for root, _, names in os.walk(folder):
        for name in names:
            out[os.path.relpath(os.path.join(root, name), folder)] = sha_file(os.path.join(root, name))
    return out


def printed(mock_print):
    return "\n".join(" ".join(str(a) for a in call.args) for call in mock_print.call_args_list)


# ------------------------------------------------------------------------------------------------ the configuration module
class AblationConfigTests(unittest.TestCase):
    def test_the_five_arms_are_fixed_as_pre_registered(self):
        self.assertEqual(list(ablation.ARMS), ["A", "B", "C", "D", "E"])
        self.assertEqual({k: v["disabled"] for k, v in ablation.ARMS.items()}, {"A": (), "B": (B,), "C": (E,), "D": (T,), "E": (T, B, E)})

    def test_the_text_shown_to_the_model_is_the_approved_wording(self):
        self.assertEqual(ablation.DISABLED_REASON, DISABLED_TEXT)

    def test_normalize_accepts_names_and_short_names_in_canonical_order(self):
        self.assertEqual(ablation.normalize(None), ())
        self.assertEqual(ablation.normalize([]), ())
        self.assertEqual(ablation.normalize(["enrichment", "traffic"]), (T, E))
        self.assertEqual(ablation.normalize((E, B, T)), (T, B, E))

    def test_normalize_refuses_anything_else(self):
        for bad in ("traffic_analyst", 5, [5], ["nope"], [S.NODE_VERDICT], [S.NODE_SUPERVISOR], [T, T], ["traffic", T]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ablation.normalize(bad)

    def test_arm_lookup_round_trips(self):
        for letter in ablation.ARMS:
            self.assertEqual(ablation.arm_for(ablation.arm_disabled(letter)), letter)
        self.assertIsNone(ablation.arm_for([T, B]))
        with self.assertRaises(ValueError):
            ablation.arm_disabled("Z")

    def test_the_traffic_to_beacon_dependency_is_written_down(self):
        self.assertEqual(ablation.cascade_skipped([T]), (B,))
        self.assertEqual(ablation.cascade_skipped([T, B]), ())
        self.assertEqual(ablation.cascade_skipped([B]), ())
        self.assertEqual(ablation.effective_specialists(()), (T, B, E))
        self.assertEqual(ablation.effective_specialists([T]), (E,))
        self.assertEqual(ablation.effective_specialists(ablation.arm_disabled("E")), ())
        self.assertIn("enrichment only", ablation.ARMS["D"]["label"])

    def test_describe_names_an_arm_or_says_custom(self):
        self.assertTrue(ablation.describe([B]).startswith("B: "))
        self.assertTrue(ablation.describe([T, B]).startswith("custom: "))


# ------------------------------------------------------------------------------------------------ the supervisor
class SupervisorAblationTests(d5.Offline):
    EXPECTED = {   # arm -> (path, supervisor visits) for an alert on which the beaconing gate opens
        "A": ([T, B, E, S.NODE_VERDICT], 5), "B": ([T, E, S.NODE_VERDICT], 4), "C": ([T, B, S.NODE_VERDICT], 4), "D": ([E, S.NODE_VERDICT], 3), "E": ([S.NODE_VERDICT], 2)}

    def test_the_beacon_fixture_really_opens_the_gate(self):
        self.assertEqual(path(drive_arm(self.registry, alerts_under_test()["beacon"], ())), self.EXPECTED["A"][0])

    def test_each_arm_takes_exactly_its_path(self):
        alert = alerts_under_test()["beacon"]
        for arm, (expected_path, visits) in self.EXPECTED.items():
            final = drive_arm(self.registry, alert, ablation.arm_disabled(arm))
            self.assertEqual(path(final), expected_path, arm)
            self.assertEqual(final["supervisor_visits"], visits, arm)

    def test_no_arm_ever_ends_in_error_or_a_failed_status_on_any_fixture_alert(self):
        for name, alert in alerts_under_test().items():
            for arm in ablation.ARMS:
                final = drive_arm(self.registry, alert, ablation.arm_disabled(arm))
                self.assertEqual((final["status"], final["errors"]), (S.STATUS_COMPLETED, []), name + " " + arm)
                self.assertLessEqual(final["supervisor_visits"], S.MAX_SUPERVISOR_VISITS)
                self.assertEqual(final["verdict"]["status"], "ok")
                S.validate_state(dict(final))

    def test_a_disabled_specialist_leaves_no_findings_and_no_evidence(self):
        alert = alerts_under_test()["beacon"]
        b = drive_arm(self.registry, alert, [B])
        self.assertIsNone(b["beacon_findings"])
        self.assertTrue(b["traffic_findings"] and b["enrichment_findings"])
        c = drive_arm(self.registry, alert, [E])
        self.assertIsNone(c["enrichment_findings"])
        d = drive_arm(self.registry, alert, [T])
        self.assertEqual((d["traffic_findings"], d["beacon_findings"]), (None, None))
        self.assertTrue(d["enrichment_findings"])
        e = drive_arm(self.registry, alert, ablation.arm_disabled("E"))
        self.assertEqual((e["traffic_findings"], e["beacon_findings"], e["enrichment_findings"], e["evidence"]), (None, None, None, []))

    def test_the_traffic_arm_cascades_to_beaconing_and_says_why(self):
        final = drive_arm(self.registry, alerts_under_test()["beacon"], [T])
        reasons = [r["reason"] for r in final["routing"]]
        self.assertTrue(any("C2 beaconing analyst skipped: the traffic analyst is disabled in this configuration" in r for r in reasons), reasons)
        self.assertNotIn(B, path(final))

    def test_only_the_routing_of_a_configured_run_carries_a_disabled_list(self):
        alert = alerts_under_test()["beacon"]
        for step in drive_arm(self.registry, alert, ())["routing"]:
            self.assertNotIn("disabled", step)
        for arm in "BCDE":
            off = list(ablation.arm_disabled(arm))
            steps = drive_arm(self.registry, alert, off)["routing"]
            self.assertTrue(steps and all(step["disabled"] == off for step in steps), arm)

    def test_the_default_is_exactly_the_day_5_graph(self):
        """With nothing disabled, the hand-driven run equals the Day 4 driver's run, and the default node is the factory's default."""
        for alert in alerts_under_test().values():
            old, _ = d3.drive(S.new_state(alert, verdict_enabled=False), traffic_analyst.make_traffic_analyst(self.registry), others=d3.all_nodes(self.registry))
            new = drive_arm(self.registry, alert, (), verdict=False)
            self.assertEqual(old, new)
        state = S.new_state(alerts_under_test()["beacon"], verdict_enabled=True)
        self.assertEqual(supervisor.supervisor_node(state), supervisor.make_supervisor_node(())(state))
        self.assertEqual(supervisor.decide(state), supervisor.decide(state, ()))

    def test_the_state_shape_is_unchanged(self):
        self.assertEqual(S.STATE_KEYS, DAY5_STATE_KEYS)
        self.assertEqual(S.MAX_SUPERVISOR_VISITS, 5)
        self.assertEqual(S.GRAPH_VERSION, "v0.1")

    def test_without_the_verdict_step_the_arms_end_cleanly(self):
        alert = alerts_under_test()["beacon"]
        e = drive_arm(self.registry, alert, ablation.arm_disabled("E"), verdict=False)
        self.assertEqual((path(e), e["status"], e["supervisor_visits"], e["verdict"]), ([], S.STATUS_COMPLETED, 1, None))
        d = drive_arm(self.registry, alert, [T], verdict=False)
        self.assertEqual((path(d), d["status"]), ([E], S.STATUS_COMPLETED))

    def test_decide_is_pure(self):
        state = S.new_state(alerts_under_test()["beacon"], verdict_enabled=True)
        before = copy.deepcopy(state)
        supervisor.decide(state, [T, B])
        self.assertEqual(state, before)

    def test_a_failing_specialist_is_still_handled_as_before_when_something_else_is_disabled(self):
        """Disabling the beaconing analyst must not change what a failed traffic analysis does: the verdict step still runs once, the graph ends failed."""
        failing = d3.FakeRegistry(lambda name, args, i: {"ok": False, "tool": name, "data": None, "error": {"code": "unavailable", "message": "no store"}})
        for off in ((), [B], [E]):
            final = drive_arm(failing, alerts_under_test()["beacon"], off)
            self.assertEqual(final["status"], S.STATUS_FAILED, off)
            self.assertEqual(path(final), [T, S.NODE_VERDICT], off)
            self.assertEqual(final["verdict"]["upstream"]["traffic"], "failed")

    def test_unknown_or_unsafe_configuration_is_refused(self):
        state = S.new_state(alerts_under_test()["beacon"])
        for bad in (["nope"], [S.NODE_VERDICT], [T, T], "traffic_analyst"):
            with self.assertRaises(ValueError):
                supervisor.decide(state, bad)
            with self.assertRaises(ValueError):
                supervisor.make_supervisor_node(bad)
            with self.assertRaises(ValueError):
                graph_module.build_graph(self.registry, disabled=bad)


# ------------------------------------------------------------------------------------------------ the prompt
class PromptAblationTests(d5.Offline):
    def payload(self, disabled, name="beacon"):
        final = drive_arm(self.registry, alerts_under_test()[name], disabled)
        return VP.findings_payload(final), final

    def test_the_agent_prompt_and_its_hash_are_unchanged(self):
        self.assertEqual(VP.prompt_sha256(), AGENT_V1_SHA)
        self.assertEqual(VP.get_prompt().sha256, AGENT_V1_SHA)

    def test_a_disabled_specialist_is_shown_as_not_run_with_the_approved_wording(self):
        a, _ = self.payload(())
        for arm, name in (("B", "c2_beacon_analyst"), ("C", "enrichment_agent"), ("D", "traffic_analyst")):
            p, _ = self.payload(ablation.arm_disabled(arm))
            self.assertEqual(p[name], {"status": "not_run", "reason": DISABLED_TEXT}, arm)
            for other in ("traffic_analyst", "c2_beacon_analyst", "enrichment_agent"):
                if other != name and not (arm == "D" and other == "c2_beacon_analyst") and not (arm in ("B", "D") and other == "enrichment_agent"):
                    self.assertEqual(p[other], a[other], arm + " " + other)

    def test_without_the_beacon_analyst_the_enrichment_agent_also_loses_its_mitre_reference_search(self):
        # Verified in the sandbox on synthetic data: enrichment_agent runs mitre_search only if beacon_findings.beacon_candidate is true,
        # so arm B (and arm D, where beaconing is skipped by cascade) removes the beacon findings AND the ATT&CK reference hits they trigger. The ablation table must say so.
        a, _ = self.payload(())
        b, _ = self.payload(ablation.arm_disabled("B"))
        self.assertTrue(any(f["kind"] == "mitre_search_hit" for f in a["enrichment_agent"]["findings"]))
        self.assertFalse(any(f["kind"].startswith("mitre") for f in b["enrichment_agent"]["findings"]))
        self.assertIn("mitre_search", [n["source"] for n in b["enrichment_agent"]["not_consulted"]])

    def test_the_traffic_arm_tells_the_model_why_beaconing_did_not_run(self):
        p, _ = self.payload([T])
        self.assertEqual(p["c2_beacon_analyst"]["status"], "not_run")
        self.assertTrue(p["c2_beacon_analyst"]["reason"].startswith("the traffic analyst is disabled in this configuration"), p["c2_beacon_analyst"])

    def test_the_none_arm_shows_all_three_as_disabled_and_nothing_else(self):
        p, final = self.payload(ablation.arm_disabled("E"))
        self.assertEqual(p, {"traffic_analyst": {"status": "not_run", "reason": DISABLED_TEXT}, "c2_beacon_analyst": {"status": "not_run", "reason": DISABLED_TEXT},
                             "enrichment_agent": {"status": "not_run", "reason": DISABLED_TEXT}, "errors": []})
        prompt = VP.build_user_prompt(final)
        self.assertIn('"alert"', prompt)
        self.assertEqual(prompt.count(DISABLED_TEXT), 3)

    def test_a_default_run_never_mentions_a_disabled_specialist_and_keeps_its_old_skip_text(self):
        p, final = self.payload((), "lone")
        self.assertNotIn(DISABLED_TEXT, VP.build_user_prompt(final))
        self.assertEqual(VP.disabled_agents(final), ())
        self.assertIn("flow(s) from the source to the destination in the traffic window (gate: at least 2)", p["c2_beacon_analyst"]["reason"])

    def test_upstream_health_says_disabled_only_in_a_configured_run(self):
        self.assertEqual(VN.upstream_health(drive_arm(self.registry, alerts_under_test()["lone"], ()))["beacon"], "not_run")
        up = VN.upstream_health(drive_arm(self.registry, alerts_under_test()["beacon"], ablation.arm_disabled("E")))
        self.assertEqual((up["traffic"], up["beacon"], up["enrichment"]), ("disabled", "disabled", "disabled"))
        up = VN.upstream_health(drive_arm(self.registry, alerts_under_test()["beacon"], [T]))
        self.assertEqual((up["traffic"], up["beacon"], up["enrichment"]), ("disabled", "not_run", "ok"))

    def test_every_arm_prompt_is_label_free_and_builds(self):
        for arm in ablation.ARMS:
            _, final = self.payload(ablation.arm_disabled(arm))
            prompt = VP.build_user_prompt(final)
            self.assertNotIn("is_attack", prompt)
            VP.check_alert(final["alert"])


@unittest.skipUnless(HAVE_LANGGRAPH, "LangGraph is not installed")
class GraphAblationTests(d5.Offline):
    def test_the_compiled_graph_takes_the_same_path_as_the_hand_driven_one_for_every_arm(self):
        for arm in ablation.ARMS:
            off = ablation.arm_disabled(arm)
            graph = graph_module.build_graph(self.registry, verdict_node=fake_verdict, disabled=off)
            for alert in alerts_under_test().values():
                final = graph_module.run_alert(graph, alert, verdict_enabled=True)
                hand = drive_arm(self.registry, alert, off)
                self.assertEqual((final["trace"], final["status"], final["routing"]), (hand["trace"], hand["status"], hand["routing"]), arm)

    def test_the_default_compiled_graph_is_unchanged(self):
        graph = graph_module.build_graph(self.registry, verdict_node=fake_verdict)
        final = graph_module.run_alert(graph, alerts_under_test()["beacon"], verdict_enabled=True)
        self.assertEqual(path(final), [T, B, E, S.NODE_VERDICT])


# ------------------------------------------------------------------------------------------------ the runner
class ArmRunnerTests(d5.RunnerBase):
    def test_arm_runs_default_to_the_day_6_folders_and_other_runs_keep_theirs(self):
        self.assertEqual(runner.parse_args(["--arm", "B"]).runs_dir, runner.DAY6_RUNS_ROOT)
        self.assertEqual(runner.parse_args(["--arm", "B", "--fake-model"]).runs_dir, runner.DAY6_FAKE_RUNS_ROOT)
        self.assertEqual(runner.parse_args([]).runs_dir, runner.RUNS_ROOT)
        self.assertEqual(runner.parse_args(["--fake-model"]).runs_dir, runner.FAKE_RUNS_ROOT)
        self.assertEqual(runner.parse_args(["--arm", "A", "--runs-dir", "x"]).runs_dir, "x")
        self.assertTrue(runner.DAY6_RUNS_ROOT.endswith(os.path.join("runs", "week3_day6")))
        self.assertTrue(runner.DAY6_FAKE_RUNS_ROOT.endswith(os.path.join("runs", "week3_day6_FAKE")))

    def test_an_unknown_arm_is_refused(self):
        with self.assertRaises(SystemExit):
            runner.parse_args(["--arm", "Z"])

    def test_every_arm_runs_end_to_end_with_the_fake_model_and_records_itself(self):
        expected = {"A": [T, B, E], "B": [T, E], "C": [T, B], "D": [E], "E": []}
        for arm in ablation.ARMS:
            name = "FAKE_arm_" + arm
            self.assertEqual(self.run_main("--fake-model", "--arm", arm, "--run-name", name), 0, arm)
            m = self.meta(name)
            record = m["agent"]["ablation"]
            off = list(ablation.arm_disabled(arm))
            self.assertEqual((record["arm"], record["disabled"], record["disabled_reason_shown_to_model"]), (arm, off, DISABLED_TEXT))
            self.assertEqual(record["enabled"], [n for n in (T, B, E) if n not in off])
            self.assertEqual(record["cascade_skipped"], [B] if arm == "D" else [])
            self.assertEqual(m["agent"]["specialists"], [n for n in (T, B, E) if n in ablation.effective_specialists(off)])
            self.assertEqual((m["prompt_sha256"], m["prompt_version"], m["fake_model"]), (AGENT_V1_SHA, "agent_v1", True))
            results = self.results(name)
            self.assertEqual(len(results), 4)
            self.assertTrue(all(r["agent_prompt_sha256"] == AGENT_V1_SHA for r in results))
            for r in results:
                ran = [n for n in r["trace"] if n not in (S.NODE_SUPERVISOR, S.NODE_VERDICT)]
                self.assertTrue(set(ran) <= set(expected[arm]), (arm, ran))
                if off:
                    self.assertTrue(all(step["disabled"] == off for step in r["routing"]))
                    for key, node in (("traffic", T), ("beacon", B), ("enrichment", E)):
                        if node in off:
                            self.assertEqual(r["upstream"][key], "disabled")
            if arm == "E":
                self.assertEqual(m["agent"]["summary"]["tool_calls"], 0)
                self.assertEqual(m["agent"]["summary"]["path_counts"], {"verdict_node": 4})

    def test_a_run_without_an_arm_keeps_the_day_5_format(self):
        self.run_main("--fake-model", "--run-name", "FAKE_plain")
        m = self.meta("FAKE_plain")
        self.assertNotIn("ablation", m["agent"])
        self.assertEqual(m["agent"]["specialists"], [T, B, E])
        for r in self.results("FAKE_plain"):
            self.assertTrue(all("disabled" not in step for step in r["routing"]))

    def test_the_arm_a_run_equals_the_plain_run_in_everything_but_the_ablation_record(self):
        self.run_main("--fake-model", "--run-name", "FAKE_plain2")
        self.run_main("--fake-model", "--arm", "A", "--run-name", "FAKE_armA2")
        for r1, r2 in zip(self.results("FAKE_plain2"), self.results("FAKE_armA2")):
            for key in ("alert_id", "status", "error_code", "prompt_sha256", "trace", "routing", "upstream", "tool_calls", "graph_errors", "attempts"):
                self.assertEqual(r1[key], r2[key], key)

    def test_the_prompt_snapshot_shows_the_arm(self):
        self.run_main("--fake-model", "--arm", "D", "--run-name", "FAKE_snap")
        text = d3.read_text(os.path.join(self.runs, "FAKE_snap", "prompt_snapshot.txt"))
        self.assertIn(DISABLED_TEXT, text)

    def test_a_dry_run_shows_the_arm_prompt_and_writes_nothing(self):
        with mock.patch("builtins.print") as pr:
            code = self.run_main("--dry-run", "--fake-model", "--arm", "D")
        out = printed(pr)
        self.assertEqual(code, 0)
        self.assertIn("Ablation arm D", out)
        self.assertIn("specialists that run: enrichment_agent", out)
        self.assertIn(DISABLED_TEXT, out)
        self.assertFalse(os.path.exists(self.runs))

    def test_a_run_is_resumed_only_with_its_own_arm(self):
        self.run_main("--fake-model", "--arm", "B", "--run-name", "FAKE_res")
        for args in (("--resume", "--run-name", "FAKE_res"), ("--resume", "--run-name", "FAKE_res", "--arm", "C")):
            with self.assertRaises(SystemExit) as cm:
                self.run_main("--fake-model", *args)
            self.assertIn("ablation arm", str(cm.exception))
        self.assertEqual(self.run_main("--fake-model", "--resume", "--run-name", "FAKE_res", "--arm", "B"), 0)
        self.run_main("--fake-model", "--run-name", "FAKE_res_plain")
        with self.assertRaises(SystemExit) as cm:
            self.run_main("--fake-model", "--resume", "--run-name", "FAKE_res_plain", "--arm", "A")
        self.assertIn("ablation arm None", str(cm.exception))

    def test_arm_runs_use_the_same_model_settings_and_hold_to_the_baseline_in_real_mode(self):
        self.write_baseline()
        built = []

        def stop_here(model, key, timeout, spec):
            built.append((model, timeout))
            raise RuntimeError("stop before any request")
        with mock.patch.object(base, "make_client_for", side_effect=stop_here), mock.patch.object(llm_module(), "get_api_key", return_value="k"):
            with self.assertRaises(RuntimeError):
                self.run_main("--arm", "B", "--run-name", "dev_agent_v1_d6_B_x", "--limit", "1")
        self.assertEqual(len(built), 1)
        self.assertEqual(built[0][1], 60)
        m = runner.ablation_record("B")
        self.assertEqual(m["label"], ablation.ARMS["B"]["label"])
        self.assertIsNone(runner.ablation_record(None))
        self.assertIsNone(runner.stored_arm({"agent": {}}))
        self.assertEqual(runner.stored_arm({"agent": {"ablation": m}}), "B")


def llm_module():
    import llm_config
    return llm_config


# ------------------------------------------------------------------------------------------------ the offline audits
class AuditTests(d5.RunnerBase):
    def audit(self, *args):
        lines = []
        code = audit.main(list(args), say=lambda *a: lines.append(" ".join(str(x) for x in a)))
        return code, "\n".join(lines)

    def fake_run(self, arm, name):
        self.run_main("--fake-model", "--arm", arm, "--run-name", name)
        return os.path.join(self.runs, name)

    def test_the_replay_passes_for_every_arm_and_counts_what_the_arm_allows(self):
        for arm in ablation.ARMS:
            code, out = self.audit("replay", "--arm", arm)
            self.assertEqual(code, 0, out)
            self.assertIn("ALL CHECKS PASSED", out)
        _, out = self.audit("replay", "--arm", "E")
        self.assertIn("tool_calls_total: 0", out)
        _, out = self.audit("replay", "--arm", "D")
        self.assertIn('"traffic": {"disabled": 4}', out)

    def test_the_replay_matches_a_fake_run_of_the_same_arm(self):
        for arm in ablation.ARMS:
            run = self.fake_run(arm, "FAKE_cmp_" + arm)
            code, out = self.audit("replay", "--arm", arm, "--compare-run", run)
            self.assertEqual(code, 0, out)
            self.assertIn("identical on every field: 4", out)

    def test_the_replay_notices_a_changed_prompt_trace_or_arm(self):
        run = self.fake_run("A", "FAKE_cmp_t")
        copy_dir = os.path.join(self.tmp.name, "tampered")
        shutil.copytree(run, copy_dir)
        rows = store.read_jsonl(os.path.join(copy_dir, "results.jsonl"))
        rows[0]["prompt_sha256"] = "0" * 64
        with open(os.path.join(copy_dir, "results.jsonl"), "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, sort_keys=True) + "\n")
        code, out = self.audit("replay", "--arm", "A", "--compare-run", copy_dir)
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)
        self.assertIn(rows[0]["alert_id"], out)
        code, out = self.audit("replay", "--arm", "B", "--compare-run", run)    # a different arm than the run was made with
        self.assertEqual(code, 1)

    def test_the_replay_flags_a_failing_tool_a_changing_prompt_and_odd_argument_types(self):
        failing = d3.FakeRegistry(lambda name, args, i: {"ok": False, "tool": name, "data": None, "error": {"code": "unavailable", "message": "no"}})
        with mock.patch.object(audit, "build_registry", return_value=failing):
            code, out = self.audit("replay", "--arm", "A", "--repeats", "1")
        self.assertEqual(code, 1)
        self.assertIn("FAIL  no tool call failed", out)
        counter = {"n": 0}
        real = VP.build_user_prompt

        def unstable(state, spec=None):
            counter["n"] += 1
            return real(state, spec) + " #" + str(counter["n"])
        with mock.patch.object(audit.verdict_prompt, "build_user_prompt", side_effect=unstable):
            code, out = self.audit("replay", "--arm", "A")
        self.assertEqual(code, 1)
        self.assertIn("FAIL  evidence, trace and verdict prompt are identical across replays", out)

    def test_non_native_argument_types_are_found(self):
        self.assertEqual(audit.non_native_types({"a": 1, "b": "x", "c": None, "d": [1, 2.5, True], "e": {"f": "g"}}), [])
        found = audit.non_native_types({"port": np.int64(80), "t": pd.Timestamp("2017-07-05"), "x": np.float64(1.5), "ok": 3})
        self.assertEqual(len(found), 3)
        self.assertTrue(any("port" in f and "int64" in f for f in found))

    def test_the_artifact_audit_passes_on_a_run_and_changes_nothing(self):
        run = self.fake_run("B", "FAKE_art")
        before = folder_hashes(run)
        code, out = self.audit("artifacts", "--run-dir", run)
        self.assertEqual(code, 0, out)
        self.assertIn("ALL CHECKS PASSED", out)
        self.assertEqual(folder_hashes(run), before)

    def test_the_artifact_audit_catches_each_kind_of_disagreement(self):
        run = self.fake_run("A", "FAKE_art2")

        def tampered(edit_results=None, edit_meta=None, edit_raw=None):
            target = os.path.join(self.tmp.name, "t" + str(len(os.listdir(self.tmp.name))))
            shutil.copytree(run, target)
            for fname, edit in (("results.jsonl", edit_results), ("raw_responses.jsonl", edit_raw)):
                if edit:
                    rows = store.read_jsonl(os.path.join(target, fname))
                    edit(rows)
                    with open(os.path.join(target, fname), "w", encoding="utf-8") as f:
                        for r in rows:
                            f.write(json.dumps(r, sort_keys=True) + "\n")
            if edit_meta:
                meta = store.read_json(os.path.join(target, "run_meta.json"))
                edit_meta(meta)
                store.write_json_atomic(os.path.join(target, "run_meta.json"), meta)
            return target

        cases = {
            "model calls": dict(edit_results=lambda rows: rows[0].__setitem__("model_calls", 9)),
            "tokens": dict(edit_results=lambda rows: rows[0].__setitem__("total_tokens", 99999)),
            "prompt hash": dict(edit_raw=lambda rows: rows[0].__setitem__("prompt", rows[0]["prompt"] + "x")),
            "status shape": dict(edit_results=lambda rows: rows[0].update({"status": "ok", "verdict": None, "error_code": None})),
            "meta tokens": dict(edit_meta=lambda m: m.__setitem__("total_tokens", 1)),
            "meta counts": dict(edit_meta=lambda m: m.__setitem__("counts", {"ok": 0, "parse_failed": 0, "model_error": 0})),
            "meta tool calls": dict(edit_meta=lambda m: m["agent"]["summary"].__setitem__("tool_calls", 1)),
        }
        for name, edits in cases.items():
            code, out = self.audit("artifacts", "--run-dir", tampered(**edits))
            self.assertEqual(code, 1, name + "\n" + out)

    def test_the_transport_tally_separates_timeouts_from_other_failures_and_estimates_requests(self):
        raw = [{"outcome": "reply", "transport_errors": [], "latency_seconds": 1.5},
               {"outcome": "reply", "transport_errors": [{"status": None, "message": "ReadTimeout: the read operation timed out"}], "latency_seconds": 62.0},
               {"outcome": "transport_failed", "latency_seconds": 61.0, "transport_errors": [{"status": 503, "message": "ServerError: unavailable"}, {"status": 429, "message": "ClientError: quota"},
                                                                                              {"status": 408, "message": "ClientError: request timeout"}, {"status": None, "message": "ConnectError: refused"},
                                                                                              {"status": None, "message": "ReadTimeout: again"}]},
               {"outcome": "permanent_error", "latency_seconds": 0.2, "transport_errors": [{"status": 400, "message": "ClientError: bad key"}]}]
        t = audit.transport_summary(raw)
        self.assertEqual((t["reply_calls"], t["failed_transport_attempts"], t["replies_that_needed_transport_retries"]), (2, 7, 1))
        self.assertEqual(t["estimated_requests_made"], 9)
        self.assertEqual(t["timeout_like_failed_attempts"], 3)    # two ReadTimeout and one 408
        self.assertEqual(t["failed_attempts_by_exception_class"]["ReadTimeout"], 2)
        self.assertEqual(t["failed_attempts_by_http_status"]["503"], 1)
        self.assertEqual(t["outcomes"], {"permanent_error": 1, "reply": 2, "transport_failed": 1})
        self.assertEqual(t["latency_seconds"]["max"], 62.0)

    def test_reports_are_written_only_to_a_new_folder(self):
        out_dir = os.path.join(self.tmp.name, "report")
        code, _ = self.audit("replay", "--arm", "C", "--out-dir", out_dir)
        self.assertEqual(code, 0)
        self.assertEqual(sorted(os.listdir(out_dir)), ["audit_replay_C.json", "audit_replay_C.txt"])
        data = json.loads(d3.read_text(os.path.join(out_dir, "audit_replay_C.json")))
        self.assertTrue(data["all_checks_passed"])
        with self.assertRaises(SystemExit):
            self.audit("replay", "--arm", "C", "--out-dir", out_dir)
        self.assertEqual(sorted(os.listdir(out_dir)), ["audit_replay_C.json", "audit_replay_C.txt"])

    def test_the_audits_refuse_when_the_frozen_unlock_is_set_and_bad_arguments(self):
        with mock.patch.dict(os.environ, {config.FROZEN_UNLOCK_ENV: "1"}):
            with self.assertRaises(SystemExit):
                self.audit("replay", "--arm", "A")
        for args in (("replay", "--arm", "Z"), ("replay", "--repeats", "0"), ("replay", "--limit", "0"), ("replay", "--compare-run", os.path.join(self.tmp.name, "nope")),
                     ("artifacts", "--run-dir", os.path.join(self.tmp.name, "nope")), ("artifacts",)):
            with self.assertRaises(SystemExit, msg=str(args)):
                self.audit(*args)

    def test_the_percentile_helper(self):
        self.assertIsNone(audit.percentile([], 0.95))
        self.assertEqual(audit.percentile([1, 2, 3, 4, 5], 0.5), 3)
        self.assertEqual(audit.percentile([7], 0.95), 7)


# ------------------------------------------------------------------------------------------------ the table
ATTACK_LABELS = ["PortScan"] * 5 + ["DoS Hulk"] * 5


def base_rows():
    """20 alerts: 0-9 attacks, 10-19 benign detector false positives. Every verdict correct, nothing missing."""
    rows = []
    for i in range(20):
        attack = i < 10
        rows.append({"alert_id": "DEV-" + str(i + 1).zfill(4), "label": ATTACK_LABELS[i] if attack else "BENIGN", "is_attack": attack, "has_verdict": True,
                     "pred_malicious": attack, "pred_attack_type": ATTACK_LABELS[i] if attack else "BENIGN", "status": "ok"})
    return rows


def with_changes(changes):
    rows = base_rows()
    for i, change in changes.items():
        rows[i].update(change)
        if change.get("has_verdict") is False:
            rows[i].update({"pred_malicious": None, "pred_attack_type": None, "status": "parse_failed"})
    return rows


MISS = {"pred_malicious": False, "pred_attack_type": "BENIGN"}
FALSE_POSITIVE = {"pred_malicious": True, "pred_attack_type": "PortScan"}
WRONG_TYPE = {"pred_attack_type": "Bot"}
NO_VERDICT = {"has_verdict": False}
REF_ROWS = lambda: with_changes({0: MISS, 3: WRONG_TYPE, 12: FALSE_POSITIVE})
B_ROWS = lambda: with_changes({1: MISS, 3: WRONG_TYPE, 7: NO_VERDICT, 12: FALSE_POSITIVE, 15: FALSE_POSITIVE})


def ratio(num, den):
    return {"value": (num / den) if den else None, "numerator": num, "denominator": den, "population": "x", "wilson95": None}


def view_block(rows, view):
    tp = fp = tn = fn = 0
    for r in rows:
        if r["has_verdict"]:
            pm = r["pred_malicious"]
        elif view == "valid_only":
            continue
        else:
            pm = True if view == "failures_escalated" else (not r["is_attack"])
        if r["is_attack"]:
            tp, fn = (tp + 1, fn) if pm else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if pm else (fp, tn + 1)
    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    f1 = 2 * precision["value"] * recall["value"] / (precision["value"] + recall["value"]) if precision["value"] and recall["value"] else 0.0
    benign = fp + tn
    return {"llm": {"precision": precision, "recall": recall, "specificity": ratio(tn, tn + fp), "f1": f1}, "llm_confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            "_fp_reduction": 100.0 * tn / benign if benign else None, "_missed": fn}


def evaluation_for(run_name, rows, prompt_sha=AGENT_V1_SHA, alerts=None, allow_partial=False, integrity=True):
    views = {v: view_block(rows, v) for v in table.VIEWS}
    fpr = {v: {"fp_reduction_pct": views[v].pop("_fp_reduction"), "attacks_missed_by_llm": views[v].pop("_missed")} for v in table.VIEWS}
    attacks = [r for r in rows if r["is_attack"]]
    valid_attacks = [r for r in attacks if r["has_verdict"]]
    correct = sum(1 for r in valid_attacks if r["pred_attack_type"] == r["label"])
    n = len(rows)
    ok = sum(1 for r in rows if r["has_verdict"])
    metrics = {"population": {"alerts": n if alerts is None else alerts, "ok": ok, "parse_failed": n - ok, "model_error": 0, "not_run": 0, "true_attacks": len(attacks), "true_benign": n - len(attacks)},
               "verdict": views, "fp_reduction": fpr,
               "attack_type": {"on_attacks_with_valid_verdict": ratio(correct, len(valid_attacks)), "all_attacks_failures_wrong": ratio(correct, len(attacks))},
               "mitre": {"accepted_on_attacks_with_valid_verdict": ratio(correct, len(valid_attacks)), "accepted_all_attacks_failures_wrong": ratio(correct, len(attacks))},
               "reliability": {"successful_verdict_coverage": ratio(ok, n), "final_parse_failure": ratio(n - ok, n), "first_try_malformed": ratio(0, n), "model_error": ratio(0, n),
                               "model_calls_total": n + (n - ok) * 2},
               "tokens": {"total_tokens": 1000 * n, "total_tokens_per_alert_mean": 1000.0}, "latency": {"per_alert_all_observations": {"mean": 1.5}}}
    return {"run": run_name, "run_meta": {"prompt_sha256": prompt_sha}, "integrity": {"run_unchanged": integrity, "protected_unchanged": True, "frozen_log_unchanged": True},
            "allow_partial": allow_partial, "metrics": metrics}


def write_run(tmp, label, run_name, disabled, rows, status="complete", fake=False, prompt_sha=AGENT_V1_SHA, model="gemini-test", n_selected=None, alerts_evaluated=None,
              with_per_alert=True, ablation_record=True, tool_calls=100, eval_run_name=None, settings=None):
    run_dir, eval_dir = os.path.join(tmp, "runs", run_name), os.path.join(tmp, "reports", run_name)
    os.makedirs(run_dir)
    os.makedirs(eval_dir)
    ids = [r["alert_id"] for r in base_rows()]
    agent = {"summary": {"tool_calls": tool_calls, "graph_seconds_total": 12.5, "path_counts": {"x": len(ids)}}, "specialists": list(ablation.effective_specialists(disabled))}
    if ablation_record:
        arm = ablation.arm_for(disabled)
        agent["ablation"] = {"arm": arm, "disabled": list(ablation.normalize(disabled))}
    meta = {"run_name": run_name, "status": status, "n_selected": len(ids) if n_selected is None else n_selected, "model": model, "prompt_version": "agent_v1", "prompt_sha256": prompt_sha,
            "settings": settings or {"temperature": 0.0, "max_output_tokens": 1024, "seed": 42, "parse_retries": 2, "timeout_seconds": 60, "transport_retries": 4, "requests_per_minute": 10.0},
            "inputs": {"dev_alerts_sha256": "a", "flow_store_dev_sha256": "b"}, "selected_alert_ids": ids, "fake_model": fake, "git": {"commit": "abc1234", "dirty": False}, "agent": agent}
    store.write_json_atomic(os.path.join(run_dir, "run_meta.json"), meta)
    store.write_json_atomic(os.path.join(eval_dir, "evaluation.json"), evaluation_for(eval_run_name or run_name, rows, prompt_sha, alerts_evaluated))
    if with_per_alert:
        frame = pd.DataFrame([{k: ("" if v is None else v) for k, v in r.items()} for r in rows])
        frame.to_csv(os.path.join(eval_dir, "per_alert.csv"), index=False)
    return [label, run_dir, eval_dir]


class TableTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = os.path.join(self.tmp.name, "out")

    def make(self, *specs):
        return [write_run(self.tmp.name, *spec[:4], **(spec[4] if len(spec) > 4 else {})) for spec in specs]

    def build(self, runs, reference="A rerun", extra=()):
        args = ["--out-dir", self.out, "--reference", reference]
        for r in runs:
            args += ["--run", *r]
        code = table.main(args + list(extra), say=lambda *a: None)
        self.assertEqual(code, 0)
        return json.loads(d3.read_text(os.path.join(self.out, "ablation_table.json"))), d3.read_text(os.path.join(self.out, "ablation_table.md"))

    def standard(self):
        return self.make(("A rerun", "run_A", [], REF_ROWS()), ("B", "run_B", [B], B_ROWS()))

    def test_cells_carry_their_sample_sizes_and_deltas_are_arm_minus_reference(self):
        data, md = self.build(self.standard())
        rows = {r["label"]: r for r in data["table"]["views"]["failures_wrong"]}
        self.assertEqual(rows["A rerun"]["cells"]["failures_wrong.recall"], {"value": 0.9, "num": 9, "den": 10})
        self.assertEqual(rows["B"]["cells"]["failures_wrong.recall"], {"value": 0.8, "num": 8, "den": 10})
        self.assertAlmostEqual(rows["B"]["deltas"]["failures_wrong.recall"], -10.0)
        self.assertAlmostEqual(rows["B"]["deltas"]["failures_wrong.precision"], -10.0)
        self.assertAlmostEqual(rows["B"]["deltas"]["failures_wrong.f1"], -0.1)
        self.assertIsNone(rows["A rerun"]["deltas"]["failures_wrong.recall"])
        self.assertIn("90.0% (9/10)", md)
        self.assertIn("80.0% (8/10)", md)
        self.assertIn("-10.0 pp", md)
        valid = {r["label"]: r for r in data["table"]["views"]["valid_only"]}
        self.assertEqual(valid["B"]["cells"]["valid_only.recall"]["den"], 9)    # one attack had no verdict and is left out of this view
        self.assertEqual(valid["B"]["cells"]["valid_only.recall"]["num"], 8)

    def test_other_metrics_use_only_what_the_files_hold(self):
        data, _ = self.build(self.standard())
        other = {r["label"]: r for r in data["table"]["other"]}
        self.assertEqual(other["B"]["cells"]["parse_failures"]["value"], 1)
        self.assertEqual(other["B"]["cells"]["tool_calls"]["value"], 100)
        self.assertEqual(other["B"]["cells"]["attack_type_all"], {"value": 0.7, "num": 7, "den": 10})
        self.assertEqual(other["A rerun"]["cells"]["attack_type_all"], {"value": 0.8, "num": 8, "den": 10})

    def test_a_missing_value_is_n_a_never_zero(self):
        runs = self.standard()
        path_b = os.path.join(runs[1][2], "evaluation.json")
        ev = json.loads(d3.read_text(path_b))
        del ev["metrics"]["tokens"]
        del ev["metrics"]["fp_reduction"]
        store.write_json_atomic(path_b, ev)
        data, md = self.build(runs)
        other = {r["label"]: r for r in data["table"]["other"]}
        self.assertIsNone(other["B"]["cells"]["total_tokens"])
        self.assertIsNone(other["B"]["deltas"]["total_tokens"])
        self.assertIn("n/a", md)

    def test_paired_counts_and_the_exact_test(self):
        data, _ = self.build(self.standard())
        p = data["paired"]["B"]
        self.assertEqual(p["alerts_compared"], 20)
        d = p["decision"]
        self.assertEqual((d["reference_only_correct"], d["arm_only_correct"], d["both_correct"], d["both_wrong"]), (3, 1, 15, 1))
        self.assertAlmostEqual(d["mcnemar_exact_p_descriptive"], 0.625)
        a = p["attack_type"]
        self.assertEqual((a["attacks"], a["reference_only_correct"], a["arm_only_correct"], a["both_wrong"]), (10, 2, 1, 1))
        self.assertAlmostEqual(a["mcnemar_exact_p_descriptive"], 1.0)

    def test_mcnemar_exact_values(self):
        self.assertEqual(table.mcnemar_exact(0, 0), 1.0)
        self.assertAlmostEqual(table.mcnemar_exact(5, 0), 0.0625)
        self.assertEqual(table.mcnemar_exact(3, 3), 1.0)
        self.assertAlmostEqual(table.mcnemar_exact(3, 1), table.mcnemar_exact(1, 3))
        self.assertLessEqual(table.mcnemar_exact(40, 2), 1e-6)

    def test_the_common_valid_set_drops_alerts_any_arm_could_not_answer(self):
        data, _ = self.build(self.standard())
        self.assertEqual(data["common_valid"]["alerts"], 19)
        rows = {r["label"]: r["metrics"] for r in data["common_valid"]["rows"]}
        self.assertEqual(rows["A rerun"]["attacks"], 9)
        self.assertEqual(rows["B"]["alerts"], 19)
        self.assertEqual(rows["B"]["recall"]["den"], 9)

    def test_incomplete_not_comparable_fake_and_mismatched_runs_are_listed_and_never_in_a_difference(self):
        runs = self.make(("A rerun", "run_A", [], REF_ROWS()), ("B", "run_B", [B], B_ROWS()),
                         ("C partial", "run_C", [E], B_ROWS()[:12], {"status": "incomplete", "n_selected": 20, "alerts_evaluated": 12}),
                         ("D other prompt", "run_D", [T], B_ROWS(), {"prompt_sha": "0" * 64}),
                         ("E fake", "run_E", ablation.arm_disabled("E"), B_ROWS(), {"fake": True}),
                         ("A other settings", "run_A2", [], REF_ROWS(), {"settings": {"temperature": 0.7, "max_output_tokens": 1024, "seed": 42, "parse_retries": 2, "timeout_seconds": 60, "transport_retries": 4}}),
                         ("A wrong eval", "run_A3", [], REF_ROWS(), {"eval_run_name": "something_else"}))
        data, md = self.build(runs)
        self.assertEqual(data["used"], ["A rerun", "B"])
        excluded = {e["label"]: e for e in data["excluded"]}
        self.assertEqual(set(excluded), {"C partial", "D other prompt", "E fake", "A other settings", "A wrong eval"})
        self.assertTrue(any("incomplete" in r for r in excluded["C partial"]["incomplete_reasons"]))
        self.assertTrue(any("12 of 20" in r for r in excluded["C partial"]["incomplete_reasons"]))
        self.assertTrue(any("prompt_sha256" in d for d in excluded["D other prompt"]["differences"]))
        self.assertTrue(any("fake" in p for p in excluded["E fake"]["problems"]))
        self.assertTrue(any("settings" in d for d in excluded["A other settings"]["differences"]))
        self.assertTrue(any("evaluation is for run" in p for p in excluded["A wrong eval"]["problems"]))
        labels_in_tables = {r["label"] for r in data["table"]["other"]}
        self.assertEqual(labels_in_tables, {"A rerun", "B"})
        self.assertIn("Runs not in the tables", md)
        self.assertIn("**C partial**", md)

    def test_an_unusable_reference_stops_the_table_and_writes_nothing(self):
        runs = self.make(("A rerun", "run_A", [], REF_ROWS(), {"status": "incomplete"}), ("B", "run_B", [B], B_ROWS()))
        with self.assertRaises(SystemExit):
            self.build(runs)
        self.assertFalse(os.path.exists(self.out))

    def test_arguments_are_checked_and_an_existing_report_is_never_overwritten(self):
        runs = self.standard()
        os.makedirs(self.out)
        with self.assertRaises(SystemExit):
            table.main(["--out-dir", self.out, "--reference", "A rerun", "--run", *runs[0]], say=lambda *a: None)
        shutil.rmtree(self.out)
        with self.assertRaises(SystemExit):
            table.main(["--out-dir", self.out, "--reference", "nope", "--run", *runs[0]], say=lambda *a: None)
        with self.assertRaises(SystemExit):
            table.main(["--out-dir", self.out, "--reference", "A rerun", "--run", *runs[0], "--run", *runs[0]], say=lambda *a: None)
        self.assertFalse(os.path.exists(self.out))

    def test_without_per_alert_csv_the_table_still_builds_and_says_so(self):
        runs = self.make(("A rerun", "run_A", [], REF_ROWS(), {"with_per_alert": False}), ("B", "run_B", [B], B_ROWS()))
        data, md = self.build(runs)
        self.assertEqual(data["paired"], {})
        self.assertTrue(any("no per_alert.csv" in n for n in data["paired_notes"]))
        self.assertEqual(data["common_valid"]["rows"][0]["label"], "B")

    def test_repeat_observations_of_the_same_arm_give_a_gap(self):
        runs = self.make(("A rerun", "run_A", [], REF_ROWS()), ("A Day 5", "run_A5", [], with_changes({0: MISS, 3: WRONG_TYPE, 12: FALSE_POSITIVE, 4: MISS}), {"ablation_record": False}),
                         ("B", "run_B", [B], B_ROWS()))
        data, md = self.build(runs)
        info = data["repeats"]["A"]
        self.assertEqual(info["labels"], ["A rerun", "A Day 5"])
        self.assertAlmostEqual(info["gaps"]["failures_wrong.recall"]["range"], 0.1)
        self.assertEqual(info["gaps"]["failures_wrong.recall"]["n_observations"], 2)
        self.assertIn("pre-Day-6 full-graph run", md)
        self.assertIn("gap, not a spread estimate", md)

    def test_the_baseline_spread_is_shown_as_a_yardstick_only(self):
        summary = {"runs": ["r1", "r2", "r3"], "prompt_version": "baseline_v3", "n_alerts": 300,
                   "headline": [{"key": "f1_valid_only", "label": "F1 [valid_only]", "unit": "number", "mean": 0.9268, "min": 0.9246, "max": 0.928, "range": 0.0034, "n_present": 3},
                                {"key": "recall_valid_only", "label": "Recall [valid_only]", "unit": "frac", "mean": 0.9587, "min": 0.9583, "max": 0.9590, "range": 0.00064, "n_present": 3},
                                {"key": "not_wanted", "label": "x", "unit": "count", "mean": 1, "min": 1, "max": 1, "range": 0, "n_present": 3}]}
        path = os.path.join(self.tmp.name, "three_run_summary.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(summary, f)
        data, md = self.build(self.standard(), extra=["--baseline-summary", path])
        self.assertEqual(sorted(data["baseline_noise"]["rows"]), ["f1_valid_only", "recall_valid_only"])
        self.assertIn("A different prompt", md)
        self.assertIn("F1 [valid_only]", md)

    def test_the_report_states_its_limits_and_pre_registration(self):
        _, md = self.build(self.standard())
        for needle in ("descriptive", "Day 7 locks the full graph", "disabled in this configuration", "enrichment only", "not significance claims", "Dev set only"):
            self.assertIn(needle, md)

    def test_the_table_changes_none_of_its_inputs(self):
        runs = self.standard()
        before = {r[0]: (folder_hashes(r[1]), folder_hashes(r[2])) for r in runs}
        self.build(runs)
        self.assertEqual({r[0]: (folder_hashes(r[1]), folder_hashes(r[2])) for r in runs}, before)

    def test_formatting_helpers(self):
        self.assertEqual(table.fmt({"value": 0.9, "num": 9, "den": 10}, "frac"), "90.0% (9/10)")
        self.assertEqual(table.fmt(None, "frac"), "n/a")
        self.assertEqual(table.fmt_diff(-10.0, "frac"), "-10.0 pp")
        self.assertEqual(table.fmt_diff(0, "count"), "0")
        self.assertEqual(table.fmt_diff(1500, "count"), "+1,500")
        self.assertEqual(table.fmt_diff(None, "count"), "n/a")
        self.assertAlmostEqual(table.diff_value({"value": 0.5}, {"value": 0.25}, "frac"), 25.0)
        self.assertIsNone(table.diff_value(None, {"value": 1}, "count"))


# ------------------------------------------------------------------------------------------------ pinned current behaviour of timeouts and failures
class FailureBehaviourTests(d5.RunnerBase):
    """Day 6 asked first for an audit and tests of what happens today. These tests PIN the current behaviour; they do not propose changes."""

    def caller(self, client, sleeps):
        run_dir = store.RunDir(os.path.join(self.tmp.name, "calls" + str(len(os.listdir(self.tmp.name)))))
        os.makedirs(run_dir.path)
        clock = {"t": 0.0}
        patches = [mock.patch.object(base, "SLEEP", side_effect=lambda s: (sleeps.append(s), clock.__setitem__("t", clock["t"] + s))), mock.patch.object(base, "CLOCK", side_effect=lambda: clock["t"])]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        c = base.RecordingCaller(client, base.Throttle(100000.0), run_dir, 1, "gemini-test")
        c.start("DEV-X")
        return c, run_dir

    class Client:
        def __init__(self, *items):
            self.items, self.calls = list(items), 0

        def generate(self, prompt):
            self.calls += 1
            item = self.items.pop(0) if self.items else self.items_default
            if isinstance(item, BaseException):
                raise item
            return gemini_client.CallRecord(text=item, finish_reason="STOP", block_reason=None, prompt_tokens=1, output_tokens=1, thinking_tokens=0, total_tokens=2)

    def test_a_call_that_keeps_timing_out_makes_five_requests_waits_sixty_seconds_in_backoff_and_ends_unavailable(self):
        client = self.Client()
        client.items_default = gemini_client.TransientModelError("ReadTimeout: the read operation timed out", None)
        sleeps = []
        caller, run_dir = self.caller(client, sleeps)
        with self.assertRaises(base.ModelUnavailable) as cm:
            caller("prompt")
        self.assertEqual(client.calls, base.TRANSPORT_RETRIES + 1)
        self.assertEqual(sleeps, [4, 8, 16, 32])
        self.assertIn("failed 5 times", str(cm.exception))
        self.assertEqual(caller.calls, [])    # only replies are counted as model calls
        raw = store.read_jsonl(run_dir.raw)
        self.assertEqual(len(raw), 1)
        self.assertEqual((raw[0]["outcome"], len(raw[0]["transport_errors"]), raw[0]["reply"]), ("transport_failed", 5, None))

    def test_the_worst_case_per_call_is_bounded_by_the_constants(self):
        timeout = base.settings_for("m", 10.0)["timeout_seconds"]
        worst_call = (base.TRANSPORT_RETRIES + 1) * timeout + sum(base.BACKOFF_SECONDS[:base.TRANSPORT_RETRIES])
        self.assertEqual((timeout, base.TRANSPORT_RETRIES, base.BACKOFF_SECONDS, worst_call), (60, 4, [4, 8, 16, 32], 360))
        self.assertEqual(base.MAX_CONSECUTIVE_MODEL_ERRORS, 5)

    def test_a_transport_failure_that_recovers_counts_one_model_call_but_two_requests(self):
        client = self.Client(gemini_client.TransientModelError("ServerError: 503", 503), "{}")
        client.items_default = "{}"
        sleeps = []
        caller, run_dir = self.caller(client, sleeps)
        self.assertEqual(caller("prompt"), "{}")
        self.assertEqual((client.calls, len(caller.calls), sleeps), (2, 1, [4]))
        raw = store.read_jsonl(run_dir.raw)
        self.assertEqual((raw[0]["outcome"], len(raw[0]["transport_errors"])), ("reply", 1))
        t = audit.transport_summary(raw)
        self.assertEqual((t["reply_calls"], t["estimated_requests_made"]), (1, 2))

    def test_a_permanent_error_is_not_retried_and_is_recorded(self):
        client = self.Client()
        client.items_default = gemini_client.PermanentModelError("ClientError: API key not valid", 400)
        sleeps = []
        caller, run_dir = self.caller(client, sleeps)
        with self.assertRaises(gemini_client.PermanentModelError):
            caller("prompt")
        self.assertEqual((client.calls, sleeps), (1, []))
        self.assertEqual(store.read_jsonl(run_dir.raw)[0]["outcome"], "permanent_error")

    def test_a_timeout_and_a_server_error_both_end_as_model_unavailable_and_differ_only_in_the_detail_text(self):
        results = {}
        for kind, error in (("timeout", gemini_client.TransientModelError("ReadTimeout: the read operation timed out", None)), ("server", gemini_client.TransientModelError("ServerError: 503 unavailable", 503))):
            client = self.Client()
            client.items_default = error
            caller, _ = self.caller(client, [])
            node = VN.make_verdict_node(caller, max_retries=2, fatal=(gemini_client.PermanentModelError,), unavailable=(base.ModelUnavailable,))
            update = node(self.state_for_verdict())
            results[kind] = update["verdict"]
        self.assertEqual({k: (v["status"], v["error_code"], v["verdict"], v["attempts"]) for k, v in results.items()},
                         {"timeout": ("model_error", "model_unavailable", None, 0), "server": ("model_error", "model_unavailable", None, 0)})
        self.assertIn("ReadTimeout", results["timeout"]["error_detail"])
        self.assertIn("ServerError", results["server"]["error_detail"])

    def state_for_verdict(self):
        final = drive_arm(self.registry, alerts_under_test()["beacon"], (), verdict=True)
        return dict(final, verdict=None, trace=[n for n in final["trace"] if n != S.NODE_VERDICT], status=S.STATUS_RUNNING)

    def test_a_tool_that_raises_inside_a_specialist_never_escapes_and_the_model_is_told_the_evidence_failed(self):
        def boom(name, args, i):
            raise RuntimeError("tool exploded")
        failing = d3.FakeRegistry(boom)
        final = drive_arm(failing, alerts_under_test()["beacon"], ())
        self.assertEqual(final["verdict"]["status"], "ok")
        self.assertIn(final["status"], (S.STATUS_FAILED, S.STATUS_COMPLETED_WITH_ERRORS))
        self.assertTrue(final["errors"])
        self.assertTrue(all(e["code"] in ("tool_exception", "no_findings", "unavailable") or e["node"] for e in final["errors"]))
        prompt = VP.build_user_prompt(final)
        self.assertIn("failed", prompt)
        self.assertNotIn("tool exploded", prompt)    # only the exception type is kept

    def test_a_tool_that_answers_with_something_that_is_not_an_envelope_is_caught_by_the_node_guard_not_turned_into_evidence(self):
        junk = d3.FakeRegistry(lambda name, args, i: "not a dict")
        final = drive_arm(junk, alerts_under_test()["beacon"], ())
        self.assertTrue(final["errors"])
        self.assertEqual([e["code"] for e in final["errors"] if e["node"] == S.NODE_TRAFFIC_ANALYST][:1], ["node_exception"])    # current behaviour: the node guard catches it; "invalid_tool_result" is not raised for a non-dict
        self.assertEqual(final["traffic_findings"]["status"], "failed")

    def test_alert_ports_given_as_floats_or_numpy_integers_reach_the_tools_as_plain_integers(self):
        for port in (80, 80.0, np.int64(80), np.float64(80.0)):
            alert = d5.full_alert(alert_id="T-P", dport=port)
            beacon_calls = c2_beacon_analyst.plan_calls(alert)
            self.assertEqual(beacon_calls[1][1]["dst_port"], 80)
            self.assertIs(type(beacon_calls[1][1]["dst_port"]), int, repr(port))
            recording = d3.FakeRegistry(lambda name, args, i: {"ok": True, "tool": name, "data": {"services": []}, "error": None})
            state = dict(S.new_state(alert), traffic_findings={"status": "ok", "findings": []})
            enrichment_agent.make_enrichment_agent(recording)(state)
            port_calls = [args for name, args in recording.calls if name == "port_info"]
            self.assertEqual(port_calls[0]["port"], 80)
            self.assertIs(type(port_calls[0]["port"]), int, repr(port))

    def test_a_float_port_runs_through_the_real_tools_without_a_single_failed_call(self):
        final = drive_arm(self.registry, d5.full_alert(alert_id="T-F", dport=80.0), ())
        self.assertTrue(all(e["ok"] for e in final["evidence"]), [e for e in final["evidence"] if not e["ok"]])
        self.assertEqual(final["errors"], [])

    def test_a_port_that_is_not_a_whole_number_is_passed_through_and_refused_by_the_tool_without_raising(self):
        final = drive_arm(self.registry, d5.full_alert(alert_id="T-H", dport=80.5), ())
        failed = [e for e in final["evidence"] if not e["ok"]]
        self.assertTrue(failed)
        self.assertTrue(all(e["tool"] in ("port_info", "beacon_stats") for e in failed))
        self.assertEqual(final["verdict"]["status"], "ok")


# ------------------------------------------------------------------------------------------------ boundaries
class BoundaryDay6Tests(unittest.TestCase):
    NEW = ("ablation_config.py", "week3_day6_audit.py", "ablation_table.py")
    BANNED = {"eval_io", "eval_labels", "evaluate", "eval_metrics", "urllib", "requests", "http", "socket", "google", "langsmith"}
    NEEDLES = ("dev_labels", "frozen_labels", "frozen_alerts", "labels.parquet", "mitre_map", "eval_labels", "load_labels", "eval_io", "read_parquet", "ReputationTool")

    def imports(self, name):
        tree = ast.parse(d3.read_text(os.path.join(ROOT, "src", name)))
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                found.add((node.module or "").split(".")[0])
        return found

    def test_the_new_modules_import_no_label_evaluation_or_network_module(self):
        for name in self.NEW:
            self.assertEqual(self.imports(name) & self.BANNED, set(), name)

    def test_the_new_modules_name_no_label_file_and_load_no_parquet(self):
        for name in self.NEW:
            text = d3.read_text(os.path.join(ROOT, "src", name))
            for needle in self.NEEDLES:
                self.assertNotIn(needle, text, name + " " + needle)

    def test_the_table_reads_only_json_and_the_harness_per_alert_csv(self):
        tree = ast.parse(d3.read_text(os.path.join(ROOT, "src", "ablation_table.py")))
        calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        self.assertEqual(calls & {"read_parquet", "read_excel", "read_pickle", "read_feather"}, set())
        file_names = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and " " not in n.value and n.value.endswith((".json", ".csv", ".parquet"))}
        self.assertTrue(file_names <= {"run_meta.json", "evaluation.json", "per_alert.csv", "ablation_table.json"}, file_names)

    def test_the_ablation_module_depends_only_on_the_agent_state_and_the_agents_know_nothing_else_about_it(self):
        self.assertEqual(self.imports("ablation_config.py"), {"agents"})
        for name in ("supervisor.py", "graph.py", "verdict_prompt.py"):
            text = d3.read_text(os.path.join(ROOT, "src", "agents", name))
            self.assertIn("import ablation_config as ablation", text)
        for name in ("traffic_analyst.py", "c2_beacon_analyst.py", "enrichment_agent.py", "common.py", "state.py", "verdict_node.py"):
            self.assertNotIn("ablation", d3.read_text(os.path.join(ROOT, "src", "agents", name)).replace("Day 6 ablation arm", ""), name)

    def test_the_agents_package_still_holds_exactly_its_day_5_files(self):
        names = sorted(n for n in os.listdir(os.path.join(ROOT, "src", "agents")) if n.endswith(".py"))
        self.assertEqual(names, ["__init__.py", "c2_beacon_analyst.py", "common.py", "enrichment_agent.py", "graph.py", "state.py", "supervisor.py", "traffic_analyst.py", "verdict_node.py", "verdict_prompt.py"])

    def test_the_audit_and_the_table_make_no_model_call_and_build_no_client(self):
        for name in ("week3_day6_audit.py", "ablation_table.py"):
            text = d3.read_text(os.path.join(ROOT, "src", name))
            for word in ("make_client", "GeminiClient", "get_api_key", "generate(", "genai"):
                self.assertNotIn(word, text, name + " " + word)

    def test_the_runner_still_reads_only_the_dev_set_and_adds_no_technique_table(self):
        text = d3.read_text(os.path.join(ROOT, "src", "run_agent_dev.py"))
        for word in ("load_labels", "frozen_alerts", "eval_io", "ReputationTool"):
            self.assertNotIn(word, text)
        import re
        self.assertEqual(sorted(set(re.findall(r"T\d{4}(?:\.\d{3})?", text))), ["T1046"])


if __name__ == "__main__":
    unittest.main()
