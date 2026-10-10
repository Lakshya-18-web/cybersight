"""Week 3 Day 3: graph v0 (shared state, deterministic supervisor, one traffic analyst). Offline: no LLM, no network, no labels, no frozen set.

Tests that need the real LangGraph package are skipped when it is not installed (install with pip install -r requirements-week3.txt).
Everything else, including a loop-guard simulation that drives the nodes by hand, runs without it.
"""
import os
import ast
import sys
import copy
import json
import tempfile
import unittest
import importlib.util
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

import pandas as pd

import triage_inputs
from agents import state as S
from agents import supervisor, traffic_analyst, graph as graph_module
from tools import FlowStore, build_registry
from tools.base import error_result

import run_graph_dev
from tests import test_week3_day1 as d1

HAVE_LANGGRAPH = importlib.util.find_spec("langgraph") is not None
AGENTS_DIR = os.path.join(ROOT, "src", "agents")
ALERT_TIME = "2017-07-05 10:05:00"


def read_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def all_nodes(registry):
    """The Day 4 agents, for hand-driven runs: traffic analyst first argument of drive, the other two in `others`."""
    from agents import c2_beacon_analyst, enrichment_agent
    return {S.NODE_C2_BEACON_ANALYST: c2_beacon_analyst.make_c2_beacon_analyst(registry), S.NODE_ENRICHMENT_AGENT: enrichment_agent.make_enrichment_agent(registry)}


def make_alert(alert_id="T-1", src=d1.BEACON_SRC, dst=d1.BEACON_DST, ts=ALERT_TIME, dport=80, **extra):
    alert = {"alert_id": alert_id, "flow_id": "x-" + str(alert_id), "timestamp": ts, "src_ip": src, "src_port": 40000, "dst_ip": dst, "dst_port": dport, "protocol": 6, "detector_score": 0.99}
    alert.update(extra)
    return alert


class FakeRegistry:
    """A registry stand-in that answers from a function, so tool failures can be scripted."""

    def __init__(self, answer):
        self.answer, self.calls = answer, []

    def call(self, name, arguments=None):
        self.calls.append((name, copy.deepcopy(arguments)))
        return self.answer(name, arguments, len(self.calls) - 1)


def summary(n=3, dest_ips=1, dest_ports=2, sources=1, top_port=80, top_flows=2):
    return {"n_flows": n, "distinct_destination_ips": dest_ips, "distinct_destination_ports": dest_ports, "distinct_source_ips": sources, "protocol_counts": {"6": n},
            "top_destination_ports": [{"dst_port": top_port, "flows": top_flows}] if n else []}


def ok_registry():
    return FakeRegistry(lambda name, args, i: {"ok": True, "tool": name, "data": summary(), "error": None})


class Offline(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch("urllib.request.urlopen", side_effect=AssertionError("network call in a unit test"))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.store = d1.make_store()
        self.registry = build_registry(flow_store=self.store)


# ------------------------------------------------------------------------------------------------ state
class StateTests(unittest.TestCase):
    def test_new_state_has_exactly_the_documented_fields(self):
        s = S.new_state(make_alert())
        self.assertEqual(set(s), set(S.STATE_KEYS))
        # Day 4: graph_version is "v0.1" and the state gained routing, beacon_findings and enrichment_findings (all empty at the start).
        self.assertEqual((s["status"], s["next_node"], s["supervisor_visits"], s["evidence"], s["traffic_findings"], s["errors"], s["trace"], s["graph_version"]),
                         (S.STATUS_PENDING, None, 0, [], None, [], [], "v0.1"))
        self.assertEqual((s["routing"], s["beacon_findings"], s["enrichment_findings"]), ([], None, None))
        self.assertEqual(s["alert_id"], "T-1")
        S.validate_state(s)

    def test_the_alert_is_copied_not_shared(self):
        alert = make_alert()
        s = S.new_state(alert)
        alert["src_ip"] = "9.9.9.9"
        self.assertEqual(s["alert"]["src_ip"], d1.BEACON_SRC)

    def test_unusable_alerts_are_rejected(self):
        for bad in (None, "x", [], 5):
            with self.assertRaises(ValueError):
                S.new_state(bad)
        for key in S.REQUIRED_ALERT_KEYS:
            alert = make_alert()
            del alert[key]
            with self.assertRaises(ValueError, msg=key):
                S.new_state(alert)
            alert[key] = None
            with self.assertRaises(ValueError, msg=key):
                S.new_state(alert)
        for bad_id in ("", "   ", 5):
            with self.assertRaises(ValueError):
                S.new_state(make_alert(alert_id=bad_id))

    def test_answer_bearing_fields_are_rejected(self):
        for name in ("label", "Label", "is_attack", "mitre_technique_id", "mitre_accepted_ids", "source_alert_id"):
            with self.assertRaises(ValueError, msg=name):
                S.new_state(make_alert(**{name: "x"}))

    def test_validate_state_names_the_problem(self):
        good = S.new_state(make_alert())
        mutations = [lambda s: s.pop("errors"), lambda s: s.update(extra=1), lambda s: s.update(status="done"), lambda s: s.update(next_node="x"),
                     lambda s: s.update(supervisor_visits=True), lambda s: s.update(supervisor_visits=-1), lambda s: s.update(evidence=()), lambda s: s.update(trace="a"),
                     lambda s: s.update(traffic_findings=[]), lambda s: s.update(graph_version="v1"), lambda s: s.update(alert_id=""), lambda s: s.update(alert=[])]
        for mutate in mutations:
            s = copy.deepcopy(good)
            mutate(s)
            with self.assertRaises(ValueError):
                S.validate_state(s)
        with self.assertRaises(ValueError):
            S.validate_state(None)

    def test_state_is_json_serialisable(self):
        json.dumps(S.new_state(make_alert()))

    def test_alert_record_drops_hidden_and_forbidden_columns(self):
        row = pd.Series({"alert_id": "A", "flow_row": 3, "flow_id": "f", "timestamp": pd.Timestamp(ALERT_TIME), "src_ip": "1.1.1.1", "src_port": 1, "dst_ip": "2.2.2.2",
                         "dst_port": 2, "protocol": 6, "detector_score": 0.9})
        record = S.alert_record(row, d1.make_store().frame)
        self.assertNotIn("flow_row", record)
        self.assertEqual(record["timestamp"], ALERT_TIME)
        with self.assertRaises(ValueError):
            S.alert_record(row, None)


# ------------------------------------------------------------------------------------------------ supervisor
class SupervisorTests(unittest.TestCase):
    def state(self, **changes):
        s = S.new_state(make_alert())
        s.update(changes)
        return s

    def test_first_visit_routes_to_the_traffic_analyst(self):
        update = supervisor.supervisor_node(self.state())
        self.assertEqual((update["next_node"], update["status"], update["supervisor_visits"], update["trace"]), ("traffic_analyst", "running", 1, ["supervisor"]))
        self.assertEqual(update["errors"], [])

    def test_after_the_analyst_it_ends_with_the_matching_status(self):
        # Day 4: after the traffic analyst the supervisor may route on to enrichment. Here the enrichment agent has already finished, so the run ends
        # with the status the traffic analyst's own status gives (ok, partial) exactly as on Day 3.
        for analyst_status, final in (("ok", "completed"), ("partial", "completed_with_errors")):
            s = self.state(status="running", supervisor_visits=1, trace=["supervisor", "traffic_analyst", "enrichment_agent"], traffic_findings={"status": analyst_status},
                           enrichment_findings={"status": "ok"})
            u = supervisor.supervisor_node(s)
            self.assertEqual((u["next_node"], u["status"], u["supervisor_visits"]), ("end", final, 2), analyst_status)
        # A failed (or unrecognised) traffic status still ends the run at once as failed, as on Day 3: nothing else runs.
        for analyst_status in ("failed", "weird"):
            s = self.state(status="running", supervisor_visits=1, trace=["supervisor", "traffic_analyst"], traffic_findings={"status": analyst_status})
            u = supervisor.supervisor_node(s)
            self.assertEqual((u["next_node"], u["status"], u["supervisor_visits"]), ("end", "failed", 2), analyst_status)

    def test_the_analyst_is_never_routed_twice(self):
        s = self.state(status="running", supervisor_visits=1, trace=["supervisor", "traffic_analyst"], traffic_findings=None)
        u = supervisor.supervisor_node(s)
        self.assertEqual((u["next_node"], u["status"]), ("end", "failed"))
        self.assertEqual([e["code"] for e in u["errors"]], ["no_findings"])

    def test_loop_guard(self):
        s = self.state(status="running", supervisor_visits=S.MAX_SUPERVISOR_VISITS)
        u = supervisor.supervisor_node(s)
        self.assertEqual((u["next_node"], u["status"]), ("end", "failed"))
        self.assertEqual([e["code"] for e in u["errors"]], ["loop_guard"])

    def test_a_terminal_state_stays_terminal(self):
        for status in S.TERMINAL_STATUSES:
            u = supervisor.supervisor_node(self.state(status=status, supervisor_visits=2))
            self.assertEqual((u["next_node"], u["status"]), ("end", status))
            self.assertEqual(u["errors"], [])

    def test_it_does_not_mutate_its_input(self):
        s = self.state()
        before = copy.deepcopy(s)
        supervisor.supervisor_node(s)
        self.assertEqual(s, before)

    def test_it_is_deterministic(self):
        s = self.state()
        self.assertEqual(supervisor.supervisor_node(s), supervisor.supervisor_node(copy.deepcopy(s)))

    def test_route_function(self):
        self.assertEqual(supervisor.route_from_supervisor({"next_node": "traffic_analyst"}), "traffic_analyst")
        self.assertEqual(supervisor.route_from_supervisor({"next_node": "end"}), "end")
        for odd in (None, "enrichment", "", 5):
            self.assertEqual(supervisor.route_from_supervisor({"next_node": odd}), "end")


# ------------------------------------------------------------------------------------------------ traffic analyst
class TrafficAnalystTests(Offline):
    def run_node(self, registry, alert=None):
        state = S.new_state(alert or make_alert())
        before = copy.deepcopy(state)
        update = traffic_analyst.make_traffic_analyst(registry)(state)
        self.assertEqual(state, before, "the node must not mutate its input")
        json.dumps(update)
        return state, update

    def test_the_planned_calls_are_fixed_and_deterministic(self):
        plan = traffic_analyst.plan_calls(make_alert())
        self.assertEqual([p[0] for p in plan], ["summarize_flows", "summarize_flows"])
        self.assertEqual(plan[0][1], {"ip": d1.BEACON_SRC, "direction": "src", "around": ALERT_TIME, "window_minutes": 5})
        self.assertEqual(plan[1][1], {"ip": d1.BEACON_DST, "direction": "dst", "around": ALERT_TIME, "window_minutes": 5})
        self.assertEqual(plan, traffic_analyst.plan_calls(make_alert()))

    def test_success_with_the_real_tools(self):
        state, u = self.run_node(self.registry)
        f = u["traffic_findings"]
        self.assertEqual((f["analyst"], f["status"], f["tool_calls"], f["tool_errors"]), ("traffic_analyst", "ok", 2, 0))
        self.assertEqual([e["tool"] for e in u["evidence"]], ["summarize_flows", "summarize_flows"])
        self.assertTrue(all(e["ok"] and e["error"] is None for e in u["evidence"]))
        self.assertEqual([e["index"] for e in u["evidence"]], [0, 1])
        kinds = [x["kind"] for x in f["findings"]]
        self.assertEqual(kinds, ["source_activity", "port_concentration", "destination_fan_in"])
        src = f["findings"][0]["metrics"]
        self.assertEqual((src["n_flows"], src["distinct_destination_ips"], src["distinct_destination_ports"]), (10, 1, 1))
        self.assertEqual(f["findings"][1]["metrics"], {"top_port": 80, "top_port_flows": 10, "top_port_share": 1.0})
        self.assertEqual(f["findings"][2]["metrics"], {"n_flows": 10, "distinct_source_ips": 1})
        self.assertEqual(u["errors"], [])
        self.assertEqual(u["trace"], ["traffic_analyst"])

    def test_every_finding_number_comes_from_the_evidence(self):
        _, u = self.run_node(self.registry)
        for finding in u["traffic_findings"]["findings"]:
            data = u["evidence"][finding["evidence_index"]]["data"]
            m = finding["metrics"]
            if finding["kind"] == "source_activity":
                self.assertEqual((m["n_flows"], m["distinct_destination_ips"], m["distinct_destination_ports"]), (data["n_flows"], data["distinct_destination_ips"], data["distinct_destination_ports"]))
            elif finding["kind"] == "destination_fan_in":
                self.assertEqual((m["n_flows"], m["distinct_source_ips"]), (data["n_flows"], data["distinct_source_ips"]))
            elif finding["kind"] == "port_concentration":
                self.assertEqual(m["top_port_flows"], data["top_destination_ports"][0]["flows"])

    def test_findings_do_not_name_an_attack_or_a_technique(self):
        _, u = self.run_node(self.registry)
        text = json.dumps(u["traffic_findings"]).lower()
        for word in ("malicious", "benign", "attack", "scan", "beacon", "ddos", "brute", "t1", "verdict", "severity"):
            self.assertNotIn(word, text, word)

    def test_empty_results_are_findings_not_errors(self):
        alert = make_alert(src="203.0.113.7", dst="203.0.113.8")
        _, u = self.run_node(self.registry, alert)
        f = u["traffic_findings"]
        self.assertEqual(f["status"], "ok")
        self.assertEqual([x["kind"] for x in f["findings"]], ["no_source_flows", "no_destination_flows"])
        self.assertEqual([x["metrics"] for x in f["findings"]], [{"n_flows": 0}, {"n_flows": 0}])
        self.assertEqual(u["errors"], [])

    def test_empty_top_ports_does_not_crash(self):
        registry = FakeRegistry(lambda name, args, i: {"ok": True, "tool": name, "data": summary(n=2, top_port=None) | {"top_destination_ports": []}, "error": None})
        _, u = self.run_node(registry)
        self.assertEqual([x["kind"] for x in u["traffic_findings"]["findings"]], ["source_activity", "destination_fan_in"])

    def test_one_tool_failing_gives_a_partial_result(self):
        def answer(name, args, i):
            if i == 0:
                return error_result(name, "unavailable", "no flow store is attached to this tool set")
            return {"ok": True, "tool": name, "data": summary(), "error": None}
        _, u = self.run_node(FakeRegistry(answer))
        f = u["traffic_findings"]
        self.assertEqual((f["status"], f["tool_calls"], f["tool_errors"]), ("partial", 2, 1))
        self.assertEqual([x["kind"] for x in f["findings"]], ["destination_fan_in"])
        self.assertEqual(u["errors"], [{"node": "traffic_analyst", "tool": "summarize_flows", "code": "unavailable", "message": "no flow store is attached to this tool set"}])
        self.assertFalse(u["evidence"][0]["ok"])
        self.assertEqual(u["evidence"][0]["error"]["code"], "unavailable")
        self.assertIsNone(u["evidence"][0]["data"])

    def test_every_tool_failing_gives_failed(self):
        registry = FakeRegistry(lambda name, args, i: error_result(name, "internal_error", "boom"))
        _, u = self.run_node(registry)
        self.assertEqual((u["traffic_findings"]["status"], u["traffic_findings"]["findings"]), ("failed", []))
        self.assertEqual(len(u["errors"]), 2)

    def test_a_registry_without_a_flow_store_fails_cleanly(self):
        _, u = self.run_node(build_registry())
        self.assertEqual(u["traffic_findings"]["status"], "failed")
        self.assertEqual({e["code"] for e in u["errors"]}, {"unavailable"})

    def test_invalid_alert_values_come_back_as_tool_errors(self):
        _, u = self.run_node(self.registry, make_alert(src="not-an-ip"))
        self.assertEqual(u["traffic_findings"]["status"], "partial")
        self.assertEqual([e["code"] for e in u["errors"]], ["invalid_input"])

    def test_a_node_exception_is_contained(self):
        class Exploding:
            def call(self, name, arguments=None):
                raise RuntimeError("secret detail that must not leak")
        _, u = self.run_node(Exploding())
        self.assertEqual(u["traffic_findings"]["status"], "failed")
        self.assertEqual([e["code"] for e in u["errors"]], ["node_exception"])
        self.assertNotIn("secret", json.dumps(u))
        self.assertIn("RuntimeError", u["errors"][0]["message"])

    def test_malformed_envelopes_are_contained(self):
        _, u = self.run_node(FakeRegistry(lambda name, args, i: {"ok": True, "tool": name, "data": {"unexpected": 1}, "error": None}))
        self.assertEqual(u["traffic_findings"]["status"], "failed")
        self.assertEqual([e["code"] for e in u["errors"]], ["node_exception"])

    def test_evidence_and_errors_are_appended_not_replaced(self):
        state = S.new_state(make_alert())
        state["evidence"] = [{"index": 0, "tool": "earlier"}]
        state["errors"] = [{"node": "x", "code": "c", "message": "m"}]
        state["trace"] = ["supervisor"]
        u = traffic_analyst.make_traffic_analyst(self.registry)(state)
        self.assertEqual(u["evidence"][0], {"index": 0, "tool": "earlier"})
        self.assertEqual(len(u["evidence"]), 3)
        self.assertEqual(u["errors"], state["errors"])
        self.assertEqual(u["trace"], ["supervisor", "traffic_analyst"])

    def test_deterministic_and_only_the_planned_tools_are_called(self):
        a = self.run_node(self.registry)[1]
        b = self.run_node(self.registry)[1]
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        fake = ok_registry()
        self.run_node(fake)
        self.assertEqual([c[0] for c in fake.calls], ["summarize_flows", "summarize_flows"])

    def test_the_reputation_tool_is_never_called(self):
        fake = ok_registry()
        self.run_node(fake)
        self.assertNotIn("reputation_lookup", [c[0] for c in fake.calls])


# ------------------------------------------------------------------------------------------------ the loop, driven by hand (no LangGraph needed)
def drive(state, analyst, limit=50, others=None):
    """Run the graph's edges by hand: supervisor, then the routed node, until 'end'. Returns (final state, steps).
    `analyst` is the traffic analyst node; `others` maps the other node names to functions (default: no other agent, so a routed-to c2/enrichment node does nothing)."""
    nodes = {S.NODE_TRAFFIC_ANALYST: analyst, S.NODE_C2_BEACON_ANALYST: (others or {}).get(S.NODE_C2_BEACON_ANALYST, lambda st: {}),
             S.NODE_ENRICHMENT_AGENT: (others or {}).get(S.NODE_ENRICHMENT_AGENT, lambda st: {})}
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


class LoopTests(Offline):
    def test_a_normal_run_runs_each_agent_once_and_ends(self):
        # Day 3 ran supervisor, traffic analyst, supervisor (3 steps). Day 4: this fixture alert has repeat contact, so the longest path runs (7 steps).
        final, steps = drive(S.new_state(make_alert()), traffic_analyst.make_traffic_analyst(self.registry), others=all_nodes(self.registry))
        self.assertEqual((final["status"], final["trace"], steps), ("completed", ["supervisor", "traffic_analyst", "supervisor", "c2_beacon_analyst", "supervisor", "enrichment_agent", "supervisor"], 7))
        S.validate_state(final)

    def test_an_analyst_that_returns_nothing_still_terminates(self):
        final, steps = drive(S.new_state(make_alert()), lambda state: {"trace": state["trace"] + ["traffic_analyst"]})
        self.assertEqual(final["status"], "failed")
        self.assertLessEqual(steps, 4)
        self.assertIn("no_findings", [e["code"] for e in final["errors"]])

    def test_an_analyst_that_never_reports_a_trace_hits_the_loop_guard(self):
        final, steps = drive(S.new_state(make_alert()), lambda state: {})
        self.assertEqual(final["status"], "failed")
        self.assertIn("loop_guard", [e["code"] for e in final["errors"]])
        self.assertLessEqual(steps, 2 * S.MAX_SUPERVISOR_VISITS + 2)

    def test_failures_end_in_the_right_final_status(self):
        failing = FakeRegistry(lambda name, args, i: error_result(name, "internal_error", "boom"))
        final, _ = drive(S.new_state(make_alert()), traffic_analyst.make_traffic_analyst(failing), others=all_nodes(failing))
        self.assertEqual(final["status"], "failed")
        self.assertEqual(final["trace"], ["supervisor", "traffic_analyst", "supervisor"])   # a failed traffic analysis stops the run: no other agent ran
        half = FakeRegistry(lambda name, args, i: error_result(name, "unavailable", "x") if i == 1 else {"ok": True, "tool": name, "data": summary(), "error": None})
        final, _ = drive(S.new_state(make_alert()), traffic_analyst.make_traffic_analyst(half), others=all_nodes(half))
        self.assertEqual(final["status"], "completed_with_errors")

    def test_the_final_status_is_always_terminal(self):
        for registry in (self.registry, build_registry(), ok_registry()):
            final, _ = drive(S.new_state(make_alert()), traffic_analyst.make_traffic_analyst(registry))
            self.assertIn(final["status"], S.TERMINAL_STATUSES)


# ------------------------------------------------------------------------------------------------ the real LangGraph graph
@unittest.skipUnless(HAVE_LANGGRAPH, "LangGraph is not installed: pip install -r requirements-week3.txt")
class LangGraphTests(Offline):
    def test_end_to_end_on_the_fixture(self):
        graph = graph_module.build_graph(self.registry)
        final = graph_module.run_alert(graph, make_alert())
        # Day 4: the fixture alert has repeat contact, so the graph takes the longest path (4 supervisor visits).
        self.assertEqual((final["status"], final["trace"], final["supervisor_visits"]),
                         ("completed", ["supervisor", "traffic_analyst", "supervisor", "c2_beacon_analyst", "supervisor", "enrichment_agent", "supervisor"], 4))
        self.assertEqual(final["traffic_findings"]["status"], "ok")
        self.assertEqual([e["tool"] for e in final["evidence"][:2]], ["summarize_flows", "summarize_flows"])   # the Day 3 analyst's evidence comes first, unchanged
        self.assertEqual(final["errors"], [])
        S.validate_state(final)

    def test_it_matches_the_hand_driven_loop_and_is_deterministic(self):
        graph = graph_module.build_graph(self.registry)
        a = graph_module.run_alert(graph, make_alert())
        b = graph_module.run_alert(graph, make_alert())
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        hand, _ = drive(S.new_state(make_alert()), traffic_analyst.make_traffic_analyst(self.registry), others=all_nodes(self.registry))
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(hand, sort_keys=True))

    def test_tool_failure_ends_the_graph_cleanly(self):
        final = graph_module.run_alert(graph_module.build_graph(build_registry()), make_alert())
        self.assertEqual(final["status"], "failed")
        self.assertEqual(len(final["errors"]), 2)

    def test_a_broken_node_cannot_loop_forever(self):
        with mock.patch.object(graph_module, "make_traffic_analyst", return_value=lambda state: {}):
            graph = graph_module.build_graph(self.registry)
        final = graph_module.run_alert(graph, make_alert())
        self.assertEqual(final["status"], "failed")
        self.assertIn("loop_guard", [e["code"] for e in final["errors"]])

    def test_a_bad_alert_is_rejected_before_the_graph_starts(self):
        graph = graph_module.build_graph(self.registry)
        with self.assertRaises(ValueError):
            graph_module.run_alert(graph, make_alert(label="DDoS"))

    def test_the_graph_is_reusable_for_many_alerts(self):
        graph = graph_module.build_graph(self.registry)
        finals = [graph_module.run_alert(graph, make_alert(alert_id="T-" + str(i))) for i in range(3)]
        self.assertEqual([f["alert_id"] for f in finals], ["T-0", "T-1", "T-2"])
        self.assertEqual({f["status"] for f in finals}, {"completed"})


class MissingLangGraphTests(Offline):
    def test_the_error_names_the_install_command(self):
        with mock.patch.dict(sys.modules, {"langgraph": None, "langgraph.graph": None}):
            with self.assertRaises(ImportError) as caught:
                graph_module.build_graph(self.registry)
        self.assertIn("pip install -r requirements-week3.txt", str(caught.exception))

    def test_the_nodes_import_without_langgraph(self):
        for name in ("state.py", "supervisor.py", "traffic_analyst.py"):
            with open(os.path.join(AGENTS_DIR, name), encoding="utf-8") as f:
                self.assertNotIn("langgraph", f.read(), name)


# ------------------------------------------------------------------------------------------------ the dev runner
def alerts_frame():
    rows = []
    for i, (src, dst, ts) in enumerate([(d1.BEACON_SRC, d1.BEACON_DST, ALERT_TIME), (d1.SCAN_SRC, d1.SCAN_DST, "2017-07-05 10:00:10"), (d1.IRREG_SRC, d1.IRREG_DST, "2017-07-05 10:03:00"),
                                        ("203.0.113.7", "203.0.113.8", ALERT_TIME)]):
        rows.append({"alert_id": "DEV-" + str(4 - i).zfill(4), "flow_row": i, "flow_id": "f" + str(i), "timestamp": pd.Timestamp(ts), "src_ip": src, "src_port": 40000, "dst_ip": dst,
                     "dst_port": 80, "protocol": 6, "detector_score": 0.9})
    return pd.DataFrame(rows)


class RunnerTests(Offline):
    def patched(self):
        return (mock.patch.object(triage_inputs, "load_dev_alerts", return_value=alerts_frame()), mock.patch.object(FlowStore, "from_dev", return_value=self.store))

    def test_select_alerts_is_sorted_and_deterministic(self):
        picked = run_graph_dev.select_alerts(alerts_frame(), 2)
        self.assertEqual(list(picked["alert_id"]), ["DEV-0001", "DEV-0002"])
        self.assertEqual(list(picked["alert_id"]), list(run_graph_dev.select_alerts(alerts_frame().iloc[::-1], 2)["alert_id"]))

    def test_limits_and_overwrite_protection(self):
        with tempfile.TemporaryDirectory() as tmp:
            for n in ("0", "21", "-1"):
                with self.assertRaises(SystemExit), mock.patch("sys.stderr"):
                    run_graph_dev.main(["--n", n, "--out", tmp])
            with open(os.path.join(tmp, "results.jsonl"), "w") as f:
                f.write("keep")
            with self.assertRaises(SystemExit), mock.patch("sys.stderr"):
                run_graph_dev.main(["--n", "1", "--out", tmp])
            self.assertEqual(read_text(os.path.join(tmp, "results.jsonl")), "keep")

    @unittest.skipUnless(HAVE_LANGGRAPH, "LangGraph is not installed")
    def test_a_small_run_writes_inspectable_files(self):
        a, b = self.patched()
        with a, b, tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "run")
            with mock.patch("sys.stdout"):
                self.assertEqual(run_graph_dev.main(["--n", "4", "--out", out]), 0)
            lines = [json.loads(x) for x in read_text(os.path.join(out, "results.jsonl")).splitlines()]
            self.assertEqual([x["alert_id"] for x in lines], ["DEV-0001", "DEV-0002", "DEV-0003", "DEV-0004"])
            self.assertEqual({x["status"] for x in lines}, {"completed"})
            summary_ = json.loads(read_text(os.path.join(out, "summary.json")))
            self.assertEqual((summary_["alerts"], summary_["llm_calls"], summary_["reputation_calls"], summary_["frozen_set_opened"], summary_["set"]), (4, 0, 0, False, "dev"))
            self.assertEqual(summary_["status_counts"], {"completed": 4})
            self.assertEqual(summary_["tool_calls"], sum(len(x["evidence"]) for x in lines))   # Day 4 agents add tool calls; the count is read from the saved states
            self.assertGreaterEqual(summary_["tool_calls"], 8)
            # the alert with no flows in the store gives empty-result findings, not an error
            empty = [x for x in lines if x["alert"]["src_ip"] == "203.0.113.7"][0]
            self.assertEqual([f["kind"] for f in empty["traffic_findings"]["findings"]], ["no_source_flows", "no_destination_flows"])
            for x in lines:
                S.validate_state(x)
            # a second identical run gives identical results
            out2 = os.path.join(tmp, "run2")
            with mock.patch("sys.stdout"):
                run_graph_dev.main(["--n", "4", "--out", out2])
            self.assertEqual(read_text(os.path.join(out, "results.jsonl")), read_text(os.path.join(out2, "results.jsonl")))

    def test_run_many_and_summarize_without_langgraph(self):
        graph = mock.Mock()
        graph.invoke.side_effect = lambda state, config=None: {**state, "status": "completed", "trace": ["supervisor"], "supervisor_visits": 2}
        finals = run_graph_dev.run_many(graph, alerts_frame().head(2), self.store)
        self.assertEqual(len(finals), 2)
        self.assertEqual(run_graph_dev.summarize(finals)["status_counts"], {"completed": 2})


# ------------------------------------------------------------------------------------------------ boundaries
class BoundaryTests(unittest.TestCase):
    FILES = sorted(f for f in os.listdir(AGENTS_DIR) if f.endswith(".py")) if os.path.isdir(AGENTS_DIR) else []

    def source(self, name):
        with open(os.path.join(AGENTS_DIR, name), encoding="utf-8") as f:
            return f.read()

    def test_agents_never_touch_labels_the_answer_key_the_frozen_set_or_the_network(self):
        banned_modules = {"eval_io", "eval_labels", "urllib", "requests", "http", "socket", "subprocess", "os", "google", "openai", "anthropic", "dotenv", "llm_config", "gemini_client"}
        banned_names = {"open", "eval", "exec", "__import__", "load_labels", "load_mitre_map", "environ", "getenv"}
        for name in self.FILES:
            tree = ast.parse(self.source(name))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    modules = [node.module or ""] if node.level == 0 else []
                else:
                    modules = []
                for module in modules:
                    self.assertNotIn(module.split(".")[0], banned_modules, name + " imports " + module)
                if isinstance(node, ast.Name):
                    self.assertNotIn(node.id, banned_names, name + " uses " + node.id)
                if isinstance(node, ast.Attribute):
                    self.assertNotIn(node.attr, banned_names, name + " uses ." + node.attr)

    def test_graph_v0_1_has_only_the_day3_and_day4_nodes(self):
        # Day 4 extended the Day 3 two-node graph with the C2 beaconing analyst and the enrichment agent; nothing else exists yet.
        self.assertEqual((S.NODE_SUPERVISOR, S.NODE_TRAFFIC_ANALYST, S.NODE_C2_BEACON_ANALYST, S.NODE_ENRICHMENT_AGENT), ("supervisor", "traffic_analyst", "c2_beacon_analyst", "enrichment_agent"))
        # Day 5 added the optional verdict step: one more route and two more agent files (the node and its prompt).
        self.assertEqual(S.ROUTES, ("traffic_analyst", "c2_beacon_analyst", "enrichment_agent", "verdict_node", "end"))
        self.assertEqual(self.FILES, ["__init__.py", "c2_beacon_analyst.py", "common.py", "enrichment_agent.py", "graph.py", "state.py", "supervisor.py", "traffic_analyst.py", "verdict_node.py", "verdict_prompt.py"])

    def test_state_has_no_fields_for_later_agents(self):
        for name in S.STATE_KEYS:
            for later in ("memory", "approval"):  # Day 4 added beacon and enrichment fields; Day 5 added verdict_enabled and verdict (checked in test_week3_day5); memory and approval do not exist yet
                self.assertNotIn(later, name)

    def test_the_registry_is_built_without_reputation_in_the_runner(self):
        with open(os.path.join(ROOT, "src", "run_graph_dev.py"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("build_registry(flow_store=store)", text)
        self.assertNotIn("ReputationTool", text)
        self.assertNotIn("from_env", text)

    def test_the_runner_reads_only_the_dev_set(self):
        with open(os.path.join(ROOT, "src", "run_graph_dev.py"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("load_dev_alerts", text)
        self.assertIn("from_dev", text)
        for word in ("load_alerts", "load_labels", "frozen_alerts", "SOC_FROZEN_UNLOCK", "eval_io"):
            self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main()
