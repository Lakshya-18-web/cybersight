"""Week 3 Day 4: C2 beaconing analyst, enrichment agent, supervisor routing, graph v0.1. Offline: no LLM, no network, no labels, no frozen set.

LangGraph-dependent tests are skipped when the package is missing. Everything else, including an exhaustive routing/termination simulation, runs without it.
"""
import os
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
import triage_inputs
from agents import state as S
from agents import supervisor, traffic_analyst, c2_beacon_analyst as c2, enrichment_agent as enrich, common, graph as graph_module
from tools import FlowStore, build_registry
from tools.base import error_result

import run_graph_dev
from tests import test_week3_day1 as d1
from tests import test_week3_day3 as d3

HAVE_LANGGRAPH = d3.HAVE_LANGGRAPH
T0 = d1.T0
ALERT_TIME = d3.ALERT_TIME            # 10:05, five minutes into the regular beacon fixture
FULL_PATH = ["supervisor", "traffic_analyst", "supervisor", "c2_beacon_analyst", "supervisor", "enrichment_agent", "supervisor"]
NO_BEACON_PATH = ["supervisor", "traffic_analyst", "supervisor", "enrichment_agent", "supervisor"]
FAILED_PATH = ["supervisor", "traffic_analyst", "supervisor"]


def build_store(specs):
    """A flow store from (timestamp, src, dst, dst_port) tuples."""
    rows = []
    for ts, src, dst, dport in specs:
        row = {"flow_row": len(rows), "flow_id": "c-" + str(len(rows)), "timestamp": ts, "src_ip": src, "src_port": 40000, "dst_ip": dst, "dst_port": dport, "protocol": 6}
        for name in config.DISPLAY_FEATURES:
            row[name] = 1.0
        row["Total Length of Fwd Packets"] = 100.0
        row["Flow Duration"] = 5.0
        row["Fwd IAT Mean"] = 0.5
        rows.append(row)
    return FlowStore(pd.DataFrame(rows))


def times(start, gaps):
    out, t = [], start
    out.append(t)
    for g in gaps:
        t = t + pd.Timedelta(seconds=g)
        out.append(t)
    return out


SRC, DST = "192.168.10.77", "198.51.100.9"


def timed_store(gaps, port=8443):
    return build_store([(t, SRC, DST, port) for t in times(T0, gaps)])


def timed_alert(port=8443, ts="2017-07-05 10:03:00"):
    return d3.make_alert(src=SRC, dst=DST, ts=ts, dport=port)


def state_for(alert=None, **changes):
    s = S.new_state(alert or d3.make_alert())
    s.update(changes)
    return s


def src_summary_evidence(dst_flows, distinct=2, dst="52.1.2.3", extra_rows=True):
    tops = [{"dst_ip": dst, "flows": dst_flows}] if dst_flows else []
    if extra_rows:
        tops.append({"dst_ip": "1.1.1.1", "flows": 1})
    return {"index": 0, "tool": "summarize_flows", "arguments": {"ip": "x", "direction": "src"}, "ok": True, "error": None,
            "data": {"n_flows": dst_flows + 1, "distinct_destination_ips": distinct, "top_destination_ips": tops}}


class Offline(d3.Offline):
    def run_node(self, node, state):
        before = copy.deepcopy(state)
        update = node(state)
        self.assertEqual(state, before, "the node must not mutate its input")
        json.dumps(update)
        return update

    def beacon_node(self, registry=None):
        return c2.make_c2_beacon_analyst(registry or self.registry)

    def enrich_node(self, registry=None):
        return enrich.make_enrichment_agent(registry or self.registry)


# ------------------------------------------------------------------------------------------------ state
class StateDay4Tests(unittest.TestCase):
    def test_new_fields_and_routes(self):
        s = S.new_state(d3.make_alert())
        self.assertEqual((s["routing"], s["beacon_findings"], s["enrichment_findings"], s["graph_version"]), ([], None, None, "v0.1"))
        self.assertEqual(S.ROUTES, ("traffic_analyst", "c2_beacon_analyst", "enrichment_agent", "verdict_node", "end"))   # Day 5 added "verdict_node"
        self.assertEqual(S.MAX_SUPERVISOR_VISITS, 5)
        S.validate_state(s)

    def test_validation_of_the_new_fields(self):
        good = S.new_state(d3.make_alert())
        for change in ({"routing": ()}, {"beacon_findings": []}, {"enrichment_findings": "x"}, {"next_node": "verdict"}):
            s = dict(good, **change)
            with self.assertRaises(ValueError, msg=str(change)):
                S.validate_state(s)
        s = dict(good)
        del s["routing"]
        with self.assertRaises(ValueError):
            S.validate_state(s)


# ------------------------------------------------------------------------------------------------ common
class CommonTests(Offline):
    def test_ok_call(self):
        entry, error = common.call_tool(self.registry, "n", "port_info", {"port": 22}, 7)
        self.assertEqual((entry["index"], entry["tool"], entry["ok"], entry["error"], error), (7, "port_info", True, None, None))
        self.assertEqual(entry["data"]["port"], 22)

    def test_tool_error_becomes_an_error_entry(self):
        entry, error = common.call_tool(self.registry, "n", "port_info", {"port": 99999}, 0)
        self.assertFalse(entry["ok"])
        self.assertEqual((entry["error"]["code"], error["code"], error["node"], error["tool"]), ("invalid_input", "invalid_input", "n", "port_info"))
        self.assertIsNone(entry["data"])
        entry, error = common.call_tool(self.registry, "n", "no_such_tool", {}, 0)
        self.assertEqual(error["code"], "unknown_tool")

    def test_a_raising_registry_is_contained(self):
        class Boom:
            def call(self, *a):
                raise RuntimeError("secret")
        entry, error = common.call_tool(Boom(), "n", "t", {}, 0)
        self.assertEqual((entry["ok"], error["code"]), (False, "tool_exception"))
        self.assertNotIn("secret", json.dumps([entry, error]))

    def test_malformed_answers_are_invalid_results(self):
        for answer in (None, "x", [], {}, {"ok": "yes"}, {"ok": True}, {"ok": True, "data": []}, {"ok": True, "data": None}):
            entry, error = common.call_tool(d3.FakeRegistry(lambda n, a, i, ans=answer: ans), "n", "t", {}, 0)
            self.assertFalse(entry["ok"], repr(answer))
            self.assertEqual(error["code"], "invalid_tool_result", repr(answer))

    def test_an_error_envelope_without_details_is_still_an_error(self):
        entry, error = common.call_tool(d3.FakeRegistry(lambda n, a, i: {"ok": False, "data": None, "error": None}), "n", "t", {}, 0)
        self.assertEqual((entry["ok"], error["code"]), (False, "unknown"))

    def test_agent_status_and_numbers(self):
        ok, bad = {"ok": True}, {"ok": False}
        self.assertEqual([common.agent_status(x) for x in ([ok, ok], [ok, bad], [bad, bad], [])], ["ok", "partial", "failed", "failed"])
        self.assertEqual([common.as_number(v) for v in (1, 2.5, True, None, "3", float("nan"), float("inf"))], [1, 2.5, None, None, None, None, None])


# ------------------------------------------------------------------------------------------------ C2 beaconing analyst
class BeaconAnalystTests(Offline):
    def run_for(self, alert, registry=None, **state_changes):
        return self.run_node(self.beacon_node(registry), state_for(alert, **state_changes))

    def test_the_planned_calls(self):
        plan = c2.plan_calls(d3.make_alert())
        self.assertEqual([p[0] for p in plan], ["beacon_stats", "beacon_stats"])
        self.assertEqual(plan[0][1], {"src_ip": d1.BEACON_SRC, "dst_ip": d1.BEACON_DST, "around": ALERT_TIME, "window_minutes": 60})
        self.assertEqual(plan[1][1], dict(plan[0][1], dst_port=80))
        self.assertEqual(plan, c2.plan_calls(d3.make_alert()))

    def test_regular_intervals_on_one_port_make_a_candidate_not_a_confirmation(self):
        u = self.run_for(d3.make_alert())
        b = u["beacon_findings"]
        self.assertEqual((b["analyst"], b["status"], b["assessment"], b["beacon_candidate"], b["basis"], b["tool_calls"], b["tool_errors"]),
                         ("c2_beacon_analyst", "ok", "regular_intervals", True, "pair", 2, 0))
        self.assertEqual([f["kind"] for f in b["findings"]], ["beacon_timing", "beacon_size_regularity", "port_scope", "beacon_assessment"])
        timing = b["findings"][0]["metrics"]
        self.assertEqual((timing["n_flows"], timing["interval_count"], timing["median_seconds"], timing["cv"], timing["share_within_10pct_of_median"]), (10, 9, 60.0, 0.0, 1.0))
        self.assertEqual(b["findings"][2]["metrics"], {"pair_flows": 10, "pair_flows_on_alert_port": 10, "share_on_alert_port": 1.0})
        self.assertEqual(b["findings"][1]["metrics"]["forward_bytes_cv"], 0.0)
        statement = b["findings"][3]["statement"]
        self.assertIn("consistent with periodic traffic", statement)
        self.assertIn("does not show that the traffic is command-and-control", statement)
        self.assertEqual(len(b["limits"]), 3)
        self.assertTrue(any("does not establish command-and-control" in x for x in b["limits"]))
        self.assertEqual(u["trace"], ["c2_beacon_analyst"])

    def test_no_output_ever_claims_c2_is_confirmed(self):
        alerts = [d3.make_alert(), d3.make_alert(src=d1.IRREG_SRC, dst=d1.IRREG_DST, dport=443, ts="2017-07-05 10:03:00"), d3.make_alert(src=d1.SCAN_SRC, dst=d1.SCAN_DST, dport=1, ts="2017-07-05 10:00:10")]
        for alert in alerts:
            text = json.dumps(self.run_for(alert)["beacon_findings"]).lower()
            for phrase in ("confirmed", "is c2", "is a beacon", "malicious", "verdict", "proves", "detected"):
                self.assertNotIn(phrase, text, phrase)

    def test_irregular_intervals(self):
        b = self.run_for(d3.make_alert(src=d1.IRREG_SRC, dst=d1.IRREG_DST, dport=443, ts="2017-07-05 10:03:00"))["beacon_findings"]
        self.assertEqual((b["assessment"], b["beacon_candidate"]), ("irregular_intervals", False))
        self.assertIn("does not look periodic", b["findings"][-1]["statement"])
        self.assertNotIn("consistent with periodic", json.dumps(b))

    def test_mixed_intervals(self):
        store = timed_store([50, 60, 70, 60, 90, 40])
        b = self.run_for(timed_alert(), build_registry(flow_store=store))["beacon_findings"]
        self.assertEqual((b["assessment"], b["beacon_candidate"]), ("mixed_intervals", False))

    def test_a_scan_has_regular_timing_but_is_not_a_candidate(self):
        b = self.run_for(d3.make_alert(src=d1.SCAN_SRC, dst=d1.SCAN_DST, dport=1, ts="2017-07-05 10:00:10"))["beacon_findings"]
        self.assertEqual(b["assessment"], "regular_intervals")
        self.assertFalse(b["beacon_candidate"])
        self.assertIn("spread over several ports", b["candidate_reason"])
        scope = [f for f in b["findings"] if f["kind"] == "port_scope"][0]["metrics"]
        self.assertEqual((scope["pair_flows"], scope["pair_flows_on_alert_port"]), (30, 1))

    def test_too_few_flows(self):
        store = timed_store([60, 60])
        b = self.run_for(timed_alert(), build_registry(flow_store=store))["beacon_findings"]
        self.assertEqual((b["assessment"], b["beacon_candidate"], b["status"]), ("insufficient_data", False, "ok"))
        self.assertIn("at least 4", b["findings"][-1]["statement"])
        self.assertIn("Nothing can be said about periodicity", b["findings"][-1]["statement"])

    def test_no_flows_between_the_pair(self):
        b = self.run_for(d3.make_alert(src="203.0.113.7", dst="203.0.113.8"))["beacon_findings"]
        self.assertEqual((b["assessment"], b["status"], b["beacon_candidate"]), ("no_flows", "ok", False))
        self.assertEqual([f["kind"] for f in b["findings"]], ["beacon_timing", "beacon_assessment"])

    def test_coarse_timestamps_are_inconclusive(self):
        store = timed_store([0, 0, 0, 0, 0])
        b = self.run_for(timed_alert(), build_registry(flow_store=store))["beacon_findings"]
        self.assertEqual((b["assessment"], b["beacon_candidate"]), ("inconclusive", False))
        self.assertIn("too coarse", b["findings"][-1]["statement"])

    def test_one_failed_call_still_gives_an_analysis(self):
        real = self.registry

        def answer(name, args, i):
            if i == 0:
                return error_result(name, "internal_error", "boom")
            return real.call(name, args)
        u = self.run_for(d3.make_alert(), d3.FakeRegistry(answer))
        b = u["beacon_findings"]
        self.assertEqual((b["status"], b["assessment"], b["basis"], b["tool_errors"]), ("partial", "regular_intervals", "pair_on_destination_port", 1))
        self.assertFalse(b["beacon_candidate"])       # the share of flows on the alert's port is unknown without the pair-level call
        self.assertIn("unknown", b["candidate_reason"])
        self.assertEqual([e["code"] for e in u["errors"]], ["internal_error"])

    def test_every_call_failing(self):
        u = self.run_for(d3.make_alert(), d3.FakeRegistry(lambda n, a, i: error_result(n, "unavailable", "no flow store")))
        b = u["beacon_findings"]
        self.assertEqual((b["status"], b["assessment"], b["findings"], b["beacon_candidate"]), ("failed", "inconclusive", [], False))
        self.assertEqual([e["code"] for e in u["errors"]], ["unavailable", "unavailable"])

    def test_a_registry_without_a_flow_store(self):
        b = self.run_for(d3.make_alert(), build_registry())["beacon_findings"]
        self.assertEqual((b["status"], b["findings"]), ("failed", []))

    def test_malformed_tool_results_are_invalid_results(self):
        bad_data = [{}, {"n_flows": "3", "sufficient_for_interval_stats": True}, {"n_flows": True, "sufficient_for_interval_stats": True}, {"n_flows": -1, "sufficient_for_interval_stats": True},
                    {"n_flows": 5, "sufficient_for_interval_stats": "yes"}, {"n_flows": 5, "sufficient_for_interval_stats": True, "intervals_seconds": []}]
        for data in bad_data:
            u = self.run_for(d3.make_alert(), d3.FakeRegistry(lambda n, a, i, d=data: {"ok": True, "tool": n, "data": d, "error": None}))
            b = u["beacon_findings"]
            self.assertEqual((b["status"], b["assessment"], b["findings"]), ("failed", "inconclusive", []), repr(data))
            self.assertEqual({e["code"] for e in u["errors"]}, {"invalid_tool_result"}, repr(data))

    def test_missing_statistics_inside_valid_data_do_not_crash(self):
        data = {"n_flows": 6, "sufficient_for_interval_stats": True, "intervals_seconds": {"count": 5, "cv": None, "share_within_10pct_of_median": None, "caveat": None}}
        b = self.run_for(d3.make_alert(), d3.FakeRegistry(lambda n, a, i: {"ok": True, "tool": n, "data": data, "error": None}))["beacon_findings"]
        self.assertEqual(b["assessment"], "inconclusive")
        self.assertIn("not defined", b["findings"][-1]["statement"])

    def test_an_exception_is_contained(self):
        class Boom:
            def call(self, *a):
                raise RuntimeError("secret detail")
        u = self.run_for(d3.make_alert(), Boom())
        self.assertEqual(u["beacon_findings"]["status"], "failed")
        self.assertEqual({e["code"] for e in u["errors"]}, {"tool_exception"})
        self.assertNotIn("secret", json.dumps(u))

    def test_an_unexpected_failure_in_the_analysis_is_contained(self):
        with mock.patch.object(c2, "build_findings", side_effect=ValueError("secret")):
            u = self.run_for(d3.make_alert())
        self.assertEqual((u["beacon_findings"]["status"], u["beacon_findings"]["assessment"], u["errors"][-1]["code"]), ("failed", "inconclusive", "node_exception"))
        self.assertNotIn("secret", json.dumps(u))
        self.assertIn("ValueError", u["errors"][-1]["message"])

    def test_evidence_indices_continue_after_earlier_evidence(self):
        earlier = [{"index": 0, "tool": "x"}, {"index": 1, "tool": "y"}, {"index": 2, "tool": "z"}]
        u = self.run_for(d3.make_alert(), evidence=earlier)
        self.assertEqual([e["index"] for e in u["evidence"]], [0, 1, 2, 3, 4])
        for f in u["beacon_findings"]["findings"]:
            self.assertIn(f["evidence_index"], (3, 4))
            self.assertEqual(u["evidence"][f["evidence_index"]]["tool"], "beacon_stats")

    def test_findings_numbers_come_from_the_evidence(self):
        u = self.run_for(d3.make_alert())
        data = u["evidence"][0]["data"]
        timing = u["beacon_findings"]["findings"][0]
        self.assertEqual(timing["evidence_index"], 0)
        self.assertEqual(timing["metrics"]["n_flows"], data["n_flows"])
        self.assertEqual(timing["metrics"]["median_seconds"], data["intervals_seconds"]["median"])

    def test_deterministic(self):
        a, b = self.run_for(d3.make_alert()), self.run_for(d3.make_alert())
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_only_beacon_stats_is_called(self):
        fake = d3.FakeRegistry(lambda n, a, i: self.registry.call(n, a))
        self.run_for(d3.make_alert(), fake)
        self.assertEqual({c[0] for c in fake.calls}, {"beacon_stats"})

    def test_it_appends_and_never_replaces(self):
        state = state_for(errors=[{"node": "x", "code": "c", "message": "m"}], trace=["supervisor", "traffic_analyst", "supervisor"])
        u = self.beacon_node()(state)
        self.assertEqual(u["errors"], state["errors"])
        self.assertEqual(u["trace"], ["supervisor", "traffic_analyst", "supervisor", "c2_beacon_analyst"])


# ------------------------------------------------------------------------------------------------ enrichment agent
def candidate_findings(candidate=True):
    return {"analyst": "c2_beacon_analyst", "status": "ok", "assessment": "regular_intervals" if candidate else "irregular_intervals", "beacon_candidate": candidate}


class EnrichmentAgentTests(Offline):
    def run_for(self, alert=None, registry=None, **changes):
        return self.run_node(self.enrich_node(registry), state_for(alert, **changes))

    def test_without_a_candidate_it_enriches_addresses_port_and_service_only(self):
        u = self.run_for()
        e = u["enrichment_findings"]
        self.assertEqual((e["agent"], e["status"], e["tool_calls"], e["tool_errors"], e["unavailable"]), ("enrichment_agent", "ok", 4, 0, []))
        self.assertEqual([x["tool"] for x in u["evidence"]], ["ip_info", "ip_info", "port_info", "service_lookup"])
        self.assertEqual([f["kind"] for f in e["findings"]], ["ip_context", "ip_context", "port_context", "service_context"])
        src, dst = e["findings"][0]["metrics"], e["findings"][1]["metrics"]
        self.assertEqual((src["role"], src["ip"], src["address_type"], src["scope"], src["flows_as_source"]), ("source", d1.BEACON_SRC, "private_rfc1918", "internal", 10))
        self.assertEqual((dst["role"], dst["ip"], dst["address_type"], dst["scope"], dst["flows_as_destination"]), ("destination", d1.BEACON_DST, "public", "external", 10))
        self.assertEqual(e["findings"][2]["metrics"]["port"], 80)
        self.assertEqual(e["findings"][2]["metrics"]["services"], ["http"])
        self.assertEqual(e["findings"][3]["metrics"]["name"], "http")
        self.assertFalse(any(f["kind"].startswith("mitre") for f in e["findings"]))

    def test_the_provenance_of_every_finding(self):
        u = self.run_for(beacon_findings=candidate_findings())
        for f in u["enrichment_findings"]["findings"]:
            entry = u["evidence"][f["evidence_index"]]
            self.assertEqual(entry["tool"], f["source_tool"])
            self.assertTrue(entry["ok"])
        self.assertEqual([e["index"] for e in u["evidence"]], list(range(len(u["evidence"]))))

    def test_mitre_reference_only_for_a_beacon_candidate(self):
        u = self.run_for(beacon_findings=candidate_findings(True))
        e = u["enrichment_findings"]
        tools = [x["tool"] for x in u["evidence"]]
        self.assertEqual(tools, ["ip_info", "ip_info", "port_info", "service_lookup", "mitre_search", "mitre_lookup", "mitre_lookup"])
        self.assertEqual(u["evidence"][4]["arguments"], {"query": "command and control beaconing", "limit": 3})
        hits = [f for f in e["findings"] if f["kind"] == "mitre_search_hit"]
        refs = [f for f in e["findings"] if f["kind"] == "mitre_reference"]
        self.assertEqual((len(hits), len(refs)), (3, 2))
        self.assertEqual([r["metrics"]["technique_id"] for r in refs], [h["metrics"]["technique_id"] for h in hits[:2]])
        for f in hits + refs:
            self.assertIn("Reference", f["statement"])
            self.assertIn("not a determination", f["statement"])
        self.assertNotIn("mitre_search", [n["source"] for n in e["not_consulted"]])
        for flag in (False, None):
            u = self.run_for(beacon_findings=candidate_findings(False) if flag is False else None)
            self.assertNotIn("mitre_search", [x["tool"] for x in u["evidence"]])
            self.assertIn("mitre_search", [n["source"] for n in u["enrichment_findings"]["not_consulted"]])

    def test_reputation_is_never_called_and_its_absence_is_explicit(self):
        fake = d3.FakeRegistry(lambda n, a, i: self.registry.call(n, a))
        u = self.run_for(registry=fake, beacon_findings=candidate_findings())
        self.assertNotIn("reputation_lookup", [c[0] for c in fake.calls])
        rep = [n for n in u["enrichment_findings"]["not_consulted"] if n["source"] == "reputation_lookup"]
        self.assertEqual(len(rep), 1)
        self.assertEqual(rep[0]["status"], "not_consulted")
        self.assertIn("no external call was made", rep[0]["reason"])

    def test_a_port_without_a_curated_service_skips_the_service_lookup_explicitly(self):
        u = self.run_for(d3.make_alert(dport=59999))
        e = u["enrichment_findings"]
        self.assertEqual([x["tool"] for x in u["evidence"]], ["ip_info", "ip_info", "port_info"])
        self.assertEqual(e["status"], "ok")
        skipped = [n for n in e["not_consulted"] if n["source"] == "service_lookup"]
        self.assertEqual(len(skipped), 1)
        self.assertIn("no curated service", skipped[0]["reason"])
        self.assertIn("says nothing about how it is used", [f for f in e["findings"] if f["kind"] == "port_context"][0]["statement"])

    def test_tool_failures_are_listed_as_unavailable(self):
        real = self.registry

        def answer(name, args, i):
            if name == "ip_info" and args["ip"] == d1.BEACON_DST:
                return error_result(name, "unavailable", "gone")
            return real.call(name, args)
        u = self.run_for(registry=d3.FakeRegistry(answer))
        e = u["enrichment_findings"]
        self.assertEqual((e["status"], e["tool_errors"]), ("partial", 1))
        self.assertEqual(e["unavailable"], [{"source": "ip_info", "arguments": {"ip": d1.BEACON_DST}, "status": "unavailable", "code": "unavailable"}])
        self.assertEqual([f["metrics"]["role"] for f in e["findings"] if f["kind"] == "ip_context"], ["source"])
        self.assertEqual([x["code"] for x in u["errors"]], ["unavailable"])

    def test_the_destination_role_is_kept_when_the_source_lookup_fails(self):
        real = self.registry
        u = self.run_for(registry=d3.FakeRegistry(lambda n, a, i: error_result(n, "internal_error", "x") if i == 0 else real.call(n, a)))
        roles = [f["metrics"]["role"] for f in u["enrichment_findings"]["findings"] if f["kind"] == "ip_context"]
        self.assertEqual(roles, ["destination"])

    def test_every_call_failing(self):
        u = self.run_for(registry=d3.FakeRegistry(lambda n, a, i: error_result(n, "internal_error", "x")))
        e = u["enrichment_findings"]
        self.assertEqual((e["status"], e["findings"], e["tool_calls"]), ("failed", [], 3))
        self.assertEqual(len(e["unavailable"]), 3)
        self.assertTrue(any(n["source"] == "service_lookup" and "port_info failed" in n["reason"] for n in e["not_consulted"]))

    def test_malformed_tool_results_are_contained(self):
        for answer in (None, {"ok": True, "data": []}, {"ok": True, "data": {"services": "x"}}, {"ok": True, "data": {"unexpected": 1}}):
            u = self.run_for(registry=d3.FakeRegistry(lambda n, a, i, ans=answer: ans))
            self.assertIn(u["enrichment_findings"]["status"], ("failed", "partial", "ok"), repr(answer))
            json.dumps(u)
            if answer is None or answer == {"ok": True, "data": []}:
                self.assertEqual(u["enrichment_findings"]["status"], "failed")
                self.assertEqual({e["code"] for e in u["errors"]}, {"invalid_tool_result"})

    def test_an_exception_is_contained(self):
        class Boom:
            def call(self, *a):
                raise RuntimeError("secret detail")
        u = self.run_for(registry=Boom())
        self.assertEqual(u["enrichment_findings"]["status"], "failed")
        self.assertNotIn("secret", json.dumps(u))
        with mock.patch.object(enrich, "findings_from_evidence", side_effect=KeyError("secret")):
            u = self.run_for()
        self.assertEqual((u["enrichment_findings"]["status"], u["errors"][-1]["code"]), ("failed", "node_exception"))
        self.assertNotIn("secret", json.dumps(u))

    def test_protocol_is_passed_to_port_info_only_when_known(self):
        fake = d3.FakeRegistry(lambda n, a, i: self.registry.call(n, a))
        self.run_for(d3.make_alert(protocol=17), fake)
        self.assertEqual(fake.calls[2], ("port_info", {"port": 80, "protocol": "udp"}))
        fake = d3.FakeRegistry(lambda n, a, i: self.registry.call(n, a))
        self.run_for(d3.make_alert(protocol=1), fake)
        self.assertEqual(fake.calls[2], ("port_info", {"port": 80}))

    def test_evidence_continues_after_earlier_evidence_and_nothing_is_replaced(self):
        earlier = [{"index": 0, "tool": "a"}, {"index": 1, "tool": "b"}]
        u = self.run_for(evidence=earlier, errors=[{"node": "x", "code": "c", "message": "m"}], trace=["supervisor"])
        self.assertEqual(u["evidence"][:2], earlier)
        self.assertEqual([e["index"] for e in u["evidence"]], [0, 1, 2, 3, 4, 5])
        self.assertEqual(u["errors"], [{"node": "x", "code": "c", "message": "m"}])
        self.assertEqual(u["trace"], ["supervisor", "enrichment_agent"])
        self.assertEqual(u["enrichment_findings"]["findings"][0]["evidence_index"], 2)

    def test_deterministic_and_makes_no_network_call(self):
        a, b = self.run_for(beacon_findings=candidate_findings()), self.run_for(beacon_findings=candidate_findings())
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))   # urllib is patched to fail in Offline.setUp

    def test_findings_do_not_name_an_attack_or_give_a_verdict(self):
        text = json.dumps(self.run_for()["enrichment_findings"]).lower()
        for word in ("malicious", "benign", "verdict", "severity", "confirmed"):
            self.assertNotIn(word, text, word)


# ------------------------------------------------------------------------------------------------ supervisor routing
class RoutingTests(Offline):
    def decide(self, **changes):
        return supervisor.decide(state_for(**changes))

    def after_traffic(self, evidence=None, status="ok", **changes):
        base = dict(status="running", supervisor_visits=1, trace=["supervisor", "traffic_analyst"], traffic_findings={"status": status}, evidence=evidence if evidence is not None else [])
        base.update(changes)
        return base

    def test_every_alert_starts_with_the_traffic_analyst(self):
        d = self.decide()
        self.assertEqual((d["route"], d["status"], d["errors"]), ("traffic_analyst", "running", []))
        self.assertIn("starts with the traffic analyst", d["reason"])

    def test_repeat_contact_routes_to_the_beacon_analyst(self):
        for flows in (2, 3, 50):
            d = self.decide(**self.after_traffic([src_summary_evidence(flows)]))
            self.assertEqual((d["route"], d["status"]), ("c2_beacon_analyst", "running"), flows)
            self.assertIn(str(flows) + " flows", d["reason"])

    def test_without_repeat_contact_the_beacon_analyst_is_skipped_with_a_reason(self):
        for flows, evidence in ((1, src_summary_evidence(1)), (0, src_summary_evidence(0, distinct=1))):   # the second table is complete and omits the destination
            d = self.decide(**self.after_traffic([evidence]))
            self.assertEqual(d["route"], "enrichment_agent", flows)
            self.assertIn("C2 beaconing analyst skipped", d["reason"])
            self.assertIn("gate: at least 2", d["reason"])

    def test_an_unreadable_count_skips_the_beacon_analyst(self):
        for evidence in ([], [{"tool": "summarize_flows", "ok": False, "arguments": {"direction": "src"}, "data": None}], [{"tool": "summarize_flows", "ok": True, "arguments": {"direction": "src"}, "data": {"n_flows": 3}}],
                         [{"tool": "summarize_flows", "ok": True, "arguments": {"direction": "src"}, "data": {"top_destination_ips": "x"}}], ["junk", None, 5]):
            d = self.decide(**self.after_traffic(evidence))
            self.assertEqual(d["route"], "enrichment_agent", repr(evidence))
            self.assertIn("could not be read", d["reason"])

    def test_repeat_contact_flows_reading(self):
        s = state_for()
        self.assertEqual(supervisor.repeat_contact_flows(dict(s, evidence=[src_summary_evidence(4)])), 4)
        self.assertEqual(supervisor.repeat_contact_flows(dict(s, evidence=[src_summary_evidence(0, distinct=1)])), 0)      # the table is complete and omits the destination
        self.assertIsNone(supervisor.repeat_contact_flows(dict(s, evidence=[src_summary_evidence(0, distinct=40)])))                            # the table is cut off: unknown
        bad = src_summary_evidence(3)
        bad["data"]["top_destination_ips"][0]["flows"] = True
        self.assertIsNone(supervisor.repeat_contact_flows(dict(s, evidence=[bad])))
        dst_only = src_summary_evidence(5)
        dst_only["arguments"]["direction"] = "dst"
        self.assertIsNone(supervisor.repeat_contact_flows(dict(s, evidence=[dst_only])))                                                        # only the source summary counts

    def test_a_failed_traffic_analysis_ends_the_run_and_nothing_else_runs(self):
        for status in ("failed", "weird", None):
            d = self.decide(**self.after_traffic([src_summary_evidence(5)], status=status))
            self.assertEqual((d["route"], d["status"]), ("end", "failed"), status)
            self.assertIn("no other agent was run", d["reason"])

    def test_the_beacon_analyst_runs_before_enrichment_and_enrichment_before_the_end(self):
        s = self.after_traffic([src_summary_evidence(3)], trace=["supervisor", "traffic_analyst", "supervisor", "c2_beacon_analyst"], supervisor_visits=2, beacon_findings={"status": "ok"})
        d = self.decide(**s)
        self.assertEqual((d["route"], d["status"]), ("enrichment_agent", "running"))
        s.update(trace=s["trace"] + ["supervisor", "enrichment_agent"], supervisor_visits=3, enrichment_findings={"status": "ok"})
        d = self.decide(**s)
        self.assertEqual((d["route"], d["status"], d["errors"]), ("end", "completed", []))

    def test_final_status_reflects_every_agent_that_ran(self):
        def final(traffic="ok", beacon="ok", enrichment="ok", ran_beacon=True):
            trace = ["supervisor", "traffic_analyst", "supervisor"] + (["c2_beacon_analyst", "supervisor"] if ran_beacon else []) + ["enrichment_agent"]
            return self.decide(status="running", supervisor_visits=4, trace=trace, traffic_findings={"status": traffic}, beacon_findings={"status": beacon} if ran_beacon else None,
                               enrichment_findings={"status": enrichment})["status"]
        self.assertEqual(final(), "completed")
        self.assertEqual(final(ran_beacon=False), "completed")
        self.assertEqual(final(traffic="partial"), "completed_with_errors")
        self.assertEqual(final(beacon="partial"), "completed_with_errors")
        self.assertEqual(final(beacon="failed"), "completed_with_errors")
        self.assertEqual(final(enrichment="partial"), "completed_with_errors")
        self.assertEqual(final(enrichment="failed"), "completed_with_errors")

    def test_an_agent_that_ran_and_left_nothing_is_an_error_and_is_not_run_again(self):
        # the beacon analyst ran (it is in the trace) but beacon_findings is None: the supervisor moves on to enrichment and never routes back
        s = self.after_traffic([src_summary_evidence(3)], trace=["supervisor", "traffic_analyst", "supervisor", "c2_beacon_analyst"], supervisor_visits=2)
        self.assertEqual(self.decide(**s)["route"], "enrichment_agent")
        s.update(trace=s["trace"] + ["supervisor", "enrichment_agent"], supervisor_visits=3, enrichment_findings={"status": "ok"})
        d = self.decide(**s)
        self.assertEqual((d["route"], d["status"]), ("end", "completed_with_errors"))
        self.assertEqual([(e["code"], e["node"]) for e in d["errors"]], [("no_findings", "supervisor")])
        self.assertIn("C2 beaconing analyst", d["errors"][0]["message"])
        # the same for the enrichment agent
        s2 = self.after_traffic([src_summary_evidence(0)], trace=["supervisor", "traffic_analyst", "supervisor", "enrichment_agent"], supervisor_visits=2)
        d = self.decide(**s2)
        self.assertEqual((d["route"], d["status"]), ("end", "completed_with_errors"))
        self.assertIn("enrichment agent", d["errors"][0]["message"])

    def test_the_missing_findings_error_is_added_only_once(self):
        s = self.after_traffic([src_summary_evidence(0)], trace=["supervisor", "traffic_analyst", "supervisor", "enrichment_agent"], supervisor_visits=2)
        u = supervisor.supervisor_node(dict(state_for(), **s))
        self.assertEqual(len(u["errors"]), 1)
        again = supervisor.supervisor_node(dict(state_for(), **dict(s, errors=u["errors"], status=u["status"])))
        self.assertEqual(len(again["errors"]), 1)            # terminal state: nothing is added again
        s["errors"] = list(u["errors"])
        self.assertEqual(supervisor.decide(state_for(**s))["errors"], [])   # already recorded

    def test_the_loop_guard_still_stops_a_runaway(self):
        d = self.decide(status="running", supervisor_visits=S.MAX_SUPERVISOR_VISITS)
        self.assertEqual((d["route"], d["status"], [e["code"] for e in d["errors"]]), ("end", "failed", ["loop_guard"]))

    def test_terminal_states_stay_terminal(self):
        for status in S.TERMINAL_STATUSES:
            d = self.decide(status=status, supervisor_visits=3)
            self.assertEqual((d["route"], d["status"], d["errors"]), ("end", status, []))

    def test_every_decision_is_logged_with_its_reason(self):
        u = supervisor.supervisor_node(state_for())
        self.assertEqual(u["routing"], [{"visit": 1, "route": "traffic_analyst", "reason": "every alert starts with the traffic analyst"}])
        u2 = supervisor.supervisor_node(dict(state_for(), **self.after_traffic([src_summary_evidence(3)]), routing=u["routing"]))
        self.assertEqual([r["visit"] for r in u2["routing"]], [1, 2])
        self.assertEqual(u2["routing"][1]["route"], "c2_beacon_analyst")

    def test_decisions_are_deterministic_and_do_not_mutate(self):
        s = dict(state_for(), **self.after_traffic([src_summary_evidence(3)]))
        before = copy.deepcopy(s)
        self.assertEqual(supervisor.supervisor_node(s), supervisor.supervisor_node(copy.deepcopy(s)))
        self.assertEqual(s, before)

    def test_the_conditional_edge_maps_every_route(self):
        for route in S.ROUTES:
            self.assertEqual(supervisor.route_from_supervisor({"next_node": route}), route)
        for odd in (None, "", "verdict", 3):
            self.assertEqual(supervisor.route_from_supervisor({"next_node": odd}), "end")


# ------------------------------------------------------------------------------------------------ exhaustive termination
def stub(key, node, outcome):
    """A stand-in agent. outcome: a status string (ok, partial, failed), 'nothing' (runs, leaves no findings) or 'silent' (does not even record that it ran)."""
    def run(state):
        if outcome == "silent":
            return {}
        update = {"trace": list(state["trace"]) + [node]}
        if outcome != "nothing":
            update[key] = {"status": outcome}
        return update
    return run


class TerminationTests(Offline):
    OUTCOMES = ("ok", "partial", "failed", "nothing", "silent")

    def test_every_combination_of_agent_outcomes_terminates_and_never_reruns_an_agent(self):
        count = 0
        for repeat, t, b, e in itertools.product((True, False), self.OUTCOMES, self.OUTCOMES, self.OUTCOMES):
            traffic_node = stub("traffic_findings", "traffic_analyst", t)
            if repeat:
                inner = traffic_node
                traffic_node = lambda state, inner=inner: dict(inner(state), evidence=[src_summary_evidence(3)])
            nodes = {S.NODE_C2_BEACON_ANALYST: stub("beacon_findings", "c2_beacon_analyst", b), S.NODE_ENRICHMENT_AGENT: stub("enrichment_findings", "enrichment_agent", e)}
            final, steps = d3.drive(S.new_state(d3.make_alert()), traffic_node, others=nodes)
            label = (repeat, t, b, e)
            self.assertIn(final["status"], S.TERMINAL_STATUSES, label)
            # The loop guard fires on the visit after the limit, so a node that never reports ends the run at MAX + 1 visits.
            self.assertLessEqual(final["supervisor_visits"], S.MAX_SUPERVISOR_VISITS + 1, label)
            self.assertLessEqual(steps, 2 * (S.MAX_SUPERVISOR_VISITS + 1), label)
            if "silent" in (t, b, e):
                # a node that does not even record that it ran cannot be told apart from one that never ran; only the loop guard stops it
                self.assertIn(final["status"], ("failed", "completed", "completed_with_errors"), label)
                if final["supervisor_visits"] > 4:
                    self.assertIn("loop_guard", [x["code"] for x in final["errors"]], label)
            else:
                for agent in ("traffic_analyst", "c2_beacon_analyst", "enrichment_agent"):
                    self.assertLessEqual(final["trace"].count(agent), 1, label)
                self.assertLessEqual(final["supervisor_visits"], 4, label)
            self.assertEqual(final["routing"][-1]["route"], "end", label)
            count += 1
        self.assertEqual(count, 2 * 5 ** 3)

    def test_a_clean_run_never_takes_more_than_four_supervisor_visits(self):
        final, steps = d3.drive(S.new_state(d3.make_alert()), stub("traffic_findings", "traffic_analyst", "ok"),
                                others={S.NODE_C2_BEACON_ANALYST: stub("beacon_findings", "c2_beacon_analyst", "ok"), S.NODE_ENRICHMENT_AGENT: stub("enrichment_findings", "enrichment_agent", "ok")})
        self.assertEqual(final["supervisor_visits"], 3)    # no evidence, so the beacon analyst is skipped: traffic, enrichment, end
        self.assertEqual(final["status"], "completed")


# ------------------------------------------------------------------------------------------------ whole paths with the real agents
class PathTests(Offline):
    def run_path(self, alert, registry=None):
        registry = registry or self.registry
        return d3.drive(S.new_state(alert), traffic_analyst.make_traffic_analyst(registry), others=d3.all_nodes(registry))[0]

    def test_path_with_repeat_contact_runs_all_three_agents(self):
        final = self.run_path(d3.make_alert())
        self.assertEqual((final["status"], final["trace"]), ("completed", FULL_PATH))
        self.assertEqual([r["route"] for r in final["routing"]], ["traffic_analyst", "c2_beacon_analyst", "enrichment_agent", "end"])
        self.assertEqual(final["beacon_findings"]["assessment"], "regular_intervals")
        self.assertTrue(final["beacon_findings"]["beacon_candidate"])
        self.assertIn("mitre_reference", [f["kind"] for f in final["enrichment_findings"]["findings"]])
        S.validate_state(final)
        json.dumps(final)

    def test_evidence_indices_are_unique_and_every_reference_resolves(self):
        final = self.run_path(d3.make_alert())
        self.assertEqual([e["index"] for e in final["evidence"]], list(range(len(final["evidence"]))))
        for key in ("traffic_findings", "beacon_findings", "enrichment_findings"):
            for f in final[key]["findings"]:
                self.assertTrue(final["evidence"][f["evidence_index"]]["ok"], (key, f["kind"]))

    def test_path_without_repeat_contact_skips_the_beacon_analyst(self):
        final = self.run_path(d3.make_alert(src=d1.SCAN_SRC, dst="10.0.0.99", dport=22, ts="2017-07-05 10:00:10"))
        self.assertEqual((final["status"], final["trace"]), ("completed", NO_BEACON_PATH))
        self.assertIsNone(final["beacon_findings"])
        self.assertIn("C2 beaconing analyst skipped", final["routing"][1]["reason"])
        self.assertIsNotNone(final["enrichment_findings"])
        self.assertNotIn("mitre_search", [e["tool"] for e in final["evidence"]])

    def test_an_alert_with_no_flows_in_the_store_still_completes(self):
        final = self.run_path(d3.make_alert(src="203.0.113.7", dst="203.0.113.8"))
        self.assertEqual((final["status"], final["trace"]), ("completed", NO_BEACON_PATH))
        self.assertEqual([f["kind"] for f in final["traffic_findings"]["findings"]], ["no_source_flows", "no_destination_flows"])

    def test_a_scan_runs_the_beacon_analyst_but_gets_no_mitre_reference(self):
        final = self.run_path(d3.make_alert(src=d1.SCAN_SRC, dst=d1.SCAN_DST, dport=1, ts="2017-07-05 10:00:10"))
        self.assertEqual(final["trace"], FULL_PATH)
        self.assertEqual((final["beacon_findings"]["assessment"], final["beacon_findings"]["beacon_candidate"]), ("regular_intervals", False))
        self.assertNotIn("mitre_search", [e["tool"] for e in final["evidence"]])

    def test_irregular_traffic_runs_the_beacon_analyst_and_reports_it_is_not_periodic(self):
        final = self.run_path(d3.make_alert(src=d1.IRREG_SRC, dst=d1.IRREG_DST, dport=443, ts="2017-07-05 10:03:00"))
        self.assertEqual((final["trace"], final["beacon_findings"]["assessment"]), (FULL_PATH, "irregular_intervals"))

    def test_path_with_a_failed_traffic_analysis_stops_early(self):
        final = self.run_path(d3.make_alert(), build_registry())
        self.assertEqual((final["status"], final["trace"]), ("failed", FAILED_PATH))
        self.assertIsNone(final["beacon_findings"])
        self.assertIsNone(final["enrichment_findings"])
        self.assertEqual(len(final["errors"]), 2)

    def test_a_failing_beacon_analyst_does_not_stop_enrichment(self):
        real = self.registry
        registry = d3.FakeRegistry(lambda n, a, i: error_result(n, "internal_error", "boom") if n == "beacon_stats" else real.call(n, a))
        final = self.run_path(d3.make_alert(), registry)
        self.assertEqual((final["status"], final["trace"]), ("completed_with_errors", FULL_PATH))
        self.assertEqual(final["beacon_findings"]["status"], "failed")
        self.assertEqual(final["enrichment_findings"]["status"], "ok")
        self.assertEqual([e["node"] for e in final["errors"]], ["c2_beacon_analyst", "c2_beacon_analyst"])

    def test_a_failing_enrichment_agent_is_reported_but_the_traffic_work_stands(self):
        real = self.registry
        registry = d3.FakeRegistry(lambda n, a, i: error_result(n, "internal_error", "boom") if n in ("ip_info", "port_info") else real.call(n, a))
        final = self.run_path(d3.make_alert(), registry)
        # ip_info and port_info fail; the MITRE lookups still succeed, so the enrichment agent is partial, not failed
        self.assertEqual((final["status"], final["traffic_findings"]["status"], final["enrichment_findings"]["status"]), ("completed_with_errors", "ok", "partial"))
        self.assertEqual({u["source"] for u in final["enrichment_findings"]["unavailable"]}, {"ip_info", "port_info"})

    def test_deterministic_and_the_reputation_tool_is_never_called(self):
        real = self.registry
        fake = d3.FakeRegistry(lambda n, a, i: real.call(n, a))
        a = self.run_path(d3.make_alert(), fake)
        b = self.run_path(d3.make_alert())
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        self.assertNotIn("reputation_lookup", [c[0] for c in fake.calls])
        self.assertEqual({c[0] for c in fake.calls}, {"summarize_flows", "beacon_stats", "ip_info", "port_info", "service_lookup", "mitre_search", "mitre_lookup"})

    def test_every_tool_call_uses_arguments_the_tools_accept(self):
        # no call made by any agent may be rejected as invalid input on a normal alert
        final = self.run_path(d3.make_alert())
        self.assertEqual([e for e in final["errors"]], [])
        self.assertTrue(all(e["ok"] for e in final["evidence"]))


@unittest.skipUnless(HAVE_LANGGRAPH, "LangGraph is not installed: pip install -r requirements-week3.txt")
class LangGraphDay4Tests(Offline):
    def test_the_compiled_graph_matches_the_hand_driven_loop_on_every_path(self):
        graph = graph_module.build_graph(self.registry)
        for alert in (d3.make_alert(), d3.make_alert(src=d1.SCAN_SRC, dst="10.0.0.99", dport=22, ts="2017-07-05 10:00:10"), d3.make_alert(src="203.0.113.7", dst="203.0.113.8"),
                      d3.make_alert(src=d1.IRREG_SRC, dst=d1.IRREG_DST, dport=443, ts="2017-07-05 10:03:00")):
            a = graph_module.run_alert(graph, alert)
            b = d3.drive(S.new_state(alert), traffic_analyst.make_traffic_analyst(self.registry), others=d3.all_nodes(self.registry))[0]
            self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
            self.assertIn(a["status"], S.TERMINAL_STATUSES)

    def test_failure_paths_terminate_in_the_real_graph(self):
        final = graph_module.run_alert(graph_module.build_graph(build_registry()), d3.make_alert())
        self.assertEqual((final["status"], final["trace"]), ("failed", FAILED_PATH))

    def test_a_node_that_never_reports_cannot_loop_forever(self):
        for target in ("make_c2_beacon_analyst", "make_enrichment_agent"):
            with mock.patch.object(graph_module, target, return_value=lambda state: {}):
                graph = graph_module.build_graph(self.registry)
            final = graph_module.run_alert(graph, d3.make_alert())
            self.assertIn(final["status"], S.TERMINAL_STATUSES, target)
            self.assertIn("loop_guard", [e["code"] for e in final["errors"]], target)
            self.assertLessEqual(final["supervisor_visits"], S.MAX_SUPERVISOR_VISITS + 1)

    def test_the_recursion_limit_covers_the_longest_path(self):
        self.assertGreaterEqual(graph_module.RECURSION_LIMIT, 7)
        self.assertGreaterEqual(graph_module.RECURSION_LIMIT, 2 * (S.MAX_SUPERVISOR_VISITS + 1) - 1)   # also covers a runaway that the loop guard has to stop


# ------------------------------------------------------------------------------------------------ Day 3 regression
class Day3RegressionTests(Offline):
    def test_the_traffic_analyst_output_is_unchanged(self):
        u = traffic_analyst.make_traffic_analyst(self.registry)(S.new_state(d3.make_alert()))
        f = u["traffic_findings"]
        self.assertEqual((f["analyst"], f["status"], f["tool_calls"], f["tool_errors"]), ("traffic_analyst", "ok", 2, 0))
        self.assertEqual([x["kind"] for x in f["findings"]], ["source_activity", "port_concentration", "destination_fan_in"])
        self.assertEqual(f["findings"][1]["metrics"], {"top_port": 80, "top_port_flows": 10, "top_port_share": 1.0})
        self.assertEqual([e["index"] for e in u["evidence"]], [0, 1])
        self.assertEqual(traffic_analyst.plan_calls(d3.make_alert())[0][1], {"ip": d1.BEACON_SRC, "direction": "src", "around": ALERT_TIME, "window_minutes": 5})

    def test_the_traffic_analyst_findings_are_the_same_inside_the_full_graph(self):
        alone = traffic_analyst.make_traffic_analyst(self.registry)(S.new_state(d3.make_alert()))
        final = d3.drive(S.new_state(d3.make_alert()), traffic_analyst.make_traffic_analyst(self.registry), others=d3.all_nodes(self.registry))[0]
        self.assertEqual(final["traffic_findings"], alone["traffic_findings"])
        self.assertEqual(final["evidence"][:2], alone["evidence"])

    def test_day3_failure_semantics_hold(self):
        final = d3.drive(S.new_state(d3.make_alert()), traffic_analyst.make_traffic_analyst(build_registry()), others=d3.all_nodes(build_registry()))[0]
        self.assertEqual((final["status"], final["traffic_findings"]["status"], len(final["errors"])), ("failed", "failed", 2))
        self.assertEqual({e["code"] for e in final["errors"]}, {"unavailable"})

    def test_day3_loop_guard_and_missing_findings_hold(self):
        final, _ = d3.drive(S.new_state(d3.make_alert()), lambda state: {})
        self.assertEqual(final["status"], "failed")
        self.assertIn("loop_guard", [e["code"] for e in final["errors"]])
        final, _ = d3.drive(S.new_state(d3.make_alert()), lambda state: {"trace": state["trace"] + ["traffic_analyst"]})
        self.assertEqual(final["status"], "failed")
        self.assertIn("no_findings", [e["code"] for e in final["errors"]])

    def test_the_label_guard_still_holds(self):
        for name in ("label", "is_attack", "mitre_technique_id"):
            with self.assertRaises(ValueError):
                S.new_state(d3.make_alert(**{name: "x"}))

    def test_the_day3_runner_contract_is_kept(self):
        graph = mock.Mock()
        graph.invoke.side_effect = lambda state, config=None: {**state, "status": "completed", "trace": ["supervisor", "traffic_analyst", "supervisor"], "supervisor_visits": 2}
        finals = run_graph_dev.run_many(graph, d3.alerts_frame().head(2), self.store)
        summary = run_graph_dev.summarize(finals)
        for key in ("graph_version", "alerts", "alert_ids", "status_counts", "tool_calls", "errors", "llm_calls", "reputation_calls", "set", "frozen_set_opened"):
            self.assertIn(key, summary)
        self.assertEqual((summary["llm_calls"], summary["reputation_calls"], summary["set"], summary["frozen_set_opened"]), (0, 0, "dev", False))
        self.assertEqual(summary["path_counts"], {"traffic_analyst": 2})
        self.assertEqual(run_graph_dev.MAX_ALERTS_DAY3, 20)
        self.assertEqual(list(run_graph_dev.select_alerts(d3.alerts_frame(), 2)["alert_id"]), ["DEV-0001", "DEV-0002"])

    @unittest.skipUnless(HAVE_LANGGRAPH, "LangGraph is not installed")
    def test_a_small_dev_style_run_writes_the_day3_files_with_the_new_paths(self):
        with mock.patch.object(triage_inputs, "load_dev_alerts", return_value=d3.alerts_frame()), mock.patch.object(FlowStore, "from_dev", return_value=self.store), \
                tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "run")
            with mock.patch("sys.stdout"):
                self.assertEqual(run_graph_dev.main(["--n", "4", "--out", out]), 0)
            self.assertEqual(sorted(os.listdir(out)), ["results.jsonl", "summary.json"])
            summary = json.loads(d3.read_text(os.path.join(out, "summary.json")))
            self.assertEqual(summary["graph_version"], "v0.1")
            self.assertEqual(summary["status_counts"], {"completed": 4})
            self.assertEqual(summary["path_counts"], {"traffic_analyst>c2_beacon_analyst>enrichment_agent": 3, "traffic_analyst>enrichment_agent": 1})
            self.assertEqual((summary["llm_calls"], summary["reputation_calls"], summary["frozen_set_opened"]), (0, 0, False))
            for line in d3.read_text(os.path.join(out, "results.jsonl")).splitlines():
                S.validate_state(json.loads(line))

    def test_run_graph_dev_still_reads_only_the_dev_set(self):
        text = d3.read_text(os.path.join(ROOT, "src", "run_graph_dev.py"))
        self.assertIn("load_dev_alerts", text)
        self.assertIn("build_registry(flow_store=store)", text)
        for word in ("load_labels", "frozen_alerts", "SOC_FROZEN_UNLOCK", "eval_io", "ReputationTool", "from_env"):
            self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main()
