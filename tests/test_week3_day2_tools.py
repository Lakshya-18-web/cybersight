"""Week 3 Day 2: per-tool tests for the nine Day 1 tools, plus regression tests for the three defects found while writing them.

Covers valid and invalid inputs, empty results, boundary values, determinism and error behaviour. Everything is offline: urllib is blocked in
every test, the reputation tool is used only in its disabled form or with a fake fetch function, and the only flow data is synthetic.
No test opens a label file, the answer key or the frozen set.
"""
import os
import sys
import json
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

import numpy as np
import pandas as pd

import config
from tools import base, build_registry, FlowStore, FlowTools, EnrichmentTools, ReputationTool, MitreTools, classify_ip
from tools import reference_data, mitre_reference, reputation, flow_query

from tests import test_week3_day1 as d1

T0 = d1.T0


def flow_rows(specs):
    """specs: dicts with offset (seconds after T0) or ts, src, dst, and optional dport, sport, proto, fwd, dur."""
    rows = []
    for s in specs:
        row = {"flow_row": len(rows), "flow_id": "x-" + str(len(rows)), "timestamp": s["ts"] if "ts" in s else T0 + pd.Timedelta(seconds=s["offset"]), "src_ip": s["src"],
               "src_port": s.get("sport", 40000), "dst_ip": s["dst"], "dst_port": s.get("dport", 80), "protocol": s.get("proto", 6)}
        for name in config.DISPLAY_FEATURES:
            row[name] = 1.0
        row["Total Length of Fwd Packets"] = s.get("fwd", 100.0)
        row["Flow Duration"] = s.get("dur", 5.0)
        rows.append(row)
    return rows


def spec_for(tool_set, name):
    return {s.name: s for s in tool_set.specs()}[name]


class OfflineCase(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch("urllib.request.urlopen", side_effect=AssertionError("network call in a unit test"))
        self.urlopen = patcher.start()
        self.addCleanup(patcher.stop)

    def store_tools(self, rows):
        store = FlowStore(pd.DataFrame(rows))
        return store, {s.name: s for s in FlowTools(store).specs()}

    def ok(self, spec, args):
        result = spec.run(args)
        self.assertTrue(result["ok"], result)
        json.dumps(result)
        return result["data"]

    def code(self, spec, args):
        result = spec.run(args)
        self.assertFalse(result["ok"], result)
        return result["error"]["code"]


# ------------------------------------------------------------------------------------------------ regressions
class RegressionTests(OfflineCase):
    """Defects found by the Day 2 tests. Each was a case where a tool could raise instead of returning an error result, or accept bad input."""

    def test_mixed_type_argument_names_return_an_error_instead_of_raising(self):
        # Before: sorted() over {1, "a"} raised TypeError out of ToolSpec.run, breaking the 'tools never raise' contract.
        spec = spec_for(EnrichmentTools(), "port_info")
        for args in ({1: 2, "a": 3}, {None: 1, "b": 2}, {(1,): 1, "z": 2, 5.5: 1}):
            result = spec.run(args)
            self.assertEqual(result["error"]["code"], "invalid_input")
        self.assertEqual(build_registry().call("ip_info", {1: 2, "a": 3})["error"]["code"], "invalid_input")

    def test_unknown_argument_names_are_listed_in_a_stable_order(self):
        spec = spec_for(EnrichmentTools(), "port_info")
        message = spec.run({"port": 22, "zeta": 1, "alpha": 2, 3: 4})["error"]["message"]
        self.assertEqual(message, "unknown argument(s): 3, alpha, zeta")

    def test_a_failure_while_converting_the_result_is_contained(self):
        # Before: plain(data) ran outside the try block, so an unconvertible value raised out of run().
        class Broken:
            year = 2017

            def strftime(self, fmt):
                raise ValueError("cannot format")

            def __ne__(self, other):
                return False
        result = base.ToolSpec("t", "d", {}, lambda c: {"when": Broken()}).run({})
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "internal_error")
        self.assertIn("ValueError", result["error"]["message"])
        self.assertNotIn("cannot format", json.dumps(result))

    def test_a_missing_time_is_converted_to_null(self):
        # Before: pandas NaT has strftime but raises when called, so a flow with no timestamp broke the whole result.
        self.assertIsNone(base.plain(pd.NaT))
        self.assertEqual(base.plain({"a": [pd.NaT, pd.Timestamp("2017-07-05 01:02:03")]}), {"a": [None, "2017-07-05 01:02:03"]})

    def test_flows_without_a_timestamp_do_not_break_the_flow_tools(self):
        rows = flow_rows([{"offset": 0, "src": "10.0.0.1", "dst": "10.0.0.2"}, {"offset": 60, "src": "10.0.0.1", "dst": "10.0.0.2"}, {"offset": 120, "src": "10.0.0.1", "dst": "10.0.0.2"}])
        rows[1]["timestamp"] = None
        _, tools_ = self.store_tools(rows)
        q = self.ok(tools_["query_flows"], {"src_ip": "10.0.0.1"})
        self.assertEqual((q["total_matches"], [f["timestamp"] for f in q["flows"]]), (3, ["2017-07-05 10:00:00", "2017-07-05 10:02:00", None]))
        self.assertEqual(self.ok(tools_["summarize_flows"], {"ip": "10.0.0.1"})["n_flows"], 3)
        self.assertEqual(self.ok(tools_["beacon_stats"], {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"})["n_flows"], 3)
        self.assertEqual(self.ok(tools_["query_flows"], {"src_ip": "10.0.0.1", "start": "2017-07-05 00:00:00"})["total_matches"], 2)

    def test_unicode_digits_are_not_a_valid_technique_id(self):
        # Before: \d matched non-ASCII digits, so these passed the format check and came back as not_found with advice to check attack.mitre.org.
        spec = spec_for(MitreTools(), "mitre_lookup")
        for bad in ["T١١١٠", "T１１１０", "T1110.００１", "T²¹¹⁰"]:
            self.assertEqual(self.code(spec, {"technique_id": bad}), "invalid_input", bad)
        self.assertEqual(self.ok(spec, {"technique_id": "T1110"})["name"], "Brute Force")

    def test_non_ascii_addresses_were_and_stay_invalid(self):
        spec = spec_for(EnrichmentTools(), "ip_info")
        for bad in ["١.١.١.١", "１.１.１.１", "8.8.8.８"]:
            self.assertEqual(self.code(spec, {"ip": bad}), "invalid_input", bad)


# ------------------------------------------------------------------------------------------------ query_flows
class QueryFlowsTests(OfflineCase):
    def test_port_boundaries(self):
        rows = flow_rows([{"offset": 0, "src": "10.0.0.1", "dst": "10.0.0.2", "dport": 0, "sport": 65535}, {"offset": 1, "src": "10.0.0.1", "dst": "10.0.0.2", "dport": 65535, "sport": 0}])
        _, t = self.store_tools(rows)
        q = t["query_flows"]
        self.assertEqual(self.ok(q, {"dst_port": 0})["flows"][0]["flow_row"], 0)
        self.assertEqual(self.ok(q, {"dst_port": 65535})["flows"][0]["flow_row"], 1)
        self.assertEqual(self.ok(q, {"src_port": 0})["flows"][0]["flow_row"], 1)
        self.assertEqual(self.ok(q, {"src_port": 65535})["flows"][0]["flow_row"], 0)
        self.assertEqual(self.code(q, {"dst_port": -1}), "invalid_input")
        self.assertEqual(self.code(q, {"dst_port": 65536}), "invalid_input")

    def test_protocol_filter_and_boundaries(self):
        rows = flow_rows([{"offset": 0, "src": "10.0.0.1", "dst": "10.0.0.2", "proto": 1}, {"offset": 1, "src": "10.0.0.1", "dst": "10.0.0.2", "proto": 6},
                          {"offset": 2, "src": "10.0.0.1", "dst": "10.0.0.2", "proto": 17}])
        _, t = self.store_tools(rows)
        for proto, expected in ((1, 1), (6, 1), (17, 1), (0, 0), (255, 0)):
            self.assertEqual(self.ok(t["query_flows"], {"protocol": proto})["total_matches"], expected, proto)
        self.assertEqual(self.code(t["query_flows"], {"protocol": 256}), "invalid_input")
        self.assertEqual(self.code(t["query_flows"], {"protocol": -1}), "invalid_input")

    def test_limit_boundaries_with_more_matches_than_the_cap(self):
        rows = flow_rows([{"offset": i, "src": "10.1.1.1", "dst": "10.0.0.2", "dport": 1000 + i} for i in range(250)])
        _, t = self.store_tools(rows)
        q = t["query_flows"]
        one = self.ok(q, {"src_ip": "10.1.1.1", "limit": 1})
        self.assertEqual((one["total_matches"], one["returned"], one["truncated"], one["flows"][0]["dst_port"]), (250, 1, True, 1000))
        full = self.ok(q, {"src_ip": "10.1.1.1", "limit": 200})
        self.assertEqual((full["total_matches"], full["returned"], full["truncated"]), (250, 200, True))
        default = self.ok(q, {"src_ip": "10.1.1.1"})
        self.assertEqual(default["returned"], flow_query.DEFAULT_ROWS)
        exact = self.ok(q, {"src_ip": "10.1.1.1", "start": "2017-07-05 10:00:00", "end": "2017-07-05 10:00:09", "limit": 10})
        self.assertEqual((exact["total_matches"], exact["returned"], exact["truncated"]), (10, 10, False))
        self.assertEqual(self.code(q, {"src_ip": "10.1.1.1", "limit": 0}), "invalid_input")
        self.assertEqual(self.code(q, {"src_ip": "10.1.1.1", "limit": 201}), "invalid_input")

    def test_window_edges_are_inclusive_and_the_window_minimum_and_maximum_work(self):
        rows = flow_rows([{"offset": 60 * k, "src": "10.0.0.1", "dst": "10.0.0.2", "dport": 100 + k} for k in range(11)])
        _, t = self.store_tools(rows)
        q = t["query_flows"]
        d = self.ok(q, {"around": "2017-07-05 10:05:00", "window_minutes": 1})
        self.assertEqual([f["dst_port"] for f in d["flows"]], [104, 105, 106])
        self.assertEqual(self.ok(q, {"around": "2017-07-05 10:05:00", "window_minutes": 720})["total_matches"], 11)
        self.assertEqual(self.ok(q, {"around": "2017-07-05 10:05:30", "window_minutes": 1})["total_matches"], 2)  # 10:04:30 .. 10:06:30
        self.assertEqual(self.code(q, {"around": "2017-07-05 10:05:00", "window_minutes": 0}), "invalid_input")
        self.assertEqual(self.code(q, {"around": "2017-07-05 10:05:00", "window_minutes": 721}), "invalid_input")

    def test_window_minutes_is_ignored_without_around(self):
        rows = flow_rows([{"offset": 0, "src": "10.0.0.1", "dst": "10.0.0.2"}])
        _, t = self.store_tools(rows)
        self.assertEqual(self.ok(t["query_flows"], {"src_ip": "10.0.0.1", "window_minutes": 1})["total_matches"], 1)

    def test_start_and_end_alone_and_together(self):
        rows = flow_rows([{"offset": 60 * k, "src": "10.0.0.1", "dst": "10.0.0.2", "dport": 100 + k} for k in range(5)])
        _, t = self.store_tools(rows)
        q = t["query_flows"]
        self.assertEqual(self.ok(q, {"start": "2017-07-05 10:03:00"})["total_matches"], 2)
        self.assertEqual(self.ok(q, {"end": "2017-07-05 10:01:00"})["total_matches"], 2)
        self.assertEqual(self.ok(q, {"start": "2017-07-05 10:02:00", "end": "2017-07-05 10:02:00"})["total_matches"], 1)
        self.assertEqual(self.ok(q, {"start": "2017-07-05T10:02", "end": "2017-07-05 10:02"})["total_matches"], 1)
        self.assertEqual(self.ok(q, {"start": "2017-07-05 11:00:00"})["total_matches"], 0)
        self.assertEqual(self.code(q, {"start": "2017-07-05 10:03:00", "end": "2017-07-05 10:02:59"}), "invalid_input")

    def test_equal_timestamps_keep_a_stable_order_in_both_directions(self):
        rows = flow_rows([{"offset": 0, "src": "10.0.0.1", "dst": "10.0.0.2", "dport": 100 + k} for k in range(6)])
        _, t = self.store_tools(list(reversed(rows)))
        q = t["query_flows"]
        self.assertEqual([f["flow_row"] for f in self.ok(q, {"src_ip": "10.0.0.1"})["flows"]], [0, 1, 2, 3, 4, 5])
        self.assertEqual([f["flow_row"] for f in self.ok(q, {"src_ip": "10.0.0.1", "order": "desc"})["flows"]], [5, 4, 3, 2, 1, 0])
        self.assertEqual([f["flow_row"] for f in self.ok(q, {"src_ip": "10.0.0.1", "order": "desc", "limit": 2})["flows"]], [5, 4])

    def test_ipv6_addresses_match_in_any_notation(self):
        rows = flow_rows([{"offset": 0, "src": "2001:db8::1", "dst": "2001:db8::2"}, {"offset": 1, "src": "10.0.0.1", "dst": "10.0.0.2"}])
        _, t = self.store_tools(rows)
        for text in ("2001:db8::1", "2001:0DB8:0:0:0:0:0:1", " 2001:db8:0::1 "):
            self.assertEqual(self.ok(t["query_flows"], {"src_ip": text})["total_matches"], 1, text)
        self.assertEqual(self.ok(t["query_flows"], {"src_ip": "2001:db8::1", "dst_ip": "2001:db8::2"})["total_matches"], 1)
        self.assertEqual(self.ok(t["query_flows"], {"src_ip": "2001:db8::1", "dst_ip": "10.0.0.2"})["total_matches"], 0)

    def test_filters_are_combined_with_and(self):
        rows = flow_rows([{"offset": 0, "src": "10.0.0.1", "dst": "10.0.0.2", "dport": 80}, {"offset": 1, "src": "10.0.0.1", "dst": "10.0.0.3", "dport": 80},
                          {"offset": 2, "src": "10.0.0.9", "dst": "10.0.0.2", "dport": 80}, {"offset": 3, "src": "10.0.0.1", "dst": "10.0.0.2", "dport": 443}])
        _, t = self.store_tools(rows)
        q = t["query_flows"]
        self.assertEqual(self.ok(q, {"src_ip": "10.0.0.1"})["total_matches"], 3)
        self.assertEqual(self.ok(q, {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"})["total_matches"], 2)
        self.assertEqual(self.ok(q, {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80})["total_matches"], 1)
        self.assertEqual(self.ok(q, {"src_ip": "10.0.0.9", "dst_ip": "10.0.0.3"})["total_matches"], 0)

    def test_returned_values_are_plain_json_types(self):
        rows = flow_rows([{"offset": 0, "src": "10.0.0.1", "dst": "10.0.0.2"}])
        _, t = self.store_tools(rows)
        flow = self.ok(t["query_flows"], {"src_ip": "10.0.0.1", "fields": "all"})["flows"][0]
        for key, value in flow.items():
            self.assertIn(type(value), (int, float, str, type(None)), key)
        self.assertIsInstance(flow["timestamp"], str)
        self.assertIsInstance(flow["flow_row"], int)
        self.assertIsInstance(flow["src_port"], int)

    def test_missing_feature_values_become_null(self):
        rows = flow_rows([{"offset": 0, "src": "10.0.0.1", "dst": "10.0.0.2"}])
        rows[0]["Flow Duration"] = float("nan")
        rows[0]["Flow Bytes/s"] = float("inf")
        _, t = self.store_tools(rows)
        flow = self.ok(t["query_flows"], {"src_ip": "10.0.0.1"})["flows"][0]
        self.assertIsNone(flow["Flow Duration"])
        self.assertIsNone(flow["Flow Bytes/s"])

    def test_queries_never_change_the_store(self):
        store, t = self.store_tools(d1.make_rows())
        before = store.frame.copy()
        for args in ({"src_ip": d1.BEACON_SRC}, {"dst_port": 80, "order": "desc"}, {"around": "2017-07-05 10:05:00", "fields": "all"}):
            t["query_flows"].run(args)
            t["summarize_flows"].run({"ip": d1.BEACON_SRC})
            t["beacon_stats"].run({"src_ip": d1.BEACON_SRC, "dst_ip": d1.BEACON_DST})
        pd.testing.assert_frame_equal(store.frame, before)

    def test_empty_and_single_row_stores(self):
        empty = FlowStore(pd.DataFrame(flow_rows([{"offset": 0, "src": "10.0.0.1", "dst": "10.0.0.2"}])).iloc[0:0])
        t = {s.name: s for s in FlowTools(empty).specs()}
        d = self.ok(t["query_flows"], {"src_ip": "10.0.0.1"})
        self.assertEqual((d["total_matches"], d["flows"], len(empty)), (0, [], 0))
        self.assertEqual(self.ok(t["summarize_flows"], {"ip": "10.0.0.1"})["n_flows"], 0)
        self.assertEqual(self.ok(t["beacon_stats"], {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"})["n_flows"], 0)
        _, one = self.store_tools(flow_rows([{"offset": 0, "src": "10.0.0.1", "dst": "10.0.0.2"}]))
        self.assertEqual(self.ok(one["query_flows"], {"src_ip": "10.0.0.1"})["returned"], 1)
        b = self.ok(one["beacon_stats"], {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"})
        self.assertEqual((b["n_flows"], b["span_seconds"], b["intervals_seconds"], b["forward_bytes"]["std"]), (1, 0.0, None, None))

    def test_a_store_with_identifier_columns_only(self):
        frame = pd.DataFrame(flow_rows([{"offset": 0, "src": "10.0.0.1", "dst": "10.0.0.2"}, {"offset": 60, "src": "10.0.0.1", "dst": "10.0.0.2"}]))[flow_query.ID_COLUMNS]
        t = {s.name: s for s in FlowTools(FlowStore(frame)).specs()}
        flow = self.ok(t["query_flows"], {"src_ip": "10.0.0.1", "fields": "all"})["flows"][0]
        self.assertEqual(list(flow), flow_query.ID_COLUMNS)
        self.assertEqual(self.ok(t["summarize_flows"], {"ip": "10.0.0.1"})["feature_summary"], {})
        b = self.ok(t["beacon_stats"], {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"})
        self.assertEqual((b["forward_bytes"], b["flow_duration"], b["intervals_seconds"]["count"]), (None, None, 1))

    def test_output_is_identical_on_repeat_and_independent_of_input_row_order(self):
        rows = d1.make_rows()
        a = {s.name: s for s in FlowTools(FlowStore(pd.DataFrame(rows))).specs()}
        b = {s.name: s for s in FlowTools(FlowStore(pd.DataFrame(list(reversed(rows))))).specs()}
        for name, args in [("query_flows", {"src_ip": d1.SCAN_SRC, "fields": "all"}), ("summarize_flows", {"ip": d1.SCAN_DST, "direction": "dst"}),
                           ("beacon_stats", {"src_ip": d1.BEACON_SRC, "dst_ip": d1.BEACON_DST})]:
            first = a[name].run(args)
            self.assertEqual(first, a[name].run(args))
            self.assertEqual(first, b[name].run(args), name)

    def test_a_time_zone_aware_store_never_raises_out_of_a_tool(self):
        frame = pd.DataFrame(d1.make_rows())
        frame["timestamp"] = pd.to_datetime(frame["timestamp"]).dt.tz_localize("UTC")
        t = {s.name: s for s in FlowTools(FlowStore(frame)).specs()}
        result = t["query_flows"].run({"start": "2017-07-05 10:00:00"})
        self.assertIn(result["ok"], (True, False))
        self.assertEqual(sorted(result), ["data", "error", "ok", "tool"])


# ------------------------------------------------------------------------------------------------ summarize_flows
class SummarizeFlowsTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.store, self.t = self.store_tools(d1.make_rows())
        self.s = self.t["summarize_flows"]

    def test_counts_match_the_store(self):
        d = self.ok(self.s, {"ip": d1.SCAN_DST, "direction": "dst"})
        expected = self.store.frame[self.store.frame["dst_ip"] == d1.SCAN_DST]
        self.assertEqual((d["n_flows"], d["distinct_source_ips"], d["distinct_destination_ports"]), (len(expected), expected["src_ip"].nunique(), expected["dst_port"].nunique()))

    def test_feature_statistics_match_pandas(self):
        d = self.ok(self.s, {"ip": d1.IRREG_SRC})
        found = self.store.frame[self.store.frame["src_ip"] == d1.IRREG_SRC]["Total Length of Fwd Packets"]
        stats = d["feature_summary"]["Total Length of Fwd Packets"]
        self.assertEqual(stats, {"mean": round(float(found.mean()), 6), "median": float(found.median()), "min": float(found.min()), "max": float(found.max())})
        self.assertEqual(set(d["feature_summary"]), set(config.DISPLAY_FEATURES))

    def test_missing_values_are_ignored_in_the_statistics(self):
        rows = flow_rows([{"offset": i, "src": "10.0.0.1", "dst": "10.0.0.2", "dur": 10.0 * (i + 1)} for i in range(3)])
        rows[1]["Flow Duration"] = float("nan")
        _, t = self.store_tools(rows)
        stats = self.ok(t["summarize_flows"], {"ip": "10.0.0.1"})["feature_summary"]["Flow Duration"]
        self.assertEqual(stats, {"mean": 20.0, "median": 20.0, "min": 10.0, "max": 30.0})
        rows[0]["Flow Duration"] = rows[2]["Flow Duration"] = float("nan")
        _, t = self.store_tools(rows)
        self.assertEqual(self.ok(t["summarize_flows"], {"ip": "10.0.0.1"})["feature_summary"]["Flow Duration"], {"mean": None, "median": None, "min": None, "max": None})

    def test_a_host_that_is_both_source_and_destination_is_counted_once_for_either(self):
        rows = flow_rows([{"offset": 0, "src": "10.0.0.1", "dst": "10.0.0.1"}, {"offset": 1, "src": "10.0.0.1", "dst": "10.0.0.2"}, {"offset": 2, "src": "10.0.0.3", "dst": "10.0.0.1"}])
        _, t = self.store_tools(rows)
        s = t["summarize_flows"]
        self.assertEqual(self.ok(s, {"ip": "10.0.0.1", "direction": "src"})["n_flows"], 2)
        self.assertEqual(self.ok(s, {"ip": "10.0.0.1", "direction": "dst"})["n_flows"], 2)
        self.assertEqual(self.ok(s, {"ip": "10.0.0.1", "direction": "either"})["n_flows"], 3)

    def test_top_lists_are_capped_ranked_and_tie_broken_by_value(self):
        rows = flow_rows([{"offset": i, "src": "10.0.0.1", "dst": "10.0.1." + str(i % 12), "dport": 2000 - i % 15} for i in range(60)])
        _, t = self.store_tools(rows)
        d = self.ok(t["summarize_flows"], {"ip": "10.0.0.1"})
        self.assertEqual(len(d["top_destination_ports"]), flow_query.TOP_N)
        self.assertEqual(len(d["top_destination_ips"]), flow_query.TOP_N)
        counts = [p["flows"] for p in d["top_destination_ports"]]
        self.assertEqual(counts, sorted(counts, reverse=True))
        for group in (d["top_destination_ports"], d["top_destination_ips"]):
            key = "dst_port" if "dst_port" in group[0] else "dst_ip"
            for a, b in zip(group, group[1:]):
                if a["flows"] == b["flows"]:
                    self.assertLess(a[key], b[key])

    def test_protocol_counts_are_sorted_string_keys(self):
        rows = flow_rows([{"offset": 0, "src": "10.0.0.1", "dst": "10.0.0.2", "proto": 17}, {"offset": 1, "src": "10.0.0.1", "dst": "10.0.0.2", "proto": 6},
                          {"offset": 2, "src": "10.0.0.1", "dst": "10.0.0.2", "proto": 6}])
        _, t = self.store_tools(rows)
        d = self.ok(t["summarize_flows"], {"ip": "10.0.0.1"})
        self.assertEqual(list(d["protocol_counts"].items()), [("6", 2), ("17", 1)])

    def test_the_window_and_port_filters_are_echoed_and_applied(self):
        d = self.ok(self.s, {"ip": d1.BEACON_SRC, "around": "2017-07-05 10:05:00", "window_minutes": 2, "dst_port": 80})
        self.assertEqual((d["n_flows"], d["window_start"], d["window_end"], d["dst_port_filter"], d["direction"]), (5, "2017-07-05 10:03:00", "2017-07-05 10:07:00", 80, "src"))
        none = self.ok(self.s, {"ip": d1.BEACON_SRC, "dst_port": 81})
        self.assertEqual((none["n_flows"], none["top_destination_ports"]), (0, []))

    def test_no_window_means_the_whole_store(self):
        d = self.ok(self.s, {"ip": d1.BEACON_SRC})
        self.assertEqual((d["window_start"], d["window_end"], d["n_flows"]), (None, None, 10))

    def test_the_empty_summary_has_the_same_fields_as_a_full_one(self):
        full = self.ok(self.s, {"ip": d1.BEACON_SRC})
        empty = self.ok(self.s, {"ip": "10.200.200.200"})
        self.assertTrue(set(empty) <= set(full))
        self.assertTrue(set(full) - set(empty) <= {"note"})

    def test_invalid_input(self):
        for args in ({}, {"ip": ""}, {"ip": "x"}, {"ip": d1.BEACON_SRC, "direction": "up"}, {"ip": d1.BEACON_SRC, "dst_port": 70000}, {"ip": d1.BEACON_SRC, "around": "2017-07-05 10:00:00", "start": "2017-07-05 09:00:00"},
                     {"ip": d1.BEACON_SRC, "start": "2017-07-05 11:00:00", "end": "2017-07-05 10:00:00"}, {"ip": d1.BEACON_SRC, "window_minutes": 0}, {"ip": d1.BEACON_SRC, "extra": 1}):
            self.assertEqual(self.code(self.s, args), "invalid_input", args)

    def test_unavailable_without_a_store(self):
        self.assertEqual(self.code(spec_for(FlowTools(None), "summarize_flows"), {"ip": d1.BEACON_SRC}), "unavailable")


# ------------------------------------------------------------------------------------------------ beacon_stats
class BeaconStatsTests(OfflineCase):
    def run_series(self, offsets, **kw):
        rows = flow_rows([dict({"offset": o, "src": "10.0.0.1", "dst": "52.0.0.1"}, **kw) for o in offsets])
        _, t = self.store_tools(rows)
        return self.ok(t["beacon_stats"], {"src_ip": "10.0.0.1", "dst_ip": "52.0.0.1", "start": "2017-07-05 00:00:00"})

    def test_exact_statistics_for_a_nearly_regular_series(self):
        iv = self.run_series([0, 60, 120, 180, 242])["intervals_seconds"]
        self.assertEqual((iv["count"], iv["mean"], iv["median"], iv["std"], iv["min"], iv["max"], iv["cv"], iv["share_within_10pct_of_median"]), (4, 60.5, 60.0, 1.0, 60.0, 62.0, 0.0165, 1.0))

    def test_exact_statistics_for_a_bursty_series(self):
        iv = self.run_series([0, 10, 20, 30, 80])["intervals_seconds"]
        self.assertEqual((iv["mean"], iv["median"], iv["std"], iv["cv"], iv["share_within_10pct_of_median"]), (20.0, 10.0, 20.0, 1.0, 0.75))

    def test_the_number_of_flows_needed_for_interval_statistics(self):
        three = self.run_series([0, 30, 90])
        self.assertEqual((three["sufficient_for_interval_stats"], three["intervals_seconds"]["count"]), (False, 2))
        self.assertAlmostEqual(three["intervals_seconds"]["std"], 21.213203, places=6)
        four = self.run_series([0, 30, 90, 100])
        self.assertTrue(four["sufficient_for_interval_stats"])
        two = self.run_series([0, 30])
        self.assertEqual((two["intervals_seconds"]["count"], two["intervals_seconds"]["std"], two["intervals_seconds"]["cv"]), (1, None, None))
        one = self.run_series([0])
        self.assertEqual((one["intervals_seconds"], one["span_seconds"], one["n_flows"]), (None, 0.0, 1))

    def test_all_flows_at_one_instant(self):
        iv = self.run_series([0, 0, 0, 0, 0])["intervals_seconds"]
        self.assertEqual((iv["mean"], iv["median"], iv["std"], iv["zero_length_intervals"]), (0.0, 0.0, 0.0, 4))
        self.assertIsNone(iv["cv"])
        self.assertIsNone(iv["share_within_10pct_of_median"])
        self.assertIsNotNone(iv["caveat"])

    def test_the_caveat_appears_only_when_most_intervals_are_zero(self):
        self.assertIsNone(self.run_series([0, 0, 60, 120, 180])["intervals_seconds"]["caveat"])
        self.assertIsNotNone(self.run_series([0, 0, 0, 0, 60])["intervals_seconds"]["caveat"])

    def test_the_series_does_not_depend_on_row_order(self):
        rows = flow_rows([{"offset": o, "src": "10.0.0.1", "dst": "52.0.0.1"} for o in (0, 60, 120, 180, 240)])
        a = self.store_tools(rows)[1]["beacon_stats"].run({"src_ip": "10.0.0.1", "dst_ip": "52.0.0.1"})
        b = self.store_tools(list(reversed(rows)))[1]["beacon_stats"].run({"src_ip": "10.0.0.1", "dst_ip": "52.0.0.1"})
        self.assertEqual(a, b)

    def test_size_and_duration_statistics(self):
        rows = flow_rows([{"offset": 60 * i, "src": "10.0.0.1", "dst": "52.0.0.1", "fwd": 100.0 + 10 * i, "dur": 1.0 + i} for i in range(4)])
        _, t = self.store_tools(rows)
        d = self.ok(t["beacon_stats"], {"src_ip": "10.0.0.1", "dst_ip": "52.0.0.1"})
        self.assertEqual((d["forward_bytes"]["column"], d["forward_bytes"]["mean"], d["forward_bytes"]["min"], d["forward_bytes"]["max"]), ("Total Length of Fwd Packets", 115.0, 100.0, 130.0))
        self.assertAlmostEqual(d["forward_bytes"]["std"], 12.909944, places=6)
        self.assertEqual((d["flow_duration"]["mean"], d["flow_duration"]["max"]), (2.5, 4.0))

    def test_direction_matters(self):
        rows = flow_rows([{"offset": 60 * i, "src": "10.0.0.1", "dst": "52.0.0.1"} for i in range(5)])
        _, t = self.store_tools(rows)
        self.assertEqual(self.ok(t["beacon_stats"], {"src_ip": "52.0.0.1", "dst_ip": "10.0.0.1"})["n_flows"], 0)

    def test_the_window_limits_the_flows(self):
        rows = flow_rows([{"offset": 60 * i, "src": "10.0.0.1", "dst": "52.0.0.1"} for i in range(30)])
        _, t = self.store_tools(rows)
        b = t["beacon_stats"]
        args = {"src_ip": "10.0.0.1", "dst_ip": "52.0.0.1", "around": "2017-07-05 10:15:00"}
        self.assertEqual(self.ok(b, dict(args, window_minutes=1))["n_flows"], 3)
        self.assertEqual(self.ok(b, dict(args))["n_flows"], 30)  # default is 60 minutes
        self.assertEqual(self.ok(b, dict(args, window_minutes=720))["n_flows"], 30)
        d = self.ok(b, dict(args, window_minutes=2))
        self.assertEqual((d["n_flows"], d["window_start"], d["window_end"], d["first_flow"], d["last_flow"]), (5, "2017-07-05 10:13:00", "2017-07-05 10:17:00", "2017-07-05 10:13:00", "2017-07-05 10:17:00"))

    def test_the_destination_port_filter_separates_services(self):
        rows = flow_rows([{"offset": 60 * i, "src": "10.0.0.1", "dst": "52.0.0.1", "dport": 80} for i in range(4)] + [{"offset": 30 + 100 * i, "src": "10.0.0.1", "dst": "52.0.0.1", "dport": 443} for i in range(3)])
        _, t = self.store_tools(rows)
        b = t["beacon_stats"]
        self.assertEqual(self.ok(b, {"src_ip": "10.0.0.1", "dst_ip": "52.0.0.1", "dst_port": 80})["n_flows"], 4)
        self.assertEqual(self.ok(b, {"src_ip": "10.0.0.1", "dst_ip": "52.0.0.1", "dst_port": 443})["n_flows"], 3)
        self.assertEqual(self.ok(b, {"src_ip": "10.0.0.1", "dst_ip": "52.0.0.1"})["n_flows"], 7)

    def test_invalid_input(self):
        b = spec_for(FlowTools(FlowStore(pd.DataFrame(d1.make_rows()))), "beacon_stats")
        good = {"src_ip": d1.BEACON_SRC, "dst_ip": d1.BEACON_DST}
        for args in ({}, {"src_ip": d1.BEACON_SRC}, {"dst_ip": d1.BEACON_DST}, dict(good, dst_port=-1), dict(good, window_minutes=721), dict(good, around="x"),
                     dict(good, around="2017-07-05 10:00:00", end="2017-07-05 11:00:00"), dict(good, start="2017-07-05 12:00:00", end="2017-07-05 11:00:00"), dict(good, src_ip="1.2.3")):
            self.assertEqual(self.code(b, args), "invalid_input", args)

    def test_unavailable_without_a_store(self):
        self.assertEqual(self.code(spec_for(FlowTools(None), "beacon_stats"), {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}), "unavailable")


# ------------------------------------------------------------------------------------------------ ip_info, port_info, service_lookup
class IpInfoTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.spec = spec_for(EnrichmentTools(), "ip_info")

    def test_range_edges(self):
        edges = {"172.15.255.255": "public", "172.16.0.0": "private_rfc1918", "172.31.255.255": "private_rfc1918", "172.32.0.0": "public",
                 "10.0.0.0": "private_rfc1918", "10.255.255.255": "private_rfc1918", "9.255.255.255": "public", "11.0.0.0": "public",
                 "192.167.255.255": "public", "192.168.0.0": "private_rfc1918", "192.168.255.255": "private_rfc1918", "192.169.0.0": "public",
                 "100.63.255.255": "public", "100.64.0.0": "shared_address_space", "100.127.255.255": "shared_address_space", "100.128.0.0": "public",
                 "169.253.255.255": "public", "169.254.0.0": "link_local", "169.254.255.255": "link_local", "169.255.0.0": "public",
                 "126.255.255.255": "public", "127.0.0.0": "loopback", "127.255.255.255": "loopback", "128.0.0.0": "public",
                 "223.255.255.255": "public", "224.0.0.0": "multicast", "239.255.255.255": "multicast", "240.0.0.0": "reserved", "255.255.255.254": "reserved",
                 "255.255.255.255": "broadcast", "0.0.0.0": "this_network", "0.255.255.255": "this_network", "1.0.0.0": "public",
                 "198.17.255.255": "public", "198.18.0.0": "benchmarking", "198.19.255.255": "benchmarking", "198.20.0.0": "public",
                 "192.0.2.255": "documentation", "198.51.100.1": "documentation", "203.0.113.255": "documentation", "203.0.114.0": "public"}
        for address, kind in edges.items():
            self.assertEqual(classify_ip(address)[0], kind, address)

    def test_scope_follows_the_type(self):
        for address, scope in {"10.1.1.1": "internal", "8.8.8.8": "external", "127.0.0.1": "special", "fd00::1": "internal", "2606:4700::1111": "external", "ff02::1": "special"}.items():
            self.assertEqual(self.ok(self.spec, {"ip": address})["scope"], scope, address)

    def test_ipv6_forms_and_output_normalisation(self):
        d = self.ok(self.spec, {"ip": "2606:4700:0000:0000:0000:0000:0000:1111"})
        self.assertEqual((d["ip"], d["version"], d["address_type"], d["is_global"]), ("2606:4700::1111", 6, "public", True))
        self.assertEqual(self.ok(self.spec, {"ip": "::"})["address_type"], "unspecified")
        self.assertEqual(self.ok(self.spec, {"ip": "::1"})["address_type"], "loopback")
        self.assertEqual(self.ok(self.spec, {"ip": "fe80::abcd"})["address_type"], "link_local")
        self.assertEqual(self.ok(self.spec, {"ip": "FD12:3456::1"})["address_type"], "private_unique_local")
        self.assertEqual(self.ok(self.spec, {"ip": "2001:db8::1"})["address_type"], "documentation")

    def test_ipv4_is_reported_as_version_4(self):
        d = self.ok(self.spec, {"ip": "192.168.1.1"})
        self.assertEqual((d["version"], d["is_global"]), (4, False))

    def test_sightings_in_the_flow_store(self):
        rows = flow_rows([{"offset": 10, "src": "10.0.0.1", "dst": "52.0.0.1"}, {"offset": 20, "src": "52.0.0.1", "dst": "10.0.0.1"}, {"offset": 5, "src": "10.0.0.1", "dst": "10.0.0.1"},
                          {"offset": 40, "src": "10.0.0.2", "dst": "52.0.0.1"}])
        spec = spec_for(EnrichmentTools(FlowStore(pd.DataFrame(rows))), "ip_info")
        a = self.ok(spec, {"ip": "10.0.0.1"})["observed_in_flow_store"]
        self.assertEqual(a, {"flows_as_source": 2, "flows_as_destination": 2, "first_seen": "2017-07-05 10:00:05", "last_seen": "2017-07-05 10:00:20"})
        b = self.ok(spec, {"ip": "52.0.0.1"})["observed_in_flow_store"]
        self.assertEqual((b["flows_as_source"], b["flows_as_destination"], b["last_seen"]), (1, 2, "2017-07-05 10:00:40"))
        c = self.ok(spec, {"ip": "9.9.9.9"})["observed_in_flow_store"]
        self.assertEqual(c, {"flows_as_source": 0, "flows_as_destination": 0, "first_seen": None, "last_seen": None})

    def test_an_empty_store_reports_no_sightings(self):
        frame = pd.DataFrame(flow_rows([{"offset": 0, "src": "10.0.0.1", "dst": "10.0.0.2"}])).iloc[0:0]
        spec = spec_for(EnrichmentTools(FlowStore(frame)), "ip_info")
        self.assertEqual(self.ok(spec, {"ip": "10.0.0.1"})["observed_in_flow_store"]["flows_as_source"], 0)

    def test_invalid_input(self):
        for args in ({}, {"ip": None}, {"ip": ""}, {"ip": "256.0.0.1"}, {"ip": "1.2.3.4/24"}, {"ip": "1.2.3.4:80"}, {"ip": "localhost"}, {"ip": 8888}, {"ip": ["8.8.8.8"]},
                     {"ip": "8.8.8.8", "port": 80}, {"ip": "x" * 201}):
            self.assertEqual(self.code(self.spec, args), "invalid_input", args)


class PortInfoTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.spec = spec_for(EnrichmentTools(), "port_info")

    def test_every_curated_service_is_returned_for_its_port(self):
        for (port, proto), names in reference_data.PORTS.items():
            for variant in ({"port": port}, {"port": port, "protocol": proto}):
                d = self.ok(self.spec, variant)
                found = {(s["service"], s["protocol"]) for s in d["services"]}
                for name in names:
                    self.assertIn((name, proto), found, (port, proto, name))
                self.assertTrue(d["in_curated_table"])
                self.assertIsNone(d["note"])

    def test_category_boundaries(self):
        for port, category in ((0, "reserved"), (1, "well_known"), (1023, "well_known"), (1024, "registered"), (49151, "registered"), (49152, "dynamic_private"), (65535, "dynamic_private")):
            self.assertEqual(self.ok(self.spec, {"port": port})["category"], category, port)

    def test_port_zero_and_the_top_port_are_valid(self):
        self.assertEqual(self.ok(self.spec, {"port": 0})["services"], [])
        self.assertEqual(self.ok(self.spec, {"port": 65535})["services"], [])

    def test_protocol_filter_is_case_insensitive_and_exclusive(self):
        self.assertEqual([s["protocol"] for s in self.ok(self.spec, {"port": 53, "protocol": "TCP"})["services"]], ["tcp"])
        self.assertEqual([s["protocol"] for s in self.ok(self.spec, {"port": 123, "protocol": "udp"})["services"]], ["udp"])
        self.assertEqual(self.ok(self.spec, {"port": 123, "protocol": "tcp"})["services"], [])
        self.assertEqual(self.ok(self.spec, {"port": 123, "protocol": "tcp"})["protocol_filter"], "tcp")

    def test_service_order_is_stable(self):
        a = self.ok(self.spec, {"port": 53})["services"]
        self.assertEqual([(s["service"], s["protocol"]) for s in a], [("dns", "tcp"), ("dns", "udp")])
        self.assertEqual(a, self.ok(self.spec, {"port": 53})["services"])

    def test_an_unlisted_port_is_flagged_not_guessed(self):
        d = self.ok(self.spec, {"port": 4444})
        self.assertEqual((d["in_curated_table"], d["services"], d["category"]), (False, [], "registered"))
        self.assertIn("says nothing", d["note"])
        self.assertEqual(d["source"], reference_data.SOURCE_NOTE)

    def test_invalid_input(self):
        for args in ({}, {"port": None}, {"port": -1}, {"port": 65536}, {"port": 22.0}, {"port": "22"}, {"port": True}, {"port": [22]}, {"port": 22, "protocol": "icmp"},
                     {"port": 22, "protocol": ""}, {"port": 22, "protocol": 6}, {"port": 22, "service": "ssh"}):
            self.assertEqual(self.code(self.spec, args), "invalid_input", args)


class ServiceLookupTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.spec = spec_for(EnrichmentTools(), "service_lookup")

    def test_every_curated_name_and_alias_is_found(self):
        for name, row in reference_data.SERVICES.items():
            d = self.ok(self.spec, {"name": name})
            self.assertEqual((d["match"], d["services"][0]["name"], d["services"][0]["ports"]), ("exact", name, row["ports"]))
            for alias in row["aliases"]:
                d = self.ok(self.spec, {"name": alias})
                self.assertEqual((d["match"], d["services"][0]["name"]), ("alias", name), alias)

    def test_case_and_surrounding_space_do_not_matter(self):
        for text in ("SSH", "Ssh", "  ssh  ", "ssh\t"):
            self.assertEqual(self.ok(self.spec, {"name": text})["services"][0]["name"], "ssh", repr(text))

    def test_partial_matches_are_sorted_capped_and_stable(self):
        d = self.ok(self.spec, {"name": "s"})
        self.assertEqual(d["match"], "partial")
        names = [s["name"] for s in d["services"]]
        self.assertEqual(names, sorted(names))
        self.assertLessEqual(len(names), 5)
        self.assertEqual(d, self.ok(self.spec, {"name": "s"}))
        d2 = self.ok(self.spec, {"name": "tp"})
        self.assertEqual(d2["match"], "partial")
        self.assertIn("ftp", [s["name"] for s in d2["services"]])

    def test_the_exact_match_wins_over_partial_matches(self):
        d = self.ok(self.spec, {"name": "ftp"})
        self.assertEqual((d["match"], len(d["services"])), ("exact", 1))
        self.assertEqual(d["services"][0]["ports"], [{"port": 21, "protocol": "tcp"}])

    def test_unknown_names_are_not_found(self):
        for name in ("no-such-service", "zzz", "sshh", "22", "ssh!"):
            self.assertEqual(self.code(self.spec, {"name": name}), "not_found", name)
        r = self.spec.run({"name": "zzz"})
        self.assertIn("zzz", r["error"]["message"])
        self.assertIsNone(r["data"])

    def test_invalid_input(self):
        for args in ({}, {"name": None}, {"name": ""}, {"name": "   "}, {"name": 22}, {"name": ["ssh"]}, {"name": "x" * 51}, {"name": "ss\x00h"}, {"name": "ssh", "port": 22}):
            self.assertEqual(self.code(self.spec, args), "invalid_input", args)

    def test_a_returned_service_cannot_be_used_to_change_the_table(self):
        d = self.ok(self.spec, {"name": "ssh"})
        d["services"][0]["ports"].append({"port": 1, "protocol": "tcp"})
        d["services"][0]["aliases"].append("x")
        self.assertEqual(reference_data.SERVICES["ssh"]["ports"], [{"port": 22, "protocol": "tcp"}])
        self.assertEqual(self.ok(self.spec, {"name": "ssh"})["services"][0]["ports"], [{"port": 22, "protocol": "tcp"}])


# ------------------------------------------------------------------------------------------------ reputation_lookup (offline)
class ReputationDisabledTests(OfflineCase):
    FIELDS = ["cache_hit", "ip", "provider", "reason", "reputation", "reputation", "source", "status"]

    def test_disabled_in_every_way_it_can_be_left_unconfigured(self):
        tools_ = [ReputationTool(), ReputationTool(api_key=""), ReputationTool(api_key=None), ReputationTool.from_env({}), ReputationTool.from_env({reputation.ENV_KEY: ""}),
                  ReputationTool.from_env({reputation.ENV_KEY: "   "}), ReputationTool.from_env({"OTHER": "x"})]
        for tool in tools_:
            self.assertFalse(tool.enabled)
            d = self.ok(tool.specs()[0], {"ip": "8.8.8.8"})
            self.assertEqual((d["status"], d["reputation"], d["cache_hit"], d["provider"]), ("disabled", None, False, "abuseipdb"))
            self.assertIn(reputation.ENV_KEY, d["reason"])
            self.assertEqual((tool.calls_made, len(tool.cache)), (0, 0))
        self.urlopen.assert_not_called()

    def test_the_result_has_a_fixed_set_of_fields_in_every_state(self):
        fields = sorted(set(self.FIELDS))
        states = {"disabled": ReputationTool(), "ok": ReputationTool(fetch=lambda ip, timeout: {"abuse_confidence_score": 1}),
                  "unavailable": ReputationTool(fetch=lambda ip, timeout: (_ for _ in ()).throw(reputation.ReputationFetchError("down")))}
        for status, tool in states.items():
            d = self.ok(tool.specs()[0], {"ip": "8.8.8.8"})
            self.assertEqual((sorted(d), d["status"]), (fields, status))
        d = self.ok(ReputationTool().specs()[0], {"ip": "10.0.0.1"})
        self.assertEqual((sorted(d), d["status"]), (fields, "not_applicable"))

    def test_private_and_special_addresses_are_not_applicable_even_when_disabled(self):
        for address in ("10.0.0.1", "172.16.5.5", "192.168.0.9", "127.0.0.1", "169.254.1.1", "224.0.0.1", "255.255.255.255", "0.0.0.0", "100.64.0.1", "::1", "fe80::1", "fd00::1", "ff02::1"):
            d = self.ok(ReputationTool().specs()[0], {"ip": address})
            self.assertEqual(d["status"], "not_applicable", address)
            self.assertIn("public", d["reason"])

    def test_disabled_never_reaches_the_cache_or_the_budget(self):
        tool = ReputationTool(max_calls=0)
        self.assertEqual(self.ok(tool.specs()[0], {"ip": "8.8.8.8"})["status"], "disabled")
        self.assertEqual(tool.calls_made, 0)

    def test_the_registry_leaves_reputation_off_by_default(self):
        with mock.patch.dict(os.environ, {reputation.ENV_KEY: "KEY-FROM-ENV"}):
            registry = build_registry()
        d = registry.call("reputation_lookup", {"ip": "8.8.8.8"})["data"]
        self.assertEqual(d["status"], "disabled")
        self.urlopen.assert_not_called()

    def test_building_a_tool_with_a_key_makes_no_request(self):
        tool = ReputationTool(api_key="KEY")
        ReputationTool.from_env({reputation.ENV_KEY: "KEY"})
        self.assertTrue(tool.enabled)
        self.assertEqual(tool.calls_made, 0)
        self.urlopen.assert_not_called()

    def test_invalid_input(self):
        spec = ReputationTool().specs()[0]
        for args in ({}, {"ip": None}, {"ip": ""}, {"ip": "8.8.8"}, {"ip": "example.com"}, {"ip": 8}, {"ip": "8.8.8.8", "force": True}, {"ip": "http://8.8.8.8"}):
            self.assertEqual(self.code(spec, args), "invalid_input", args)


class ReputationFakeFetchTests(OfflineCase):
    def test_ipv6_cache_key_is_the_normalised_address(self):
        calls = []
        tool = ReputationTool(fetch=lambda ip, timeout: calls.append(ip) or {"abuse_confidence_score": 0})
        spec = tool.specs()[0]
        for text in ("2606:4700::1111", "2606:4700:0:0:0:0:0:1111", "2606:4700::1111".upper()):
            self.ok(spec, {"ip": text})
        self.assertEqual(calls, ["2606:4700::1111"])

    def test_a_zero_call_budget_never_calls_the_fetch(self):
        calls = []
        tool = ReputationTool(fetch=lambda ip, timeout: calls.append(ip) or {}, max_calls=0)
        d = self.ok(tool.specs()[0], {"ip": "8.8.8.8"})
        self.assertEqual((d["status"], calls), ("unavailable", []))

    def test_results_are_identical_for_identical_requests(self):
        tool = ReputationTool(fetch=lambda ip, timeout: {"abuse_confidence_score": 7, "total_reports": 2})
        spec = tool.specs()[0]
        first = self.ok(spec, {"ip": "1.1.1.1"})
        second = self.ok(spec, {"ip": "1.1.1.1"})
        self.assertEqual(dict(first, cache_hit=None), dict(second, cache_hit=None))
        self.assertEqual((first["cache_hit"], second["cache_hit"]), (False, True))


# ------------------------------------------------------------------------------------------------ mitre_lookup and mitre_search
class MitreLookupTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.lookup = spec_for(MitreTools(), "mitre_lookup")
        self.search = spec_for(MitreTools(), "mitre_search")

    def test_every_technique_in_the_reference_can_be_looked_up(self):
        for tid, row in mitre_reference.TECHNIQUES.items():
            d = self.ok(self.lookup, {"technique_id": tid})
            self.assertEqual(sorted(d), ["flow_observables", "is_subtechnique", "name", "parent", "parent_id", "source", "subtechniques", "summary", "tactics", "technique_id"], tid)
            self.assertEqual((d["technique_id"], d["name"], d["tactics"], d["is_subtechnique"], d["parent_id"]), (tid, row["name"], row["tactics"], row["is_subtechnique"], row["parent_id"]))
            if row["parent_id"]:
                self.assertEqual(d["parent"]["technique_id"], row["parent_id"])
                self.assertEqual(d["subtechniques"], [])
            else:
                self.assertIsNone(d["parent"])
                self.assertEqual([s["technique_id"] for s in d["subtechniques"]], sorted(t for t, r in mitre_reference.TECHNIQUES.items() if r["parent_id"] == tid))

    def test_id_formats_that_are_accepted(self):
        for text in ("T1110", "t1110", " T1110 ", "T1110.001", "t1110.001", "T1110.001   "):
            self.assertTrue(self.lookup.run({"technique_id": text})["ok"], text)

    def test_id_formats_that_are_rejected(self):
        for text in ("", "   ", "T", "T1", "T111", "T11100", "1110", "TT1110", "T1110.", "T1110.0", "T1110.01", "T1110.0011", "T1110.001.001", "T-1110", "T1110 .001", "T1110;1",
                     "T1110/001", "ATT1110", "T11a0"):
            r = self.lookup.run({"technique_id": text})
            self.assertFalse(r["ok"], repr(text))
            self.assertEqual(r["error"]["code"], "invalid_input", repr(text))

    def test_well_formed_but_unknown_ids_are_not_found_and_say_so_plainly(self):
        for tid in ("T0000", "T9999", "T1110.000", "T1110.999", "T1234", "T1595.009"):
            r = self.lookup.run({"technique_id": tid})
            self.assertEqual((r["ok"], r["error"]["code"], r["data"]), (False, "not_found", None), tid)
            self.assertIn("not in the curated", r["error"]["message"])
            self.assertIn("attack.mitre.org", r["error"]["message"])
        self.assertIn("Brute Force", self.lookup.run({"technique_id": "T1110.999"})["error"]["message"])
        self.assertNotIn("parent", self.lookup.run({"technique_id": "T9999"})["error"]["message"].lower().replace("not in the curated", ""))

    def test_missing_wrong_type_and_extra_arguments(self):
        for args in ({}, {"technique_id": None}, {"technique_id": 1110}, {"technique_id": ["T1110"]}, {"technique_id": "T1110", "tactic": "x"}, {"technique_id": "T" * 13}):
            self.assertEqual(self.code(self.lookup, args), "invalid_input", args)

    def test_returned_data_cannot_alter_the_reference(self):
        d = self.ok(self.lookup, {"technique_id": "T1110"})
        d["tactics"].append("Impact")
        d["name"] = "changed"
        again = self.ok(self.lookup, {"technique_id": "T1110"})
        self.assertEqual((again["tactics"], again["name"]), (["Credential Access"], "Brute Force"))
        self.assertEqual(mitre_reference.TECHNIQUES["T1110"]["tactics"], ["Credential Access"])

    def test_lookup_is_deterministic(self):
        self.assertEqual(self.lookup.run({"technique_id": "T1071"}), self.lookup.run({"technique_id": "t1071"}))


class MitreSearchTests(OfflineCase):
    def setUp(self):
        super().setUp()
        self.search = spec_for(MitreTools(), "mitre_search")

    def test_every_technique_is_found_first_by_its_own_id(self):
        for tid in mitre_reference.TECHNIQUES:
            d = self.ok(self.search, {"query": tid, "limit": 10})
            ids = [t["technique_id"] for t in d["techniques"]]
            self.assertIn(tid, ids, tid)
            self.assertEqual(ids[0], tid, tid)
            self.assertEqual(d["techniques"][0]["score"], max(t["score"] for t in d["techniques"]))

    def test_a_subtechnique_id_ranks_the_subtechnique_not_its_parent(self):
        d = self.ok(self.search, {"query": "T1595.001"})
        self.assertEqual(d["techniques"][0]["technique_id"], "T1595.001")
        d = self.ok(self.search, {"query": "t1595"})
        self.assertEqual(d["techniques"][0]["technique_id"], "T1595")

    def test_every_technique_is_found_by_its_own_name(self):
        for tid, row in mitre_reference.TECHNIQUES.items():
            d = self.ok(self.search, {"query": row["name"], "limit": 10})
            self.assertIn(tid, [t["technique_id"] for t in d["techniques"]], tid)

    def test_case_does_not_matter(self):
        a = self.ok(self.search, {"query": "Password Guessing"})
        b = self.ok(self.search, {"query": "PASSWORD guessing"})
        self.assertEqual(a["techniques"], b["techniques"])

    def test_ranking_is_by_score_then_id(self):
        d = self.ok(self.search, {"query": "remote services", "limit": 10})
        keys = [(-t["score"], t["technique_id"]) for t in d["techniques"]]
        self.assertEqual(keys, sorted(keys))
        self.assertTrue(all(isinstance(t["score"], int) and t["score"] > 0 for t in d["techniques"]))

    def test_limit_boundaries_and_totals(self):
        for limit in (1, 5, 10):
            d = self.ok(self.search, {"query": "traffic flows web", "limit": limit})
            self.assertEqual(d["returned"], len(d["techniques"]))
            self.assertLessEqual(d["returned"], limit)
            self.assertGreaterEqual(d["total_matches"], d["returned"])
        big = self.ok(self.search, {"query": "flows", "limit": 10})
        self.assertEqual((big["returned"], big["total_matches"] > 10), (10, True))
        one = self.ok(self.search, {"query": "flows", "limit": 1})
        self.assertEqual(one["techniques"][0], big["techniques"][0])
        self.assertEqual(self.code(self.search, {"query": "flows", "limit": 0}), "invalid_input")
        self.assertEqual(self.code(self.search, {"query": "flows", "limit": 11}), "invalid_input")

    def test_the_tactic_filter_for_every_tactic(self):
        for tactic in [t.lower() for t in mitre_reference.TACTICS]:
            d = self.ok(self.search, {"query": "access traffic flows services", "tactic": tactic, "limit": 10})
            self.assertEqual(d["tactic_filter"], tactic)
            for t in d["techniques"]:
                self.assertIn(tactic, [x.lower() for x in t["tactics"]])
        self.assertEqual(self.ok(self.search, {"query": "access", "tactic": " IMPACT "})["tactic_filter"], "impact")

    def test_queries_with_nothing_searchable_are_invalid(self):
        for query in ("", "   ", "the of a", "!!!", "...", "x", "a b c", "to and or in", "-"):
            self.assertEqual(self.code(self.search, {"query": query}), "invalid_input", repr(query))

    def test_queries_with_no_match_return_an_empty_list(self):
        for query in ("zzzzqqq", "qwerty uiop", "1234567"):
            d = self.ok(self.search, {"query": query})
            self.assertEqual((d["total_matches"], d["returned"], d["techniques"]), (0, 0, []), query)

    def test_punctuation_and_unicode_are_tolerated(self):
        for query in ("brute-force, login!", "brute/force", "naïve brute force", "force\tbrute", "BRUTE\nFORCE"):
            d = self.ok(self.search, {"query": query})
            self.assertGreater(d["total_matches"], 0, repr(query))

    def test_missing_wrong_type_and_extra_arguments(self):
        for args in ({}, {"query": None}, {"query": 5}, {"query": ["scan"]}, {"query": "scan", "tactic": "wizardry"}, {"query": "scan", "tactic": 5}, {"query": "scan", "limit": "5"},
                     {"query": "scan", "limit": 2.5}, {"query": "x" * 121}, {"query": "scan", "technique_id": "T1046"}):
            self.assertEqual(self.code(self.search, args), "invalid_input", args)

    def test_the_search_is_deterministic(self):
        first = self.search.run({"query": "flood web server", "limit": 10})
        for _ in range(3):
            self.assertEqual(self.search.run({"query": "flood web server", "limit": 10}), first)

    def test_reference_is_not_modified_by_searching(self):
        before = json.dumps(mitre_reference.TECHNIQUES, sort_keys=True)
        d = self.ok(self.search, {"query": "scan"})
        d["techniques"][0]["tactics"].append("Impact")
        self.assertEqual(json.dumps(mitre_reference.TECHNIQUES, sort_keys=True), before)


if __name__ == "__main__":
    unittest.main()
