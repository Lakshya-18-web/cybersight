import os
import re
import sys
import ast
import json
import unittest
import subprocess
import urllib.error
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

import pandas as pd

import config
import tools
from tools import base, reference_data, mitre_reference, flow_query, enrichment, reputation, mitre_lookup, registry as registry_module
from tools import FlowStore, FlowTools, EnrichmentTools, ReputationTool, MitreTools, build_registry, classify_ip

from tests import test_week2_day3 as d3

TOOLS_DIR = os.path.join(ROOT, "src", "tools")


def read_tool_file(name):
    with open(os.path.join(TOOLS_DIR, name), encoding="utf-8") as f:
        return f.read()


TOOL_MODULES = sorted(f for f in os.listdir(TOOLS_DIR) if f.endswith(".py"))
T0 = pd.Timestamp("2017-07-05 10:00:00")
BEACON_SRC, BEACON_DST = "192.168.10.5", "52.1.2.3"
SCAN_SRC, SCAN_DST = "192.168.10.9", "10.0.0.2"
IRREG_SRC, IRREG_DST = "192.168.10.7", "52.9.9.9"


def make_rows():
    rows = []

    def add(ts, src, dst, dport, proto=6, fwd=100.0, dur=5.0, sport=40000):
        row = {"flow_row": len(rows), "flow_id": "t-" + str(len(rows)), "timestamp": ts, "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport, "protocol": proto}
        for name in config.DISPLAY_FEATURES:
            row[name] = 1.0
        row["Total Length of Fwd Packets"] = fwd
        row["Flow Duration"] = dur
        row["Fwd IAT Mean"] = 0.5
        rows.append(row)

    for i in range(10):  # regular: one flow a minute, same size
        add(T0 + pd.Timedelta(seconds=60 * i), BEACON_SRC, BEACON_DST, 80)
    for i, port in enumerate(range(1, 31)):  # scan: one tiny flow a second to 30 ports
        add(T0 + pd.Timedelta(seconds=i), SCAN_SRC, SCAN_DST, port, fwd=0.0, dur=0.1)
    offset = 0
    for gap in [0, 10, 200, 30, 400]:  # irregular
        offset += gap
        add(T0 + pd.Timedelta(seconds=offset), IRREG_SRC, IRREG_DST, 443, fwd=50.0 + offset)
    add(T0 + pd.Timedelta(hours=3), "192.168.10.50", "10.0.0.2", 53, proto=17)
    add(T0 + pd.Timedelta(hours=3, seconds=1), "192.168.10.51", "10.0.0.2", 53, proto=17)
    return rows


def make_store(rows=None):
    return FlowStore(pd.DataFrame(rows if rows is not None else make_rows()))


class StoreCase(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch("urllib.request.urlopen", side_effect=AssertionError("network call in a unit test"))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.store = make_store()
        self.flow = {s.name: s for s in FlowTools(self.store).specs()}

    def data(self, name, args):
        result = self.flow[name].run(args)
        self.assertTrue(result["ok"], result)
        json.dumps(result)
        return result["data"]


# ------------------------------------------------------------------------------------------------ base
class ArgumentTests(unittest.TestCase):
    PARAMS = {
        "n": base.P("integer", "n", required=True, minimum=1, maximum=10),
        "x": base.P("number", "x", default=1.5, minimum=0),
        "ip": base.P("ip", "ip"), "when": base.P("timestamp", "when"), "mode": base.P("enum", "mode", default="a", enum=["a", "b"]),
        "flag": base.P("boolean", "flag", default=False), "text": base.P("string", "text", max_length=5),
    }

    def clean(self, **args):
        return base.clean_arguments(self.PARAMS, args)

    def test_defaults_and_types(self):
        c = self.clean(n=3)
        self.assertEqual((c["n"], c["x"], c["mode"], c["flag"], c["ip"]), (3, 1.5, "a", False, None))

    def test_unknown_argument_is_rejected(self):
        for bad in ("path", "file", "set", "which"):
            with self.assertRaises(ValueError):
                self.clean(n=1, **{bad: "/etc/passwd"})

    def test_missing_required(self):
        with self.assertRaises(ValueError):
            self.clean()

    def test_wrong_types_and_ranges(self):
        for kwargs in [{"n": "3"}, {"n": 3.0}, {"n": True}, {"n": 0}, {"n": 11}, {"n": 1, "x": float("nan")}, {"n": 1, "x": -1}, {"n": 1, "x": "1"},
                       {"n": 1, "flag": 1}, {"n": 1, "mode": "c"}, {"n": 1, "mode": 5}, {"n": 1, "text": "toolong"}, {"n": 1, "text": "  "}, {"n": 1, "text": "a\x00b"}]:
            with self.assertRaises(ValueError, msg=str(kwargs)):
                self.clean(**kwargs)

    def test_enum_is_case_insensitive_and_normalised(self):
        self.assertEqual(self.clean(n=1, mode=" B ")["mode"], "b")

    def test_ip_is_validated_and_normalised(self):
        self.assertEqual(self.clean(n=1, ip=" 192.168.1.1 ")["ip"], "192.168.1.1")
        self.assertEqual(self.clean(n=1, ip="2001:0DB8:0:0:0:0:0:1")["ip"], "2001:db8::1")
        for bad in ["999.1.1.1", "example.com", "1.2.3", "../etc", "1.2.3.4; ls"]:
            with self.assertRaises(ValueError):
                self.clean(n=1, ip=bad)

    def test_timestamp_formats(self):
        self.assertEqual(self.clean(n=1, when="2017-07-05 14:30:00")["when"].hour, 14)
        self.assertEqual(self.clean(n=1, when="2017-07-05T14:30")["when"].minute, 30)
        for bad in ["yesterday", "2017-13-01 00:00:00", "05/07/2017", "2017-07-05 14:30:00+02:00"]:
            with self.assertRaises(ValueError):
                self.clean(n=1, when=bad)

    def test_arguments_must_be_an_object(self):
        with self.assertRaises(ValueError):
            base.clean_arguments(self.PARAMS, [1, 2])
        self.assertEqual(base.clean_arguments({}, None), {})


class EnvelopeTests(unittest.TestCase):
    def test_success_and_error_shapes(self):
        spec = base.ToolSpec("t", "d", {"n": base.P("integer", "n", required=True)}, lambda c: {"n": c["n"]})
        good = spec.run({"n": 2})
        self.assertEqual(good, {"ok": True, "tool": "t", "data": {"n": 2}, "error": None})
        bad = spec.run({})
        self.assertEqual((bad["ok"], bad["data"], bad["error"]["code"]), (False, None, base.CODE_INVALID))

    def test_a_tool_failure_becomes_an_error_result(self):
        def handler(c):
            raise base.ToolFailure(base.CODE_NOT_FOUND, "nothing here")
        result = base.ToolSpec("t", "d", {}, handler).run({})
        self.assertEqual(result["error"], {"code": "not_found", "message": "nothing here"})

    def test_an_unexpected_exception_is_contained_and_not_leaked(self):
        def handler(c):
            raise RuntimeError("secret detail /home/user/key")
        result = base.ToolSpec("t", "d", {}, handler).run({})
        self.assertEqual(result["error"]["code"], base.CODE_INTERNAL)
        self.assertNotIn("secret", json.dumps(result))
        self.assertIn("RuntimeError", result["error"]["message"])

    def test_plain_converts_numpy_pandas_and_nan(self):
        import numpy as np
        out = base.plain({"a": np.int64(3), "b": np.float32(1.5), "c": float("nan"), "d": pd.Timestamp("2017-07-05 01:02:03"), "e": [np.bool_(True), float("inf")]})
        self.assertEqual(out, {"a": 3, "b": 1.5, "c": None, "d": "2017-07-05 01:02:03", "e": [True, None]})
        json.dumps(out)

    def test_json_schema_describes_the_parameters(self):
        spec = base.ToolSpec("t", "desc", {"n": base.P("integer", "n", required=True, minimum=1, maximum=9), "m": base.P("enum", "m", enum=["a", "b"], default="a"),
                                           "w": base.P("timestamp", "w")}, lambda c: {})
        schema = spec.json_schema()
        self.assertEqual(schema["required"], ["n"])
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["n"], {"description": "n", "type": "integer", "minimum": 1, "maximum": 9})
        self.assertEqual(schema["properties"]["m"]["enum"], ["a", "b"])
        self.assertIn("YYYY-MM-DD", schema["properties"]["w"]["description"])
        self.assertEqual(spec.declaration()["name"], "t")


# ------------------------------------------------------------------------------------------------ flow store and flow tools
class FlowStoreTests(unittest.TestCase):
    def test_store_is_sorted_by_time_and_the_input_is_untouched(self):
        rows = list(reversed(make_rows()))
        frame = pd.DataFrame(rows)
        before = frame.copy()
        store = FlowStore(frame)
        self.assertTrue(store.frame["timestamp"].is_monotonic_increasing)
        pd.testing.assert_frame_equal(frame, before)

    def test_missing_columns_are_rejected(self):
        frame = pd.DataFrame(make_rows()).drop(columns=["dst_port"])
        with self.assertRaises(ValueError):
            FlowStore(frame)

    def test_label_columns_are_rejected(self):
        for column in ["label", "Label", "is_attack", "source_file"]:
            frame = pd.DataFrame(make_rows())
            frame[column] = "x"
            with self.assertRaises(ValueError, msg=column):
                FlowStore(frame)

    def test_from_dev_loads_only_through_the_dev_loader(self):
        with mock.patch("triage_inputs.load_dev_flow_store", return_value=pd.DataFrame(make_rows())) as loader:
            store = FlowStore.from_dev()
        loader.assert_called_once_with()
        self.assertEqual(len(store), len(make_rows()))

    def test_feature_columns_exclude_identifiers(self):
        store = make_store()
        self.assertNotIn("src_ip", store.feature_columns)
        self.assertIn("Fwd IAT Mean", store.feature_columns)
        self.assertEqual(store.display_columns, config.DISPLAY_FEATURES)


class QueryFlowsTests(StoreCase):
    def test_filter_by_source(self):
        d = self.data("query_flows", {"src_ip": BEACON_SRC})
        self.assertEqual((d["total_matches"], d["returned"], d["truncated"]), (10, 10, False))
        self.assertTrue(all(f["src_ip"] == BEACON_SRC for f in d["flows"]))

    def test_filters_combine(self):
        d = self.data("query_flows", {"src_ip": SCAN_SRC, "dst_port": 22})
        self.assertEqual(d["total_matches"], 1)
        self.assertEqual(self.data("query_flows", {"dst_port": 53, "protocol": 17})["total_matches"], 2)
        self.assertEqual(self.data("query_flows", {"dst_port": 53, "protocol": 6})["total_matches"], 0)

    def test_no_match_is_an_empty_result_not_an_error(self):
        d = self.data("query_flows", {"src_ip": "10.99.99.99"})
        self.assertEqual((d["total_matches"], d["returned"], d["flows"], d["truncated"]), (0, 0, [], False))

    def test_window_around_a_time(self):
        d = self.data("query_flows", {"src_ip": BEACON_SRC, "around": "2017-07-05 10:05:00", "window_minutes": 2})
        self.assertEqual(d["total_matches"], 5)  # 10:03 .. 10:07
        times = [f["timestamp"] for f in d["flows"]]
        self.assertEqual(times, sorted(times))

    def test_start_and_end_are_inclusive(self):
        d = self.data("query_flows", {"src_ip": BEACON_SRC, "start": "2017-07-05 10:01:00", "end": "2017-07-05 10:03:00"})
        self.assertEqual(d["total_matches"], 3)

    def test_default_window_is_the_project_context_window(self):
        d = self.data("query_flows", {"around": "2017-07-05 10:00:00"})
        self.assertGreater(d["total_matches"], 0)
        self.assertEqual(flow_query.triage_inputs.CONTEXT_WINDOW_MINUTES, 5)

    def test_conflicting_or_missing_time_arguments(self):
        r = self.flow["query_flows"].run({"around": "2017-07-05 10:00:00", "start": "2017-07-05 09:00:00"})
        self.assertEqual(r["error"]["code"], "invalid_input")
        r = self.flow["query_flows"].run({"src_ip": BEACON_SRC, "start": "2017-07-05 11:00:00", "end": "2017-07-05 10:00:00"})
        self.assertEqual(r["error"]["code"], "invalid_input")
        r = self.flow["query_flows"].run({})
        self.assertEqual(r["error"]["code"], "invalid_input")

    def test_limit_truncates_and_reports_it(self):
        d = self.data("query_flows", {"src_ip": SCAN_SRC, "limit": 5})
        self.assertEqual((d["total_matches"], d["returned"], d["truncated"]), (30, 5, True))
        self.assertEqual([f["dst_port"] for f in d["flows"]], [1, 2, 3, 4, 5])

    def test_descending_order_returns_the_latest_flows(self):
        d = self.data("query_flows", {"src_ip": SCAN_SRC, "limit": 3, "order": "desc"})
        self.assertEqual([f["dst_port"] for f in d["flows"]], [30, 29, 28])

    def test_limit_is_capped(self):
        r = self.flow["query_flows"].run({"src_ip": SCAN_SRC, "limit": flow_query.MAX_ROWS + 1})
        self.assertEqual(r["error"]["code"], "invalid_input")

    def test_field_sets(self):
        identity = self.data("query_flows", {"src_ip": BEACON_SRC, "limit": 1, "fields": "identity"})["flows"][0]
        display = self.data("query_flows", {"src_ip": BEACON_SRC, "limit": 1})["flows"][0]
        everything = self.data("query_flows", {"src_ip": BEACON_SRC, "limit": 1, "fields": "all"})["flows"][0]
        self.assertEqual(list(identity), flow_query.ID_COLUMNS)
        self.assertEqual(list(display), flow_query.ID_COLUMNS + config.DISPLAY_FEATURES)
        self.assertIn("Fwd IAT Mean", everything)
        self.assertNotIn("Fwd IAT Mean", display)

    def test_rows_contain_no_label_columns(self):
        row = self.data("query_flows", {"src_ip": BEACON_SRC, "limit": 1, "fields": "all"})["flows"][0]
        self.assertEqual({k.lower() for k in row} & {"label", "is_attack", "source_file", "original_row"}, set())

    def test_invalid_values_are_rejected_before_any_lookup(self):
        for args in [{"src_ip": "not-an-ip"}, {"dst_port": 70000}, {"dst_port": "80"}, {"protocol": -1}, {"around": "tomorrow"}, {"src_ip": BEACON_SRC, "fields": "labels"},
                     {"src_ip": BEACON_SRC, "file": "x.parquet"}, {"src_ip": BEACON_SRC, "path": "/etc/passwd"}]:
            self.assertEqual(self.flow["query_flows"].run(args)["error"]["code"], "invalid_input", args)

    def test_no_store_means_unavailable(self):
        spec = {s.name: s for s in FlowTools(None).specs()}["query_flows"]
        self.assertEqual(spec.run({"src_ip": BEACON_SRC})["error"]["code"], "unavailable")


class SummarizeFlowsTests(StoreCase):
    def test_summary_of_a_scanner(self):
        d = self.data("summarize_flows", {"ip": SCAN_SRC})
        self.assertEqual((d["n_flows"], d["distinct_destination_ips"], d["distinct_destination_ports"], d["distinct_source_ips"]), (30, 1, 30, 1))
        self.assertEqual(d["protocol_counts"], {"6": 30})
        self.assertEqual(d["first_flow"], "2017-07-05 10:00:00")
        self.assertEqual(d["last_flow"], "2017-07-05 10:00:29")
        self.assertEqual(d["feature_summary"]["Total Length of Fwd Packets"]["max"], 0.0)

    def test_top_ports_are_ranked_by_count_then_port_number(self):
        d = self.data("summarize_flows", {"ip": SCAN_SRC})
        self.assertEqual([p["dst_port"] for p in d["top_destination_ports"]], list(range(1, 11)))
        self.assertEqual(len(d["top_destination_ports"]), flow_query.TOP_N)

    def test_direction(self):
        self.assertEqual(self.data("summarize_flows", {"ip": SCAN_DST, "direction": "dst"})["n_flows"], 32)
        self.assertEqual(self.data("summarize_flows", {"ip": SCAN_DST, "direction": "src"})["n_flows"], 0)
        self.assertEqual(self.data("summarize_flows", {"ip": SCAN_DST, "direction": "either"})["n_flows"], 32)
        d = self.data("summarize_flows", {"ip": SCAN_DST, "direction": "dst"})
        self.assertEqual(d["distinct_source_ips"], 3)

    def test_port_filter_and_window(self):
        d = self.data("summarize_flows", {"ip": SCAN_DST, "direction": "dst", "dst_port": 53})
        self.assertEqual((d["n_flows"], d["protocol_counts"]), (2, {"17": 2}))
        d = self.data("summarize_flows", {"ip": SCAN_SRC, "around": "2017-07-05 10:00:10", "window_minutes": 1})
        self.assertEqual(d["n_flows"], 30)

    def test_unknown_host_gives_an_empty_summary(self):
        d = self.data("summarize_flows", {"ip": "10.88.88.88"})
        self.assertEqual((d["n_flows"], d["top_destination_ports"], d["feature_summary"]), (0, [], {}))

    def test_ip_is_required(self):
        self.assertEqual(self.flow["summarize_flows"].run({})["error"]["code"], "invalid_input")


class BeaconStatsTests(StoreCase):
    def test_regular_flows_show_a_constant_interval(self):
        d = self.data("beacon_stats", {"src_ip": BEACON_SRC, "dst_ip": BEACON_DST})
        iv = d["intervals_seconds"]
        self.assertEqual((d["n_flows"], iv["count"], iv["mean"], iv["median"], iv["std"], iv["min"], iv["max"]), (10, 9, 60.0, 60.0, 0.0, 60.0, 60.0))
        self.assertEqual((iv["cv"], iv["share_within_10pct_of_median"], iv["zero_length_intervals"], iv["caveat"]), (0.0, 1.0, 0, None))
        self.assertEqual(d["span_seconds"], 540.0)
        self.assertEqual((d["forward_bytes"]["mean"], d["forward_bytes"]["std"]), (100.0, 0.0))
        self.assertTrue(d["sufficient_for_interval_stats"])

    def test_irregular_flows_show_spread(self):
        d = self.data("beacon_stats", {"src_ip": IRREG_SRC, "dst_ip": IRREG_DST})
        iv = d["intervals_seconds"]
        self.assertEqual((iv["count"], iv["min"], iv["max"], iv["median"], iv["zero_length_intervals"]), (4, 10.0, 400.0, 115.0, 0))
        self.assertEqual(iv["share_within_10pct_of_median"], 0.0)
        self.assertGreater(iv["cv"], 1.0)

    def test_the_tool_makes_no_judgement(self):
        text = json.dumps(self.data("beacon_stats", {"src_ip": BEACON_SRC, "dst_ip": BEACON_DST})).lower()
        for word in ["malicious", "benign", "verdict", "is_beacon", "suspicious"]:
            self.assertNotIn(word, text)

    def test_few_flows_are_flagged_as_insufficient(self):
        d = self.data("beacon_stats", {"src_ip": "192.168.10.50", "dst_ip": SCAN_DST})
        self.assertEqual((d["n_flows"], d["sufficient_for_interval_stats"], d["intervals_seconds"]), (1, False, None))
        d = self.data("beacon_stats", {"src_ip": BEACON_SRC, "dst_ip": BEACON_DST, "around": "2017-07-05 10:00:00", "window_minutes": 1})
        self.assertEqual((d["n_flows"], d["intervals_seconds"]["count"], d["intervals_seconds"]["std"]), (2, 1, None))

    def test_no_flows(self):
        d = self.data("beacon_stats", {"src_ip": BEACON_SRC, "dst_ip": "10.1.1.1"})
        self.assertEqual((d["n_flows"], d["first_flow"], d["intervals_seconds"]), (0, None, None))

    def test_flows_sharing_a_timestamp_get_a_caveat(self):
        rows = [dict(r, timestamp=T0, flow_row=i) for i, r in enumerate(make_rows()[:6])]
        for r in rows:
            r.update(src_ip="1.1.1.1", dst_ip="2.2.2.2")
        spec = {s.name: s for s in FlowTools(make_store(rows)).specs()}["beacon_stats"]
        iv = spec.run({"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"})["data"]["intervals_seconds"]
        self.assertEqual(iv["zero_length_intervals"], 5)
        self.assertIsNone(iv["share_within_10pct_of_median"])
        self.assertIn("coarse", iv["caveat"])

    def test_port_filter(self):
        self.assertEqual(self.data("beacon_stats", {"src_ip": BEACON_SRC, "dst_ip": BEACON_DST, "dst_port": 80})["n_flows"], 10)
        self.assertEqual(self.data("beacon_stats", {"src_ip": BEACON_SRC, "dst_ip": BEACON_DST, "dst_port": 81})["n_flows"], 0)

    def test_both_addresses_are_required(self):
        self.assertEqual(self.flow["beacon_stats"].run({"src_ip": BEACON_SRC})["error"]["code"], "invalid_input")

    def test_long_windows_are_allowed_up_to_the_cap(self):
        self.assertTrue(self.flow["beacon_stats"].run({"src_ip": BEACON_SRC, "dst_ip": BEACON_DST, "around": "2017-07-05 10:00:00", "window_minutes": 720})["ok"])
        self.assertFalse(self.flow["beacon_stats"].run({"src_ip": BEACON_SRC, "dst_ip": BEACON_DST, "around": "2017-07-05 10:00:00", "window_minutes": 721})["ok"])


# ------------------------------------------------------------------------------------------------ enrichment
class IpInfoTests(StoreCase):
    def test_address_types(self):
        expected = {"192.168.10.5": ("private_rfc1918", "internal"), "10.1.2.3": ("private_rfc1918", "internal"), "172.16.0.1": ("private_rfc1918", "internal"),
                    "172.31.255.255": ("private_rfc1918", "internal"), "172.32.0.1": ("public", "external"), "8.8.8.8": ("public", "external"),
                    "127.0.0.1": ("loopback", "special"), "169.254.1.1": ("link_local", "special"), "224.0.0.251": ("multicast", "special"),
                    "255.255.255.255": ("broadcast", "special"), "0.0.0.0": ("this_network", "special"), "100.64.0.1": ("shared_address_space", "special"),
                    "203.0.113.5": ("documentation", "special"), "240.0.0.1": ("reserved", "special"), "fd12::1": ("private_unique_local", "internal"),
                    "::1": ("loopback", "special"), "fe80::1": ("link_local", "special"), "ff02::1": ("multicast", "special"), "2606:4700::1111": ("public", "external")}
        for address, result in expected.items():
            self.assertEqual(classify_ip(address), result, address)

    def test_ip_info_result(self):
        spec = {s.name: s for s in EnrichmentTools(self.store).specs()}["ip_info"]
        d = spec.run({"ip": BEACON_SRC})["data"]
        self.assertEqual((d["address_type"], d["scope"], d["version"], d["is_global"]), ("private_rfc1918", "internal", 4, False))
        self.assertEqual(d["observed_in_flow_store"]["flows_as_source"], 10)
        self.assertEqual(d["observed_in_flow_store"]["flows_as_destination"], 0)
        self.assertEqual(d["observed_in_flow_store"]["first_seen"], "2017-07-05 10:00:00")
        unseen = spec.run({"ip": "8.8.8.8"})["data"]
        self.assertEqual((unseen["observed_in_flow_store"]["flows_as_source"], unseen["observed_in_flow_store"]["first_seen"]), (0, None))

    def test_without_a_store_the_observation_is_absent(self):
        spec = {s.name: s for s in EnrichmentTools().specs()}["ip_info"]
        self.assertIsNone(spec.run({"ip": "8.8.8.8"})["data"]["observed_in_flow_store"])

    def test_invalid_address(self):
        spec = {s.name: s for s in EnrichmentTools().specs()}["ip_info"]
        self.assertEqual(spec.run({"ip": "300.1.1.1"})["error"]["code"], "invalid_input")

    def test_no_dataset_specific_addresses_are_embedded(self):
        text = read_tool_file("enrichment.py") + read_tool_file("reference_data.py")
        for address in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text):
            self.assertIn(address.split(".")[0], {"0", "10", "100", "127", "169", "172", "192", "198", "203", "224", "240", "255"}, address)
        self.assertNotIn("205.174", text)
        self.assertNotIn("192.168.10", text)


class PortAndServiceTests(unittest.TestCase):
    def setUp(self):
        self.spec = {s.name: s for s in EnrichmentTools().specs()}

    def test_well_known_port(self):
        d = self.spec["port_info"].run({"port": 22})["data"]
        self.assertEqual((d["category"], d["in_curated_table"], d["services"][0]["service"], d["services"][0]["protocol"]), ("well_known", True, "ssh", "tcp"))

    def test_protocol_filter(self):
        both = self.spec["port_info"].run({"port": 53})["data"]["services"]
        self.assertEqual(sorted(s["protocol"] for s in both), ["tcp", "udp"])
        self.assertEqual([s["protocol"] for s in self.spec["port_info"].run({"port": 53, "protocol": "udp"})["data"]["services"]], ["udp"])
        self.assertEqual(self.spec["port_info"].run({"port": 22, "protocol": "udp"})["data"]["services"], [])

    def test_port_ranges(self):
        cats = {0: "reserved", 1: "well_known", 1023: "well_known", 1024: "registered", 49151: "registered", 49152: "dynamic_private", 65535: "dynamic_private"}
        for port, cat in cats.items():
            self.assertEqual(enrichment.port_category(port), cat, port)

    def test_unlisted_port_is_not_guessed(self):
        d = self.spec["port_info"].run({"port": 31337})["data"]
        self.assertEqual((d["in_curated_table"], d["services"], d["category"]), (False, [], "registered"))
        self.assertIn("not in the curated table", d["note"])

    def test_port_validation(self):
        for bad in [-1, 65536, "22", 22.5, None]:
            self.assertFalse(self.spec["port_info"].run({"port": bad})["ok"], bad)

    def test_service_lookup_exact_alias_partial_and_missing(self):
        exact = self.spec["service_lookup"].run({"name": "SSH"})["data"]
        self.assertEqual((exact["match"], exact["services"][0]["ports"]), ("exact", [{"port": 22, "protocol": "tcp"}]))
        alias = self.spec["service_lookup"].run({"name": "rdp"})["data"]
        self.assertEqual((alias["match"], alias["services"][0]["name"], alias["services"][0]["ports"][0]["port"]), ("alias", "ms-wbt-server", 3389))
        partial = self.spec["service_lookup"].run({"name": "sql"})["data"]
        self.assertEqual(partial["match"], "partial")
        self.assertEqual(sorted(s["name"] for s in partial["services"]), ["ms-sql-s", "mysql", "postgresql"])
        missing = self.spec["service_lookup"].run({"name": "no-such-thing"})
        self.assertEqual(missing["error"]["code"], "not_found")

    def test_service_lookup_input_limits(self):
        self.assertFalse(self.spec["service_lookup"].run({"name": ""})["ok"])
        self.assertFalse(self.spec["service_lookup"].run({"name": "x" * 51})["ok"])

    def test_reference_tables_are_consistent(self):
        for (port, proto), names in reference_data.PORTS.items():
            self.assertIn(proto, ("tcp", "udp"))
            self.assertTrue(0 < port < 65536)
            for name in names:
                self.assertIn({"port": port, "protocol": proto}, reference_data.SERVICES[name]["ports"])
        for alias, name in reference_data.ALIASES.items():
            self.assertIn(name, reference_data.SERVICES)
            self.assertNotIn(alias, reference_data.SERVICES)
        for name, port in [("ftp", 21), ("ssh", 22), ("http", 80), ("https", 443), ("microsoft-ds", 445), ("ms-wbt-server", 3389)]:
            self.assertIn({"port": port, "protocol": "tcp"}, reference_data.SERVICES[name]["ports"])


# ------------------------------------------------------------------------------------------------ reputation
class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class ReputationTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch("urllib.request.urlopen", side_effect=AssertionError("network call in a unit test"))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.calls = []
        self.clock = FakeClock()

    def fetch(self, ip, timeout):
        self.calls.append((ip, timeout))
        return {"abuse_confidence_score": 42, "total_reports": 3}

    def tool(self, **kw):
        kw.setdefault("fetch", self.fetch)
        kw.setdefault("clock", self.clock)
        return ReputationTool(**kw)

    def run_ip(self, tool, ip="8.8.8.8"):
        result = tool.specs()[0].run({"ip": ip})
        self.assertTrue(result["ok"], result)
        return result["data"]

    def test_default_tool_is_off_and_never_calls_anything(self):
        tool = ReputationTool()
        d = self.run_ip(tool)
        self.assertEqual((d["status"], tool.enabled, tool.calls_made, d["reputation"]), ("disabled", False, 0, None))
        self.assertIn(reputation.ENV_KEY, d["reason"])

    def test_missing_key_in_the_environment_fails_gracefully(self):
        tool = ReputationTool.from_env({})
        self.assertFalse(tool.enabled)
        self.assertEqual(self.run_ip(tool)["status"], "disabled")

    def test_key_in_the_environment_enables_it(self):
        self.assertTrue(ReputationTool.from_env({reputation.ENV_KEY: " k "}).enabled)
        self.assertFalse(ReputationTool.from_env({reputation.ENV_KEY: "  "}).enabled)

    def test_bad_timeout_setting_falls_back(self):
        self.assertEqual(ReputationTool.from_env({reputation.ENV_TIMEOUT: "abc"}).timeout, reputation.DEFAULT_TIMEOUT)

    def test_timeout_is_clamped(self):
        self.assertEqual(ReputationTool(timeout=999).timeout, reputation.MAX_TIMEOUT)
        self.assertEqual(ReputationTool(timeout=0).timeout, 0.5)

    def test_a_public_address_is_looked_up_and_the_timeout_is_passed(self):
        d = self.run_ip(self.tool(timeout=3))
        self.assertEqual((d["status"], d["cache_hit"], d["reputation"]["abuse_confidence_score"], d["provider"]), ("ok", False, 42, "abuseipdb"))
        self.assertEqual(self.calls, [("8.8.8.8", 3.0)])

    def test_private_and_special_addresses_are_never_sent(self):
        tool = self.tool()
        for ip in ["192.168.1.1", "10.0.0.1", "127.0.0.1", "224.0.0.1", "fd00::1", "::1"]:
            self.assertEqual(self.run_ip(tool, ip)["status"], "not_applicable", ip)
        self.assertEqual(self.calls, [])

    def test_the_second_lookup_comes_from_the_cache(self):
        tool = self.tool()
        self.run_ip(tool)
        d = self.run_ip(tool)
        self.assertEqual((d["status"], d["cache_hit"], len(self.calls), tool.calls_made), ("ok", True, 1, 1))

    def test_the_cache_expires(self):
        tool = self.tool(ttl_seconds=100)
        self.run_ip(tool)
        self.clock.now += 99
        self.assertTrue(self.run_ip(tool)["cache_hit"])
        self.clock.now += 2
        self.assertFalse(self.run_ip(tool)["cache_hit"])
        self.assertEqual(len(self.calls), 2)

    def test_the_cache_is_bounded(self):
        cache = reputation.TTLCache(ttl_seconds=100, max_entries=2, clock=self.clock)
        cache.put("a", 1)
        self.clock.now += 1
        cache.put("b", 2)
        self.clock.now += 1
        cache.put("c", 3)
        self.assertEqual((len(cache), cache.get("a"), cache.get("b"), cache.get("c")), (2, None, 2, 3))

    def failing(self, error):
        def fetch(ip, timeout):
            self.calls.append(ip)
            raise error
        return fetch

    def test_a_service_error_is_a_normal_result_and_is_cached_briefly(self):
        tool = self.tool(fetch=self.failing(reputation.ReputationFetchError("the reputation service answered HTTP 503")))
        d = self.run_ip(tool)
        self.assertEqual((d["status"], d["reputation"]), ("unavailable", None))
        self.assertIn("503", d["reason"])
        again = self.run_ip(tool)
        self.assertEqual((again["status"], again["cache_hit"], len(self.calls)), ("unavailable", True, 1))
        self.clock.now += reputation.FAILURE_TTL + 1
        self.run_ip(tool)
        self.assertEqual(len(self.calls), 2)

    def test_an_unexpected_exception_in_the_fetch_is_contained(self):
        tool = self.tool(fetch=self.failing(RuntimeError("boom with secret")))
        d = self.run_ip(tool)
        self.assertEqual(d["status"], "unavailable")
        self.assertNotIn("secret", json.dumps(d))

    def test_a_timeout_is_a_normal_result(self):
        tool = self.tool(fetch=self.failing(TimeoutError()))
        self.assertEqual(self.run_ip(tool)["status"], "unavailable")

    def test_call_budget(self):
        tool = self.tool(max_calls=2)
        for ip in ["8.8.8.8", "8.8.4.4", "1.1.1.1"]:
            d = self.run_ip(tool, ip)
        self.assertEqual((d["status"], len(self.calls), tool.calls_made), ("unavailable", 2, 2))
        self.assertIn("budget", d["reason"])
        self.assertEqual(self.run_ip(tool, "8.8.8.8")["cache_hit"], True)

    def test_the_key_never_appears_in_a_result_or_the_repr(self):
        tool = ReputationTool(api_key="SUPERSECRETKEY", fetch=self.failing(reputation.ReputationFetchError("down")))
        self.assertNotIn("SUPERSECRETKEY", repr(tool))
        self.assertNotIn("SUPERSECRETKEY", json.dumps(self.run_ip(tool)))

    def test_input_validation(self):
        spec = self.tool().specs()[0]
        for bad in [{}, {"ip": "host.example"}, {"ip": "8.8.8.8", "url": "http://x"}, {"ip": 8}]:
            self.assertEqual(spec.run(bad)["error"]["code"], "invalid_input", bad)


class DefaultFetchTests(unittest.TestCase):
    """The built-in fetch function, with urlopen replaced. No network."""

    class Response:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=-1):
            return self.body if n < 0 else self.body[:n]

    GOOD = json.dumps({"data": {"abuseConfidenceScore": 77, "totalReports": 5, "lastReportedAt": "2026-01-01T00:00:00+00:00", "countryCode": "NL",
                                "usageType": "Data Center", "isWhitelisted": False, "ipAddress": "8.8.8.8", "extra": "ignored"}}).encode()

    def run_fetch(self, opener):
        with mock.patch("urllib.request.urlopen", side_effect=opener) as m:
            try:
                return reputation.make_abuseipdb_fetch("KEY123")("8.8.8.8", 4.0), m
            except reputation.ReputationFetchError as error:
                return error, m

    def test_request_goes_to_the_fixed_host_with_the_key_in_a_header(self):
        seen = {}

        def opener(request, timeout=None):
            seen["url"], seen["headers"], seen["timeout"] = request.full_url, dict(request.header_items()), timeout
            return self.Response(self.GOOD)
        result, _ = self.run_fetch(opener)
        parsed = reputation.urllib.parse.urlparse(seen["url"])
        self.assertEqual((parsed.scheme, parsed.netloc, parsed.path), ("https", reputation.API_HOST, reputation.API_PATH))
        self.assertEqual(reputation.urllib.parse.parse_qs(parsed.query), {"ipAddress": ["8.8.8.8"], "maxAgeInDays": [str(reputation.MAX_AGE_DAYS)]})
        self.assertEqual(seen["headers"]["Key"], "KEY123")
        self.assertNotIn("KEY123", seen["url"])
        self.assertEqual(seen["timeout"], 4.0)
        self.assertEqual(result, {"abuse_confidence_score": 77, "total_reports": 5, "last_reported_at": "2026-01-01T00:00:00+00:00", "country_code": "NL",
                                  "usage_type": "Data Center", "is_whitelisted": False})

    def test_failures_become_fetch_errors_without_the_key(self):
        def http(request, timeout=None):
            raise urllib.error.HTTPError(request.full_url, 429, "Too Many", {}, None)

        def url(request, timeout=None):
            raise urllib.error.URLError(TimeoutError())

        def sock(request, timeout=None):
            raise TimeoutError()
        for opener, text in [(http, "429"), (url, "could not be reached"), (sock, "failed")]:
            error, _ = self.run_fetch(opener)
            self.assertIsInstance(error, reputation.ReputationFetchError)
            self.assertIn(text, str(error))
            self.assertNotIn("KEY123", str(error))

    def test_bad_answers_become_fetch_errors(self):
        for body in [b"not json", b"{}", json.dumps({"data": {"abuseConfidenceScore": "x"}}).encode(), b"x" * (reputation.MAX_RESPONSE_BYTES + 5)]:
            error, _ = self.run_fetch(lambda request, timeout=None, b=body: self.Response(b))
            self.assertIsInstance(error, reputation.ReputationFetchError)

    def test_a_tool_built_with_a_key_uses_the_default_fetch(self):
        with mock.patch("urllib.request.urlopen", side_effect=lambda request, timeout=None: self.Response(self.GOOD)) as m:
            tool = ReputationTool(api_key="KEY123")
            d = tool.specs()[0].run({"ip": "8.8.8.8"})["data"]
            tool.specs()[0].run({"ip": "8.8.8.8"})
        self.assertEqual((d["status"], d["reputation"]["abuse_confidence_score"]), ("ok", 77))
        self.assertEqual(m.call_count, 1)


# ------------------------------------------------------------------------------------------------ MITRE
class MitreTests(unittest.TestCase):
    def setUp(self):
        self.spec = {s.name: s for s in MitreTools().specs()}

    def lookup(self, technique_id):
        return self.spec["mitre_lookup"].run({"technique_id": technique_id})

    def test_lookup_a_technique_with_subtechniques(self):
        d = self.lookup("T1110")["data"]
        self.assertEqual((d["name"], d["tactics"], d["is_subtechnique"], d["parent"]), ("Brute Force", ["Credential Access"], False, None))
        self.assertEqual([s["technique_id"] for s in d["subtechniques"]], ["T1110.001", "T1110.002", "T1110.003", "T1110.004"])
        self.assertTrue(d["flow_observables"])
        self.assertEqual(d["source"], mitre_reference.SOURCE_NOTE)

    def test_lookup_a_subtechnique_and_case_insensitive_id(self):
        d = self.lookup(" t1071.001 ")["data"]
        self.assertEqual((d["technique_id"], d["name"], d["parent"]["technique_id"], d["subtechniques"]), ("T1071.001", "Web Protocols", "T1071", []))

    def test_malformed_ids_are_invalid_input(self):
        for bad in ["", "1110", "T11", "T1110.1", "T1110.0011", "T1110; DROP", "../T1110", "brute force"]:
            self.assertEqual(self.lookup(bad)["error"]["code"], "invalid_input", bad)

    def test_unknown_id_is_not_found_and_not_guessed(self):
        r = self.lookup("T9999")
        self.assertEqual(r["error"]["code"], "not_found")
        self.assertIn("not in the curated", r["error"]["message"])
        self.assertIsNone(r["data"])

    def test_unknown_subtechnique_mentions_a_known_parent(self):
        self.assertIn("T1110", self.lookup("T1110.009")["error"]["message"])
        self.assertIn("Brute Force", self.lookup("T1110.009")["error"]["message"])

    def test_search_ranks_by_relevance_and_is_deterministic(self):
        a = self.spec["mitre_search"].run({"query": "brute force login"})["data"]
        b = self.spec["mitre_search"].run({"query": "brute force login"})["data"]
        self.assertEqual(a, b)
        self.assertEqual(a["techniques"][0]["technique_id"], "T1110")
        scores = [t["score"] for t in a["techniques"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_search_by_id_and_tactic_filter(self):
        self.assertEqual(self.spec["mitre_search"].run({"query": "T1046"})["data"]["techniques"][0]["technique_id"], "T1046")
        d = self.spec["mitre_search"].run({"query": "flood", "tactic": "impact"})["data"]
        self.assertTrue(d["techniques"])
        self.assertTrue(all("Impact" in t["tactics"] for t in d["techniques"]))
        none = self.spec["mitre_search"].run({"query": "flood", "tactic": "reconnaissance"})["data"]
        self.assertEqual(none["techniques"], [])

    def test_search_limit_and_validation(self):
        self.assertEqual(len(self.spec["mitre_search"].run({"query": "traffic", "limit": 2})["data"]["techniques"]), 2)
        for bad in [{"query": "the of a"}, {"query": ""}, {"query": "x", "limit": 0}, {"query": "x", "limit": 11}, {"query": "x", "tactic": "wizardry"}, {"query": "x" * 121}]:
            self.assertEqual(self.spec["mitre_search"].run(bad)["error"]["code"], "invalid_input", bad)

    def test_search_with_no_hit_is_an_empty_result(self):
        d = self.spec["mitre_search"].run({"query": "zzzzqqq"})["data"]
        self.assertEqual((d["total_matches"], d["techniques"]), (0, []))

    def test_reference_is_internally_consistent(self):
        t = mitre_reference.TECHNIQUES
        for tid, row in t.items():
            self.assertRegex(tid, r"^T\d{4}(\.\d{3})?$")
            self.assertEqual(row["technique_id"], tid)
            self.assertTrue(row["summary"] and row["flow_observables"] and row["name"])
            self.assertTrue(set(row["tactics"]) <= set(mitre_reference.TACTICS), tid)
            if "." in tid:
                self.assertIn(row["parent_id"], t)
                self.assertEqual(row["tactics"], t[row["parent_id"]]["tactics"] if tid.startswith(("T1071", "T1110", "T1595", "T1498", "T1499", "T1021", "T1573")) else row["tactics"])

    def test_pinned_ids_and_names(self):
        expected = {"T1595": "Active Scanning", "T1595.001": "Scanning IP Blocks", "T1595.002": "Vulnerability Scanning", "T1046": "Network Service Discovery",
                    "T1190": "Exploit Public-Facing Application", "T1110": "Brute Force", "T1110.001": "Password Guessing", "T1110.003": "Password Spraying",
                    "T1071": "Application Layer Protocol", "T1071.001": "Web Protocols", "T1071.004": "DNS", "T1573": "Encrypted Channel", "T1095": "Non-Application Layer Protocol",
                    "T1498": "Network Denial of Service", "T1498.001": "Direct Network Flood", "T1499": "Endpoint Denial of Service",
                    "T1499.002": "Service Exhaustion Flood", "T1021.001": "Remote Desktop Protocol", "T1021.004": "SSH", "T1029": "Scheduled Transfer"}
        for tid, name in expected.items():
            self.assertEqual(mitre_reference.TECHNIQUES[tid]["name"], name, tid)

    def test_the_reference_is_not_the_answer_key(self):
        source = read_tool_file("mitre_reference.py")
        for word in ["Hulk", "GoldenEye", "slowloris", "Slowhttptest", "Patator", "PortScan", "CIC-IDS", "DoS Hulk", "accepted"]:
            self.assertNotIn(word, source)
        self.assertIsNone(re.search(r"\bBot\b|\bDDoS\b|\bBENIGN\b", source))
        for name in ["mitre_reference.py", "mitre_lookup.py"]:
            used, modules = d3.SeparationTests.names_used(d3.SeparationTests(), os.path.join("tools", name))
            self.assertEqual(sorted(used & {"MITRE_MAP", "MITRE_MAP_PATH", "load_mitre_map", "load_answer_key", "eval_io", "eval_labels", "config"}), [], name)
        for name in ("mitre_reference.py", "mitre_lookup.py"):
            self.assertNotIn("mitre_map", read_tool_file(name))

    def test_no_class_to_technique_mapping_is_exposed(self):
        classes = set(config.MITRE_MAP) - {"BENIGN"}
        blob = json.dumps(mitre_reference.TECHNIQUES)
        for c in classes:
            self.assertNotIn(c, blob)


# ------------------------------------------------------------------------------------------------ registry
class RegistryTests(StoreCase):
    EXPECTED = ["beacon_stats", "ip_info", "mitre_lookup", "mitre_search", "port_info", "query_flows", "reputation_lookup", "service_lookup", "summarize_flows"]

    def test_the_registry_lists_every_day_1_tool(self):
        self.assertEqual(build_registry(self.store).names(), self.EXPECTED)

    def test_declarations_are_complete_and_json_serialisable(self):
        declarations = build_registry(self.store).declarations()
        json.dumps(declarations)
        for d in declarations:
            self.assertTrue(d["description"])
            self.assertEqual(d["parameters"]["type"], "object")
            self.assertFalse(d["parameters"]["additionalProperties"])
            for name, prop in d["parameters"]["properties"].items():
                self.assertIn(prop["type"], ("string", "integer", "number", "boolean"))
                self.assertTrue(prop["description"], d["name"] + "." + name)
            self.assertTrue(set(d["parameters"]["required"]) <= set(d["parameters"]["properties"]))

    def test_call_by_name(self):
        r = build_registry(self.store)
        self.assertEqual(r.call("port_info", {"port": 22})["data"]["services"][0]["service"], "ssh")
        self.assertEqual(r.call("query_flows", {"src_ip": BEACON_SRC, "limit": 1})["data"]["total_matches"], 10)
        self.assertEqual(r.call("mitre_lookup", {"technique_id": "T1046"})["data"]["name"], "Network Service Discovery")

    def test_unknown_tool_and_garbage_never_raise(self):
        r = build_registry(self.store)
        self.assertEqual(r.call("rm_rf", {})["error"]["code"], "unknown_tool")
        for name in [None, 5, ["x"], "x" * 500]:
            self.assertFalse(r.call(name, {})["ok"])
        for args in [None, [], "x", 5, {"zzz": 1}, {"port": object()}]:
            result = r.call("port_info", args)
            self.assertIn(result["error"]["code"], ("invalid_input",), args)

    def test_every_result_has_the_same_envelope(self):
        r = build_registry(self.store)
        for name, args in [("port_info", {"port": 22}), ("port_info", {}), ("ip_info", {"ip": "8.8.8.8"}), ("nope", {}), ("mitre_lookup", {"technique_id": "T9999"}),
                           ("reputation_lookup", {"ip": "8.8.8.8"}), ("summarize_flows", {"ip": BEACON_SRC})]:
            result = r.call(name, args)
            self.assertEqual(sorted(result), ["data", "error", "ok", "tool"])
            self.assertEqual(result["ok"], result["error"] is None)
            self.assertEqual(result["ok"], result["data"] is not None)

    def test_flow_tools_are_unavailable_without_a_store_and_the_rest_still_work(self):
        r = build_registry()
        self.assertEqual(r.call("summarize_flows", {"ip": BEACON_SRC})["error"]["code"], "unavailable")
        self.assertTrue(r.call("port_info", {"port": 80})["ok"])
        self.assertTrue(r.call("mitre_search", {"query": "scan"})["ok"])

    def test_reputation_is_off_by_default_even_if_the_environment_has_a_key(self):
        with mock.patch.dict(os.environ, {reputation.ENV_KEY: "KEY"}):
            r = build_registry(self.store)
        self.assertEqual(r.call("reputation_lookup", {"ip": "8.8.8.8"})["data"]["status"], "disabled")

    def test_reputation_can_be_switched_on_explicitly(self):
        tool = ReputationTool(fetch=lambda ip, timeout: {"abuse_confidence_score": 1})
        r = build_registry(self.store, reputation=tool)
        self.assertEqual(r.call("reputation_lookup", {"ip": "8.8.8.8"})["data"]["status"], "ok")

    def test_duplicate_names_and_wrong_types_are_rejected(self):
        spec = base.ToolSpec("a", "d", {}, lambda c: {})
        with self.assertRaises(ValueError):
            registry_module.ToolRegistry([spec, spec])
        with self.assertRaises(TypeError):
            registry_module.ToolRegistry([object()])

    def test_the_tools_are_independent_of_each_other(self):
        for specs in (FlowTools(self.store).specs(), EnrichmentTools().specs(), MitreTools().specs(), ReputationTool().specs()):
            self.assertTrue(registry_module.ToolRegistry(specs).names())


# ------------------------------------------------------------------------------------------------ separation and safety
class Day1SeparationTests(unittest.TestCase):
    ALLOWED_TOP_LEVEL = {"os", "re", "json", "math", "time", "datetime", "ipaddress", "urllib", "pandas", "config", "triage_inputs", ""}
    FORBIDDEN_IMPORTS = ["eval_io", "eval_labels", "eval_metrics", "evaluate", "llm_config", "gemini_client", "google", "genai", "langgraph", "langchain", "langsmith",
                         "anthropic", "openai", "requests", "socket", "http", "subprocess", "shutil", "pickle", "numpy", "chromadb", "sqlalchemy", "redis", "celery",
                         "run_baseline_dev", "baseline_prompt", "prompt_registry", "verdict_parser", "verdict_schema"]

    def source(self, name):
        with open(os.path.join(TOOLS_DIR, name), encoding="utf-8") as f:
            return f.read()

    def imports(self, name):
        tree = ast.parse(self.source(name))
        tops = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                tops.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                tops.add("" if node.level else (node.module or "").split(".")[0])
        return tops

    def test_the_package_has_exactly_the_planned_modules(self):
        self.assertEqual(TOOL_MODULES, ["__init__.py", "base.py", "enrichment.py", "flow_query.py", "mitre_lookup.py", "mitre_reference.py", "reference_data.py",
                                        "registry.py", "reputation.py"])

    def test_no_forbidden_or_new_dependencies(self):
        for name in TOOL_MODULES:
            tops = self.imports(name)
            self.assertEqual(sorted(tops & set(self.FORBIDDEN_IMPORTS)), [], name)
            self.assertTrue(tops <= self.ALLOWED_TOP_LEVEL, name + ": " + str(sorted(tops - self.ALLOWED_TOP_LEVEL)))

    def test_only_the_reputation_module_reaches_the_network(self):
        for name in TOOL_MODULES:
            has_urllib = "urllib" in self.imports(name)
            self.assertEqual(has_urllib, name == "reputation.py", name)

    def test_tools_never_touch_labels_the_answer_key_or_the_frozen_set(self):
        for name in TOOL_MODULES:
            used, _ = d3.SeparationTests.names_used(d3.SeparationTests(), os.path.join("tools", name))
            self.assertEqual(sorted(used & d3.SeparationTests.FORBIDDEN_NAMES), [], name)
            text = self.source(name)
            self.assertNotIn("frozen", text.lower(), name)
            self.assertNotIn(config.FROZEN_UNLOCK_VALUE, text)
            self.assertNotIn("FROZEN", text)
            for forbidden in ["dev_labels", "labels.parquet", "mitre_map.csv", "flow_store_frozen", "SOC_FROZEN_UNLOCK"]:
                self.assertNotIn(forbidden, text, name)

    def test_the_only_data_source_is_the_dev_loader(self):
        text = self.source("flow_query.py")
        self.assertEqual(set(re.findall(r"triage_inputs\.(\w+)", text)), {"assert_label_free", "load_dev_flow_store", "CONTEXT_WINDOW_MINUTES"})
        for name in TOOL_MODULES:
            self.assertNotIn("read_parquet", self.source(name))
            self.assertNotIn("read_csv", self.source(name))

    def test_tools_never_write_to_disk_or_run_code(self):
        for name in TOOL_MODULES:
            text = self.source(name)
            self.assertIsNone(re.search(r"(?<![A-Za-z_])open\(", text), name)
            for forbidden in ["os.system", "os.popen", "os.listdir", "os.walk", "os.remove", "os.makedirs", "eval(", "exec(", "__import__", "to_parquet", "to_csv", "getattr(os"]:
                self.assertNotIn(forbidden, text, name + ": " + forbidden)

    def test_tools_make_no_llm_call_and_hold_no_graph_or_verdict_logic(self):
        for name in TOOL_MODULES:
            low = self.source(name).lower()
            for forbidden in ["generate_content", "gemini", "stategraph", "langgraph", "supervisor", "specialist", "is_malicious", "final_verdict", "severity"]:
                self.assertNotIn(forbidden, low, name + ": " + forbidden)

    def test_environment_is_read_only_by_the_reputation_module(self):
        for name in TOOL_MODULES:
            self.assertEqual("os.environ" in self.source(name), name == "reputation.py", name)

    def test_importing_the_tools_loads_no_label_or_evaluation_module_and_creates_no_frozen_log(self):
        code = ("import sys; sys.path.insert(0, %r); sys.path.insert(0, %r)\nimport tools\n"
                "print(sorted(m for m in ('eval_labels', 'evaluate', 'eval_metrics', 'llm_config', 'gemini_client', 'langgraph', 'langchain') if m in sys.modules))")
        result = subprocess.run([sys.executable, "-c", code % (os.path.join(ROOT, "src"), ROOT)], capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "[]")

    def test_week2_baseline_is_untouched_by_the_tools(self):
        import prompt_registry
        self.assertEqual(prompt_registry.get_prompt("baseline_v3").sha256, "9403e7ea1937ff0f0f4b4fba548b58efa93bcc6296daa7326970adbaed1b61b7")


if __name__ == "__main__":
    unittest.main()
