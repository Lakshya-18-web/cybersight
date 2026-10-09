"""Week 3 Day 2: the registry and the tool declarations (schemas).

The declarations are what a model sees when it is allowed to call a tool, so they are pinned here: names, descriptions, argument names,
types, required arguments, ranges and enums. A change to any of them must be a deliberate change to the snapshot below.
Nothing here uses the network or the frozen set. Reputation stays off.
"""
import os
import re
import sys
import json
import copy
import hashlib
import unittest
import subprocess
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

from tools import base, build_registry, ReputationTool
from tools import registry as registry_module

from tests import test_week3_day1 as d1

TOOL_NAMES = ["beacon_stats", "ip_info", "mitre_lookup", "mitre_search", "port_info", "query_flows", "reputation_lookup", "service_lookup", "summarize_flows"]

# The smallest valid call for each tool (required arguments only).
MINIMAL = {
    "beacon_stats": {"src_ip": d1.BEACON_SRC, "dst_ip": d1.BEACON_DST},
    "ip_info": {"ip": "8.8.8.8"},
    "mitre_lookup": {"technique_id": "T1110"},
    "mitre_search": {"query": "brute force"},
    "port_info": {"port": 22},
    "query_flows": {"src_ip": d1.BEACON_SRC},
    "reputation_lookup": {"ip": "8.8.8.8"},
    "service_lookup": {"name": "ssh"},
    "summarize_flows": {"ip": d1.BEACON_SRC},
}

TACTICS = ["reconnaissance", "initial access", "persistence", "privilege escalation", "defense evasion", "credential access", "discovery",
           "lateral movement", "collection", "command and control", "exfiltration", "impact"]
PORT = {"type": "integer", "minimum": 0, "maximum": 65535}
WINDOW = {"type": "integer", "minimum": 1, "maximum": 720}

# name -> (required arguments, [(argument, type, extra keywords)] in declaration order). "extra" excludes description.
SNAPSHOT = {
    "beacon_stats": (["src_ip", "dst_ip"], [("src_ip", "string", {}), ("dst_ip", "string", {}), ("dst_port", "integer", {"minimum": 0, "maximum": 65535}),
                                            ("around", "string", {}), ("window_minutes", "integer", {"minimum": 1, "maximum": 720, "default": 60}),
                                            ("start", "string", {}), ("end", "string", {})]),
    "ip_info": (["ip"], [("ip", "string", {})]),
    "mitre_lookup": (["technique_id"], [("technique_id", "string", {"maxLength": 12})]),
    "mitre_search": (["query"], [("query", "string", {"maxLength": 120}), ("tactic", "string", {"enum": TACTICS}),
                                 ("limit", "integer", {"minimum": 1, "maximum": 10, "default": 5})]),
    "port_info": (["port"], [("port", "integer", {"minimum": 0, "maximum": 65535}), ("protocol", "string", {"enum": ["tcp", "udp"]})]),
    "query_flows": ([], [("src_ip", "string", {}), ("dst_ip", "string", {}), ("src_port", "integer", {"minimum": 0, "maximum": 65535}),
                         ("dst_port", "integer", {"minimum": 0, "maximum": 65535}), ("protocol", "integer", {"minimum": 0, "maximum": 255}),
                         ("around", "string", {}), ("window_minutes", "integer", {"minimum": 1, "maximum": 720, "default": 5}),
                         ("start", "string", {}), ("end", "string", {}),
                         ("fields", "string", {"enum": ["identity", "display", "all"], "default": "display"}),
                         ("limit", "integer", {"minimum": 1, "maximum": 200, "default": 50}), ("order", "string", {"enum": ["asc", "desc"], "default": "asc"})]),
    "reputation_lookup": (["ip"], [("ip", "string", {})]),
    "service_lookup": (["name"], [("name", "string", {"maxLength": 50})]),
    "summarize_flows": (["ip"], [("ip", "string", {}), ("direction", "string", {"enum": ["src", "dst", "either"], "default": "src"}),
                                 ("dst_port", "integer", {"minimum": 0, "maximum": 65535}), ("around", "string", {}),
                                 ("window_minutes", "integer", {"minimum": 1, "maximum": 720, "default": 5}), ("start", "string", {}), ("end", "string", {})]),
}

ALLOWED_PROPERTY_KEYS = {"type", "description", "enum", "minimum", "maximum", "maxLength", "default"}
ALLOWED_TYPES = {"string", "integer", "number", "boolean"}
UNKNOWN_ARGUMENT_NAMES = ["path", "file", "filename", "set", "which", "store", "column", "columns", "query_string", "sql", "url", "host", "command", "frozen", "label", "labels"]


def schema_errors(schema, arguments):
    """A small JSON-Schema check for the keywords the declarations use. Returns a list of problems (empty = valid)."""
    problems = []
    if not isinstance(arguments, dict):
        return ["arguments must be an object"]
    for name in schema["required"]:
        if arguments.get(name) is None:
            problems.append("missing " + name)
    for name, value in arguments.items():
        prop = schema["properties"].get(name)
        if prop is None:
            if schema.get("additionalProperties") is False:
                problems.append("unknown " + str(name))
            continue
        kind = prop["type"]
        if kind == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
            problems.append(name + " not an integer")
        elif kind == "number" and (isinstance(value, bool) or not isinstance(value, (int, float))):
            problems.append(name + " not a number")
        elif kind == "boolean" and not isinstance(value, bool):
            problems.append(name + " not a boolean")
        elif kind == "string" and not isinstance(value, str):
            problems.append(name + " not a string")
        else:
            if "minimum" in prop and value < prop["minimum"]:
                problems.append(name + " below minimum")
            if "maximum" in prop and value > prop["maximum"]:
                problems.append(name + " above maximum")
            if "enum" in prop and str(value).strip().lower() not in prop["enum"]:
                problems.append(name + " not in enum")
            if "maxLength" in prop and len(str(value).strip()) > prop["maxLength"]:
                problems.append(name + " too long")
    return problems


class RegistryCase(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch("urllib.request.urlopen", side_effect=AssertionError("network call in a unit test"))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.store = d1.make_store()
        self.registry = build_registry(self.store)
        self.declarations = {d["name"]: d for d in self.registry.declarations()}

    def assert_envelope(self, result):
        self.assertEqual(sorted(result), ["data", "error", "ok", "tool"])
        self.assertIsInstance(result["ok"], bool)
        self.assertEqual(result["ok"], result["error"] is None)
        self.assertEqual(result["ok"], result["data"] is not None)
        if not result["ok"]:
            self.assertEqual(sorted(result["error"]), ["code", "message"])
            self.assertIn(result["error"]["code"], ["invalid_input", "not_found", "unavailable", "unknown_tool", "internal_error"])
            self.assertIsInstance(result["error"]["message"], str)
        json.dumps(result)


# ------------------------------------------------------------------------------------------------ registry
class RegistryTests(RegistryCase):
    def test_all_nine_tools_are_registered(self):
        self.assertEqual(self.registry.names(), TOOL_NAMES)
        self.assertEqual(len(self.registry.names()), 9)

    def test_names_are_unique_and_declarations_are_sorted(self):
        listed = [d["name"] for d in self.registry.declarations()]
        self.assertEqual(listed, sorted(listed))
        self.assertEqual(len(listed), len(set(listed)))

    def test_every_name_can_be_fetched(self):
        for name in TOOL_NAMES:
            self.assertEqual(self.registry.get(name).name, name)
        self.assertIsNone(self.registry.get("nope"))
        self.assertIsNone(self.registry.get(None))

    def test_registry_rejects_duplicates_and_non_tools(self):
        spec = base.ToolSpec("same", "d", {}, lambda c: {})
        with self.assertRaises(ValueError):
            registry_module.ToolRegistry([spec, base.ToolSpec("same", "other", {}, lambda c: {})])
        for bad in (object(), "port_info", {"name": "x"}, None):
            with self.assertRaises(TypeError):
                registry_module.ToolRegistry([bad])

    def test_an_empty_registry_is_allowed_and_lists_nothing(self):
        empty = registry_module.ToolRegistry([])
        self.assertEqual((empty.names(), empty.declarations()), ([], []))
        self.assertEqual(empty.call("port_info", {"port": 1})["error"]["code"], "unknown_tool")

    def test_every_tool_works_without_a_flow_store_or_says_unavailable(self):
        bare = build_registry()
        flow_tools = {"query_flows", "summarize_flows", "beacon_stats"}
        for name, args in MINIMAL.items():
            result = bare.call(name, args)
            self.assert_envelope(result)
            if name in flow_tools:
                self.assertEqual(result["error"]["code"], "unavailable", name)
            else:
                self.assertTrue(result["ok"] or result["error"]["code"] == "not_found", name)

    def test_each_tool_set_can_be_registered_on_its_own(self):
        from tools import FlowTools, EnrichmentTools, MitreTools
        groups = {"flow": (FlowTools(self.store).specs(), 3), "enrichment": (EnrichmentTools().specs(), 3), "mitre": (MitreTools().specs(), 2),
                  "reputation": (ReputationTool().specs(), 1)}
        for label, (specs, count) in groups.items():
            self.assertEqual(len(registry_module.ToolRegistry(specs).names()), count, label)

    def test_the_registry_holds_no_state_between_calls(self):
        before = json.dumps(self.registry.declarations(), sort_keys=True)
        for name, args in MINIMAL.items():
            self.registry.call(name, args)
            self.registry.call(name, {})
        self.assertEqual(json.dumps(self.registry.declarations(), sort_keys=True), before)


# ------------------------------------------------------------------------------------------------ declarations
class DeclarationShapeTests(RegistryCase):
    def test_top_level_keys(self):
        for name, d in self.declarations.items():
            self.assertEqual(sorted(d), ["description", "name", "parameters"], name)

    def test_names_are_valid_function_names(self):
        for name in self.declarations:
            self.assertRegex(name, r"^[a-z][a-z0-9_]{1,63}$")

    def test_descriptions_are_clear(self):
        seen = set()
        for name, d in self.declarations.items():
            text = d["description"]
            self.assertEqual(text, text.strip(), name)
            self.assertNotIn("\n", text, name)
            self.assertTrue(40 <= len(text) <= 450, name + " " + str(len(text)))
            self.assertTrue(text[0].isupper(), name)
            self.assertTrue(text.endswith("."), name)
            self.assertNotIn(text, seen, name)
            seen.add(text)

    def test_descriptions_state_what_the_tool_does_not_do(self):
        for name in ("summarize_flows", "beacon_stats"):
            self.assertIn("Facts only", self.declarations[name]["description"])
        self.assertIn("Never required", self.declarations["reputation_lookup"]["description"])
        self.assertIn("disabled", self.declarations["reputation_lookup"]["description"])
        self.assertIn("At least one filter is required", self.declarations["query_flows"]["description"])
        self.assertIn("not guessed", self.declarations["mitre_lookup"]["description"])

    def test_parameters_object_shape(self):
        for name, d in self.declarations.items():
            p = d["parameters"]
            self.assertEqual(sorted(p), ["additionalProperties", "properties", "required", "type"], name)
            self.assertEqual(p["type"], "object")
            self.assertIs(p["additionalProperties"], False)
            self.assertIsInstance(p["required"], list)
            self.assertEqual(len(p["required"]), len(set(p["required"])), name)
            self.assertTrue(set(p["required"]) <= set(p["properties"]), name)

    def test_every_argument_has_an_explicit_type_and_a_description(self):
        for name, d in self.declarations.items():
            for arg, prop in d["parameters"]["properties"].items():
                label = name + "." + arg
                self.assertRegex(arg, r"^[a-z][a-z0-9_]*$", label)
                self.assertTrue(set(prop) <= ALLOWED_PROPERTY_KEYS, label + str(sorted(set(prop) - ALLOWED_PROPERTY_KEYS)))
                self.assertIn(prop["type"], ALLOWED_TYPES, label)
                self.assertTrue(prop["description"].strip(), label)
                self.assertEqual(prop["description"], prop["description"].strip(), label)

    def test_numeric_bounds_enums_and_defaults_are_consistent(self):
        for name, d in self.declarations.items():
            for arg, prop in d["parameters"]["properties"].items():
                label = name + "." + arg
                if prop["type"] == "integer":
                    self.assertIsInstance(prop["minimum"], int, label)
                    self.assertIsInstance(prop["maximum"], int, label)
                    self.assertLessEqual(prop["minimum"], prop["maximum"], label)
                    if "default" in prop:
                        self.assertIsInstance(prop["default"], int, label)
                        self.assertTrue(prop["minimum"] <= prop["default"] <= prop["maximum"], label)
                else:
                    self.assertNotIn("minimum", prop, label)
                    self.assertNotIn("maximum", prop, label)
                if "enum" in prop:
                    self.assertTrue(prop["enum"], label)
                    self.assertEqual(len(prop["enum"]), len(set(prop["enum"])), label)
                    self.assertTrue(all(isinstance(v, str) and v == v.lower() and v == v.strip() for v in prop["enum"]), label)
                    if "default" in prop:
                        self.assertIn(prop["default"], prop["enum"], label)
                if "maxLength" in prop:
                    self.assertIsInstance(prop["maxLength"], int, label)
                    self.assertGreater(prop["maxLength"], 0, label)
                    self.assertEqual(prop["type"], "string", label)

    def test_timestamp_and_address_arguments_describe_their_format(self):
        for name, d in self.declarations.items():
            for arg, prop in d["parameters"]["properties"].items():
                if arg in ("around", "start", "end"):
                    self.assertIn("YYYY-MM-DD HH:MM:SS", prop["description"], name + "." + arg)
                if arg in ("ip", "src_ip", "dst_ip"):
                    self.assertTrue("address" in prop["description"].lower() or "suspected" in prop["description"].lower() or "host" in prop["description"].lower(), name + "." + arg)

    def test_time_window_arguments_say_how_they_combine(self):
        props = self.declarations["query_flows"]["parameters"]["properties"]
        self.assertIn("Do not combine with start or end", props["around"]["description"])
        self.assertIn("Do not combine with around", props["start"]["description"])
        self.assertIn("Ignored without 'around'", props["window_minutes"]["description"])

    def test_the_declarations_are_json_serialisable_and_round_trip(self):
        for d in self.registry.declarations():
            self.assertEqual(json.loads(json.dumps(d)), d)

    def test_a_returned_declaration_is_a_copy(self):
        first = self.registry.declarations()
        first[0]["parameters"]["required"].append("x")
        first[0]["parameters"]["properties"].clear()
        again = self.registry.declarations()
        self.assertNotEqual(first[0]["parameters"], again[0]["parameters"])
        self.assertTrue(again[0]["parameters"]["properties"])
        self.assertNotIn("x", again[0]["parameters"]["required"])
        enum = self.registry.get("port_info").json_schema()["properties"]["protocol"]["enum"]
        enum.append("icmp")
        self.assertEqual(self.registry.get("port_info").json_schema()["properties"]["protocol"]["enum"], ["tcp", "udp"])

    def test_declaration_keywords_used_across_all_tools(self):
        """Documents what a Day 3 tool-calling adapter has to map: only these JSON-Schema keywords occur."""
        used = set()
        for d in self.declarations.values():
            used |= set(d["parameters"])
            for prop in d["parameters"]["properties"].values():
                used |= set(prop)
        self.assertEqual(used, {"type", "properties", "required", "additionalProperties", "description", "enum", "minimum", "maximum", "maxLength", "default"})


class SnapshotTests(RegistryCase):
    def test_snapshot_covers_exactly_the_registered_tools(self):
        self.assertEqual(sorted(SNAPSHOT), TOOL_NAMES)

    def test_every_declaration_matches_the_pinned_snapshot(self):
        for name, (required, arguments) in SNAPSHOT.items():
            p = self.declarations[name]["parameters"]
            self.assertEqual(p["required"], required, name)
            self.assertEqual(list(p["properties"]), [a for a, _, _ in arguments], name + " argument order")
            for arg, kind, extra in arguments:
                prop = {k: v for k, v in p["properties"][arg].items() if k != "description"}
                self.assertEqual(prop, dict(extra, type=kind), name + "." + arg)

    def test_required_arguments_are_exactly_the_pinned_ones(self):
        for name, (required, _) in SNAPSHOT.items():
            self.assertEqual(self.declarations[name]["parameters"]["required"], required)
            self.assertEqual([a for a, spec in self.registry.get(name).params.items() if spec["required"]], required)

    def test_the_schema_digest_is_stable(self):
        """If this fails after an intended schema change, update SNAPSHOT above, then this digest."""
        digest = hashlib.sha256(json.dumps(self.registry.declarations(), sort_keys=True).encode()).hexdigest()
        self.assertEqual(len(digest), 64)
        again = hashlib.sha256(json.dumps(build_registry(self.store).declarations(), sort_keys=True).encode()).hexdigest()
        self.assertEqual(digest, again)


class DeterminismTests(RegistryCase):
    CODE = ("import sys, json, hashlib; sys.path.insert(0, %r); sys.path.insert(0, %r)\n"
            "from tools import build_registry\n"
            "print(hashlib.sha256(json.dumps(build_registry().declarations()).encode()).hexdigest())")

    def test_declarations_are_identical_across_builds(self):
        a = json.dumps(self.registry.declarations())
        b = json.dumps(build_registry(d1.make_store()).declarations())
        c = json.dumps(build_registry().declarations())
        self.assertEqual(a, b)
        self.assertEqual(a, c)

    def test_declarations_do_not_depend_on_the_flow_store_or_the_reputation_setting(self):
        plain = json.dumps(build_registry().declarations())
        on = json.dumps(build_registry(self.store, reputation=ReputationTool(fetch=lambda ip, timeout: {})).declarations())
        self.assertEqual(plain, on)

    def test_declarations_are_identical_under_different_hash_seeds(self):
        digests = set()
        for seed in ("0", "1", "4242"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            out = subprocess.run([sys.executable, "-c", self.CODE % (os.path.join(ROOT, "src"), ROOT)], capture_output=True, text=True, env=env, timeout=120)
            self.assertEqual(out.returncode, 0, out.stderr)
            digests.add(out.stdout.strip())
        self.assertEqual(len(digests), 1)

    def test_repeated_calls_give_identical_results(self):
        for name, args in MINIMAL.items():
            first = json.dumps(self.registry.call(name, args), sort_keys=False)
            for _ in range(3):
                self.assertEqual(json.dumps(self.registry.call(name, args), sort_keys=False), first, name)

    def test_results_do_not_depend_on_argument_order(self):
        a = self.registry.call("query_flows", {"src_ip": d1.SCAN_SRC, "limit": 5, "order": "desc"})
        b = self.registry.call("query_flows", {"order": "desc", "limit": 5, "src_ip": d1.SCAN_SRC})
        self.assertEqual(a, b)

    def test_calls_do_not_modify_their_arguments(self):
        args = {"src_ip": d1.SCAN_SRC, "around": "2017-07-05 10:00:00", "limit": 3}
        before = copy.deepcopy(args)
        self.registry.call("query_flows", args)
        self.assertEqual(args, before)

    def test_a_fresh_registry_gives_the_same_results(self):
        other = build_registry(d1.make_store())
        for name, args in MINIMAL.items():
            self.assertEqual(self.registry.call(name, args), other.call(name, args), name)


# ------------------------------------------------------------------------------------------------ required and typed arguments
class RequiredArgumentTests(RegistryCase):
    def test_a_minimal_call_succeeds_for_every_tool(self):
        for name, args in MINIMAL.items():
            result = self.registry.call(name, args)
            self.assert_envelope(result)
            self.assertTrue(result["ok"], name + str(result))

    def test_the_minimal_calls_cover_exactly_the_required_arguments(self):
        for name, args in MINIMAL.items():
            required = SNAPSHOT[name][0]
            if required:
                self.assertEqual(sorted(args), sorted(required), name)

    def test_each_missing_required_argument_is_named_in_the_error(self):
        for name, (required, _) in SNAPSHOT.items():
            for arg in required:
                args = {k: v for k, v in MINIMAL[name].items() if k != arg}
                result = self.registry.call(name, args)
                self.assert_envelope(result)
                self.assertEqual(result["error"]["code"], "invalid_input", name + "." + arg)
                self.assertIn(arg, result["error"]["message"], name + "." + arg)
                self.assertEqual(result["tool"], name)

    def test_an_explicit_null_counts_as_missing_for_required_arguments(self):
        for name, (required, _) in SNAPSHOT.items():
            for arg in required:
                result = self.registry.call(name, dict(MINIMAL[name], **{arg: None}))
                self.assertEqual(result["error"]["code"], "invalid_input", name + "." + arg)

    def test_no_arguments_at_all(self):
        for name, (required, _) in SNAPSHOT.items():
            for empty in (None, {}):
                result = self.registry.call(name, empty)
                self.assert_envelope(result)
                self.assertEqual(result["error"]["code"], "invalid_input", name)

    def test_optional_arguments_really_are_optional_and_null_means_default(self):
        for name, (required, arguments) in SNAPSHOT.items():
            for arg, _, _ in arguments:
                if arg in required:
                    continue
                held = dict(MINIMAL[name], protocol=6) if name == "query_flows" else dict(MINIMAL[name])  # query_flows needs one filter to remain
                result = self.registry.call(name, dict(held, **{arg: None}))
                self.assertTrue(result["ok"], name + "." + arg + str(result))


BAD_VALUES = {
    "integer": ["1", 1.5, 2.0, True, False, [], {}, [1], float("nan"), float("inf"), "x", b"1"],
    "string": [1, 1.5, True, [], {}, ["a"], b"abc", object()],
    "ip": [1, True, [], {}, "", "   ", "not-an-ip", "1.2.3", "1.2.3.4.5", "999.1.1.1", "01.02.03.04", "1.2.3.4; ls", "example.com", "::g"],
    "timestamp": [1, True, [], "", "yesterday", "2017-02-30 00:00:00", "2017-07-05", "05/07/2017 10:00", "2017-07-05 25:00:00", "2017-07-05 10:00:00+02:00"],
    "enum": [1, True, [], "", "nope", "ALL!", " "],
}


class WrongTypeTests(RegistryCase):
    def test_wrong_values_are_rejected_for_every_argument_of_every_tool(self):
        checked = 0
        for name, spec in ((n, self.registry.get(n)) for n in TOOL_NAMES):
            for arg, p in spec.params.items():
                for bad in BAD_VALUES[p["type"]]:
                    result = self.registry.call(name, dict(MINIMAL[name], **{arg: bad}))
                    self.assert_envelope(result)
                    self.assertEqual(result["error"]["code"], "invalid_input", name + "." + arg + "=" + repr(bad))
                    checked += 1
        self.assertGreater(checked, 300)

    def test_the_error_names_the_bad_argument(self):
        for name, arg, bad in [("port_info", "port", "22"), ("query_flows", "limit", 2.5), ("ip_info", "ip", "999.1.1.1"), ("query_flows", "start", "tomorrow"),
                               ("port_info", "protocol", "icmp"), ("summarize_flows", "direction", "sideways")]:
            result = self.registry.call(name, dict(MINIMAL[name], **{arg: bad}))
            self.assertEqual(result["error"]["code"], "invalid_input")
            self.assertIn(arg, result["error"]["message"])

    def test_booleans_are_never_accepted_as_numbers(self):
        for name, spec in ((n, self.registry.get(n)) for n in TOOL_NAMES):
            for arg, p in spec.params.items():
                if p["type"] == "integer":
                    for bad in (True, False):
                        self.assertEqual(self.registry.call(name, dict(MINIMAL[name], **{arg: bad}))["error"]["code"], "invalid_input", name + "." + arg)

    def test_strings_are_stripped_and_control_characters_rejected(self):
        self.assertTrue(self.registry.call("ip_info", {"ip": "  8.8.8.8  "})["ok"])
        self.assertEqual(self.registry.call("ip_info", {"ip": "  8.8.8.8  "})["data"]["ip"], "8.8.8.8")
        for bad in ("ss\x00h", "ss\x1bh", "ss\x7fh", "ss\x08h"):
            self.assertEqual(self.registry.call("service_lookup", {"name": bad})["error"]["code"], "invalid_input", repr(bad))
        for ok in ("ss\th", "ss\nh"):  # tab and newline are not control characters here; they are just not a known service
            self.assertEqual(self.registry.call("service_lookup", {"name": ok})["error"]["code"], "not_found")


# ------------------------------------------------------------------------------------------------ ranges, enums and lengths
class BoundaryTests(RegistryCase):
    def test_integer_bounds_in_the_declaration_are_the_bounds_that_are_enforced(self):
        for name, d in self.declarations.items():
            for arg, prop in d["parameters"]["properties"].items():
                if prop["type"] != "integer":
                    continue
                base_args = dict(MINIMAL[name])
                for value in (prop["minimum"], prop["maximum"], (prop["minimum"] + prop["maximum"]) // 2):
                    result = self.registry.call(name, dict(base_args, **{arg: value}))
                    self.assertTrue(result["ok"], name + "." + arg + "=" + str(value) + str(result))
                for value in (prop["minimum"] - 1, prop["maximum"] + 1, prop["minimum"] - 10 ** 6, prop["maximum"] + 10 ** 6, -(10 ** 12), 10 ** 12):
                    result = self.registry.call(name, dict(base_args, **{arg: value}))
                    self.assertEqual(result["error"]["code"], "invalid_input", name + "." + arg + "=" + str(value))

    def test_every_enum_value_is_accepted_and_nothing_else(self):
        for name, d in self.declarations.items():
            for arg, prop in d["parameters"]["properties"].items():
                if "enum" not in prop:
                    continue
                for value in prop["enum"]:
                    for variant in (value, value.upper(), "  " + value + "  "):
                        result = self.registry.call(name, dict(MINIMAL[name], **{arg: variant}))
                        self.assertTrue(result["ok"], name + "." + arg + "=" + repr(variant) + str(result))
                for bad in ("", "other", prop["enum"][0] + "x", prop["enum"][0][:-1]):
                    if bad in prop["enum"]:
                        continue
                    self.assertEqual(self.registry.call(name, dict(MINIMAL[name], **{arg: bad}))["error"]["code"], "invalid_input", name + "." + arg + "=" + repr(bad))

    def test_max_length_in_the_declaration_is_the_length_that_is_enforced(self):
        for name, d in self.declarations.items():
            spec = self.registry.get(name)
            for arg, prop in d["parameters"]["properties"].items():
                if "maxLength" not in prop:
                    continue
                n = prop["maxLength"]
                cleaned = base.clean_arguments(spec.params, dict(MINIMAL[name], **{arg: "a" * n}))
                self.assertEqual(len(cleaned[arg]), n)
                with self.assertRaises(ValueError):
                    base.clean_arguments(spec.params, dict(MINIMAL[name], **{arg: "a" * (n + 1)}))
                # padding with spaces does not count: the value is stripped first
                base.clean_arguments(spec.params, dict(MINIMAL[name], **{arg: "  " + "a" * n + "  "}))
                result = self.registry.call(name, dict(MINIMAL[name], **{arg: "a" * (n + 1)}))
                self.assertEqual(result["error"]["code"], "invalid_input")

    def test_defaults_in_the_declaration_are_the_defaults_that_are_used(self):
        for name, d in self.declarations.items():
            spec = self.registry.get(name)
            cleaned = base.clean_arguments(spec.params, MINIMAL[name])
            for arg, prop in d["parameters"]["properties"].items():
                if "default" in prop:
                    self.assertEqual(cleaned[arg], prop["default"], name + "." + arg)
                elif arg not in MINIMAL[name]:
                    self.assertIsNone(cleaned[arg], name + "." + arg)


class UnknownArgumentTests(RegistryCase):
    def test_unknown_arguments_are_rejected_for_every_tool(self):
        for name in TOOL_NAMES:
            for extra in UNKNOWN_ARGUMENT_NAMES:
                result = self.registry.call(name, dict(MINIMAL[name], **{extra: "x"}))
                self.assertEqual(result["error"]["code"], "invalid_input", name + "." + extra)
                self.assertIn(extra, result["error"]["message"])

    def test_a_path_cannot_be_smuggled_in_as_a_value_either(self):
        for value in ("../../etc/passwd", "C:\\Windows\\win.ini", "/proc/self/environ", "file:///etc/passwd", "eval/frozen_alerts.parquet"):
            for name, arg in [("ip_info", "ip"), ("service_lookup", "name"), ("mitre_lookup", "technique_id"), ("mitre_search", "query"), ("query_flows", "src_ip")]:
                result = self.registry.call(name, dict(MINIMAL[name], **{arg: value}))
                self.assert_envelope(result)
                if result["ok"]:
                    self.assertNotIn("root:", json.dumps(result))

    def test_non_string_argument_names_do_not_crash(self):
        for name in TOOL_NAMES:
            for args in ({1: 2}, {1: 2, "a": 3}, {None: 1}, {(1, 2): 3, "z": 1}, {b"x": 1, "x": 2}):
                result = self.registry.call(name, args)
                self.assert_envelope(result)
                self.assertEqual(result["error"]["code"], "invalid_input", (name, args))


# ------------------------------------------------------------------------------------------------ malformed calls
class MalformedCallTests(RegistryCase):
    def test_unknown_or_malformed_tool_names(self):
        for bad in [None, "", " ", "nope", "PORT_INFO", "port_info ", " port_info", "port-info", "port_info\x00", "../port_info", "port_info;ls", "x" * 5000, 5, 1.5, True,
                    ["port_info"], {"name": "port_info"}, ("port_info",), b"port_info", "port_info.port"]:
            result = self.registry.call(bad, {"port": 22})
            self.assert_envelope(result)
            self.assertEqual(result["error"]["code"], "unknown_tool", repr(bad)[:40])
            self.assertLessEqual(len(result["error"]["message"]), 400)
            self.assertLessEqual(len(result["tool"]), 60)

    def test_the_unknown_tool_error_lists_the_available_tools(self):
        message = self.registry.call("nope", {})["error"]["message"]
        for name in TOOL_NAMES:
            self.assertIn(name, message)

    def test_malformed_argument_containers(self):
        for bad in [[], [1], (), "x", "port=22", 5, 1.5, True, b"{}", set(), object(), lambda: 1]:
            result = self.registry.call("port_info", bad)
            self.assert_envelope(result)
            self.assertEqual(result["error"]["code"], "invalid_input", repr(bad)[:40])

    def test_a_json_string_is_not_parsed_for_the_caller(self):
        result = self.registry.call("port_info", '{"port": 22}')
        self.assertEqual(result["error"]["code"], "invalid_input")
        self.assertIn("object", result["error"]["message"])

    def test_nested_and_huge_values_are_rejected_without_crashing(self):
        deep = {}
        node = deep
        for _ in range(500):
            node["a"] = {}
            node = node["a"]
        for bad in (deep, {"x": [1] * 100000}, "z" * 10 ** 6, list(range(10 ** 5))):
            for name in ("port_info", "ip_info", "service_lookup", "mitre_search", "query_flows"):
                result = self.registry.call(name, dict(MINIMAL[name], **{list(MINIMAL[name])[0]: bad}))
                self.assert_envelope(result)
                self.assertEqual(result["error"]["code"], "invalid_input")

    def test_an_error_result_always_names_the_tool_that_was_called(self):
        for name in TOOL_NAMES:
            self.assertEqual(self.registry.call(name, {"zzz": 1})["tool"], name)

    def test_nothing_that_a_caller_sends_can_raise_out_of_the_registry(self):
        values = [None, 0, -1, 1, 2 ** 70, 1.5, float("nan"), "", " ", "x", "8.8.8.8", True, [], [1], {}, {"a": 1}, (1,), b"b", object()]
        for name in TOOL_NAMES:
            for arg in list(self.registry.get(name).params):
                for value in values:
                    for args in ({arg: value}, dict(MINIMAL[name], **{arg: value})):
                        self.assert_envelope(self.registry.call(name, args))

    def test_the_internal_error_path_does_not_leak_details(self):
        def boom(c):
            raise RuntimeError("password=hunter2 path=/home/user/.env")
        spec = base.ToolSpec("boom", "Always fails.", {}, boom)
        result = registry_module.ToolRegistry([spec]).call("boom", {})
        self.assertEqual(result["error"]["code"], "internal_error")
        self.assertNotIn("hunter2", json.dumps(result))
        self.assertNotIn("/home", json.dumps(result))


# ------------------------------------------------------------------------------------------------ schema <-> validator agreement
class SchemaAgreementTests(RegistryCase):
    """For every tool the declared JSON schema and the validation that really runs must give the same verdict on type, range, enum, length,
    required and unknown arguments (cross-field and format rules, such as 'around or start/end', are described in text, not in the schema)."""

    def cases(self, name):
        spec = self.registry.get(name)
        declaration = self.declarations[name]["parameters"]
        base_args = dict(MINIMAL[name])
        out = [("minimal", base_args)]
        for arg, prop in declaration["properties"].items():
            if prop["type"] == "integer":
                for label, value in (("min", prop["minimum"]), ("max", prop["maximum"]), ("below", prop["minimum"] - 1), ("above", prop["maximum"] + 1), ("string", "5"), ("float", 1.5), ("bool", True)):
                    out.append((arg + ":" + label, dict(base_args, **{arg: value})))
            if "enum" in prop:
                out.append((arg + ":enum_ok", dict(base_args, **{arg: prop["enum"][0]})))
                out.append((arg + ":enum_bad", dict(base_args, **{arg: "zzz"})))
                out.append((arg + ":enum_int", dict(base_args, **{arg: 3})))
            if "maxLength" in prop:
                out.append((arg + ":len_ok", dict(base_args, **{arg: "a" * prop["maxLength"]})))
                out.append((arg + ":len_bad", dict(base_args, **{arg: "a" * (prop["maxLength"] + 1)})))
            if prop["type"] == "string":
                out.append((arg + ":not_string", dict(base_args, **{arg: 7})))
        for arg in declaration["required"]:
            out.append((arg + ":missing", {k: v for k, v in base_args.items() if k != arg}))
        out.append(("unknown", dict(base_args, bogus=1)))
        return spec, declaration, out

    def test_schema_and_validation_agree(self):
        total = 0
        for name in TOOL_NAMES:
            spec, declaration, cases = self.cases(name)
            for label, args in cases:
                by_schema = not schema_errors(declaration, args)
                try:
                    base.clean_arguments(spec.params, args)
                    by_code = True
                except ValueError:
                    by_code = False
                self.assertEqual(by_schema, by_code, name + " " + label + " " + str(schema_errors(declaration, args)))
                total += 1
        self.assertGreater(total, 140)

    def test_the_schema_checker_itself_catches_the_obvious_errors(self):
        schema = self.declarations["port_info"]["parameters"]
        self.assertEqual(schema_errors(schema, {"port": 22}), [])
        for bad in ({}, {"port": "22"}, {"port": 70000}, {"port": 22, "protocol": "icmp"}, {"port": 22, "x": 1}, {"port": True}):
            self.assertTrue(schema_errors(schema, bad), bad)


if __name__ == "__main__":
    unittest.main()
