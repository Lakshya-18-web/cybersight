"""Tests for the final-evaluation tooling (week5.evalrun). All data is the SYNTHETIC fixture and all models are fakes. No protected file is read, no key is needed, no network is used.
The protected-set gate is tested for its DEFAULT behaviour (closed) and for every way it can be wrong, using temporary files only. Run: PYTHONPATH=src:. python -m unittest tests.test_week5_evalrun"""
import contextlib
import copy
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

import pandas as pd

from week5.evalrun import CONFIGS, data as D, gate, pipeline, plan as P, rehearsal as R, report as RP, validate as V, metrics as M, collect as C
from week5.evalrun import __main__ as cli

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
EVALRUN_DIR = os.path.join(SRC, "week5", "evalrun")
NOW = gate._parse_time("2026-10-20T12:00:00Z")


def frozen_plan():
    plan = P.make_plan("final", "fixture", engine="instrumented")
    plan = copy.deepcopy(plan)
    plan["set"] = "frozen"
    plan["model"] = {"name": "gemini-test", "fake": False, "temperature": 0.0, "max_output_tokens": 1024, "seed": 42, "parse_retries": 2}
    plan["configs"]["full_system"]["engine"] = "langgraph"
    assert P.validate_plan(plan) == [], P.validate_plan(plan)
    return plan


class Tripwire:
    """Stands in for eval_io. Any call is recorded; tests assert the record is empty or exactly as expected."""

    def __init__(self, data=None):
        self.calls, self.data = [], data

    def _hit(self, name, which, reason):
        self.calls.append((name, which, reason))
        if self.data is None:
            raise AssertionError("the protected loader was called")
        return {"load_alerts": self.data.alerts, "load_labels": self.data.labels, "load_flow_store": self.data.flows}[name]

    def load_alerts(self, which, reason=None):
        return self._hit("load_alerts", which, reason)

    def load_labels(self, which, reason=None):
        return self._hit("load_labels", which, reason)

    def load_flow_store(self, which, reason=None):
        return self._hit("load_flow_store", which, reason)


def write_auth(path, plan, **over):
    auth = {"schema": gate.SCHEMA_AUTH, "statement": gate.STATEMENT, "authorized_by": "Test Person", "authorized_at": "2026-10-19T09:00:00Z", "expires_at": "2026-10-22T09:00:00Z",
            "plan_sha256": P.plan_sha256(plan), "set": "frozen", "allowed_runs": P.run_keys(plan) + ["score/all"]}
    auth.update(over)
    for k in [k for k, v in auth.items() if v is gate]:       # sentinel: drop the key
        del auth[k]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(auth, fh)
    return auth


def slurp(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def jsonl(path):
    return [json.loads(line) for line in slurp(path).splitlines() if line.strip()]


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def path(self, *parts):
        return os.path.join(self.tmp, *parts)


# ================================================================================ the gate
class GateDefaults(TempDirCase):
    def test_unlock_value_matches_the_existing_eval_io_guard(self):
        import config
        self.assertEqual((gate.ENV_UNLOCK, gate.UNLOCK_VALUE), (config.FROZEN_UNLOCK_ENV, config.FROZEN_UNLOCK_VALUE))

    def test_default_environment_is_closed_and_the_loader_is_never_touched(self):
        plan, wire = frozen_plan(), Tripwire()
        with self.assertRaises(gate.GateDenied) as ctx:
            gate.open_frozen(plan, P.plan_sha256(plan), "full_system/run1", self.path("ledger.jsonl"), env={}, now=NOW, acknowledged=False, loader=wire)
        self.assertEqual(wire.calls, [])
        self.assertFalse(os.path.exists(self.path("ledger.jsonl")))
        self.assertTrue(len(ctx.exception.reasons) >= 3)

    def test_environment_variable_alone_is_not_enough(self):
        plan = frozen_plan()
        reasons = gate.decide(plan, P.plan_sha256(plan), "full_system/run1", {gate.ENV_UNLOCK: gate.UNLOCK_VALUE}, NOW, acknowledged=True, ledger_path=self.path("l"))
        self.assertTrue(any("authorisation file" in r for r in reasons))

    def test_authorisation_file_alone_is_not_enough(self):
        plan = frozen_plan()
        write_auth(self.path("auth.json"), plan)
        reasons = gate.decide(plan, P.plan_sha256(plan), "full_system/run1", {gate.ENV_AUTH: self.path("auth.json")}, NOW, acknowledged=True, ledger_path=self.path("l"))
        self.assertTrue(any(gate.ENV_UNLOCK in r for r in reasons))

    def test_acknowledgement_flag_is_required(self):
        plan = frozen_plan()
        write_auth(self.path("auth.json"), plan)
        env = {gate.ENV_UNLOCK: gate.UNLOCK_VALUE, gate.ENV_AUTH: self.path("auth.json")}
        self.assertTrue(any("acknowledgement" in r for r in gate.decide(plan, P.plan_sha256(plan), "full_system/run1", env, NOW, acknowledged=False, ledger_path=self.path("l"))))
        self.assertEqual(gate.decide(plan, P.plan_sha256(plan), "full_system/run1", env, NOW, acknowledged=True, ledger_path=self.path("l")), [])

    def test_the_gate_only_guards_the_frozen_set(self):
        plan = P.make_plan("x", "fixture", engine="instrumented")
        self.assertIn("not a frozen-set plan", gate.decide(plan, P.plan_sha256(plan), "k", {}, NOW, True, self.path("l"))[0])


class GateBadAuthorisations(TempDirCase):
    def setUp(self):
        super().setUp()
        self.plan = frozen_plan()
        self.env = {gate.ENV_UNLOCK: gate.UNLOCK_VALUE, gate.ENV_AUTH: self.path("auth.json")}

    def reasons(self, key="full_system/run1", now=NOW, **over):
        write_auth(self.path("auth.json"), self.plan, **over)
        return gate.decide(self.plan, P.plan_sha256(self.plan), key, self.env, now, True, self.path("l"))

    def test_a_correct_file_opens_the_gate(self):
        self.assertEqual(self.reasons(), [])

    def test_each_defect_closes_it(self):
        cases = {
            "wrong statement": ({"statement": "ok"}, "statement"),
            "empty name": ({"authorized_by": " "}, "authorized_by"),
            "wrong schema": ({"schema": "x"}, "schema"),
            "other plan": ({"plan_sha256": "0" * 64}, "different plan"),
            "other set": ({"set": "dev"}, "frozen set"),
            "run not listed": ({"allowed_runs": ["raw_detector/run1"]}, "allowed_runs"),
            "allowed_runs not a list": ({"allowed_runs": "full_system/run1"}, "allowed_runs"),
            "expired": ({"expires_at": "2026-10-20T11:59:59Z", "authorized_at": "2026-10-19T09:00:00Z"}, "expired"),
            "future": ({"authorized_at": "2026-10-21T09:00:00Z", "expires_at": "2026-10-22T09:00:00Z"}, "future"),
            "window too long": ({"authorized_at": "2026-10-01T00:00:00Z", "expires_at": "2026-11-30T00:00:00Z"}, "window"),
            "backwards window": ({"authorized_at": "2026-10-19T09:00:00Z", "expires_at": "2026-10-18T09:00:00Z"}, "expired"),
            "bad timestamp": ({"authorized_at": "yesterday"}, "look like"),
            "extra field": ({"note": "hi"}, "exactly the required fields"),
            "missing field": ({"expires_at": gate}, "exactly the required fields"),
        }
        for name, (over, fragment) in cases.items():
            with self.subTest(name):
                joined = " | ".join(self.reasons(**over))
                self.assertTrue(joined, name + " should close the gate")
                self.assertIn(fragment, joined)

    def test_malformed_missing_or_oversized_files_close_it(self):
        gate_args = (self.plan, P.plan_sha256(self.plan), "full_system/run1", self.env, NOW, True, self.path("l"))
        with open(self.path("auth.json"), "w") as fh:
            fh.write("{not json")
        self.assertTrue(gate.decide(*gate_args))
        with open(self.path("auth.json"), "w") as fh:
            fh.write("[]")
        self.assertTrue(gate.decide(*gate_args))
        with open(self.path("auth.json"), "w") as fh:
            fh.write(" " * (gate.MAX_AUTH_BYTES + 1))
        self.assertTrue(any("too large" in r for r in gate.decide(*gate_args)))
        os.remove(self.path("auth.json"))
        self.assertTrue(any("does not exist" in r for r in gate.decide(*gate_args)))

    def test_editing_the_plan_invalidates_the_authorisation(self):
        write_auth(self.path("auth.json"), self.plan)
        edited = copy.deepcopy(self.plan)
        edited["model"]["temperature"] = 0.7
        self.assertTrue(any("different plan" in r for r in gate.decide(edited, P.plan_sha256(edited), "full_system/run1", self.env, NOW, True, self.path("l"))))

    def test_unexpected_internal_errors_fail_closed(self):
        class Boom(dict):
            def get(self, *a):
                raise RuntimeError("boom")
        self.assertTrue(gate.decide(Boom(set="frozen"), "x", "k", self.env, NOW, True, self.path("l")))


class GateOpening(TempDirCase):
    def setUp(self):
        super().setUp()
        self.plan = frozen_plan()
        write_auth(self.path("auth.json"), self.plan)
        self.env = {gate.ENV_UNLOCK: gate.UNLOCK_VALUE, gate.ENV_AUTH: self.path("auth.json")}
        self.fx = D.fixture_data(8)

    def test_an_authorised_run_opens_once_and_is_ledgered_before_loading(self):
        wire = Tripwire(self.fx)
        data = gate.open_frozen(self.plan, P.plan_sha256(self.plan), "full_system/run1", self.path("ledger.jsonl"), self.env, NOW, True, loader=wire)
        self.assertEqual(data.set_name, "frozen")
        self.assertEqual([c[0] for c in wire.calls], ["load_alerts", "load_labels", "load_flow_store"])
        self.assertTrue(all(c[1] == "frozen" and "full_system/run1" in c[2] for c in wire.calls))
        ledger = gate.read_ledger(self.path("ledger.jsonl"))
        self.assertEqual([r["run_key"] for r in ledger], ["full_system/run1"])
        with self.assertRaises(gate.GateDenied) as ctx:                      # a second look at the same run is refused
            gate.open_frozen(self.plan, P.plan_sha256(self.plan), "full_system/run1", self.path("ledger.jsonl"), self.env, NOW, True, loader=Tripwire(self.fx))
        self.assertIn("already opened", " ".join(ctx.exception.reasons))

    def test_a_crash_while_loading_still_leaves_the_ledger_line(self):
        class Crash(Tripwire):
            def load_alerts(self, which, reason=None):
                raise OSError("disk")
        with self.assertRaises(OSError):
            gate.open_frozen(self.plan, P.plan_sha256(self.plan), "raw_detector/run1", self.path("ledger.jsonl"), self.env, NOW, True, loader=Crash(self.fx))
        self.assertEqual(len(gate.read_ledger(self.path("ledger.jsonl"))), 1)
        with self.assertRaises(gate.GateDenied):
            gate.open_frozen(self.plan, P.plan_sha256(self.plan), "raw_detector/run1", self.path("ledger.jsonl"), self.env, NOW, True, loader=Tripwire(self.fx))

    def test_other_runs_are_not_affected_by_one_ledger_line(self):
        for key in ("raw_detector/run1", "raw_detector/run2"):
            gate.open_frozen(self.plan, P.plan_sha256(self.plan), key, self.path("ledger.jsonl"), self.env, NOW, True, loader=Tripwire(self.fx))
        self.assertEqual(len(gate.read_ledger(self.path("ledger.jsonl"))), 2)


class NeverTouchesProtectedData(TempDirCase):
    def test_the_rehearsal_never_calls_the_loader(self):
        """Run the whole rehearsal in a fresh interpreter in which eval_io is a tripwire: it must finish and the tripwire must record nothing."""
        script = ("import sys, types\n"
                  "calls = []\n"
                  "m = types.ModuleType('eval_io')\n"
                  "def hit(*a, **k):\n    calls.append(a)\n    raise AssertionError('eval_io was called')\n"
                  "m.load_alerts = m.load_labels = m.load_flow_store = m.load_mitre_map = hit\n"
                  "sys.modules['eval_io'] = m\n"
                  "from week5.evalrun import pipeline\n"
                  "result, files, out = pipeline.rehearse(sys.argv[1])\n"
                  "assert result['valid'], result['problems']\n"
                  "assert calls == [], calls\n"
                  "print('clean')\n")
        env = dict(os.environ, PYTHONPATH=SRC + os.pathsep + os.path.dirname(SRC))
        env.pop(gate.ENV_UNLOCK, None)
        out = subprocess.run([sys.executable, "-c", script, self.path("rehearsal_out")], capture_output=True, text=True, env=env, timeout=240)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("clean", out.stdout)

    def test_only_the_gate_and_the_dev_branch_mention_the_loader(self):
        for name in sorted(os.listdir(EVALRUN_DIR)):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(EVALRUN_DIR, name), "r", encoding="utf-8") as fh:
                text = fh.read()
            self.assertNotRegex(text, r"frozen_(alerts|labels)|flow_store_frozen|FROZEN_(ALERTS|LABELS)_PATH|FLOW_STORE_FROZEN", name)      # no path to a protected file is ever computed here
            if name not in ("gate.py", "pipeline.py"):
                self.assertNotRegex(text, r"(?m)^\s*(import eval_io|from eval_io)", name)
            for hit in re.findall(r"load_(?:alerts|labels|flow_store)\(\s*\"frozen\"", text):
                self.assertEqual(name, "gate.py")
        with open(os.path.join(EVALRUN_DIR, "gate.py"), "r", encoding="utf-8") as fh:
            gate_text = fh.read()
        self.assertEqual(gate_text.count("import eval_io"), 1)
        self.assertLess(gate_text.index("def open_frozen"), gate_text.index("import eval_io as loader"))

    def test_live_runs_are_refused_before_any_data_is_loaded(self):
        plan = frozen_plan()
        wire = Tripwire()
        with self.assertRaises(pipeline.PipelineError):
            pipeline.collect_one(plan, "single_llm_baseline", 1, self.path("o"), live=False, env={}, loader=wire)
        with self.assertRaises(pipeline.PipelineError):
            pipeline.collect_one(plan, "single_llm_baseline", 1, self.path("o"), live=True, env={}, loader=wire)         # --live without WEEK5_ALLOW_LIVE_MODEL=1
        self.assertEqual(wire.calls, [])
        self.assertFalse(os.path.exists(self.path("o")))
        with self.assertRaises(pipeline.PipelineError):
            pipeline.live_backends(P.make_plan("x", "fixture", engine="instrumented"), {})


# ================================================================================ plan
class PlanTests(unittest.TestCase):
    def test_default_plan_is_valid_and_shares_one_model(self):
        plan = P.make_plan("p", "fixture", engine="instrumented")
        self.assertEqual(set(plan["configs"]), set(CONFIGS))
        self.assertEqual(plan["runs_per_config"], 3)
        self.assertTrue(plan["model"]["fake"])
        self.assertEqual(P.run_keys(plan)[:3], ["raw_detector/run1", "raw_detector/run2", "raw_detector/run3"])
        self.assertEqual(len(P.run_keys(plan)), 9)

    def test_hash_changes_with_any_setting(self):
        a = P.make_plan("p", "fixture", engine="instrumented")
        b = P.make_plan("p", "fixture", memory="on", engine="instrumented")
        c = P.make_plan("p", "fixture", alias_ids=True, engine="instrumented")
        self.assertEqual(len({P.plan_sha256(x) for x in (a, b, c)}), 3)
        self.assertEqual(P.plan_sha256(a), P.plan_sha256(copy.deepcopy(a)))

    def test_invalid_plans_are_named(self):
        base = P.make_plan("p", "fixture", engine="instrumented")
        cases = {"runs": lambda p: p.update(runs_per_config=2), "configs": lambda p: p["configs"].pop("raw_detector"), "memory": lambda p: p["configs"]["full_system"].update(memory="maybe"),
                 "fake name": lambda p: p["model"].update(fake=False), "fixture real": lambda p: p["model"].update(name="gemini-x", fake=False), "set": lambda p: p.update(set="test"),
                 "dev fake": lambda p: p.update(set="dev"), "frozen instrumented": lambda p: p.update(set="frozen", model={"name": "g", "fake": False, "temperature": 0, "max_output_tokens": 1, "seed": 1, "parse_retries": 1}),
                 "model key": lambda p: p["model"].pop("seed")}
        for name, edit in cases.items():
            with self.subTest(name):
                plan = copy.deepcopy(base)
                edit(plan)
                self.assertTrue(P.validate_plan(plan), name)

    def test_project_defaults_report_missing_files_clearly(self):
        try:
            P.project_defaults()
        except RuntimeError as error:
            self.assertIn("project settings", str(error))
        except Exception as error:      # a checkout with the Week 2 files may legitimately succeed or fail in other ways here
            self.fail("unexpected %s" % type(error).__name__)


# ================================================================================ collection, validation, metrics
class Rehearsed(TempDirCase):
    """One full rehearsal per test class (cheap: 24 fixture alerts, fake models)."""
    result = out_dir = root = plan = data = None

    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        cls.result, cls.files, cls.out_dir = pipeline.rehearse(cls.root, "rh", engine="instrumented")
        cls.plan = cls.result["plan"]
        cls.data = D.fixture_data(24)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    copies = 0

    def fresh_copy(self):
        type(self).copies += 1
        dst = self.path("copy%d" % type(self).copies)
        shutil.copytree(self.root, dst)
        return dst


class CollectTests(Rehearsed):
    def test_nine_runs_with_unique_ids_and_all_files(self):
        ids = []
        for config in CONFIGS:
            for i in (1, 2, 3):
                run = os.path.join(self.root, "rh", config, "run%d" % i)
                self.assertEqual(sorted(os.listdir(run)), sorted(list(C.FILES) + ["run.sha256"]))
                with open(os.path.join(run, "run_meta.json")) as fh:
                    meta = json.load(fh)
                ids.append(meta["run_id"])
                self.assertEqual((meta["status"], meta["alerts_recorded"], meta["concurrency"]), ("complete", 24, 1))
        self.assertEqual(len(set(ids)), 9)

    def test_runs_are_write_once(self):
        with self.assertRaises(C.CollectError):
            C.collect_run(self.plan, "raw_detector", 1, self.data, self.root)

    def test_a_crash_leaves_a_visible_partial_and_validation_reports_it(self):
        import gemini_client
        root = self.path("crash")
        plan = P.make_plan("cr", "fixture", engine="instrumented")

        class Dies(R.ScriptedClient):
            def generate(self, prompt):
                if self.i == 3:
                    raise gemini_client.PermanentModelError("refused", 400)
                return super().generate(prompt)
        with self.assertRaises(gemini_client.PermanentModelError):
            C.collect_run(plan, "single_llm_baseline", 1, self.data, root, client=Dies(R.baseline_script(24)))
        self.assertTrue(os.path.isdir(os.path.join(root, "cr", "single_llm_baseline", "run1.partial")))
        self.assertFalse(os.path.isdir(os.path.join(root, "cr", "single_llm_baseline", "run1")))
        with self.assertRaises(C.CollectError):                              # and it cannot be silently overwritten
            C.collect_run(plan, "single_llm_baseline", 1, self.data, root, client=R.ScriptedClient(R.baseline_script(24)))
        codes = {p["code"] for p in V.validate_runs(plan, root)["problems"]}
        self.assertIn("PARTIAL_RUN", codes)
        self.assertIn("MISSING_RUN", codes)

    def test_wrong_set_and_missing_backends_are_refused(self):
        with self.assertRaises(C.CollectError):
            C.collect_run(self.plan, "raw_detector", 2, D.EvalData("dev", self.data.alerts, self.data.labels, self.data.flows), self.path("x"))
        with self.assertRaises(C.CollectError):
            C.collect_run(self.plan, "single_llm_baseline", 1, self.data, self.path("y"))
        with self.assertRaises(C.CollectError):
            C.collect_run(self.plan, "full_system", 1, self.data, self.path("z"))
        with self.assertRaises(C.CollectError):
            C.collect_run(self.plan, "raw_detector", 4, self.data, self.path("w"))

    def test_no_prompt_or_raw_reply_is_stored(self):
        for config in ("single_llm_baseline", "full_system"):
            with open(os.path.join(self.root, "rh", config, "run1", "results.jsonl")) as fh:
                text = fh.read()
            self.assertNotIn('"reply"', text)
            self.assertNotIn('"prompt":', text)
            self.assertIn("prompt_sha256", text)
            for line in text.splitlines():
                rec = json.loads(line)
                if rec.get("verdict"):
                    self.assertIsNone(rec["verdict"].get("evidence"))

    def test_failures_are_classified_and_listed(self):
        recs = jsonl(os.path.join(self.root, "rh", "full_system", "run1", "results.jsonl"))
        kinds = sorted({r["failure_kind"] for r in recs})
        self.assertEqual(kinds, ["model_unavailable", "none", "parse_failure"])
        errors = jsonl(os.path.join(self.root, "rh", "full_system", "run1", "errors.jsonl"))
        self.assertEqual(len(errors), 2)

    def test_observed_model_is_recorded_from_the_client_not_the_plan(self):
        with open(os.path.join(self.root, "rh", "single_llm_baseline", "run1", "run_meta.json")) as fh:
            meta = json.load(fh)
        self.assertEqual(meta["observed"]["model"], "FAKE:rehearsal")

    def test_the_system_failure_of_one_alert_is_recorded_not_fatal(self):
        class BrokenRunner:
            provider = R.full_system_provider(["x"])

            def execute(self, *a, **k):
                raise KeyError("boom")
        recs = list(C.full_system_records(self.plan, D.fixture_data(3), BrokenRunner(), False))
        self.assertEqual([(r["status"], C.failure_kind(r), r["error_code"]) for r in recs], [("model_error", "system_error", "system_exception")] * 3)
        self.assertEqual(recs[0]["error_detail"], "the system raised KeyError")


class ValidationTests(Rehearsed):
    def rewrite(self, root, rel, edit, plan_id="rh"):
        """Change one file of one run and recompute run.sha256 so that ONLY the intended check can trip."""
        run_dir = os.path.join(root, plan_id, os.path.dirname(rel))
        name = os.path.basename(rel)
        path = os.path.join(run_dir, name)
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(edit(text))
        with open(os.path.join(run_dir, "run.sha256"), "w", encoding="ascii", newline="\n") as fh:
            for n in C.FILES:
                fh.write("%s  %s\n" % (C.sha256_file(os.path.join(run_dir, n)), n))

    def codes(self, root, data=None, plan=None):
        rep = V.validate_runs(plan or self.plan, root, data)
        return {p["code"] for p in rep["problems"]}, rep

    def edit_meta(self, root, rel, **changes):
        def edit(text):
            meta = json.loads(text)
            for k, v in changes.items():
                meta[k] = v
            return json.dumps(meta, indent=1, sort_keys=True) + "\n"
        self.rewrite(root, rel, edit)

    def edit_records(self, root, rel, fn):
        def edit(text):
            recs = [json.loads(l) for l in text.splitlines() if l.strip()]
            recs = fn(recs)
            return "".join(json.dumps(r, sort_keys=True) + "\n" for r in recs)
        self.rewrite(root, rel, edit)

    def test_the_rehearsal_is_valid(self):
        codes, rep = self.codes(self.root, self.data)
        self.assertEqual(codes, set())
        self.assertTrue(rep["valid"])

    def test_missing_run(self):
        root = self.fresh_copy()
        shutil.rmtree(os.path.join(root, "rh", "full_system", "run2"))
        self.assertIn("MISSING_RUN", self.codes(root)[0])

    def test_unexpected_run_folder(self):
        root = self.fresh_copy()
        os.makedirs(os.path.join(root, "rh", "full_system", "run4"))
        self.assertIn("UNEXPECTED_RUN", self.codes(root)[0])

    def test_truncated_results_file(self):
        root = self.fresh_copy()
        path = os.path.join(root, "rh", "single_llm_baseline", "run1", "results.jsonl")
        with open(path, "r+", encoding="utf-8") as fh:
            lines = fh.readlines()
            fh.seek(0)
            fh.writelines(lines[:-3])
            fh.truncate()
        self.assertIn("HASH_MISMATCH", self.codes(root)[0])

    def test_missing_file(self):
        root = self.fresh_copy()
        os.remove(os.path.join(root, "rh", "raw_detector", "run3", "errors.jsonl"))
        self.assertIn("MISSING_FILE", self.codes(root)[0])

    def test_run_of_a_different_plan(self):
        root = self.fresh_copy()
        self.edit_meta(root, "full_system/run1/run_meta.json", plan_sha256="0" * 64)
        self.assertIn("PLAN_MISMATCH", self.codes(root)[0])

    def test_incomplete_status(self):
        root = self.fresh_copy()
        self.edit_meta(root, "raw_detector/run1/run_meta.json", status="running")
        self.assertIn("NOT_COMPLETE", self.codes(root)[0])

    def test_record_count_mismatch_and_missing_alerts(self):
        root = self.fresh_copy()
        self.edit_records(root, "single_llm_baseline/run2/results.jsonl", lambda recs: recs[:-1])
        codes, _ = self.codes(root, self.data)
        self.assertIn("COUNT_MISMATCH", codes)
        self.assertIn("ALERT_SET_MISMATCH", codes)

    def test_order_mismatch(self):
        root = self.fresh_copy()
        self.edit_records(root, "raw_detector/run1/results.jsonl", lambda recs: list(reversed(recs)))
        self.assertIn("ALERT_ORDER_MISMATCH", self.codes(root, self.data)[0])

    def test_duplicate_alert(self):
        root = self.fresh_copy()
        self.edit_records(root, "single_llm_baseline/run3/results.jsonl", lambda recs: recs[:-1] + [dict(recs[0])])
        self.assertIn("DUPLICATE_ALERT", self.codes(root)[0])

    def test_schema_problems(self):
        for name, fn in {"missing key": lambda r: [{k: v for k, v in r[0].items() if k != "status"}] + r[1:],
                         "bad status": lambda r: [dict(r[0], status="great")] + r[1:],
                         "ok without verdict": lambda r: [dict(r[0], verdict=None)] + r[1:],
                         "verdict on a failure": lambda r: [dict(r[0], status="parse_failed", failure_kind="parse_failure")] + r[1:]}.items():
            with self.subTest(name):
                root = self.fresh_copy()
                self.edit_records(root, "single_llm_baseline/run1/results.jsonl", fn)
                self.assertIn("RECORD_SCHEMA", self.codes(root)[0])

    def test_errors_file_must_match_the_records(self):
        root = self.fresh_copy()
        self.rewrite(root, "full_system/run1/errors.jsonl", lambda text: "")
        self.assertIn("ERRORS_MISMATCH", self.codes(root)[0])

    def test_input_records_or_labels_that_differ_between_runs(self):
        root = self.fresh_copy()
        meta_path = os.path.join(root, "rh", "full_system", "run3", "run_meta.json")
        with open(meta_path) as fh:
            inputs = json.load(fh)["inputs"]
        self.edit_meta(root, "full_system/run3/run_meta.json", inputs=dict(inputs, labels_sha256="f" * 64))
        self.assertIn("INPUT_MISMATCH", self.codes(root)[0])

    def test_data_supplied_now_must_match_what_the_runs_used(self):
        changed = D.fixture_data(24)
        changed.labels.loc[0, "label"] = "DDoS"
        self.assertIn("INPUT_MISMATCH", self.codes(self.root, changed)[0])
        other = D.fixture_data(20)
        self.assertIn("ALERT_SET_MISMATCH", self.codes(self.root, other)[0])

    def test_different_model_or_settings_in_a_run(self):
        for field, value in (("model", "gemini-other"), ("temperature", 0.9), ("seed", 7), ("max_output_tokens", 5)):
            with self.subTest(field):
                root = self.fresh_copy()
                path = os.path.join(root, "rh", "single_llm_baseline", "run2", "run_meta.json")
                with open(path) as fh:
                    observed = json.load(fh)["observed"]
                self.edit_meta(root, "single_llm_baseline/run2/run_meta.json", observed=dict(observed, **{field: value}))
                self.assertIn("OBSERVED_MODEL_MISMATCH", self.codes(root)[0])

    def test_plan_model_recorded_in_a_run_must_match_the_plan(self):
        root = self.fresh_copy()
        self.edit_meta(root, "full_system/run1/run_meta.json", model=dict(self.plan["model"], temperature=0.5))
        self.assertIn("MODEL_MISMATCH", self.codes(root)[0])

    def test_fake_flag_mismatch_and_mixing(self):
        root = self.fresh_copy()
        self.edit_meta(root, "full_system/run1/run_meta.json", fake_model=False)
        codes, _ = self.codes(root)
        self.assertIn("FAKE_MISMATCH", codes)
        self.assertIn("FAKE_MIXED", codes)

    def test_fake_runs_cannot_belong_to_a_real_plan(self):
        real = copy.deepcopy(self.plan)
        real["set"] = "dev"
        codes, _ = self.codes(self.root, plan=real)
        self.assertIn("BAD_PLAN", codes)

    def test_threshold_and_policy_mismatch(self):
        root = self.fresh_copy()
        self.edit_meta(root, "raw_detector/run1/run_meta.json", threshold=0.5)
        self.assertIn("THRESHOLD_MISMATCH", self.codes(root)[0])
        root2 = self.fresh_copy()

        def bad_policy(recs):
            recs[0]["routing"] = dict(recs[0]["routing"], policy_sha256="0" * 64)
            return recs
        self.edit_records(root2, "full_system/run1/results.jsonl", bad_policy)
        self.assertIn("POLICY_MISMATCH", self.codes(root2)[0])

    def test_raw_detector_must_be_deterministic(self):
        root = self.fresh_copy()

        def flip(recs):
            recs[0]["verdict"] = dict(recs[0]["verdict"], is_malicious=False)
            return recs
        self.edit_records(root, "raw_detector/run2/results.jsonl", flip)
        self.assertIn("RAW_NOT_DETERMINISTIC", self.codes(root)[0])

    def test_duplicate_run_id(self):
        root = self.fresh_copy()
        with open(os.path.join(root, "rh", "raw_detector", "run1", "run_meta.json")) as fh:
            rid = json.load(fh)["run_id"]
        self.edit_meta(root, "raw_detector/run2/run_meta.json", run_id=rid)
        self.assertIn("DUPLICATE_RUN_ID", self.codes(root)[0])

    def test_a_changed_config_snapshot_is_detected(self):
        root = self.fresh_copy()

        def edit(text):
            snap = json.loads(text)
            snap["config_settings"] = dict(snap["config_settings"], memory="on")
            return json.dumps(snap, indent=1, sort_keys=True) + "\n"
        self.rewrite(root, "full_system/run1/config_snapshot.json", edit)
        self.assertIn("CONFIG_MISMATCH", self.codes(root)[0])


class MetricsTests(Rehearsed):
    """The fixture, the scripted replies and the definitions are all known, so the expected numbers are worked out here independently of the code under test."""

    def expected_baseline(self):
        tp = fp = fn = tn = 0
        for i in range(24):
            actual = (i % 4) in (0, 1)
            predicted = R._verdict(i)["is_malicious"]
            tp += actual and predicted
            fp += (not actual) and predicted
            fn += actual and (not predicted)
            tn += (not actual) and (not predicted)
        return tp, fp, fn, tn

    def test_raw_detector_is_malicious_for_every_alert(self):
        m = self.result["per_run"]["raw_detector/run1"]
        c = m["verdict"]["valid_only"]["detector_confusion"]
        self.assertEqual((c["tp"], c["fp"], c["fn"], c["tn"]), (12, 12, 0, 0))
        self.assertAlmostEqual(m["verdict"]["valid_only"]["detector"]["precision"]["value"], 0.5)
        self.assertEqual(m["failure_breakdown"]["no_verdict_system_failures"], {"parse_failure": 0, "model_unavailable": 0, "system_error": 0})

    def test_baseline_counts_match_the_hand_computation(self):
        tp, fp, fn, tn = self.expected_baseline()
        c = self.result["per_run"]["single_llm_baseline/run1"]["verdict"]["valid_only"]["llm_confusion"]
        self.assertEqual((c["tp"], c["fp"], c["fn"], c["tn"]), (tp, fp, fn, tn))

    def test_system_failures_are_not_counted_as_classification_errors(self):
        fb = self.result["per_run"]["full_system/run1"]["failure_breakdown"]
        self.assertEqual(fb["no_verdict_system_failures"], {"parse_failure": 1, "model_unavailable": 1, "system_error": 0})
        self.assertEqual(fb["valid_verdicts"], 22)
        self.assertEqual(fb["classification_errors_among_valid_verdicts"], fb["of_which_false_positives"] + fb["of_which_false_negatives"])
        pop = self.result["per_run"]["full_system/run1"]["population"]
        self.assertEqual((pop["ok"], pop["parse_failed"], pop["model_error"]), (22, 1, 1))
        # the three no-verdict policies give different answers exactly because 2 alerts have no verdict
        v = self.result["per_run"]["full_system/run1"]["verdict"]
        self.assertNotEqual(v["valid_only"]["alerts_in_population"], v["failures_wrong"]["alerts_in_population"])

    def test_routing_covers_every_alert_and_no_attack_is_auto_closed_here(self):
        r = self.result["per_run"]["full_system/run1"]["routing"]
        self.assertEqual(sum(r["counts"].values()), 24)
        self.assertEqual(r["true_attacks_auto_closed"]["numerator"], 0)
        self.assertEqual(r["auto_closed_attack_alert_ids"], [])

    def test_fake_runs_report_no_tokens_and_no_cost(self):
        m = self.result["per_run"]["full_system/run1"]
        self.assertIsNone(m["tokens"]["total_tokens"])
        self.assertFalse(m["cost"]["available"])
        self.assertIn("fake", m["cost"]["reason"])

    def test_throughput_and_latency_are_reported_separately(self):
        t = self.result["per_run"]["single_llm_baseline/run1"]["throughput"]
        self.assertEqual(t["alerts"], 24)
        self.assertGreater(t["alerts_per_second"], 0)
        self.assertIn("per_alert_all_observations", self.result["per_run"]["single_llm_baseline/run1"]["latency"])

    def test_spread_and_agreement(self):
        s = M.spread([1.0, 2.0, 3.0])
        self.assertEqual((s["mean"], s["min"], s["max"], s["range"]), (2.0, 1.0, 3.0, 2.0))
        self.assertIsNone(M.spread([None, None])["mean"])
        a = pd.DataFrame({"pred_malicious": [True, False, None]})
        b = pd.DataFrame({"pred_malicious": [True, True, None]})
        ag = M.verdict_agreement([a, b, a])
        self.assertEqual((ag["alerts_identical_in_all_runs"], ag["alerts_with_a_different_outcome_in_some_run"]), (2, 1))
        self.assertIsNone(M.verdict_agreement([a]))

    def test_each_run_is_scored_with_the_week2_input_checks(self):
        """The Week 2 check_inputs refuses alerts below the detector threshold; a run on such data must not be scored."""
        low = D.fixture_data(24)
        low.alerts.loc[0, "detector_score"] = 0.0
        rep = V.validate_runs(self.plan, self.root, self.data)
        run = rep["runs"]["raw_detector/run1"]
        from evaluate import EvaluationInputError
        with self.assertRaises(EvaluationInputError):
            M.run_metrics(run, low)


class ReportTests(Rehearsed):
    def test_rehearsal_report_is_labelled_synthetic_and_complete(self):
        text = slurp(os.path.join(self.out_dir, "COMPARISON_REPORT.md"))
        self.assertIn("REHEARSAL", text)
        self.assertIn("NOTHING about the detector", text)
        for heading in ("## 1. Validity", "## 2. Definitions", "## 3. Raw detector", "## 4. Comparison", "## 5. Failures kept apart", "## 6. Full system: routing", "## 7. Stability",
                        "## 8. Per-class results", "## 9. Sources of non-determinism"):
            self.assertIn(heading, text)
        self.assertIn("No significance test", text)
        self.assertIn("TRUE ATTACKS AUTO-CLOSED", text)

    def test_machine_readable_outputs(self):
        with open(os.path.join(self.out_dir, "comparison.json")) as fh:
            res = json.load(fh)
        self.assertEqual(res["schema"], "week5-evalrun-comparison-v1")
        self.assertTrue(res["valid"])
        self.assertEqual(sorted(res["per_run"]), sorted(P.run_keys(self.plan)))
        self.assertEqual(res["plan_sha256"], P.plan_sha256(self.plan))
        with open(os.path.join(self.out_dir, "comparison_metrics.csv")) as fh:
            rows = fh.read().splitlines()
        self.assertEqual(rows[0], "config,run,metric,value")
        self.assertGreater(len(rows), 50)

    def test_invalid_runs_produce_no_numbers(self):
        root = self.path("broken")
        shutil.copytree(self.root, root)
        shutil.rmtree(os.path.join(root, "rh", "full_system", "run1"))
        result, files, out_dir = pipeline.score(self.plan, root, data=self.data)
        self.assertFalse(result["valid"])
        self.assertIsNone(result["per_run"])
        text = slurp(os.path.join(out_dir, "COMPARISON_REPORT.md"))
        self.assertIn("NOT COMPARABLE", text)
        self.assertIn("MISSING_RUN", text)
        self.assertNotIn("## 4. Comparison", text)
        with open(os.path.join(out_dir, "comparison_metrics.csv")) as fh:
            self.assertEqual(len(fh.read().splitlines()), 1)

    def test_the_rehearsal_is_reproducible_apart_from_ids_and_timings(self):
        def strip(path):
            out = []
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    rec = json.loads(line)
                    for k in [k for k in rec if k in ("wall_seconds", "latency_seconds") or "utc" in k]:
                        rec.pop(k)
                    out.append(rec)
            return out
        other = self.path("again")
        pipeline.rehearse(other, "rh", engine="instrumented")
        for config in CONFIGS:
            self.assertEqual(strip(os.path.join(self.root, "rh", config, "run1", "results.jsonl")), strip(os.path.join(other, "rh", config, "run1", "results.jsonl")), config)


# ================================================================================ authorised path end to end + CLI
class AuthorisedFlow(TempDirCase):
    def test_authorised_frozen_run_with_an_injected_loader(self):
        plan = frozen_plan()
        fx = D.fixture_data(24)
        write_auth(self.path("auth.json"), plan)
        env = {gate.ENV_UNLOCK: gate.UNLOCK_VALUE, gate.ENV_AUTH: self.path("auth.json")}
        wire = Tripwire(fx)
        client = R.ScriptedClient(R.baseline_script(24))
        client.model = "gemini-test"
        client.config = {"temperature": 0.0, "max_output_tokens": 1024, "seed": 42}
        # the gate's clock is the real one; the authorisation above is dated in the past, so build a window around the real now
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        write_auth(self.path("auth.json"), plan, authorized_at=(now - datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), expires_at=(now + datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        out = pipeline.collect_one(plan, "raw_detector", 1, self.path("o"), env=env, acknowledged=True, loader=wire)
        self.assertTrue(os.path.isdir(out))
        self.assertEqual(len(wire.calls), 3)
        self.assertEqual(len(gate.read_ledger(os.path.join(self.path("o"), "final", gate.LEDGER_NAME))), 1)
        with self.assertRaises(gate.GateDenied):
            pipeline.collect_one(plan, "raw_detector", 1, self.path("o"), env=env, acknowledged=True, loader=Tripwire(fx))
        with self.assertRaises(gate.GateDenied):                              # without the acknowledgement flag
            pipeline.collect_one(plan, "raw_detector", 2, self.path("o"), env=env, acknowledged=False, loader=Tripwire(fx))


class CliTests(TempDirCase):
    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(list(args))
        return code, out.getvalue()

    def test_rehearse_command(self):
        code, text = self.run_cli("rehearse", "--out-root", self.path("r"), "--plan-id", "c1")
        self.assertEqual(code, 0)
        self.assertIn("REHEARSAL", text)
        self.assertTrue(os.path.isfile(self.path("r", "c1", "comparison", "COMPARISON_REPORT.md")))

    def test_plan_command_for_the_fixture(self):
        code, text = self.run_cli("plan", "--set", "fixture", "--plan-id", "c2", "--out", self.path("plan.json"))
        self.assertEqual(code, 0)
        with open(self.path("plan.json")) as fh:
            plan = json.load(fh)
        self.assertIn(P.plan_sha256(plan), text)

    def test_gate_status_is_closed_by_default_and_reads_nothing_protected(self):
        plan = frozen_plan()
        with open(self.path("plan.json"), "w") as fh:
            json.dump(plan, fh)
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            for k in (gate.ENV_UNLOCK, gate.ENV_AUTH):
                os.environ.pop(k, None)
            code, text = self.run_cli("gate-status", "--plan", self.path("plan.json"), "--run-key", "full_system/run1")
        self.assertEqual(code, 3)
        self.assertIn("CLOSED", text)

    def test_collect_on_a_frozen_plan_is_refused_without_creating_anything(self):
        plan = frozen_plan()
        with open(self.path("plan.json"), "w") as fh:
            json.dump(plan, fh)
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            for k in (gate.ENV_UNLOCK, gate.ENV_AUTH):
                os.environ.pop(k, None)
            code, text = self.run_cli("collect", "--plan", self.path("plan.json"), "--config", "raw_detector", "--run", "1", "--out-root", self.path("out"), "--i-understand-this-opens-the-frozen-set")
        self.assertEqual(code, 3)
        self.assertIn("STOPPED", text)
        self.assertFalse(os.path.exists(self.path("out")))

    def test_authorization_template_is_blank_and_not_accepted(self):
        plan = frozen_plan()
        with open(self.path("plan.json"), "w") as fh:
            json.dump(plan, fh)
        code, _ = self.run_cli("authorization-template", "--plan", self.path("plan.json"), "--out", self.path("auth.json"))
        self.assertEqual(code, 0)
        with open(self.path("auth.json")) as fh:
            auth = json.load(fh)
        self.assertEqual((auth["authorized_by"], auth["authorized_at"], auth["expires_at"]), ("", "", ""))
        self.assertEqual(auth["plan_sha256"], P.plan_sha256(plan))
        env = {gate.ENV_UNLOCK: gate.UNLOCK_VALUE, gate.ENV_AUTH: self.path("auth.json")}
        self.assertTrue(gate.decide(plan, P.plan_sha256(plan), "raw_detector/run1", env, NOW, True, self.path("l")))

    def test_validate_command_reports_problems_with_a_nonzero_exit(self):
        self.run_cli("rehearse", "--out-root", self.path("r"), "--plan-id", "c3")
        with open(self.path("r", "c3", "comparison", "comparison.json")) as fh:
            plan = json.load(fh)["plan"]
        with open(self.path("plan.json"), "w") as fh:
            json.dump(plan, fh)
        self.assertEqual(self.run_cli("validate", "--plan", self.path("plan.json"), "--out-root", self.path("r"))[0], 0)
        shutil.rmtree(self.path("r", "c3", "raw_detector", "run1"))
        code, text = self.run_cli("validate", "--plan", self.path("plan.json"), "--out-root", self.path("r"))
        self.assertEqual(code, 1)
        self.assertIn("MISSING_RUN", text)


class RunnerExecuteTests(unittest.TestCase):
    def test_execute_is_what_run_uses_and_returns_routing(self):
        from tests import week5_support as W5
        rig = W5.Rig()
        from week5 import fixtures
        ex = rig.runner.execute(fixtures.make_alert(0, "EX"), False, 1, 1)
        self.assertEqual(ex.state["alert_id"], "EX-000000")
        self.assertIn(ex.routed["routing"]["decision"], ("auto_close", "escalate", "needs_review"))
        self.assertTrue(ex.caller.calls)


if __name__ == "__main__":
    import unittest.mock  # noqa: F401
    unittest.main()
