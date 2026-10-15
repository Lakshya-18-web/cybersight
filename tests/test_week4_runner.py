"""Week 4 runner and case ingest: run_memory_dev.py (memory off / on, fake model only) and ingest_cases.py.
Offline: the runner's FakeClient (canned replies), a fixture flow store, a synthetic memory store. No model call, no network, no real data, no frozen set."""
import ast
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import pandas as pd

import baseline_store as store
import config
import llm_config
import run_agent_dev as w3
import run_baseline_dev as base
from agents import verdict_prompt as VP
from tools import FlowStore

from week4 import ingest_cases, policy as policy_module, run_memory_dev as runner, seed_memory
from week4.db.fake import MemoryRepository
from week4.graph import prompt as P2
from week4.memory import records as R, store as MS

from tests.test_week3_day5 import BASELINE_V3_SHA, Offline, full_alerts_frame
from tests.week4_support import make_train_frame, seed_analysts

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")


def read_text(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class RunnerBase(Offline):
    TRAIN_SHA = "e" * 64      # the (made-up) hash recorded as the train file's in the synthetic memory manifest

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.runs = os.path.join(self.tmp.name, "v2_runs")
        self.w3_runs = os.path.join(self.tmp.name, "w3_runs")
        self.base_runs = os.path.join(self.tmp.name, "baseline_runs")
        frame = make_train_frame(per_class=30)
        self.mem_dir = os.path.join(self.tmp.name, "memory_store")
        self.memory = MS.seed_store(R.candidates_from_frame(frame), self.mem_dir, self.TRAIN_SHA, len(frame), per_class_cap=20, say=lambda *_: None)
        self.dev_keys = []
        patches = [mock.patch.object(base, "load_inputs", return_value=(full_alerts_frame(), pd.DataFrame(), {"dev_alerts_sha256": "a", "flow_store_dev_sha256": "b"})),
                   mock.patch.object(FlowStore, "from_dev", return_value=self.store),
                   mock.patch.object(base, "check_llm_config", return_value={"small": "gemini-test-lite", "strong": "gemini-test-pro"}),
                   mock.patch.object(base, "git_info", return_value={"commit": "abc1234", "dirty": False}),
                   mock.patch.object(base, "package_versions", return_value={}),
                   mock.patch.object(base, "week1_snapshot", return_value={}),
                   mock.patch.object(base, "count_lines", return_value=0),
                   mock.patch.object(seed_memory, "dev_key_texts", side_effect=lambda: list(self.dev_keys))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        out = mock.patch("sys.stdout")
        out.start()
        self.addCleanup(out.stop)

    def run_main(self, *args):
        return runner.main(["--runs-dir", self.runs, "--baseline-runs-dir", self.base_runs, "--memory-dir", self.mem_dir, *args])

    def run_w3(self, *args):
        return w3.main(["--runs-dir", self.w3_runs, "--baseline-runs-dir", self.base_runs, *args])

    def results(self, name):
        return store.read_jsonl(os.path.join(self.runs, name, "results.jsonl"))

    def states(self, name):
        return store.read_jsonl(os.path.join(self.runs, name, "states.jsonl"))

    def meta(self, name):
        return store.read_json(os.path.join(self.runs, name, "run_meta.json"))

    def write_baseline(self, name="dev_flash_lite_v3_final"):
        meta = {"run_name": name, "set": "dev", "prompt_version": "baseline_v3", "prompt_sha256": BASELINE_V3_SHA, "model": "gemini-test-lite", "provider": "gemini", "status": "complete",
                "settings": {"temperature": llm_config.TEMPERATURE, "max_output_tokens": llm_config.MAX_OUTPUT_TOKENS, "seed": base.GENERATION_SEED, "parse_retries": llm_config.MAX_RETRIES,
                             "timeout_seconds": 60, "transport_retries": 4, "requests_per_minute": 10.0}}
        os.makedirs(os.path.join(self.base_runs, name))
        store.write_json_atomic(os.path.join(self.base_runs, name, "run_meta.json"), meta)


class FakeRunTests(RunnerBase):
    def test_memory_off_writes_the_week2_files_plus_states_and_records_the_configuration(self):
        code = self.run_main("--memory", "off", "--fake-model", "--run-name", "FAKE_off")
        self.assertEqual(code, 0)
        self.assertEqual(sorted(os.listdir(os.path.join(self.runs, "FAKE_off"))), ["prompt_snapshot.txt", "raw_responses.jsonl", "results.jsonl", "run_meta.json", "states.jsonl", "verdicts.csv"])
        m = self.meta("FAKE_off")
        self.assertEqual((m["fake_model"], m["runner"], m["set"], m["prompt_version"], m["prompt_sha256"]), (True, "run_memory_dev", "dev", "agent_v1", VP.prompt_sha256()))
        self.assertEqual((m["agent"]["graph_version"], m["agent"]["memory"]["mode"], m["agent"]["memory"]["manifest_sha256"], m["agent"]["memory"]["isolation_check"]), ("v2.0", "off", None, None))
        policy = policy_module.load_policy()
        self.assertEqual(m["agent"]["policy"], {"version": policy.version, "sha256": policy.sha256})
        for r in self.results("FAKE_off"):
            self.assertEqual((r["memory_mode"], r["memory"], r["graph_version"]), ("off", None, "v2.0"))
            self.assertIsNotNone(r["risk_routing"])
            self.assertEqual(r["risk_routing"]["policy_sha256"], policy.sha256)

    def test_memory_on_runs_the_memory_step_uses_the_memory_prompt_and_records_isolation_evidence(self):
        self.assertEqual(self.run_main("--memory", "on", "--fake-model", "--run-name", "FAKE_on"), 0)
        m = self.meta("FAKE_on")
        self.assertEqual((m["prompt_version"], m["prompt_sha256"]), ("agent_v2_memory", P2.get_prompt().sha256))
        self.assertEqual(m["agent"]["memory"]["manifest_sha256"], self.memory.manifest_sha256)
        self.assertEqual(m["agent"]["memory"]["isolation_check"]["dev_overlap"], 0)
        self.assertEqual(m["agent"]["memory"]["isolation_check"]["records_checked"], len(self.memory.records))
        for r in self.results("FAKE_on"):
            self.assertEqual(r["memory_mode"], "on")
            self.assertEqual(r["memory"]["status"], "ok")
            self.assertIn("memory_node", r["trace"])
        for s in self.states("FAKE_on"):
            for hit in s["state"]["memory"]["hits"]:
                self.assertEqual(hit["source_split"], "train")
                self.assertIn(hit["memory_id"], self.memory.allowlist)
        self.assertIn("Incident memory", read_text(os.path.join(self.runs, "FAKE_on", "prompt_snapshot.txt")))

    def test_with_memory_off_every_verdict_outcome_equals_the_week3_runner(self):
        self.run_main("--memory", "off", "--fake-model", "--run-name", "FAKE_v2off")
        self.run_w3("--fake-model", "--run-name", "FAKE_w3")
        a = {r["alert_id"]: r for r in self.results("FAKE_v2off")}
        b = {r["alert_id"]: r for r in store.read_jsonl(os.path.join(self.w3_runs, "FAKE_w3", "results.jsonl"))}
        self.assertEqual(sorted(a), sorted(b))
        for alert_id in a:
            for key in ("status", "verdict", "error_code", "attempts", "malformed_first_try", "agent_prompt_sha256", "model_calls", "tool_calls", "graph_status"):
                self.assertEqual(a[alert_id][key], b[alert_id][key], (alert_id, key))
            self.assertEqual(a[alert_id]["trace"], b[alert_id]["trace"])

    def test_states_hold_the_finished_state_and_the_routing_for_each_finished_alert(self):
        self.run_main("--memory", "on", "--fake-model", "--run-name", "FAKE_st")
        results = {r["alert_id"]: r for r in self.results("FAKE_st")}
        for s in self.states("FAKE_st"):
            self.assertEqual(s["state"]["alert_id"], s["alert_id"])
            self.assertEqual(s["routed"]["routing"], results[s["alert_id"]]["risk_routing"])
            self.assertEqual(s["routed"]["actions"], results[s["alert_id"]]["proposed_actions"])

    def test_proposed_actions_are_only_recorded_never_executed(self):
        self.run_main("--memory", "on", "--fake-model", "--run-name", "FAKE_pa")
        text = json.dumps(self.results("FAKE_pa"))
        self.assertNotIn("executed", text.replace("never executed", ""))

    def test_a_dry_run_writes_nothing_and_makes_no_model_call(self):
        with mock.patch.object(w3, "FakeClient", side_effect=AssertionError("a client was built")), mock.patch.object(base, "make_client_for", side_effect=AssertionError("a model client was built")):
            self.assertEqual(self.run_main("--memory", "on", "--dry-run", "--fake-model", "--limit", "1"), 0)
        self.assertFalse(os.path.exists(self.runs))

    def test_a_missing_key_is_not_needed_for_fake_runs_and_no_secret_is_written(self):
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "SECRET-KEY-VALUE-123"}):
            self.run_main("--memory", "on", "--fake-model", "--run-name", "FAKE_sec")
        for root, _, files in os.walk(os.path.join(self.runs, "FAKE_sec")):
            for name in files:
                self.assertNotIn("SECRET-KEY-VALUE-123", read_text(os.path.join(root, name)))

    def test_the_run_resumes_only_with_the_same_memory_mode_store_and_policy(self):
        self.run_main("--memory", "on", "--fake-model", "--run-name", "FAKE_r", "--limit", "2")
        with self.assertRaises(SystemExit) as ctx:
            self.run_main("--memory", "off", "--fake-model", "--resume", "--run-name", "FAKE_r")
        self.assertIn("memory on", str(ctx.exception))
        policy = json.loads(read_text(policy_module.POLICY_PATH))
        policy["memory"]["min_hits"] = 4
        path = os.path.join(self.tmp.name, "other_policy.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(policy, fh)
        with self.assertRaises(SystemExit) as ctx:
            self.run_main("--memory", "on", "--fake-model", "--resume", "--run-name", "FAKE_r", "--policy", path)
        self.assertIn("risk policy differs", str(ctx.exception))
        with self.assertRaises(SystemExit) as ctx:
            self.run_main("--memory", "on", "--fake-model", "--resume", "--run-name", "FAKE_r", "--memory-k", "7")
        self.assertIn("memory store or k differs", str(ctx.exception))
        self.assertEqual(self.run_main("--memory", "on", "--fake-model", "--resume", "--run-name", "FAKE_r"), 0)
        self.assertEqual(len(self.results("FAKE_r")), 2)   # nothing was run twice

    def test_a_new_run_refuses_an_existing_folder(self):
        self.run_main("--memory", "off", "--fake-model", "--run-name", "FAKE_x")
        with self.assertRaises(SystemExit):
            self.run_main("--memory", "off", "--fake-model", "--run-name", "FAKE_x")


class FailClosedTests(RunnerBase):
    def test_memory_on_without_a_store_stops_before_anything_is_written(self):
        shutil.rmtree(self.mem_dir)
        with self.assertRaises(SystemExit) as ctx:
            self.run_main("--memory", "on", "--fake-model", "--run-name", "FAKE_nostore")
        self.assertIn("Nothing was substituted", str(ctx.exception))
        self.assertFalse(os.path.exists(os.path.join(self.runs, "FAKE_nostore")))

    def test_memory_off_does_not_need_or_touch_the_store(self):
        shutil.rmtree(self.mem_dir)
        self.assertEqual(self.run_main("--memory", "off", "--fake-model", "--run-name", "FAKE_nomem"), 0)

    def test_a_store_that_shares_a_flow_with_a_dev_alert_is_refused(self):
        frame = make_train_frame(per_class=30)
        row = frame.iloc[0]
        self.dev_keys = [R.flow_key_text(row["Flow ID"], row["Timestamp"], row["Source IP"], row["Source Port"], row["Destination IP"])]
        overlapping = [r for r in self.memory.records if r["flow_key_sha256"] == R.key_hash(self.dev_keys[0])]
        if not overlapping:     # the capped selection may not contain row 0: use a key that is in the store
            rec = self.memory.records[0]
            orig = rec["source_ref"]["original_row"]
            row = frame[frame["original_row"] == orig].iloc[0]
            self.dev_keys = [R.flow_key_text(row["Flow ID"], row["Timestamp"], row["Source IP"], row["Source Port"], row["Destination IP"])]
        with self.assertRaises(SystemExit) as ctx:
            self.run_main("--memory", "on", "--fake-model", "--run-name", "FAKE_overlap")
        self.assertIn("MemoryIsolationError", str(ctx.exception))
        self.assertFalse(os.path.exists(os.path.join(self.runs, "FAKE_overlap")))

    def test_a_tampered_store_is_refused(self):
        with open(os.path.join(self.mem_dir, "records.jsonl"), "a", encoding="utf-8") as fh:
            fh.write("\n")
        with self.assertRaises(SystemExit):
            self.run_main("--memory", "on", "--fake-model", "--run-name", "FAKE_tamper")

    def test_a_missing_or_invalid_policy_stops_the_run(self):
        with self.assertRaises(SystemExit) as ctx:
            self.run_main("--memory", "off", "--fake-model", "--run-name", "FAKE_nop", "--policy", os.path.join(self.tmp.name, "absent.json"))
        self.assertIn("fail closed", str(ctx.exception))
        self.assertFalse(os.path.exists(os.path.join(self.runs, "FAKE_nop")))

    def test_the_frozen_unlock_variable_stops_the_run(self):
        with mock.patch.dict(os.environ, {config.FROZEN_UNLOCK_ENV: "1"}):
            with self.assertRaises(SystemExit):
                self.run_main("--memory", "off", "--fake-model", "--run-name", "FAKE_frz")

    def test_a_real_run_needs_the_locked_baseline_and_a_model_never_starts_without_it(self):
        with mock.patch.object(base, "make_client_for", side_effect=AssertionError("a model client was built")):
            with self.assertRaises(SystemExit) as ctx:
                self.run_main("--memory", "off", "--run-name", "real_a")
        self.assertIn("baseline", str(ctx.exception))
        self.assertFalse(os.path.exists(os.path.join(self.runs, "real_a")))

    def test_a_real_run_is_held_equal_to_the_baseline_model(self):
        self.write_baseline()
        with mock.patch.object(base, "check_llm_config", return_value={"small": "another-model", "strong": "x"}), \
                mock.patch.object(base, "make_client_for", side_effect=AssertionError("a model client was built")):
            with self.assertRaises(SystemExit) as ctx:
                self.run_main("--memory", "off", "--run-name", "real_b")
        self.assertIn("not held equal", str(ctx.exception))


class ArgumentTests(unittest.TestCase):
    def test_argument_rules(self):
        bad = [[], ["--memory", "maybe"], ["--memory", "on", "--resume"], ["--memory", "on", "--retry-model-errors"], ["--memory", "on", "--limit", "0"],
               ["--memory", "on", "--rpm", "0"], ["--memory", "on", "--memory-k", "0"], ["--memory", "on", "--memory-k", "51"],
               ["--memory", "on", "--fake-model", "--run-name", "real"], ["--memory", "on", "--run-name", "FAKE_x"],
               ["--memory", "on", "--resume", "--run-name", "x", "--limit", "3"]]
        for argv in bad:
            with self.subTest(argv=argv), mock.patch("sys.stderr"):
                with self.assertRaises(SystemExit):
                    runner.parse_args(argv)
        self.assertEqual(runner.parse_args(["--memory", "on", "--fake-model"]).runs_dir, runner.FAKE_RUNS_ROOT)
        self.assertEqual(runner.parse_args(["--memory", "off"]).runs_dir, runner.RUNS_ROOT)
        self.assertNotEqual(runner.FAKE_RUNS_ROOT, runner.RUNS_ROOT)


class BoundaryTests(unittest.TestCase):
    def imported(self, rel):
        with open(os.path.join(SRC, rel), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                mods.add((node.module or "").split(".")[0])
                mods |= {a.name for a in node.names}
        return mods

    def test_the_runner_and_ingest_import_no_label_frozen_or_evaluation_module(self):
        forbidden = {"eval_io", "eval_labels", "evaluate", "eval_metrics", "final_test_eval", "verify_eval"}
        for rel in ("week4/run_memory_dev.py", "week4/ingest_cases.py", "week4/seed_memory.py"):
            self.assertFalse(self.imported(rel) & forbidden, rel)

    def test_the_runner_names_no_frozen_path(self):
        text = read_text(os.path.join(SRC, "week4", "run_memory_dev.py"))
        for word in ("FROZEN_ALERTS", "frozen_alerts", "FLOW_STORE_FROZEN", "final_test"):
            self.assertNotIn(word, text)


class IngestTests(RunnerBase):
    def make_run(self, name="FAKE_ing", memory="on"):
        self.run_main("--memory", memory, "--fake-model", "--run-name", name)
        return os.path.join(self.runs, name)

    def test_every_finished_alert_becomes_a_case_and_a_second_ingest_changes_nothing(self):
        run_dir = self.make_run()
        repo = MemoryRepository()
        first = ingest_cases.ingest_run(repo, run_dir, say=lambda *_: None)
        self.assertEqual(first["problems"], [])
        self.assertEqual(first["outcomes"], {"created": first["total"]})
        self.assertGreater(first["total"], 0)
        second = ingest_cases.ingest_run(repo, run_dir, say=lambda *_: None)
        self.assertEqual(second["outcomes"], {"duplicate": first["total"]})
        self.assertEqual(repo.list_cases(limit=200)["total"], first["total"])

    def test_a_fake_run_is_stored_as_synthetic_and_a_real_run_as_dev(self):
        run_dir = self.make_run()
        payloads, meta = ingest_cases.build_payloads(run_dir)
        self.assertTrue(all(p["alert_set"] == "synthetic" for _, p in payloads))
        meta["fake_model"] = False
        store.write_json_atomic(os.path.join(run_dir, "run_meta.json"), meta)
        payloads, _ = ingest_cases.build_payloads(run_dir)
        self.assertTrue(all(p["alert_set"] == "dev" for _, p in payloads))

    def test_proposed_actions_enter_the_store_as_pending_and_unexecuted(self):
        run_dir = self.make_run()
        repo = MemoryRepository()
        ingest_cases.ingest_run(repo, run_dir, say=lambda *_: None)
        proposed = sum(len(r["proposed_actions"]) for r in store.read_jsonl(os.path.join(run_dir, "results.jsonl")))
        pending = repo.list_pending_actions(limit=200)
        self.assertEqual(pending["total"], proposed)
        for item in pending["items"]:
            full = repo.get_action(item["action_id"])
            self.assertEqual(full["action"]["state"], "pending")
            self.assertIsNone(full["decision"])
            self.assertIsNone(full["execution"])

    def test_a_non_dev_or_foreign_run_is_refused(self):
        run_dir = self.make_run()
        meta = store.read_json(os.path.join(run_dir, "run_meta.json"))
        for change in ({"set": "frozen"}, {"runner": "run_agent_dev"}):
            store.write_json_atomic(os.path.join(run_dir, "run_meta.json"), dict(meta, **change))
            with self.assertRaises(ingest_cases.IngestError):
                ingest_cases.build_payloads(run_dir)

    def test_a_dry_run_validates_without_a_repository(self):
        result = ingest_cases.ingest_run(None, self.make_run(), dry_run=True, say=lambda *_: None)
        self.assertEqual(result["outcomes"], {"validated": result["total"]})

    def test_a_changed_resubmission_is_a_conflict_and_is_reported(self):
        run_dir = self.make_run()
        repo = MemoryRepository()
        ingest_cases.ingest_run(repo, run_dir, say=lambda *_: None)
        path = os.path.join(run_dir, "states.jsonl")
        records = store.read_jsonl(path)
        records[0]["state"]["alert"]["detector_score"] = 0.123456
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("".join(json.dumps(r, sort_keys=True) + "\n" for r in records))
        result = ingest_cases.ingest_run(repo, run_dir, say=lambda *_: None)
        self.assertEqual(result["outcomes"].get("conflict"), 1)
        self.assertEqual(len(result["problems"]), 1)


if __name__ == "__main__":
    unittest.main()
