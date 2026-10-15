"""Week 4 lock (src/week4_report.py): build/verify, every refusal, tamper detection, suite-log parsing, the Week 3 lock left alone.
Offline. The runs are FAKE-model runs made by the runner and relabelled as real only to exercise the lock; the labels, logs and train file are synthetic. Nothing here is a result."""
import hashlib
import json
import os
import shutil
import unittest
from unittest import mock

import baseline_store as store
import config
import eval_labels
import triage_inputs
import week4_report as L
from agents import verdict_prompt as VP
from week4 import evaluate_memory as E
from week4 import hashing
from week4.graph import state as S2

from tests.test_week3_day5 import full_alerts_frame
from tests.test_week4_evaluate import EvalBase, labels_frame
from tests.test_week4_runner import read_text, SRC

REAL_ROOT = os.path.dirname(SRC)
TRAIN_BYTES = b"synthetic train file for the lock tests"


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def write(path, text, binary=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if binary else "w", **({} if binary else {"encoding": "utf-8", "newline": "\n"})) as fh:
        fh.write(text)


class LockBase(EvalBase):
    TRAIN_SHA = hashlib.sha256(TRAIN_BYTES).hexdigest()

    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.tmp.name, "repo")
        # Week 4 sources (copied), the policy, a Week 4 test module marker
        shutil.copytree(os.path.join(SRC, "week4"), os.path.join(self.root, "src", "week4"), ignore=shutil.ignore_patterns("__pycache__"))
        write(os.path.join(self.root, "config", "risk_policy.json"), read_text(os.path.join(REAL_ROOT, "config", "risk_policy.json")))
        write(os.path.join(self.root, "src", "week4_report.py"), "# placeholder for the lock script\n")
        write(os.path.join(self.root, "tests", "test_week4_runner.py"), "# marker\n")
        # a minimal Week 3 lock with two locked source files
        self.w3_files = {"src/agents/a.py": "locked agent source\n", "src/baseline_prompt.py": "locked prompt source\n"}
        for p, text in self.w3_files.items():
            write(os.path.join(self.root, *p.split("/")), text)
        write(os.path.join(self.root, "WEEK3_REPORT.md"), "# Week 3\r\n")
        lock3 = {"schema": "week3_agent_lock_v1", "system": {"prompt_sha256": VP.prompt_sha256(), "graph_version": "v0.1"},
                 "source_files_sha256": {p: hashing.normalized_sha256(os.path.join(self.root, *p.split("/"))) for p in self.w3_files}}
        write(os.path.join(self.root, "reports", "week3_agent_lock.json"), json.dumps(lock3, indent=2, sort_keys=True))
        # runs, comparison, memory store, train file, suite log: moved or written under the repo root
        shutil.copytree(self.runs, os.path.join(self.root, "runs", "week4_memory"))
        shutil.copytree(self.mem_dir, os.path.join(self.root, "memory_store"))
        self.train = os.path.join(self.root, "data", "processed", "train.parquet")
        write(self.train, TRAIN_BYTES, binary=True)
        self.off = os.path.join(self.root, "runs", "week4_memory", "FAKE_off")
        self.on = os.path.join(self.root, "runs", "week4_memory", "FAKE_on")
        self.cmp_dir = os.path.join(self.root, "reports", "week4_eval", "FAKE_off_vs_FAKE_on")
        E.write_outputs(self.compare(), self.cmp_dir)
        self.write_suite()
        self.frozen = os.path.join(self.root, "eval", "frozen_access.log")
        self.snapshot = lambda: {}
        self.w3_ok = lambda root, snap=None: [("stub week 3 check", True, "")]

    def write_suite(self, ran=1200, ok=True, module="tests.test_week4_runner", encoding="utf-8", name="full_suite.txt"):
        lines = ["test_a (%s.A.test_a) ... ok" % module, "", "-" * 70, "Ran %d tests in 12.3s" % ran, ""]
        lines.append("OK (skipped=3)" if ok else "FAILED (failures=2)")
        data = "\r\n".join(lines).encode(encoding)
        write(os.path.join(self.root, "reports", "week4_day7", name), data, binary=True)

    def args(self, action="build", *extra):
        return L.build_parser().parse_args([action, "--root", self.root, "--off-run", "FAKE_off", "--on-run", "FAKE_on", "--train-path", self.train, "--frozen-log", self.frozen,
                                            "--suite-log", "reports/week4_day7/full_suite.txt", *extra])

    def build(self, *extra, lines=None):
        out = []
        code = L.do_build(self.args("build", *extra), self.snapshot, say=out.append if lines is None else lines.append, week3_verifier=self.w3_ok)
        return code, out

    def verify(self, *extra):
        out = []
        code = L.do_verify(self.args("verify", *extra), self.snapshot, say=out.append, week3_verifier=self.w3_ok)
        return code, out

    def lock(self):
        return json.loads(read_text(os.path.join(self.root, "reports", "week4_memory_lock.json")))

    def outputs(self):
        return [os.path.join(self.root, p) for p in ("WEEK4_REPORT.md", "reports/week4_memory_lock.json", "reports/week4_artifact_manifest.json")]

    def failed(self, out):
        return [l for l in out if l.startswith("FAIL")]


class BuildTests(LockBase):
    def test_a_clean_build_passes_every_check_and_writes_report_lock_and_manifest(self):
        code, out = self.build()
        self.assertEqual(code, 0, "\n".join(out))
        self.assertEqual(self.failed(out), [])
        for path in self.outputs():
            self.assertTrue(os.path.isfile(path), path)
        lock = self.lock()
        self.assertEqual(lock["schema"], L.SCHEMA)
        self.assertEqual(lock["system"]["prompts"]["agent_v1"], VP.prompt_sha256())
        self.assertEqual(lock["system"]["graph_version"], S2.GRAPH_VERSION)
        self.assertEqual(lock["split_boundaries"]["train_sha256"], self.TRAIN_SHA)
        self.assertEqual(lock["split_boundaries"]["isolation_check"]["dev_overlap"], 0)
        self.assertTrue(all(c["passed"] for c in lock["checks"]))
        self.assertEqual(lock["suite"]["ran"], 1200)
        self.assertIsNone(lock["pg_suite"])
        self.assertIn("src/week4/policy.py", lock["source_files_sha256"])
        self.assertIn("src/week4/db/migrations/0001_core_schema.sql", lock["source_files_sha256"])

    def test_the_manifest_lists_every_locked_artifact_with_sha256_and_size(self):
        self.build()
        manifest = json.loads(read_text(self.outputs()[2]))
        files = manifest["files"]
        for expected in ("src/week4/policy.py", "runs/week4_memory/FAKE_on/results.jsonl", "runs/week4_memory/FAKE_on/states.jsonl", "memory_store/manifest.json", "memory_store/vectors.npy",
                         "reports/week4_eval/FAKE_off_vs_FAKE_on/comparison.json", "reports/week4_day7/full_suite.txt", "WEEK4_REPORT.md"):
            self.assertIn(expected, files)
        for p, e in files.items():
            self.assertEqual(set(e), {"sha256", "bytes"})
            self.assertEqual(len(e["sha256"]), 64)
        self.assertEqual(self.lock()["artifact_manifest"]["sha256"], L.raw_sha(self.outputs()[2]))

    def test_the_report_has_the_required_sections_and_reads_its_numbers_from_the_comparison(self):
        self.build()
        report = read_text(self.outputs()[0])
        for heading in ("## 1. What was built", "## 2. Split isolation", "## 3. Memory off vs memory on (dev set)", "## 4. Tests", "## 5. Lock checks", "## 6. What this lock does not show", "## 7. Reproduce",
                        "### Limitations and confounders"):
            self.assertIn(heading, report)
        cmp_ = json.loads(read_text(os.path.join(self.cmp_dir, "comparison.json")))
        n = cmp_["arms"]["memory_on"]["population"]["alerts"]
        self.assertIn("alerts compared | %d | %d" % (n, n), report)
        self.assertIn("No PostgreSQL-enabled suite log was supplied", report)
        self.assertNotIn("improv", report.lower())

    def test_the_week3_lock_and_report_are_not_touched(self):
        before = {p: L.raw_sha(os.path.join(self.root, *p.split("/"))) for p in ["reports/week3_agent_lock.json", "WEEK3_REPORT.md", *self.w3_files]}
        self.build()
        self.verify()
        self.assertEqual(before, {p: L.raw_sha(os.path.join(self.root, *p.split("/"))) for p in before})

    def test_a_pg_suite_log_is_recorded_when_given(self):
        self.write_suite(name="pg_suite.txt")
        code, out = self.build("--pg-suite-log", "reports/week4_day7/pg_suite.txt")
        self.assertEqual(code, 0, "\n".join(out))
        self.assertEqual(self.lock()["pg_suite"]["ran"], 1200)
        self.assertNotIn("No PostgreSQL-enabled suite log", read_text(self.outputs()[0]))

    def test_it_refuses_to_replace_a_lock_without_force(self):
        self.build()
        code, out = self.build()
        self.assertEqual(code, 1)
        self.assertIn("already exists", out[-1])
        self.assertEqual(self.build("--force")[0], 0)

    def test_it_needs_both_runs_and_a_suite_log(self):
        out = []
        self.assertEqual(L.do_build(L.build_parser().parse_args(["build", "--root", self.root]), self.snapshot, say=out.append), 1)
        args = L.build_parser().parse_args(["build", "--root", self.root, "--off-run", "a", "--on-run", "b"])
        self.assertEqual(L.do_build(args, self.snapshot, say=out.append), 1)
        self.assertTrue(any("--suite-log" in o for o in out))


class RefusalTests(LockBase):
    def refused(self, fragment, **kw):
        code, out = self.build(**kw)
        self.assertEqual(code, 1, "\n".join(out))
        self.assertTrue(any(fragment in l for l in out if l.startswith(("FAIL", "STOPPED"))), "\n".join(out))
        for path in self.outputs():
            self.assertFalse(os.path.exists(path), "a failed build wrote " + path)

    def test_a_failing_suite_is_refused(self):
        self.write_suite(ok=False)
        self.refused("full suite passed")

    def test_a_suite_that_is_too_small_or_misses_week4_modules_is_refused(self):
        self.write_suite(ran=1000)
        self.refused("at least the Week 3 suite")
        self.write_suite(module="tests.test_other")
        self.refused("names every Week 4 test module")

    def test_a_missing_suite_log_is_refused(self):
        os.remove(os.path.join(self.root, "reports", "week4_day7", "full_suite.txt"))
        self.refused("suite log exists")

    def test_a_missing_train_file_is_refused_never_replaced(self):
        os.remove(self.train)
        self.refused("current train.parquet")

    def test_a_changed_train_file_is_refused(self):
        write(self.train, b"another file", binary=True)
        self.refused("current train.parquet")

    def test_a_changed_week3_locked_file_is_refused(self):
        write(os.path.join(self.root, "src", "agents", "a.py"), "edited\n")
        self.refused("locked by Week 3")

    def test_a_failing_week3_verification_is_refused(self):
        self.w3_ok = lambda root, snap=None: [("Week 3 thing", False, "changed")]
        self.refused("Week 3 verification")

    def test_a_missing_week3_lock_stops_the_build(self):
        os.remove(os.path.join(self.root, "reports", "week3_agent_lock.json"))
        code, out = self.build()
        self.assertEqual(code, 1)
        self.assertIn("Week 3 lock record", out[-1])

    def test_a_fake_run_or_a_partial_comparison_is_refused(self):
        self.relabel(self.on, True)
        self.refused("comparable")

    def test_a_comparison_for_other_runs_is_refused(self):
        path = os.path.join(self.cmp_dir, "comparison.json")
        doc = json.loads(read_text(path))
        doc["provenance"]["memory_on_run"]["run_name"] = "someone_else"
        write(path, json.dumps(doc))
        self.refused("exactly these two runs")

    def test_a_missing_comparison_is_refused_with_the_instruction(self):
        shutil.rmtree(self.cmp_dir)
        code, out = self.build()
        self.assertEqual(code, 1)
        self.assertIn("evaluate_memory.py", out[-1])

    def test_a_memory_store_that_differs_from_the_one_the_run_used_is_refused(self):
        path = os.path.join(self.root, "memory_store", "records.jsonl")
        write(path, read_text(path) + "\n")
        self.refused("memory store loads")

    def test_a_changed_policy_file_is_refused(self):
        path = os.path.join(self.root, "config", "risk_policy.json")
        doc = json.loads(read_text(path))
        doc["memory"]["min_hits"] = 4
        write(path, json.dumps(doc))
        self.refused("risk policy in the runs")

    def test_a_credential_in_a_source_file_is_refused(self):
        write(os.path.join(self.root, "src", "week4", "leak.py"), 'DB = "postgresql://soc:Sup3rSecretPw@db:5432/soc"\n')
        self.refused("credential-like")

    def test_placeholders_and_variable_references_are_not_credentials(self):
        write(os.path.join(self.root, "docker-compose.yml"), "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: ${WEEK4_DB_PASSWORD:?set it}\n")
        write(os.path.join(self.root, ".env.week4.example"), "WEEK4_DATABASE_URL=postgresql://soc_api:<password>@localhost:5432/soc\nWEEK4_DB_PASSWORD=changeme-example-only\n")
        self.assertEqual(self.build()[0], 0)

    def test_the_frozen_unlock_variable_is_refused(self):
        with mock.patch.dict(os.environ, {config.FROZEN_UNLOCK_ENV: "1"}):
            self.refused("unlock variable")

    def test_a_grown_frozen_access_log_is_refused(self):
        with mock.patch("week2_report.count_lines", return_value=3):
            self.refused("frozen access log")


class VerifyTests(LockBase):
    def setUp(self):
        super().setUp()
        self.assertEqual(self.build()[0], 0)

    def test_an_untouched_lock_verifies(self):
        code, out = self.verify()
        self.assertEqual(code, 0, "\n".join(out))
        self.assertEqual(self.failed(out), [])
        self.assertIn("unchanged since the lock", out[-1])

    def test_each_kind_of_change_is_detected(self):
        def edit(relpath, change):
            full = os.path.join(self.root, *relpath.split("/"))
            original = read_bytes(full)
            return full, original, change(full)
        cases = {
            "a Week 4 source file": ("src/week4/policy.py", lambda f: write(f, read_text(f) + "\n# edit\n")),
            "a run file": ("runs/week4_memory/FAKE_on/results.jsonl", lambda f: write(f, read_text(f) + "\n")),
            "a comparison file": ("reports/week4_eval/FAKE_off_vs_FAKE_on/comparison.json", lambda f: write(f, read_text(f) + " ")),
            "the memory vectors": ("memory_store/vectors.npy", lambda f: write(f, read_bytes(f)[:-1] + bytes([read_bytes(f)[-1] ^ 0xFF]), binary=True)),
            "the policy": ("config/risk_policy.json", lambda f: write(f, read_text(f).replace("0.5", "0.6", 1))),
            "the report": ("WEEK4_REPORT.md", lambda f: write(f, read_text(f) + "x\n")),
            "the manifest": ("reports/week4_artifact_manifest.json", lambda f: write(f, read_text(f) + " ")),
            "the suite log": ("reports/week4_day7/full_suite.txt", lambda f: write(f, b"changed", binary=True)),
            "a migration": ("src/week4/db/migrations/0003_functions.sql", lambda f: write(f, read_text(f) + "\n-- edit\n")),
            "a Week 3 locked file": ("src/agents/a.py", lambda f: write(f, "edited\n")),
            "the Week 3 lock": ("reports/week3_agent_lock.json", lambda f: write(f, read_text(f) + " ")),
            "WEEK3_REPORT.md": ("WEEK3_REPORT.md", lambda f: write(f, "# changed\n")),
            "the train file": ("data/processed/train.parquet", lambda f: write(f, b"changed", binary=True)),
        }
        for name, (relpath, change) in cases.items():
            with self.subTest(name):
                full, original, _ = edit(relpath, change)
                try:
                    code, out = self.verify()
                    self.assertEqual(code, 1, name + " was not detected")
                    self.assertTrue(self.failed(out))
                finally:
                    with open(full, "wb") as fh:
                        fh.write(original)
        self.assertEqual(self.verify()[0], 0)

    def test_a_new_source_file_is_detected(self):
        write(os.path.join(self.root, "src", "week4", "extra.py"), "X = 1\n")
        code, out = self.verify()
        self.assertEqual(code, 1)
        self.assertTrue(any("added since the lock" in l for l in self.failed(out)))

    def test_a_week3_verification_failure_is_detected(self):
        self.w3_ok = lambda root, snap=None: [("Week 3 thing", False, "")]
        self.assertEqual(self.verify()[0], 1)

    def test_crlf_checkouts_verify_the_same(self):
        for rel in ("src/week4/policy.py", "config/risk_policy.json"):
            full = os.path.join(self.root, *rel.split("/"))
            data = read_bytes(full).replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            with open(full, "wb") as fh:
                fh.write(data)
        code, out = self.verify()
        self.assertNotIn("source file", "\n".join(self.failed(out)))
        self.assertTrue(all("risk policy" not in l and "source file" not in l for l in self.failed(out)), "\n".join(self.failed(out)))

    def test_recompute_rescores_the_runs_against_the_dev_labels(self):
        with mock.patch.object(triage_inputs, "load_dev_alerts", return_value=full_alerts_frame()), mock.patch.object(eval_labels, "load_dev_labels", return_value=labels_frame()):
            code, out = self.verify("--recompute")
        self.assertEqual(code, 0, "\n".join(out))
        self.assertTrue(any("re-scoring both runs" in l and l.startswith("PASS") for l in out))

    def test_recompute_detects_different_labels(self):
        other = labels_frame()
        other.loc[other["alert_id"] == "DEV-0003", ["label", "mitre_technique_id", "mitre_accepted_ids"]] = ["BENIGN", "NONE", "NONE"]
        other.loc[other["alert_id"] == "DEV-0003", "is_attack"] = 0
        with mock.patch.object(triage_inputs, "load_dev_alerts", return_value=full_alerts_frame()), mock.patch.object(eval_labels, "load_dev_labels", return_value=other):
            code, out = self.verify("--recompute")
        self.assertEqual(code, 1)
        self.assertTrue(any("re-scoring" in l for l in self.failed(out)))


class SuiteLogTests(unittest.TestCase):
    def parse(self, raw, modules=("test_week4_runner",)):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "log.txt")
            with open(path, "wb") as fh:
                fh.write(raw)
            return L.parse_suite_log(path, modules)

    TEXT = "test_a (tests.test_week4_runner.A.test_a) ... ok\n\n----------------------------------------------------------------------\nRan 1200 tests in 30.5s\n\nOK (skipped=7)\n"

    def test_utf8_utf8_bom_utf16_and_crlf_logs_all_parse(self):
        for name, raw in (("utf-8", self.TEXT.encode("utf-8")), ("utf-8-bom", b"\xef\xbb\xbf" + self.TEXT.encode("utf-8")), ("utf-16 (PowerShell)", self.TEXT.encode("utf-16")),
                          ("utf-16-le without BOM", self.TEXT.encode("utf-16-le")), ("crlf", self.TEXT.replace("\n", "\r\n").encode("utf-8"))):
            with self.subTest(name):
                r = self.parse(raw)
                self.assertEqual((r["ran"], r["ok"], r["skipped"], r["failed"], r["modules_named"]), (1200, True, 7, None, ["test_week4_runner"]))

    def test_a_failed_log_is_not_ok_and_a_log_without_a_summary_is_not_ok(self):
        self.assertFalse(self.parse(self.TEXT.replace("OK (skipped=7)", "FAILED (errors=1)").encode())["ok"])
        r = self.parse(b"nothing here\n")
        self.assertEqual((r["ran"], r["ok"]), (None, False))

    def test_ok_without_skips_reports_zero_skipped(self):
        self.assertEqual(self.parse(self.TEXT.replace(" (skipped=7)", "").encode())["skipped"], 0)


class HashingTests(unittest.TestCase):
    def test_crlf_and_lf_text_hash_the_same_and_binary_does_not_normalise(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            a, b, c, e = (os.path.join(d, n) for n in ("a.py", "b.py", "c.npy", "d.npy"))
            for path, data in ((a, b"x\ny\n"), (b, b"x\r\ny\r\n"), (c, b"x\ny\n"), (e, b"x\r\ny\r\n")):
                with open(path, "wb") as fh:
                    fh.write(data)
            self.assertEqual(hashing.normalized_sha256(a), hashing.normalized_sha256(b))
            self.assertNotEqual(hashing.normalized_sha256(c), hashing.normalized_sha256(e))

    def test_a_missing_file_raises_instead_of_being_skipped(self):
        with self.assertRaises(FileNotFoundError):
            hashing.tree_hashes(REAL_ROOT, ["no/such/file.py"])

    def test_combined_hash_ignores_order(self):
        self.assertEqual(hashing.combined_sha256({"a": "1", "b": "2"}), hashing.combined_sha256({"b": "2", "a": "1"}))


if __name__ == "__main__":
    unittest.main()
