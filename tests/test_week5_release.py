"""Week 5 release tooling: the package manifest, the verifier, and the locked-artifact checks. Offline, standard library only, synthetic trees in a temporary folder.
The synthetic project mirrors the REAL lock-record layout (keys read from src/week4_report.py and src/week3_report.py); it is not the user's project. One test class runs against the real lock
records when the tests are run from a project root that has them, and is skipped otherwise."""
import contextlib
import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
import unittest.mock

from week5.release import __main__ as cli
from week5.release import manifest as M
from week5.release import verify as V


def sha(text, crlf=False):
    return hashlib.sha256(text.replace("\n", "\r\n").encode() if crlf else text.encode()).hexdigest()


def write(root, rel, text, crlf=False):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write((text.replace("\n", "\r\n") if crlf else text).encode())
    return path


def make_project(root):
    """A small project with Week 1, 2, 3 and 4 artifacts and lock records in the real layout."""
    w4 = {"src/week4/policy.py": "policy v1\n", "config/risk_policy.json": '{"policy_version": "risk-policy-v1"}\n'}
    w3 = {"src/agents/a.py": "agent\n", "src/baseline_prompt.py": "prompt\n"}
    w2 = {"src/gemini_client.py": "client\n"}
    w1 = {"config_data/alerts_dev.parquet": "w1 alerts bytes\n", "models/detector.json": "w1 model bytes\n"}
    with open(os.path.join(root, "w1_binary.bin"), "wb") as fh:
        fh.write(BINARY_W1)
    for group in (w4, w3, w2, w1):
        for rel, text in group.items():
            write(root, rel, text)
    write(root, "WEEK3_REPORT.md", "week3 report\n")
    write(root, "WEEK4_REPORT.md", "week4 report\n")
    lock3 = {"schema": "week3_agent_lock_v1", "source_files_sha256": {k: sha(v) for k, v in w3.items()}}
    write(root, "reports/week3_agent_lock.json", json.dumps(lock3, indent=2))
    lock2 = {"locked_source_files_sha256": {k: sha(v) for k, v in w2.items()}}
    write(root, "reports/week2_baseline_lock.json", json.dumps(lock2, indent=2))
    manifest4 = {"schema": "week4_artifact_manifest_v1", "files": {"src/week4/policy.py": {"sha256": sha(w4["src/week4/policy.py"]), "size": 10}}}
    write(root, "reports/week4_artifact_manifest.json", json.dumps(manifest4, indent=2))
    with open(os.path.join(root, "reports", "week3_agent_lock.json"), "rb") as fh:
        lock3_raw = hashlib.sha256(fh.read()).hexdigest()
    with open(os.path.join(root, "reports", "week4_artifact_manifest.json"), "rb") as fh:
        manifest_raw = hashlib.sha256(fh.read()).hexdigest()
    lock4 = {"schema": "week4_memory_lock_v1",
             "source_files_sha256": {k: sha(v) for k, v in w4.items()},
             "split_boundaries": {"week1_files_sha256": dict({k: sha(v) for k, v in w1.items()}, **{"w1_binary.bin": hashlib.sha256(BINARY_W1).hexdigest()}), "frozen_access_log": {"lines": 2, "sha256_normalized": sha("a\nb\n")}},
             "week3": {"lock_file": "reports/week3_agent_lock.json", "lock_file_sha256": lock3_raw, "report_sha256_normalized": sha("week3 report\n"),
                       "locked_sources_sha256": {k: sha(v) for k, v in w3.items()}},
             "report": {"path": "WEEK4_REPORT.md", "sha256_normalized": sha("week4 report\n")},
             "artifact_manifest": {"path": "reports/week4_artifact_manifest.json", "sha256": manifest_raw}}
    write(root, "reports/week4_memory_lock.json", json.dumps(lock4, indent=2))
    write(root, "eval/frozen_access.log", "a\nb\n")


BINARY_W1 = b"PAR1\r\n\x00\x01\r\n\xff\r\nPAR1"      # a binary file that happens to contain CRLF bytes: it must be compared as raw bytes


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="w5rel_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "project")
        os.makedirs(self.root)

    def failed(self, checks):
        return [c["name"] for c in checks if c["kind"] == "required" and not c["ok"]]


class LockChecks(Tmp):
    def setUp(self):
        super().setUp()
        make_project(self.root)

    def test_the_real_lock_layout_is_verified_and_a_changed_locked_file_is_caught(self):
        checks = V.check_locks(self.root)
        self.assertEqual(self.failed(checks), [])
        self.assertGreaterEqual(len([c for c in checks if c["ok"]]), 9)
        write(self.root, "src/week4/policy.py", "policy v2 (edited)\n")
        failed = self.failed(V.check_locks(self.root))
        self.assertTrue(any("locked Week 4 file" in n for n in failed), failed)
        self.assertTrue(any("artifact in the Week 4 manifest" in n for n in failed), failed)

    def test_each_kind_of_locked_artifact_is_watched(self):
        edits = {
            "a Week 4 report": ("WEEK4_REPORT.md", "edited\n", "WEEK4_REPORT"),
            "the Week 3 report": ("WEEK3_REPORT.md", "edited\n", "WEEK3_REPORT"),
            "a Week 3 source": ("src/agents/a.py", "edited\n", "Week 3 source"),
            "a Week 2 source": ("src/gemini_client.py", "edited\n", "Week 2"),
            "a Week 1 file": ("models/detector.json", "edited\n", "Week 1 files"),
            "the Week 3 lock": ("reports/week3_agent_lock.json", "{}\n", "Week 3 lock file"),
            "the Week 4 manifest": ("reports/week4_artifact_manifest.json", "{}\n", "artifact manifest"),
        }
        for label, (rel, text, needle) in edits.items():
            with self.subTest(label):
                root = os.path.join(self.tmp, "p_" + hashlib.md5(label.encode()).hexdigest()[:6])
                os.makedirs(root)
                make_project(root)
                self.assertEqual(self.failed(V.check_locks(root)), [])
                write(root, rel, text)
                failed = self.failed(V.check_locks(root))
                self.assertTrue(any(needle in n for n in failed), (label, failed))

    def test_a_missing_locked_file_fails(self):
        os.remove(os.path.join(self.root, "src", "agents", "a.py"))
        self.assertTrue(any("Week 3" in n for n in self.failed(V.check_locks(self.root))))

    def test_line_endings_do_not_matter_for_normalised_files(self):
        for rel, text in (("src/week4/policy.py", "policy v1\n"), ("src/agents/a.py", "agent\n"), ("WEEK4_REPORT.md", "week4 report\n")):
            write(self.root, rel, text, crlf=True)
        self.assertEqual(self.failed(V.check_locks(self.root)), [])

    def test_week1_files_are_compared_as_raw_bytes(self):
        self.assertEqual(self.failed(V.check_locks(self.root)), [], "a binary file containing CRLF bytes passes untouched")
        with open(os.path.join(self.root, "w1_binary.bin"), "wb") as fh:
            fh.write(BINARY_W1.replace(b"\r\n", b"\n"))                  # what a line-ending conversion would do to it
        self.assertTrue(any("Week 1" in n for n in self.failed(V.check_locks(self.root))))

    def test_a_missing_or_malformed_lock_is_a_failure_not_a_pass_or_a_crash(self):
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        self.assertEqual(len(self.failed(V.check_locks(empty))), 1)
        write(self.root, "reports/week4_memory_lock.json", "{ not json")
        self.assertEqual(self.failed(V.check_locks(self.root)), ["Week 4 lock record is readable and well formed"])
        write(self.root, "reports/week4_memory_lock.json", json.dumps({"source_files_sha256": {}}))
        self.assertEqual(self.failed(V.check_locks(self.root)), ["Week 4 lock record is readable and well formed"])

    def test_a_protected_path_in_a_lock_is_refused_and_never_read(self):
        lock = json.load(open(os.path.join(self.root, "reports", "week4_memory_lock.json")))
        lock["split_boundaries"]["week1_files_sha256"]["data/frozen/test.parquet"] = "0" * 64
        write(self.root, "reports/week4_memory_lock.json", json.dumps(lock))
        write(self.root, "data/frozen/test.parquet", "PROTECTED-SENTINEL")
        seen = []
        real = V.read_bytes

        def spy(path):
            seen.append(path)
            return real(path)
        with unittest.mock.patch.object(V, "read_bytes", spy):
            failed = self.failed(V.check_locks(self.root))
        self.assertTrue(any("Week 1" in n for n in failed))
        self.assertFalse([p for p in seen if "frozen" in p.lower() and not p.endswith("frozen_access.log")], seen)

    def test_the_frozen_access_log_is_informational_and_is_the_only_frozen_path_read(self):
        write(self.root, "eval/frozen_access.log", "a\nb\nc\n")
        checks = V.check_locks(self.root)
        self.assertEqual(self.failed(checks), [])
        self.assertTrue([c for c in checks if c["kind"] == "info" and not c["ok"]])

    def test_fingerprint_before_and_after(self):
        before = V.fingerprint(self.root)
        self.assertGreater(len(before["files"]), 10)
        self.assertEqual(self.failed(V.compare_fingerprint(before, self.root)), [])
        write(self.root, "src/agents/a.py", "edited\n")
        self.assertEqual(len(self.failed(V.compare_fingerprint(before, self.root))), 1)
        self.assertNotIn("eval/frozen_access.log", before["files"])


class ManifestChecks(Tmp):
    def setUp(self):
        super().setUp()
        self.payload = os.path.join(self.tmp, "pkg", "payload")
        write(self.payload, "src/week5/a.py", "print(1)\n")
        write(self.payload, "tests/test_week5_a.py", "x = 1\n")
        write(self.payload, ".env.week5.example", "WEEK5_X=\n")
        write(self.payload, "docs/WEEK5.md", "doc\n")
        write(self.payload, "src/week5/security/injection/data/payloads.json", "[]\n")
        self.manifest = M.build(self.payload)

    def test_the_manifest_lists_every_file_with_two_hashes(self):
        self.assertEqual(self.manifest["file_count"], 5)
        entry = self.manifest["files"]["src/week5/a.py"]
        self.assertEqual((entry["category"], entry["bytes"]), ("new", 9))
        self.assertEqual(entry["raw_sha256"], sha("print(1)\n"))

    def test_a_clean_payload_verifies(self):
        checks = V.check_manifest(self.manifest, self.payload) + V.check_no_extra_files(self.manifest, self.payload) + V.check_forbidden(self.manifest, self.payload)
        self.assertEqual(self.failed(checks), [])

    def test_a_changed_missing_or_extra_file_is_caught(self):
        write(self.payload, "src/week5/a.py", "print(2)\n")
        self.assertEqual(len(self.failed(V.check_manifest(self.manifest, self.payload))), 1)
        os.remove(os.path.join(self.payload, "docs", "WEEK5.md"))
        self.assertEqual(len(self.failed(V.check_manifest(self.manifest, self.payload))), 2)
        write(self.payload, "src/week5/new.py", "x\n")
        self.assertEqual(len(self.failed(V.check_no_extra_files(self.manifest, self.payload))), 1)

    def test_normalised_hashes_survive_a_crlf_checkout(self):
        write(self.payload, "src/week5/a.py", "print(1)\n", crlf=True)
        self.assertEqual(len(self.failed(V.check_manifest(self.manifest, self.payload, normalize=False))), 1)
        self.assertEqual(self.failed(V.check_manifest(self.manifest, self.payload, normalize=True)), [])

    def test_forbidden_files_and_key_shaped_strings_are_caught(self):
        for rel in (".env.week5", ".env", "memory_store/a.json", "runs/x/results.jsonl", "eval/frozen_access.log", "data/train.parquet", "src/week5/__pycache__/a.pyc", "reports/x.json"):
            with self.subTest(rel):
                bad = {"files": {rel: {"category": "new", "raw_sha256": "0" * 64, "sha256": "0" * 64, "bytes": 1}}}
                self.assertEqual(len(self.failed(V.check_forbidden(bad))), 1)
        write(self.payload, "src/week5/leak.py", "KEY = 'AIza" + "x" * 30 + "'\n")
        checks = V.check_forbidden(M.build(self.payload), self.payload)
        self.assertEqual(len(self.failed(checks)), 1)

    def test_the_example_env_file_and_the_payload_data_folder_are_allowed(self):
        self.assertEqual(self.failed(V.check_forbidden(self.manifest, self.payload)), [])

    def test_overlap_with_a_locked_file_or_a_modified_file_is_caught(self):
        make_project(self.root)
        clash = M.build(self.payload)
        clash["files"]["src/week4/policy.py"] = {"category": "new", "raw_sha256": "0" * 64, "sha256": "0" * 64, "bytes": 1}
        self.assertEqual(len(self.failed(V.check_no_overlap(clash, self.root))), 1)
        mod = M.build(self.payload)
        mod["files"]["src/week5/a.py"]["category"] = "modified"
        self.assertEqual(len(self.failed(V.check_no_overlap(mod, self.root))), 1)
        self.assertEqual(self.failed(V.check_no_overlap(self.manifest, self.root)), [])

    def test_without_lock_records_the_overlap_check_says_it_is_incomplete(self):
        checks = V.check_no_overlap(self.manifest, os.path.join(self.tmp, "nowhere"))
        self.assertEqual(self.failed(checks), [])
        self.assertTrue([c for c in checks if c["kind"] == "info" and not c["ok"]])

    def test_manifest_files_must_be_a_manifest(self):
        path = os.path.join(self.tmp, "m.json")
        M.write(self.manifest, path)
        self.assertEqual(M.load(path)["file_count"], 5)
        with open(path, "w") as fh:
            fh.write('{"schema": "other"}')
        with self.assertRaises(ValueError):
            M.load(path)


class CliChecks(Tmp):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def setUp(self):
        super().setUp()
        self.pkg = os.path.join(self.tmp, "pkg")
        write(os.path.join(self.pkg, "payload"), "src/week5/a.py", "print(1)\n")
        write(os.path.join(self.pkg, "payload"), "docs/WEEK5.md", "doc\n")
        os.makedirs(os.path.join(self.pkg, "release"))
        self.assertEqual(self.run_cli("build-manifest", "--payload", os.path.join(self.pkg, "payload"), "--out", os.path.join(self.pkg, "release", "WEEK5_MANIFEST.json"))[0], 0)

    def test_verify_package_passes_and_writes_a_machine_readable_record(self):
        record = os.path.join(self.tmp, "rec.json")
        code, out, _ = self.run_cli("verify-package", "--package-dir", self.pkg, "--json", record)
        self.assertEqual(code, 0, out)
        data = json.load(open(record))
        self.assertEqual((data["schema"], data["summary"]["ok"], data["command"]), (V.SCHEMA, True, "verify-package"))

    def test_verify_package_fails_with_exit_1_when_a_file_changes(self):
        write(os.path.join(self.pkg, "payload"), "src/week5/a.py", "tampered\n")
        code, out, _ = self.run_cli("verify-package", "--package-dir", self.pkg)
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)

    def test_a_missing_manifest_is_exit_2_not_a_traceback(self):
        os.remove(os.path.join(self.pkg, "release", "WEEK5_MANIFEST.json"))
        code, _out, err = self.run_cli("verify-package", "--package-dir", self.pkg)
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", err)

    def test_apply_then_verify_applied_and_locks(self):
        make_project(self.root)
        fp = os.path.join(self.tmp, "fp.json")
        self.assertEqual(self.run_cli("fingerprint", "--root", self.root, "--out", fp)[0], 0)
        shutil.copytree(os.path.join(self.pkg, "payload"), self.root, dirs_exist_ok=True)
        code, out, _ = self.run_cli("verify-applied", "--root", self.root, "--package-dir", self.pkg)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.run_cli("compare", "--root", self.root, "--fingerprint", fp)[0], 0)
        self.assertEqual(self.run_cli("verify-locks", "--root", self.root)[0], 0)
        write(self.root, "src/week4/policy.py", "changed after applying\n")
        self.assertEqual(self.run_cli("compare", "--root", self.root, "--fingerprint", fp)[0], 1)
        self.assertEqual(self.run_cli("verify-locks", "--root", self.root)[0], 1)

    def test_check_conflicts_before_applying(self):
        make_project(self.root)
        code, out, _ = self.run_cli("check-conflicts", "--root", self.root, "--package-dir", self.pkg)
        self.assertEqual(code, 0, out)
        write(self.root, "src/week5/a.py", "someone else's file\n")
        code, out, _ = self.run_cli("check-conflicts", "--root", self.root, "--package-dir", self.pkg)
        self.assertEqual(code, 1)
        self.assertIn("src/week5/a.py", out)
        write(self.root, "src/week5/a.py", "print(1)\n", crlf=True)          # identical content with CRLF endings is not a conflict
        self.assertEqual(self.run_cli("check-conflicts", "--root", self.root, "--package-dir", self.pkg)[0], 0)

    def test_verify_locks_without_lock_records_fails(self):
        code, out, _ = self.run_cli("verify-locks", "--root", os.path.join(self.tmp, "nowhere"))
        self.assertEqual(code, 1)
        self.assertIn("Week 4 lock record exists", out)


_REAL = os.path.isfile(os.path.join("reports", "week4_memory_lock.json"))


@unittest.skipUnless(_REAL, "run from a project root that has reports/week4_memory_lock.json")
class LiveProjectLocks(unittest.TestCase):
    def test_the_projects_own_locked_artifacts_still_match_their_lock_records(self):
        failed = [c for c in V.check_locks(".") if c["kind"] == "required" and not c["ok"]]
        self.assertEqual(failed, [])


if __name__ == "__main__":
    unittest.main()
