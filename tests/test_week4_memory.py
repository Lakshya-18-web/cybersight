"""Incident memory: train-only seeding, determinism, safe rebuild, verification, retrieval with isolation, and the static import boundary. Offline; synthetic data only."""
import ast
import json
import os
import shutil
import tempfile
import unittest

import numpy as np

from week4.memory import loader, records as R, store as S
from week4.memory.errors import MemoryDataError, MemoryIsolationError, MemoryQueryError, MemoryStoreError

from tests.week4_support import alert_from_row, make_train_frame

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
FAKE_SHA = "d" * 64


def rd(path, binary=False):
    with open(path, "rb" if binary else "r", **({} if binary else {"encoding": "utf-8"})) as fh:
        return fh.read()


def rjson(path):
    return json.loads(rd(path))


def wjson(path, doc):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)


class TmpMixin:
    def tmp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        return d

    def seed(self, frame=None, out=None, **kw):
        frame = make_train_frame() if frame is None else frame
        out = out or os.path.join(self.tmp(), "mem")
        kw.setdefault("per_class_cap", 10)
        built = S.seed_store(R.candidates_from_frame(frame), out, FAKE_SHA, len(frame), say=lambda *_: None, **kw)
        return built, out, frame


class RecordTests(unittest.TestCase):
    def test_query_vector_matches_the_training_matrix_row(self):
        frame = make_train_frame(per_class=5)
        cands = R.candidates_from_frame(frame)
        scaler = R.fit_scaler(cands.raw)
        row = frame.iloc[7]
        np.testing.assert_allclose(R.query_vector(alert_from_row(row), scaler), R.apply_scaler(cands.raw[7], scaler), rtol=0, atol=1e-12)

    def test_flags_for_port_and_protocol(self):
        frame = make_train_frame(per_class=1, labels=["SSH-Patator", "PortScan"])
        raw = R.candidates_from_frame(frame).raw
        names = R.FEATURE_NAMES
        self.assertEqual(raw[0][names.index("port_22")], 1.0)
        self.assertEqual(raw[0][names.index("port_1024_or_above")], 0.0)
        self.assertEqual(raw[1][names.index("port_1024_or_above")], 1.0)
        self.assertEqual(raw[0][names.index("protocol_tcp")], 1.0)

    def test_unusable_alert_values_are_refused_not_imputed(self):
        frame = make_train_frame(per_class=3)
        scaler = R.fit_scaler(R.candidates_from_frame(frame).raw)
        base = alert_from_row(frame.iloc[0])
        for name, change in {"missing feature": {"Flow Duration": None}, "nan": {"Flow Bytes/s": float("nan")}, "inf": {"Flow Packets/s": float("inf")}, "bool": {"Flow IAT Mean": True},
                             "text": {"SYN Flag Count": "many"}, "no port": {"dst_port": None}, "no protocol": {"protocol": None}}.items():
            with self.subTest(name):
                with self.assertRaises(MemoryQueryError):
                    R.query_vector(dict(base, **change), scaler)
        with self.assertRaises(MemoryQueryError):
            R.query_vector("not a dict", scaler)

    def test_negative_values_are_clipped(self):
        frame = make_train_frame(per_class=3)
        frame.loc[0, "Flow Bytes/s"] = -5.0
        cands = R.candidates_from_frame(frame)
        self.assertEqual(cands.raw[0][R.FEATURE_NAMES.index("Flow Bytes/s")], 0.0)

    def test_bad_training_tables_are_refused(self):
        frame = make_train_frame(per_class=3)
        with self.assertRaises(MemoryDataError):
            R.candidates_from_frame(frame.drop(columns=["Label"]))
        with self.assertRaises(MemoryDataError):
            R.candidates_from_frame(frame.iloc[0:0])
        with self.assertRaises(MemoryDataError):
            R.candidates_from_frame(frame.assign(Label="Made Up Class"))
        with self.assertRaises(MemoryDataError):
            R.candidates_from_frame("not a table")
        dup = frame.copy()
        dup["original_row"] = 1
        dup["source_file"] = "same.csv"
        with self.assertRaises(MemoryDataError):
            R.candidates_from_frame(dup)

    def test_invalid_rows_are_counted_and_left_out(self):
        frame = make_train_frame(per_class=4)
        frame.loc[0, "Flow Duration"] = np.nan
        frame.loc[1, "Destination Port"] = np.nan
        frame.loc[2, "Label"] = None
        cands = R.candidates_from_frame(frame)
        self.assertEqual((cands.n_invalid, len(cands)), (3, len(frame) - 3))

    def test_selection_is_capped_deterministic_and_order_independent(self):
        frame = make_train_frame(per_class=30)
        a = R.candidates_from_frame(frame)
        b = R.candidates_from_frame(frame.sample(frac=1.0, random_state=3).reset_index(drop=True))
        ia, _ = R.select(a, 8, 42)
        ib, _ = R.select(b, 8, 42)
        self.assertEqual([a.ids[i] for i in ia], [b.ids[i] for i in ib])
        counts = {}
        for i in ia:
            counts[a.labels[i]] = counts.get(a.labels[i], 0) + 1
        self.assertTrue(all(v == 8 for v in counts.values()), counts)
        other, _ = R.select(a, 8, 43)
        self.assertNotEqual([a.ids[i] for i in ia], [a.ids[i] for i in other])
        for bad in (0, -1, True, 1.5, "3"):
            with self.assertRaises(ValueError):
                R.select(a, bad, 42)

    def test_identical_fingerprints_in_a_class_are_collapsed(self):
        frame = make_train_frame(per_class=6, labels=["PortScan"])
        for c in frame.columns:
            if c in ("Flow Duration", "Flow IAT Mean"):
                frame[c] = 5.0
        cols = [c for c in frame.columns if c not in ("Flow ID", "Timestamp", "Source IP", "Source Port", "Destination IP", "Label", "source_file", "original_row")]
        frame[cols] = frame[cols].iloc[0].values
        idx, stats = R.select(R.candidates_from_frame(frame), 10, 42)
        self.assertEqual((len(idx), stats["duplicates_collapsed"]), (1, 5))


class SeedAndLoadTests(TmpMixin, unittest.TestCase):
    def test_seed_writes_the_three_files_and_a_complete_manifest(self):
        built, out, frame = self.seed()
        self.assertEqual(sorted(os.listdir(out)), ["manifest.json", "records.jsonl", "vectors.npy"])
        m = built.manifest
        self.assertEqual((m["split"], m["train_sha256"], m["train_rows"], m["n_records"], m["per_class_cap"], m["seed"]), ("train", FAKE_SHA, len(frame), 50, 10, 42))
        self.assertEqual(m["label_counts"], {k: 10 for k in sorted(set(frame["Label"]))})
        self.assertEqual(m["dev_overlap_check"], {"performed": False, "dev_keys_compared": 0, "overlapping_rows": 0})
        self.assertEqual(built.verify_isolation(), [])

    def test_records_hold_no_addresses_or_technique_ids(self):
        _, out, _ = self.seed()
        text = rd(os.path.join(out, "records.jsonl"))
        self.assertNotRegex(text, r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        self.assertNotRegex(text, r'"T\d{4}')
        for line in text.splitlines():
            rec = json.loads(line)
            self.assertEqual(set(rec), {"memory_id", "label", "flow_key_sha256", "source_ref", "vector_sha256"})
            self.assertEqual(rec["source_ref"]["split"], "train")

    def test_seeding_is_byte_for_byte_repeatable(self):
        _, a, _ = self.seed()
        _, b, _ = self.seed()
        for name in S.FILES:
            self.assertEqual(rd(os.path.join(a, name), True), rd(os.path.join(b, name), True), name)

    def test_rebuild_is_a_noop_when_nothing_changed_and_keeps_the_old_store_when_it_did(self):
        built, out, frame = self.seed()
        again = S.seed_store(R.candidates_from_frame(frame), out, FAKE_SHA, len(frame), per_class_cap=10, say=lambda *_: None)
        self.assertEqual(again.manifest_sha256, built.manifest_sha256)
        self.assertEqual([n for n in os.listdir(os.path.dirname(out)) if n != "mem"], [])
        changed = S.seed_store(R.candidates_from_frame(frame), out, FAKE_SHA, len(frame), per_class_cap=5, say=lambda *_: None)
        self.assertNotEqual(changed.manifest_sha256, built.manifest_sha256)
        prev = os.path.join(os.path.dirname(out), "mem.prev-" + built.manifest_sha256[:12])
        self.assertTrue(os.path.isdir(prev))
        self.assertEqual(S.MemoryStore.load(prev).manifest_sha256, built.manifest_sha256)

    def test_a_failed_build_leaves_no_partial_store_and_keeps_the_old_one(self):
        built, out, frame = self.seed()
        dev_keys = [R.flow_key_text(*[frame.iloc[0][c] for c in R.TRAIN_KEY_COLUMNS])]
        with self.assertRaises(MemoryIsolationError):
            S.seed_store(R.candidates_from_frame(frame), out, FAKE_SHA, len(frame), per_class_cap=5, dev_key_texts=dev_keys, say=lambda *_: None)
        self.assertFalse(os.path.exists(out + ".building"))
        self.assertEqual(S.MemoryStore.load(out).manifest_sha256, built.manifest_sha256)

    def test_an_interrupted_build_is_never_silently_reused_or_overwritten(self):
        _, out, frame = self.seed()
        os.makedirs(out + ".building")
        with self.assertRaises(MemoryStoreError):
            S.seed_store(R.candidates_from_frame(frame), out, FAKE_SHA, len(frame), per_class_cap=5, say=lambda *_: None)

    def test_dev_overlap_check_is_recorded_and_enforced(self):
        frame = make_train_frame(per_class=5)
        other = ["1|2017-07-05 00:00:00|1.1.1.1|1|2.2.2.2", None]
        built, _, _ = self.seed(frame=frame, dev_key_texts=other)
        self.assertEqual(built.manifest["dev_overlap_check"], {"performed": True, "dev_keys_compared": 1, "overlapping_rows": 0})
        hit = [R.flow_key_text(*[frame.iloc[3][c] for c in R.TRAIN_KEY_COLUMNS])]
        out = os.path.join(self.tmp(), "mem2")
        with self.assertRaises(MemoryIsolationError):
            S.seed_store(R.candidates_from_frame(frame), out, FAKE_SHA, len(frame), dev_key_texts=hit, say=lambda *_: None)
        self.assertFalse(os.path.exists(out))

    def test_empty_selection_is_refused(self):
        frame = make_train_frame(per_class=3)
        frame["Flow Duration"] = np.nan
        with self.assertRaises(MemoryDataError):
            S.seed_store(R.candidates_from_frame(frame), os.path.join(self.tmp(), "m"), FAKE_SHA, 15, say=lambda *_: None)

    def test_loading_detects_every_kind_of_tampering(self):
        built, out, _ = self.seed()

        def copy():
            d = os.path.join(self.tmp(), "c")
            shutil.copytree(out, d)
            return d

        def edit(path, fn, binary=False):
            with open(path, "rb" if binary else "r", **({} if binary else {"encoding": "utf-8"})) as fh:
                data = fh.read()
            with open(path, "wb" if binary else "w", **({} if binary else {"encoding": "utf-8", "newline": "\n"})) as fh:
                fh.write(fn(data))

        d = copy()
        edit(os.path.join(d, "records.jsonl"), lambda t: t.replace('"label":"BENIGN"', '"label":"Bot"', 1))
        with self.assertRaises(MemoryStoreError):
            S.MemoryStore.load(d)
        d = copy()
        v = np.load(os.path.join(d, "vectors.npy"))
        v[0, 0] += 1.0
        np.save(os.path.join(d, "vectors.npy"), v)
        with self.assertRaises(MemoryStoreError):
            S.MemoryStore.load(d)
        d = copy()
        edit(os.path.join(d, "manifest.json"), lambda t: t.replace('"per_class_cap": 10', '"per_class_cap": 11'))
        with self.assertRaises(MemoryStoreError):
            S.MemoryStore.load(d)
        d = copy()
        os.remove(os.path.join(d, "vectors.npy"))
        with self.assertRaises(MemoryStoreError):
            S.MemoryStore.load(d)
        with self.assertRaises(MemoryStoreError):
            S.MemoryStore.load(os.path.join(self.tmp(), "does-not-exist"))

    def test_a_manifest_that_claims_another_split_is_an_isolation_error_even_if_rehashed(self):
        built, out, _ = self.seed()
        d = os.path.join(self.tmp(), "c")
        shutil.copytree(out, d)
        doc = rjson(os.path.join(d, "manifest.json"))
        doc["manifest"]["split"] = "val"
        doc["manifest_sha256"] = R.sha256_text(R.canonical_json(doc["manifest"]))
        wjson(os.path.join(d, "manifest.json"), doc)
        with self.assertRaises(MemoryIsolationError):
            S.MemoryStore.load(d)

    def test_a_record_from_another_split_is_an_isolation_error(self):
        built, out, _ = self.seed()
        d = os.path.join(self.tmp(), "c")
        shutil.copytree(out, d)
        path = os.path.join(d, "records.jsonl")
        text = rd(path).replace('"split":"train"', '"split":"val"', 1)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        doc = rjson(os.path.join(d, "manifest.json"))
        doc["manifest"]["records_sha256"] = loader.file_sha256(path)
        doc["manifest_sha256"] = R.sha256_text(R.canonical_json(doc["manifest"]))
        wjson(os.path.join(d, "manifest.json"), doc)
        with self.assertRaises(MemoryIsolationError):
            S.MemoryStore.load(d)


class RetrievalTests(TmpMixin, unittest.TestCase):
    def setUp(self):
        self.built, self.out, self.frame = self.seed(frame=make_train_frame(per_class=30), per_class_cap=20)

    def test_similar_flows_find_their_own_class_with_full_provenance(self):
        row = self.frame[self.frame["Label"] == "SSH-Patator"].iloc[2]
        alert = alert_from_row(row)
        alert["flow_id"] = "a-flow-that-is-not-in-the-store"
        res = self.built.retrieve(alert, k=5)
        self.assertEqual((res["status"], res["k_returned"]), ("ok", 5))
        self.assertEqual(res["label_counts"].get("SSH-Patator", 0), 5)
        for rank, h in enumerate(res["hits"], 1):
            self.assertEqual((h["rank"], h["source_split"], h["manifest_sha256"]), (rank, "train", self.built.manifest_sha256))
            self.assertEqual(set(h), {"rank", "memory_id", "distance", "label", "source_split", "source_ref", "manifest_sha256"})
            self.assertIn(h["memory_id"], self.built.allowlist)
        self.assertEqual([h["distance"] for h in res["hits"]], sorted(h["distance"] for h in res["hits"]))
        self.assertEqual(res["nearest_distance"], res["hits"][0]["distance"])
        self.assertEqual(res["store"]["manifest_sha256"], self.built.manifest_sha256)

    def test_retrieval_is_repeatable(self):
        alert = alert_from_row(self.frame.iloc[5])
        self.assertEqual(self.built.retrieve(alert), self.built.retrieve(alert))

    def test_the_current_flow_is_never_its_own_neighbour(self):
        stored = {json.loads(l)["flow_key_sha256"] for l in rd(os.path.join(self.out, "records.jsonl")).splitlines()}
        alert = None
        for _, row in self.frame.iterrows():
            a = alert_from_row(row)
            if R.key_hash(R.alert_flow_key_text(a)) in stored:
                alert = a
                break
        self.assertIsNotNone(alert)
        res = self.built.retrieve(alert, k=5)
        self.assertEqual(res["filtered"]["same_flow"], 1)
        own = R.key_hash(R.alert_flow_key_text(alert))
        self.assertTrue(all(self.built.records[self.built.index_by_id[h["memory_id"]]]["flow_key_sha256"] != own for h in res["hits"]))

    def test_a_result_that_would_include_a_non_allowlisted_record_stops_retrieval(self):
        alert = alert_from_row(self.frame.iloc[0])
        victim = self.built.retrieve(alert)["hits"][0]["memory_id"]
        self.built.allowlist.discard(victim)
        with self.assertRaises(MemoryIsolationError):
            self.built.retrieve(alert)

    def test_bad_arguments(self):
        alert = alert_from_row(self.frame.iloc[0])
        for k in (0, 51, True, 2.5, "5"):
            with self.assertRaises(ValueError):
                self.built.retrieve(alert, k=k)
        with self.assertRaises(MemoryQueryError):
            self.built.retrieve(dict(alert, **{"Flow Duration": None}))

    def test_an_empty_result_is_reported_as_empty(self):
        frame = make_train_frame(per_class=1, labels=["BENIGN"])
        built, _, _ = self.seed(frame=frame, per_class_cap=1)
        res = built.retrieve(alert_from_row(frame.iloc[0]))     # the only record is the alert's own flow
        self.assertEqual((res["status"], res["k_returned"], res["nearest_distance"]), ("empty", 0, None))

    def test_isolation_report_flags_planted_addresses(self):
        self.assertEqual(self.built.verify_isolation(), [])
        with open(os.path.join(self.out, "records.jsonl"), "a", encoding="utf-8") as fh:
            fh.write('{"note": "10.1.2.3"}\n')
        self.assertTrue(any("IPv4" in p for p in self.built.verify_isolation()))

    def test_agreement_check_is_perfect_for_the_exact_backend(self):
        self.assertEqual(self.built.agreement_check(10)["top1_agree"], 1.0)


class LoaderAndCliTests(unittest.TestCase):
    def test_only_train_parquet_is_accepted(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for name in ("val.parquet", "test.parquet", "dev_alerts.parquet", "frozen_alerts.parquet", "alerts_val.parquet", "flow_store_dev.parquet", "train.csv"):
            path = os.path.join(d, name)
            with open(path, "wb"):
                pass
            with self.subTest(name):
                with self.assertRaises(MemoryDataError):
                    loader.check_train_path(path)

    def test_a_missing_training_split_fails_closed_with_a_clear_message(self):
        with self.assertRaises(MemoryDataError) as ctx:
            loader.load_train_frame(os.path.join(tempfile.gettempdir(), "no-such-dir-w4", "train.parquet"))
        self.assertIn("no other data", str(ctx.exception))

    def test_the_seed_command_stops_with_exit_code_2_when_training_data_is_missing(self):
        from week4 import seed_memory
        out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out, True)
        code = seed_memory.main(["seed", "--out-dir", os.path.join(out, "m"), "--train-path", os.path.join(out, "gone", "train.parquet")])
        self.assertEqual(code, 2)
        self.assertEqual(os.listdir(out), [])

    def test_the_verify_command_fails_closed_on_a_missing_store(self):
        from week4 import seed_memory
        self.assertEqual(seed_memory.main(["verify", "--out-dir", os.path.join(tempfile.gettempdir(), "no-such-store-w4")]), 2)


class ChromaOptionalTests(TmpMixin, unittest.TestCase):
    def test_chroma_index_matches_the_manifest(self):
        try:
            import chromadb  # noqa: F401
        except ImportError:
            self.skipTest("chromadb is not installed here; the Chroma backend is untested in this environment")
        frame = make_train_frame(per_class=30)
        built, out, _ = self.seed(frame=frame, per_class_cap=20, backend="chroma", chroma_path=os.path.join(self.tmp(), "chroma"))
        res = built.retrieve(alert_from_row(frame.iloc[1]), k=3)
        self.assertTrue(all(h["memory_id"] in built.allowlist for h in res["hits"]))
        self.assertGreaterEqual(built.agreement_check(10)["top1_agree"], 0.0)


class StaticBoundaryTests(unittest.TestCase):
    """The memory package must not be able to reach dev data, the frozen set, labels or the answer key."""
    FORBIDDEN_MODULES = {"eval_io", "eval_labels", "triage_inputs", "final_test_eval", "build_eval_sets", "verify_eval", "evaluate", "split", "make_alerts", "baseline_store"}
    ALLOWED_CONFIG_NAMES = {"DISPLAY_FEATURES", "TRAIN_PATH"}

    def modules(self):
        d = os.path.join(SRC, "week4", "memory")
        return [os.path.join(d, n) for n in sorted(os.listdir(d)) if n.endswith(".py")]

    def test_no_forbidden_imports_and_only_train_config_names(self):
        for path in self.modules():
            tree = ast.parse(rd(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = {a.name.split(".")[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom):
                    names = {(node.module or "").split(".")[0]}
                else:
                    names = set()
                self.assertFalse(names & self.FORBIDDEN_MODULES, path + " imports " + str(names & self.FORBIDDEN_MODULES))
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "config":
                    self.assertIn(node.attr, self.ALLOWED_CONFIG_NAMES, path + " reads config." + node.attr)

    def test_no_dev_frozen_label_or_answer_key_words_in_code(self):
        words = ("frozen", "FROZEN", "SOC_FROZEN", "VAL_PATH", "TEST_PATH", "ALERTS_", "FLOW_STORE", "MITRE_MAP", "mitre_map", "DEV_ALERTS", "dev_labels")
        for path in self.modules():
            code = rd(path)
            tree = ast.parse(code)
            for node in ast.walk(tree):                     # look at identifiers and attribute names, not at prose in docstrings
                ident = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None
                if ident:
                    self.assertFalse(any(w in ident for w in words), path + ": " + ident)


if __name__ == "__main__":
    unittest.main()
