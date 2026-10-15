"""The memory store: seeding from the train split, loading with verification, and retrieval with isolation checks.

On disk (one directory, deterministic content, no timestamps):
  manifest.json   {"manifest": {...}, "manifest_sha256": ...}  the split definition, the training file's sha256, parameters, scaler, counts and the hashes of the other files
  records.jsonl   one line per record: memory_id, label, flow_key_sha, source_ref (split, source_file, original_row), vector_sha256   -- no addresses, no technique ids
  vectors.npy     the scaled fingerprints, in records order
Re-seeding from the same training file with the same parameters gives byte-identical files and the same manifest_sha256.
"""
import json
import os
import shutil

import numpy as np

from . import records as R
from .backends import ChromaBackend, NumpyBackend
from .errors import MemoryDataError, MemoryIsolationError, MemoryQueryError, MemoryStoreError

MANIFEST_SCHEMA = "week4_memory_manifest_v1"
DEFAULT_PER_CLASS_CAP = 100      # a size choice made up front, not tuned
DEFAULT_SEED = 42                # the project seed (config.SEED)
DEFAULT_K = 5
DEFAULT_COLLECTION_PREFIX = "incident_memory_"
FILES = ("manifest.json", "records.jsonl", "vectors.npy")


def _write_text(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _read_text(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _file_sha(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_files(cands, train_sha256, train_rows, per_class_cap, seed, dev_key_texts, directory):
    """Select, fingerprint and write the three files into directory (which must not exist). Returns the manifest dict."""
    if len(cands) == 0:
        raise MemoryDataError("no usable training rows: nothing to seed")
    overlap = None
    if dev_key_texts is not None:
        dev = set(t for t in dev_key_texts if t)
        overlap = sum(1 for t in cands.key_texts if t in dev)
        if overlap:
            raise MemoryIsolationError("%d training rows have the same flow key as a dev alert. The train/dev boundary is violated; seeding stopped and nothing was written." % overlap)
    idx, stats = R.select(cands, per_class_cap, seed)
    if not idx:
        raise MemoryDataError("selection produced no records")
    raw = cands.raw[idx]
    scaler = R.fit_scaler(raw)
    vectors = R.apply_scaler(raw, scaler)
    lines, ids, labels = [], [], {}
    for row, i in enumerate(idx):
        rec = {"memory_id": cands.ids[i], "label": str(cands.labels[i]), "flow_key_sha256": R.key_hash(cands.key_texts[i]),
               "source_ref": {"split": R.SPLIT, "source_file": cands.source_files[i], "original_row": cands.original_rows[i]}, "vector_sha256": R.vector_sha256(vectors[row])}
        lines.append(R.canonical_json(rec))
        ids.append(rec["memory_id"])
        labels[rec["label"]] = labels.get(rec["label"], 0) + 1
    os.makedirs(directory)
    _write_text(os.path.join(directory, "records.jsonl"), "\n".join(lines) + "\n")
    np.save(os.path.join(directory, "vectors.npy"), vectors, allow_pickle=False)
    manifest = {
        "schema": MANIFEST_SCHEMA, "split": R.SPLIT, "train_file": "train.parquet", "train_sha256": train_sha256, "train_rows": int(train_rows),
        "vector_spec": R.VECTOR_SPEC, "features": R.FEATURE_NAMES, "scaler": scaler, "per_class_cap": per_class_cap, "seed": seed,
        "n_records": len(ids), "label_counts": dict(sorted(labels.items())), "allowlist_sha256": R.sha256_text("\n".join(ids)),
        "records_sha256": _file_sha(os.path.join(directory, "records.jsonl")), "vectors_sha256": R.vector_sha256(vectors),
        "usable_training_rows": len(cands), "left_out": {"invalid_rows": cands.n_invalid, "duplicate_fingerprints_collapsed": stats["duplicates_collapsed"]},
        "dev_overlap_check": {"performed": dev_key_texts is not None, "dev_keys_compared": (len(set(t for t in dev_key_texts if t)) if dev_key_texts is not None else 0),
                              "overlapping_rows": overlap or 0},
    }
    doc = {"manifest": manifest, "manifest_sha256": R.sha256_text(R.canonical_json(manifest))}
    _write_text(os.path.join(directory, "manifest.json"), json.dumps(doc, indent=2, sort_keys=True) + "\n")
    return manifest


def seed_store(cands, out_dir, train_sha256, train_rows, per_class_cap=DEFAULT_PER_CLASS_CAP, seed=DEFAULT_SEED, dev_key_texts=None, backend="numpy", chroma_path=None, say=print):
    """Build the store in a temporary directory, verify it by loading it, and only then put it in place. An existing store is renamed to <dir>.prev-<its manifest hash>, never deleted.
    Returns the loaded MemoryStore."""
    tmp = out_dir + ".building"
    if os.path.exists(tmp):
        raise MemoryStoreError("a previous build was interrupted: " + tmp + " exists. Inspect it, move it away, and run again.")
    try:
        manifest = build_files(cands, train_sha256, train_rows, per_class_cap, seed, dev_key_texts, tmp)
        MemoryStore.load(tmp, backend="numpy")            # the files must verify before they replace anything
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    new_sha = _read_json(os.path.join(tmp, "manifest.json"))["manifest_sha256"]
    if os.path.exists(out_dir):
        try:
            old_sha = _read_json(os.path.join(out_dir, "manifest.json"))["manifest_sha256"]
        except (OSError, ValueError, KeyError):
            old_sha = "unreadable"
        if old_sha == new_sha:
            say("the memory store is already up to date (manifest " + new_sha[:12] + "); nothing replaced")
            shutil.rmtree(tmp, ignore_errors=True)
            return MemoryStore.load(out_dir, backend=backend, chroma_path=chroma_path, build_index=(backend == "chroma"))
        prev = out_dir + ".prev-" + old_sha[:12]
        if os.path.exists(prev):
            shutil.rmtree(tmp, ignore_errors=True)
            raise MemoryStoreError(prev + " already exists; move it away before rebuilding")
        os.rename(out_dir, prev)
        say("the previous store was kept as " + prev)
    os.rename(tmp, out_dir)
    say("seeded %d records from %d usable training rows (manifest %s)" % (manifest["n_records"], manifest["usable_training_rows"], new_sha[:12]))
    return MemoryStore.load(out_dir, backend=backend, chroma_path=chroma_path, build_index=(backend == "chroma"))


class MemoryStore:
    def __init__(self, directory, manifest, manifest_sha256, records, vectors, backend, chroma=None):
        self.directory, self.manifest, self.manifest_sha256 = directory, manifest, manifest_sha256
        self.records, self.vectors = records, vectors
        self.allowlist = {r["memory_id"] for r in records}
        self.backend = backend
        self.chroma = chroma
        self.index_by_id = {r["memory_id"]: i for i, r in enumerate(records)}
        self.exact = NumpyBackend(vectors)

    # ------------------------------------------------------------------ loading and verification (fail closed)
    @classmethod
    def load(cls, directory, backend="numpy", chroma_path=None, build_index=False):
        for name in FILES:
            if not os.path.isfile(os.path.join(directory, name)):
                raise MemoryStoreError("the memory store is missing " + name + " in " + str(directory) + ". Seed it with: python -m week4.seed_memory seed")
        try:
            doc = _read_json(os.path.join(directory, "manifest.json"))
            manifest, claimed = doc["manifest"], doc["manifest_sha256"]
        except (OSError, ValueError, KeyError, TypeError):
            raise MemoryStoreError("the memory manifest cannot be read") from None
        if R.sha256_text(R.canonical_json(manifest)) != claimed:
            raise MemoryStoreError("the memory manifest does not match its own hash; the store was modified")
        if manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("split") != R.SPLIT or manifest.get("vector_spec") != R.VECTOR_SPEC:
            raise MemoryIsolationError("the manifest does not describe a train-split " + R.VECTOR_SPEC + " store")
        if _file_sha(os.path.join(directory, "records.jsonl")) != manifest["records_sha256"]:
            raise MemoryStoreError("records.jsonl does not match the manifest")
        records = [json.loads(line) for line in _read_text(os.path.join(directory, "records.jsonl")).splitlines() if line.strip()]
        vectors = np.load(os.path.join(directory, "vectors.npy"), allow_pickle=False)
        if vectors.shape != (len(records), R.DIM) or len(records) != manifest["n_records"]:
            raise MemoryStoreError("the stored vectors do not match the records")
        if R.vector_sha256(vectors) != manifest["vectors_sha256"]:
            raise MemoryStoreError("vectors.npy does not match the manifest")
        ids = [r["memory_id"] for r in records]
        if ids != sorted(ids) or len(set(ids)) != len(ids) or R.sha256_text("\n".join(ids)) != manifest["allowlist_sha256"]:
            raise MemoryStoreError("the record ids do not match the manifest's allowlist")
        for r in records:
            if (r.get("source_ref") or {}).get("split") != R.SPLIT:
                raise MemoryIsolationError("a stored record is not from the train split: " + str(r.get("memory_id")))
        chroma = None
        if backend == "chroma":
            name = DEFAULT_COLLECTION_PREFIX + claimed[:12]
            path = chroma_path or os.path.join(directory, "chroma")
            if build_index:
                metas = [{"label": r["label"], "split": R.SPLIT} for r in records]
                chroma = ChromaBackend(path, name, ids=ids, vectors=vectors, metadatas=metas)
            else:
                chroma = ChromaBackend(path, name)
            if chroma.count() != len(records):
                raise MemoryStoreError("the ChromaDB collection has %d entries but the manifest lists %d; rebuild the memory" % (chroma.count(), len(records)))
        elif backend != "numpy":
            raise ValueError("backend must be 'numpy' or 'chroma'")
        return cls(directory, manifest, claimed, records, vectors, backend, chroma)

    def info(self):
        m = self.manifest
        return {"manifest_sha256": self.manifest_sha256, "backend": self.backend, "n_records": m["n_records"], "per_class_cap": m["per_class_cap"], "seed": m["seed"],
                "train_sha256": m["train_sha256"], "vector_spec": m["vector_spec"], "label_counts": m["label_counts"]}

    # ------------------------------------------------------------------ retrieval
    def retrieve(self, alert, k=DEFAULT_K):
        """Similar past incidents for an alert (label-free alert dict). Returns the result dict stored in graph state:
        {status ok|empty, k_requested, k_returned, hits[...], label_counts, nearest_distance, filtered, store}.
        Raises MemoryQueryError (alert unusable) or MemoryIsolationError / MemoryStoreError (the store broke a rule). Never returns a record that is not on the allowlist."""
        if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= 50:
            raise ValueError("k must be an integer from 1 to 50")
        q = R.query_vector(alert, self.manifest["scaler"])
        own_key = R.key_hash(R.alert_flow_key_text(alert))
        want = min(k + 10, len(self.records))
        if self.backend == "chroma":
            found = []
            for mid, dist in self.chroma.query_ids(q, want):
                if mid not in self.index_by_id:
                    raise MemoryIsolationError("the ChromaDB index returned an id that is not on the allowlist: " + str(mid))
                found.append((self.index_by_id[mid], dist))
        else:
            found = self.exact.query(q, want)
        filtered = {"same_flow": 0, "duplicate_fingerprint": 0}
        hits, seen = [], set()
        for i, dist in found:
            rec = self.records[i]
            if rec["memory_id"] not in self.allowlist or (rec.get("source_ref") or {}).get("split") != R.SPLIT:
                raise MemoryIsolationError("a retrieved record is not an allowlisted train record: " + str(rec.get("memory_id")))
            if own_key is not None and rec.get("flow_key_sha256") == own_key:
                filtered["same_flow"] += 1
                continue
            if rec["vector_sha256"] in seen:
                filtered["duplicate_fingerprint"] += 1
                continue
            seen.add(rec["vector_sha256"])
            if len(hits) < k:
                hits.append({"rank": len(hits) + 1, "memory_id": rec["memory_id"], "distance": round(dist, 6), "label": rec["label"], "source_split": R.SPLIT,
                             "source_ref": dict(rec["source_ref"]), "manifest_sha256": self.manifest_sha256})
        counts = {}
        for h in hits:
            counts[h["label"]] = counts.get(h["label"], 0) + 1
        return {"status": "ok" if hits else "empty", "k_requested": k, "k_returned": len(hits), "hits": hits, "label_counts": dict(sorted(counts.items())),
                "nearest_distance": hits[0]["distance"] if hits else None, "filtered": filtered, "store": self.info()}

    def verify_isolation(self):
        """Re-check, on the loaded store, every rule that can be checked without the data: all records are train, ids are the allowlist, and none holds an address or technique id.
        Returns a list of problems (empty when clean)."""
        problems = []
        for r in self.records:
            if (r.get("source_ref") or {}).get("split") != R.SPLIT:
                problems.append("not train: " + str(r.get("memory_id")))
            extra = set(r) - {"memory_id", "label", "flow_key_sha256", "source_ref", "vector_sha256"}
            if extra:
                problems.append("unexpected fields " + ",".join(sorted(extra)) + " in " + str(r.get("memory_id")))
            if set(r.get("source_ref") or {}) != {"split", "source_file", "original_row"}:
                problems.append("unexpected source_ref fields in " + str(r.get("memory_id")))
        text = _read_text(os.path.join(self.directory, "records.jsonl"))
        import re
        if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text):
            problems.append("an IPv4 address appears in records.jsonl")
        if re.search(r"\"T\d{4}", text):
            problems.append("a technique id appears in records.jsonl")
        return problems

    def agreement_check(self, n=50):
        """For up to n stored records, compare the backend's nearest neighbour with the exact one (the record itself is skipped, as it would be in retrieval). Returns {checked, top1_agree}.
        With the numpy backend this is trivially 1.0."""
        checked = agree = 0
        for i in range(0, len(self.records), max(len(self.records) // n, 1)):
            if checked >= n:
                break
            q = self.vectors[i]
            exact = [j for j, _ in self.exact.query(q, 2) if j != i][:1]
            if self.backend == "chroma":
                got = [self.index_by_id[m] for m, _ in self.chroma.query_ids(q, 2) if m in self.index_by_id and self.index_by_id[m] != i][:1]
            else:
                got = exact
            checked += 1
            agree += int(got == exact)
        return {"checked": checked, "top1_agree": (agree / checked) if checked else None}
