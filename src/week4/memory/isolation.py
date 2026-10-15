"""Run-time split-isolation checks for a loaded memory store (no data files are read here; the caller passes in what to compare against).

  dev_overlap(store, dev_key_texts)   how many stored records share a flow key with a dev alert (must be 0)
  check_run_isolation(store, dev_key_texts)   raises MemoryIsolationError on any overlap or any structural problem; returns the evidence dict recorded in run_meta.json

Flow keys are compared as hashes (records hold only the hash). Dev keys come from the label-free dev alert loader; the frozen set is never involved.
"""
from . import records as R
from .errors import MemoryIsolationError


def dev_overlap(store, dev_key_texts):
    dev_hashes = set(R.key_hash(t) for t in dev_key_texts if t)
    return sum(1 for r in store.records if r.get("flow_key_sha256") in dev_hashes)


def check_run_isolation(store, dev_key_texts):
    if dev_key_texts is None:
        raise MemoryIsolationError("the dev flow keys were not supplied, so the train/dev boundary cannot be checked; refusing to run with memory")
    problems = store.verify_isolation()
    if problems:
        raise MemoryIsolationError("the memory store failed its isolation check: " + "; ".join(problems[:3]))
    overlap = dev_overlap(store, dev_key_texts)
    if overlap:
        raise MemoryIsolationError("%d stored memory records have the same flow key as a dev alert; the train/dev boundary is violated" % overlap)
    return {"records_checked": len(store.records), "dev_keys_compared": len(set(t for t in dev_key_texts if t)), "dev_overlap": 0, "structural_problems": 0,
            "manifest_sha256": store.manifest_sha256, "train_sha256": store.manifest["train_sha256"]}
