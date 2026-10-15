"""Seed, rebuild and verify the incident memory.

  python -m week4.seed_memory seed   [--out-dir memory_store] [--backend numpy|chroma] [--per-class-cap 100] [--seed 42]
  python -m week4.seed_memory verify [--out-dir memory_store] [--backend numpy|chroma]

seed    reads data/processed/train.parquet ONLY, checks that none of its flows is a dev alert (through the label-free dev alert loader), and builds the store. Re-running with the same
        inputs is a no-op (identical manifest); a changed input replaces the store and keeps the old one as <dir>.prev-<hash>. Missing training data stops the run with exit code 2.
verify  loads the store, re-checks the manifest, hashes and train-only rules, and (for ChromaDB) measures agreement with the exact search. Prints JSON; exit 0 only when clean.
No Gemini or other model is called. The frozen set is never opened here.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))      # src/

from week4.memory import loader, records as R, store
from week4.memory.errors import MemoryDataError, MemoryIsolationError, MemoryQueryError, MemoryStoreError

import config

DEFAULT_OUT_DIR = os.path.join(config.PROJECT_ROOT, "memory_store")


def dev_key_texts():
    """Flow keys of the dev alerts, read through the label-free dev alert loader (the same one the agent uses). The frozen set is not reachable from here."""
    import triage_inputs
    alerts = triage_inputs.load_dev_alerts()
    keys = []
    for row in alerts.to_dict("records"):
        keys.append(R.flow_key_text(row.get("flow_id"), row.get("timestamp"), row.get("src_ip"), row.get("src_port"), row.get("dst_ip")))
    return keys


def parse_args(argv):
    p = argparse.ArgumentParser(description="Incident memory: seed from the train split, verify.")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("seed")
    s.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    s.add_argument("--train-path", default=None, help="must be a file named train.parquet (default: config.TRAIN_PATH)")
    s.add_argument("--backend", choices=["numpy", "chroma"], default="numpy")
    s.add_argument("--per-class-cap", type=int, default=store.DEFAULT_PER_CLASS_CAP)
    s.add_argument("--seed", type=int, default=store.DEFAULT_SEED)
    s.add_argument("--skip-dev-overlap-check", action="store_true", help="NOT recommended: the manifest records that the check was not performed")
    v = sub.add_parser("verify")
    v.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    v.add_argument("--backend", choices=["numpy", "chroma"], default="numpy")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        if args.command == "seed":
            frame, train_sha = loader.load_train_frame(args.train_path)
            cands = R.candidates_from_frame(frame)
            dev_keys = None if args.skip_dev_overlap_check else dev_key_texts()
            built = store.seed_store(cands, args.out_dir, train_sha, len(frame), per_class_cap=args.per_class_cap, seed=args.seed, dev_key_texts=dev_keys, backend=args.backend)
            print(json.dumps({"manifest_sha256": built.manifest_sha256, "n_records": built.manifest["n_records"], "label_counts": built.manifest["label_counts"],
                              "left_out": built.manifest["left_out"], "dev_overlap_check": built.manifest["dev_overlap_check"], "backend": args.backend}, indent=2, sort_keys=True))
            return 0
        loaded = store.MemoryStore.load(args.out_dir, backend=args.backend)
        problems = loaded.verify_isolation()
        report = {"manifest_sha256": loaded.manifest_sha256, "n_records": loaded.manifest["n_records"], "isolation_problems": problems, "agreement": loaded.agreement_check()}
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if not problems else 1
    except (MemoryDataError, MemoryStoreError, MemoryIsolationError, MemoryQueryError) as error:
        print("STOPPED: " + type(error).__name__ + ": " + str(error))
        return 2


if __name__ == "__main__":
    sys.exit(main())
