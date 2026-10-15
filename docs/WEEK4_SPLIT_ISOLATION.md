# Week 4 split isolation: how train, dev and frozen data are kept apart

## The rules

1. **Memory is seeded from the training split only.** The one file the seeder will read is `train.parquet` (`memory/loader.py` refuses any other file name). A missing file is an error (`MemoryDataError`, exit code 2): nothing is substituted - not dev, not validation, not test, not frozen.
2. **Allowlist.** The store's eligible records are exactly the sorted `memory_id`s `train:<source_file>:<original_row>` listed in `records.jsonl`; `manifest.json` carries their combined hash (`allowlist_sha256`) and the train file's sha256. Every stored record has `source_ref.split == "train"`.
3. **No dev or frozen flow can be in memory.** At seeding, every training flow key is compared with the flow keys of the dev alerts (read through the label-free dev loader); any overlap stops the build and writes nothing. The frozen set is not reachable from the memory code at all (no import of `eval_io`, labels or the frozen loaders).
4. **Re-checked at run time.** `run_memory_dev.py --memory on` loads the store (hash and structure verified), then compares the stored flow-key hashes with the dev alerts again. Overlap, damage or a missing store stops the run before any model call. The evidence (`records_checked`, `dev_keys_compared`, `dev_overlap = 0`, manifest and train hashes) is written to `run_meta.json`.
5. **Retrieval validates every hit.** A hit that is not on the allowlist or not `train` raises `MemoryIsolationError` and the memory step records an `isolation_violation` error (the case then cannot be auto-closed). The alert's own flow and duplicate fingerprints are filtered out of results.
6. **Records carry no answer-bearing text.** A record is: label, a 22-number fingerprint, a flow-key hash and its source reference. No addresses, no ports as text, no MITRE technique ids, no free text. The model sees only label counts and the label/distance of the closest three.
7. **Evaluation is separate.** Labels are read only by `evaluate_memory.py` (dev labels, dev answer key). The frozen set is never used to tune, seed or choose thresholds; the runner refuses to start if `SOC_FROZEN_UNLOCK` is set; the frozen access log is hashed before and after each run and in the lock.
8. **Rebuild is safe and deterministic.** Selection is a per-class cap (default 100), hash-ranked with a fixed seed (42), fingerprint-deduplicated; no timestamps are written. Same inputs = byte-identical store. A different train file or parameter produces a new manifest and keeps the old store as `.prev-<hash>`.

## How the isolation is tested

| rule | test module |
|---|---|
| train-only file, missing train fails closed, allowlist, manifest, tamper detection, deterministic rebuild | `tests/test_week4_memory.py` |
| retrieval refuses non-allowlisted or non-train hits; own flow and duplicates filtered | `tests/test_week4_memory.py`, `tests/test_week4_graph.py` |
| dev overlap stops seeding and stops a memory-on run before any call; missing/tampered store stops the run | `tests/test_week4_memory.py`, `tests/test_week4_runner.py` |
| memory errors become explicit auditable states and block auto-close; memory cannot authorise anything | `tests/test_week4_graph.py`, `tests/test_week4_policy_approval.py` |
| no agent-side module imports labels, the evaluator or frozen loaders; the evaluator reads dev labels only | `tests/test_week4_runner.py`, `tests/test_week4_evaluate.py` |
| frozen access log, Week 1 files and the Week 3 lock are unchanged by the runs and the lock | `tests/test_week4_runner.py`, `tests/test_week4_lock.py` |
| the lock refuses a comparison with a clean-isolation record missing, a changed store or a changed train file | `tests/test_week4_evaluate.py`, `tests/test_week4_lock.py` |

All of these use synthetic training data (`tests/week4_support.make_train_frame`). They prove the boundaries hold in the code; they do not claim anything about real data. Real-data evidence comes from `python -m week4.seed_memory seed`/`verify` and the recorded isolation check of the real runs.

## Known limits

- Flow-key comparison catches the same flow appearing in both splits. It cannot catch *different* flows that are statistically near-identical (CIC-IDS2017 repeats attack tools and hosts across days), so memory can look more useful on the dev set than it would on unfamiliar traffic. This is reported as a confounder in the comparison.
- The split itself (Week 1) is the project's definition of "train"; this code verifies its own use of it, not the original split.
