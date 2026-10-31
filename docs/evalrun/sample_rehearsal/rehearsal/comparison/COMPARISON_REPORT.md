# Week 5 final-evaluation comparison: raw detector vs single-LLM baseline vs full SOC-Triage system

> **REHEARSAL. Synthetic fixture data and a fake model. These numbers exercise the tooling; they say NOTHING about the detector, the baseline or the system. Do not quote them.**

Plan `rehearsal` (SHA-256 `ef13b79ce9a79f1804802098f6bbecfd2cb655d314d37f7c63920606d32a1fa9`), set **fixture**, generated 2026-10-18T07:58:49Z. Model: `FAKE:rehearsal` (temperature 0.0, max output tokens 1024, seed 42, parse retries 2). Detector threshold 0.00459436746314168.

## 1. Validity of the comparison

All checks passed: nine runs present and complete (three per configuration), no partial folders, file hashes intact, every record well-formed, every run covers exactly the evaluation set's alerts in the same order, the same input hashes (alerts, labels, flows) in every run, the plan's model and generation settings in every model-based run, the same detector threshold, the same risk policy, no fake run mixed in, and the raw detector identical in its three runs.

| run | unique run id |
|---|---|
| raw_detector/run1 | rehearsal-raw_detector-r1-39ee8b0b |
| raw_detector/run2 | rehearsal-raw_detector-r2-9990cb6c |
| raw_detector/run3 | rehearsal-raw_detector-r3-b5f62f44 |
| single_llm_baseline/run1 | rehearsal-single_llm_baseline-r1-3ae2a421 |
| single_llm_baseline/run2 | rehearsal-single_llm_baseline-r2-382bef24 |
| single_llm_baseline/run3 | rehearsal-single_llm_baseline-r3-2f7d86ef |
| full_system/run1 | rehearsal-full_system-r1-1e3a3aa0 |
| full_system/run2 | rehearsal-full_system-r2-fdd64f16 |
| full_system/run3 | rehearsal-full_system-r3-506d7514 |

Inputs: set=fixture, alert_count=24, alerts_sha256=5ccdd81c4de09167807e282e7019e298a7d85b7b26c454a73a597171051bb3b7, alert_ids_sha256=fc92929cb3e3fb8ec534a76af9bb44659cacbb8c31064e10dcfcbc747b516c0e, labels_sha256=315458ccb38748b155f71a7da3c05d226e31f97fd903c96546a1a39751b1a0c4.

## 2. Definitions (the project's own, reused)

Positive class = malicious. Every alert in the evaluation set is a detector alert, so the raw detector's decision on every alert is "malicious". Three denominator policies handle alerts that received no verdict:

- **valid_only**: Only alerts that received a valid verdict. Alerts with no verdict are left out of the denominator.
- **failures_escalated**: All alerts. An alert with no verdict stays escalated (counted as predicted malicious), as an analyst queue would treat an untriaged alert.
- **failures_wrong**: All alerts. An alert with no verdict is always counted wrong: an attack becomes a miss, a benign alert becomes a false positive. Worst case.

A request that failed is never mixed with an ordinary classification error: section 5 lists system failures (parse failure, model unavailable, system error) separately from wrong verdicts. Recall is measured among alerts the detector already raised; attacks the detector missed are not in the set, so this is not end-to-end recall.

## 3. Raw detector

| metric | value (3 identical runs) |
|---|---|
| precision | 0.5000 |
| recall | 1.0000 |
| F1 | 0.6667 |
| specificity | 0.0000 |
| false positives | 12 |
| false negatives | 0 |

## 4. Comparison, mean of three runs [min to max when runs differ]

| metric | single-LLM baseline | full system |
|---|---|---|
| precision (valid verdicts only) | 0.8333 | 0.9091 |
| recall (valid verdicts only) | 0.8333 | 0.9091 |
| F1 (valid verdicts only) | 0.8333 | 0.9091 |
| precision (no-verdict counted wrong) | 0.8333 | 0.8333 |
| recall (no-verdict counted wrong) | 0.8333 | 0.8333 |
| F1 (no-verdict counted wrong) | 0.8333 | 0.8333 |
| false-positive reduction % (no-verdict stays escalated) | 83.3333 | 83.3333 |
| attacks missed (no-verdict stays escalated) | 2 | 1 |
| verdict coverage | 1.0000 | 0.9167 |
| final parse-failure rate | 0.0000 | 0.0417 |
| model-error rate | 0.0000 | 0.0417 |
| attack-type accuracy | 0.8333 | 0.3636 |
| MITRE accuracy (all attacks; no-verdict wrong) | 0.8333 | 0.3333 |
| auto-close rate | n/a | 0.0000 |
| review-queue rate | n/a | 1.0000 |
| TRUE ATTACKS AUTO-CLOSED (count) | n/a | 0 |
| latency per alert, median (s) | 0.0000 | 0.0000 |
| latency per alert, p95 (s) | 0.0000 | 0.0000 |
| throughput (alerts/s) | 743.4991 [705.8824 to 797.3422] | 60.5065 [49.5050 to 76.4331] |
| total tokens | n/a | n/a |

Routing and auto-close rows exist only for the full system (the baseline has no routing). Tokens and cost appear only when the provider reported tokens; a fake model reports none. No significance test is given: three runs of a non-deterministic model cannot support one. Differences smaller than the spread between runs of the same configuration should be read as noise.

## 5. Failures kept apart from classification errors

| run | alerts | valid verdicts | parse failures | model unavailable | system errors | wrong verdicts | of which FP | of which FN |
|---|---|---|---|---|---|---|---|---|
| raw_detector/run1 | 24 | 24 | 0 | 0 | 0 | 12 | 12 | 0 |
| raw_detector/run2 | 24 | 24 | 0 | 0 | 0 | 12 | 12 | 0 |
| raw_detector/run3 | 24 | 24 | 0 | 0 | 0 | 12 | 12 | 0 |
| single_llm_baseline/run1 | 24 | 24 | 0 | 0 | 0 | 4 | 2 | 2 |
| single_llm_baseline/run2 | 24 | 24 | 0 | 0 | 0 | 4 | 2 | 2 |
| single_llm_baseline/run3 | 24 | 24 | 0 | 0 | 0 | 4 | 2 | 2 |
| full_system/run1 | 24 | 22 | 1 | 1 | 0 | 2 | 1 | 1 |
| full_system/run2 | 24 | 22 | 1 | 1 | 0 | 2 | 1 | 1 |
| full_system/run3 | 24 | 22 | 1 | 1 | 0 | 2 | 1 | 1 |

## 6. Full system: routing

| run | auto_close | escalate | needs_review | no routing | true attacks auto-closed | which |
|---|---|---|---|---|---|---|
| run1 | 0 | 22 | 2 | 0 | 0 of 12 | none |
| run2 | 0 | 22 | 2 | 0 | 0 of 12 | none |
| run3 | 0 | 22 | 2 | 0 | 0 of 12 | none |

An auto-closed attack is a missed attack; that column is the safety-critical one. Guard signals (full system): none.

## 7. Stability across the three runs

| configuration | alerts identical in all runs | alerts that changed | share identical |
|---|---|---|---|
| raw_detector | 24 | 0 | 1.0000 |
| single_llm_baseline | 24 | 0 | 1.0000 |
| full_system | 24 | 0 | 1.0000 |

## 8. Sources of non-determinism and other limits

- Model replies can differ between runs even at temperature 0 and a fixed seed (provider-side non-determinism).
- Latency depends on provider load, network and the calls-per-minute gate, not only on the system.
- Runs are sequential; no concurrency effects are introduced by this tool.
- The full system and the baseline share one model and one set of generation settings by plan; the full system also makes up to the plan's parse retries per alert and runs the Week 3/4 graph (tools, guard, risk policy).
- The full system ran with memory `off` and identifier aliasing `off` (see the plan); aliasing off keeps prompts byte-identical to the Week 3/4 dev runs, which is safe only because evaluation alert ids are trusted dataset ids.
- Prompts and raw model replies are not stored in the run folders; their hashes are.
- Cost: not computed (fake model).

