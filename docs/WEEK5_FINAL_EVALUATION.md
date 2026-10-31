# Week 5 — Final-Evaluation Tooling (Day 5)

## What this is

Tooling to compare three configurations on the same alerts, with three recorded runs per configuration: the **raw detector**, the **single-LLM baseline**, and the **full SOC-Triage system**.

This tooling is intended for a separately authorised final evaluation. **No protected-set evaluation is claimed here.** The rehearsal and tests use synthetic fixtures and fake models; their results describe the tooling, not the accuracy or security of a real system.

## What was reused (nothing re-implemented)

| Need | Existing code reused |
|---|---|
| Threshold, model name, temperature, max tokens, seed and parse retries | `config.ACCEPTED_THRESHOLD`, `llm_config`, `run_baseline_dev.GENERATION_SEED` (read by `plan --set dev/frozen`) |
| Baseline prompt and per-alert record | `prompt_registry.build_prompt_for_row`, `run_baseline_dev.process_alert`, `verdict_parser` |
| Full system | `week5.runner.GraphRunner.execute` — Week 3/4 graph, response guard and Week 4 routing policy, with the Week 5 post-routing evidence safeguards |
| Input checks and per-alert table | `evaluate.check_inputs`, `evaluate.build_table` (Week 2) |
| Precision/recall/F1 under three no-verdict policies, confusion, FP reduction, attack-type and MITRE accuracy, reliability, tokens, cost and latency | `eval_metrics.build_metrics` (Week 2) |
| Routing and auto-close metrics | `week4.evaluate_memory.routing_metrics` |

New components include the evaluation plan, protected-data gate, run recorder, validator, cross-run summary and report.

## The three configurations

- **`raw_detector`** — no model. Every alert in the set is treated as malicious under the Week 2 definition. It provides no attack type or technique; those metrics are not shown. The three runs must be identical, which is checked.
- **`single_llm_baseline`** — the Week 2 baseline prompt and parser, with one model call per alert plus parse retries.
- **`full_system`** — Week 3/4 graph (tools, specialists and verdict), response guard, Week 4 risk policy, and the Week 5 post-routing evidence safeguards. Memory on/off and identifier aliasing on/off are plan fields selected before a run.

Both model-based configurations share a model and generation settings stored in the plan. Each run records the model and settings read from the client object actually used. The validator compares these values against the plan.

## Files and layout

`src/week5/evalrun/` contains:

- `plan.py` — plan and plan hash
- `gate.py` — protected-set gate
- `data.py` — `EvalData` and synthetic fixture
- `collect.py` — one recorded run
- `validate.py` — run validation
- `metrics.py` — metrics
- `report.py` — report generation
- `pipeline.py` — evaluation pipeline
- `rehearsal.py` — fake-model rehearsal
- `__main__.py` — command-line interface

A run is written under:

`<out-root>/<plan_id>/<config>/run<k>/`

It contains `config_snapshot.json`, `run_meta.json`, `results.jsonl`, `errors.jsonl` and `run.sha256`. Incomplete output is written to a `.partial` directory and renamed only when complete. Existing runs are not overwritten.

Prompts and raw model replies are not stored. Prompt hashes and parse outcomes are recorded, and free-text model evidence is blanked to avoid copying protected alert content into result files.

## Validation before any comparison (`validate.py`)

Validation checks for:

- Missing or partial runs and unexpected folders.
- Missing, truncated or tampered files.
- Invalid schemas and inconsistent statuses.
- Duplicate alerts, missing alerts or alerts in the wrong order.
- Runs from a different plan.
- Different input hashes for alerts, labels or flows between runs or against the supplied data.
- Differences in model or settings between the plan, run record and actual client.
- Differences in threshold or risk policy.
- Fake runs mixed with real runs or used with a real plan.
- A non-deterministic raw-detector result.

If any validation check fails, the report says **NOT COMPARABLE**, lists the problems and prints no metrics. Records are not silently repaired or dropped.

## Metrics and what is deliberately not claimed

Per-run metrics and mean/minimum/maximum across the three runs include:

- Precision, recall and F1 under three no-verdict policies.
- Confusion counts and false-positive reduction.
- Attack-type and MITRE accuracy.
- Routing and auto-close behaviour, including the safety-critical count of true attacks auto-closed.
- Review-queue rate.
- Parse-failure and model-error rates.
- Median and p95 latency, throughput, tokens and cost.
- Number of alerts whose verdict changes between runs.

System failures (parse failure, model unavailable or system error) are listed separately from wrong verdicts.

Tokens are reported only when the provider reports them. Cost is reported only when a pricing record is included in the plan. Nothing is estimated.

Three runs of a non-deterministic model do not support claims of statistical significance. Differences smaller than the spread between runs should be treated cautiously.

Recall is measured among alerts already raised by the detector; it is not end-to-end recall.

## Non-determinism

Model replies can differ between runs even at temperature zero and with a fixed seed. Latency depends on provider load, network conditions and rate limits. Runs are sequential (concurrency 1), so this tool adds no concurrency effects.

For model-based configurations, external model-service behaviour is a potential source of run-to-run variation. The raw-detector runs must be identical.

## The protected-data gate (fail closed)

The evaluation code does not discover or load the frozen set by itself. The only code path that can open it is `gate.open_frozen()`, and all of the following conditions must hold:

1. `SOC_FROZEN_UNLOCK` has the documented value retained from `eval_io.py`.
2. `WEEK5_FINAL_EVAL_AUTH` names a JSON authorisation file containing the exact statement: "I authorise opening the frozen evaluation set for exactly the runs listed in this file." It must include `authorized_by`, `authorized_at`, an `expires_at` no more than seven days later and not already passed, `set: "frozen"`, the SHA-256 of one exact plan, and permitted run keys such as `full_system/run1` and `score/all`.
3. The run key has not previously opened the frozen set. The append-only `final_eval_ledger.jsonl` records access; repeating a run requires a new plan and authorisation.
4. The `--i-understand-this-opens-the-frozen-set` flag is provided.

Any missing, malformed, oversized, expired, mismatched or unexpected condition results in denial. The ledger entry is written and flushed before any protected file is read. `eval_io` is imported only inside `open_frozen()`. Scoring is a separate gated operation (`score/all`). Changing the plan after authorisation invalidates that authorisation.

The 71 tests in `tests/test_week5_evalrun.py` exercise the closed default environment, tripwires, invalid authorisation cases, ledger behaviour and synthetic rehearsal. These tests establish the tested gate behaviour; they do not establish that a real protected-set evaluation has occurred.

## Commands (Windows PowerShell, from the repository root)

### Safe synthetic rehearsal

```powershell
$env:PYTHONPATH = "src;."
python -m week5.evalrun rehearse --out-root runs_tmp\evalrun_rehearsal
```

This uses synthetic data and fake models. It does not require opening the protected set.

### Tests

```powershell
python -m unittest tests.test_week5_evalrun
```

### Inspect gate status without reading protected data

```powershell
python -m week5.evalrun gate-status --plan PLAN.json --run-key full_system/run1
```

Replace `PLAN.json` with the actual plan path when one exists.

## Authorised final evaluation

The protected-set evaluation is a separate, explicit action. Do not run it until the configuration choices have been made and the live dev-set dry run has been reviewed.

The intended workflow is:

1. Decide the open items below.
2. Create a frozen plan using `python -m week5.evalrun plan --set frozen --plan-id final_v1 --out PLAN.json`, adding `--memory on` and/or `--alias-ids` only if those are the chosen settings.
3. Generate the authorisation template, then fill in the authorisation details and set `WEEK5_FINAL_EVAL_AUTH`.
4. Collect the nine authorised runs with the documented `--live` and `--i-understand-this-opens-the-frozen-set` flags. This requires the live-model setting, a valid provider key and real API calls.
5. Run the separately authorised scoring step with `score/all` included in the authorisation.
6. Review `COMPARISON_REPORT.md`.

A development-set dry run should be completed first. Use a dev plan and the documented commands, without opening the protected set. Check the CLI help for the exact options supported by the installed version before running a live command.

## Open items that need a decision

1. **Memory for the full system:** on or off. This is a plan field and changes the system being evaluated.
2. **Identifier aliasing during evaluation:** default off to keep prompts aligned with Week 3/4 development runs. Enable it only if that is the intended evaluation configuration.
3. **Week 5 evidence safeguard:** implemented and tested against PI-E02. The full-system evaluation must include the current Week 5 routing behaviour, and the chosen configuration must be recorded in the plan before its hash is frozen. The upgrade adds `evidence-policy-v1` after your W5-RR1 safeguards (`docs/WEEK5_POLICY_CHANGES.md`): a plan made after it records the combined identity `risk-policy-v1+evidence-policy-v1`, and results from plans made before it are NOT comparable with plans made after it. The W5-RR1 functions in `runner.py` are code and are not part of that identity.
4. **Pricing record:** include one if cost reporting is required; otherwise cost is unavailable.
5. **Live evaluation path:** the real Gemini clients and live backends must be exercised in a dev-set dry run before any protected-set evaluation.

## Not verified

- Equivalence with a real LangGraph runtime if the run used the instrumented engine. A frozen plan requires `engine=langgraph`.
- Real Gemini behaviour and the real development dataset/flow store.
- Memory-on runs unless separately executed.
- Real token usage and cost figures unless supplied by the provider and pricing record.
- A protected-set evaluation. The synthetic rehearsal is not evidence of model accuracy on that set.

## Interpretation

The evaluation tooling is designed to make runs comparable, preserve evidence and prevent accidental access to protected data. Passing its tests does not demonstrate model accuracy, production readiness or security against all attacks.

The Week 5 RR-1 safeguard changes routing for tested evidence patterns. It is a conservative review trigger, not proof that an alert is malicious. The final evaluation should record the safeguard and assess routing outcomes rather than treating the scripted injection suite as a substitute for real-model evaluation.
