# Evaluation guide: datasets, reproducible commands, metrics, and what each result can and cannot say

There are three separate things here. They are never mixed in one table, and every report says which one it is.

| | What it is | Data | Model | What it can say |
|---|---|---|---|---|
| **A. Sensor-pipeline suite** | `python -m week5.evalrun.sensor_suite` | `synthetic-sensor-v1`: 56 generated scenarios (30 attack, 26 benign, 11 families) written as EVE events + flows by `week5/evalrun/sensor_scenarios.py`. Labels come from how each scenario is built. **Synthetic.** | A scripted fake with named behaviours (`oracle`, `lazy_benign`, `noisy`) | What the deterministic layers (sensor severity, risk policy, evidence policy veto, safe failure) do under an *assumed* model behaviour; safety invariants; latency/throughput of this software. **Not detection accuracy.** |
| **B. Formal three-way comparison** | `python -m week5.evalrun plan / collect / validate / score` | The CIC-IDS2017 dev set (real labelled flows, already in the project) or, with separate written authorisation, the frozen set | Real Gemini (`--live`) or fake (rehearsal) | The raw detector vs the single-LLM baseline vs the full system on the same alerts, 3 runs each. This is the only route to a real accuracy statement, and it has **not been run**. |
| **C. Security regression suite** | `python -m week5.security.injection run --out-dir runs_tmp\injection` and the unit tests (63 payloads incl. controls, 9 gates; see `WEEK5_SECURITY.md`) | Fixed hostile cases (prompt injection in alert, tool and analyst text, malformed model output, secret redaction, authorization, approval bypass, provider failure, retries) | Scripted | Pass/fail of each safety behaviour. Sample output: `docs/security/sample_run/`. |

## A. Reproduce the sensor-pipeline suite (offline, free, deterministic)

```powershell
$env:PYTHONPATH = "src;."
python -m week5.evalrun.sensor_suite --out runs_tmp\sensor_eval
```
Options: `--profiles oracle,lazy_benign,noisy`, `--failure-fraction 0.2` (share of alerts given an injected model outage in the provider-failure run), `--seed N`. It writes `sensor_eval.json` (all numbers), `sensor_eval_records.json` (one record per alert and configuration), and `SENSOR_EVAL_REPORT.md`. Same seed, same input: same numbers except wall-clock timings. A pre-generated run is in `docs/evalrun/sensor_sample_run/`.

To see it in the console: copy the three files into `reports\` and start the stack with `docker-compose.reports.yml` (see `WEEK5_DEPLOYMENT.md`), or set `WEEK5_EVAL_REPORT_DIR` for a local API.

**Reading it.** *Positive* means "the alert was not closed" (it went to an analyst). A *missed attack* is an attack that was closed. A *sensor alert is never auto-closed* (it has no detector score), so the plain flagged rate is 100%, false-positive rate is 100% and specificity 0%: the system prioritises, it does not reduce volume. The informative rows are the `*_escalate_only` ones (flagged = top-priority queue) and the per-class and per-family tables. This is a finding about the design, not a defect in the numbers. The one remaining way a real attack could be closed is a low-score alert with no sensor evidence at all (known issue PI-E12 in `WEEK5_SECURITY.md`).

Configurations compared on the same scenarios: `sensor_passthrough`, `sensor_severity_rule` (Suricata severity 1-2 flagged, no model), `model_only`, `model_plus_risk_policy`, `full_pipeline` (what the system stores). Metrics per configuration: TP, FP, TN, FN, precision, recall, F1, specificity, false-positive rate, false-negative rate, flagged rate, attacks wrongly closed, missed scenario names; per true class and per family; operations: latency median and p95, throughput, failed jobs, retried alerts, total attempts, tokens and cost.

**Tokens and cost** are `unavailable` for a fake model, with the reason printed. Cost is only reported when token counts exist *and* a verified pricing file is configured (`pricing.template.json` is a template with no prices); no price is ever assumed.

**Invariants** checked on every run and reported as violations if broken: no attack closed by the model alone, no sensor alert auto-closed, the evidence policy never lowered caution, no action left pending without a human, every injected outage routed to a person.

## B. The formal comparison (real accuracy lives here; not yet run)

Documented in `WEEK5_FINAL_EVALUATION.md`: `plan --set dev` then `collect` for each of three configurations and three runs (`--live` needs `WEEK5_ALLOW_LIVE_MODEL=1` and your Gemini key and spends real calls), then `validate` and `score`. The metrics now include false-positive and false-negative rates, per-class results and retry counts (report section 8).

- **Dev set**: real labelled CIC-IDS2017 flows already in the project. Using it requires your key and your decision to spend the calls. Nothing here ran it.
- **Frozen set**: never opened by any tool in this package. `gate.open_frozen()` requires a written authorisation file naming the exact plan hash, an expiry, a per-run key and an explicit flag; the ledger is written before any protected file is read. Do not open it for tuning.
- **Real Suricata traffic**: none was available. The only EVE events in the repository are hand-written samples (`samples/eve/`), which exercise parsing and the pipeline, not detection.

## What each level of evidence in this package is

| Claim | Evidence | Level |
|---|---|---|
| The pipeline never closes a sensor alert and the evidence policy never lowers caution | unit tests, exhaustive monotonicity test, suite invariants | unit-tested |
| EVE event to case to analyst feedback works end to end | `tests/test_week5_sensor_e2e.py` (memory and PostgreSQL), browser run | integration-tested; PostgreSQL verified |
| Behaviour under a wrong or lazy model | suite profiles `lazy_benign`, `noisy` | synthetic, scripted |
| Gemini output handling | scripted malformed/hostile model replies | unit-tested; **not** verified with live Gemini |
| AbuseIPDB enrichment | stub HTTP server tests | unit-tested; **not** verified with the live service |
| Detection accuracy on real traffic | none | **not evaluated** |
