# Load test report

Run: 2026-10-16T20:25:55Z to 2026-10-16T20:26:04Z, mode `inprocess`, model `FAKE:canned` (FAKE).
Machine: Python 3.13.16, 2 CPU(s). Week 5 version week5-v1.

## Parameters

| parameter | value |
|---|---|
| client_threads | 8 |
| drain_timeout_s | 120.0 |
| duplicate_fraction | 0.0 |
| label | "open_loop_overload_2w (sandbox, fake model)" |
| pattern | "open loop" |
| rate_per_s | 40.0 |
| seed | 12 |
| total_alerts | 200 |

## Backend

| setting | value |
|---|---|
| api_rate_limit_per_minute | 0 |
| engine | "instrumented" |
| failure_mix | "none" |
| job_timeout_s | 30.0 |
| max_attempts | 3 |
| model | "FAKE:canned (simulated latency)" |
| queue | "in-memory job store polled by worker threads" |
| retry_backoff_s | [0.05, 0.1, 0.2] |
| simulated_model_delay_s | 0.05 |
| simulated_model_jitter_s | 0.02 |
| worker_poll_s | 0.005 |
| workers | 2 |

## Outcome

| measure | value |
|---|---|
| submissions | 200 |
| jobs created | 200 |
| duplicates recognised | 0 |
| succeeded | 200 |
| failed | 0 |
| timed out | 0 |
| unfinished at drain timeout | 0 |
| retried jobs | 0 |
| requests not accepted | 0 |
| HTTP statuses | {"202": 200} |

## Throughput

| measure | value |
|---|---|
| accepted per second | 40.166 |
| completed per second | 24.095 |
| makespan (s) | 8.300 |
| submit window (s) | 4.979 |
| max jobs in flight observed | 78 |

## Latency

| metric | unit | n | min | mean | p50 | p90 | p95 | p99 | max | low-sample percentiles |
|---|---|---|---|---|---|---|---|---|---|---|
| api_submit_ms | ms | 200 | 0.2660 | 0.7680 | 0.4190 | 0.5460 | 0.7610 | 4.1990 | 40.2590 | - |
| queue_wait_s | seconds | 200 | 0.0001 | 1.5786 | 1.5631 | 2.8860 | 3.0622 | 3.2044 | 3.2556 | - |
| processing_s | seconds | 200 | 0.0386 | 0.0825 | 0.0802 | 0.1082 | 0.1153 | 0.1306 | 0.1581 | - |
| end_to_end_s | seconds | 200 | 0.0963 | 1.6610 | 1.6601 | 2.9556 | 3.1589 | 3.2847 | 3.3247 | - |
| client_lag_s | seconds | 200 | 0.0001 | 0.0038 | 0.0009 | 0.0118 | 0.0155 | 0.0230 | 0.0288 | - |

## Time per graph node (seconds per job)

| node | mean | p95 | calls per job |
|---|---|---|---|
| c2_beacon_analyst | 0.006948 | 0.011012 | 1.00 |
| enrichment_agent | 0.002963 | 0.004794 | 1.00 |
| supervisor | 0.000098 | 0.000139 | 4.75 |
| traffic_analyst | 0.014728 | 0.029377 | 1.00 |
| verdict_node | 0.052636 | 0.071173 | 1.00 |

## Verdict and routing outcomes (succeeded jobs)

Verdict status: `{"ok": 200}`. Routing decision: `{"escalate": 200}`. With a fake model these are plumbing results, not detection quality.

## Errors

By error code: `{}`. Non-success HTTP: `{}`.

## Model usage and cost

Model calls: 200. Tokens: unavailable (a fake model reports no token counts). Cost: unavailable (unavailable: cost needs real token counts and a priced, sourced pricing file; a fake model has neither).

## How to read this

- Percentiles are nearest-rank; a percentile with too few samples is listed in low_sample and equals (or nearly equals) the maximum.
- The model is a FAKE with a SIMULATED delay. These numbers describe this software's own overhead plus that delay. They say nothing about Gemini's real latency, quota or cost.
- No token counts and no cost are reported: a fake model has none, and nothing was estimated.
- In-process mode calls the API handlers directly (no HTTP, no network, no database) and runs the workers as threads of one Python process, so it cannot show true parallel speed-up of CPU work.
- Results are for one machine and one run; repeat it (different seeds) before drawing conclusions, and never compare runs made with different settings.
