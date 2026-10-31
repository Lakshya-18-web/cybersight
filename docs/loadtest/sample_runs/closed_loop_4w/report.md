# Load test report

Run: 2026-10-16T20:25:45Z to 2026-10-16T20:25:55Z, mode `inprocess`, model `FAKE:canned` (FAKE).
Machine: Python 3.13.16, 2 CPU(s). Week 5 version week5-v1.

## Parameters

| parameter | value |
|---|---|
| client_threads | 16 |
| drain_timeout_s | 120.0 |
| duplicate_fraction | 0.0 |
| label | "closed_loop_4w (sandbox, fake model)" |
| pattern | "closed loop" |
| rate_per_s | 0.0 |
| seed | 11 |
| total_alerts | 300 |

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
| workers | 4 |

## Outcome

| measure | value |
|---|---|
| submissions | 300 |
| jobs created | 300 |
| duplicates recognised | 0 |
| succeeded | 300 |
| failed | 0 |
| timed out | 0 |
| unfinished at drain timeout | 0 |
| retried jobs | 0 |
| requests not accepted | 0 |
| HTTP statuses | {"202": 300} |

## Throughput

| measure | value |
|---|---|
| accepted per second | 454.327 |
| completed per second | 30.923 |
| makespan (s) | 9.702 |
| submit window (s) | 0.660 |
| max jobs in flight observed | 283 |

## Latency

| metric | unit | n | min | mean | p50 | p90 | p95 | p99 | max | low-sample percentiles |
|---|---|---|---|---|---|---|---|---|---|---|
| api_submit_ms | ms | 300 | 0.2150 | 27.1896 | 29.0330 | 54.8600 | 68.9030 | 79.8310 | 91.6560 | - |
| queue_wait_s | seconds | 300 | 0.0059 | 4.5147 | 4.4558 | 8.1736 | 8.6500 | 8.9649 | 9.0186 | - |
| processing_s | seconds | 300 | 0.0426 | 0.1269 | 0.1219 | 0.1866 | 0.2027 | 0.2156 | 0.2351 | - |
| end_to_end_s | seconds | 300 | 0.1482 | 4.6416 | 4.5547 | 8.3098 | 8.7592 | 9.0476 | 9.0840 | - |
| client_lag_s | seconds | 300 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | - |

## Time per graph node (seconds per job)

| node | mean | p95 | calls per job |
|---|---|---|---|
| c2_beacon_analyst | 0.010310 | 0.031474 | 1.00 |
| enrichment_agent | 0.004214 | 0.011130 | 1.00 |
| supervisor | 0.000097 | 0.000134 | 4.75 |
| traffic_analyst | 0.037546 | 0.100232 | 1.00 |
| verdict_node | 0.056828 | 0.078611 | 1.00 |

## Verdict and routing outcomes (succeeded jobs)

Verdict status: `{"ok": 300}`. Routing decision: `{"escalate": 300}`. With a fake model these are plumbing results, not detection quality.

## Errors

By error code: `{}`. Non-success HTTP: `{}`.

## Model usage and cost

Model calls: 300. Tokens: unavailable (a fake model reports no token counts). Cost: unavailable (unavailable: cost needs real token counts and a priced, sourced pricing file; a fake model has neither).

## How to read this

- Percentiles are nearest-rank; a percentile with too few samples is listed in low_sample and equals (or nearly equals) the maximum.
- The model is a FAKE with a SIMULATED delay. These numbers describe this software's own overhead plus that delay. They say nothing about Gemini's real latency, quota or cost.
- No token counts and no cost are reported: a fake model has none, and nothing was estimated.
- In-process mode calls the API handlers directly (no HTTP, no network, no database) and runs the workers as threads of one Python process, so it cannot show true parallel speed-up of CPU work.
- Results are for one machine and one run; repeat it (different seeds) before drawing conclusions, and never compare runs made with different settings.
