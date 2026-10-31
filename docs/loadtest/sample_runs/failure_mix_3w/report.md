# Load test report

Run: 2026-10-16T20:26:04Z to 2026-10-16T20:26:13Z, mode `inprocess`, model `FAKE:canned` (FAKE).
Machine: Python 3.13.16, 2 CPU(s). Week 5 version week5-v1.

## Parameters

| parameter | value |
|---|---|
| client_threads | 8 |
| drain_timeout_s | 120.0 |
| duplicate_fraction | 0.1 |
| label | "failure_mix_3w (sandbox, fake model)" |
| pattern | "closed loop" |
| rate_per_s | 0.0 |
| seed | 13 |
| total_alerts | 200 |

## Backend

| setting | value |
|---|---|
| api_rate_limit_per_minute | 0 |
| engine | "instrumented" |
| failure_mix | "unavailable=0.1,malformed=0.05,permanent=0.05" |
| job_timeout_s | 30.0 |
| max_attempts | 3 |
| model | "FAKE:canned (simulated latency)" |
| queue | "in-memory job store polled by worker threads" |
| retry_backoff_s | [0.05, 0.1, 0.2] |
| simulated_model_delay_s | 0.03 |
| simulated_model_jitter_s | 0.0 |
| worker_poll_s | 0.005 |
| workers | 3 |

## Outcome

| measure | value |
|---|---|
| submissions | 220 |
| jobs created | 200 |
| duplicates recognised | 20 |
| succeeded | 191 |
| failed | 9 |
| timed out | 0 |
| unfinished at drain timeout | 0 |
| retried jobs | 14 |
| requests not accepted | 0 |
| HTTP statuses | {"200": 20, "202": 200} |

## Throughput

| measure | value |
|---|---|
| accepted per second | 1700.168 |
| completed per second | 22.244 |
| makespan (s) | 8.587 |
| submit window (s) | 0.129 |
| max jobs in flight observed | 200 |

## Latency

| metric | unit | n | min | mean | p50 | p90 | p95 | p99 | max | low-sample percentiles |
|---|---|---|---|---|---|---|---|---|---|---|
| api_submit_ms | ms | 220 | 0.1030 | 0.1722 | 0.1570 | 0.2320 | 0.2860 | 0.3680 | 0.4610 | - |
| queue_wait_s | seconds | 200 | 0.0387 | 3.3750 | 3.3753 | 6.1107 | 6.3844 | 6.5894 | 6.6839 | - |
| processing_s | seconds | 191 | 0.0386 | 0.0966 | 0.0873 | 0.1628 | 0.1854 | 0.2311 | 0.2733 | - |
| end_to_end_s | seconds | 191 | 0.1483 | 3.8274 | 3.8274 | 6.5896 | 8.0107 | 8.4595 | 8.5506 | - |
| client_lag_s | seconds | 220 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | - |

## Time per graph node (seconds per job)

| node | mean | p95 | calls per job |
|---|---|---|---|
| c2_beacon_analyst | 0.008312 | 0.018854 | 1.00 |
| enrichment_agent | 0.003755 | 0.007997 | 1.00 |
| supervisor | 0.000101 | 0.000142 | 4.74 |
| traffic_analyst | 0.024365 | 0.073657 | 1.00 |
| verdict_node | 0.050365 | 0.155939 | 1.00 |

## Verdict and routing outcomes (succeeded jobs)

Verdict status: `{"model_error": 14, "ok": 168, "parse_failed": 9}`. Routing decision: `{"escalate": 168, "needs_review": 23}`. With a fake model these are plumbing results, not detection quality.

## Errors

By error code: `{"model_rejected": 9}`. Non-success HTTP: `{}`.

## Model usage and cost

Model calls: 209. Tokens: unavailable (a fake model reports no token counts). Cost: unavailable (unavailable: cost needs real token counts and a priced, sourced pricing file; a fake model has neither).

## How to read this

- Percentiles are nearest-rank; a percentile with too few samples is listed in low_sample and equals (or nearly equals) the maximum.
- The model is a FAKE with a SIMULATED delay. These numbers describe this software's own overhead plus that delay. They say nothing about Gemini's real latency, quota or cost.
- No token counts and no cost are reported: a fake model has none, and nothing was estimated.
- In-process mode calls the API handlers directly (no HTTP, no network, no database) and runs the workers as threads of one Python process, so it cannot show true parallel speed-up of CPU work.
- Results are for one machine and one run; repeat it (different seeds) before drawing conclusions, and never compare runs made with different settings.
