# Week 5 - Load testing with a fake model (Day 2)

## What this measures, and what it does not
It measures **this software's own behaviour under load**: how fast the API accepts alerts, how long a job waits in the queue, how long the worker takes per job, how retries, duplicates, rate limits and failures show up. The model is **always a fake** with an optional simulated delay. The tool has no option to call a live model: that would spend money and quota and needs your explicit decision.

It does **not** measure Gemini latency, Gemini quota, token use or cost. **No token count and no cost is ever reported for a fake model**; nothing is estimated. `validate` rejects a results file that carries invented tokens or cost.

## Two modes
| Mode | What runs | Use it for |
|---|---|---|
| `inprocess` (default) | the real API handlers (`Api5`), job store, dispatcher, worker, graph runner and policy, in one Python process; workers are threads; the store is in memory | repeatable software-overhead numbers, no network or database needed |
| `http` | an HTTP client against a running API (`--base-url`) | the deployed stack: the real web layer, database and queue. Needs a bearer token in an environment variable |

In-process mode cannot show true parallel speed-up of CPU work (one interpreter) and has no database or network cost. HTTP mode against the Docker stack is the realistic one, and it **has not been run** (no Docker daemon in the sandbox); only an HTTP client against a stdlib test double of the web layer was exercised.

## Load shapes
- **Closed loop** (`--rate 0`, default): `--concurrency` client threads each submit as fast as the API answers. Throughput is limited by the system.
- **Open loop** (`--rate N`): alerts arrive at N per second regardless of how the system copes (the realistic overload test). `client_lag_s` records how late the client itself was, so a slow client is visible and not blamed on the server.
- `--duplicates F` resubmits a fraction of alerts with the same content (tests idempotency: they must be recognised, not double-processed).
- `--failure-mix unavailable=0.1,malformed=0.05,permanent=0.05` scripts the fake model to fail for that share of alerts (retries, fail-closed cases, permanent refusals); duplicates are left out of the queue and processing figures.
- `--api-rate-limit N` turns on the per-user limiter (requests per minute) so 429s appear.
- `--workers`, `--model-delay`, `--jitter`, `--max-attempts`, `--seed` (same seed, same alerts and same scripted failures).

## Metrics and how they are defined
| Metric | Definition |
|---|---|
| `api_submit_ms` | wall time of the submit call as the client saw it |
| `queue_wait_s` | first start minus enqueue time: from the job being stored to a worker starting its first attempt (includes the workers' poll delay; waiting between a failed attempt and its retry is not included) |
| `processing_s` | finish minus start of the final attempt: graph, model and case storage |
| `end_to_end_s` | finish minus enqueue: everything, including retries and their back-off |
| `client_lag_s` | how late an open-loop client sent each request versus its schedule |
| accepted/s, completed/s, makespan, max in flight | throughput and backlog |
| outcomes | succeeded, failed, timed out, unfinished at the drain timeout (counted, never hidden), retried jobs, HTTP statuses |

Percentiles are **nearest-rank**: always a value that was actually observed. With fewer than 100 samples p99 is the maximum; the table lists such percentiles under `low_sample` so it never looks more precise than it is. Per-node timings (traffic, beacon, enrichment, verdict, supervisor) are reported per job.

## Commands (Windows PowerShell, from the repository root, one at a time)
```powershell
$env:PYTHONPATH = "src;."
python -m week5.loadtest run --mode inprocess --total 300 --concurrency 16 --workers 4 --model-delay 0.05 --jitter 0.02 --out-dir runs_tmp\loadtest_a
python -m week5.loadtest run --mode inprocess --total 200 --rate 40 --workers 2 --out-dir runs_tmp\loadtest_overload
python -m week5.loadtest run --mode inprocess --total 200 --workers 3 --duplicates 0.1 --failure-mix unavailable=0.1,malformed=0.05,permanent=0.05 --out-dir runs_tmp\loadtest_failures
python -m week5.loadtest report --results runs_tmp\loadtest_a\results.json
```
Outputs per run: `results.json` (everything, machine-readable), `jobs.csv` (one row per job), `summary.csv` (one row per metric) and `report.md`. Use a scratch folder outside `runs/` (which holds Week 4 evidence). Against the Docker stack:
```powershell
$env:WEEK5_LOADTEST_TOKEN = "<a token you made with python -m week4.api.auth new-token --analyst alice>"
python -m week5.loadtest run --mode http --base-url http://127.0.0.1:8000 --total 100 --concurrency 4 --out-dir runs_tmp\loadtest_http
```
The token is read from the environment, never from the command line. A non-loopback `--base-url` is refused unless you add `--allow-remote`.

## Saved sample runs (`docs/loadtest/sample_runs/`, produced in the sandbox with the fake model)
| Run | Shape | Result worth noting |
|---|---|---|
| `closed_loop_4w` | 300 alerts, 16 clients, 4 workers, 50 ms simulated model | 300 of 300 succeeded; about 31 jobs/s completed; mean queue wait 4.5 s versus mean processing 0.13 s: the queue, not the processing, dominates when clients outrun workers |
| `open_loop_overload_2w` | 200 alerts at 40/s, 2 workers | accepted at 40.2/s, completed at 24.1/s; backlog peaked at 78 jobs; queue wait mean 1.6 s: the API kept accepting while the workers fell behind, as designed |
| `failure_mix_3w` | 200 alerts + 20 duplicates, 3 workers, scripted failures | 20 duplicates recognised (HTTP 200); 14 retried jobs; 191 succeeded, 9 failed; no job left unfinished |

These are numbers for one two-CPU sandbox, one run each, with a **simulated** delay. Do not quote them as performance claims; repeat on your machine with several seeds first.

## Reading a report honestly
- A big gap between `queue_wait_s` and `processing_s` means the system is **worker-bound**: add workers or reduce model time, not API capacity.
- `requests not accepted` (429 queue full, 429 rate limit, 503) are the system protecting itself; they are not failures of the test.
- `unfinished at drain timeout` greater than zero means the backlog had not drained; the other numbers describe only the finished jobs.
- Compare runs only when every parameter except the one you changed is the same.

## Tests
`python -m unittest tests.test_week5_loadtest` (29 tests: percentile maths against hand values, the no-fake-tokens rule, result consistency, latency parts adding up, deterministic workloads, the HTTP client against a local stdlib test double, CLI refusals).
