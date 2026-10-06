# Week 2, Day 3 hand-off: baseline prompt v1 and the dev runner

Blueprint Day 3: baseline prompt v1, one plain call per alert, no tools, no memory. Output: baseline runner and dev outputs.

## Status

- Implemented and tested with mocked and canned model replies: **59 new tests, all pass**. The Day 1 (18) and Day 2 (45) tests are untouched.
- **The real Gemini DEV run has not been done.** I have no API key and no access to your real dev files. Run it yourself with the commands below, after inspecting the package.
- Also run once, outside the unit tests: the whole runner end to end on a synthetic copy of the project (300 synthetic dev alerts, real loader, real manifest check, real `GeminiClient` code, a scripted fake in place of the Google SDK, with transient errors, empty replies, prose replies and fenced replies mixed in). It finished complete, and a hash of every file outside `runs/` was identical before and after.

No Day 4 work: nothing here scores a verdict against labels. No tools, memory, retrieval, LangGraph, LangSmith or orchestration. The frozen set, the labels and the MITRE answer key are not reachable from the new code.

## Files (all new paths, nothing is overwritten)

| path | role |
|---|---|
| `src/baseline_prompt.py` | prompt v1 (system prompt, user template, allowed-field check, SHA256 fingerprint) |
| `src/gemini_client.py` | the only file that touches the Google SDK; one `generate(prompt)` call, errors sorted into transient and permanent |
| `src/baseline_store.py` | append-only JSONL files, resume helpers, `verdicts.csv` |
| `src/run_baseline_dev.py` | the runner (CLI) |
| `tests/test_week2_day3.py` | 59 tests, no network, no key |
| `WEEK2_DAY3_HANDOFF.md` | this file |

Day 1 and Day 2 files are used as they are: `triage_inputs.py` builds the model input, `verdict_parser.parse_with_retries` does parsing and retries, `Verdict` has the five fields, `llm_config` gives the model ids and settings.

## Commands

From the repo root, venv active:

```
unzip week2-day3-files.zip
python -m unittest tests.test_week2_day3 -v
python -m unittest tests.test_week2_day1 tests.test_week2_day2 tests.test_week2_day3
```

Expected: 59 Day 3 tests OK, and 122 in total (18 + 45 + 59).

Check the prompt and every alert's input without any model call (needs no key, writes nothing):

```
python src/run_baseline_dev.py --dry-run
```

Real run, in this order. Put `GEMINI_API_KEY` in `.env` first (not in chat), and check `python src/llm_config.py` shows the key present and the two Gemini model ids.

```
python src/run_baseline_dev.py --limit 3 --run-name smoke_3
python src/run_baseline_dev.py --run-name dev_flash_lite_v1
```

- The first is a 3-alert smoke test in its own run folder. Read its `raw_responses.jsonl` before the full run. It is never merged into the full run.
- The second is the real DEV run: 300 dev alerts, the small model (`--model small` is the default), 10 calls per minute. At that rate expect roughly 30 to 40 minutes.
- If your Gemini quota allows more, raise `--rpm` (for example `--rpm 60`). Retries count as calls.

If a run stops (quota, network, Ctrl+C, a closed laptop), nothing finished is lost:

```
python src/run_baseline_dev.py --resume --run-name dev_flash_lite_v1
python src/run_baseline_dev.py --resume --run-name dev_flash_lite_v1 --retry-model-errors
```

The second form also runs again the alerts that ended in `model_error`. Alerts that ended in `parse_failed` are final and are never run again, because that is a model result Day 4 has to count.

## What a run does

1. Refuses to start if `SOC_FROZEN_UNLOCK` is set, if `llm_config` is not a Gemini setup (it checks `PROVIDER` if present and that both model ids start with `gemini`), or if `eval/dev_alerts.parquet` or `eval/flow_store_dev.parquet` do not match `eval/MANIFEST.json`.
2. Builds the prompt for all 300 alerts first. Any alert with a field outside the allowed list, or a missing or infinite number, stops the run before the first model call.
3. For each dev alert, in file order: one call; the reply goes through `parse_with_retries` (at most `llm_config.MAX_RETRIES` = 2 retries, so at most 3 calls, each retry showing the model its own bad reply and the problem).
4. Network and quota errors (HTTP 408, 429, 5xx, timeouts) are retried up to 4 times with waits of 4, 8, 16 and 32 seconds. If they never clear, the alert is recorded as `model_error` with no verdict. Five `model_error` alerts in a row stop the run. Errors that will not clear by repeating (bad key, bad model name, other 4xx, anything unrecognised) stop the run at once, and that alert is not recorded, so a resume does it again.
5. At the end it checks that the frozen access log has the same number of lines and that the dev files, manifest, threshold, model and feature list have the same SHA256 as at the start. If not, it prints a warning and exits with code 3.

Exit codes: 0 normal end, 2 stopped early, 3 a Week 1 file or the frozen access log changed, 130 interrupted.

## Prompt v1

`PROMPT_VERSION = "baseline_v1"`. The full text is in `src/baseline_prompt.py`, and each run saves it in `prompt_snapshot.txt` with its SHA256.

- The system prompt says what the task is, that alerts include real attacks and false alarms, that there are no tools or other data, what each field means (units, directions, what the detector score is, what the context counts are), and the exact five-field JSON format with the allowed values. The class list in it is read from `verdict_schema`, so it cannot drift from the parser.
- The user prompt is the alert and context JSON from `triage_inputs.build_model_input`, and nothing else.
- Not in the prompt: labels, the MITRE answer key, a class-to-technique table, example answers, the false-positive share of the dev set, class descriptions. The only technique ids written in it are the format example T1059 and T1059.001, which belong to no class in the answer key.
- The model sees the same things Day 1 decided: the alert fields (including `detector_score`, IPs, ports, timestamp and `flow_id`), the 12 display features, and the four context counts. The fields are an explicit allowlist in `baseline_prompt.ALERT_FIELDS`, so a new column in the alert file stops the run instead of being sent silently.
- A test pins the prompt's SHA256. Editing the prompt text fails that test on purpose: baseline v1 is not to be tuned. A new prompt is a new version.

Call settings, shared by every run: temperature 0.0, `max_output_tokens` from `llm_config`, seed 42, plain text reply (no JSON mode, no response schema), system prompt sent as the system instruction. Temperature 0 with a seed is not a guarantee of identical replies, which is one reason raw replies are saved.

## What is saved

A run folder `runs/week2_baseline_v1/<run-name>/` holds:

| file | content |
|---|---|
| `results.jsonl` | one line per alert (more only after `--retry-model-errors`; the last line for an alert wins) |
| `raw_responses.jsonl` | one line per model call, written the moment the call returns |
| `verdicts.csv` | one row per alert: the five fields, status, attempts, first-try flag, error code; blank fields for failures |
| `run_meta.json` | run settings, prompt SHA256, model id, input file hashes, git commit, package versions, sessions, counts, integrity checks |
| `prompt_snapshot.txt` | the system prompt and the user prompt of the first alert |

`results.jsonl` fields: `alert_id`; `status` (`ok`, `parse_failed` or `model_error`); `verdict` (the five fields, or null); `error_code` and `error_detail` (the Day 2 code of the last failed parse, or `model_unavailable`); `attempts` (replies received); `malformed_first_try`; `attempt_log` (per attempt: error code, detail, local repairs); `repairs`; `model_calls`; token totals (`prompt_tokens`, `output_tokens`, `thinking_tokens`, `total_tokens`, null if the API gave none); `latency_seconds`; `finish_reasons`; `prompt_sha256`; `session`; `finished_utc`.

`raw_responses.jsonl` fields: `alert_id`, `call_index`, `session`, `model`, `outcome` (`reply`, `transport_failed` or `permanent_error`), the full `prompt` sent, the full `reply` text exactly as returned (null if none), `finish_reason`, `block_reason`, token counts, `latency_seconds`, `transport_errors` (status and message of each failed try), `timestamp_utc`.

Failures never get a made-up verdict: `verdict` is null and the `verdicts.csv` cells are empty. Local repairs are the Day 2 ones only (code fence, text around the object, trailing comma) and are recorded. Raw text is never edited. The API key is never written anywhere (error messages are scrubbed of it too).

The run prints only operational counts (how many ok, parse_failed, model_error, how many replies needed a retry, calls, tokens). It does not compute accuracy or any other evaluation metric.

## Things to confirm or watch

1. **Day 1 Gemini config.** The Day 1 zip I was given still has the Anthropic version of `llm_config.py`, not the Gemini one you described, so I could not read it. The runner uses only names that file already had and Day 2 relies on: `models()` (keys `small` and `strong`), `get_api_key()`, `TEMPERATURE`, `MAX_OUTPUT_TOKENS`, `MAX_RETRIES`, and optionally `REQUEST_TIMEOUT_SECONDS` (default 60) and `PROVIDER`. If your Gemini version renamed any of them, the runner stops at the start and says which. In my sandbox I tested against a stand-in `llm_config.py` written to your description, which is not part of this package.
2. **Free-tier limits.** `--rpm 10` is a cautious default. If you hit daily quota, the run stops after five `model_error` alerts in a row and can be resumed later.
3. **Plain call, no JSON mode.** More malformed replies are possible than with a schema-constrained mode. That is what the Day 2 parser, the retries and the `malformed_first_try` count are for. It is the baseline, so I left it plain.
4. **The strong model** (`--model strong`) may count internal thinking tokens against `max_output_tokens`, which can cut replies short. Day 3 is the small model.
5. **Raw output is committed or not**, your call: a 300-alert run is roughly 1 to 2 MB. Nothing in this package changes `.gitignore`. The run folders contain no key.
6. The prompt shows IPs, ports and timestamps, as decided on Day 1. The IP and time masked ablation and the score-masked ablation come later.

## Checks done before hand-off

- Only dev data: the runner loads alerts and flows only through `triage_inputs.load_dev_alerts` and `load_dev_flow_store`; no module of this package imports `eval_io`, `eval_labels`, or any label, answer-key or frozen path name (AST test); no `"frozen"` string and no unlock value in any of them; the runner refuses to start with the unlock variable set.
- Frozen set not accessed: in the end-to-end run the frozen access log had the same line count before and after, and the run records that in `run_meta.json`.
- Nothing label-bearing reaches Gemini: allowlist check on every model input; tests send forbidden columns through it and they are refused; user prompts contain no class name, no label word and no MITRE field; the same check passes on all 300 prompts built from the synthetic dev set.
- Week 1 artifacts untouched: a SHA256 of every file in the test project outside `runs/` was identical before and after a full run; the runner also checks its own inputs (dev alerts, dev flow store, manifest, threshold, model, feature list) at the start and the end of each run.
- No other SDK: AST tests show no `anthropic`, `openai`, `langsmith`, `langchain`, `langgraph` or `chromadb` import, and no plain HTTP client, in any new module; the only SDK import is `google.genai`, inside one function in `gemini_client.py`; a test also reads `requirements-week2.txt` and fails if it lists `anthropic` or `openai`.

## Next step (not started)

Week 2 Day 4: the evaluation harness (verdict and MITRE accuracy against the dev labels, malformed rate, cost), run on the Day 3 dev outputs.
