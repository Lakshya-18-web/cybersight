# Week 2, Day 2 hand-off

Blueprint Day 2: define the verdict format (is_malicious, attack type, MITRE technique, severity, evidence), then parsing, validation, and retries. Output: verdict schema, parser with tests.

## What was done

- `src/verdict_schema.py`: the `Verdict` model with exactly the five blueprint fields.
- `src/verdict_parser.py`: `parse_verdict(text)` turns raw model text into a `Verdict` or one named error; `parse_with_retries(call_model, prompt)` asks again with feedback when the reply is malformed.
- `tests/test_week2_day2.py`: 45 tests on canned reply strings.

No Gemini or other API call, no baseline runner, no prompt v1, no LangSmith, no evaluation harness. The frozen set and all label files were not opened. No Week 1 file and none of the Day 1 files were changed, so the Day 1 checkpoint stays as it is.

## Files in this package

| path | role |
|---|---|
| `src/verdict_schema.py` | Pydantic model `Verdict`, allowed values, consistency rules |
| `src/verdict_parser.py` | extraction, validation, error codes, retry loop, repair message |
| `tests/test_week2_day2.py` | 45 tests, canned strings only |
| `WEEK2_DAY2_HANDOFF.md` | this file |

Extract at the repo root. All four paths are new; nothing is overwritten. No `.env`, keys, data, labels or evaluation files are included.

## The format

| field | allowed |
|---|---|
| `is_malicious` | a JSON `true` or `false` (the text "true" or 1 is rejected) |
| `attack_type` | `BENIGN` or one of the 11 Week 1 classes (same list as `triage_schema.py`; Infiltration, Heartbleed and the unmerged XSS/SQL names are rejected; matching is exact, case included) |
| `mitre_technique` | `T` + 4 digits, optionally `.` + 3 digits; `NONE` for benign. Format only |
| `severity` | `none`, `low`, `medium`, `high`, `critical` |
| `evidence` | required, 1 to 600 characters after trimming |

Extra keys are rejected. Contradictions are rejected: malicious with BENIGN (or the reverse), BENIGN with a technique or a severity, an attack class with technique NONE or severity none.

## Validation and repair behaviour

Error codes (one per failure, for the Day 4 malformed-rate count): `empty_response`, `no_json`, `invalid_json`, `multiple_json_objects`, `not_an_object`, `missing_fields`, `extra_fields`, `invalid_field`, `contradictory`.

Local repair is formatting only, and is recorded in `repairs`: a markdown code fence is removed, text around the JSON object is ignored, trailing commas are removed. No value is ever corrected, no field renamed, no missing field filled in. Duplicate keys, two JSON objects, and a JSON list are rejected.

Retry: after a failure the model gets the original prompt, the problem with its error code, its own previous reply (cut at 1,500 characters) and a restatement of the format. Up to `llm_config.MAX_RETRIES` (2) retries, so at most 3 calls. `RetryOutcome` has `attempts`, a per-attempt `attempt_log`, `malformed_first_try` and `malformed_final`, which the Day 4 harness will use. Errors from the model call itself (network, quota) are not caught; the Day 3 runner handles those.

## Validation performed

`python -m unittest tests.test_week2_day2 tests.test_week2_day1 -v`: 45 Day 2 tests and the 18 Day 1 tests pass, also with unclosed-file warnings turned into errors. Day 2 covers valid JSON (malicious and benign, all 12 classes, all severities), fenced and prose-wrapped replies, trailing comma, malformed and truncated JSON, empty replies, missing fields (each of the five), invalid attack type, MITRE id, severity, boolean and evidence, six contradictions, extra fields, duplicate keys, lists, two objects, and the retry cases (first-try success, repair after each kind of failure, two failures then success, giving up, zero retries, errors passing through). Source checks show the modules reference no labels, answer key, evaluation loader, frozen path or model SDK.

Not done: any real model reply has not been parsed. Real Gemini output may fail in ways the canned strings do not cover (for example a reply wrapped in extra text, or JSON in a mode the SDK adds). Day 3's first dev run is the real test, and the error codes will show what happens.

## Things to know

- `triage_schema.py` (Day 1, seven fields including `alert_id`, `confidence`, `reasoning`, `recommended_action`) is still in the repo. The Day 2 `Verdict` follows the blueprint and is the format the baseline and harness will use. The two are not linked in code; they only share the class list, which a test checks. Say if you want `triage_schema.py` retired later.
- Severity has an extra value, `none`, for benign alerts. The blueprint names the field but not its values.
- The technique id is checked for format only. Whether it is the right technique for the class is scored on Day 4 against the answer key.

## Exact next step (not started)

Week 2 Day 3: write baseline prompt v1 (one plain call per alert, no tools, no memory), the baseline runner that builds the model input with `triage_inputs.py`, calls the small Gemini model through `parse_with_retries`, throttles for rate limits, and saves raw replies and parsed verdicts for the 300 dev alerts. This needs the first real API calls, so I will wait for your instruction and for `GEMINI_API_KEY` to be in your `.env`.
