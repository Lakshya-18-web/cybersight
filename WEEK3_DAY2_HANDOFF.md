# Week 3 Day 2 handoff: tool tests and schemas

Scope: unit tests and declarations for the nine Day 1 tools. No LangGraph, supervisor, specialist, graph state, verdict node, evaluation, ablation, report, commit or tag. No LLM or network call anywhere (urllib is patched to fail in the tests). Week 1 and Week 2 files, the frozen set and `eval/` are untouched.

## Files created
| File | Purpose |
|---|---|
| `tests/test_week3_day2_schemas.py` | 58 tests: registry, declarations, pinned golden schema per tool, determinism (also across PYTHONHASHSEED values), required args, wrong types, boundaries, unknown args, malformed calls, schema/validator agreement |
| `tests/test_week3_day2_tools.py` | 97 tests: every tool for valid, invalid, missing, wrong-type, empty, boundary, deterministic, error, reputation-disabled and fake-fetch cases, plus regression tests for the fixes below |
| `WEEK3_DAY2_HANDOFF.md` | this note |

## Files modified (Day 1 code; behaviour fixes are minimal and each has a regression test)
| File | Change | Why |
|---|---|---|
| `src/tools/base.py` | `clean_arguments` sorts unknown names with `key=str` | `{1: 2, "a": 3}` raised `TypeError` out of `run()`, breaking "tools never raise" |
| `src/tools/base.py` | `plain()` returns None for NaT | a missing timestamp could not be formatted |
| `src/tools/base.py` | `ToolSpec.run` serialises (`plain`) inside the try block | serialisation failures escaped as exceptions; now `internal_error` |
| `src/tools/mitre_lookup.py` | technique id regex uses `[0-9]` | Unicode digits were accepted and gave a misleading `not_found`; now `invalid_input` |
| `src/tools/mitre_lookup.py` | `mitre_search` matches whole ids (`T1595.001`) | the tokenizer split the id, so a sub-technique could never rank first by its own id (its parent did) |
| `src/tools/flow_query.py` | description text only | states "do not combine `around` with `start`/`end`", "at least one filter is required", "`window_minutes` ignored without `around`" |

## Commands (run one at a time, from the repo root)
1. `python -W error::ResourceWarning -m unittest tests.test_week3_day2_schemas`  (expect 58 OK)
2. `python -W error::ResourceWarning -m unittest tests.test_week3_day2_tools`  (expect 97 OK)
3. `python -W error::ResourceWarning -m unittest tests.test_week3_day1`  (expect 113 OK)
4. Full suite: `python -m unittest tests.test_week2_day1 tests.test_week2_day2 tests.test_week2_day3 tests.test_week2_day4 tests.test_week2_day5 tests.test_week2_day6 tests.test_week2_day7 tests.test_week3_day1 tests.test_week3_day2_schemas tests.test_week3_day2_tools`
5. `python src/week2_report.py verify`
6. `git status --short`  (expect only the 3 modified `src/tools` files and 3 new files; nothing under Week 1/2 or `eval/`)

Sandbox result (synthetic data, shimmed xgboost/pyarrow): Day 2 = 155 tests OK; Week 2 (Days 1,2,3,5,6,7) + Day 1 + Day 2 = 612 OK (5 skipped). Not yet run in the real repo.

Commit is left to you (none was made): `git add src/tools tests/test_week3_day2_schemas.py tests/test_week3_day2_tools.py WEEK3_DAY2_HANDOFF.md`

## Remaining concerns for Day 3
- Declarations use `additionalProperties`, `maxLength` and `default`. Some tool-calling APIs (Gemini's schema subset, for example) reject these. Day 3 may need a thin adapter that strips them; a test pins the keyword set so the adapter has a fixed target.
- IPv6 zone ids (`fe80::1%eth0`) are accepted as given and not pinned by any test.
- The sandbox ran `tests.test_week2_day4` with 2 failures in report-formatting tests unrelated to tools (it was not part of earlier sandbox runs; the real repo is the authority). Please confirm it passes in your repo in command 4.
