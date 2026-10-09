# Week 3 Day 3 handoff: graph v0 (LangGraph skeleton)

Scope: shared state, a deterministic supervisor, one traffic analyst, a small dev run. No LLM call, no reputation call, no labels, no frozen set. No C2 beaconing analyst, enrichment agent, multi-specialist routing, verdict node, metrics, ablation, report, commit or tag. No Day 1 or Day 2 code was changed (no defect was found).

## IMPORTANT: LangGraph was not verified in the build sandbox
The sandbox could not install LangGraph (package index blocked), so `src/agents/graph.py` has **not been run against the real package**. What was verified:
- state, supervisor and traffic analyst are plain functions and were fully tested without LangGraph;
- the graph wiring was exercised in the sandbox only through a stand-in module that mimics the small API surface used (`StateGraph`, `add_node`, `add_edge`, `add_conditional_edges`, `compile().invoke`). The stand-in is NOT shipped and is not evidence that real LangGraph accepts the wiring.
First action for you: install it and run the Day 3 tests; the 7 LangGraph-dependent tests only run once it is installed.

## Architecture
```
START -> supervisor --route--> traffic_analyst -> supervisor --route--> END
```
Supervisor (deterministic, no LLM): first visit routes to `traffic_analyst`; after the analyst it ends and sets the final status; a visit counter (`MAX_SUPERVISOR_VISITS = 4`) and LangGraph's `recursion_limit` stop any runaway; the analyst is never routed twice. Normal run = 2 supervisor visits + 1 analyst run.

Traffic analyst (deterministic, no LLM): calls `summarize_flows` twice through the registry, ±5 minutes around the alert time (the Week 2 context window): (0) the alert source as source, (1) the alert destination as destination. Findings are facts only (counts, distinct addresses/ports, top-port share, fan-in), each with the index of the evidence entry it came from. It names no attack, technique or verdict. Empty results become findings (`no_source_flows`, `no_destination_flows`); a failed call becomes an error entry and the other call is still reported; a node exception is contained (`node_exception`, type name only).

Final status: `completed` (all tool calls ok), `completed_with_errors` (some failed), `failed` (none ok, analyst left nothing, or loop guard).

## Shared state (`GraphState`, one alert)
| Field | Meaning |
|---|---|
| `alert_id`, `alert` | label-free alert record (built with the Week 2 `triage_inputs.build_model_input`; forbidden columns rejected) |
| `status` | pending, running, completed, completed_with_errors, failed |
| `next_node` | supervisor's last decision: traffic_analyst or end |
| `supervisor_visits` | loop-guard counter |
| `evidence` | one entry per tool call: index, tool, arguments, ok, error, data (only what the tool returned) |
| `traffic_findings` | analyst output: analyst, status, findings, tool_calls, tool_errors (None until it runs) |
| `errors` | node/tool failures: node, code, message[, tool] |
| `trace` | node names in run order |
| `graph_version` | "v0" |
Nodes return only changed keys and never mutate their input.

## Files
Created: `src/agents/__init__.py`, `src/agents/state.py`, `src/agents/supervisor.py`, `src/agents/traffic_analyst.py`, `src/agents/graph.py`, `src/run_graph_dev.py`, `requirements-week3.txt`, `tests/test_week3_day3.py` (52 tests), `WEEK3_DAY3_HANDOFF.md`.
Modified: none.
Imports follow the repo convention (top-level `import triage_inputs`, relative imports inside `agents`; scripts run as `python src/x.py`).

## Commands (one at a time, repo root)
1. Install (exact): `pip install -r requirements-week3.txt`  (contains `langgraph>=0.2`; then run `pip show langgraph` and tell me the version)
2. `python -W error::ResourceWarning -m unittest tests.test_week3_day3`  (expect 52 tests OK, 0 skipped)
3. Full suite: `python -m unittest tests.test_week2_day1 tests.test_week2_day2 tests.test_week2_day3 tests.test_week2_day4 tests.test_week2_day5 tests.test_week2_day6 tests.test_week2_day7 tests.test_week3_day1 tests.test_week3_day2_schemas tests.test_week3_day2_tools tests.test_week3_day3`  (expect 675 + 52 = 727, if your earlier 675 count was the same set)
4. `python src/week2_report.py verify`
5. Dev run (5 dev alerts, writes under untracked `runs/`): `python src/run_graph_dev.py --n 5 --out runs/week3_graph_v0/dev_smoke_5`
6. `git status --short` (expect only the new files above plus the known untracked `audit_day5_step1.py`, `diag.py`, `runs/`; nothing under `eval/`, nothing modified)

## Dev alerts used
`run_graph_dev.py` takes the first N dev alerts in `alert_id` order (default 5: DEV-0001 to DEV-0005). Maximum 20 on Day 3. Output: `results.jsonl` (full final state per alert) and `summary.json`. It refuses to overwrite an existing run.

## Sandbox results (what I actually ran)
- Day 3 tests, with the LangGraph stand-in: 52 OK. Without any langgraph: 52 run, 7 skipped, OK.
- Week 2 Days 1,2,3,5,6,7 + Week 3 Days 1-3 (sandbox): 664 OK, 5 skipped. Not run in the sandbox: Day 4 (2 unrelated sandbox-only failures reported on Day 2).
- Dev run on the sandbox's SYNTHETIC dev data (5 alerts, stand-in graph): all 5 `completed`, 10 tool calls, 0 errors. These findings are meaningless as results; only your real-repo run counts.
- Nothing was run in your real repository.

## Limitations / known issues
- Real LangGraph unverified (above). Possible issues to watch: TypedDict state handling, `recursion_limit` config key, version differences.
- Findings are descriptive only; interpreting them is the Day 4+ specialists' and Day 5 verdict node's job.
- Tool declarations still use `additionalProperties`/`maxLength`/`default`; irrelevant on Day 3 (no model calls tools yet) but Day 4+ with Gemini function-calling may need the adapter noted on Day 2.
- argparse prints usage text when the runner is given bad arguments (tests silence it).

## Confirmations
- No LLM, Gemini or reputation API calls: the agents package imports no network/LLM module (enforced by an AST test); the tests patch `urllib` to fail; the runner builds the registry with reputation off.
- Week 1 and Week 2 locked artifacts untouched: no existing file was modified; the frozen set was not opened (the runner and agents use only the dev loaders; tests assert this).
