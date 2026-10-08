# Week 3 Day 1 handoff: the tool layer

Scope: the `tools/` package only. No LangGraph, supervisor, specialists, graph state, verdict node, Week 3 evaluation, ablation, report or tag. No LLM call anywhere in the tools. Nothing from Week 1 or Week 2 is changed, and the frozen set is not opened.

## Files (all new)

| File | Purpose |
|---|---|
| `src/tools/__init__.py` | package exports |
| `src/tools/base.py` | argument validation, result envelope, `ToolSpec` (JSON-Schema declaration + `run`) |
| `src/tools/reference_data.py` | curated IANA port/service table |
| `src/tools/mitre_reference.py` | curated ATT&CK subset (49 techniques), separate from the evaluation answer key |
| `src/tools/flow_query.py` | `FlowStore` + tools `query_flows`, `summarize_flows`, `beacon_stats` |
| `src/tools/enrichment.py` | tools `ip_info`, `port_info`, `service_lookup` |
| `src/tools/reputation.py` | optional tool `reputation_lookup` (off by default, cached, timeout, call budget) |
| `src/tools/mitre_lookup.py` | tools `mitre_lookup`, `mitre_search` |
| `src/tools/registry.py` | `build_registry(...)`: lists, describes and calls tools by name |
| `tests/test_week3_day1.py` | 113 tests |
| `WEEK3_DAY1_HANDOFF.md` | this note |

## Contract (every tool)

Result: `{"ok": bool, "tool": str, "data": dict|None, "error": {"code","message"}|None}`. Codes: `invalid_input`, `not_found`, `unavailable`, `unknown_tool`, `internal_error`. Tools never raise to the caller. Unknown arguments are rejected, so a call cannot carry a path, a set name or an option.

| Tool | Needs | Returns (facts only, no verdict) |
|---|---|---|
| `query_flows` | at least one filter | matching flows (capped at 200), total matched, truncated flag |
| `summarize_flows` | `ip` | flow counts, distinct destinations/ports, protocol mix, top ports/IPs, feature statistics |
| `beacon_stats` | `src_ip`, `dst_ip` | gaps between flows (mean, median, std, cv, share within 10% of median), forward bytes, duration |
| `ip_info` | `ip` | address type and scope from the address range; flow-store sightings if a store is attached |
| `port_info` | `port` | IANA range and curated services |
| `service_lookup` | `name` | ports and description |
| `reputation_lookup` | `ip` | status `disabled` / `not_applicable` / `unavailable` / `ok` and score |
| `mitre_lookup` | `technique_id` | name, tactics, summary, flow observables, parent/sub-techniques |
| `mitre_search` | `query` | best-matching techniques |

Use from Day 3: `registry = build_registry(flow_store=FlowStore.from_dev())`, then `registry.declarations()` for the model and `registry.call(name, args)` for execution.

## Assumptions (the repo has no existing resource for these)

1. The package is `src/tools/` (not a top-level `tools/`), because every project script imports from `src/`.
2. The flow store is the existing dev store, loaded through `triage_inputs.load_dev_flow_store()` (dev only, label-free check reused). The tools take no argument that selects a set.
3. MITRE: `config.py` says the lookup tool must not use the answer key, so `mitre_reference.py` is a separate, hand-curated ATT&CK subset (ids, names, tactics, paraphrased summaries). It holds no class-to-technique mapping. I wrote it from my own knowledge of ATT&CK Enterprise; no network was used. Check the ids and names against attack.mitre.org before you rely on the table in the report.
4. Port and service tables are a curated IANA subset, not the full registry. A port not in the table is reported as unlisted, never guessed.
5. IP type is classified from address ranges only. No dataset-specific attacker or victim addresses are embedded, because the dataset card warns that models can recognise attacks from lab IPs.
6. Reputation provider: AbuseIPDB-style HTTPS API (fixed host, stdlib `urllib`, no new dependency). Enabled only if `SOC_REPUTATION_API_KEY` is set AND the caller builds the tool with `ReputationTool.from_env()`. `build_registry` leaves it off by default. I made no real reputation call and cannot confirm the live API response shape; the parser is tested against a mocked answer only. Caching is in memory (no files).
7. The feature columns are returned as stored in the flow store; I could not see whether they are scaled, so the tools say so in a note and do not interpret them.

## Commands (one at a time, from the repository root)

**1.** Copy the 11 files into the repository at the same relative paths, then:

```
python -m unittest tests.test_week3_day1 -v
```
Expect `Ran 113 tests ... OK`.

**2.** Regression, all earlier suites plus Day 1:

```
python -m unittest tests.test_week2_day1 tests.test_week2_day2 tests.test_week2_day3 tests.test_week2_day4 tests.test_week2_day5 tests.test_week2_day6 tests.test_week2_day7 tests.test_week3_day1
```
Expect `OK` (your earlier 407 tests plus 113 new ones).

**3.** Smoke test on the real dev flow store (reads the dev set only; no frozen access, no API call):

```
python -c "import sys; sys.path.insert(0,'src'); from tools import build_registry, FlowStore; r=build_registry(FlowStore.from_dev()); print(r.names()); print(r.call('ip_info', {'ip':'8.8.8.8'})); print(r.call('mitre_lookup', {'technique_id':'T1071.001'})['data']['name']); print(r.call('reputation_lookup', {'ip':'8.8.8.8'})['data']['status'])"
```
Expect nine tool names, `public`/`external` for 8.8.8.8, `Web Protocols`, and `disabled`.

**4.** Confirm the Week 2 lock still holds:

```
python src/week2_report.py verify
```
Expect all `PASS` (the frozen access log, Week 1 files, locked source files and runs are unchanged).

**5.** Check the working tree:

```
git status --short
```
Expect only new files: `src/tools/` (9 files), `tests/test_week3_day1.py`, `WEEK3_DAY1_HANDOFF.md`. `audit_day5_step1.py`, `diag.py` and `runs/` stay untracked and are not committed. Nothing modified.

**6.** Commit (only after 1 to 5 pass; no tag on Day 1):

```
git add src/tools tests/test_week3_day1.py WEEK3_DAY1_HANDOFF.md
git commit -m "week 3 day 1 tool layer" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>" -m "Claude-Session: https://claude.ai/code/session_012J2oPbKhbdQCkDtd13R2kx"
```

## Left for Day 2

Exhaustive per-tool tests against the real dev store, and finalising the written tool schemas. The schemas already exist (`registry.declarations()`), so Day 2 can refine them rather than start them.
