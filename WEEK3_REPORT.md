# Week 3 report: agent system v1 (LangGraph supervisor, three specialists, verdict node), locked on the dev set

Generated 2026-10-12T20:29:14Z by `python src/week3_report.py build`. Every number below was read from the files listed in section 12; nothing was typed in by hand.
Git at lock time: branch `master`, commit `792d7bf498d06d38379fd1c60917ff43fc4198e7` (the commit before the Day 7 commit; the `week3-agents` tag goes on the Day 7 commit). All paths are relative to the repository root.

**Status:** all 29 lock checks passed when this report was built (section 13). The report is part of the lock: `python src/week3_report.py verify` fails if this file or anything it cites changes.

**What is, and is not, claimed.** Everything here is measured on the 300-alert DEV set, which was used while the agent was being built. No number in this report is an independent evaluation, the frozen evaluation set was not opened (section 11), every arm was run once, and nothing here says the agent is universally better than the baseline. The Day 6 ablation is descriptive.

## 1. What is locked

- **Agent system v1:** graph `v0.1` (supervisor, traffic analyst, C2 beaconing analyst, enrichment agent, verdict node) with verdict prompt `agent_v1` (sha256 `8df5e3fee15280d6b409e2a1fd1d01a505cfbe449421d9dafa1f8a30ee99f4c7`), model `gemini-3.5-flash-lite`.
- **Reference run:** Day 6 arm A (`runs/week3_day6/day6_arm_A`), the full graph run on the final code. The Day 5 run is kept as history (section 5), not as the reference.
- **Unchanged and checked:** the Week 2 baseline lock (`reports/week2_baseline_lock.json`), including the five hash-locked Week 2 source files, still verifies (section 11).

## 2. Architecture and data flow

One alert goes through a deterministic supervisor loop; no LLM decides the routing. Only the verdict node calls a model.

```
alert -> supervisor -> traffic_analyst -> supervisor -> [c2_beacon_analyst] -> supervisor -> enrichment_agent -> supervisor -> verdict_node -> supervisor -> end
```

- **State:** a typed dictionary (`alert`, `evidence`, one findings slot per agent, `routing` with a reason for every decision, `errors`, `trace`, `verdict`, `status`). Each agent returns an update and always goes back to the supervisor.
- **Supervisor** (`src/agents/supervisor.py`): re-derives its decision from the state at every visit. The traffic analyst runs first. The beaconing analyst runs only on repeat contact, i.e. at least 2 flows from the alert source to the alert destination in the traffic analyst's own evidence (a routing gate that saves work, not a detection threshold). Then the enrichment agent, then the verdict node. Every agent runs at most once. A loop guard ends the graph after 5 supervisor visits. If the graph ends before the verdict node ran, no verdict is invented.
- **Traffic analyst:** queries the flow store (local, offline) for the source and destination and summarises who the source talks to.
- **C2 beaconing analyst:** looks for regular intervals to one destination and port and may flag a `beacon_candidate`.
- **Enrichment agent:** adds IP-range, port and service context and, only when a `beacon_candidate` was flagged, a few MITRE ATT&CK reference entries (reference material, not a determination). The optional reputation lookup is never called in graph v0.1; its absence is recorded in the evidence as `not_consulted`.
- **Verdict node:** one model call per alert with the collected evidence and the `agent_v1` prompt; the reply must be the same five-field verdict as the Week 2 baseline (`is_malicious`, `attack_type`, `mitre_technique`, `severity`, `evidence`), validated by the locked Week 2 parser, with up to 2 parse retries. A reply that still fails validation is a final parse failure and is scored, not dropped.
- **Paths taken in arm A:** `traffic_analyst>c2_beacon_analyst>enrichment_agent>verdict_node` on 279 alerts; `traffic_analyst>enrichment_agent>verdict_node` on 21 alerts.

## 3. Configuration (from arm A's `run_meta.json`)

| setting | value |
|---|---|
| model | gemini-3.5-flash-lite |
| verdict prompt | agent_v1 `8df5e3fee15280d6b409e2a1fd1d01a505cfbe449421d9dafa1f8a30ee99f4c7` |
| graph version | v0.1 |
| specialists | traffic_analyst, c2_beacon_analyst, enrichment_agent |
| temperature | 0.0 |
| max_output_tokens | 1024 |
| seed | 42 |
| parse_retries | 2 |
| timeout_seconds | 60 |
| transport_retries | 4 |
| requests_per_minute | 10.0 |
| alerts | 300 |
| dev alerts sha256 | `7de717eddd6763f635e2365a1adcde07089462be7e3290747fee8b53e18b0e59` |
| dev flow store sha256 | `e3df785fe091e8817e23c4a83e293e7db5837b85cf653e8214bd3cc42aa63800` |
| python | 3.10.11 |
| packages | {"google-genai": "2.26.0", "pandas": "2.3.3", "pydantic": "2.13.5"} |
| git commit recorded by the run | {"commit": "ce619c4", "dirty": true} (the Day 6 code was committed after the runs; section 9, limitation 5) |

## 4. Primary result: agent arm A against the locked baseline (dev set, 300 alerts)

The primary view is `failures_wrong`: all 300 alerts count, and an alert with no valid verdict counts as wrong. Its denominator is the same for every run, so runs are comparable. `valid_only` drops alerts without a verdict, so its alert set differs between runs; read it with care. `failures_escalated` treats a missing verdict as 'escalated'.

Baseline = `dev_flash_lite_v3_final`, the locked Week 2 baseline_v3 run (one run; its three-run spread is in section 6). Agent = arm A, one run. Day 5 = the earlier agent run, history only.

| metric | baseline_v3 (locked) | agent arm A | A minus baseline | agent Day 5 (historical) |
|---|---|---|---|---|
| `failures_wrong` Precision | 89.0% (186/209) | 98.9% (180/182) | +9.9 pp | 98.9% (177/179) |
| `failures_wrong` Recall | 95.4% (186/195) | 92.3% (180/195) | -3.1 pp | 90.8% (177/195) |
| `failures_wrong` F1 | 0.9208 | 0.9549 | +0.0341 | 0.9465 |
| `failures_wrong` Specificity (benign dismissed) | 78.1% (82/105) | 98.1% (103/105) | +20.0 pp | 98.1% (103/105) |
| `failures_wrong` FP reduction | 78.1% | 98.1% | +20.0 pp | 98.1% |
| `failures_wrong` Attacks missed | 9 | 15 | +6 | 18 |
| `failures_escalated` Precision | 89.0% (187/210) | 98.9% (186/188) | +9.9 pp | 98.9% (185/187) |
| `failures_escalated` Recall | 95.9% (187/195) | 95.4% (186/195) | -0.5 pp | 94.9% (185/195) |
| `failures_escalated` F1 | 0.9235 | 0.9713 | +0.0478 | 0.9686 |
| `failures_escalated` Specificity (benign dismissed) | 78.1% (82/105) | 98.1% (103/105) | +20.0 pp | 98.1% (103/105) |
| `failures_escalated` FP reduction | 78.1% | 98.1% | +20.0 pp | 98.1% |
| `failures_escalated` Attacks missed | 8 | 9 | +1 | 10 |
| `valid_only` Precision | 89.9% (186/207) | 98.9% (180/182) | +9.0 pp | 98.9% (177/179) |
| `valid_only` Recall | 95.9% (186/194) | 95.2% (180/189) | -0.6 pp | 94.7% (177/187) |
| `valid_only` F1 | 0.9277 | 0.9704 | +0.0427 | 0.9672 |
| `valid_only` Specificity (benign dismissed) | 79.6% (82/103) | 98.1% (103/105) | +18.5 pp | 98.1% (103/105) |
| `valid_only` FP reduction | 79.6% | 98.1% | +18.5 pp | 98.1% |
| `valid_only` Attacks missed | 8 | 9 | +1 | 10 |
| Attack-type accuracy (all attacks, no verdict = wrong) | 36.4% (71/195) | 32.3% (63/195) | -4.1 pp | 31.3% (61/195) |
| Attack-type accuracy (attacks with a valid verdict) | 36.6% (71/194) | 33.3% (63/189) | -3.3 pp | 32.6% (61/187) |
| MITRE accepted (all attacks, no verdict = wrong) | 57.4% (112/195) | 50.3% (98/195) | -7.2 pp | 49.2% (96/195) |
| MITRE accepted (attacks with a valid verdict) | 57.7% (112/194) | 51.9% (98/189) | -5.9 pp | 51.3% (96/187) |
| Valid-verdict coverage | 99.0% (297/300) | 98.0% (294/300) | -1.0 pp | 97.3% (292/300) |
| Final parse failures (alerts) | 3 | 6 | +3 | 8 |
| First-try malformed (alerts) | 5 | 16 | +11 | 17 |
| Model errors (alerts) | 0 | 0 | 0 | 0 |
| Model calls | 309 | 326 | +17 | 329 |
| Total tokens | 673,476 | 1,082,001 | +408,525 | 1,090,933 |
| Tokens per alert (mean) | 2,244.9 | 3,606.7 | +1,361.8 | 3,636.4 |
| Tool calls | n/a | 2,287 | n/a | 2,287 |
| Graph seconds, all alerts (includes the request-rate wait) | n/a | 1957.17 | n/a | 1969.97 |
| Model latency per alert, mean (s) | 2.15 | 1.91 | -0.24 | 1.63 |

Cells show the value and, for ratios, numerator/denominator. The baseline has no tool calls (it uses none), so that row is n/a. The Wilson 95% intervals for every ratio are in each run's `evaluation.json`.

**Numbers that may be quoted (dev set, single run, with the denominators):** with failed verdicts counted as wrong, arm A has precision 98.9% (180/182), recall 92.3% (180/195), specificity 98.1% (103/105); attack-type accuracy 32.3% (63/195) and MITRE accepted 50.3% (98/195) over all attacks; 98.0% (294/300) of alerts got a valid verdict (6 final parse failures). The same baseline numbers are in the third column. Quote them as dev-set results, never as an independent test.

## 5. Day 5 (historical) against Day 6 arm A (final code)

The Day 5 run (`runs/week3_agent_v1/dev_agent_v1_flash_lite`, recorded git `{"commit": "e75b34e", "dirty": true}`) was collected on the Day 5 code, before the Day 6 retry and audit changes, and was not rerun. Arm A is the same full graph on the final code.

A replay of arm A against the Day 5 run (`reports/week3_day6/audit_replay_A_vs_day5/audit_replay_A.json`, sha256 `bc81b794047e4f14f62abdf3ffffde2e6e7e5fcd3685dbb49381aab674670538`) compared 300 alerts and found 300 identical on the verdict prompt hash, trace, routing, tool-call count and upstream statuses. The two runs therefore built the same prompts; any difference between their results comes from the model's replies, which are not exactly repeatable even with temperature 0 and a fixed seed.

|  | Day 5 (historical) | Day 6 arm A (final code) |
|---|---|---|
| valid verdicts / parse failures / model errors | 292/8/0 | 294/6/0 |
| model calls | 329 | 326 |
| total tokens | 1,090,933 | 1,082,001 |
| tool calls | 2,287 | 2,287 |
| graph seconds | 1969.97 | 1957.17 |
| `failures_wrong` Precision | 98.9% (177/179) | 98.9% (180/182) |
| `failures_wrong` Recall | 90.8% (177/195) | 92.3% (180/195) |
| `failures_wrong` F1 | 0.9465 | 0.9549 |
| `failures_wrong` Specificity (benign dismissed) | 98.1% (103/105) | 98.1% (103/105) |
| Attack-type accuracy (all attacks, no verdict = wrong) | 31.3% (61/195) | 32.3% (63/195) |
| MITRE accepted (all attacks, no verdict = wrong) | 49.2% (96/195) | 50.3% (98/195) |

## 6. Ablation, arms A to E (descriptive; one run per arm)

The arms are defined in `src/ablation_config.py`. Day 7 locks the full graph (arm A); this table describes what switching parts off did and does not change that choice. Switching a specialist off is shown to the model as 'disabled in this configuration'.

| arm | what runs | specialists that ran |
|---|---|---|
| A | full graph (reference) | traffic_analyst, c2_beacon_analyst, enrichment_agent |
| B | no beaconing analyst | traffic_analyst, enrichment_agent |
| C | no enrichment agent | traffic_analyst, c2_beacon_analyst |
| D | no traffic analyst (so no beaconing either: enrichment only) | enrichment_agent |
| E | no specialists (verdict step only, alert as given) | none |

### `failures_wrong` (primary)

all alerts; an alert with no verdict counts as wrong (worst case). The denominator is the same in every arm, so this is the view the plan names as primary.

| run | Precision | Recall | F1 | Specificity (benign dismissed) | FP reduction | Attacks missed |
|---|---|---|---|---|---|---|
| arm A | 98.9% (180/182) | 92.3% (180/195) | 0.9549 | 98.1% (103/105) | 98.1% | 15 |
| arm B | 98.4% (185/188) (-0.5 pp) | 94.9% (185/195) (+2.6 pp) | 0.9661 (+0.0112) | 97.1% (102/105) (-1.0 pp) | 97.1% (-1.0 pp) | 10 (-5) |
| arm C | 98.9% (178/180) (-0.0 pp) | 91.3% (178/195) (-1.0 pp) | 0.9493 (-0.0056) | 98.1% (103/105) (0.0 pp) | 98.1% (0.0 pp) | 17 (+2) |
| arm D | 98.8% (165/167) (-0.1 pp) | 84.6% (165/195) (-7.7 pp) | 0.9116 (-0.0433) | 98.1% (103/105) (0.0 pp) | 98.1% (0.0 pp) | 30 (+15) |
| arm E | 99.4% (166/167) (+0.5 pp) | 85.1% (166/195) (-7.2 pp) | 0.9171 (-0.0378) | 99.0% (104/105) (+1.0 pp) | 99.0% (+1.0 pp) | 29 (+14) |

### `failures_escalated`

all alerts; an alert with no verdict stays escalated (counted as predicted malicious).

| run | Precision | Recall | F1 | Specificity (benign dismissed) | FP reduction | Attacks missed |
|---|---|---|---|---|---|---|
| arm A | 98.9% (186/188) | 95.4% (186/195) | 0.9713 | 98.1% (103/105) | 98.1% | 9 |
| arm B | 98.4% (188/191) (-0.5 pp) | 96.4% (188/195) (+1.0 pp) | 0.9741 (+0.0028) | 97.1% (102/105) (-1.0 pp) | 97.1% (-1.0 pp) | 7 (-2) |
| arm C | 98.9% (187/189) (+0.0 pp) | 95.9% (187/195) (+0.5 pp) | 0.9740 (+0.0027) | 98.1% (103/105) (0.0 pp) | 98.1% (0.0 pp) | 8 (-1) |
| arm D | 98.8% (165/167) (-0.1 pp) | 84.6% (165/195) (-10.8 pp) | 0.9116 (-0.0597) | 98.1% (103/105) (0.0 pp) | 98.1% (0.0 pp) | 30 (+21) |
| arm E | 99.4% (166/167) (+0.5 pp) | 85.1% (166/195) (-10.3 pp) | 0.9171 (-0.0542) | 99.0% (104/105) (+1.0 pp) | 99.0% (+1.0 pp) | 29 (+20) |

### `valid_only`

only alerts that got a valid verdict. The set of alerts differs between arms, and parse failures are not spread evenly over the classes, so read this view with care.

| run | Precision | Recall | F1 | Specificity (benign dismissed) | FP reduction | Attacks missed |
|---|---|---|---|---|---|---|
| arm A | 98.9% (180/182) | 95.2% (180/189) | 0.9704 | 98.1% (103/105) | 98.1% | 9 |
| arm B | 98.9% (185/187) (+0.0 pp) | 96.4% (185/192) (+1.1 pp) | 0.9763 (+0.0059) | 98.1% (102/104) (-0.0 pp) | 98.1% (-0.0 pp) | 7 (-2) |
| arm C | 98.9% (178/180) (-0.0 pp) | 95.7% (178/186) (+0.5 pp) | 0.9727 (+0.0023) | 98.1% (103/105) (0.0 pp) | 98.1% (0.0 pp) | 8 (-1) |
| arm D | 98.8% (165/167) (-0.1 pp) | 84.6% (165/195) (-10.6 pp) | 0.9116 (-0.0587) | 98.1% (103/105) (0.0 pp) | 98.1% (0.0 pp) | 30 (+21) |
| arm E | 99.4% (166/167) (+0.5 pp) | 85.1% (166/195) (-10.1 pp) | 0.9171 (-0.0532) | 99.0% (104/105) (+1.0 pp) | 99.0% (+1.0 pp) | 29 (+20) |

### Other measures

| run | Attack-type accuracy (all attacks, no verdict = wrong) | Attack-type accuracy (attacks with a valid verdict) | MITRE accepted (all attacks, no verdict = wrong) | MITRE accepted (attacks with a valid verdict) | Valid-verdict coverage | Final parse failures (alerts) | First-try malformed (alerts) | Model calls | Total tokens | Tokens per alert (mean) | Tool calls | Graph seconds, all alerts (includes the request-rate wait) | Model latency per alert, mean (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| arm A | 32.3% (63/195) | 33.3% (63/189) | 50.3% (98/195) | 51.9% (98/189) | 98.0% (294/300) | 6 | 16 | 326 | 1,082,001 | 3,606.7 | 2,287 | 1957.17 | 1.91 |
| arm B | 36.4% (71/195) (+4.1 pp) | 37.0% (71/192) (+3.6 pp) | 54.4% (106/195) (+4.1 pp) | 55.2% (106/192) (+3.4 pp) | 98.7% (296/300) (+0.7 pp) | 4 (-2) | 11 (-5) | 317 (-9) | 953,789 (-128,212) | 3,179.3 (-427.4) | 1,729 (-558) | 1921.18 (-35.99) | 1.81 (-0.10) |
| arm C | 33.8% (66/195) (+1.5 pp) | 35.5% (66/186) (+2.2 pp) | 55.4% (108/195) (+5.1 pp) | 58.1% (108/186) (+6.2 pp) | 97.0% (291/300) (-1.0 pp) | 9 (+3) | 24 (+8) | 338 (+12) | 1,039,707 (-42,294) | 3,465.7 (-141.0) | 1,158 (-1,129) | 2024.54 (+67.37) | 1.68 (-0.23) |
| arm D | 28.7% (56/195) (-3.6 pp) | 28.7% (56/195) (-4.6 pp) | 24.6% (48/195) (-25.6 pp) | 24.6% (48/195) (-27.2 pp) | 100.0% (300/300) (+2.0 pp) | 0 (-6) | 7 (-9) | 307 (-19) | 865,483 (-216,518) | 2,884.9 (-721.7) | 1,129 (-1,158) | 1833.89 (-123.28) | 1.29 (-0.62) |
| arm E | 30.3% (59/195) (-2.1 pp) | 30.3% (59/195) (-3.1 pp) | 61.5% (120/195) (+11.3 pp) | 61.5% (120/195) (+9.7 pp) | 100.0% (300/300) (+2.0 pp) | 0 (-6) | 1 (-15) | 301 (-25) | 763,196 (-318,805) | 2,544.0 (-1,062.7) | 0 (-2,287) | 1836.93 (-120.24) | 1.92 (+0.01) |

Differences in brackets are arm minus arm A (percentage points for fractions, plain differences otherwise). They are not significance claims.

### The committed ablation table, verbatim

`reports/week3_day6/ablation_comparison/ablation_table.md` (sha256 `d6195b22e3825ce7d551cd8560ec8826e253073917bfa4128e946208b154a568`; its numbers equal the evaluations, check in section 13) holds the paired per-alert comparisons, the common-valid-alert table, the baseline three-run spread and its own limitations. It is reproduced here unchanged:

### Week 3 Day 6: specialist ablation table (DEV set, descriptive)

Generated 2026-10-11T18:36:45Z from the runs and evaluations listed below. Only measured values appear. Every ratio shows its numerator and denominator. Differences are arm minus reference (percentage points for fractions). The arms were fixed before any result existed; Day 7 locks the full graph whatever this table shows.

Reference: **A**. Arms: A = full graph (reference); B = no beaconing analyst; C = no enrichment agent; D = no traffic analyst (so no beaconing either: enrichment only); E = no specialists (verdict step only, alert as given).

#### 1. Runs

| label | arm | run | status | alerts | model | prompt | git | in table |
|---|---|---|---|---|---|---|---|---|
| A | A | `day6_arm_A` | complete | 300/300 | gemini-3.5-flash-lite | agent_v1 8df5e3fee1 | ce619c4 (dirty) | used |
| B | B | `day6_arm_B` | complete | 300/300 | gemini-3.5-flash-lite | agent_v1 8df5e3fee1 | ce619c4 (dirty) | used |
| C | C | `day6_arm_C` | complete | 300/300 | gemini-3.5-flash-lite | agent_v1 8df5e3fee1 | ce619c4 (dirty) | used |
| D | D | `day6_arm_D` | complete | 300/300 | gemini-3.5-flash-lite | agent_v1 8df5e3fee1 | ce619c4 (dirty) | used |
| E | E | `day6_arm_E` | complete | 300/300 | gemini-3.5-flash-lite | agent_v1 8df5e3fee1 | ce619c4 (dirty) | used |

- A: day6 arm run
- B: day6 arm run
- C: day6 arm run
- D: day6 arm run
- E: day6 arm run

#### 2a. View `failures_wrong`

all alerts; an alert with no verdict counts as wrong (worst case). The denominator is the same in every arm, so this is the view the plan names as primary.

| arm | run | Precision | Recall | F1 | Specificity (benign dismissed) | FP reduction | Attacks missed |
|---|---|---|---|---|---|---|---|
| A | A | 98.9% (180/182) | 92.3% (180/195) | 0.9549 | 98.1% (103/105) | 98.1% | 15 |
| B | B | 98.4% (185/188) | 94.9% (185/195) | 0.9661 | 97.1% (102/105) | 97.1% | 10 |
|  | &nbsp;&nbsp;vs reference | -0.5 pp | +2.6 pp | +0.0112 | -1.0 pp | -1.0 pp | -5 |
| C | C | 98.9% (178/180) | 91.3% (178/195) | 0.9493 | 98.1% (103/105) | 98.1% | 17 |
|  | &nbsp;&nbsp;vs reference | -0.0 pp | -1.0 pp | -0.0056 | 0.0 pp | 0.0 pp | +2 |
| D | D | 98.8% (165/167) | 84.6% (165/195) | 0.9116 | 98.1% (103/105) | 98.1% | 30 |
|  | &nbsp;&nbsp;vs reference | -0.1 pp | -7.7 pp | -0.0433 | 0.0 pp | 0.0 pp | +15 |
| E | E | 99.4% (166/167) | 85.1% (166/195) | 0.9171 | 99.0% (104/105) | 99.0% | 29 |
|  | &nbsp;&nbsp;vs reference | +0.5 pp | -7.2 pp | -0.0378 | +1.0 pp | +1.0 pp | +14 |

#### 2b. View `failures_escalated`

all alerts; an alert with no verdict stays escalated (counted as predicted malicious).

| arm | run | Precision | Recall | F1 | Specificity (benign dismissed) | FP reduction | Attacks missed |
|---|---|---|---|---|---|---|---|
| A | A | 98.9% (186/188) | 95.4% (186/195) | 0.9713 | 98.1% (103/105) | 98.1% | 9 |
| B | B | 98.4% (188/191) | 96.4% (188/195) | 0.9741 | 97.1% (102/105) | 97.1% | 7 |
|  | &nbsp;&nbsp;vs reference | -0.5 pp | +1.0 pp | +0.0028 | -1.0 pp | -1.0 pp | -2 |
| C | C | 98.9% (187/189) | 95.9% (187/195) | 0.9740 | 98.1% (103/105) | 98.1% | 8 |
|  | &nbsp;&nbsp;vs reference | +0.0 pp | +0.5 pp | +0.0027 | 0.0 pp | 0.0 pp | -1 |
| D | D | 98.8% (165/167) | 84.6% (165/195) | 0.9116 | 98.1% (103/105) | 98.1% | 30 |
|  | &nbsp;&nbsp;vs reference | -0.1 pp | -10.8 pp | -0.0597 | 0.0 pp | 0.0 pp | +21 |
| E | E | 99.4% (166/167) | 85.1% (166/195) | 0.9171 | 99.0% (104/105) | 99.0% | 29 |
|  | &nbsp;&nbsp;vs reference | +0.5 pp | -10.3 pp | -0.0542 | +1.0 pp | +1.0 pp | +20 |

#### 2c. View `valid_only`

only alerts that got a valid verdict. The set of alerts differs between arms, and parse failures are not spread evenly over the classes, so read this view with care.

| arm | run | Precision | Recall | F1 | Specificity (benign dismissed) | FP reduction | Attacks missed |
|---|---|---|---|---|---|---|---|
| A | A | 98.9% (180/182) | 95.2% (180/189) | 0.9704 | 98.1% (103/105) | 98.1% | 9 |
| B | B | 98.9% (185/187) | 96.4% (185/192) | 0.9763 | 98.1% (102/104) | 98.1% | 7 |
|  | &nbsp;&nbsp;vs reference | +0.0 pp | +1.1 pp | +0.0059 | -0.0 pp | -0.0 pp | -2 |
| C | C | 98.9% (178/180) | 95.7% (178/186) | 0.9727 | 98.1% (103/105) | 98.1% | 8 |
|  | &nbsp;&nbsp;vs reference | -0.0 pp | +0.5 pp | +0.0023 | 0.0 pp | 0.0 pp | -1 |
| D | D | 98.8% (165/167) | 84.6% (165/195) | 0.9116 | 98.1% (103/105) | 98.1% | 30 |
|  | &nbsp;&nbsp;vs reference | -0.1 pp | -10.6 pp | -0.0587 | 0.0 pp | 0.0 pp | +21 |
| E | E | 99.4% (166/167) | 85.1% (166/195) | 0.9171 | 99.0% (104/105) | 99.0% | 29 |
|  | &nbsp;&nbsp;vs reference | +0.5 pp | -10.1 pp | -0.0532 | +1.0 pp | +1.0 pp | +20 |

#### 3. Attack type, MITRE, reliability and cost

| arm | run | Attack-type accuracy (attacks with a valid verdict) | Attack-type accuracy (all attacks, no verdict = wrong) | MITRE accepted (attacks with a valid verdict) | MITRE accepted (all attacks, no verdict = wrong) | Valid-verdict coverage | Final parse failures (alerts) | First-try malformed (alerts) | Model errors (alerts) | Model calls | Total tokens | Tokens per alert (mean) | Tool calls | Graph seconds, all alerts (includes the request-rate wait) | Model latency per alert, mean (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A | A | 33.3% (63/189) | 32.3% (63/195) | 51.9% (98/189) | 50.3% (98/195) | 98.0% (294/300) | 6 | 16 | 0 | 326 | 1,082,001 | 3,606.7 | 2,287 | 1957.17 | 1.91 |
| B | B | 37.0% (71/192) | 36.4% (71/195) | 55.2% (106/192) | 54.4% (106/195) | 98.7% (296/300) | 4 | 11 | 0 | 317 | 953,789 | 3,179.3 | 1,729 | 1921.18 | 1.81 |
|  | &nbsp;&nbsp;vs reference | +3.6 pp | +4.1 pp | +3.4 pp | +4.1 pp | +0.7 pp | -2 | -5 | 0 | -9 | -128,212 | -427.4 | -558 | -35.99 | -0.10 |
| C | C | 35.5% (66/186) | 33.8% (66/195) | 58.1% (108/186) | 55.4% (108/195) | 97.0% (291/300) | 9 | 24 | 0 | 338 | 1,039,707 | 3,465.7 | 1,158 | 2024.54 | 1.68 |
|  | &nbsp;&nbsp;vs reference | +2.2 pp | +1.5 pp | +6.2 pp | +5.1 pp | -1.0 pp | +3 | +8 | 0 | +12 | -42,294 | -141.0 | -1,129 | +67.37 | -0.23 |
| D | D | 28.7% (56/195) | 28.7% (56/195) | 24.6% (48/195) | 24.6% (48/195) | 100.0% (300/300) | 0 | 7 | 0 | 307 | 865,483 | 2,884.9 | 1,129 | 1833.89 | 1.29 |
|  | &nbsp;&nbsp;vs reference | -4.6 pp | -3.6 pp | -27.2 pp | -25.6 pp | +2.0 pp | -6 | -9 | 0 | -19 | -216,518 | -721.7 | -1,158 | -123.28 | -0.62 |
| E | E | 30.3% (59/195) | 30.3% (59/195) | 61.5% (120/195) | 61.5% (120/195) | 100.0% (300/300) | 0 | 1 | 0 | 301 | 763,196 | 2,544.0 | 0 | 1836.93 | 1.92 |
|  | &nbsp;&nbsp;vs reference | -3.1 pp | -2.1 pp | +9.7 pp | +11.3 pp | +2.0 pp | -6 | -15 | 0 | -25 | -318,805 | -1,062.7 | -2,287 | -120.24 | +0.01 |

#### 4. Paired comparison with the reference (same alerts)

For each alert, whether the reference and the arm were each right. Only the alerts where they differ carry information about the arm. The p-value is an exact McNemar test, descriptive and uncorrected.

| arm | alerts | decision: only reference right | decision: only arm right | p | type: only reference right | type: only arm right | p |
|---|---|---|---|---|---|---|---|
| B | 300 | 7 | 11 | 0.481 | 5 | 13 | 0.096 |
| C | 300 | 10 | 8 | 0.815 | 7 | 10 | 0.629 |
| D | 300 | 23 | 8 | 0.011 | 18 | 11 | 0.265 |
| E | 300 | 22 | 9 | 0.029 | 15 | 11 | 0.557 |


#### 5. The same metrics on the alerts every arm answered

Alerts with a valid verdict in every arm in the table: 282. This removes the effect of different parse failures.

| arm | run | precision | recall | F1 | specificity | attack-type accuracy |
|---|---|---|---|---|---|---|
| A | A | 98.8% (169/171) | 94.9% (169/178) | 0.9685 | 98.1% (102/104) | 30.9% (55/178) |
| B | B | 98.9% (172/174) | 96.6% (172/178) | 0.9773 | 98.1% (102/104) | 33.7% (60/178) |
| C | C | 98.8% (170/172) | 95.5% (170/178) | 0.9714 | 98.1% (102/104) | 33.7% (60/178) |
| D | D | 98.7% (154/156) | 86.5% (154/178) | 0.9222 | 98.1% (102/104) | 27.5% (49/178) |
| E | E | 99.4% (153/154) | 86.0% (153/178) | 0.9217 | 99.0% (103/104) | 28.1% (50/178) |

#### 6. How much could repeating a run change a number?

No arm has a repeated observation in this table.

#### 7. Runs not in the tables

None: every listed run is complete and comparable.

#### 8. Limits

- Dev set only (300 alerts). Nothing here is an independent evaluation: the dev set was used while building the agent, and no number from it is a resume claim.
- One run per arm unless the repeats section says otherwise. With the same prompt and settings the baseline's three runs disagreed on 5 of 298 decisions and 21 attack types, so a difference of a few alerts is within what repeating a run can produce.
- Parse failures are not spread evenly over the classes, so the valid_only view compares different alert sets across arms. The failures_wrong view and the common-valid table keep the set fixed.
- A specialist that is switched off is shown to the model as 'disabled in this configuration'. The model sees that a source of evidence is absent, which a run that never had it would not say.
- Switching off the traffic analyst also removes the beaconing analyst (its repeat-contact gate reads the traffic evidence). Arm D is therefore enrichment only, not 'beaconing without traffic'.
- The McNemar p-values are descriptive and uncorrected for the number of arms. They are not significance claims.
- Gemini model behaviour can change between days under the same model name. Runs made on different days are not guaranteed to be on the same service state.

## 7. Parse failures are uneven across arms

| run | valid verdicts | final parse failures | by error code | first-try malformed (alerts) | total tokens | tokens per alert |
|---|---|---|---|---|---|---|
| arm A | 294 | 6 | {"extra_fields": 4, "invalid_json": 2} | 16 | 1,082,001 | 3,606.7 |
| arm B | 296 | 4 | {"extra_fields": 4} | 11 | 953,789 | 3,179.3 |
| arm C | 291 | 9 | {"extra_fields": 6, "invalid_json": 3} | 24 | 1,039,707 | 3,465.7 |
| arm D | 300 | 0 | {} | 7 | 865,483 | 2,884.9 |
| arm E | 300 | 0 | {} | 1 | 763,196 | 2,544.0 |

Final parse failures per arm are A 6, B 4, C 9, D 0, E 0. They are real results: they count as wrong in `failures_wrong` and are absent from `valid_only`, so `valid_only` compares different alert sets across arms. The table's common-valid view uses the 282 alerts every arm answered. Arm C has the most final parse failures and arm D, arm E had none. Tokens per alert, arm C against the arms without failures: 3,465.7 against D 2,884.9, E 2,544.0. With one run per arm, and a baseline that differed from itself across identical-prompt runs (baseline spread in the table above), a difference of a few parse failures is not evidence that one arm is more reliable, and these data cannot say why the failures are uneven (prompt length, the amount of evidence, or chance). This report draws no causal conclusion.

## 8. Reliability: calls, tokens, tool calls, latency and every observed transport error

Transport errors are read from each run's `raw_responses.jsonl` (the harness records every failed attempt). Nothing is excluded.

| run | raw rows | reply rows | transport_failed rows | failed attempts | by HTTP status | by exception | timeout-like failed attempts | sessions | session ended because | final model-error alerts |
|---|---|---|---|---|---|---|---|---|---|---|
| arm A | 326 | 326 | 0 | 0 | {} | {} | 0 | 1 | finished | 0 |
| arm B | 318 | 317 | 1 | 5 | {"429": 5} | {"ClientError": 5} | 0 | 2 | interrupted; finished | 0 |
| arm C | 338 | 338 | 0 | 0 | {} | {} | 0 | 1 | finished | 0 |
| arm D | 308 | 307 | 1 | 5 | {"429": 5} | {"ClientError": 5} | 0 | 2 | interrupted; finished | 0 |
| arm E | 302 | 301 | 1 | 6 | {"429": 5, "503": 1} | {"ClientError": 5, "ServerError": 1} | 0 | 2 | interrupted; finished | 0 |
| Day 5 (historical) | 329 | 329 | 0 | 0 | {} | {} | 0 | 1 | finished | 0 |

Observed failed attempts over all six runs, by HTTP status: {"429": 15, "503": 1} (429 = rate limit or quota, 503 = service unavailable). The client makes up to 5 attempts per call (first try plus 4 transport retries, backoff 4, 8, 16 and 32 s). A `transport_failed` row is a call whose 5 attempts all failed; the final results of the arm runs contain A 0, B 0, C 0, D 0, E 0 model-error alerts (arms A to E), so no alert is missing from the scored results. The sessions column is read from each run's `run_meta.json`; a run with more than one session was resumed after it stopped. Failed attempts are counted in the totals above but not in the model calls.

| run | model calls (replies) | estimated requests (replies + failed attempts) | total tokens | tool calls | graph seconds | model latency per alert, mean (s) | per-call latency p95 (s) | per-call latency max (s) |
|---|---|---|---|---|---|---|---|---|
| arm A | 326 | 326 | 1,082,001 | 2,287 | 1957.17 | 1.91 | 2.39 | 10.50 |
| arm B | 317 | 322 | 953,789 | 1,729 | 1921.18 | 1.81 | 2.36 | 18.66 |
| arm C | 338 | 338 | 1,039,707 | 1,158 | 2024.54 | 1.68 | 1.97 | 3.42 |
| arm D | 307 | 312 | 865,483 | 1,129 | 1833.89 | 1.29 | 1.60 | 4.77 |
| arm E | 301 | 307 | 763,196 | 0 | 1836.93 | 1.92 | 6.54 | 10.92 |

`graph seconds` include the requests-per-minute wait (10.0 per minute), so they are not model latency. Tool calls are local and offline; arm E makes none by design.

## 9. Limitations (known, not fixed in v1)

1. Dev set only (300 alerts). Nothing here is an independent evaluation: the dev set was used while building the agent, and no number from it is a resume claim. (carried over from the ablation table)
2. One run per arm unless the repeats section says otherwise. With the same prompt and settings the baseline's three runs disagreed on 5 of 298 decisions and 21 attack types, so a difference of a few alerts is within what repeating a run can produce. (carried over from the ablation table)
3. Parse failures are not spread evenly over the classes, so the valid_only view compares different alert sets across arms. The failures_wrong view and the common-valid table keep the set fixed. (carried over from the ablation table)
4. A specialist that is switched off is shown to the model as 'disabled in this configuration'. The model sees that a source of evidence is absent, which a run that never had it would not say. (carried over from the ablation table)
5. Switching off the traffic analyst also removes the beaconing analyst (its repeat-contact gate reads the traffic evidence). Arm D is therefore enrichment only, not 'beaconing without traffic'. (carried over from the ablation table)
6. The McNemar p-values are descriptive and uncorrected for the number of arms. They are not significance claims. (carried over from the ablation table)
7. Gemini model behaviour can change between days under the same model name. Runs made on different days are not guaranteed to be on the same service state. (carried over from the ablation table)
8. **Arms B and D change more than one thing.** In graph v0.1 the enrichment agent looks up ATT&CK reference entries only when the beaconing analyst flagged a `beacon_candidate` (`src/agents/enrichment_agent.py`, `wants_mitre`). Switching off the beaconing analyst (B) therefore also removes those reference entries from the verdict prompt, and arm D (no traffic analyst, so no beaconing either) loses them too. The beaconing analyst ran on 279 of 300 alerts in arm A. A difference for B or D cannot be attributed to the beaconing analyst alone.
9. **One run per arm.** No arm was repeated, so run-to-run variation of the agent is unmeasured. The baseline's three identical-prompt runs are the only measured yardstick and they differ from one another (baseline spread in the table above).
10. **Parse failures are uneven** across arms (section 7) and the valid-only view is not like-for-like.
11. **Dev set only.** Every number here is from the dev set that guided development. The frozen set has not been used.
12. **The Day 6 runs recorded git `{"commit": "ce619c4", "dirty": true}`:** they ran on the Day 5 commit plus Day 6 changes that were committed afterwards. Run-time code identity is not recorded in the runs. It is established after the fact by the Day 7 replay audits: for every arm, the committed code, replayed on all 300 alerts, reproduces the real run's verdict prompt hash, trace, routing, tool-call counts and upstream statuses (section 13). That proves the committed code builds the same model inputs; it cannot prove byte-identical code at run time.
13. **The Day 5 run** is historical (section 5).
14. **Model service drift.** The same model name can behave differently on different days; the arms were run at different times (see the session records in each `run_meta.json`) and are not guaranteed to see the same service state.

### Timeout handling: recorded decision

**Decision: known limitation, recorded at build time with `--timeout-decision known-limitation`.** The Gemini client uses a 60 s request timeout and up to 5 attempts per call with 4, 8, 16 and 32 s backoff, so a failing call can take about 6 minutes. There is no per-alert time limit; a run stops after 5 alerts in a row end in a model error. A timeout and a 5xx error both end as `model_unavailable` and differ only in the stored error text; the harness keeps the raw exception class and HTTP status of every failed attempt (section 8). In the six runs reported here, timeout-class failed attempts: 0; failed attempts by HTTP status: {"429": 15, "503": 1}. The Gemini client file is one of the five hash-locked Week 2 files, so no change to it is part of this lock. Proposed for Week 4, not implemented: a structured `error_kind` on failed calls, a per-alert time cap, and honouring a server-provided retry delay for HTTP 429.

## 10. Reproducibility

- The Week 2 baseline lock and every run folder, evaluation, the ablation table, the audit reports and the suite log are hashed in `reports/week3_agent_lock.json`.
- The runs call a live model; a rerun gives similar, not identical, replies. What is reproducible is everything downstream of the saved replies: the evaluation (`python src/evaluate.py ...`), the table (`python src/ablation_table.py ...`) and this report.
- The model inputs are reproducible without a model: the replay audits rebuild every arm's prompts on all 300 alerts and compare them with the real runs.

## 11. Frozen-set and baseline protection

`python src/week2_report.py verify` logic was re-run inside this build: 16 of 16 checks passed.

| Week 2 check | result |
|---|---|
| baseline_v3 prompt hash equals the locked hash | PASS |
| registered prompt hashes equal the locked ones | PASS |
| locked source file src/baseline_prompt.py | PASS |
| locked source file src/prompt_registry.py | PASS |
| locked source file src/verdict_schema.py | PASS |
| locked source file src/verdict_parser.py | PASS |
| locked source file src/gemini_client.py | PASS |
| reference run dev_flash_lite_v1 | PASS |
| reference run dev_flash_lite_v2 | PASS |
| reference run dev_flash_lite_v3_final | PASS |
| reference run dev_flash_lite_v3_d6_rep1 | PASS |
| reference run dev_flash_lite_v3_d6_rep2 | PASS |
| reference run dev_flash_lite_v3_d6_rep3 | PASS |
| frozen access log unchanged (lines and hash) | PASS |
| frozen unlock variable not set | PASS |
| Week 1 files unchanged | PASS |

Frozen access log: 1 lines, sha256 (line endings normalised) `aca942b50b058a0c3a428541db79bfa600f72976308f319de821e713cd0cfda3`; the same line count is recorded by every evaluation. The frozen unlock variable is not set. The Week 1 files hash the same as in every evaluation (section 13).

## 12. Evidence: paths and SHA-256 hashes

`git` is the file's state in the repository when this report was built: `tracked`, or `untracked` (a local file that the Day 7 evidence commit adds, or that is only hashed in the lock). Run folders are protected by the hashes in the lock whether or not they are tracked.

| run | folder | results.jsonl sha256 (first 16) | run_meta.json sha256 (first 16) | git (run_meta.json) |
|---|---|---|---|---|
| arm A | `runs/week3_day6/day6_arm_A/` | `f0f5045318d11c9b` | `e473c8712e355506` | untracked |
| arm B | `runs/week3_day6/day6_arm_B/` | `e72cdc47b60c1fbc` | `9ec685fb081da79b` | untracked |
| arm C | `runs/week3_day6/day6_arm_C/` | `e744242722977760` | `1f8de928e9877649` | untracked |
| arm D | `runs/week3_day6/day6_arm_D/` | `263bbc2ee451cc27` | `b8d4aac9fdfbcedf` | untracked |
| arm E | `runs/week3_day6/day6_arm_E/` | `513cfd9575f45ef5` | `59c8d2702a992463` | untracked |
| Day 5 (historical) | `runs/week3_agent_v1/dev_agent_v1_flash_lite/` | `73d611e51567a0d9` | `54000d9a2aa8efbf` | untracked |

| evidence | path | sha256 | git |
|---|---|---|---|
| arm A | `reports/week3_day6/eval_A/evaluation.json` | `1dd8c6dd3c891140e17dc5454b21c64c8e7db6326408ae8f3b9bb1193f8282f1` | tracked |
| arm B | `reports/week3_day6/eval_B/evaluation.json` | `8cc73e32622fcf2304f27de0cfe745ca19140f2db26b3b66322196101a258912` | tracked |
| arm C | `reports/week3_day6/eval_C/evaluation.json` | `b7165a27ed6f58ecdf2f9c286837a0e86ef641e135f47b1ea1bc6ca597a32ccc` | tracked |
| arm D | `reports/week3_day6/eval_D/evaluation.json` | `3ac3d08bce1d779dff107629aab92e1934ce0a9ff303ea134e6d9335a33a4294` | tracked |
| arm E | `reports/week3_day6/eval_E/evaluation.json` | `373265671410ad70f92d517df7add7ce4a9769e7b11a49423bec9b846b335b23` | tracked |
| Day 5 (historical) | `reports/week2_eval/dev_agent_v1_flash_lite/evaluation.json` | `2495c83c98a27f73fe1308fa75621a5c9b5b5a00c5af2344a41ac70c94a8b286` | untracked |
| baseline_v3 | `reports/week2_eval/dev_flash_lite_v3_final/evaluation.json` | `a5092154cb8e4a95fa6461fe3572caac6c1283f04252888dbde31bd8e1a2215b` | tracked |
| ablation table (json) | `reports/week3_day6/ablation_comparison/ablation_table.json` | `027f327b18c2be58a4937a77fb8ecf323e50bd7075df52dc2161e4a48848bdc2` | tracked |
| ablation table (md) | `reports/week3_day6/ablation_comparison/ablation_table.md` | `d6195b22e3825ce7d551cd8560ec8826e253073917bfa4128e946208b154a568` | tracked |
| Day 6 replay audit, arm A | `reports/week3_day6/audit_replay_A/audit_replay_A.json` | `07f8c68f02f1e5e9d7086ff6949bad5761591a47e077597c1538127f5064ed84` | untracked |
| Day 6 replay audit, arm B | `reports/week3_day6/audit_replay_B/audit_replay_B.json` | `30cedffe454611b8cc566f6d3b49b6b904471162c5085526dff23275ab6a318b` | untracked |
| Day 6 replay audit, arm C | `reports/week3_day6/audit_replay_C/audit_replay_C.json` | `69fc8f3eb7abe6d7a63caa61b38a6f59f6979f3a254fa29a6a11c71a9cb90beb` | untracked |
| Day 6 replay audit, arm D | `reports/week3_day6/audit_replay_D/audit_replay_D.json` | `97be50381da9df9d208eccb19762426e7e75d06a62ef35f60a50b715001b4499` | untracked |
| Day 6 replay audit, arm E | `reports/week3_day6/audit_replay_E/audit_replay_E.json` | `a719fc16df40c235ba76c27f317fead7ebc491e36a372d376c7c0fbb78189e2a` | untracked |
| Day 6 replay audit, arm A against the Day 5 run | `reports/week3_day6/audit_replay_A_vs_day5/audit_replay_A.json` | `bc81b794047e4f14f62abdf3ffffde2e6e7e5fcd3685dbb49381aab674670538` | untracked |
| Day 6 artifacts audit of the Day 5 run | `reports/week3_day6/audit_artifacts_day5/audit_artifacts.json` | `32aa17b250c193933ac85c8af1a76f248e20dbbab1148b8661c5f18936b4687b` | untracked |
| Day 7 replay audit of the committed code against the real arm A run | `reports/week3_day7/audit_replay_vs_run_A/audit_replay_A.json` | `13e304cc56bf4318b8d2336c7ae46f6c7897e8e7fc57bf0e740a4772d39015b4` | untracked |
| Day 7 artifacts audit of the real arm A run | `reports/week3_day7/audit_artifacts_A/audit_artifacts.json` | `6826586952c2bf3ae508e85034ac3daaf92b4ca6226f379a98e980c6aa72b5a1` | untracked |
| Day 7 replay audit of the committed code against the real arm B run | `reports/week3_day7/audit_replay_vs_run_B/audit_replay_B.json` | `1ec45095a61ac28206d614add48e67241ba2164bcdcad72fc80b96e295f30dee` | untracked |
| Day 7 artifacts audit of the real arm B run | `reports/week3_day7/audit_artifacts_B/audit_artifacts.json` | `68e7ce4e4445d70303cd293fcc3b4d3cac6d47b0eec161c99c6d4bf4c1d209b3` | untracked |
| Day 7 replay audit of the committed code against the real arm C run | `reports/week3_day7/audit_replay_vs_run_C/audit_replay_C.json` | `8d7ade48e4dbd1698caa090a4fceaf96539aae9c09afa576620a99d1b7431d4b` | untracked |
| Day 7 artifacts audit of the real arm C run | `reports/week3_day7/audit_artifacts_C/audit_artifacts.json` | `48076eb9816a054d3482701fe8cca30250fa0aa682ce656ebf8ede80cfa02c69` | untracked |
| Day 7 replay audit of the committed code against the real arm D run | `reports/week3_day7/audit_replay_vs_run_D/audit_replay_D.json` | `af2e63dd32072322da6e206e24f63a02b326ba8bc7f89837e55b6b7d9f7199c9` | untracked |
| Day 7 artifacts audit of the real arm D run | `reports/week3_day7/audit_artifacts_D/audit_artifacts.json` | `9389345c770267c6392e4b2bd2bf7cc590d0e8a4228d55d62778c97860eb2cb3` | untracked |
| Day 7 replay audit of the committed code against the real arm E run | `reports/week3_day7/audit_replay_vs_run_E/audit_replay_E.json` | `f33f064a72d9147b470a6b9861c60bd78db9966932d65d456238b3599839bdd7` | untracked |
| Day 7 artifacts audit of the real arm E run | `reports/week3_day7/audit_artifacts_E/audit_artifacts.json` | `fd6b56a866ac10d89b962af0c0c75b7ca0b216dd71cad2a2a5cc73d0e58dbe10` | untracked |
| full-suite log | `reports/week3_day7/full_suite_792d7bf.txt` | `6ee87980d334f4f66f6bee780f41ee4aa38234b308012542e353e71738388a6c` | untracked |
| Week 2 baseline lock | `reports/week2_baseline_lock.json` | `a6d803be58c053fc945050836f7d1a5e3a3fcd923a58818acf658c8c433d2ddc` | tracked |

Source files hashed in the lock (line endings normalised): 42 files, listed with their hashes in the lock record. The five locked Week 2 files: `src/baseline_prompt.py`, `src/prompt_registry.py`, `src/verdict_schema.py`, `src/verdict_parser.py`, `src/gemini_client.py`.

## 13. Acceptance criteria and checks

The lock was written only because all of these passed in `build`:

| # | check | result | detail |
|---|---|---|---|
| 1 | the agent_v1 prompt in the code has the pinned hash | PASS | 8df5e3fee15280d6 |
| 2 | the graph version is v0.1 | PASS |  |
| 3 | every arm run and the Day 5 run used prompt agent_v1 with the pinned hash | PASS |  |
| 4 | every run used one model, gemini-3.5-flash-lite | PASS | gemini-3.5-flash-lite |
| 5 | every arm run and the Day 5 run used identical generation, retry, timeout and rate settings | PASS |  |
| 6 | every arm run and the Day 5 run used the same dev inputs and the same 300-alert list | PASS |  |
| 7 | every arm run is a complete real dev run (not a fake-model run) | PASS |  |
| 8 | each arm run recorded the ablation arm, switched-off specialists and effective specialists that ablation_config defines for it | PASS | 5 of 5 |
| 9 | every arm run ended with 300 final results and no model_error alert | PASS | 5 of 5 |
| 10 | every arm evaluation is complete, for its own run, with the run's prompt hash and true integrity checks | PASS |  |
| 11 | the Day 5 and baseline_v3 evaluations are complete and for their own runs | PASS |  |
| 12 | no evaluation was partial | PASS |  |
| 13 | every run folder matches the run_file_sha256 its own evaluation recorded | PASS | 6 of 6 match |
| 14 | the frozen access log has the same number of lines now as in every evaluation (frozen set not opened) | PASS | lines now 1, in evaluations [1] |
| 15 | no run recorded a changed frozen access log or Week 1 file | PASS |  |
| 16 | the frozen unlock variable is not set in this shell | PASS |  |
| 17 | the Week 1 files hash the same now as in every evaluation | PASS | 30 hash comparisons |
| 18 | the ablation table has reference A, all five arms in A to E order, and no excluded run | PASS | used ['A', 'B', 'C', 'D', 'E'], excluded 0 |
| 19 | the ablation table was built from exactly the five arm runs and their evaluation folders | PASS |  |
| 20 | every number in the committed ablation table equals what the evaluations give now | PASS | all cells match |
| 21 | every required audit report exists | PASS | 17 of 17 |
| 22 | every audit report says all its checks passed | PASS |  |
| 23 | the committed code reproduces every arm run: 300 alerts replayed per arm; prompt hash, trace, routing, tool-call counts and upstream statuses identical to the real run | PASS | 5 of 5 |
| 24 | arm A's replay matches the Day 5 run on every compared field | PASS | compared 300, identical 300 |
| 25 | each Day 7 artifacts audit is for its own arm run | PASS | 5 of 5 |
| 26 | the Week 2 baseline verification passes (16 checks: locked prompt, five locked source files, reference runs, frozen log, Week 1 files) | PASS | 16 of 16 |
| 27 | the five locked Week 2 source files hash the same as in the Week 2 lock record | PASS |  |
| 28 | the baseline_v3 evaluation used in the comparison is the one the Week 2 lock recorded | PASS |  |
| 29 | a full-suite log exists, shows OK, 1017 or more tests, and lists the Day 7 tests | PASS | ran 1092, OK, Day 7 tests listed: True |

Full test suite (`reports/week3_day7/full_suite_792d7bf.txt`): ran 1092 tests in 577.987 s, OK, skipped 3. The log was made before the lock record existed, so the real-lock tests in `tests/test_week3_day7.py` were skipped in it; they run once the lock exists.

**Commands that reproduce the verification (read-only, no model call):**

```
python -m unittest discover -s tests -t .
python src/week2_report.py verify
python src/week3_report.py verify
git status --short
```

**Tag:** the annotated tag `week3-agents` is created on the Day 7 commit only after the commands above pass and the project owner approves.
