# Week 3 Day 6: specialist ablation table (DEV set, descriptive)

Generated 2026-10-11T18:36:45Z from the runs and evaluations listed below. Only measured values appear. Every ratio shows its numerator and denominator. Differences are arm minus reference (percentage points for fractions). The arms were fixed before any result existed; Day 7 locks the full graph whatever this table shows.

Reference: **A**. Arms: A = full graph (reference); B = no beaconing analyst; C = no enrichment agent; D = no traffic analyst (so no beaconing either: enrichment only); E = no specialists (verdict step only, alert as given).

## 1. Runs

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

## 2a. View `failures_wrong`

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

## 2b. View `failures_escalated`

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

## 2c. View `valid_only`

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

## 3. Attack type, MITRE, reliability and cost

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

## 4. Paired comparison with the reference (same alerts)

For each alert, whether the reference and the arm were each right. Only the alerts where they differ carry information about the arm. The p-value is an exact McNemar test, descriptive and uncorrected.

| arm | alerts | decision: only reference right | decision: only arm right | p | type: only reference right | type: only arm right | p |
|---|---|---|---|---|---|---|---|
| B | 300 | 7 | 11 | 0.481 | 5 | 13 | 0.096 |
| C | 300 | 10 | 8 | 0.815 | 7 | 10 | 0.629 |
| D | 300 | 23 | 8 | 0.011 | 18 | 11 | 0.265 |
| E | 300 | 22 | 9 | 0.029 | 15 | 11 | 0.557 |


## 5. The same metrics on the alerts every arm answered

Alerts with a valid verdict in every arm in the table: 282. This removes the effect of different parse failures.

| arm | run | precision | recall | F1 | specificity | attack-type accuracy |
|---|---|---|---|---|---|---|
| A | A | 98.8% (169/171) | 94.9% (169/178) | 0.9685 | 98.1% (102/104) | 30.9% (55/178) |
| B | B | 98.9% (172/174) | 96.6% (172/178) | 0.9773 | 98.1% (102/104) | 33.7% (60/178) |
| C | C | 98.8% (170/172) | 95.5% (170/178) | 0.9714 | 98.1% (102/104) | 33.7% (60/178) |
| D | D | 98.7% (154/156) | 86.5% (154/178) | 0.9222 | 98.1% (102/104) | 27.5% (49/178) |
| E | E | 99.4% (153/154) | 86.0% (153/178) | 0.9217 | 99.0% (103/104) | 28.1% (50/178) |

## 6. How much could repeating a run change a number?

No arm has a repeated observation in this table.

## 7. Runs not in the tables

None: every listed run is complete and comparable.

## 8. Limits

- Dev set only (300 alerts). Nothing here is an independent evaluation: the dev set was used while building the agent, and no number from it is a resume claim.
- One run per arm unless the repeats section says otherwise. With the same prompt and settings the baseline's three runs disagreed on 5 of 298 decisions and 21 attack types, so a difference of a few alerts is within what repeating a run can produce.
- Parse failures are not spread evenly over the classes, so the valid_only view compares different alert sets across arms. The failures_wrong view and the common-valid table keep the set fixed.
- A specialist that is switched off is shown to the model as 'disabled in this configuration'. The model sees that a source of evidence is absent, which a run that never had it would not say.
- Switching off the traffic analyst also removes the beaconing analyst (its repeat-contact gate reads the traffic evidence). Arm D is therefore enrichment only, not 'beaconing without traffic'.
- The McNemar p-values are descriptive and uncorrected for the number of arms. They are not significance claims.
- Gemini model behaviour can change between days under the same model name. Runs made on different days are not guaranteed to be on the same service state.
