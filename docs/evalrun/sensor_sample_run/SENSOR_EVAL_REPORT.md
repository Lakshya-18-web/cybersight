# Sensor pipeline evaluation (SYNTHETIC scenarios, SCRIPTED model)

> **Read this first.** The traffic is synthetic, the model is a scripted fake whose behaviour is an assumption, and no real service was called. These numbers describe what the deterministic layers do under assumed model behaviour. They are **not** detection accuracy and must not be quoted as such. Real-model performance is not measured here.

Set `synthetic-sensor-v1`: 56 scenarios (30 attack, 26 benign), SHA-256 `a63c4840b766e355311aab5616d23df16980e65f76292d5145d4d869156bd459`. Generated 2026-10-25T06:48:18Z. Week 5 `week5-v1`, risk policy `risk-policy-v1`, evidence policy `evidence-policy-v1`.

Families: ssh_brute=6, port_scan=6, c2_beacon=6, dos_flood=4, stealth_beacon=4, quiet_attack=4, benign_tls=10, benign_http=6, benign_update_poller=4, benign_inventory_scanner=2, benign_hostile_signature_text=4.

Positive = the alert is **not closed** (flagged for an analyst). A missed attack is an attack that was closed. Configurations: `sensor_passthrough` (everything flagged), `sensor_severity_rule` (Suricata severity 1-2 flagged, no model), `model_only` (the verdict alone), `model_plus_risk_policy` (verdict + Week 4 policy), `full_pipeline` (+ evidence policy veto = what the system actually stores). The two `*_escalate_only` rows count only the top-priority queue (`escalate`) as flagged. **Why:** a sensor alert has no detector score, so the system never auto-closes it; the plain rows therefore flag everything and the information is in WHICH queue a case lands in.

**Invariants held on every run:** no attack was auto-closed, no sensor alert was auto-closed, the evidence policy never lowered caution, and no action left `pending` without a human.

## Model profile `oracle`

The model is always right. This is the ceiling: what the pipeline does when the model cannot be blamed.

| configuration | TP | FP | FN (attacks closed) | TN | precision | recall | F1 | specificity | FPR | flagged rate (analyst workload) |
|---|---|---|---|---|---|---|---|---|---|---|
| sensor_passthrough | 30 | 26 | 0 | 0 | 0.536 | 1.000 | 0.698 | 0.0% | 100.0% | 100.0% |
| sensor_severity_rule | 22 | 0 | 8 | 26 | 1.000 | 0.733 | 0.846 | 100.0% | 0.0% | 39.3% |
| model_only | 30 | 0 | 0 | 26 | 1.000 | 1.000 | 1.000 | 100.0% | 0.0% | 53.6% |
| model_plus_risk_policy | 30 | 26 | 0 | 0 | 0.536 | 1.000 | 0.698 | 0.0% | 100.0% | 100.0% |
| full_pipeline | 30 | 26 | 0 | 0 | 0.536 | 1.000 | 0.698 | 0.0% | 100.0% | 100.0% |
| model_plus_risk_policy_escalate_only | 30 | 0 | 0 | 26 | 1.000 | 1.000 | 1.000 | 100.0% | 0.0% | 53.6% |
| full_pipeline_escalate_only | 30 | 0 | 0 | 26 | 1.000 | 1.000 | 1.000 | 100.0% | 0.0% | 53.6% |

Attacks closed by the full pipeline: none. Attacks NOT in the escalate queue (priority view; they are in needs_review): none.

Per class (full pipeline, priority view: flagged = escalate):

| true class | support | escalated | not escalated | recall / specificity |
|---|---|---|---|---|
| SSH-Patator | 6 | 6 | 0 | 100.0% |
| PortScan | 6 | 6 | 0 | 100.0% |
| Bot | 10 | 10 | 0 | 100.0% |
| DoS Hulk | 4 | 4 | 0 | 100.0% |
| Web Attack - Brute Force | 4 | 4 | 0 | 100.0% |
| BENIGN | 26 | 0 | 26 | 100.0% |

Per family (full pipeline, priority view):

| family | label | support | escalated |
|---|---|---|---|
| ssh_brute | attack | 6 | 6 |
| port_scan | attack | 6 | 6 |
| c2_beacon | attack | 6 | 6 |
| dos_flood | attack | 4 | 4 |
| stealth_beacon | attack | 4 | 4 |
| quiet_attack | attack | 4 | 4 |
| benign_tls | benign | 10 | 0 |
| benign_http | benign | 6 | 0 |
| benign_update_poller | benign | 4 | 0 |
| benign_inventory_scanner | benign | 2 | 0 |
| benign_hostile_signature_text | benign | 4 | 0 |

Operations: 56 alerts, 0 jobs failed (0.0%), 0 retried, attempts total 56, drain 1.49s (37.7 alerts/s), latency median 0.026 s, p95 0.035 s. Tokens: unavailable (fake model). Cost: unavailable (no tokens, no verified pricing).

## Model profile `noisy`

The model is wrong on 25% of alerts (deterministic per alert id): an attack called benign, or benign traffic called a PortScan.

| configuration | TP | FP | FN (attacks closed) | TN | precision | recall | F1 | specificity | FPR | flagged rate (analyst workload) |
|---|---|---|---|---|---|---|---|---|---|---|
| sensor_passthrough | 30 | 26 | 0 | 0 | 0.536 | 1.000 | 0.698 | 0.0% | 100.0% | 100.0% |
| sensor_severity_rule | 22 | 0 | 8 | 26 | 1.000 | 0.733 | 0.846 | 100.0% | 0.0% | 39.3% |
| model_only | 26 | 2 | 4 | 24 | 0.929 | 0.867 | 0.897 | 92.3% | 7.7% | 50.0% |
| model_plus_risk_policy | 30 | 26 | 0 | 0 | 0.536 | 1.000 | 0.698 | 0.0% | 100.0% | 100.0% |
| full_pipeline | 30 | 26 | 0 | 0 | 0.536 | 1.000 | 0.698 | 0.0% | 100.0% | 100.0% |
| model_plus_risk_policy_escalate_only | 26 | 2 | 4 | 24 | 0.929 | 0.867 | 0.897 | 92.3% | 7.7% | 50.0% |
| full_pipeline_escalate_only | 27 | 2 | 3 | 24 | 0.931 | 0.900 | 0.915 | 92.3% | 7.7% | 51.8% |

Attacks closed by the full pipeline: none. Attacks NOT in the escalate queue (priority view; they are in needs_review): ssh_brute-02, dos_flood-01, dos_flood-02.

Per class (full pipeline, priority view: flagged = escalate):

| true class | support | escalated | not escalated | recall / specificity |
|---|---|---|---|---|
| SSH-Patator | 6 | 5 | 1 | 83.3% |
| PortScan | 6 | 6 | 0 | 100.0% |
| Bot | 10 | 10 | 0 | 100.0% |
| DoS Hulk | 4 | 2 | 2 | 50.0% |
| Web Attack - Brute Force | 4 | 4 | 0 | 100.0% |
| BENIGN | 26 | 2 | 24 | 92.3% |

Per family (full pipeline, priority view):

| family | label | support | escalated |
|---|---|---|---|
| ssh_brute | attack | 6 | 5 |
| port_scan | attack | 6 | 6 |
| c2_beacon | attack | 6 | 6 |
| dos_flood | attack | 4 | 2 |
| stealth_beacon | attack | 4 | 4 |
| quiet_attack | attack | 4 | 4 |
| benign_tls | benign | 10 | 0 |
| benign_http | benign | 6 | 0 |
| benign_update_poller | benign | 4 | 0 |
| benign_inventory_scanner | benign | 2 | 1 |
| benign_hostile_signature_text | benign | 4 | 1 |

Operations: 56 alerts, 0 jobs failed (0.0%), 0 retried, attempts total 56, drain 1.55s (36.04 alerts/s), latency median 0.028 s, p95 0.039 s. Tokens: unavailable (fake model). Cost: unavailable (no tokens, no verified pricing).

## Model profile `lazy_benign`

The model calls every alert benign (talked into it, or blind to the attack). This shows what the deterministic layers alone catch.

| configuration | TP | FP | FN (attacks closed) | TN | precision | recall | F1 | specificity | FPR | flagged rate (analyst workload) |
|---|---|---|---|---|---|---|---|---|---|---|
| sensor_passthrough | 30 | 26 | 0 | 0 | 0.536 | 1.000 | 0.698 | 0.0% | 100.0% | 100.0% |
| sensor_severity_rule | 22 | 0 | 8 | 26 | 1.000 | 0.733 | 0.846 | 100.0% | 0.0% | 39.3% |
| model_only | 0 | 0 | 30 | 26 | n/a | 0.000 | n/a | 100.0% | 0.0% | 0.0% |
| model_plus_risk_policy | 30 | 26 | 0 | 0 | 0.536 | 1.000 | 0.698 | 0.0% | 100.0% | 100.0% |
| full_pipeline | 30 | 26 | 0 | 0 | 0.536 | 1.000 | 0.698 | 0.0% | 100.0% | 100.0% |
| model_plus_risk_policy_escalate_only | 0 | 0 | 30 | 26 | n/a | 0.000 | n/a | 100.0% | 0.0% | 0.0% |
| full_pipeline_escalate_only | 6 | 0 | 24 | 26 | 1.000 | 0.200 | 0.333 | 100.0% | 0.0% | 10.7% |

Attacks closed by the full pipeline: none. Attacks NOT in the escalate queue (priority view; they are in needs_review): ssh_brute-00, ssh_brute-01, ssh_brute-02, ssh_brute-03, ssh_brute-04, ssh_brute-05, port_scan-00, port_scan-01, port_scan-02, port_scan-03, port_scan-04, port_scan-05, dos_flood-00, dos_flood-01, dos_flood-02, dos_flood-03, stealth_beacon-00, stealth_beacon-01, stealth_beacon-02, stealth_beacon-03, quiet_attack-00, quiet_attack-01, quiet_attack-02, quiet_attack-03.

Per class (full pipeline, priority view: flagged = escalate):

| true class | support | escalated | not escalated | recall / specificity |
|---|---|---|---|---|
| SSH-Patator | 6 | 0 | 6 | 0.0% |
| PortScan | 6 | 0 | 6 | 0.0% |
| Bot | 10 | 6 | 4 | 60.0% |
| DoS Hulk | 4 | 0 | 4 | 0.0% |
| Web Attack - Brute Force | 4 | 0 | 4 | 0.0% |
| BENIGN | 26 | 0 | 26 | 100.0% |

Per family (full pipeline, priority view):

| family | label | support | escalated |
|---|---|---|---|
| ssh_brute | attack | 6 | 0 |
| port_scan | attack | 6 | 0 |
| c2_beacon | attack | 6 | 6 |
| dos_flood | attack | 4 | 0 |
| stealth_beacon | attack | 4 | 0 |
| quiet_attack | attack | 4 | 0 |
| benign_tls | benign | 10 | 0 |
| benign_http | benign | 6 | 0 |
| benign_update_poller | benign | 4 | 0 |
| benign_inventory_scanner | benign | 2 | 0 |
| benign_hostile_signature_text | benign | 4 | 0 |

Operations: 56 alerts, 0 jobs failed (0.0%), 0 retried, attempts total 56, drain 1.68s (33.24 alerts/s), latency median 0.027 s, p95 0.042 s. Tokens: unavailable (fake model). Cost: unavailable (no tokens, no verified pricing).

## Provider failure

A model outage was injected for 20% of alerts (13 alerts, deterministic), persistent through every retry (3 attempts).

- Cases still created with `model_error` and routed to review: yes (13 alerts).
- Attacks hit by the outage: 9; of those, closed: 0.
- Job retries: 13 alerts retried, 82 attempts in total. Failed jobs after retries: 0.

## Limits

- SYNTHETIC: the traffic is generated by scripts in this repository; labels are by construction. It is not real Suricata output and not real network behaviour.
- FAKE MODEL: replies are scripted per profile. The profiles are assumptions about a model, not measurements of Gemini. Nothing here is real model accuracy.
- No frozen or holdout data was used. No real API (Gemini, AbuseIPDB) was called; threat intelligence is not part of this run.
- Sensor alerts carry no detector score, so by policy (R3 and E6) the full pipeline never auto-closes them: every benign alert is a workload cost. That is a design decision, visible in 'flagged rate'.
- Families such as quiet_attack look like ordinary traffic to every deterministic rule. They are caught only when the model catches them.
- Latency and throughput are in-process timings with an instant fake model on one machine. They are not capacity figures.
- Counts are small (see the support column). A rate computed from a handful of scenarios is not a stable estimate.

Reproduce: `python -m week5.evalrun.sensor_suite --out <folder>` (no network, no key, no database). Per-scenario records: `sensor_eval_records.json`.
