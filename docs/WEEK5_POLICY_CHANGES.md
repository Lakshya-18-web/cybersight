# Week 5 phase 2 - policy and semantic changes

Every change below alters what the system stores or decides. Results produced before these changes (including any evaluation plan hashed before them) are **not comparable** with results produced after.

## 1. Policy identity (versioned)
| Before | After |
|---|---|
| `routing.policy_version = "risk-policy-v1"`, `policy_sha256` = SHA-256 of `config/risk_policy.json` | `routing.policy_version = "risk-policy-v1+evidence-policy-v1"`, `policy_sha256` = SHA-256 over both files (`evidence_policy.combined_identity`) |
Both files are hashed after line-ending normalisation (CRLF and LF hash the same). Any edit to either file changes the stored identity. `provenance.week5.risk_policy` and `provenance.week5.evidence_policy` also record each file's own version and hash. `week5_version` stamped on jobs and cases is now `week5-v2`. Existing cases keep the identity they were decided under; nothing is rewritten.

## 2. New deterministic rules (`config/evidence_policy.json`, `evidence-policy-v1`)
They run after the Week 4 risk policy and the response guard. They can only raise caution (`auto_close` -> `needs_review` -> `escalate`); they never close, approve, propose or execute.
| Rule | Fires when | Floor |
|---|---|---|
| E1 sensor_severity | Suricata severity <= 1 / <= 2 | escalate / needs_review |
| E2 sensor_category | category is in the configured list (exact match) | escalate |
| E3 beacon_candidate | the beacon specialist's structured finding has `beacon_candidate == true` | needs_review |
| E4 scan_like_source | source has >= 20 flows to >= 20 distinct destination ports in the window | needs_review |
| E5 threat_intel_high | provider status ok and score >= 75 with >= 3 reports (escalate), or score >= 25 (review) | escalate / needs_review |
| E6 sensor_without_flow | a sensor alert has no linked flow record | needs_review |
Missing, failed, skipped, disabled or zero-score threat intelligence changes nothing. A benign verdict that the evidence raises to review/escalate yields no action proposals.

## 3. Sensor alerts are never auto-closed
A sensor alert (EVE) has no detector score (`detector_score` is always `null`, listed in `unavailable_fields`), so Week 4 rule R3 and E6 keep it out of `auto_close`. **Consequence:** on sensor data the system cannot reduce analyst workload by closing; it prioritises (`escalate` vs `needs_review`). The labelled sensor evaluation (docs/evalrun/sensor_sample_run) shows this as a 100% flagged rate for the plain view and reports a priority view separately. Changing this needs a calibrated score for EVE traffic, which does not exist.

## 4. Response guard
New flag code `untrusted_text` (alongside `instruction_echo`, `control_chars`): a verdict that repeats text taken from sensor free text. Like other flags it blocks auto-close and is audited.

## 5. Storage and API semantics
- Cases are presented in four kinds of evidence, never mixed: `observed`, `external_enrichment`, `model_hypothesis`, `policy_decision` (`GET /cases/{id}/analysis`). Storage keeps the original tables; the grouping is by origin, e.g. `reputation_lookup` tool calls are `external_enrichment`, the verdict is `model_hypothesis`.
- New `alert_set` value `sensor` (jobs and cases). `soc.sensor_events` (append-only), `soc.case_notes`, `soc.case_feedback` (append-only). Migration `0002_sensor_and_case_management.sql` is additive (new tables, new functions, widened check constraints); no existing row is changed.
- Analyst feedback never changes a verdict or routing and is never read by a prompt.
- Resolving a case records the decision and (Week 4 behaviour kept) deciding the last pending action auto-resolves an escalated or needs_review case.

## 6. Payload suite expectations changed
PI-E02 (benign verdict on a scan-pattern alert) was the demonstration of RR-1 and succeeded before. It is now neutralised (by the W5-RR1 safeguards if your runner has them, otherwise by the evidence policy) and its expectation is `neutralised/policy`. **`payloads.json` itself is not replaced by the upgrade** (you may have edited it): the two payloads the upgrade adds are in `data/payloads_evidence.json`, loaded alongside it. PI-E12 (no evidence at all) is the remaining declared residual; PI-E13 (beacon evidence) is a control that is neutralised. The payload count limit is now 30-60 adversarial payloads (51 with both files).

## 7. What did not change
Week 1-4 code and its tests, the 21-field intake contract, the CIC-style ingestion path (`POST /alerts`), the approval roles, simulated execution, the audit hash chain, the job state machine.

## 8. Rollback
The code is additive. To go back: deploy the previous image; leave migration 0002's tables in place (unused, harmless). Cases created under `risk-policy-v1+evidence-policy-v1` stay valid. See docs/WEEK5_OPERATIONS.md.

## 9. Relationship to the W5-RR1 safeguards already in your runner
Your live `runner.py` has `apply_beacon_candidate_veto` and `apply_scan_evidence_veto` (reason prefix `W5-RR1`), applied after the Week 4 policy and the response guard. The upgrade keeps them byte for byte and applies `evidence-policy-v1` after them. E3 (beacon) repeats the first; E4 (scan-like source, from stored sensor flows) is the same idea as the second but reads different data. They agree; neither lowers caution. **The W5-RR1 functions are not part of the recorded policy identity** (`risk-policy-v1+evidence-policy-v1` hashes the two JSON files only), so a change to them changes routing without changing the stored identity: record such a change by hand, and do not compare evaluation results across it.
