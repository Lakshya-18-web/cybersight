# Dataset card: SOC triage evaluation sets

Two sets of detector alerts, one for development (dev) and one for the final numbers (frozen), built from CIC-IDS2017.

## Source

- CIC-IDS2017, Canadian Institute for Cybersecurity, University of New Brunswick. Labelled network flows captured Monday 3 July to Friday 7 July 2017.
- Reference: Sharafaldin, Lashkari, Ghorbani. Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. ICISSP 2018.
- Cleaning (Day 2): empty rows, label text repair, timestamp repair, NaN and inf rows, exact and feature-vector duplicates removed. Infiltration and Heartbleed dropped (too few flows). Web Attack XSS and SQL injection merged into one class. See reports/cleaning_log.md.
- Split (Day 3): inside every (source file, label) group in time order, 60% train, 20% validation, 20% test, with 1% gap rows dropped at each boundary.

## How the alerts were made

- Detector: XGBoost, 53 features, Destination Port not used, trained on the train split only.
- Alert rule: detector score >= 0.00459436746314168 (accepted at the end of Day 5).
- The threshold is the highest one with pooled validation recall >= 0.95 and validation false positive share >= 0.3. The first rule (recall only) gave a threshold that missed most of the small attack classes and left almost no false positives, so it was replaced.
- On the full validation split at this threshold: recall 1.0000, precision 0.6993, 115466 alerts of which 34721 are false positives. The worst attack class is Bot with recall 0.9946.

## How the sets were built

- Dev set: 300 alerts sampled from the validation-split alerts. Frozen set: 2500 alerts sampled from the test-split alerts. Dev and frozen never share a flow.
- False positives are 35% of each set by design. Attack alerts are shared across the 11 attack classes as evenly as the number of available alerts allows (caps: 25 per class dev, 200 per class frozen).
- Inside each class and for the false positives, alerts are drawn uniformly at random with fixed seeds. The detector score is not used to choose alerts. Rows are shuffled and given new ids, so the id order says nothing about time or class.
- Labels, MITRE answers, source file names and row numbers are only in the *_labels.parquet files. The alert files carry none of them.
- The frozen set was built and frozen on Week 1, Day 6 and stays closed to tuning and development. Reads go through src/eval_io.py, which logs every frozen access.

## Composition

| class | dev | frozen |
|---|---|---|
| Bot | 18 | 150 |
| DDoS | 18 | 150 |
| DoS GoldenEye | 18 | 150 |
| DoS Hulk | 18 | 150 |
| DoS Slowhttptest | 18 | 150 |
| DoS slowloris | 18 | 150 |
| FTP-Patator | 18 | 150 |
| PortScan | 18 | 150 |
| SSH-Patator | 17 | 149 |
| Web Attack - Brute Force | 17 | 149 |
| Web Attack - XSS/SQLi | 17 | 127 |
| BENIGN (detector false positives) | 105 | 875 |
| total | 300 | 2500 |

## Files

- *_alerts.parquet: alert_id, flow_row, flow_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, detector_score and 12 flow features.
- *_labels.parquet: label, is_attack, MITRE tactic, technique and accepted ids, source alert id, source file, row number. Read only by the evaluation harness.
- flow_store_dev.parquet and flow_store_frozen.parquet: every flow of the validation or test split without labels, for the agent's flow log tool. flow_row links an alert to its flow.
- mitre_map.csv: answer key from class to ATT&CK technique. Never given to the agent or to its MITRE lookup tool.
- MANIFEST.json: content hashes of every file, the threshold, the seed and the sizes.

## Known limitations

- The traffic is generated in a lab on a fixed weekly schedule. Attacker and victim IP addresses and attack times are well known for this dataset, so a language model may recognise attacks from them rather than from the traffic. An IP and time masked ablation is planned.
- CIC-IDS2017 has documented flow-construction and labelling problems (for example Engelen, Rimmer, Joosen, 2021). Some labels are noisy.
- Sets are class-balanced samples with a built-in 35% false positive share. They do not show real attack prevalence. Any false positive reduction is measured against this mix and must be reported with the detector's natural precision (0.70 at this threshold).
- The threshold is low, so the alert stream is large (115466 validation alerts). That is a design choice to keep small classes visible, not an operating recommendation.
- Small classes have few alerts. Per-class results for them rest on a few dozen alerts and carry wide uncertainty.
- MITRE labels are one reasonable mapping per class, with a list of accepted ids. DoS variants share one technique and the DDoS mapping is a judgment call. See mitre_map.csv.
- The detector score is part of every alert, so the agent sees what the detector thought. Alerts with high scores are mostly true positives, and the false positives sit at low scores. A score-masked ablation shows how much the agent leans on it.
- One fixed seed (42) and one draw. No resampling variance is reported.

## Integrity

Run python src/verify_eval.py to compare every file with MANIFEST.json.
