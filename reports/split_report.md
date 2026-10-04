# Split report

Input: C:\Users\laksh\Downloads\soc-triage-day1\soc-triage\data\processed\flows_clean.parquet
Rows: 2519415
Feature columns used for duplicate checks: 79
Split inside every (source file, label) group, in time order: 60% train, 20% validation, 20% test
Gap rows dropped after each boundary: 1.0% of the group

## Rows per split

| split | rows | share of kept rows | attack share | first time | last time |
|---|---|---|---|---|---|
| train | 1511650 | 61.2% | 16.9% | 2017-07-03 08:55:58 | 2017-07-07 16:12:00 |
| val | 478687 | 19.4% | 16.9% | 2017-07-03 13:14:13 | 2017-07-07 16:29:00 |
| test | 478692 | 19.4% | 16.9% | 2017-07-03 15:15:31 | 2017-07-07 17:02:00 |

Gap rows dropped at boundaries: 50386

## Rows per class per split

| label | train | val | test | gap dropped | total |
|---|---|---|---|---|---|
| BENIGN | 1256650 | 397939 | 397940 | 41888 | 2094417 |
| Bot | 1169 | 370 | 371 | 38 | 1948 |
| DDoS | 76807 | 24322 | 24322 | 2560 | 128011 |
| DoS GoldenEye | 6172 | 1954 | 1954 | 206 | 10286 |
| DoS Hulk | 103631 | 32816 | 32817 | 3454 | 172718 |
| DoS Slowhttptest | 3137 | 993 | 994 | 104 | 5228 |
| DoS slowloris | 3230 | 1023 | 1023 | 108 | 5384 |
| FTP-Patator | 3559 | 1127 | 1127 | 118 | 5931 |
| PortScan | 54078 | 17125 | 17125 | 1802 | 90130 |
| SSH-Patator | 1931 | 612 | 612 | 64 | 3219 |
| Web Attack - Brute Force | 882 | 279 | 279 | 30 | 1470 |
| Web Attack - XSS/SQLi | 404 | 127 | 128 | 14 | 673 |

## Rows per (source file, label) group

| source file | label | rows | train | val | test | gap |
|---|---|---|---|---|---|---|
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | BENIGN | 89723 | 53834 | 17047 | 17048 | 1794 |
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | DDoS | 128011 | 76807 | 24322 | 24322 | 2560 |
| Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | BENIGN | 114435 | 68661 | 21743 | 21743 | 2288 |
| Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | PortScan | 90130 | 54078 | 17125 | 17125 | 1802 |
| Friday-WorkingHours-Morning.pcap_ISCX.csv | BENIGN | 170989 | 102593 | 32488 | 32488 | 3420 |
| Friday-WorkingHours-Morning.pcap_ISCX.csv | Bot | 1948 | 1169 | 370 | 371 | 38 |
| Monday-WorkingHours.pcap_ISCX.csv | BENIGN | 502753 | 301652 | 95522 | 95523 | 10056 |
| Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | BENIGN | 241650 | 144990 | 45914 | 45914 | 4832 |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | BENIGN | 153992 | 92395 | 29259 | 29258 | 3080 |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | Web Attack - Brute Force | 1470 | 882 | 279 | 279 | 30 |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | Web Attack - XSS/SQLi | 673 | 404 | 127 | 128 | 14 |
| Tuesday-WorkingHours.pcap_ISCX.csv | BENIGN | 412386 | 247432 | 78353 | 78353 | 8248 |
| Tuesday-WorkingHours.pcap_ISCX.csv | FTP-Patator | 5931 | 3559 | 1127 | 1127 | 118 |
| Tuesday-WorkingHours.pcap_ISCX.csv | SSH-Patator | 3219 | 1931 | 612 | 612 | 64 |
| Wednesday-workingHours.pcap_ISCX.csv | BENIGN | 408489 | 245093 | 77613 | 77613 | 8170 |
| Wednesday-workingHours.pcap_ISCX.csv | DoS GoldenEye | 10286 | 6172 | 1954 | 1954 | 206 |
| Wednesday-workingHours.pcap_ISCX.csv | DoS Hulk | 172718 | 103631 | 32816 | 32817 | 3454 |
| Wednesday-workingHours.pcap_ISCX.csv | DoS Slowhttptest | 5228 | 3137 | 993 | 994 | 104 |
| Wednesday-workingHours.pcap_ISCX.csv | DoS slowloris | 5384 | 3230 | 1023 | 1023 | 108 |

## Leakage checks

- PASS: every row is in exactly one split or the gap (1511650 + 478687 + 478692 + 50386 = 2519415)
- PASS: no row appears in two splits
- PASS: inside every group train ends before val starts and val ends before test starts (0 problems)
- PASS: no identical feature vector in two splits (val in train 0, test in train 0, test in val 0)
- PASS: every class appears in train, val and test ([])
- PASS: every class has at least 50 rows in val and test ([])
- PASS: no NaN or inf in any feature column ([])

Saved 1511650 rows to C:\Users\laksh\Downloads\soc-triage-day1\soc-triage\data\processed\train.parquet

Saved 478687 rows to C:\Users\laksh\Downloads\soc-triage-day1\soc-triage\data\processed\val.parquet

Saved 478692 rows to C:\Users\laksh\Downloads\soc-triage-day1\soc-triage\data\processed\test.parquet

## Feature selection (train only)

Candidate numeric columns: 79
Excluded before selection: Flow ID, Source IP, Source Port, Destination IP, Timestamp, Label, source_file, original_row

### Constant columns in train (8)
- Bwd PSH Flags
- Bwd URG Flags
- Fwd Avg Bytes/Bulk
- Fwd Avg Packets/Bulk
- Fwd Avg Bulk Rate
- Bwd Avg Bytes/Bulk
- Bwd Avg Packets/Bulk
- Bwd Avg Bulk Rate

### Duplicate column
- Fwd Header Length.1 dropped. Identical to Fwd Header Length on train: True

### Correlated columns dropped (|corr| >= 0.99 on 500000 train rows)
- Total Backward Packets (kept Total Fwd Packets, corr 0.9992)
- Total Length of Bwd Packets (kept Total Fwd Packets, corr 0.9995)
- Fwd IAT Total (kept Flow Duration, corr 0.9982)
- Fwd IAT Max (kept Flow IAT Max, corr 0.9976)
- SYN Flag Count (kept Fwd PSH Flags, corr 1.0000)
- CWE Flag Count (kept Fwd URG Flags, corr 1.0000)
- ECE Flag Count (kept RST Flag Count, corr 1.0000)
- Average Packet Size (kept Packet Length Mean, corr 0.9980)
- Avg Fwd Segment Size (kept Fwd Packet Length Mean, corr 1.0000)
- Avg Bwd Segment Size (kept Bwd Packet Length Mean, corr 1.0000)
- Subflow Fwd Packets (kept Total Fwd Packets, corr 1.0000)
- Subflow Fwd Bytes (kept Total Length of Fwd Packets, corr 1.0000)
- Subflow Bwd Packets (kept Total Fwd Packets, corr 0.9992)
- Subflow Bwd Bytes (kept Total Fwd Packets, corr 0.9995)
- Idle Max (kept Idle Mean, corr 0.9903)
- Idle Min (kept Idle Mean, corr 0.9902)

### Final model features (54)

Candidates 79 - constant 8 - duplicate 1 - correlated 16 = 54
Note: the blueprint expected about 60 to 70. The count above comes from the data and the rules, so it is not an error.
1. Destination Port
2. Protocol
3. Flow Duration
4. Total Fwd Packets
5. Total Length of Fwd Packets
6. Fwd Packet Length Max
7. Fwd Packet Length Min
8. Fwd Packet Length Mean
9. Fwd Packet Length Std
10. Bwd Packet Length Max
11. Bwd Packet Length Min
12. Bwd Packet Length Mean
13. Bwd Packet Length Std
14. Flow Bytes/s
15. Flow Packets/s
16. Flow IAT Mean
17. Flow IAT Std
18. Flow IAT Max
19. Flow IAT Min
20. Fwd IAT Mean
21. Fwd IAT Std
22. Fwd IAT Min
23. Bwd IAT Total
24. Bwd IAT Mean
25. Bwd IAT Std
26. Bwd IAT Max
27. Bwd IAT Min
28. Fwd PSH Flags
29. Fwd URG Flags
30. Fwd Header Length
31. Bwd Header Length
32. Fwd Packets/s
33. Bwd Packets/s
34. Min Packet Length
35. Max Packet Length
36. Packet Length Mean
37. Packet Length Std
38. Packet Length Variance
39. FIN Flag Count
40. RST Flag Count
41. PSH Flag Count
42. ACK Flag Count
43. URG Flag Count
44. Down/Up Ratio
45. Init_Win_bytes_forward
46. Init_Win_bytes_backward
47. act_data_pkt_fwd
48. min_seg_size_forward
49. Active Mean
50. Active Std
51. Active Max
52. Active Min
53. Idle Mean
54. Idle Std

Saved C:\Users\laksh\Downloads\soc-triage-day1\soc-triage\models\feature_list.json

### Duplicate check on the model's own features

Rows in val identical to a train row: 0
Rows in test identical to a train or val row: 0

### Final rows per class per split

| label | train | val | test |
|---|---|---|---|
| BENIGN | 1256650 | 397939 | 397940 |
| Bot | 1169 | 370 | 371 |
| DDoS | 76807 | 24322 | 24322 |
| DoS GoldenEye | 6172 | 1954 | 1954 |
| DoS Hulk | 103631 | 32816 | 32817 |
| DoS Slowhttptest | 3137 | 993 | 994 |
| DoS slowloris | 3230 | 1023 | 1023 |
| FTP-Patator | 3559 | 1127 | 1127 |
| PortScan | 54078 | 17125 | 17125 |
| SSH-Patator | 1931 | 612 | 612 |
| Web Attack - Brute Force | 882 | 279 | 279 |
| Web Attack - XSS/SQLi | 404 | 127 | 128 |

### Display features for the agent alert (not used for training)
- Flow Duration
- Total Fwd Packets
- Total Backward Packets
- Total Length of Fwd Packets
- Total Length of Bwd Packets
- Flow Bytes/s
- Flow Packets/s
- Fwd Packet Length Mean
- Bwd Packet Length Mean
- Flow IAT Mean
- SYN Flag Count
- ACK Flag Count
