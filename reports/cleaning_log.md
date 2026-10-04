# Cleaning log

## Step 1 to 4: load, label fix, timestamps, numeric conversion

| file | raw rows | empty rows | kept | unparsed timestamps | wrong date | inf values | first time | last time |
|---|---|---|---|---|---|---|---|---|
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | 225745 | 0 | 225745 | 0 | 0 | 64 | 2017-07-07 15:30:00 | 2017-07-07 17:02:00 |
| Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | 286467 | 0 | 286467 | 0 | 0 | 727 | 2017-07-07 13:00:00 | 2017-07-07 15:29:00 |
| Friday-WorkingHours-Morning.pcap_ISCX.csv | 191033 | 0 | 191033 | 0 | 0 | 216 | 2017-07-07 08:59:00 | 2017-07-07 12:59:00 |
| Monday-WorkingHours.pcap_ISCX.csv | 529918 | 0 | 529918 | 0 | 0 | 810 | 2017-07-03 08:55:58 | 2017-07-03 17:01:34 |
| Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | 288602 | 0 | 288602 | 0 | 0 | 396 | 2017-07-06 13:00:00 | 2017-07-06 17:04:00 |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 458968 | 288602 | 170366 | 0 | 0 | 250 | 2017-07-06 08:59:00 | 2017-07-06 12:59:00 |
| Tuesday-WorkingHours.pcap_ISCX.csv | 445909 | 0 | 445909 | 0 | 0 | 327 | 2017-07-04 08:53:00 | 2017-07-04 17:00:00 |
| Wednesday-workingHours.pcap_ISCX.csv | 692703 | 0 | 692703 | 0 | 0 | 1586 | 2017-07-05 08:42:00 | 2017-07-05 17:10:00 |

Raw rows: 3119345
Completely empty rows removed: 288602
Rows with data: 2830743
Feature columns: 79
Labels after fixing: ['BENIGN', 'Bot', 'DDoS', 'DoS GoldenEye', 'DoS Hulk', 'DoS Slowhttptest', 'DoS slowloris', 'FTP-Patator', 'Heartbleed', 'Infiltration', 'PortScan', 'SSH-Patator', 'Web Attack - Brute Force', 'Web Attack - SQL Injection', 'Web Attack - XSS']

After load, label fix, timestamps, numeric: 2830743 rows

## Step 5: rows with NaN or inf in a feature
- Flow Bytes/s: 2867
- Flow Packets/s: 2867
- BENIGN lost 1777 of 2273097 (0.08%)
- DoS Hulk lost 949 of 231073 (0.41%)
- PortScan lost 126 of 158930 (0.08%)
- DDoS lost 2 of 128027 (0.00%)
- DoS GoldenEye lost 0 of 10293 (0.00%)
- FTP-Patator lost 3 of 7938 (0.04%)
- SSH-Patator lost 0 of 5897 (0.00%)
- DoS slowloris lost 0 of 5796 (0.00%)
- DoS Slowhttptest lost 0 of 5499 (0.00%)
- Bot lost 10 of 1966 (0.51%)
- Web Attack - Brute Force lost 0 of 1507 (0.00%)
- Web Attack - XSS lost 0 of 652 (0.00%)
- Infiltration lost 0 of 36 (0.00%)
- Web Attack - SQL Injection lost 0 of 21 (0.00%)
- Heartbleed lost 0 of 11 (0.00%)

After NaN drop: 2827876 rows

## Step 6: rows missing a required field
Rows dropped: 0

After required fields: 2827876 rows

## Step 7: exact duplicate rows
Rows dropped: 199

After exact duplicates: 2827677 rows

## Step 8: negative value audit
- Init_Win_bytes_backward: 1439475 negative values
- Init_Win_bytes_forward: 1001172 negative values
- Flow IAT Min: 2890 negative values
- Flow Duration: 115 negative values
- Flow Packets/s: 115 negative values
- Flow IAT Mean: 115 negative values
- Flow IAT Max: 115 negative values
- Flow Bytes/s: 85 negative values
- Fwd Header Length: 35 negative values
- Fwd Header Length.1: 35 negative values
- min_seg_size_forward: 35 negative values
- Bwd Header Length: 22 negative values
- Fwd IAT Min: 17 negative values
Rows dropped for negative Flow Duration: 115

After negative duration: 2827562 rows

## Step 9: dropped and merged classes
- dropping Infiltration: 36 rows
- dropping Heartbleed: 11 rows
- merging Web Attack - XSS into Web Attack - XSS/SQLi: 652 rows
- merging Web Attack - SQL Injection into Web Attack - XSS/SQLi: 21 rows

After class drop and merge: 2827515 rows

## Step 10: feature-vector duplicates
Rows with identical features but different labels (all copies dropped): 6664
- DoS Hulk: 4872
- PortScan: 1053
- BENIGN: 732
- DDoS: 6
- DoS slowloris: 1
Repeated identical vectors with the same label dropped: 301436

After feature-vector dedupe: 2519415 rows

## Class check
- BENIGN: 2094417
- DoS Hulk: 172718
- DDoS: 128011
- PortScan: 90130
- DoS GoldenEye: 10286
- FTP-Patator: 5931
- DoS slowloris: 5384
- DoS Slowhttptest: 5228
- SSH-Patator: 3219
- Bot: 1948
- Web Attack - Brute Force: 1470
- Web Attack - XSS/SQLi: 673  <-- under 1000, review

## Rows per class after every step

| label | load, label fix, timestamps, numeric | NaN drop | required fields | exact duplicates | negative duration | class drop and merge | feature-vector dedupe |
|---|---|---|---|---|---|---|---|
| BENIGN | 2273097 | 2271320 | 2271320 | 2271122 | 2271007 | 2271007 | 2094417 |
| Bot | 1966 | 1956 | 1956 | 1956 | 1956 | 1956 | 1948 |
| DDoS | 128027 | 128025 | 128025 | 128025 | 128025 | 128025 | 128011 |
| DoS GoldenEye | 10293 | 10293 | 10293 | 10293 | 10293 | 10293 | 10286 |
| DoS Hulk | 231073 | 230124 | 230124 | 230123 | 230123 | 230123 | 172718 |
| DoS Slowhttptest | 5499 | 5499 | 5499 | 5499 | 5499 | 5499 | 5228 |
| DoS slowloris | 5796 | 5796 | 5796 | 5796 | 5796 | 5796 | 5384 |
| FTP-Patator | 7938 | 7935 | 7935 | 7935 | 7935 | 7935 | 5931 |
| Heartbleed | 11 | 11 | 11 | 11 | 11 | 0 | 0 |
| Infiltration | 36 | 36 | 36 | 36 | 36 | 0 | 0 |
| PortScan | 158930 | 158804 | 158804 | 158804 | 158804 | 158804 | 90130 |
| SSH-Patator | 5897 | 5897 | 5897 | 5897 | 5897 | 5897 | 3219 |
| Web Attack - Brute Force | 1507 | 1507 | 1507 | 1507 | 1507 | 1507 | 1470 |
| Web Attack - SQL Injection | 21 | 21 | 21 | 21 | 21 | 0 | 0 |
| Web Attack - XSS | 652 | 652 | 652 | 652 | 652 | 0 | 0 |
| Web Attack - XSS/SQLi | 0 | 0 | 0 | 0 | 0 | 673 | 673 |

Saved 2519415 rows and 87 columns to C:\Users\laksh\Downloads\soc-triage-day1\soc-triage\data\processed\flows_clean.parquet
