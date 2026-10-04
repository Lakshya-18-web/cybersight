# Spot check: 30 dev alerts

Drawn from the dev set only (seeded). 2 alerts per attack class and 8 detector false positives. The frozen set was not opened.
Alert file has no label columns: yes.
For each alert decide whether the alert, its label and the context make sense together. Fill human_verdict (OK, PROBLEM or UNSURE) and notes in spot_check_30.csv, then run: python src/spot_check_alerts.py --finalize
A PROBLEM means something looks wrong with the data or the label. Do not fix it by editing the frozen files: report it.

## 1. DEV-0076 - Bot

- Source file: Friday-WorkingHours-Morning.pcap_ISCX.csv (attack)
- Timestamp 2017-07-07 11:21:00, 192.168.10.9:5474.0 -> 205.174.165.73:8080.0, protocol 6.0, detector score 0.00699
- Expected for this label: Small periodic flows from an infected host to one outside server over HTTP (beaconing).
- Context (same source, +/- 5 min, from the dev flow store): 63 flows, 7 distinct destination ports, 25 distinct destination IPs
- MITRE answer key: T1071.001 (accepted: T1071;T1071.001)
- Flow features: Flow Duration = 9.995e+05, Total Fwd Packets = 3, Total Backward Packets = 3, Total Length of Fwd Packets = 0, Total Length of Bwd Packets = 18, Flow Bytes/s = 18.01, Flow Packets/s = 6.003, Fwd Packet Length Mean = 0, Bwd Packet Length Mean = 6, Flow IAT Mean = 1.999e+05, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 2. DEV-0095 - Bot

- Source file: Friday-WorkingHours-Morning.pcap_ISCX.csv (attack)
- Timestamp 2017-07-07 10:50:00, 192.168.10.8:2994.0 -> 205.174.165.73:8080.0, protocol 6.0, detector score 0.96883
- Expected for this label: Small periodic flows from an infected host to one outside server over HTTP (beaconing).
- Context (same source, +/- 5 min, from the dev flow store): 41 flows, 8 distinct destination ports, 3 distinct destination IPs
- MITRE answer key: T1071.001 (accepted: T1071;T1071.001)
- Flow features: Flow Duration = 1.046e+05, Total Fwd Packets = 4, Total Backward Packets = 3, Total Length of Fwd Packets = 210, Total Length of Bwd Packets = 134, Flow Bytes/s = 3290, Flow Packets/s = 66.95, Fwd Packet Length Mean = 52.5, Bwd Packet Length Mean = 44.67, Flow IAT Mean = 1.743e+04, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 3. DEV-0185 - DDoS

- Source file: Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv (attack)
- Timestamp 2017-07-07 16:09:00, 172.16.0.1:55954.0 -> 192.168.10.50:80.0, protocol 6.0, detector score 0.99871
- Expected for this label: Very many short flows to the same web server, often from several sources.
- Context (same source, +/- 5 min, from the dev flow store): 24322 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1498 (accepted: T1498;T1498.001;T1499;T1499.002)
- Flow features: Flow Duration = 4.512e+04, Total Fwd Packets = 3, Total Backward Packets = 5, Total Length of Fwd Packets = 26, Total Length of Bwd Packets = 1.16e+04, Flow Bytes/s = 2.577e+05, Flow Packets/s = 177.3, Fwd Packet Length Mean = 8.667, Bwd Packet Length Mean = 2320, Flow IAT Mean = 6445, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 4. DEV-0199 - DDoS

- Source file: Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv (attack)
- Timestamp 2017-07-07 16:10:00, 172.16.0.1:33800.0 -> 192.168.10.50:80.0, protocol 6.0, detector score 0.99915
- Expected for this label: Very many short flows to the same web server, often from several sources.
- Context (same source, +/- 5 min, from the dev flow store): 24322 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1498 (accepted: T1498;T1498.001;T1499;T1499.002)
- Flow features: Flow Duration = 2.702e+05, Total Fwd Packets = 3, Total Backward Packets = 6, Total Length of Fwd Packets = 26, Total Length of Bwd Packets = 1.161e+04, Flow Bytes/s = 4.306e+04, Flow Packets/s = 33.31, Fwd Packet Length Mean = 8.667, Bwd Packet Length Mean = 1934, Flow IAT Mean = 3.377e+04, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 5. DEV-0091 - DoS GoldenEye

- Source file: Wednesday-workingHours.pcap_ISCX.csv (attack)
- Timestamp 2017-07-05 11:17:00, 172.16.0.1:40824.0 -> 192.168.10.50:80.0, protocol 6.0, detector score 0.97212
- Expected for this label: Many HTTP flows from one source to one web server, with keep-alive style long flows.
- Context (same source, +/- 5 min, from the dev flow store): 1954 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1499.002 (accepted: T1499;T1499.002)
- Flow features: Flow Duration = 1.6e+07, Total Fwd Packets = 2, Total Backward Packets = 0, Total Length of Fwd Packets = 0, Total Length of Bwd Packets = 0, Flow Bytes/s = 0, Flow Packets/s = 0.125, Fwd Packet Length Mean = 0, Bwd Packet Length Mean = 0, Flow IAT Mean = 1.6e+07, SYN Flag Count = 0, ACK Flag Count = 1
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 6. DEV-0258 - DoS GoldenEye

- Source file: Wednesday-workingHours.pcap_ISCX.csv (attack)
- Timestamp 2017-07-05 11:17:00, 172.16.0.1:40804.0 -> 192.168.10.50:80.0, protocol 6.0, detector score 0.99716
- Expected for this label: Many HTTP flows from one source to one web server, with keep-alive style long flows.
- Context (same source, +/- 5 min, from the dev flow store): 1954 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1499.002 (accepted: T1499;T1499.002)
- Flow features: Flow Duration = 1.058e+07, Total Fwd Packets = 10, Total Backward Packets = 7, Total Length of Fwd Packets = 1380, Total Length of Bwd Packets = 1.163e+04, Flow Bytes/s = 1230, Flow Packets/s = 1.607, Fwd Packet Length Mean = 138, Bwd Packet Length Mean = 1662, Flow IAT Mean = 6.612e+05, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 7. DEV-0159 - DoS Hulk

- Source file: Wednesday-workingHours.pcap_ISCX.csv (attack)
- Timestamp 2017-07-05 10:56:00, 172.16.0.1:38266.0 -> 192.168.10.50:80.0, protocol 6.0, detector score 0.99992
- Expected for this label: Very high rate of HTTP flows from one source to one web server.
- Context (same source, +/- 5 min, from the dev flow store): 32816 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1499.002 (accepted: T1499;T1499.002)
- Flow features: Flow Duration = 9.968e+07, Total Fwd Packets = 6, Total Backward Packets = 5, Total Length of Fwd Packets = 342, Total Length of Bwd Packets = 1.16e+04, Flow Bytes/s = 119.8, Flow Packets/s = 0.1104, Fwd Packet Length Mean = 57, Bwd Packet Length Mean = 2319, Flow IAT Mean = 9.968e+06, SYN Flag Count = 0, ACK Flag Count = 1
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 8. DEV-0173 - DoS Hulk

- Source file: Wednesday-workingHours.pcap_ISCX.csv (attack)
- Timestamp 2017-07-05 10:53:00, 172.16.0.1:47464.0 -> 192.168.10.50:80.0, protocol 6.0, detector score 0.99981
- Expected for this label: Very high rate of HTTP flows from one source to one web server.
- Context (same source, +/- 5 min, from the dev flow store): 32816 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1499.002 (accepted: T1499;T1499.002)
- Flow features: Flow Duration = 1.01e+08, Total Fwd Packets = 7, Total Backward Packets = 7, Total Length of Fwd Packets = 750, Total Length of Bwd Packets = 1.16e+04, Flow Bytes/s = 122.2, Flow Packets/s = 0.1386, Fwd Packet Length Mean = 107.1, Bwd Packet Length Mean = 1656, Flow IAT Mean = 7.772e+06, SYN Flag Count = 0, ACK Flag Count = 1
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 9. DEV-0015 - DoS Slowhttptest

- Source file: Wednesday-workingHours.pcap_ISCX.csv (attack)
- Timestamp 2017-07-05 10:32:00, 172.16.0.1:37738.0 -> 192.168.10.50:80.0, protocol 6.0, detector score 0.03784
- Expected for this label: Long, slow flows to port 80 with very low packet rate.
- Context (same source, +/- 5 min, from the dev flow store): 206 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1499.002 (accepted: T1499;T1499.002)
- Flow features: Flow Duration = 50, Total Fwd Packets = 1, Total Backward Packets = 2, Total Length of Fwd Packets = 1448, Total Length of Bwd Packets = 535, Flow Bytes/s = 3.97e+07, Flow Packets/s = 6e+04, Fwd Packet Length Mean = 1448, Bwd Packet Length Mean = 267.5, Flow IAT Mean = 25, SYN Flag Count = 0, ACK Flag Count = 1
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 10. DEV-0240 - DoS Slowhttptest

- Source file: Wednesday-workingHours.pcap_ISCX.csv (attack)
- Timestamp 2017-07-05 10:26:00, 172.16.0.1:38654.0 -> 192.168.10.50:80.0, protocol 6.0, detector score 0.95036
- Expected for this label: Long, slow flows to port 80 with very low packet rate.
- Context (same source, +/- 5 min, from the dev flow store): 918 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1499.002 (accepted: T1499;T1499.002)
- Flow features: Flow Duration = 6.313e+07, Total Fwd Packets = 7, Total Backward Packets = 0, Total Length of Fwd Packets = 0, Total Length of Bwd Packets = 0, Flow Bytes/s = 0, Flow Packets/s = 0.1109, Fwd Packet Length Mean = 0, Bwd Packet Length Mean = 0, Flow IAT Mean = 1.05e+07, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 11. DEV-0004 - DoS slowloris

- Source file: Wednesday-workingHours.pcap_ISCX.csv (attack)
- Timestamp 2017-07-05 10:05:00, 172.16.0.1:60212.0 -> 192.168.10.50:80.0, protocol 6.0, detector score 0.99726
- Expected for this label: Many long-lived, low-volume flows to port 80 from one source.
- Context (same source, +/- 5 min, from the dev flow store): 1023 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1499.002 (accepted: T1499;T1499.002)
- Flow features: Flow Duration = 1.057e+08, Total Fwd Packets = 16, Total Backward Packets = 3, Total Length of Fwd Packets = 2541, Total Length of Bwd Packets = 6, Flow Bytes/s = 24.1, Flow Packets/s = 0.1798, Fwd Packet Length Mean = 158.8, Bwd Packet Length Mean = 2, Flow IAT Mean = 5.872e+06, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 12. DEV-0229 - DoS slowloris

- Source file: Wednesday-workingHours.pcap_ISCX.csv (attack)
- Timestamp 2017-07-05 10:04:00, 172.16.0.1:59904.0 -> 192.168.10.50:80.0, protocol 6.0, detector score 0.99725
- Expected for this label: Many long-lived, low-volume flows to port 80 from one source.
- Context (same source, +/- 5 min, from the dev flow store): 1023 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1499.002 (accepted: T1499;T1499.002)
- Flow features: Flow Duration = 1.036e+08, Total Fwd Packets = 15, Total Backward Packets = 3, Total Length of Fwd Packets = 2541, Total Length of Bwd Packets = 6, Flow Bytes/s = 24.58, Flow Packets/s = 0.1737, Fwd Packet Length Mean = 169.4, Bwd Packet Length Mean = 2, Flow IAT Mean = 6.096e+06, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 13. DEV-0174 - FTP-Patator

- Source file: Tuesday-WorkingHours.pcap_ISCX.csv (attack)
- Timestamp 2017-07-04 10:02:00, 172.16.0.1:57768.0 -> 192.168.10.50:21.0, protocol 6.0, detector score 0.99552
- Expected for this label: Many short flows from one source to port 21.
- Context (same source, +/- 5 min, from the dev flow store): 1012 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1110.001 (accepted: T1110;T1110.001)
- Flow features: Flow Duration = 9.203e+06, Total Fwd Packets = 9, Total Backward Packets = 15, Total Length of Fwd Packets = 111, Total Length of Bwd Packets = 188, Flow Bytes/s = 32.49, Flow Packets/s = 2.608, Fwd Packet Length Mean = 12.33, Bwd Packet Length Mean = 12.53, Flow IAT Mean = 4.001e+05, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 14. DEV-0279 - FTP-Patator

- Source file: Tuesday-WorkingHours.pcap_ISCX.csv (attack)
- Timestamp 2017-07-04 10:04:00, 172.16.0.1:58048.0 -> 192.168.10.50:21.0, protocol 6.0, detector score 0.98808
- Expected for this label: Many short flows from one source to port 21.
- Context (same source, +/- 5 min, from the dev flow store): 839 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1110.001 (accepted: T1110;T1110.001)
- Flow features: Flow Duration = 250, Total Fwd Packets = 2, Total Backward Packets = 1, Total Length of Fwd Packets = 14, Total Length of Bwd Packets = 0, Flow Bytes/s = 5.6e+04, Flow Packets/s = 1.2e+04, Fwd Packet Length Mean = 7, Bwd Packet Length Mean = 0, Flow IAT Mean = 125, SYN Flag Count = 1, ACK Flag Count = 1
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 15. DEV-0125 - PortScan

- Source file: Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv (attack)
- Timestamp 2017-07-07 14:55:00, 172.16.0.1:37528.0 -> 192.168.10.50:6007.0, protocol 6.0, detector score 0.99265
- Expected for this label: Many tiny flows from one source to many different destination ports.
- Context (same source, +/- 5 min, from the dev flow store): 17126 flows, 997 distinct destination ports, 2 distinct destination IPs
- MITRE answer key: T1046 (accepted: T1046;T1595;T1595.001;T1595.002)
- Flow features: Flow Duration = 52, Total Fwd Packets = 1, Total Backward Packets = 1, Total Length of Fwd Packets = 0, Total Length of Bwd Packets = 6, Flow Bytes/s = 1.154e+05, Flow Packets/s = 3.846e+04, Fwd Packet Length Mean = 0, Bwd Packet Length Mean = 6, Flow IAT Mean = 52, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 16. DEV-0253 - PortScan

- Source file: Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv (attack)
- Timestamp 2017-07-07 14:55:00, 172.16.0.1:46816.0 -> 192.168.10.50:100.0, protocol 6.0, detector score 0.99266
- Expected for this label: Many tiny flows from one source to many different destination ports.
- Context (same source, +/- 5 min, from the dev flow store): 17126 flows, 997 distinct destination ports, 2 distinct destination IPs
- MITRE answer key: T1046 (accepted: T1046;T1595;T1595.001;T1595.002)
- Flow features: Flow Duration = 65, Total Fwd Packets = 1, Total Backward Packets = 1, Total Length of Fwd Packets = 0, Total Length of Bwd Packets = 6, Flow Bytes/s = 9.231e+04, Flow Packets/s = 3.077e+04, Fwd Packet Length Mean = 0, Bwd Packet Length Mean = 6, Flow IAT Mean = 65, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 17. DEV-0012 - SSH-Patator

- Source file: Tuesday-WorkingHours.pcap_ISCX.csv (attack)
- Timestamp 2017-07-04 14:52:00, 172.16.0.1:50552.0 -> 192.168.10.50:22.0, protocol 6.0, detector score 0.99546
- Expected for this label: Many short flows from one source to port 22.
- Context (same source, +/- 5 min, from the dev flow store): 547 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1110.001 (accepted: T1110;T1110.001)
- Flow features: Flow Duration = 1.154e+07, Total Fwd Packets = 22, Total Backward Packets = 32, Total Length of Fwd Packets = 2008, Total Length of Bwd Packets = 2745, Flow Bytes/s = 411.8, Flow Packets/s = 4.678, Fwd Packet Length Mean = 91.27, Bwd Packet Length Mean = 85.78, Flow IAT Mean = 2.178e+05, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 18. DEV-0096 - SSH-Patator

- Source file: Tuesday-WorkingHours.pcap_ISCX.csv (attack)
- Timestamp 2017-07-04 14:54:00, 172.16.0.1:50784.0 -> 192.168.10.50:22.0, protocol 6.0, detector score 0.99545
- Expected for this label: Many short flows from one source to port 22.
- Context (same source, +/- 5 min, from the dev flow store): 455 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1110.001 (accepted: T1110;T1110.001)
- Flow features: Flow Duration = 1.403e+07, Total Fwd Packets = 21, Total Backward Packets = 32, Total Length of Fwd Packets = 2008, Total Length of Bwd Packets = 2745, Flow Bytes/s = 338.7, Flow Packets/s = 3.777, Fwd Packet Length Mean = 95.62, Bwd Packet Length Mean = 85.78, Flow IAT Mean = 2.699e+05, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 19. DEV-0170 - Web Attack - Brute Force

- Source file: Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv (attack)
- Timestamp 2017-07-06 09:47:00, 172.16.0.1:40634.0 -> 192.168.10.50:80.0, protocol 6.0, detector score 0.98176
- Expected for this label: Many HTTP flows from one source to the web login page (port 80).
- Context (same source, +/- 5 min, from the dev flow store): 279 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1110.001 (accepted: T1110;T1110.001)
- Flow features: Flow Duration = 5.982e+06, Total Fwd Packets = 3, Total Backward Packets = 1, Total Length of Fwd Packets = 0, Total Length of Bwd Packets = 0, Flow Bytes/s = 0, Flow Packets/s = 0.6687, Fwd Packet Length Mean = 0, Bwd Packet Length Mean = 0, Flow IAT Mean = 1.994e+06, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 20. DEV-0217 - Web Attack - Brute Force

- Source file: Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv (attack)
- Timestamp 2017-07-06 09:45:00, 172.16.0.1:38588.0 -> 192.168.10.50:80.0, protocol 6.0, detector score 0.98176
- Expected for this label: Many HTTP flows from one source to the web login page (port 80).
- Context (same source, +/- 5 min, from the dev flow store): 226 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1110.001 (accepted: T1110;T1110.001)
- Flow features: Flow Duration = 5.924e+06, Total Fwd Packets = 3, Total Backward Packets = 1, Total Length of Fwd Packets = 0, Total Length of Bwd Packets = 0, Flow Bytes/s = 0, Flow Packets/s = 0.6752, Fwd Packet Length Mean = 0, Bwd Packet Length Mean = 0, Flow IAT Mean = 1.975e+06, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 21. DEV-0036 - Web Attack - XSS/SQLi

- Source file: Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv (attack)
- Timestamp 2017-07-06 10:31:00, 172.16.0.1:34010.0 -> 192.168.10.50:80.0, protocol 6.0, detector score 0.98176
- Expected for this label: HTTP flows from one source to the web application (port 80), few and larger than a scan.
- Context (same source, +/- 5 min, from the dev flow store): 127 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1190 (accepted: T1190)
- Flow features: Flow Duration = 5.46e+06, Total Fwd Packets = 3, Total Backward Packets = 1, Total Length of Fwd Packets = 0, Total Length of Bwd Packets = 0, Flow Bytes/s = 0, Flow Packets/s = 0.7325, Fwd Packet Length Mean = 0, Bwd Packet Length Mean = 0, Flow IAT Mean = 1.82e+06, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 22. DEV-0166 - Web Attack - XSS/SQLi

- Source file: Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv (attack)
- Timestamp 2017-07-06 10:29:00, 172.16.0.1:60762.0 -> 192.168.10.50:80.0, protocol 6.0, detector score 0.98176
- Expected for this label: HTTP flows from one source to the web application (port 80), few and larger than a scan.
- Context (same source, +/- 5 min, from the dev flow store): 127 flows, 1 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: T1190 (accepted: T1190)
- Flow features: Flow Duration = 5.198e+06, Total Fwd Packets = 3, Total Backward Packets = 1, Total Length of Fwd Packets = 0, Total Length of Bwd Packets = 0, Flow Bytes/s = 0, Flow Packets/s = 0.7696, Fwd Packet Length Mean = 0, Bwd Packet Length Mean = 0, Flow IAT Mean = 1.733e+06, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 23. DEV-0053 - BENIGN

- Source file: Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv (false positive of the detector)
- Timestamp 2017-07-07 14:48:00, 192.168.10.15:56468.0 -> 205.174.165.73:8080.0, protocol 6.0, detector score 0.00798
- Expected for this label: A false positive: ordinary traffic the detector flagged. Nothing attack-like should be obvious.
- Context (same source, +/- 5 min, from the dev flow store): 670 flows, 10 distinct destination ports, 124 distinct destination IPs
- MITRE answer key: NONE (accepted: NONE)
- Flow features: Flow Duration = 1.03e+06, Total Fwd Packets = 3, Total Backward Packets = 3, Total Length of Fwd Packets = 0, Total Length of Bwd Packets = 18, Flow Bytes/s = 17.48, Flow Packets/s = 5.828, Fwd Packet Length Mean = 0, Bwd Packet Length Mean = 6, Flow IAT Mean = 2.059e+05, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 24. DEV-0054 - BENIGN

- Source file: Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv (false positive of the detector)
- Timestamp 2017-07-06 15:29:00, 192.168.10.8:34036.0 -> 192.168.10.16:8193.0, protocol 6.0, detector score 0.00569
- Expected for this label: A false positive: ordinary traffic the detector flagged. Nothing attack-like should be obvious.
- Context (same source, +/- 5 min, from the dev flow store): 8065 flows, 1040 distinct destination ports, 51 distinct destination IPs
- MITRE answer key: NONE (accepted: NONE)
- Flow features: Flow Duration = 62, Total Fwd Packets = 2, Total Backward Packets = 2, Total Length of Fwd Packets = 4, Total Length of Bwd Packets = 12, Flow Bytes/s = 2.581e+05, Flow Packets/s = 6.452e+04, Fwd Packet Length Mean = 2, Bwd Packet Length Mean = 6, Flow IAT Mean = 20.67, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 25. DEV-0056 - BENIGN

- Source file: Wednesday-workingHours.pcap_ISCX.csv (false positive of the detector)
- Timestamp 2017-07-05 14:45:00, 192.168.10.17:33350.0 -> 169.55.70.227:443.0, protocol 6.0, detector score 0.00705
- Expected for this label: A false positive: ordinary traffic the detector flagged. Nothing attack-like should be obvious.
- Context (same source, +/- 5 min, from the dev flow store): 903 flows, 9 distinct destination ports, 167 distinct destination IPs
- MITRE answer key: NONE (accepted: NONE)
- Flow features: Flow Duration = 153, Total Fwd Packets = 2, Total Backward Packets = 0, Total Length of Fwd Packets = 0, Total Length of Bwd Packets = 0, Flow Bytes/s = 0, Flow Packets/s = 1.307e+04, Fwd Packet Length Mean = 0, Bwd Packet Length Mean = 0, Flow IAT Mean = 153, SYN Flag Count = 0, ACK Flag Count = 1
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 26. DEV-0073 - BENIGN

- Source file: Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv (false positive of the detector)
- Timestamp 2017-07-06 15:27:00, 192.168.10.8:42452.0 -> 192.168.10.12:3324.0, protocol 6.0, detector score 0.00630
- Expected for this label: A false positive: ordinary traffic the detector flagged. Nothing attack-like should be obvious.
- Context (same source, +/- 5 min, from the dev flow store): 6712 flows, 1034 distinct destination ports, 21 distinct destination IPs
- MITRE answer key: NONE (accepted: NONE)
- Flow features: Flow Duration = 112, Total Fwd Packets = 2, Total Backward Packets = 2, Total Length of Fwd Packets = 4, Total Length of Bwd Packets = 12, Flow Bytes/s = 1.429e+05, Flow Packets/s = 3.571e+04, Fwd Packet Length Mean = 2, Bwd Packet Length Mean = 6, Flow IAT Mean = 37.33, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 27. DEV-0075 - BENIGN

- Source file: Tuesday-WorkingHours.pcap_ISCX.csv (false positive of the detector)
- Timestamp 2017-07-04 15:00:00, 192.168.10.19:42016.0 -> 104.196.48.127:443.0, protocol 6.0, detector score 0.03517
- Expected for this label: A false positive: ordinary traffic the detector flagged. Nothing attack-like should be obvious.
- Context (same source, +/- 5 min, from the dev flow store): 1842 flows, 9 distinct destination ports, 264 distinct destination IPs
- MITRE answer key: NONE (accepted: NONE)
- Flow features: Flow Duration = 673, Total Fwd Packets = 2, Total Backward Packets = 0, Total Length of Fwd Packets = 0, Total Length of Bwd Packets = 0, Flow Bytes/s = 0, Flow Packets/s = 2972, Fwd Packet Length Mean = 0, Bwd Packet Length Mean = 0, Flow IAT Mean = 673, SYN Flag Count = 0, ACK Flag Count = 1
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 28. DEV-0158 - BENIGN

- Source file: Friday-WorkingHours-Morning.pcap_ISCX.csv (false positive of the detector)
- Timestamp 2017-07-07 11:06:00, 192.168.10.50:21.0 -> 192.168.10.5:50218.0, protocol 6.0, detector score 0.00522
- Expected for this label: A false positive: ordinary traffic the detector flagged. Nothing attack-like should be obvious.
- Context (same source, +/- 5 min, from the dev flow store): 123 flows, 47 distinct destination ports, 13 distinct destination IPs
- MITRE answer key: NONE (accepted: NONE)
- Flow features: Flow Duration = 95, Total Fwd Packets = 1, Total Backward Packets = 3, Total Length of Fwd Packets = 6, Total Length of Bwd Packets = 18, Flow Bytes/s = 2.526e+05, Flow Packets/s = 4.211e+04, Fwd Packet Length Mean = 6, Bwd Packet Length Mean = 6, Flow IAT Mean = 31.67, SYN Flag Count = 0, ACK Flag Count = 1
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 29. DEV-0194 - BENIGN

- Source file: Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv (false positive of the detector)
- Timestamp 2017-07-06 15:38:00, 192.168.10.8:38739.0 -> 192.168.10.16:3071.0, protocol 6.0, detector score 0.00606
- Expected for this label: A false positive: ordinary traffic the detector flagged. Nothing attack-like should be obvious.
- Context (same source, +/- 5 min, from the dev flow store): 10770 flows, 1044 distinct destination ports, 177 distinct destination IPs
- MITRE answer key: NONE (accepted: NONE)
- Flow features: Flow Duration = 120, Total Fwd Packets = 2, Total Backward Packets = 2, Total Length of Fwd Packets = 4, Total Length of Bwd Packets = 12, Flow Bytes/s = 1.333e+05, Flow Packets/s = 3.333e+04, Fwd Packet Length Mean = 2, Bwd Packet Length Mean = 6, Flow IAT Mean = 40, SYN Flag Count = 0, ACK Flag Count = 0
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)

## 30. DEV-0218 - BENIGN

- Source file: Wednesday-workingHours.pcap_ISCX.csv (false positive of the detector)
- Timestamp 2017-07-05 15:03:00, 117.53.117.16:80.0 -> 192.168.10.19:47952.0, protocol 6.0, detector score 0.03396
- Expected for this label: A false positive: ordinary traffic the detector flagged. Nothing attack-like should be obvious.
- Context (same source, +/- 5 min, from the dev flow store): 29 flows, 29 distinct destination ports, 1 distinct destination IPs
- MITRE answer key: NONE (accepted: NONE)
- Flow features: Flow Duration = 59, Total Fwd Packets = 1, Total Backward Packets = 1, Total Length of Fwd Packets = 6, Total Length of Bwd Packets = 6, Flow Bytes/s = 2.034e+05, Flow Packets/s = 3.39e+04, Fwd Packet Length Mean = 6, Bwd Packet Length Mean = 6, Flow IAT Mean = 59, SYN Flag Count = 0, ACK Flag Count = 1
- Automatic checks: all passed
- Your verdict: OK / PROBLEM / UNSURE (write it in the csv)
