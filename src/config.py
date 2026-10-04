import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(PROJECT_ROOT, "data", "raw")
PROCESSED_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
EVAL_DIR = os.path.join(PROJECT_ROOT, "eval")

SEED = 42

LABEL_COLUMN = "Label"
IDENTIFIER_COLUMNS = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp"]
BOOKKEEPING_COLUMNS = ["source_file", "original_row"]
NON_FEATURE_COLUMNS = IDENTIFIER_COLUMNS + [LABEL_COLUMN] + BOOKKEEPING_COLUMNS
REQUIRED_COLUMNS = ["Flow ID", "Source IP", "Destination IP", "Timestamp", "Label"]

CAPTURE_YEAR = 2017
CAPTURE_MONTH = 7
DAY_OF_MONTH_BY_WEEKDAY = {
    "Monday": 3,
    "Tuesday": 4,
    "Wednesday": 5,
    "Thursday": 6,
    "Friday": 7,
}

WEB_ATTACK_NAMES = {
    "brute force": "Web Attack - Brute Force",
    "xss": "Web Attack - XSS",
    "sql injection": "Web Attack - SQL Injection",
}
DROPPED_CLASSES = ["Infiltration", "Heartbleed"]
MERGED_CLASSES = {
    "Web Attack - XSS": "Web Attack - XSS/SQLi",
    "Web Attack - SQL Injection": "Web Attack - XSS/SQLi",
}

MAX_CLASS_LOSS_PERCENT = 5.0
SMALL_CLASS_LIMIT = 1000

TRAIN_FRACTION = 0.60
VAL_FRACTION = 0.20
TEST_FRACTION = 0.20
BOUNDARY_TRIM_FRACTION = 0.01
MIN_ROWS_PER_SPLIT = 50
CORRELATION_LIMIT = 0.99

TARGET_RECALL = 0.95
DEV_CAP_PER_CLASS = 25
FROZEN_CAP_PER_CLASS = 200
FP_SHARE_MIN = 0.30
FP_SHARE_MAX = 0.50

CLEAN_PATH = os.path.join(PROCESSED_DIR, "flows_clean.parquet")
TRAIN_PATH = os.path.join(PROCESSED_DIR, "train.parquet")
VAL_PATH = os.path.join(PROCESSED_DIR, "val.parquet")
TEST_PATH = os.path.join(PROCESSED_DIR, "test.parquet")
FEATURE_LIST_PATH = os.path.join(MODELS_DIR, "feature_list.json")
SPLIT_REPORT_PATH = os.path.join(REPORTS_DIR, "split_report.md")

FEATURE_SAMPLE_ROWS = 500000
PROTECTED_FEATURES = ["Destination Port", "Protocol"]
DISPLAY_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow IAT Mean",
    "SYN Flag Count",
    "ACK Flag Count",
]

MODEL_PATH = os.path.join(MODELS_DIR, "detector_xgb.json")
DETECTOR_METRICS_PATH = os.path.join(REPORTS_DIR, "detector_metrics.json")
THRESHOLD_PATH = os.path.join(MODELS_DIR, "threshold.json")
THRESHOLD_REPORT_PATH = os.path.join(REPORTS_DIR, "threshold_report.md")

ALERTS_VAL_PATH = os.path.join(PROCESSED_DIR, "alerts_val.parquet")
ALERTS_TEST_PATH = os.path.join(PROCESSED_DIR, "alerts_test.parquet")
ALERTS_VAL_LABELS_PATH = os.path.join(PROCESSED_DIR, "alerts_val_labels.parquet")
ALERTS_TEST_LABELS_PATH = os.path.join(PROCESSED_DIR, "alerts_test_labels.parquet")

# data column -> name shown to the agent. Order is the column order in the alert file.
ALERT_ID_COLUMNS = {
    "Flow ID": "flow_id",
    "Timestamp": "timestamp",
    "Source IP": "src_ip",
    "Source Port": "src_port",
    "Destination IP": "dst_ip",
    "Destination Port": "dst_port",
    "Protocol": "protocol",
}
FORBIDDEN_ALERT_COLUMNS = ["Label", "label", "is_attack", "source_file", "original_row"]
THRESHOLD_GRID = [0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9, 0.95, 0.99, 0.999]
SCORE_CHECK_TOLERANCE = 1e-5

# ---------------------------------------------------------------- Day 6
# Threshold accepted at the end of Day 5. The build refuses to run if threshold.json disagrees.
ACCEPTED_THRESHOLD = 0.00459436746314168
ACCEPTED_VAL_ALERTS = 115466
ACCEPTED_VAL_FP = 34721

DEV_ALERTS_PATH = os.path.join(EVAL_DIR, "dev_alerts.parquet")
DEV_LABELS_PATH = os.path.join(EVAL_DIR, "dev_labels.parquet")
FROZEN_ALERTS_PATH = os.path.join(EVAL_DIR, "frozen_alerts.parquet")
FROZEN_LABELS_PATH = os.path.join(EVAL_DIR, "frozen_labels.parquet")
FLOW_STORE_DEV_PATH = os.path.join(EVAL_DIR, "flow_store_dev.parquet")
FLOW_STORE_FROZEN_PATH = os.path.join(EVAL_DIR, "flow_store_frozen.parquet")
MITRE_MAP_PATH = os.path.join(EVAL_DIR, "mitre_map.csv")
MANIFEST_PATH = os.path.join(EVAL_DIR, "MANIFEST.json")
DATASET_CARD_PATH = os.path.join(EVAL_DIR, "DATASET_CARD.md")
FROZEN_ACCESS_LOG = os.path.join(EVAL_DIR, "frozen_access.log")
BUILD_REPORT_PATH = os.path.join(REPORTS_DIR, "eval_build_report.md")

# Set sizes. The plan says dev "about 300" and frozen "2,000 to 3,000". The per-class caps above
# (DEV_CAP_PER_CLASS, FROZEN_CAP_PER_CLASS) stay as upper limits, but with 11 attack classes and an
# FP share of 0.30 to 0.50 they cannot all be reached at once, so the total size is the main target.
DEV_TARGET_SIZE = 300
FROZEN_TARGET_SIZE = 2500
SET_FP_SHARE = 0.35
MIN_DEV_PER_CLASS = 10
MIN_FROZEN_PER_CLASS = 50

FROZEN_UNLOCK_ENV = "SOC_FROZEN_UNLOCK"
FROZEN_UNLOCK_VALUE = "week1-day6"

# Answer key for MITRE accuracy. Read only by the evaluation harness. The Week 3 MITRE lookup tool
# must use a separate ATT&CK reference, never this file. IDs and names checked against attack.mitre.org.
MITRE_MAP = {
    "BENIGN": {
        "tactic": "NONE", "technique_id": "NONE", "technique_name": "NONE", "accepted": [],
        "note": "Not an attack. A correct verdict is is_malicious = false."},
    "Bot": {
        "tactic": "Command and Control", "technique_id": "T1071.001", "technique_name": "Application Layer Protocol: Web Protocols",
        "accepted": ["T1071", "T1071.001"],
        "note": "Ares botnet in CIC-IDS2017 talks to its C2 server over HTTP. Flows show beaconing only."},
    "DDoS": {
        "tactic": "Impact", "technique_id": "T1498", "technique_name": "Network Denial of Service",
        "accepted": ["T1498", "T1498.001", "T1499", "T1499.002"],
        "note": "Distributed flood. Judgment call: network flood versus HTTP service flood, so both families are accepted."},
    "DoS GoldenEye": {
        "tactic": "Impact", "technique_id": "T1499.002", "technique_name": "Endpoint Denial of Service: Service Exhaustion Flood",
        "accepted": ["T1499", "T1499.002"], "note": "HTTP keep-alive flood against the web server."},
    "DoS Hulk": {
        "tactic": "Impact", "technique_id": "T1499.002", "technique_name": "Endpoint Denial of Service: Service Exhaustion Flood",
        "accepted": ["T1499", "T1499.002"], "note": "HTTP flood with unique URLs."},
    "DoS Slowhttptest": {
        "tactic": "Impact", "technique_id": "T1499.002", "technique_name": "Endpoint Denial of Service: Service Exhaustion Flood",
        "accepted": ["T1499", "T1499.002"],
        "note": "Slow HTTP connection exhaustion. Judgment call: ATT&CK text names HTTP floods, not slow connections, but this is the closest technique."},
    "DoS slowloris": {
        "tactic": "Impact", "technique_id": "T1499.002", "technique_name": "Endpoint Denial of Service: Service Exhaustion Flood",
        "accepted": ["T1499", "T1499.002"], "note": "Slow partial HTTP requests. Same judgment call as Slowhttptest."},
    "FTP-Patator": {
        "tactic": "Credential Access", "technique_id": "T1110.001", "technique_name": "Brute Force: Password Guessing",
        "accepted": ["T1110", "T1110.001"], "note": "Password guessing against FTP."},
    "PortScan": {
        "tactic": "Discovery", "technique_id": "T1046", "technique_name": "Network Service Discovery",
        "accepted": ["T1046", "T1595", "T1595.001", "T1595.002"],
        "note": "Port scan. Active scanning IDs are accepted because the scanner is outside the victim network."},
    "SSH-Patator": {
        "tactic": "Credential Access", "technique_id": "T1110.001", "technique_name": "Brute Force: Password Guessing",
        "accepted": ["T1110", "T1110.001"], "note": "Password guessing against SSH."},
    "Web Attack - Brute Force": {
        "tactic": "Credential Access", "technique_id": "T1110.001", "technique_name": "Brute Force: Password Guessing",
        "accepted": ["T1110", "T1110.001"], "note": "Login guessing against a web application."},
    "Web Attack - XSS/SQLi": {
        "tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
        "accepted": ["T1190"], "note": "Merged class: cross-site scripting and SQL injection against the web application."},
}

# ---------------------------------------------------------------- Day 7
# Everything below is new. No Day 1-6 setting above was changed.
REPRO_REPORT_MD = os.path.join(REPORTS_DIR, "reproducibility_report.md")
REPRO_REPORT_JSON = os.path.join(REPORTS_DIR, "reproducibility_report.json")
SPOT_CHECK_CSV = os.path.join(REPORTS_DIR, "spot_check_30.csv")
SPOT_CHECK_MD = os.path.join(REPORTS_DIR, "spot_check_30.md")
SPOT_CHECK_SUMMARY = os.path.join(REPORTS_DIR, "spot_check_summary.json")
SPOT_CHECK_PER_CLASS = 2
SPOT_CHECK_BENIGN = 8
SPOT_CHECK_TOTAL = 30
SPOT_CHECK_WINDOW_MINUTES = 5
TEST_METRICS_JSON = os.path.join(REPORTS_DIR, "test_metrics.json")
TEST_METRICS_MD = os.path.join(REPORTS_DIR, "test_metrics.md")
TEST_EVAL_LOCK = os.path.join(REPORTS_DIR, "test_eval.lock")
WEEK1_REPORT_PATH = os.path.join(PROJECT_ROOT, "WEEK1_REPORT.md")
README_PATH = os.path.join(PROJECT_ROOT, "README.md")
HANDOFF_PATH = os.path.join(PROJECT_ROOT, "HANDOFF.md")
RUNBOOK_PATH = os.path.join(PROJECT_ROOT, "DAY7_RUNBOOK.md")
FREEZE_TAG = "week1-freeze"
GITIGNORE_REQUIRED = ["data/raw/", "data/processed/", "venv/", "__pycache__/", ".ipynb_checkpoints/", "eval/flow_store_*.parquet"]
MODEL_PR_AUC_TOLERANCE = 1e-6

# Where each attack class sits in the CIC-IDS2017 capture week (used only by the spot check).
EXPECTED_WEEKDAY_BY_LABEL = {
    "FTP-Patator": "Tuesday", "SSH-Patator": "Tuesday",
    "DoS slowloris": "Wednesday", "DoS Slowhttptest": "Wednesday", "DoS Hulk": "Wednesday", "DoS GoldenEye": "Wednesday",
    "Web Attack - Brute Force": "Thursday", "Web Attack - XSS/SQLi": "Thursday",
    "Bot": "Friday", "PortScan": "Friday", "DDoS": "Friday",
}
CLASS_HINTS = {
    "BENIGN": "A false positive: ordinary traffic the detector flagged. Nothing attack-like should be obvious.",
    "Bot": "Small periodic flows from an infected host to one outside server over HTTP (beaconing).",
    "DDoS": "Very many short flows to the same web server, often from several sources.",
    "DoS GoldenEye": "Many HTTP flows from one source to one web server, with keep-alive style long flows.",
    "DoS Hulk": "Very high rate of HTTP flows from one source to one web server.",
    "DoS Slowhttptest": "Long, slow flows to port 80 with very low packet rate.",
    "DoS slowloris": "Many long-lived, low-volume flows to port 80 from one source.",
    "FTP-Patator": "Many short flows from one source to port 21.",
    "PortScan": "Many tiny flows from one source to many different destination ports.",
    "SSH-Patator": "Many short flows from one source to port 22.",
    "Web Attack - Brute Force": "Many HTTP flows from one source to the web login page (port 80).",
    "Web Attack - XSS/SQLi": "HTTP flows from one source to the web application (port 80), few and larger than a scan.",
}
