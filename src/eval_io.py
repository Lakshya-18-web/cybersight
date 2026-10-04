"""Loaders for the evaluation sets.

Use these functions instead of reading eval/*.parquet directly.
- Dev files load freely.
- Frozen files load only when the environment variable SOC_FROZEN_UNLOCK is set to "week1-day6" and a reason is given.
  Every frozen read is appended to eval/frozen_access.log, so the log shows how often the frozen set was opened.
- Labels and the MITRE answer key are for the evaluation harness only. Agent code must never import them.
"""
import os
import sys
import datetime
import pandas as pd

import config

_PATHS = {
    ("dev", "alerts"): config.DEV_ALERTS_PATH,
    ("dev", "labels"): config.DEV_LABELS_PATH,
    ("dev", "flows"): config.FLOW_STORE_DEV_PATH,
    ("frozen", "alerts"): config.FROZEN_ALERTS_PATH,
    ("frozen", "labels"): config.FROZEN_LABELS_PATH,
    ("frozen", "flows"): config.FLOW_STORE_FROZEN_PATH,
}


def _guard(which, kind, reason):
    if which not in ("dev", "frozen"):
        raise ValueError("which must be 'dev' or 'frozen'")
    if which == "dev":
        return
    if os.environ.get(config.FROZEN_UNLOCK_ENV) != config.FROZEN_UNLOCK_VALUE:
        raise PermissionError("The frozen set was frozen at the Week 1, Day 6 build and is closed to tuning and development. Set " + config.FROZEN_UNLOCK_ENV + "=" + config.FROZEN_UNLOCK_VALUE
                              + " only for the final evaluation runs.")
    if reason is None or len(reason.strip()) < 5:
        raise ValueError("Give a reason of a few words for opening the frozen set, for example reason='final run 1 of 3: full system'.")
    os.makedirs(config.EVAL_DIR, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    caller = os.path.basename(sys.argv[0]) if len(sys.argv) > 0 else "unknown"
    with open(config.FROZEN_ACCESS_LOG, "a", encoding="utf-8") as f:
        f.write(stamp + "\t" + kind + "\t" + caller + "\t" + reason.strip() + "\n")


def _load(which, kind, reason):
    _guard(which, kind, reason)
    return pd.read_parquet(_PATHS[(which, kind)])


def load_alerts(which, reason=None):
    """Alerts the agent may see: no label, no file name, no row number."""
    return _load(which, "alerts", reason)


def load_flow_store(which, reason=None):
    """Unlabelled flows for the flow log tool. dev uses validation flows, frozen uses test flows."""
    return _load(which, "flows", reason)


def load_labels(which, reason=None):
    """Ground truth. Evaluation harness only."""
    return _load(which, "labels", reason)


def load_mitre_map():
    """Answer key. Evaluation harness only."""
    return pd.read_csv(config.MITRE_MAP_PATH)
