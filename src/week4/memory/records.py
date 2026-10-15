"""Turning training flows into memory records, and an alert into a query vector. Pure functions over a DataFrame / dict; no file reading here.

Fingerprint (vec-v1): the 12 display features (log1p of the non-negative value, then standardised with the mean and standard deviation of the seeded records),
plus flags for the destination port (21, 22, 53, 80, 443, other well-known <1024, 1024 and above) and the protocol (TCP, UDP, other). 22 numbers per flow.
The detector score is NOT part of the fingerprint: it is in-sample for training flows, so it would not mean the same thing for a new alert.
These choices are fixed up front, not tuned on any data. The same code path builds the training matrix and the query vector.
"""
import hashlib
import json

import numpy as np
import pandas as pd

import config
import verdict_schema

from .errors import MemoryDataError, MemoryQueryError

VECTOR_SPEC = "vec-v1"
SPLIT = "train"
NUMERIC_FEATURES = list(config.DISPLAY_FEATURES)            # names are identical in the train file and in an alert
KNOWN_PORTS = (21, 22, 53, 80, 443)
PORT_FLAGS = ["port_" + str(p) for p in KNOWN_PORTS] + ["port_other_well_known", "port_1024_or_above"]
PROTOCOL_FLAGS = ["protocol_tcp", "protocol_udp", "protocol_other"]
FEATURE_NAMES = NUMERIC_FEATURES + PORT_FLAGS + PROTOCOL_FLAGS
DIM = len(FEATURE_NAMES)
N_NUMERIC = len(NUMERIC_FEATURES)

TRAIN_ID_COLUMNS = ["source_file", "original_row"]
TRAIN_LABEL = "Label"
TRAIN_KEY_COLUMNS = ["Flow ID", "Timestamp", "Source IP", "Source Port", "Destination IP"]
TRAIN_PORT, TRAIN_PROTOCOL = "Destination Port", "Protocol"
REQUIRED_TRAIN_COLUMNS = TRAIN_ID_COLUMNS + [TRAIN_LABEL] + TRAIN_KEY_COLUMNS + [TRAIN_PORT, TRAIN_PROTOCOL] + NUMERIC_FEATURES
ALERT_KEY_FIELDS = ["flow_id", "timestamp", "src_ip", "src_port", "dst_ip"]


def _finite_column(series):
    """float64 values, NaN for anything missing, non-numeric, boolean or not finite."""
    if series.dtype == bool:
        return np.full(len(series), np.nan)
    values = np.array(pd.to_numeric(series, errors="coerce").to_numpy(dtype=np.float64, na_value=np.nan), dtype=np.float64, copy=True)
    values[~np.isfinite(values)] = np.nan
    return values


def raw_matrix(columns, port, protocol):
    """(n x 22 matrix, valid mask). columns: feature name -> array-like of length n. A row with any missing or non-finite input is invalid (its numbers are not used)."""
    n = len(port)
    cols = [_finite_column(pd.Series(columns[name])) for name in NUMERIC_FEATURES]
    p, pr = _finite_column(pd.Series(port)), _finite_column(pd.Series(protocol))
    valid = ~(np.isnan(np.stack(cols, axis=1)).any(axis=1) | np.isnan(p) | np.isnan(pr))
    out = np.zeros((n, DIM), dtype=np.float64)
    for i, v in enumerate(cols):
        out[:, i] = np.log1p(np.clip(np.nan_to_num(v), 0.0, None))
    pi = np.nan_to_num(p).astype(np.int64)
    pri = np.nan_to_num(pr).astype(np.int64)
    for j, k in enumerate(KNOWN_PORTS):
        out[:, N_NUMERIC + j] = (pi == k)
    known = np.isin(pi, KNOWN_PORTS)
    out[:, N_NUMERIC + len(KNOWN_PORTS)] = (pi < 1024) & ~known
    out[:, N_NUMERIC + len(KNOWN_PORTS) + 1] = (pi >= 1024)
    base = N_NUMERIC + len(PORT_FLAGS)
    out[:, base] = (pri == 6)
    out[:, base + 1] = (pri == 17)
    out[:, base + 2] = ~np.isin(pri, (6, 17))
    return out, valid


def fit_scaler(raw):
    """Mean and standard deviation of the numeric part (flags stay 0/1). A constant column gets std 1 so it contributes nothing."""
    mean = raw[:, :N_NUMERIC].mean(axis=0)
    std = raw[:, :N_NUMERIC].std(axis=0)
    std = np.where(std < 1e-12, 1.0, std)
    return {"mean": [float(x) for x in mean], "std": [float(x) for x in std]}


def apply_scaler(raw, scaler):
    out = np.array(raw, dtype=np.float64, copy=True)
    out[..., :N_NUMERIC] = (out[..., :N_NUMERIC] - np.array(scaler["mean"])) / np.array(scaler["std"])
    return out


def vector_sha256(vec):
    return hashlib.sha256(np.ascontiguousarray(vec, dtype=np.float64).tobytes()).hexdigest()


def query_vector(alert, scaler):
    """The scaled query vector for an alert dict (alert field names). Raises MemoryQueryError when something needed is missing."""
    if not isinstance(alert, dict):
        raise MemoryQueryError("the alert is not a mapping")
    cols = {name: [alert.get(name)] for name in NUMERIC_FEATURES}
    raw, valid = raw_matrix(cols, [alert.get("dst_port")], [alert.get("protocol")])
    if not valid[0]:
        raise MemoryQueryError("the alert is missing a flow feature, the destination port or the protocol, or one is not a finite number")
    return apply_scaler(raw[0], scaler)


# ----------------------------------------------------------------------------- flow keys (no addresses are stored; only this text is hashed)
def flow_key_text(flow_id, timestamp, src_ip, src_port, dst_ip):
    """'flow_id|YYYY-mm-dd HH:MM:SS|src_ip|src_port|dst_ip', or None when any part is missing."""
    parts = [flow_id, timestamp, src_ip, src_port, dst_ip]
    if any(p is None or (isinstance(p, float) and p != p) for p in parts):
        return None
    try:
        stamp = pd.Timestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        port = int(float(src_port))
    except (ValueError, TypeError):
        return None
    return "|".join([str(flow_id), stamp, str(src_ip), str(port), str(dst_ip)])


def key_hash(text):
    return None if text is None else hashlib.sha256(text.encode("utf-8")).hexdigest()


def alert_flow_key_text(alert):
    return flow_key_text(*[alert.get(k) for k in ALERT_KEY_FIELDS])


def frame_key_texts(df):
    """flow_key_text for every row of a training frame (None for an unusable row), vectorised."""
    ts = pd.to_datetime(df["Timestamp"], errors="coerce")
    port = pd.to_numeric(df["Source Port"], errors="coerce")
    ok = ts.notna() & port.notna() & df["Flow ID"].notna() & df["Source IP"].notna() & df["Destination IP"].notna()
    text = (df["Flow ID"].astype(str) + "|" + ts.dt.strftime("%Y-%m-%d %H:%M:%S") + "|" + df["Source IP"].astype(str) + "|"
            + port.fillna(0).astype("int64").astype(str) + "|" + df["Destination IP"].astype(str))
    return text.where(ok, None).tolist()


# ----------------------------------------------------------------------------- training frame -> candidates -> selection
def validate_train_frame(df):
    if not isinstance(df, pd.DataFrame):
        raise MemoryDataError("the training data is not a table")
    missing = [c for c in REQUIRED_TRAIN_COLUMNS if c not in df.columns]
    if missing:
        raise MemoryDataError("the training table is missing columns: " + ", ".join(missing))
    if len(df) == 0:
        raise MemoryDataError("the training table has no rows")
    bad = sorted(set(df[TRAIN_LABEL].dropna().astype(str)) - set(verdict_schema.ATTACK_TYPES))
    if bad:
        raise MemoryDataError("the training table has labels that are not known classes: " + ", ".join(bad))
    return df


class Candidates:
    """Usable training rows as parallel arrays. n_invalid counts rows left out for a missing or non-finite value (nothing is imputed)."""

    def __init__(self, ids, labels, raw, key_texts, source_files, original_rows, n_invalid):
        self.ids, self.labels, self.raw, self.key_texts = ids, labels, raw, key_texts
        self.source_files, self.original_rows, self.n_invalid = source_files, original_rows, n_invalid

    def __len__(self):
        return len(self.ids)


def candidates_from_frame(df):
    validate_train_frame(df)
    raw, valid = raw_matrix({c: df[c] for c in NUMERIC_FEATURES}, df[TRAIN_PORT], df[TRAIN_PROTOCOL])
    original = _finite_column(df["original_row"])
    labelled = df[TRAIN_LABEL].notna().to_numpy() & df["source_file"].notna().to_numpy() & ~np.isnan(original)
    keep = valid & labelled
    sub = df.loc[keep]
    orig = original[keep].astype(np.int64)
    files = sub["source_file"].astype(str).tolist()
    ids = ["train:%s:%d" % (f, o) for f, o in zip(files, orig)]
    if len(set(ids)) != len(ids):
        raise MemoryDataError("the training table has duplicate (source_file, original_row) keys")
    keys = frame_key_texts(sub)
    return Candidates(ids, sub[TRAIN_LABEL].astype(str).to_numpy(), raw[keep], keys, files, orig.tolist(), int((~keep).sum()))


def select(cands, per_class_cap, seed, exclude_key_texts=()):
    """Deterministic stratified selection. Returns (indices sorted by memory_id, stats).
    Identical fingerprints inside one class are collapsed (first by memory_id); each class then keeps the per_class_cap rows with the smallest sha256(seed|memory_id).
    The result does not depend on the input row order. Rows whose flow key is in exclude_key_texts are an isolation failure, not a filter: see seed_store."""
    if isinstance(per_class_cap, bool) or not isinstance(per_class_cap, int) or per_class_cap < 1:
        raise ValueError("per_class_cap must be an integer >= 1")
    order = np.argsort(np.array(cands.ids, dtype=object), kind="stable")
    frame = pd.DataFrame(cands.raw[order])
    frame["__label"] = cands.labels[order]
    dup = frame.duplicated(keep="first").to_numpy()
    by_label = {}
    for i, d in zip(order.tolist(), dup.tolist()):
        if not d:
            by_label.setdefault(str(cands.labels[i]), []).append(i)
    chosen = []
    for label in sorted(by_label):
        ranked = sorted(by_label[label], key=lambda i: (hashlib.sha256((str(seed) + "|" + cands.ids[i]).encode("utf-8")).hexdigest(), cands.ids[i]))
        chosen.extend(ranked[:per_class_cap])
    chosen.sort(key=lambda i: cands.ids[i])
    return chosen, {"duplicates_collapsed": int(dup.sum())}


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
