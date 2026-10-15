"""Shared helpers for the Week 4 tests (not a test module).

PostgreSQL integration tests are OPT-IN. They run only when WEEK4_TEST_PG=1 and the standard libpq variables (PGHOST, PGPORT, PGUSER, PGPASSWORD ...) point at a server where
the user may CREATE DATABASE. They never touch an existing database: each test class creates a uniquely named scratch database from a migrated template and drops it afterwards.
"""
import copy
import hashlib
import json
import os
import shutil
import unittest
import uuid

from week4.db import drivers, migrate
from week4.db.fake import MemoryRepository
from week4.db.repository import PgRepository

PG_REASON = None


def pg_enabled():
    """(True, '') when the PostgreSQL tests can run, else (False, reason)."""
    if os.environ.get("WEEK4_TEST_PG") != "1":
        return False, "set WEEK4_TEST_PG=1 (and the PG* variables) to run the PostgreSQL integration tests"
    if not shutil.which("psql"):
        return False, "the psql client is not installed"
    try:
        drivers.PsqlDriver(env=_env("postgres")).scalar("SELECT 1")
    except drivers.DbError as error:
        return False, "cannot reach PostgreSQL: " + str(error)
    return True, ""


def _env(database):
    env = dict(os.environ)
    env["PGDATABASE"] = database
    env.pop("WEEK4_DATABASE_URL", None)
    return env


def driver_for(database):
    return drivers.PsqlDriver(env=_env(database))


class PgHarness:
    """One migrated template database per process; one scratch database per test (cloned from the template, so it is fast)."""
    template = None

    @classmethod
    def ensure_template(cls):
        if cls.template is None:
            admin = driver_for("postgres")
            name = "w4_tpl_" + uuid.uuid4().hex[:12]
            admin.run_script('CREATE DATABASE "%s"' % name)
            migrate.apply(driver_for(name), say=lambda *_: None)
            cls.template = name
            import atexit
            atexit.register(cls.drop_template)
        return cls.template

    @classmethod
    def drop_template(cls):
        if cls.template:
            try:
                driver_for("postgres").run_script('DROP DATABASE IF EXISTS "%s"' % cls.template)
            except drivers.DbError:
                pass
            cls.template = None

    @classmethod
    def new_database(cls):
        tpl = cls.ensure_template()
        name = "w4_t_" + uuid.uuid4().hex[:12]
        driver_for("postgres").run_script('CREATE DATABASE "%s" TEMPLATE "%s"' % (name, tpl))
        return name

    @staticmethod
    def drop(name):
        try:
            driver_for("postgres").run_script('DROP DATABASE IF EXISTS "%s" WITH (FORCE)' % name)
        except drivers.DbError:
            pass


ANALYSTS = [("alice", "approver"), ("dave", "approver"), ("bob", "analyst"), ("carol", "viewer"), ("root", "admin")]


def seed_analysts(repo):
    for aid, role in ANALYSTS:
        repo.upsert_analyst(aid, role)
    repo.upsert_analyst("erin", "approver", active=False)


def sha(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode("utf-8")).hexdigest()


def make_payload(key=None, decision="escalate", actions=None, verdict="malicious", hits=True, **over):
    """A valid case payload. decision: auto_close | escalate | needs_review."""
    key = key or "run1:dev:%s:off" % uuid.uuid4().hex[:10]
    alert = {"alert_id": "dev-0001", "Destination Port": 80, "Flow Duration": 1234, "Total Fwd Packets": 7}
    ver = {"status": "ok", "is_malicious": True, "attack_type": "DoS Hulk", "mitre_technique": "T1499", "severity": "high", "evidence_text": "burst of connections",
           "prompt_version": "agent_v1", "prompt_sha256": "a" * 64, "model": "mock-model", "error_code": None}
    if verdict == "benign":
        ver.update(is_malicious=False, attack_type="BENIGN", mitre_technique="none", severity="none")
    elif verdict == "failed":
        ver = {"status": "parse_failed", "error_code": "json"}
    elif verdict is None:
        ver = None
    if actions is None:
        actions = [{"action_type": "block_source_ip", "target": "198.51.100.7", "parameters": {"duration_h": 24}, "rationale": "verdict malicious, high severity"}] if decision == "escalate" else []
    evidence = [{"kind": "tool_call", "ordinal": 0, "source": "flow_query", "payload": {"rows": 3}, "payload_sha256": sha({"rows": 3})}]
    p = {
        "idempotency_key": key, "alert_set": "dev", "alert_id": "dev-0001", "run_name": "unit", "graph_version": "graph-v2", "memory_mode": "off",
        "alert": alert, "provenance": {"note": "unit test"}, "verdict": ver,
        "routing": {"decision": decision, "risk_level": {"auto_close": "low", "escalate": "high", "needs_review": "unknown"}[decision], "reasons": ["R1: test"],
                    "policy_version": "p1", "policy_sha256": "b" * 64, "memory_raised_risk": False},
        "evidence": evidence,
        "memory_hits": ([{"rank": 1, "memory_id": "m-1", "distance": 0.12, "label": "DoS Hulk", "source_split": "train", "source_ref": {"row": 5}, "manifest_sha256": "c" * 64}] if hits else []),
        "actions": actions,
    }
    p.update(over)
    p["payload_sha256"] = over.get("payload_sha256") or sha({k: v for k, v in p.items() if k != "payload_sha256"})
    return p


def variant(payload, **changes):
    """A deep copy of payload with top-level changes, and a recomputed hash unless one is given."""
    p = copy.deepcopy(payload)
    p.update(changes)
    if "payload_sha256" not in changes:
        p["payload_sha256"] = sha({k: v for k, v in p.items() if k != "payload_sha256"})
    return p


# ---------------------------------------------------------------------------------------------- synthetic training data for the memory tests
CLASS_CENTERS = {
    # label: (destination port, protocol, log-scale centre for the 12 display features)
    "BENIGN": (443, 6, 8.0), "PortScan": (1025, 6, 1.5), "DoS Hulk": (80, 6, 11.0), "SSH-Patator": (22, 6, 5.0), "Bot": (8080, 6, 6.5),
}


def make_train_frame(per_class=30, seed=0, labels=None):
    """A synthetic stand-in for train.parquet: the same columns, made-up values. Never real data, never a claim about real performance."""
    import numpy as np
    import pandas as pd
    import config
    rng = np.random.default_rng(seed)
    rows = []
    n = 0
    for label in (labels or list(CLASS_CENTERS)):
        port, proto, centre = CLASS_CENTERS[label]
        for i in range(per_class):
            row = {"Flow ID": "10.0.0.%d-10.0.1.%d-%d-%d-%d" % (n % 250, i % 250, 1000 + i, port, proto), "Timestamp": pd.Timestamp("2017-07-05 10:00:00") + pd.Timedelta(seconds=7 * n),
                   "Source IP": "10.0.0.%d" % (n % 250), "Source Port": 1000 + i, "Destination IP": "10.0.1.%d" % (i % 250), "Destination Port": port, "Protocol": proto,
                   "Label": label, "source_file": "Test-%s.csv" % label.replace(" ", "_"), "original_row": n}
            for f in config.DISPLAY_FEATURES:
                row[f] = float(np.expm1(rng.normal(centre, 0.6)).clip(0, None))
            rows.append(row)
            n += 1
    return pd.DataFrame(rows)


def alert_from_row(row, detector_score=0.3):
    """The label-free alert dict an agent would see for a training-like flow (alert field names)."""
    import config
    alert = {"alert_id": "DEV-X", "timestamp": row["Timestamp"].strftime("%Y-%m-%d %H:%M:%S"), "flow_id": row["Flow ID"], "src_ip": row["Source IP"], "src_port": int(row["Source Port"]),
             "dst_ip": row["Destination IP"], "dst_port": int(row["Destination Port"]), "protocol": int(row["Protocol"]), "detector_score": detector_score}
    for f in config.DISPLAY_FEATURES:
        alert[f] = float(row[f])
    return alert
