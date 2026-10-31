"""Repository additions for Week 5 phase 2: sensor events, case search, notes, feedback, case resolution, overview numbers and threat-intelligence status.

The Week 2-4 files are hash-locked, so nothing here edits week4.db.repository. `wrap(repo)` returns an object that has every method of the Week 4 repository (calls are passed through)
plus the methods below. There are two implementations that behave the same and pass the same contract tests (tests/test_week5_repo5.py):

  PgRepo5   the real thing. Writes call the SECURITY DEFINER functions of Week 5 migration 0002; reads are plain SELECTs.
  MemRepo5  an in-process stand-in over week4.db.fake.MemoryRepository, for offline tests. A test double, not a store.

Business outcomes are RETURNED as a dict with an "outcome" key; only bad input (ValueError) and database failures (DbError) raise.
"""
import copy
import datetime
import json
import re
import threading

from week4.db.drivers import DbError
from week4.db.repository import ANALYST_ID_RE, PgRepository, clamp_page, parse_uuid

SORTS = ("created_desc", "created_asc", "updated_desc", "severity_desc", "risk_desc")
SEVERITIES = ("none", "low", "medium", "high", "critical")
RISKS = ("low", "medium", "high", "unknown")
ROUTINGS = ("auto_close", "escalate", "needs_review")
VERDICT_STATUSES = ("ok", "parse_failed", "model_error", "missing")
CASE_STATUSES = ("auto_closed", "escalated", "needs_review", "resolved")
ALERT_SETS = ("dev", "synthetic", "sensor")
ASSESSMENTS = ("correct", "incorrect", "unsure")
DISPOSITIONS = ("true_positive", "false_positive", "true_negative", "false_negative", "inconclusive")
Q_MAX = 100
NOTE_MAX = 4000
COMMENT_MAX = 2000
REASON_MAX = 1000
SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "none": 1}
RISK_RANK = {"high": 3, "medium": 2, "low": 1, "unknown": 0}
ORDER_SQL = {
    "created_desc": "c.created_at DESC, c.case_id",
    "created_asc": "c.created_at ASC, c.case_id",
    "updated_desc": "c.updated_at DESC, c.case_id",
    "severity_desc": "(CASE v.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'none' THEN 1 ELSE 0 END) DESC, c.created_at DESC, c.case_id",
    "risk_desc": "(CASE r.risk_level WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) DESC, c.created_at DESC, c.case_id",
}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _choice(name, value, allowed):
    if value is not None and value not in allowed:
        raise ValueError("%s must be one of %s" % (name, ", ".join(allowed)))
    return value


def _action_filters(state, executed):
    state = None if state in (None, "") else state
    _choice("state", state, ("pending", "approved", "rejected"))
    if executed in (None, ""):
        return state, None
    if isinstance(executed, bool):
        return state, executed
    if executed in ("true", "1"):
        return state, True
    if executed in ("false", "0"):
        return state, False
    raise ValueError("executed must be true or false")


def clean_filters(f):
    """Validate the case search filters. Returns a normalised dict with every key present (None when not given). Raises ValueError with a message that never echoes the value."""
    f = dict(f or {})
    out = {"q": f.get("q"), "status": f.get("status"), "severity": f.get("severity"), "risk_level": f.get("risk_level"), "routing_decision": f.get("routing_decision"),
           "alert_set": f.get("alert_set"), "verdict_status": f.get("verdict_status"), "is_malicious": f.get("is_malicious"), "has_pending": f.get("has_pending"),
           "created_from": f.get("created_from"), "created_to": f.get("created_to"), "sort": f.get("sort") or "created_desc"}
    for key, value in list(out.items()):
        if value == "":
            out[key] = None
    if out["q"] is not None:
        if not isinstance(out["q"], str) or len(out["q"]) > Q_MAX or re.search(r"[\x00-\x1f\x7f]", out["q"]):
            raise ValueError("q must be text of at most %d characters" % Q_MAX)
        out["q"] = out["q"].strip() or None
    _choice("status", out["status"], CASE_STATUSES)
    _choice("severity", out["severity"], SEVERITIES)
    _choice("risk_level", out["risk_level"], RISKS)
    _choice("routing_decision", out["routing_decision"], ROUTINGS)
    _choice("alert_set", out["alert_set"], ALERT_SETS)
    _choice("verdict_status", out["verdict_status"], VERDICT_STATUSES)
    _choice("sort", out["sort"], SORTS)
    for key in ("is_malicious", "has_pending"):
        v = out[key]
        if v is None or isinstance(v, bool):
            continue
        if v in ("true", "1"):
            out[key] = True
        elif v in ("false", "0"):
            out[key] = False
        else:
            raise ValueError(key + " must be true or false")
    for key in ("created_from", "created_to"):
        v = out[key]
        if v is not None:
            if not isinstance(v, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?(Z|[+-]\d{2}:?\d{2})?)?", v):
                raise ValueError(key + " must be a date like 2026-10-24 or a date and time")
            try:
                datetime.datetime.fromisoformat(v.replace("Z", "+00:00").replace(" ", "T"))
            except ValueError:
                raise ValueError(key + " is not a real date") from None
    return out


def like_pattern(q):
    """A LIKE pattern for a plain substring search, with the wildcard characters escaped."""
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def check_case_text(name, value, limit, required=True):
    if value is None:
        if required:
            raise ValueError(name + " is required")
        return None
    if not isinstance(value, str) or (required and not value.strip()) or len(value) > limit or re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", value):
        raise ValueError("%s must be text of 1 to %d characters without control characters" % (name, limit))
    return value


def check_key(key):
    if key is None or key == "":
        return None
    if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9._:\-]{8,200}", key):
        raise ValueError("Idempotency-Key must be 8 to 200 characters from A-Z a-z 0-9 . _ : -")
    return key


def check_actor(actor):
    if not isinstance(actor, str) or not ANALYST_ID_RE.match(actor):
        raise ValueError("the actor is not a valid analyst id")
    return actor


class Repo5:
    """Interface (see module docstring)."""

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):              # every Week 4 method passes straight through
        return getattr(self._inner, name)


def wrap(repo):
    """-> a Repo5 over a PgRepository or a MemoryRepository (an already wrapped repository is returned as it is)."""
    if isinstance(repo, Repo5):
        return repo
    if isinstance(repo, PgRepository):
        return PgRepo5(repo)
    return MemRepo5(repo)


# ================================================================== PostgreSQL
class PgRepo5(Repo5):
    kind = "postgres"

    def __init__(self, inner):
        super().__init__(inner)
        self.db = inner.db

    def _one(self, sql, params=()):
        return self.db.query_json("SELECT to_jsonb(t) FROM (" + sql + ") t", params)

    def _list(self, sql, params=()):
        return self.db.query_json("SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (" + sql + ") t", params) or []

    # -- sensor events
    def ingest_sensor_batch(self, actor, sensor, records):
        """records: normalised EVE records (week5.eve.normalise). -> {"outcome": ok|unauthorized, "results": [{"index", "outcome": stored|duplicate, "event_id"}], "stored", "duplicates"}. All or nothing."""
        check_actor(actor)
        payload = {"actor": actor, "sensor": sensor, "events": [{k: r[k] for k in ("event_sha256", "event_type", "flow_ref", "event_time", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "record")}
                                                              for r in records]}
        # JSON goes to the database as TEXT with an explicit cast: the psycopg 3 driver does not adapt a Python dict to jsonb (the psql driver does), and the cast works with both.
        rows = self._list("SELECT * FROM soc.w5_ingest_sensor_batch(%s::jsonb)", [json.dumps(payload, sort_keys=True, allow_nan=False)])
        if rows and rows[0]["outcome"] == "unauthorized":
            return {"outcome": "unauthorized", "results": [], "stored": 0, "duplicates": 0}
        results = [{"index": r["o_index"], "outcome": r["outcome"], "event_id": r["o_event_id"]} for r in rows]
        return {"outcome": "ok", "results": results, "stored": sum(1 for r in results if r["outcome"] == "stored"), "duplicates": sum(1 for r in results if r["outcome"] == "duplicate")}

    def sensor_alert(self, alert_id):
        return self.db.query_json("SELECT record || jsonb_build_object('event_id', event_id, 'received_at', received_at) FROM soc.sensor_events WHERE event_type = 'alert' AND record ->> 'alert_id' = %s",
                                  [alert_id])

    def sensor_flow_for(self, sensor, flow_ref):
        return self.db.query_json("SELECT record FROM soc.sensor_events WHERE event_type = 'flow' AND sensor = %s AND flow_ref = %s ORDER BY event_id DESC LIMIT 1", [sensor, flow_ref])

    def flows_near(self, ips, around, window_minutes=120, limit=5000):
        """Flow records that involve any of ips, within window_minutes of `around` (ISO text). Oldest first."""
        import ipaddress
        clean = sorted({str(ipaddress.ip_address(i)) for i in ips})
        if not clean:
            return []
        arr = "{" + ",".join(clean) + "}"
        limit = max(1, min(int(limit), 20000))
        return self.db.query_json(
            "SELECT coalesce(jsonb_agg(record ORDER BY event_time, event_id), '[]'::jsonb) FROM (SELECT record, event_time, event_id FROM soc.sensor_events "
            "WHERE event_type = 'flow' AND (src_ip = ANY(%s::inet[]) OR dst_ip = ANY(%s::inet[])) "
            "AND event_time BETWEEN %s::timestamptz - make_interval(mins => %s) AND %s::timestamptz + make_interval(mins => %s) ORDER BY event_time, event_id LIMIT %s) t",
            [arr, arr, around, int(window_minutes), around, int(window_minutes), limit]) or []

    def audit_tail(self, limit=50):
        limit = max(1, min(int(limit), 500))
        return self.db.query_json("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.event_id DESC), '[]'::jsonb) FROM (SELECT event_id, occurred_at, actor, event_type, entity_type, entity_id, case_id, payload "
                                  "FROM soc.audit_events ORDER BY event_id DESC LIMIT %s) t", [limit]) or []

    def sensor_stats(self):
        return self.db.query_json(
            "SELECT jsonb_build_object('events', count(*), 'flows', count(*) FILTER (WHERE event_type = 'flow'), 'alerts', count(*) FILTER (WHERE event_type = 'alert'), "
            "'last_received_at', max(received_at), 'sensors', count(DISTINCT sensor)) FROM soc.sensor_events")

    # -- decided actions and their SIMULATED executions (read only)
    def list_actions(self, state=None, executed=None, limit=None, offset=None):
        """Proposed actions with their decision and simulated execution, newest activity first. state: pending|approved|rejected; executed: True|False. Nothing here executes anything."""
        state, executed = _action_filters(state, executed)
        limit, offset = clamp_page(limit, offset)
        where = "WHERE (%s::text IS NULL OR a.state = %s::text) AND (%s::boolean IS NULL OR (x.execution_id IS NOT NULL) = %s::boolean) "
        frm = "FROM soc.proposed_actions a JOIN soc.cases c USING (case_id) LEFT JOIN soc.executed_actions x USING (action_id) "
        flt = [state, state, executed, executed]
        total = int(self.db.scalar("SELECT count(*) " + frm + where, flt))
        items = self._list(
            "SELECT a.action_id, a.case_id, c.alert_id, a.action_type, a.target, a.state, a.proposed_by, a.created_at, a.decided_at, a.decided_by, a.decision_reason, "
            "(x.execution_id IS NOT NULL) AS executed, x.mode AS execution_mode, x.executed_by, x.executed_at "
            + frm + where + "ORDER BY coalesce(x.executed_at, a.decided_at, a.created_at) DESC, a.action_id LIMIT %s OFFSET %s", flt + [limit, offset])
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    # -- case search
    def search_cases(self, filters=None, limit=None, offset=None):
        f = clean_filters(filters)
        limit, offset = clamp_page(limit, offset)
        pattern = like_pattern(f["q"]) if f["q"] else None
        where = ("WHERE (%s::text IS NULL OR c.status = %s::text) AND (%s::text IS NULL OR v.severity = %s::text) AND (%s::text IS NULL OR r.risk_level = %s::text) "
                 "AND (%s::text IS NULL OR r.decision = %s::text) AND (%s::text IS NULL OR c.alert_set = %s::text) AND (%s::text IS NULL OR v.status = %s::text) "
                 "AND (%s::boolean IS NULL OR v.is_malicious IS NOT DISTINCT FROM %s::boolean) "
                 "AND (%s::boolean IS NULL OR ((SELECT count(*) FROM soc.proposed_actions a WHERE a.case_id = c.case_id AND a.state = 'pending') > 0) = %s::boolean) "
                 "AND (%s::timestamptz IS NULL OR c.created_at >= %s::timestamptz) AND (%s::timestamptz IS NULL OR c.created_at < %s::timestamptz) "
                 "AND (%s::text IS NULL OR c.alert_id ILIKE %s::text ESCAPE '\\' OR c.case_id::text ILIKE %s::text ESCAPE '\\' OR c.alert ->> 'src_ip' ILIKE %s::text ESCAPE '\\' "
                 "OR c.alert ->> 'dst_ip' ILIKE %s::text ESCAPE '\\' OR v.attack_type ILIKE %s::text ESCAPE '\\')")
        flt = [f["status"], f["status"], f["severity"], f["severity"], f["risk_level"], f["risk_level"], f["routing_decision"], f["routing_decision"], f["alert_set"], f["alert_set"],
               f["verdict_status"], f["verdict_status"], f["is_malicious"], f["is_malicious"], f["has_pending"], f["has_pending"], f["created_from"], f["created_from"],
               f["created_to"], f["created_to"], pattern, pattern, pattern, pattern, pattern, pattern]
        frm = "FROM soc.cases c LEFT JOIN soc.verdicts v USING (case_id) LEFT JOIN soc.routing_decisions r USING (case_id) "
        total = int(self.db.scalar("SELECT count(*) " + frm + where, flt))
        items = self._list(
            "SELECT c.case_id, c.alert_set, c.alert_id, c.run_name, c.graph_version, c.memory_mode, c.status, c.created_at, c.updated_at, v.status AS verdict_status, v.attack_type, v.severity, "
            "v.is_malicious, r.decision AS routing_decision, r.risk_level, c.alert ->> 'src_ip' AS src_ip, c.alert ->> 'dst_ip' AS dst_ip, c.alert ->> 'dst_port' AS dst_port, "
            "(SELECT count(*) FROM soc.proposed_actions a WHERE a.case_id = c.case_id AND a.state = 'pending') AS pending_actions, "
            "(SELECT count(*) FROM soc.case_notes n WHERE n.case_id = c.case_id AND n.kind = 'note') AS notes_count, "
            "(SELECT x.verdict_assessment FROM soc.case_feedback x WHERE x.case_id = c.case_id ORDER BY x.feedback_id DESC LIMIT 1) AS latest_feedback "
            + frm + where + " ORDER BY " + ORDER_SQL[f["sort"]] + " LIMIT %s OFFSET %s", flt + [limit, offset])
        return {"items": items, "total": total, "limit": limit, "offset": offset, "filters": {k: v for k, v in f.items() if v is not None}}

    # -- notes, feedback, resolution
    def add_note(self, case_id, actor, body, key=None):
        case_id = parse_uuid(case_id)
        check_actor(actor)
        check_case_text("body", body, NOTE_MAX)
        row = self._one("SELECT * FROM soc.w5_add_note(%s::uuid, %s, %s, %s)", [case_id, actor, body, check_key(key)])
        return {"outcome": row["outcome"], "note_id": row.get("o_note_id")}

    def add_feedback(self, case_id, actor, assessment, disposition=None, comment=None, key=None):
        case_id = parse_uuid(case_id)
        check_actor(actor)
        _choice("assessment", assessment, ASSESSMENTS)
        if assessment is None:
            raise ValueError("assessment is required")
        _choice("disposition", disposition, DISPOSITIONS)
        check_case_text("comment", comment, COMMENT_MAX, required=False)
        row = self._one("SELECT * FROM soc.w5_add_feedback(%s::uuid, %s, %s, %s, %s, %s)", [case_id, actor, assessment, disposition, comment, check_key(key)])
        return {"outcome": row["outcome"], "feedback_id": row.get("o_feedback_id")}

    def resolve_case(self, case_id, actor, disposition, reason, key=None):
        case_id = parse_uuid(case_id)
        check_actor(actor)
        _choice("disposition", disposition, DISPOSITIONS)
        check_case_text("reason", reason, REASON_MAX)
        row = self._one("SELECT * FROM soc.w5_resolve_case(%s::uuid, %s, %s, %s, %s)", [case_id, actor, disposition, reason, check_key(key)])
        return {"outcome": row["outcome"], "status": row.get("o_status")}

    def case_notes(self, case_id):
        case_id = parse_uuid(case_id)
        return self._list("SELECT note_id, kind, author, body, created_at FROM soc.case_notes WHERE case_id = %s::uuid ORDER BY note_id", [case_id])

    def case_feedback(self, case_id):
        case_id = parse_uuid(case_id)
        return self._list("SELECT feedback_id, author, verdict_assessment, disposition, comment, created_at FROM soc.case_feedback WHERE case_id = %s::uuid ORDER BY feedback_id", [case_id])

    # -- numbers for the overview and the provider panel
    def overview(self):
        return self.db.query_json(
            """SELECT jsonb_build_object(
                 'cases_total', (SELECT count(*) FROM soc.cases),
                 'cases_last_24h', (SELECT count(*) FROM soc.cases WHERE created_at >= now() - interval '24 hours'),
                 'by_status', (SELECT coalesce(jsonb_object_agg(k, n), '{}'::jsonb) FROM (SELECT status AS k, count(*) AS n FROM soc.cases GROUP BY 1) s),
                 'by_source', (SELECT coalesce(jsonb_object_agg(k, n), '{}'::jsonb) FROM (SELECT alert_set AS k, count(*) AS n FROM soc.cases GROUP BY 1) s),
                 'by_severity', (SELECT coalesce(jsonb_object_agg(k, n), '{}'::jsonb) FROM (SELECT coalesce(v.severity, 'unavailable') AS k, count(*) AS n FROM soc.cases c LEFT JOIN soc.verdicts v USING (case_id) GROUP BY 1) s),
                 'by_routing', (SELECT coalesce(jsonb_object_agg(k, n), '{}'::jsonb) FROM (SELECT decision AS k, count(*) AS n FROM soc.routing_decisions GROUP BY 1) s),
                 'by_risk', (SELECT coalesce(jsonb_object_agg(k, n), '{}'::jsonb) FROM (SELECT risk_level AS k, count(*) AS n FROM soc.routing_decisions GROUP BY 1) s),
                 'by_verdict_status', (SELECT coalesce(jsonb_object_agg(k, n), '{}'::jsonb) FROM (SELECT status AS k, count(*) AS n FROM soc.verdicts GROUP BY 1) s),
                 'pending_actions', (SELECT count(*) FROM soc.proposed_actions WHERE state = 'pending'),
                 'actions_by_state', (SELECT coalesce(jsonb_object_agg(k, n), '{}'::jsonb) FROM (SELECT state AS k, count(*) AS n FROM soc.proposed_actions GROUP BY 1) s),
                 'simulated_executions', (SELECT count(*) FROM soc.executed_actions),
                 'feedback_by_assessment', (SELECT coalesce(jsonb_object_agg(k, n), '{}'::jsonb) FROM (SELECT verdict_assessment AS k, count(*) AS n FROM soc.case_feedback GROUP BY 1) s),
                 'notes_total', (SELECT count(*) FROM soc.case_notes WHERE kind = 'note'),
                 'jobs_by_status', (SELECT coalesce(jsonb_object_agg(k, n), '{}'::jsonb) FROM (SELECT status AS k, count(*) AS n FROM soc.jobs GROUP BY 1) s),
                 'oldest_queued_age_seconds', (SELECT extract(epoch FROM clock_timestamp() - min(enqueued_at)) FROM soc.jobs WHERE status IN ('queued', 'running'))
               )""")

    def provider_outcomes(self, hours=24):
        """Reputation-lookup outcomes recorded in cases created in the last `hours`: {status: n}, plus the newest timestamp. Read from stored evidence, so it needs no extra table."""
        hours = max(1, min(int(hours), 24 * 90))
        return self.db.query_json(
            "SELECT jsonb_build_object('by_status', coalesce((SELECT jsonb_object_agg(k, n) FROM (SELECT coalesce(e.payload -> 'data' ->> 'status', e.payload -> 'error' ->> 'code', 'unknown') AS k, count(*) AS n "
            "FROM soc.evidence_items e JOIN soc.cases c USING (case_id) WHERE e.kind = 'tool_call' AND e.source = 'reputation_lookup' AND c.created_at >= now() - make_interval(hours => %s) GROUP BY 1) s), '{}'::jsonb), "
            "'last_lookup_at', (SELECT max(c.created_at) FROM soc.evidence_items e JOIN soc.cases c USING (case_id) WHERE e.kind = 'tool_call' AND e.source = 'reputation_lookup' "
            "AND coalesce(e.payload -> 'data' ->> 'status', '') = 'ok'), 'hours', %s::int)", [hours, hours])


# ================================================================== in memory (test double)
class MemRepo5(Repo5):
    kind = "memory"

    def __init__(self, inner):
        super().__init__(inner)
        self._lock5 = threading.RLock()
        self.sensor_events = []
        self.notes = []
        self.feedback = []

    # The Week 4 in-memory repository only knows two alert sets; 'sensor' is stored by the real schema (migration 0002). The stand-in files it under 'synthetic' for validation, then relabels it.
    def ingest_case(self, payload):
        if isinstance(payload, dict) and payload.get("alert_set") == "sensor":
            outcome = self._inner.ingest_case(dict(payload, alert_set="synthetic"))
            if outcome.get("case_id") and outcome["outcome"] == "created":
                self._inner.cases[outcome["case_id"]]["alert_set"] = "sensor"
            return outcome
        return self._inner.ingest_case(payload)

    def _writer(self, actor):
        who = self._inner.analysts.get(actor) if isinstance(actor, str) else None
        return bool(who and who["active"] and who["role"] in ("analyst", "approver", "admin"))

    def ingest_sensor_batch(self, actor, sensor, records):
        check_actor(actor)
        with self._lock5:
            if not self._writer(actor):
                self._inner._audit(actor, "sensor_batch_refused", "sensor", sensor, None, {"reason": "not an active analyst"})
                return {"outcome": "unauthorized", "results": [], "stored": 0, "duplicates": 0}
            known = {e["event_sha256"] for e in self.sensor_events}
            results, stored, dups = [], 0, 0
            for index, r in enumerate(records):
                if r["event_sha256"] in known:
                    results.append({"index": index, "outcome": "duplicate", "event_id": None})
                    dups += 1
                    continue
                event_id = len(self.sensor_events) + 1
                self.sensor_events.append(dict(copy.deepcopy(r), event_id=event_id, sensor=sensor, received_by=actor, received_at=_now()))
                known.add(r["event_sha256"])
                results.append({"index": index, "outcome": "stored", "event_id": event_id})
                stored += 1
            self._inner._audit(actor, "sensor_batch_ingested", "sensor", sensor, None, {"received": len(records), "stored": stored, "duplicates": dups})
            return {"outcome": "ok", "results": results, "stored": stored, "duplicates": dups}

    def audit_tail(self, limit=50):
        with self._inner._lock:
            return [copy.deepcopy(e) for e in reversed(self._inner.audit_events[-max(1, min(int(limit), 500)):])]

    def sensor_alert(self, alert_id):
        with self._lock5:
            for e in self.sensor_events:
                if e["event_type"] == "alert" and e["record"].get("alert_id") == alert_id:
                    return dict(copy.deepcopy(e["record"]), event_id=e["event_id"], received_at=e["received_at"])
        return None

    def sensor_flow_for(self, sensor, flow_ref):
        with self._lock5:
            hits = [e for e in self.sensor_events if e["event_type"] == "flow" and e["sensor"] == sensor and e["flow_ref"] == flow_ref]
            return copy.deepcopy(hits[-1]["record"]) if hits else None

    def flows_near(self, ips, around, window_minutes=120, limit=5000):
        import ipaddress
        want = {str(ipaddress.ip_address(i)) for i in ips}
        centre = datetime.datetime.fromisoformat(around.replace("Z", "+00:00").replace(" ", "T"))
        if centre.tzinfo is None:
            centre = centre.replace(tzinfo=datetime.timezone.utc)
        delta = datetime.timedelta(minutes=int(window_minutes))
        with self._lock5:
            rows = []
            for e in self.sensor_events:
                if e["event_type"] != "flow" or (e["src_ip"] not in want and e["dst_ip"] not in want):
                    continue
                when = datetime.datetime.fromisoformat(e["event_time"])
                if centre - delta <= when <= centre + delta:
                    rows.append((when, e["event_id"], copy.deepcopy(e["record"])))
            rows.sort(key=lambda r: (r[0], r[1]))
            return [r[2] for r in rows[:max(1, min(int(limit), 20000))]]

    def sensor_stats(self):
        with self._lock5:
            ev = self.sensor_events
            return {"events": len(ev), "flows": sum(1 for e in ev if e["event_type"] == "flow"), "alerts": sum(1 for e in ev if e["event_type"] == "alert"),
                    "last_received_at": max((e["received_at"] for e in ev), default=None), "sensors": len({e["sensor"] for e in ev})}

    # -- search
    def _summary(self, c):
        cid = c["case_id"]
        v, r = self._inner.verdicts.get(cid, {}), self._inner.routing.get(cid, {})
        fb = [x for x in self.feedback if x["case_id"] == cid]
        return {"case_id": cid, "alert_set": c["alert_set"], "alert_id": c["alert_id"], "run_name": c["run_name"], "graph_version": c["graph_version"], "memory_mode": c["memory_mode"],
                "status": c["status"], "created_at": c["created_at"], "updated_at": c["updated_at"], "verdict_status": v.get("status"), "attack_type": v.get("attack_type"),
                "severity": v.get("severity"), "is_malicious": v.get("is_malicious"), "routing_decision": r.get("decision"), "risk_level": r.get("risk_level"),
                "src_ip": c["alert"].get("src_ip"), "dst_ip": c["alert"].get("dst_ip"), "dst_port": None if c["alert"].get("dst_port") is None else str(c["alert"]["dst_port"]),
                "pending_actions": self._inner._pending_count(cid), "notes_count": sum(1 for n in self.notes if n["case_id"] == cid and n["kind"] == "note"),
                "latest_feedback": fb[-1]["verdict_assessment"] if fb else None}

    def search_cases(self, filters=None, limit=None, offset=None):
        f = clean_filters(filters)
        limit, offset = clamp_page(limit, offset)
        needle = f["q"].lower() if f["q"] else None
        with self._inner._lock:
            rows = []
            for c in self._inner.cases.values():
                s = self._summary(c)
                if f["status"] and s["status"] != f["status"] or f["severity"] and s["severity"] != f["severity"] or f["risk_level"] and s["risk_level"] != f["risk_level"]:
                    continue
                if f["routing_decision"] and s["routing_decision"] != f["routing_decision"] or f["alert_set"] and s["alert_set"] != f["alert_set"]:
                    continue
                if f["verdict_status"] and s["verdict_status"] != f["verdict_status"]:
                    continue
                if f["is_malicious"] is not None and s["is_malicious"] is not f["is_malicious"]:
                    continue
                if f["has_pending"] is not None and (s["pending_actions"] > 0) != f["has_pending"]:
                    continue
                if f["created_from"] and s["created_at"] < _as_utc(f["created_from"]) or f["created_to"] and s["created_at"] >= _as_utc(f["created_to"]):
                    continue
                if needle and not any(needle in str(x).lower() for x in (s["alert_id"], s["case_id"], s["src_ip"], s["dst_ip"], s["attack_type"]) if x is not None):
                    continue
                rows.append((c["_seq"], s))
            key = f["sort"]
            if key == "created_asc":
                rows.sort(key=lambda p: (p[1]["created_at"], p[0]))
            elif key == "updated_desc":
                rows.sort(key=lambda p: (p[1]["updated_at"], p[0]), reverse=True)
            elif key == "severity_desc":
                rows.sort(key=lambda p: (SEV_RANK.get(p[1]["severity"], 0), p[1]["created_at"], p[0]), reverse=True)
            elif key == "risk_desc":
                rows.sort(key=lambda p: (RISK_RANK.get(p[1]["risk_level"], 0), p[1]["created_at"], p[0]), reverse=True)
            else:
                rows.sort(key=lambda p: (p[1]["created_at"], p[0]), reverse=True)
            return {"items": [s for _, s in rows[offset:offset + limit]], "total": len(rows), "limit": limit, "offset": offset, "filters": {k: v for k, v in f.items() if v is not None}}

    def list_actions(self, state=None, executed=None, limit=None, offset=None):
        state, executed = _action_filters(state, executed)
        limit, offset = clamp_page(limit, offset)
        with self._inner._lock:
            rows = []
            for a in self._inner.actions.values():
                ex = self._inner.executions.get(a["action_id"])
                if state and a["state"] != state or executed is not None and (ex is not None) != executed:
                    continue
                case = self._inner.cases.get(a["case_id"]) or {}
                rows.append({"action_id": a["action_id"], "case_id": a["case_id"], "alert_id": case.get("alert_id"), "action_type": a["action_type"], "target": a["target"], "state": a["state"],
                             "proposed_by": a["proposed_by"], "created_at": a["created_at"], "decided_at": a.get("decided_at"), "decided_by": a.get("decided_by"),
                             "decision_reason": a.get("decision_reason"), "executed": ex is not None, "execution_mode": ex["mode"] if ex else None,
                             "executed_by": ex["executed_by"] if ex else None, "executed_at": ex["executed_at"] if ex else None})
            rows.sort(
    key=lambda r: (
        r["executed_at"] is not None,
        r["executed_at"] or r["decided_at"] or r["created_at"],
        r["action_id"],
    ),
    reverse=True,
)
            return {"items": rows[offset:offset + limit], "total": len(rows), "limit": limit, "offset": offset}

    # -- notes, feedback, resolution
    def _exists(self, case_id):
        return case_id in self._inner.cases

    def add_note(self, case_id, actor, body, key=None):
        case_id = parse_uuid(case_id)
        check_actor(actor)
        check_case_text("body", body, NOTE_MAX)
        key = check_key(key)
        with self._lock5, self._inner._lock:
            if not self._writer(actor):
                self._inner._audit(actor, "case_note_refused", "case", case_id, case_id if self._exists(case_id) else None, {"reason": "unauthorized"})
                return {"outcome": "unauthorized", "note_id": None}
            if not self._exists(case_id):
                return {"outcome": "not_found", "note_id": None}
            if key:
                old = next((n for n in self.notes if n["author"] == actor and n["idempotency_key"] == key), None)
                if old:
                    return {"outcome": "replayed" if old["case_id"] == case_id and old["body"] == body else "conflict", "note_id": old["note_id"]}
            note = {"note_id": len(self.notes) + 1, "case_id": case_id, "kind": "note", "author": actor, "body": body, "idempotency_key": key, "created_at": _now()}
            self.notes.append(note)
            self._inner._audit(actor, "case_note_added", "case", case_id, case_id, {"note_id": note["note_id"], "length": len(body)})
            return {"outcome": "created", "note_id": note["note_id"]}

    def add_feedback(self, case_id, actor, assessment, disposition=None, comment=None, key=None):
        case_id = parse_uuid(case_id)
        check_actor(actor)
        _choice("assessment", assessment, ASSESSMENTS)
        if assessment is None:
            raise ValueError("assessment is required")
        _choice("disposition", disposition, DISPOSITIONS)
        check_case_text("comment", comment, COMMENT_MAX, required=False)
        key = check_key(key)
        with self._lock5, self._inner._lock:
            if not self._writer(actor):
                self._inner._audit(actor, "case_feedback_refused", "case", case_id, case_id if self._exists(case_id) else None, {"reason": "unauthorized"})
                return {"outcome": "unauthorized", "feedback_id": None}
            if not self._exists(case_id):
                return {"outcome": "not_found", "feedback_id": None}
            if key:
                old = next((x for x in self.feedback if x["author"] == actor and x["idempotency_key"] == key), None)
                if old:
                    same = old["case_id"] == case_id and old["verdict_assessment"] == assessment and old["disposition"] == disposition and old["comment"] == comment
                    return {"outcome": "replayed" if same else "conflict", "feedback_id": old["feedback_id"]}
            row = {"feedback_id": len(self.feedback) + 1, "case_id": case_id, "author": actor, "verdict_assessment": assessment, "disposition": disposition, "comment": comment,
                   "idempotency_key": key, "created_at": _now()}
            self.feedback.append(row)
            self._inner._audit(actor, "case_feedback_added", "case", case_id, case_id, {"feedback_id": row["feedback_id"], "assessment": assessment, "disposition": disposition})
            return {"outcome": "created", "feedback_id": row["feedback_id"]}

    def resolve_case(self, case_id, actor, disposition, reason, key=None):
        case_id = parse_uuid(case_id)
        check_actor(actor)
        _choice("disposition", disposition, DISPOSITIONS)
        check_case_text("reason", reason, REASON_MAX)
        key = check_key(key)
        with self._lock5, self._inner._lock:
            if not self._writer(actor):
                self._inner._audit(actor, "case_resolve_refused", "case", case_id, case_id if self._exists(case_id) else None, {"reason": "unauthorized"})
                return {"outcome": "unauthorized", "status": None}
            c = self._inner.cases.get(case_id)
            if c is None:
                return {"outcome": "not_found", "status": None}
            if c["status"] == "resolved":
                old = next((n for n in self.notes if n["case_id"] == case_id and n["kind"] == "resolution" and n["author"] == actor and key and n["idempotency_key"] == key), None)
                return {"outcome": "replayed" if old else "conflict", "status": "resolved"}
            if c["status"] not in ("escalated", "needs_review"):
                self._inner._audit(actor, "case_resolve_refused", "case", case_id, case_id, {"reason": "status", "status": c["status"]})
                return {"outcome": "conflict", "status": c["status"]}
            if self._inner._pending_count(case_id):
                self._inner._audit(actor, "case_resolve_refused", "case", case_id, case_id, {"reason": "pending_actions"})
                return {"outcome": "pending_actions", "status": c["status"]}
            self.notes.append({"note_id": len(self.notes) + 1, "case_id": case_id, "kind": "resolution", "author": actor, "body": reason, "idempotency_key": key, "created_at": _now()})
            if disposition:
                self.feedback.append({"feedback_id": len(self.feedback) + 1, "case_id": case_id, "author": actor, "verdict_assessment": "unsure", "disposition": disposition,
                                      "comment": "recorded when the case was resolved", "idempotency_key": None, "created_at": _now()})
            previous = c["status"]
            c["status"], c["updated_at"] = "resolved", _now()
            self._inner._audit(actor, "case_resolved", "case", case_id, case_id, {"from_status": previous, "disposition": disposition})
            return {"outcome": "resolved", "status": "resolved"}

    def case_notes(self, case_id):
        case_id = parse_uuid(case_id)
        with self._lock5:
            return [{k: n[k] for k in ("note_id", "kind", "author", "body", "created_at")} for n in self.notes if n["case_id"] == case_id]

    def case_feedback(self, case_id):
        case_id = parse_uuid(case_id)
        with self._lock5:
            return [{k: x[k] for k in ("feedback_id", "author", "verdict_assessment", "disposition", "comment", "created_at")} for x in self.feedback if x["case_id"] == case_id]

    # -- numbers
    @staticmethod
    def _count(values):
        out = {}
        for v in values:
            out[v] = out.get(v, 0) + 1
        return out

    def overview(self, jobs=None):
        with self._inner._lock:
            cases = list(self._inner.cases.values())
            cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=24)).isoformat()
            return {"cases_total": len(cases), "cases_last_24h": sum(1 for c in cases if c["created_at"] >= cutoff),
                    "by_status": self._count(c["status"] for c in cases), "by_source": self._count(c["alert_set"] for c in cases),
                    "by_severity": self._count((self._inner.verdicts.get(c["case_id"], {}).get("severity") or "unavailable") for c in cases),
                    "by_routing": self._count(r["decision"] for r in self._inner.routing.values()), "by_risk": self._count(r["risk_level"] for r in self._inner.routing.values()),
                    "by_verdict_status": self._count(v["status"] for v in self._inner.verdicts.values()),
                    "pending_actions": sum(1 for a in self._inner.actions.values() if a["state"] == "pending"),
                    "actions_by_state": self._count(a["state"] for a in self._inner.actions.values()), "simulated_executions": len(self._inner.executions),
                    "feedback_by_assessment": self._count(x["verdict_assessment"] for x in self.feedback), "notes_total": sum(1 for n in self.notes if n["kind"] == "note"),
                    "jobs_by_status": {}, "oldest_queued_age_seconds": None}

    def provider_outcomes(self, hours=24):
        cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=max(1, int(hours)))).isoformat()
        by, last = {}, None
        with self._inner._lock:
            for cid, items in self._inner.evidence.items():
                created = self._inner.cases[cid]["created_at"]
                for e in items:
                    if e["kind"] != "tool_call" or e["source"] != "reputation_lookup" or created < cutoff:
                        continue
                    p = e["payload"]
                    status = (p.get("data") or {}).get("status") or (p.get("error") or {}).get("code") or "unknown"
                    by[status] = by.get(status, 0) + 1
                    if status == "ok" and (last is None or created > last):
                        last = created
        return {"by_status": by, "last_lookup_at": last, "hours": int(hours)}


def _as_utc(text):
    value = datetime.datetime.fromisoformat(text.replace("Z", "+00:00").replace(" ", "T"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=datetime.timezone.utc)
    return value.isoformat()
