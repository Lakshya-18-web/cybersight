"""The case store, as one interface with two implementations.

  PgRepository      the real thing. Every write goes through a SECURITY DEFINER function from migration 0003, so the rules (idempotency, approval state machine,
                    append-only evidence, audit chain) are enforced by PostgreSQL and not by this file.
  MemoryRepository  (week4.db.fake) an in-process stand-in with the same observable behaviour, for offline unit tests of the API and the graph.
                    Both are run through the same contract tests (tests/test_week4_repository_contract.py).

Everything returned is plain JSON-safe data (dict / list / str / number / bool / None). Outcomes of business rules are returned as a dict with an
"outcome" key, never raised; only invalid input (ValueError) and database failures (DbError) raise.
"""
import re
import uuid

from week4.db.drivers import DbError  # noqa: F401  (re-exported for callers)

MAX_PAGE = 200
DEFAULT_PAGE = 50

ROLES = ("viewer", "analyst", "approver", "admin")
CASE_STATUSES = ("auto_closed", "escalated", "needs_review", "resolved")
ACTION_STATES = ("pending", "approved", "rejected")
ANALYST_ID_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")


def parse_uuid(value):
    """A canonical lower-case UUID string, or ValueError."""
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        raise ValueError("not a valid UUID")


def clamp_page(limit, offset):
    """Validate pagination. A limit above MAX_PAGE is refused rather than silently reduced, so a client never believes it saw everything."""
    limit = DEFAULT_PAGE if limit is None else limit
    offset = 0 if offset is None else offset
    if isinstance(limit, bool) or isinstance(offset, bool) or not isinstance(limit, int) or not isinstance(offset, int):
        raise ValueError("limit and offset must be integers")
    if limit < 1 or limit > MAX_PAGE:
        raise ValueError("limit must be between 1 and %d" % MAX_PAGE)
    if offset < 0:
        raise ValueError("offset must not be negative")
    return limit, offset


def check_choice(name, value, allowed):
    if value is not None and value not in allowed:
        raise ValueError("%s must be one of %s" % (name, ", ".join(allowed)))
    return value


class Repository:
    """The interface. See the module docstring."""

    def upsert_analyst(self, analyst_id, role, display_name=None, active=True, actor="system:admin"):
        raise NotImplementedError

    def get_analyst(self, analyst_id):
        raise NotImplementedError

    def ingest_case(self, payload):
        """-> {outcome: created|duplicate|conflict|invalid, case_id, status, detail}"""
        raise NotImplementedError

    def get_case(self, case_id):
        raise NotImplementedError

    def list_cases(self, status=None, memory_mode=None, alert_set=None, limit=None, offset=None):
        raise NotImplementedError

    def list_pending_actions(self, limit=None, offset=None):
        raise NotImplementedError

    def get_action(self, action_id):
        raise NotImplementedError

    def decide_action(self, action_id, decision, actor, reason, idempotency_key):
        """-> {outcome: applied|replayed|conflict|unauthorized|not_found|invalid, action_id, state, decided_by, decided_at, detail}"""
        raise NotImplementedError

    def simulate_execution(self, action_id, actor):
        """-> {outcome: simulated|already_simulated|not_approved|unauthorized|not_found, execution_id, state, detail}. Bookkeeping only: nothing is ever executed."""
        raise NotImplementedError

    def case_evidence(self, case_id):
        raise NotImplementedError

    def case_memory_hits(self, case_id):
        raise NotImplementedError

    def case_history(self, case_id):
        """Audit events for a case, oldest first."""
        raise NotImplementedError

    def action_history(self, action_id):
        """Audit events for one proposed action, oldest first."""
        raise NotImplementedError

    def verify_audit_chain(self):
        """-> {ok: bool, first_bad_event_id: int|None}"""
        raise NotImplementedError

    def ping(self):
        raise NotImplementedError


# --------------------------------------------------------------------------- PostgreSQL
_ACTION_JSON = "to_jsonb(a) - 'row_version'"


def _page_sql(order):
    return " ORDER BY " + order + " LIMIT %s OFFSET %s"


class PgRepository(Repository):
    def __init__(self, driver):
        self.db = driver

    # -- helpers
    def _one(self, sql, params=()):
        return self.db.query_json("SELECT to_jsonb(t) FROM (" + sql + ") t", params)

    def _list(self, sql, params=()):
        return self.db.query_json("SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (" + sql + ") t", params) or []

    def ping(self):
        return self.db.scalar("SELECT 1") == "1"

    # -- analysts
    def upsert_analyst(self, analyst_id, role, display_name=None, active=True, actor="system:admin"):
        if not isinstance(analyst_id, str) or not ANALYST_ID_RE.match(analyst_id):
            raise ValueError("analyst_id must be 1-64 characters from A-Z a-z 0-9 _ . @ -")
        check_choice("role", role, ROLES)
        if role is None:
            raise ValueError("role is required")
        script = (
            "BEGIN;\n"
            "INSERT INTO soc.analysts (analyst_id, display_name, role, active) VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (analyst_id) DO UPDATE SET display_name = EXCLUDED.display_name, role = EXCLUDED.role, active = EXCLUDED.active;\n"
            "SELECT soc.audit(%s, 'analyst_upserted', 'analyst', %s, NULL, jsonb_build_object('role', %s::text, 'active', %s::boolean));\n"
            "COMMIT;"
        )
        from week4.db.drivers import bind
        self.db.run_script(bind(script, [analyst_id, display_name, role, bool(active), actor, analyst_id, role, bool(active)]))
        return self.get_analyst(analyst_id)

    def get_analyst(self, analyst_id):
        if not isinstance(analyst_id, str) or not ANALYST_ID_RE.match(analyst_id):
            return None
        return self._one("SELECT analyst_id, display_name, role, active, created_at FROM soc.analysts WHERE analyst_id = %s", [analyst_id])

    # -- cases
    def ingest_case(self, payload):
        row = self._one("SELECT * FROM soc.ingest_case(%s)", [payload])
        return {"outcome": row["outcome"], "case_id": row["o_case_id"], "status": row["o_status"], "detail": row["detail"]}

    def get_case(self, case_id):
        case_id = parse_uuid(case_id)
        return self.db.query_json(
            """SELECT jsonb_build_object(
                 'case_id', c.case_id, 'idempotency_key', c.idempotency_key, 'payload_sha256', c.payload_sha256, 'alert_set', c.alert_set,
                 'alert_id', c.alert_id, 'run_name', c.run_name, 'graph_version', c.graph_version, 'memory_mode', c.memory_mode,
                 'alert', c.alert, 'provenance', c.provenance, 'status', c.status, 'created_at', c.created_at, 'updated_at', c.updated_at,
                 'verdict', (SELECT to_jsonb(v) - 'verdict_id' FROM soc.verdicts v WHERE v.case_id = c.case_id),
                 'routing', (SELECT to_jsonb(r) FROM soc.routing_decisions r WHERE r.case_id = c.case_id),
                 'actions', (SELECT coalesce(jsonb_agg(""" + _ACTION_JSON + """ ORDER BY a.created_at, a.action_id), '[]'::jsonb)
                             FROM soc.proposed_actions a WHERE a.case_id = c.case_id))
               FROM soc.cases c WHERE c.case_id = %s::uuid""", [case_id])

    def list_cases(self, status=None, memory_mode=None, alert_set=None, limit=None, offset=None):
        limit, offset = clamp_page(limit, offset)
        check_choice("status", status, CASE_STATUSES)
        check_choice("memory_mode", memory_mode, ("off", "on"))
        check_choice("alert_set", alert_set, ("dev", "synthetic"))
        where = "WHERE (%s::text IS NULL OR c.status = %s::text) AND (%s::text IS NULL OR c.memory_mode = %s::text) AND (%s::text IS NULL OR c.alert_set = %s::text)"
        flt = [status, status, memory_mode, memory_mode, alert_set, alert_set]
        total = int(self.db.scalar("SELECT count(*) FROM soc.cases c " + where, flt))
        items = self._list(
            """SELECT c.case_id, c.alert_set, c.alert_id, c.run_name, c.graph_version, c.memory_mode, c.status, c.created_at, c.updated_at,
                      v.status AS verdict_status, v.attack_type, v.severity, v.is_malicious, r.decision AS routing_decision, r.risk_level,
                      (SELECT count(*) FROM soc.proposed_actions a WHERE a.case_id = c.case_id AND a.state = 'pending') AS pending_actions
               FROM soc.cases c LEFT JOIN soc.verdicts v USING (case_id) LEFT JOIN soc.routing_decisions r USING (case_id) """ + where + _page_sql("c.created_at DESC, c.case_id"),
            flt + [limit, offset])
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    # -- actions
    def list_pending_actions(self, limit=None, offset=None):
        limit, offset = clamp_page(limit, offset)
        total = int(self.db.scalar("SELECT count(*) FROM soc.pending_approvals"))
        items = self._list("SELECT * FROM soc.pending_approvals" + _page_sql("created_at, action_id"), [limit, offset])
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    def get_action(self, action_id):
        action_id = parse_uuid(action_id)
        return self.db.query_json(
            """SELECT jsonb_build_object(
                 'action', (SELECT """ + _ACTION_JSON + """ FROM soc.proposed_actions a WHERE a.action_id = %s::uuid),
                 'decision', (SELECT to_jsonb(d) - 'decision_id' FROM soc.approval_decisions d WHERE d.action_id = %s::uuid),
                 'execution', (SELECT to_jsonb(e) FROM soc.executed_actions e WHERE e.action_id = %s::uuid))
               WHERE EXISTS (SELECT 1 FROM soc.proposed_actions WHERE action_id = %s::uuid)""", [action_id] * 4)

    def decide_action(self, action_id, decision, actor, reason, idempotency_key):
        action_id = parse_uuid(action_id)
        row = self._one("SELECT * FROM soc.decide_action(%s::uuid, %s, %s, %s, %s)", [action_id, decision, actor, reason, idempotency_key])
        return {"outcome": row["outcome"], "action_id": row["o_action_id"], "state": row["o_state"], "decided_by": row["o_decided_by"],
                "decided_at": row["o_decided_at"], "detail": row["detail"]}

    def simulate_execution(self, action_id, actor):
        action_id = parse_uuid(action_id)
        row = self._one("SELECT * FROM soc.simulate_execution(%s::uuid, %s)", [action_id, actor])
        return {"outcome": row["outcome"], "execution_id": row["o_execution_id"], "state": row["o_state"], "detail": row["detail"]}

    # -- evidence, memory, history
    def case_evidence(self, case_id):
        case_id = parse_uuid(case_id)
        return self._list("SELECT case_id, kind, ordinal, source, payload, payload_sha256 FROM soc.evidence_items WHERE case_id = %s::uuid ORDER BY kind, ordinal", [case_id])

    def case_memory_hits(self, case_id):
        case_id = parse_uuid(case_id)
        return self._list("SELECT case_id, rank, memory_id, distance, label, source_split, source_ref, manifest_sha256 FROM soc.memory_hits WHERE case_id = %s::uuid ORDER BY rank", [case_id])

    _AUDIT_COLS = "event_id, occurred_at, actor, event_type, entity_type, entity_id, case_id, payload, prev_hash, event_hash"

    def case_history(self, case_id):
        case_id = parse_uuid(case_id)
        return self._list("SELECT " + self._AUDIT_COLS + " FROM soc.audit_events WHERE case_id = %s::uuid ORDER BY event_id", [case_id])

    def action_history(self, action_id):
        action_id = parse_uuid(action_id)
        return self._list("SELECT " + self._AUDIT_COLS + " FROM soc.audit_events WHERE entity_type = 'action' AND entity_id = %s ORDER BY event_id", [action_id])

    def verify_audit_chain(self):
        row = self._one("SELECT ok, first_bad_event_id FROM soc.verify_audit_chain()")
        return {"ok": row["ok"], "first_bad_event_id": row["first_bad_event_id"]}
