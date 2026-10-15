"""MemoryRepository: an in-process Repository with the same rules as the PostgreSQL schema, for offline tests.

It is a test double, not an alternative store: nothing is persisted. It copies the behaviour of migrations 0001-0003 closely enough that the same contract tests pass
against both implementations (tests/test_week4_repository_contract.py). Where a database CHECK/trigger would raise, this raises DbError with the same SQLSTATE class.
"""
import copy
import datetime
import hashlib
import json
import re
import threading
import uuid

from week4.db.drivers import DbError
from week4.db.repository import (Repository, ROLES, ANALYST_ID_RE, check_choice, clamp_page, parse_uuid)

SECRET_RE = re.compile(r'"[^"]*(password|passwd|secret|api[_-]?key|authorization|bearer|access[_-]?token|auth[_-]?token|private[_-]?key|credential)[^"]*"\s*:', re.I)
ANSWER_KEYS = ("label", "Label", "is_attack", "source_file", "original_row", "source_alert_id", "mitre_tactic", "mitre_technique_id", "mitre_accepted_ids")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
ACTION_TYPES = ("block_source_ip", "isolate_host", "rate_limit_source", "increase_monitoring")
EVIDENCE_KINDS = ("tool_call", "specialist_finding", "memory_summary", "graph_error", "routing_step")
REQUIRED = ("idempotency_key", "payload_sha256", "alert_set", "alert_id", "run_name", "graph_version", "memory_mode", "alert", "routing")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _check(cond, message, state="23514"):
    if not cond:
        raise DbError(message, state)


def has_secret_key(obj):
    return bool(SECRET_RE.search(json.dumps(obj, sort_keys=True)))


class MemoryRepository(Repository):
    def __init__(self):
        self._lock = threading.RLock()
        self.analysts = {}
        self.cases = {}
        self.verdicts = {}
        self.routing = {}
        self.evidence = {}
        self.hits = {}
        self.actions = {}
        self.decisions = {}
        self.decision_keys = {}
        self.executions = {}
        self.audit_events = []

    # -- audit (hash chain, same idea as the SQL trigger; the exact hash function differs)
    @staticmethod
    def _hash(prev, event):
        body = json.dumps([prev, event["event_id"], event["occurred_at"], event["actor"], event["event_type"], event["entity_type"], event["entity_id"], event["case_id"], event["payload"]],
                          sort_keys=True)
        return hashlib.sha256(body.encode("utf-8")).hexdigest()

    def _audit(self, actor, kind, entity_type, entity_id, case_id, payload):
        _check(not has_secret_key(payload or {}), "audit payload looks like a credential")
        prev = self.audit_events[-1]["event_hash"] if self.audit_events else "GENESIS"
        event = {"event_id": len(self.audit_events) + 1, "occurred_at": _now(), "actor": actor or "unknown", "event_type": kind, "entity_type": entity_type,
                 "entity_id": str(entity_id), "case_id": case_id, "payload": copy.deepcopy(payload or {}), "prev_hash": prev}
        event["event_hash"] = self._hash(prev, event)
        self.audit_events.append(event)

    def ping(self):
        return True

    # -- analysts
    def upsert_analyst(self, analyst_id, role, display_name=None, active=True, actor="system:admin"):
        if not isinstance(analyst_id, str) or not ANALYST_ID_RE.match(analyst_id):
            raise ValueError("analyst_id must be 1-64 characters from A-Z a-z 0-9 _ . @ -")
        check_choice("role", role, ROLES)
        if role is None:
            raise ValueError("role is required")
        with self._lock:
            old = self.analysts.get(analyst_id)
            self.analysts[analyst_id] = {"analyst_id": analyst_id, "display_name": display_name, "role": role, "active": bool(active), "created_at": old["created_at"] if old else _now()}
            self._audit(actor, "analyst_upserted", "analyst", analyst_id, None, {"role": role, "active": bool(active)})
            return copy.deepcopy(self.analysts[analyst_id])

    def get_analyst(self, analyst_id):
        if not isinstance(analyst_id, str) or not ANALYST_ID_RE.match(analyst_id):
            return None
        with self._lock:
            return copy.deepcopy(self.analysts.get(analyst_id))

    def _is_approver(self, actor):
        who = self.analysts.get(actor) if isinstance(actor, str) else None
        return bool(who and who["active"] and who["role"] in ("approver", "admin"))

    # -- ingest
    def ingest_case(self, p):
        with self._lock:
            if not isinstance(p, dict) or any(k not in p or p[k] is None for k in REQUIRED):
                return {"outcome": "invalid", "case_id": None, "status": None, "detail": "the case payload is missing required keys"}
            routing = p["routing"]
            verdict = p.get("verdict")
            decision = routing.get("decision") if isinstance(routing, dict) else None
            actions = p.get("actions") if isinstance(p.get("actions"), list) else []
            if decision not in ("auto_close", "escalate", "needs_review"):
                return {"outcome": "invalid", "case_id": None, "status": None, "detail": "unknown routing decision"}
            if decision == "auto_close" and (not isinstance(verdict, dict) or verdict.get("status") != "ok" or verdict.get("is_malicious") is not False):
                return {"outcome": "invalid", "case_id": None, "status": None, "detail": "auto_close needs a complete benign verdict"}
            if decision != "escalate" and actions:
                return {"outcome": "invalid", "case_id": None, "status": None, "detail": "only an escalated case may carry proposed actions"}

            key = p["idempotency_key"]
            existing = next((c for c in self.cases.values() if c["idempotency_key"] == key), None)
            if existing is not None:
                outcome = "duplicate" if existing["payload_sha256"] == p["payload_sha256"] else "conflict"
                self._audit(p.get("ingested_by") or "system:ingest", "case_" + outcome, "case", existing["case_id"], existing["case_id"], {"idempotency_key": key})
                return {"outcome": outcome, "case_id": existing["case_id"], "status": existing["status"],
                        "detail": "the same case was already stored; nothing was written" if outcome == "duplicate"
                        else "the idempotency key exists with a different payload; nothing was written"}

            # validate everything before storing anything, as the single SQL transaction would roll back
            _check(isinstance(key, str) and 8 <= len(key) <= 200, "bad idempotency_key")
            _check(isinstance(p["payload_sha256"], str) and SHA_RE.match(p["payload_sha256"]), "bad payload_sha256")
            _check(p["alert_set"] in ("dev", "synthetic"), "alert_set must be dev or synthetic")
            _check(isinstance(p["alert_id"], str) and 1 <= len(p["alert_id"]) <= 200, "bad alert_id")
            _check(p["memory_mode"] in ("off", "on"), "bad memory_mode")
            _check(isinstance(p["alert"], dict) and not any(k in p["alert"] for k in ANSWER_KEYS), "the alert carries an answer-bearing key")
            prov = p.get("provenance") or {}
            _check(isinstance(prov, dict), "provenance must be an object")
            _check(not has_secret_key(p["alert"]) and not has_secret_key(prov), "a record looks like it carries a credential")
            v = verdict if isinstance(verdict, dict) else None
            if v is not None:
                full = all(v.get(k) is not None for k in ("is_malicious", "attack_type", "mitre_technique", "severity"))
                none = all(v.get(k) is None for k in ("is_malicious", "attack_type", "mitre_technique", "severity"))
                _check((v.get("status") == "ok" and full) or (v.get("status") in ("parse_failed", "model_error", "missing") and none), "verdict fields do not match its status")
                _check(v.get("severity") is None or v["severity"] in ("none", "low", "medium", "high", "critical"), "bad severity")
                _check(v.get("evidence_text") is None or len(v["evidence_text"]) <= 2000, "evidence_text too long")
            _check(routing.get("risk_level") in ("low", "medium", "high", "unknown"), "bad risk_level")
            _check(isinstance(routing.get("reasons"), list) and len(routing["reasons"]) >= 1, "routing needs at least one reason")
            _check(isinstance(routing.get("policy_sha256"), str) and SHA_RE.match(routing["policy_sha256"]), "bad policy_sha256")
            seen = set()
            for e in p.get("evidence") or []:
                _check(e.get("kind") in EVIDENCE_KINDS and isinstance(e.get("ordinal"), int) and e["ordinal"] >= 0, "bad evidence item")
                _check((e["kind"], e["ordinal"]) not in seen, "duplicate evidence ordinal", "23505")
                seen.add((e["kind"], e["ordinal"]))
                _check(isinstance(e.get("payload_sha256"), str) and SHA_RE.match(e["payload_sha256"]), "bad evidence hash")
                _check(not has_secret_key(e.get("payload")), "evidence looks like it carries a credential")
            ranks, mids = set(), set()
            for h in p.get("memory_hits") or []:
                _check(h.get("source_split") == "train", "memory hits must come from the train split")
                _check(isinstance(h.get("rank"), int) and h["rank"] >= 1 and h.get("distance", -1) >= 0, "bad memory hit")
                _check(h["rank"] not in ranks and h["memory_id"] not in mids, "duplicate memory hit", "23505")
                ranks.add(h["rank"])
                mids.add(h["memory_id"])
                _check(isinstance(h.get("manifest_sha256"), str) and SHA_RE.match(h["manifest_sha256"]), "bad manifest hash")
            akeys = set()
            for a in actions:
                _check(a.get("action_type") in ACTION_TYPES and 1 <= len(str(a.get("target", ""))) <= 200, "bad proposed action")
                _check((a["action_type"], a["target"]) not in akeys, "duplicate proposed action", "23505")
                akeys.add((a["action_type"], a["target"]))
                _check(not has_secret_key(a.get("parameters") or {}), "action parameters look like a credential")

            case_id = str(uuid.uuid4())
            status = {"auto_close": "auto_closed", "escalate": "escalated", "needs_review": "needs_review"}[decision]
            now = _now()
            self.cases[case_id] = {"case_id": case_id, "idempotency_key": key, "payload_sha256": p["payload_sha256"], "alert_set": p["alert_set"], "alert_id": p["alert_id"],
                                   "run_name": p["run_name"], "graph_version": p["graph_version"], "memory_mode": p["memory_mode"], "alert": copy.deepcopy(p["alert"]),
                                   "provenance": copy.deepcopy(prov), "status": status, "created_at": now, "updated_at": now, "_seq": len(self.cases)}
            if v is not None:
                self.verdicts[case_id] = {"case_id": case_id, "status": v["status"], "is_malicious": v.get("is_malicious"), "attack_type": v.get("attack_type"),
                                          "mitre_technique": v.get("mitre_technique"), "severity": v.get("severity"), "evidence_text": v.get("evidence_text"),
                                          "prompt_version": v.get("prompt_version"), "prompt_sha256": v.get("prompt_sha256"), "model": v.get("model"),
                                          "error_code": v.get("error_code"), "created_at": now}
            else:
                self.verdicts[case_id] = {"case_id": case_id, "status": "missing", "is_malicious": None, "attack_type": None, "mitre_technique": None, "severity": None,
                                          "evidence_text": None, "prompt_version": None, "prompt_sha256": None, "model": None, "error_code": None, "created_at": now}
            self.routing[case_id] = {"case_id": case_id, "decision": decision, "risk_level": routing["risk_level"], "reasons": copy.deepcopy(routing["reasons"]),
                                     "policy_version": routing.get("policy_version"), "policy_sha256": routing["policy_sha256"],
                                     "memory_raised_risk": bool(routing.get("memory_raised_risk", False)), "decided_at": now}
            self.evidence[case_id] = [{"case_id": case_id, "kind": e["kind"], "ordinal": e["ordinal"], "source": e["source"], "payload": copy.deepcopy(e["payload"]),
                                       "payload_sha256": e["payload_sha256"]} for e in p.get("evidence") or []]
            self.hits[case_id] = [{"case_id": case_id, "rank": h["rank"], "memory_id": h["memory_id"], "distance": h["distance"], "label": h["label"], "source_split": h["source_split"],
                                   "source_ref": copy.deepcopy(h["source_ref"]), "manifest_sha256": h["manifest_sha256"]} for h in p.get("memory_hits") or []]
            proposer = p.get("proposed_by") or "agent:graph-v2"
            for a in actions:
                aid = str(uuid.uuid4())
                self.actions[aid] = {"action_id": aid, "case_id": case_id, "action_type": a["action_type"], "target": a["target"], "parameters": copy.deepcopy(a.get("parameters") or {}),
                                     "rationale": a["rationale"], "requires_approval": True, "state": "pending", "proposed_by": proposer, "created_at": now, "decided_at": None,
                                     "decided_by": None, "decision_reason": None, "row_version": 0}
                self._audit(proposer, "action_proposed", "case", case_id, case_id, {"action_type": a["action_type"], "target": a["target"]})
            self._audit(p.get("ingested_by") or "system:ingest", "case_ingested", "case", case_id, case_id,
                        {"decision": decision, "status": status, "proposed_actions": len(actions), "idempotency_key": key})
            return {"outcome": "created", "case_id": case_id, "status": status, "detail": None}

    # -- reads
    def _case_actions(self, case_id):
        rows = sorted((copy.deepcopy(a) for a in self.actions.values() if a["case_id"] == case_id), key=lambda a: (a["created_at"], a["action_id"]))
        for a in rows:
            a.pop("row_version", None)   # internal optimistic-lock counter; not part of the public record
        return rows

    def get_case(self, case_id):
        case_id = parse_uuid(case_id)
        with self._lock:
            c = self.cases.get(case_id)
            if c is None:
                return None
            out = {k: copy.deepcopy(v) for k, v in c.items() if not k.startswith("_")}
            out["verdict"] = copy.deepcopy(self.verdicts.get(case_id))
            out["routing"] = copy.deepcopy(self.routing.get(case_id))
            out["actions"] = self._case_actions(case_id)
            return out

    def _pending_count(self, case_id):
        return sum(1 for a in self.actions.values() if a["case_id"] == case_id and a["state"] == "pending")

    def list_cases(self, status=None, memory_mode=None, alert_set=None, limit=None, offset=None):
        limit, offset = clamp_page(limit, offset)
        check_choice("status", status, ("auto_closed", "escalated", "needs_review", "resolved"))
        check_choice("memory_mode", memory_mode, ("off", "on"))
        check_choice("alert_set", alert_set, ("dev", "synthetic"))
        with self._lock:
            rows = [c for c in self.cases.values() if (status is None or c["status"] == status) and (memory_mode is None or c["memory_mode"] == memory_mode)
                    and (alert_set is None or c["alert_set"] == alert_set)]
            rows.sort(key=lambda c: (c["created_at"], c["_seq"]), reverse=True)
            items = []
            for c in rows[offset:offset + limit]:
                v, r = self.verdicts.get(c["case_id"], {}), self.routing.get(c["case_id"], {})
                items.append({"case_id": c["case_id"], "alert_set": c["alert_set"], "alert_id": c["alert_id"], "run_name": c["run_name"], "graph_version": c["graph_version"],
                              "memory_mode": c["memory_mode"], "status": c["status"], "created_at": c["created_at"], "updated_at": c["updated_at"],
                              "verdict_status": v.get("status"), "attack_type": v.get("attack_type"), "severity": v.get("severity"), "is_malicious": v.get("is_malicious"),
                              "routing_decision": r.get("decision"), "risk_level": r.get("risk_level"), "pending_actions": self._pending_count(c["case_id"])})
            return {"items": items, "total": len(rows), "limit": limit, "offset": offset}

    def list_pending_actions(self, limit=None, offset=None):
        limit, offset = clamp_page(limit, offset)
        with self._lock:
            rows = sorted((a for a in self.actions.values() if a["state"] == "pending"), key=lambda a: (a["created_at"], a["action_id"]))
            items = []
            for a in rows[offset:offset + limit]:
                c, v, r = self.cases[a["case_id"]], self.verdicts.get(a["case_id"], {}), self.routing.get(a["case_id"], {})
                items.append({"action_id": a["action_id"], "case_id": a["case_id"], "action_type": a["action_type"], "target": a["target"], "parameters": copy.deepcopy(a["parameters"]),
                              "rationale": a["rationale"], "created_at": a["created_at"], "proposed_by": a["proposed_by"], "alert_id": c["alert_id"], "alert_set": c["alert_set"],
                              "run_name": c["run_name"], "memory_mode": c["memory_mode"], "case_status": c["status"], "verdict_status": v.get("status"), "attack_type": v.get("attack_type"),
                              "severity": v.get("severity"), "risk_level": r.get("risk_level"), "routing_decision": r.get("decision")})
            return {"items": items, "total": len(rows), "limit": limit, "offset": offset}

    def get_action(self, action_id):
        action_id = parse_uuid(action_id)
        with self._lock:
            a = self.actions.get(action_id)
            if a is None:
                return None
            a = copy.deepcopy(a)
            a.pop("row_version", None)
            d = self.decisions.get(action_id)
            ex = self.executions.get(action_id)
            return {"action": a, "decision": copy.deepcopy(d), "execution": copy.deepcopy(ex)}

    # -- decisions
    def decide_action(self, action_id, decision, actor, reason, idempotency_key):
        action_id = parse_uuid(action_id)
        with self._lock:
            out = {"outcome": None, "action_id": action_id, "state": None, "decided_by": None, "decided_at": None, "detail": None}
            if (decision not in ("approved", "rejected") or not isinstance(actor, str) or not actor.strip() or not isinstance(reason, str) or not reason.strip()
                    or not isinstance(idempotency_key, str) or not 8 <= len(idempotency_key) <= 200):
                out.update(outcome="invalid", detail="decision must be approved or rejected, with an actor, a reason and an idempotency key of 8 to 200 characters")
                return out
            a = self.actions.get(action_id)
            if not self._is_approver(actor):
                self._audit(actor, "approval_denied", "action", action_id, a["case_id"] if a else None, {"attempted": decision, "why": "not an active approver"})
                out.update(outcome="unauthorized", detail="the caller is not an active approver")
                return out
            if a is None:
                out.update(outcome="not_found", detail="no such proposed action")
                return out
            if a["state"] == "pending":
                if idempotency_key in self.decision_keys:
                    self._audit(actor, "decision_conflict", "action", action_id, a["case_id"], {"attempted": decision, "why": "idempotency key used for another request"})
                    out.update(outcome="conflict", state="pending", detail="the idempotency key was already used for another request")
                    return out
                now = _now()
                a.update(state=decision, decided_at=now, decided_by=actor, decision_reason=reason, row_version=a["row_version"] + 1)
                self.decisions[action_id] = {"action_id": action_id, "decision": decision, "decided_by": actor, "reason": reason, "idempotency_key": idempotency_key, "decided_at": now}
                self.decision_keys[idempotency_key] = action_id
                self._audit(actor, "action_approved" if decision == "approved" else "action_rejected", "action", action_id, a["case_id"],
                            {"action_type": a["action_type"], "target": a["target"], "reason": reason, "idempotency_key": idempotency_key})
                if self._pending_count(a["case_id"]) == 0 and self.cases[a["case_id"]]["status"] in ("escalated", "needs_review"):
                    self.cases[a["case_id"]].update(status="resolved", updated_at=now)
                out.update(outcome="applied", state=a["state"], decided_by=actor, decided_at=now)
                return out
            d = self.decisions[action_id]
            out.update(state=a["state"], decided_by=a["decided_by"], decided_at=a["decided_at"])
            if d["idempotency_key"] == idempotency_key and d["decision"] == decision and d["decided_by"] == actor:
                self._audit(actor, "decision_replayed", "action", action_id, a["case_id"], {"decision": decision, "idempotency_key": idempotency_key})
                out.update(outcome="replayed", detail="this request was already applied")
                return out
            self._audit(actor, "decision_conflict", "action", action_id, a["case_id"], {"attempted": decision, "existing": a["state"], "existing_decided_by": a["decided_by"]})
            out.update(outcome="conflict", detail="the proposal is already " + a["state"])
            return out

    def simulate_execution(self, action_id, actor):
        action_id = parse_uuid(action_id)
        with self._lock:
            out = {"outcome": None, "execution_id": None, "state": None, "detail": None}
            a = self.actions.get(action_id)
            if not self._is_approver(actor):
                self._audit(actor, "execution_denied", "action", action_id, a["case_id"] if a else None, {"why": "not an active approver"})
                out.update(outcome="unauthorized", detail="the caller is not an active approver")
                return out
            if a is None:
                out.update(outcome="not_found", detail="no such proposed action")
                return out
            out["state"] = a["state"]
            if a["state"] != "approved":
                self._audit(actor, "execution_blocked", "action", action_id, a["case_id"], {"state": a["state"]})
                out.update(outcome="not_approved", detail="only an approved action can be executed (state is %s)" % a["state"])
                return out
            if action_id in self.executions:
                out.update(outcome="already_simulated", execution_id=self.executions[action_id]["execution_id"], detail="a simulated execution was already recorded")
                return out
            ex = {"execution_id": str(uuid.uuid4()), "action_id": action_id, "mode": "simulated", "executed_by": actor, "executed_at": _now(),
                  "result": {"simulated": True, "action_type": a["action_type"], "target": a["target"], "note": "no live containment was performed"}}
            self.executions[action_id] = ex
            self._audit(actor, "execution_simulated", "action", action_id, a["case_id"], {"action_type": a["action_type"], "target": a["target"]})
            out.update(outcome="simulated", execution_id=ex["execution_id"])
            return out

    # -- evidence, memory, history
    def case_evidence(self, case_id):
        case_id = parse_uuid(case_id)
        with self._lock:
            return sorted(copy.deepcopy(self.evidence.get(case_id, [])), key=lambda e: (e["kind"], e["ordinal"]))

    def case_memory_hits(self, case_id):
        case_id = parse_uuid(case_id)
        with self._lock:
            return sorted(copy.deepcopy(self.hits.get(case_id, [])), key=lambda h: h["rank"])

    def case_history(self, case_id):
        case_id = parse_uuid(case_id)
        with self._lock:
            return [copy.deepcopy(e) for e in self.audit_events if e["case_id"] == case_id]

    def action_history(self, action_id):
        action_id = parse_uuid(action_id)
        with self._lock:
            return [copy.deepcopy(e) for e in self.audit_events if e["entity_type"] == "action" and e["entity_id"] == action_id]

    def verify_audit_chain(self):
        with self._lock:
            prev = "GENESIS"
            for e in self.audit_events:
                if e["prev_hash"] != prev or e["event_hash"] != self._hash(e["prev_hash"], e):
                    return {"ok": False, "first_bad_event_id": e["event_id"]}
                prev = e["event_hash"]
            return {"ok": True, "first_bad_event_id": None}
