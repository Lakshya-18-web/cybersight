"""Api.dispatch(): everything the HTTP layer needs, with no web framework.

dispatch(name, headers, query, path_params, body) -> Response(status, body, headers)

Order of checks for a protected route: authenticate (401) -> the analyst must exist and be active (403) -> the role must allow the route (403) -> validate input (422/400) -> act.
Business outcomes map to statuses: applied 200, replayed 200 (replayed=true), conflict 409, unauthorized 403, not found 404, invalid 422, store unavailable 503 (no internals in the message).
The identity used for a decision is the authenticated principal. The request body has no field for it, and an unknown field is refused.
"""
import re
from collections import namedtuple

from pydantic import ValidationError

from week4.approval import ApprovalService, AuthorizationError
from week4.db.drivers import DbError
from week4.db.repository import MAX_PAGE, parse_uuid

from . import routes
from .schemas import DecisionRequest

Response = namedtuple("Response", "status body headers")
IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9._:\-]{8,200}$")
DIGITS_RE = re.compile(r"^[0-9]{1,9}$")


def error(status, code, message, headers=None):
    return Response(status, {"error": {"code": code, "message": message}}, headers or {})


def ok(body, status=200):
    return Response(status, body, {})


def lower_headers(headers):
    return {str(k).lower(): v for k, v in (headers or {}).items()}


class Api:
    def __init__(self, repo, auth_config, service=None, log=None):
        self.repo = repo
        self.auth = auth_config
        self.service = service or ApprovalService(repo)
        self.log = log or (lambda *a: None)

    # ------------------------------------------------------------------ dispatch
    def dispatch(self, name, headers=None, query=None, path_params=None, body=None):
        route = routes.BY_NAME.get(name)
        if route is None:
            return error(404, "not_found", "no such route")
        headers, query, path_params = lower_headers(headers), dict(query or {}), dict(path_params or {})
        principal = None
        if route.role is not None:
            who = self.auth.authenticate(headers)
            if who is None:
                return error(401, "unauthenticated", "a valid credential is required", {"WWW-Authenticate": "Bearer"})
            try:
                principal = self.service.principal(who)
            except DbError:
                return self._unavailable()
            if principal is None or not principal.active:
                return error(403, "forbidden", "this account is not active")
            allowed = principal.can_decide() if route.role == "decide" else principal.can_read()
            if not allowed:
                self.log("denied", who, route.name)
                return error(403, "forbidden", "your role does not allow this")
        try:
            return getattr(self, "_" + name)(principal, headers, query, path_params, body)
        except ValueError as exc:
            return error(422, "invalid_input", str(exc))
        except AuthorizationError:
            return error(403, "forbidden", "your role does not allow this")
        except DbError:
            return self._unavailable()

    def _unavailable(self):
        self.log("store_error")
        return error(503, "store_unavailable", "the case store is not available right now; nothing was changed by this request")

    # ------------------------------------------------------------------ input helpers
    @staticmethod
    def _page(query):
        out = {}
        for key, default in (("limit", None), ("offset", None)):
            raw = query.get(key)
            if raw is None or raw == "":
                out[key] = default
            elif isinstance(raw, int) and not isinstance(raw, bool):
                out[key] = raw
            elif isinstance(raw, str) and DIGITS_RE.match(raw):
                out[key] = int(raw)
            else:
                raise ValueError(key + " must be a non-negative whole number")
        if out["limit"] is not None and not 1 <= out["limit"] <= MAX_PAGE:
            raise ValueError("limit must be between 1 and %d" % MAX_PAGE)
        return out

    @staticmethod
    def _uuid(path_params, key):
        try:
            return parse_uuid(path_params.get(key))
        except ValueError:
            raise ValueError(key + " is not a valid id") from None

    @staticmethod
    def _with_next(page):
        nxt = page["offset"] + len(page["items"])
        page["next_offset"] = nxt if nxt < page["total"] else None
        return page

    # ------------------------------------------------------------------ handlers
    def _health(self, principal, headers, query, path_params, body):
        try:
            alive = self.repo.ping()
        except DbError:
            return error(503, "store_unavailable", "the case store is not reachable")
        return ok({"status": "ok" if alive else "degraded", "auth_mode": self.auth.mode})

    def _list_cases(self, principal, headers, query, path_params, body):
        page = self._page(query)
        return ok(self._with_next(self.repo.list_cases(status=query.get("status") or None, memory_mode=query.get("memory_mode") or None, alert_set=query.get("alert_set") or None, **page)))

    def _get_case(self, principal, headers, query, path_params, body):
        case = self.repo.get_case(self._uuid(path_params, "case_id"))
        return ok(case) if case else error(404, "not_found", "no such case")

    def _case_exists(self, case_id):
        return self.repo.get_case(case_id) is not None

    def _case_evidence(self, principal, headers, query, path_params, body):
        case_id = self._uuid(path_params, "case_id")
        if not self._case_exists(case_id):
            return error(404, "not_found", "no such case")
        return ok({"case_id": case_id, "items": self.repo.case_evidence(case_id)})

    def _case_memory(self, principal, headers, query, path_params, body):
        case_id = self._uuid(path_params, "case_id")
        case = self.repo.get_case(case_id)
        if case is None:
            return error(404, "not_found", "no such case")
        return ok({"case_id": case_id, "memory_mode": case["memory_mode"], "memory": (case.get("provenance") or {}).get("memory"), "hits": self.repo.case_memory_hits(case_id)})

    def _case_history(self, principal, headers, query, path_params, body):
        case_id = self._uuid(path_params, "case_id")
        if not self._case_exists(case_id):
            return error(404, "not_found", "no such case")
        return ok({"case_id": case_id, "events": self.repo.case_history(case_id)})

    def _pending_approvals(self, principal, headers, query, path_params, body):
        return ok(self._with_next(self.repo.list_pending_actions(**self._page(query))))

    def _get_action(self, principal, headers, query, path_params, body):
        action_id = self._uuid(path_params, "action_id")
        got = self.repo.get_action(action_id)
        if got is None:
            return error(404, "not_found", "no such action")
        return ok(dict(got, history=self.repo.action_history(action_id)))

    def _decide(self, principal, headers, query, path_params, body):
        action_id = self._uuid(path_params, "action_id")
        key = headers.get("idempotency-key")
        if key is None or key == "":
            return error(400, "idempotency_key_required", "send an Idempotency-Key header (8 to 200 characters) so a retry cannot decide twice")
        if not IDEMPOTENCY_RE.match(key):
            return error(422, "invalid_input", "Idempotency-Key must be 8 to 200 characters from A-Z a-z 0-9 . _ : -")
        if not isinstance(body, dict):
            return error(422, "invalid_input", "the body must be a JSON object")
        try:
            req = DecisionRequest(**body)
        except (ValidationError, TypeError) as exc:
            fields = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()}) if isinstance(exc, ValidationError) else []
            return error(422, "invalid_input", "invalid decision request" + (": check " + ", ".join(fields) if fields else ""))
        result = self.service.decide(principal, action_id, req.decision, req.reason, key)
        self.log("decision", principal.analyst_id, action_id, result["outcome"])
        outcome = result["outcome"]
        if outcome in ("applied", "replayed"):
            got = self.repo.get_action(action_id)
            return ok({"outcome": outcome, "replayed": outcome == "replayed", "action": got["action"], "decision": got["decision"], "execution": got["execution"]})
        if outcome == "conflict":
            got = self.repo.get_action(action_id)
            return Response(409, {"error": {"code": "conflict", "message": result["detail"]}, "action": got["action"] if got else None}, {})
        if outcome == "not_found":
            return error(404, "not_found", "no such action")
        if outcome == "unauthorized":
            return error(403, "forbidden", "your role does not allow this")
        return error(422, "invalid_input", result.get("detail") or "invalid decision request")

    def _simulate_execution(self, principal, headers, query, path_params, body):
        action_id = self._uuid(path_params, "action_id")
        result = self.service.execute_simulated(principal, action_id)
        self.log("simulate", principal.analyst_id, action_id, result["outcome"])
        outcome = result["outcome"]
        if outcome in ("simulated", "already_simulated"):
            got = self.repo.get_action(action_id)
            return ok({"outcome": outcome, "mode": "simulated", "action": got["action"], "execution": got["execution"]}, 201 if outcome == "simulated" else 200)
        if outcome == "not_approved":
            return error(409, "not_approved", result["detail"])
        if outcome == "not_found":
            return error(404, "not_found", "no such action")
        return error(403, "forbidden", "your role does not allow this")
