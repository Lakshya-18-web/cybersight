"""Api5: the Week 4 Api plus alert ingestion and job status. No web framework here either: dispatch(name, headers, query, path_params, body, raw_body) -> Response.

Order of checks for POST /alerts (each step can only refuse; nothing is stored until the last one):
  authenticate (401) -> active account (403) -> role may submit (403) -> rate limit (429) -> content type (415) -> size and JSON shape (413/400) -> strict field validation (422)
  -> idempotency header (422) -> store the job (created 202 | duplicate 200 | conflict 409 | queue full 429 | store down 503) -> hand it to the queue.
Every refusal at the intake steps writes one audit event (ingest_rejected) with the reason code, field name, size and a SHA-256 of the body, and nothing else.
The identity of the submitter is the authenticated principal; the body cannot name one. The alert set comes from server configuration, never from the request.
Responses never contain submitted values, only ids, codes and the field NAMES that failed.
"""
import re
import threading
import time

from week4.api import handlers as h
from week4.db.drivers import DbError
from week4.db.repository import MAX_PAGE
from week5 import intake, jobs as jobs_module

from . import routes5

SUBMIT_ROLES = ("analyst", "approver", "admin")
JSON_TYPES = ("application/json",)
IDEMPOTENCY_KEY_RE = re.compile(r"[A-Za-z0-9._:\-]{8,200}", re.ASCII)      # fullmatch: the Week 4 pattern uses $, which also accepts a trailing newline
RETRY_AFTER_QUEUE_FULL = 10


class RateLimiter:
    """A token bucket per caller. rate_per_minute 0 disables it. Memory is bounded: idle buckets are dropped and at most max_keys are kept."""

    def __init__(self, rate_per_minute, burst, clock=time.monotonic, max_keys=10000):
        self.rate = float(rate_per_minute) / 60.0
        self.burst = float(burst)
        self.clock, self.max_keys = clock, max_keys
        self.buckets = {}
        self.lock = threading.Lock()

    def allow(self, key):
        """-> (allowed, retry_after_seconds)"""
        if self.rate <= 0:
            return True, 0
        with self.lock:
            now = self.clock()
            tokens, last = self.buckets.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if len(self.buckets) >= self.max_keys and key not in self.buckets:
                self._prune(now)
            if tokens >= 1.0:
                self.buckets[key] = (tokens - 1.0, now)
                return True, 0
            self.buckets[key] = (tokens, now)
            return False, max(1, int((1.0 - tokens) / self.rate) + 1)

    def _prune(self, now):
        full_after = self.burst / self.rate
        for k in [k for k, (_t, last) in self.buckets.items() if now - last >= full_after]:
            del self.buckets[k]
        while len(self.buckets) >= self.max_keys:
            self.buckets.pop(next(iter(self.buckets)))


class Api5(h.Api):
    def __init__(self, repo, auth_config, job_store, dispatcher, settings, service=None, log=None, clock=time.monotonic):
        super().__init__(repo, auth_config, service=service, log=log)
        self.jobs, self.dispatcher, self.settings = job_store, dispatcher, settings
        self.limiter = RateLimiter(settings.rate_limit_per_minute, settings.rate_burst, clock)

    # ------------------------------------------------------------------ dispatch
    def dispatch(self, name, headers=None, query=None, path_params=None, body=None, raw_body=None):
        route = routes5.BY_NAME5.get(name)
        if route is None:
            return super().dispatch(name, headers, query, path_params, body)
        headers, query, path_params = h.lower_headers(headers), dict(query or {}), dict(path_params or {})
        principal = None
        if route.role is not None:
            who = self.auth.authenticate(headers)
            if who is None:
                return h.error(401, "unauthenticated", "a valid credential is required", {"WWW-Authenticate": "Bearer"})
            try:
                principal = self.service.principal(who)
            except DbError:
                return self._unavailable()
            if principal is None or not principal.active:
                return h.error(403, "forbidden", "this account is not active")
            allowed = principal.can_read() if route.role == "read" else (principal.active and principal.role in SUBMIT_ROLES)
            if not allowed:
                self.log("denied", who, route.name)
                return h.error(403, "forbidden", "your role does not allow this")
        try:
            return getattr(self, "_" + name)(principal, headers, query, path_params, body, raw_body)
        except ValueError as exc:
            return h.error(422, "invalid_input", str(exc))
        except DbError:
            return self._unavailable()

    # ------------------------------------------------------------------ health
    def _health_live(self, principal, headers, query, path_params, body, raw_body):
        return h.ok({"status": "ok"})

    def _health_ready(self, principal, headers, query, path_params, body, raw_body):
        try:
            database = bool(self.repo.ping()) and bool(self.jobs.ping())
        except DbError:
            database = False
        if not database:
            return h.error(503, "not_ready", "the database is not reachable")
        broker_ok, _detail = self.dispatcher.queue.ready()
        return h.ok({"status": "ok" if broker_ok else "degraded", "database": True, "broker": bool(broker_ok), "queue_backend": self.dispatcher.queue.name})

    # ------------------------------------------------------------------ jobs
    def _get_job(self, principal, headers, query, path_params, body, raw_body):
        job = self.jobs.get(self._uuid(path_params, "job_id"))
        if job is None:
            return h.error(404, "not_found", "no such job")
        view = jobs_module.public_job(job)
        view["case_url"] = ("/cases/" + view["case_id"]) if view.get("case_id") else None
        return h.ok(view)

    def _list_jobs(self, principal, headers, query, path_params, body, raw_body):
        page = self._page(query)
        status = query.get("status") or None
        result = self.jobs.list_jobs(status=status, limit=page["limit"], offset=page["offset"])
        result = dict(result, items=[jobs_module.public_job(j) for j in result["items"]])
        return h.ok(self._with_next(result))

    # ------------------------------------------------------------------ submit
    def _audit_rejection(self, principal, code, field, raw):
        size = len(raw) if isinstance(raw, (bytes, bytearray)) else (len(str(raw)) if raw is not None else 0)
        digest = intake.body_sha256(raw if raw is not None else b"")
        try:
            self.jobs.record_security_event("api:" + principal.analyst_id, "ingest_rejected", digest, None, {"code": code, "field": field, "bytes": size, "body_sha256": digest})
        except (DbError, ValueError):
            self.log("audit_not_recorded", code)

    def _submit_alert(self, principal, headers, query, path_params, body, raw_body):
        ok_, retry_after = self.limiter.allow(principal.analyst_id)
        if not ok_:
            return h.error(429, "rate_limited", "too many submissions; slow down", {"Retry-After": str(retry_after)})
        ctype = (headers.get("content-type") or "").split(";")[0].strip().lower()
        if ctype not in JSON_TYPES:
            return h.error(415, "unsupported_media_type", "send the body as application/json")
        if raw_body is None:
            raw_body = intake.canonical(body).encode("utf-8") if isinstance(body, dict) else b""
        try:
            parsed = intake.parse_body(raw_body, self.settings.max_body_bytes)
            submission = intake.validate_submission(parsed, self.settings.default_memory, memory_allowed=bool(self.settings.memory_dir))
        except intake.IntakeError as rejection:
            self._audit_rejection(principal, rejection.code, rejection.field, raw_body)
            status = 413 if rejection.code == intake.TOO_LARGE else (400 if rejection.code == intake.BAD_BODY else 422)
            return h.Response(status, {"error": {"code": "invalid_alert" if status == 422 else rejection.code, "reason": rejection.code, "field": rejection.field, "message": str(rejection)}}, {})
        client_key = headers.get("idempotency-key")
        if client_key is not None and client_key != "" and not IDEMPOTENCY_KEY_RE.fullmatch(client_key):
            self._audit_rejection(principal, "bad_idempotency_key", "idempotency-key", raw_body)
            return h.error(422, "invalid_input", "Idempotency-Key must be 8 to 200 characters from A-Z a-z 0-9 . _ : -")
        key = intake.idempotency_key(principal.analyst_id, client_key or None, submission.alert, submission.memory)
        result = self.jobs.submit(submission.alert, self.settings.alert_set, submission.memory, principal.analyst_id, key, intake.payload_sha256(submission.alert, submission.memory),
                                  self.settings.max_attempts, max_queue_depth=self.settings.max_queue_depth, dispatched=self.dispatcher.queue.implicit_dispatch)
        outcome = result["outcome"]
        if outcome == "queue_full":
            return h.error(429, "queue_full", "the queue is full; try again later", {"Retry-After": str(RETRY_AFTER_QUEUE_FULL)})
        if outcome == "conflict":
            return h.Response(409, {"error": {"code": "conflict", "message": "that Idempotency-Key was already used with a different alert"}, "job_id": result["job_id"]}, {})
        if outcome == "invalid":
            return h.error(422, "invalid_input", "the job was refused")
        dispatch = "none"
        if outcome == "created":
            dispatch = self.dispatcher.dispatch(result["job_id"])
        body_out = {"job_id": result["job_id"], "status": result["status"], "duplicate": outcome == "duplicate", "dispatch": dispatch, "status_url": "/jobs/" + result["job_id"]}
        return h.Response(202 if outcome == "created" else 200, body_out, {"Location": "/jobs/" + result["job_id"]})
