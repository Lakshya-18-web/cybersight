"""The job store: durable state of every submitted alert, as one interface with two implementations (the same pattern as week4.db.repository).

  PgJobStore      the real thing. Every write goes through a SECURITY DEFINER function of Week 5 migration 0001, so the rules (one owner per running job, terminal states are final,
                  bounded attempts, append-only events, no credential-shaped keys) are enforced by PostgreSQL and not by this file.
  MemoryJobStore  an in-process stand-in with the same observable behaviour, for offline tests and for the fake-model load test. Both pass the same contract tests (tests/test_week5_jobs.py).

States:  queued -> running -> succeeded | failed | timed_out;  running -> queued (a retry after a failed attempt, or after a lost worker). Terminal states never change.
Business outcomes are RETURNED as a dict with an "outcome" key (never raised); only invalid input (ValueError) and database failures (DbError) raise.
Everything returned is plain JSON-safe data. A job never contains a credential: the alert is validated (week5.intake) before it gets here, and the database refuses credential-shaped keys.
"""
import copy
import datetime
import threading
import uuid

from week4.db.drivers import DbError
from week4.db.repository import clamp_page, check_choice, parse_uuid

STATUSES = ("queued", "running", "succeeded", "failed", "timed_out")
TERMINAL = ("succeeded", "failed", "timed_out")
DETAIL_MAX = 500
SECURITY_EVENTS = ("ingest_rejected", "response_withheld", "policy_violation")


def clip(text, limit=DETAIL_MAX):
    return str(text)[:limit]


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


_TS_RE = None


def parse_ts(value):
    """An aware datetime from an ISO string (as PostgreSQL's to_jsonb or MemoryJobStore writes it), or None. Accepts 1-6 fractional digits and +00 / +00:00 / Z offsets."""
    global _TS_RE
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        return value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)
    import re
    if _TS_RE is None:
        _TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}(?::?\d{2})?)?$")
    m = _TS_RE.match(str(value).strip())
    if not m:
        raise ValueError("not a timestamp")
    date, clock, frac, zone = m.groups()
    frac = (frac or "").ljust(6, "0")
    if zone is None or zone == "Z":
        offset = "+00:00"
    else:
        digits = zone[1:].replace(":", "")
        offset = zone[0] + digits[:2] + ":" + (digits[2:4] or "00")
    return datetime.datetime.fromisoformat(date + "T" + clock + "." + frac + offset)


PUBLIC_KEYS = ("job_id", "status", "attempts", "max_attempts", "alert_id", "alert_set", "memory_mode", "submitted_by", "enqueued_at", "first_started_at", "started_at",
               "finished_at", "not_before", "case_id", "error_code", "error_detail", "result", "timings", "usage")


def public_job(job):
    """The view of a job that API clients get: no lease owner, no idempotency key, no payload hash, no alert body."""
    if job is None:
        return None
    return {k: job.get(k) for k in PUBLIC_KEYS}


class JobStore:
    """The interface. See the module docstring."""

    def submit(self, alert, alert_set, memory_mode, submitted_by, idempotency_key, payload_sha256, max_attempts, max_queue_depth=None, dispatched=False):
        """-> {outcome: created|duplicate|conflict|queue_full|invalid, job_id, status, detail}"""
        raise NotImplementedError

    def get(self, job_id):
        raise NotImplementedError

    def list_jobs(self, status=None, submitted_by=None, limit=None, offset=None):
        raise NotImplementedError

    def events(self, job_id):
        raise NotImplementedError

    def claim(self, worker, lease_seconds, job_id=None):
        """One due queued job, now running and owned by worker; or None."""
        raise NotImplementedError

    def heartbeat(self, job_id, worker, lease_seconds):
        raise NotImplementedError

    def complete(self, job_id, worker, case_id, result=None, timings=None, usage=None):
        """-> {outcome: completed|already_complete|not_owner|not_found, status}"""
        raise NotImplementedError

    def fail(self, job_id, worker, code, detail, retryable, delay_seconds=0, timed_out=False):
        """-> {outcome: retry_scheduled|failed|not_owner|not_found, status}"""
        raise NotImplementedError

    def reap_expired(self, limit=100):
        """-> [{job_id, status}] for every job whose worker lease ran out."""
        raise NotImplementedError

    def mark_dispatched(self, job_id):
        raise NotImplementedError

    def undispatched(self, older_than_seconds, limit=100):
        """-> [job_id] of due queued jobs never handed to the broker, or not within older_than_seconds."""
        raise NotImplementedError

    def record_security_event(self, actor, event_type, entity_id, case_id=None, payload=None):
        raise NotImplementedError

    def stats(self):
        """-> {status: {n, oldest_age_seconds}} for every status that has jobs."""
        raise NotImplementedError

    def ping(self):
        raise NotImplementedError


# --------------------------------------------------------------------------- PostgreSQL
class PgJobStore(JobStore):
    def __init__(self, driver):
        self.db = driver

    def _row(self, sql, params=()):
        return self.db.query_json("SELECT to_jsonb(t) FROM (" + sql + ") t", params)

    def _list(self, sql, params=()):
        return self.db.query_json("SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (" + sql + ") t", params) or []

    def ping(self):
        return self.db.scalar("SELECT 1") in (1, "1")      # psycopg returns an int (your fix), the psql driver the text "1" (the repository's own PostgreSQL tests use it)

    def submit(self, alert, alert_set, memory_mode, submitted_by, idempotency_key, payload_sha256, max_attempts, max_queue_depth=None, dispatched=False):
        payload = {"idempotency_key": idempotency_key, "payload_sha256": payload_sha256, "alert": alert, "alert_id": alert["alert_id"], "alert_set": alert_set, "memory_mode": memory_mode,
                   "submitted_by": submitted_by, "max_attempts": int(max_attempts), "dispatched": bool(dispatched)}
        if max_queue_depth is not None:
            payload["max_queue_depth"] = int(max_queue_depth)
        import json
        row = self._row("SELECT * FROM soc.submit_job(%s::jsonb)", [json.dumps(payload)])
        return {"outcome": row["outcome"], "job_id": row["o_job_id"], "status": row["o_status"], "detail": row["detail"]}

    def get(self, job_id):
        job_id = parse_uuid(job_id)
        job = self._row("SELECT * FROM soc.jobs WHERE job_id = %s::uuid", [job_id])
        if job:
            job.pop("row_version", None)
        return job

    def list_jobs(self, status=None, submitted_by=None, limit=None, offset=None):
        limit, offset = clamp_page(limit, offset)
        check_choice("status", status, STATUSES)
        where = "WHERE (%s::text IS NULL OR status = %s::text) AND (%s::text IS NULL OR submitted_by = %s::text)"
        flt = [status, status, submitted_by, submitted_by]
        total = int(self.db.scalar("SELECT count(*) FROM soc.jobs " + where, flt))
        items = self._list("SELECT job_id, status, attempts, max_attempts, alert_id, alert_set, memory_mode, submitted_by, enqueued_at, first_started_at, started_at, finished_at, "
                           "not_before, case_id, error_code, error_detail, result, timings, usage FROM soc.jobs " + where + " ORDER BY enqueued_at DESC, job_id LIMIT %s OFFSET %s",
                           flt + [limit, offset])
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    def events(self, job_id):
        job_id = parse_uuid(job_id)
        return self._list("SELECT event_id, occurred_at, event, attempt, detail FROM soc.job_events WHERE job_id = %s::uuid ORDER BY event_id", [job_id])

    def claim(self, worker, lease_seconds, job_id=None):
        job = self._row("SELECT * FROM soc.claim_job(%s, %s, %s::uuid)", [worker, int(lease_seconds), parse_uuid(job_id) if job_id else None])
        if job:
            job.pop("row_version", None)
        return job

    def heartbeat(self, job_id, worker, lease_seconds):
        return self.db.scalar("SELECT soc.heartbeat_job(%s::uuid, %s, %s)", [parse_uuid(job_id), worker, int(lease_seconds)]) == "t"

    def complete(self, job_id, worker, case_id, result=None, timings=None, usage=None):
        # Psycopg does not adapt plain Python dicts to PostgreSQL jsonb automatically.
        # Serialize the JSON payloads and cast the placeholders explicitly.
        import json
        row = self._row(
            "SELECT * FROM soc.complete_job(%s::uuid, %s, %s::uuid, %s::jsonb, %s::jsonb, %s::jsonb)",
            [parse_uuid(job_id), worker, parse_uuid(case_id),
             json.dumps(result or {}, allow_nan=False),
             json.dumps(timings or {}, allow_nan=False),
             json.dumps(usage or {}, allow_nan=False)],
        )
        return {"outcome": row["outcome"], "status": row["o_status"]}

    def fail(self, job_id, worker, code, detail, retryable, delay_seconds=0, timed_out=False):
        row = self._row("SELECT * FROM soc.fail_job(%s::uuid, %s, %s, %s, %s, %s, %s)",
                        [parse_uuid(job_id), worker, code, clip(detail), bool(retryable), int(max(0, delay_seconds)), bool(timed_out)])
        return {"outcome": row["outcome"], "status": row["o_status"]}

    def reap_expired(self, limit=100):
        return [{"job_id": r["o_job_id"], "status": r["o_status"]} for r in self._list("SELECT * FROM soc.reap_expired(%s)", [int(limit)])]

    def mark_dispatched(self, job_id):
        return self.db.scalar("SELECT soc.mark_dispatched(%s::uuid)", [parse_uuid(job_id)]) == "t"

    def undispatched(self, older_than_seconds, limit=100):
        return [r["o_job_id"] for r in self._list("SELECT * FROM soc.undispatched_jobs(%s, %s)", [int(older_than_seconds), int(limit)])]

    def record_security_event(self, actor, event_type, entity_id, case_id=None, payload=None):
        if event_type not in SECURITY_EVENTS:
            raise ValueError("unknown security event type")
        self.db.run_script(_bind("SELECT soc.record_security_event(%s, %s, %s, %s::uuid, %s);", [actor, event_type, entity_id, parse_uuid(case_id) if case_id else None, payload or {}]))

    def stats(self):
        rows = self._list("SELECT status, n, oldest_age_seconds FROM soc.job_stats")
        return {r["status"]: {"n": int(r["n"]), "oldest_age_seconds": float(r["oldest_age_seconds"]) if r["oldest_age_seconds"] is not None else None} for r in rows}


def _bind(sql, params):
    from week4.db.drivers import bind
    return bind(sql, params)


# --------------------------------------------------------------------------- in-memory
class MemoryJobStore(JobStore):
    """Same rules as the SQL functions. A test double and the store of the in-process load test: nothing is persisted."""

    def __init__(self, clock=None):
        self._lock = threading.RLock()
        self._clock = clock or utcnow
        self.jobs = {}
        self.by_key = {}
        self._events = {}
        self.security_events = []
        self.fail_next = 0          # tests: make the next N calls raise DbError (a database outage)

    # -- helpers
    def _now(self):
        return self._clock()

    def _iso(self, dt):
        return dt.isoformat() if dt is not None else None

    def _check_db(self):
        if self.fail_next > 0:
            self.fail_next -= 1
            raise DbError("the job store is not available (simulated)")

    def _event(self, job_id, event, attempt, detail=None):
        self._events.setdefault(job_id, []).append({"event_id": sum(len(v) for v in self._events.values()) + 1, "occurred_at": self._iso(self._now()), "event": event,
                                                    "attempt": attempt, "detail": copy.deepcopy(detail or {})})

    def _view(self, j):
        out = copy.deepcopy(j)
        for key in ("not_before", "enqueued_at", "dispatched_at", "first_started_at", "started_at", "finished_at", "lease_expires_at"):
            out[key] = self._iso(out[key])
        return out

    def ping(self):
        self._check_db()
        return True

    # -- submit / read
    def submit(self, alert, alert_set, memory_mode, submitted_by, idempotency_key, payload_sha256, max_attempts, max_queue_depth=None, dispatched=False):
        with self._lock:
            self._check_db()
            if not (isinstance(alert, dict) and isinstance(idempotency_key, str) and 8 <= len(idempotency_key) <= 200 and alert_set in ("dev", "synthetic", "sensor") and memory_mode in ("off", "on")
                    and isinstance(payload_sha256, str) and len(payload_sha256) == 64 and 1 <= int(max_attempts) <= 10):
                return {"outcome": "invalid", "job_id": None, "status": None, "detail": "the job payload is not valid"}
            existing = self.jobs.get(self.by_key.get(idempotency_key))
            if existing is not None:
                same = existing["payload_sha256"] == payload_sha256
                return {"outcome": "duplicate" if same else "conflict", "job_id": existing["job_id"], "status": existing["status"],
                        "detail": "the same alert was already submitted; nothing new was queued" if same else "the idempotency key was already used with a different alert; nothing was queued"}
            if max_queue_depth is not None and sum(1 for j in self.jobs.values() if j["status"] in ("queued", "running")) >= max_queue_depth:
                return {"outcome": "queue_full", "job_id": None, "status": None, "detail": "the queue is full; try again later"}
            now = self._now()
            job_id = str(uuid.uuid4())
            self.jobs[job_id] = {"job_id": job_id, "idempotency_key": idempotency_key, "payload_sha256": payload_sha256, "alert_id": alert["alert_id"], "alert_set": alert_set,
                                 "memory_mode": memory_mode, "alert": copy.deepcopy(alert), "submitted_by": submitted_by, "status": "queued", "attempts": 0,
                                 "max_attempts": int(max_attempts), "not_before": now, "enqueued_at": now, "dispatched_at": now if dispatched else None, "first_started_at": None,
                                 "started_at": None, "finished_at": None, "lease_owner": None, "lease_expires_at": None, "case_id": None, "error_code": None, "error_detail": None,
                                 "result": {}, "timings": {}, "usage": {}}
            self.by_key[idempotency_key] = job_id
            self._event(job_id, "submitted", 0, {"submitted_by": submitted_by})
            return {"outcome": "created", "job_id": job_id, "status": "queued", "detail": "queued"}

    def get(self, job_id):
        job_id = parse_uuid(job_id)
        with self._lock:
            self._check_db()
            j = self.jobs.get(job_id)
            return self._view(j) if j else None

    def list_jobs(self, status=None, submitted_by=None, limit=None, offset=None):
        limit, offset = clamp_page(limit, offset)
        check_choice("status", status, STATUSES)
        with self._lock:
            self._check_db()
            rows = [j for j in self.jobs.values() if (status is None or j["status"] == status) and (submitted_by is None or j["submitted_by"] == submitted_by)]
            rows.sort(key=lambda j: (-j["enqueued_at"].timestamp(), j["job_id"]))
            items = [public_job(self._view(j)) for j in rows[offset:offset + limit]]
            return {"items": items, "total": len(rows), "limit": limit, "offset": offset}

    def events(self, job_id):
        job_id = parse_uuid(job_id)
        with self._lock:
            return copy.deepcopy(self._events.get(job_id, []))

    # -- worker side
    def claim(self, worker, lease_seconds, job_id=None):
        with self._lock:
            self._check_db()
            if not worker or not 5 <= int(lease_seconds) <= 86400:
                raise DbError("a worker id and a lease of 5 to 86400 seconds are required", "22023")
            now = self._now()
            due = [j for j in self.jobs.values() if j["status"] == "queued" and j["not_before"] <= now and (job_id is None or j["job_id"] == parse_uuid(job_id))]
            if not due:
                return None
            j = sorted(due, key=lambda x: (x["not_before"], x["enqueued_at"]))[0]
            j.update(status="running", attempts=j["attempts"] + 1, lease_owner=worker, lease_expires_at=now + datetime.timedelta(seconds=int(lease_seconds)), started_at=now,
                     first_started_at=j["first_started_at"] or now)
            self._event(j["job_id"], "claimed", j["attempts"], {"worker": worker})
            return self._view(j)

    def heartbeat(self, job_id, worker, lease_seconds):
        with self._lock:
            self._check_db()
            j = self.jobs.get(parse_uuid(job_id))
            if j is None or j["status"] != "running" or j["lease_owner"] != worker or not 5 <= int(lease_seconds) <= 86400:
                return False
            j["lease_expires_at"] = self._now() + datetime.timedelta(seconds=int(lease_seconds))
            return True

    def complete(self, job_id, worker, case_id, result=None, timings=None, usage=None):
        with self._lock:
            self._check_db()
            j = self.jobs.get(parse_uuid(job_id))
            if j is None:
                return {"outcome": "not_found", "status": None}
            if j["status"] == "succeeded" and j["case_id"] == parse_uuid(case_id):
                return {"outcome": "already_complete", "status": j["status"]}
            if j["status"] != "running" or j["lease_owner"] != worker:
                return {"outcome": "not_owner", "status": j["status"]}
            j.update(status="succeeded", case_id=parse_uuid(case_id), finished_at=self._now(), lease_owner=None, lease_expires_at=None, error_code=None, error_detail=None,
                     result=copy.deepcopy(result or {}), timings=copy.deepcopy(timings or {}), usage=copy.deepcopy(usage or {}))
            self._event(j["job_id"], "succeeded", j["attempts"], {"case_id": j["case_id"]})
            return {"outcome": "completed", "status": "succeeded"}

    def fail(self, job_id, worker, code, detail, retryable, delay_seconds=0, timed_out=False):
        import re
        if not isinstance(code, str) or not re.match(r"^[a-z0-9_]{1,64}$", code):
            raise DbError("error code must be lower-case letters, digits and underscores", "22023")
        with self._lock:
            self._check_db()
            j = self.jobs.get(parse_uuid(job_id))
            if j is None:
                return {"outcome": "not_found", "status": None}
            if j["status"] != "running" or j["lease_owner"] != worker:
                return {"outcome": "not_owner", "status": j["status"]}
            now = self._now()
            if retryable and j["attempts"] < j["max_attempts"]:
                j.update(status="queued", lease_owner=None, lease_expires_at=None, dispatched_at=None, error_code=code, error_detail=clip(detail),
                         not_before=now + datetime.timedelta(seconds=max(0, delay_seconds)))
                self._event(j["job_id"], "retry_scheduled", j["attempts"], {"code": code, "delay_seconds": max(0, delay_seconds)})
                return {"outcome": "retry_scheduled", "status": "queued"}
            final = "timed_out" if timed_out else "failed"
            j.update(status=final, lease_owner=None, lease_expires_at=None, finished_at=now, error_code=code, error_detail=clip(detail))
            self._event(j["job_id"], final, j["attempts"], {"code": code, "retries_exhausted": bool(retryable) and j["attempts"] >= j["max_attempts"]})
            return {"outcome": "failed", "status": final}

    def reap_expired(self, limit=100):
        with self._lock:
            self._check_db()
            now = self._now()
            out = []
            for j in sorted((x for x in self.jobs.values() if x["status"] == "running" and x["lease_expires_at"] < now), key=lambda x: x["lease_expires_at"])[:max(limit, 1)]:
                owner = j["lease_owner"]
                if j["attempts"] < j["max_attempts"]:
                    j.update(status="queued", lease_owner=None, lease_expires_at=None, dispatched_at=None, error_code="worker_lost",
                             error_detail="the worker stopped before finishing; the job was queued again", not_before=now)
                    self._event(j["job_id"], "lease_expired_requeued", j["attempts"], {"worker": owner})
                else:
                    j.update(status="failed", lease_owner=None, lease_expires_at=None, finished_at=now, error_code="worker_lost",
                             error_detail="the worker stopped before finishing and no attempts were left")
                    self._event(j["job_id"], "lease_expired_failed", j["attempts"], {"worker": owner})
                out.append({"job_id": j["job_id"], "status": j["status"]})
            return out

    def mark_dispatched(self, job_id):
        with self._lock:
            self._check_db()
            j = self.jobs.get(parse_uuid(job_id))
            if j is None or j["status"] != "queued":
                return False
            j["dispatched_at"] = self._now()
            return True

    def undispatched(self, older_than_seconds, limit=100):
        with self._lock:
            self._check_db()
            now = self._now()
            cutoff = now - datetime.timedelta(seconds=max(1, older_than_seconds))
            rows = [j for j in self.jobs.values() if j["status"] == "queued" and j["not_before"] <= now and (j["dispatched_at"] is None or j["dispatched_at"] < cutoff)]
            rows.sort(key=lambda j: j["enqueued_at"])
            return [j["job_id"] for j in rows[:max(limit, 1)]]

    def record_security_event(self, actor, event_type, entity_id, case_id=None, payload=None):
        if event_type not in SECURITY_EVENTS:
            raise ValueError("unknown security event type")
        with self._lock:
            self._check_db()
            self.security_events.append({"actor": actor, "event_type": event_type, "entity_id": entity_id, "case_id": case_id, "payload": copy.deepcopy(payload or {})})

    def stats(self):
        with self._lock:
            self._check_db()
            now = self._now()
            out = {}
            for j in self.jobs.values():
                s = out.setdefault(j["status"], {"n": 0, "oldest": None})
                s["n"] += 1
                s["oldest"] = j["enqueued_at"] if s["oldest"] is None else min(s["oldest"], j["enqueued_at"])
            return {k: {"n": v["n"], "oldest_age_seconds": (now - v["oldest"]).total_seconds()} for k, v in out.items()}
