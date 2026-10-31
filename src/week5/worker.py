"""The worker: takes one job, runs the Week 4 graph on it, stores the case, records the result.

One job, start to finish (process_claimed):
   claim (the database gives each job to one worker)  ->  GraphRunner.run (time-limited)  ->  repository.ingest_case (idempotent)  ->  store.complete
   any exception  ->  errors.classify  ->  store.fail (retry with back-off, or final failure/timeout)  ->  dispatcher.dispatch (re-publish for the Celery backend)

Safety properties (each has a test):
  * Business outcomes never raise out of process_claimed; the job ends in a recorded state. A worker bug that raises is caught and recorded as `worker_exception` (type name only).
  * If the lease was lost (the reaper gave the job to someone else), complete/fail return not_owner and this worker does NOT touch the job again.
  * A duplicate or conflicting case insert uses the stored case id: the job still finishes, and nothing is stored twice.
  * A security signal from the response guard is written to the audit log (codes only, never the withheld text).
  * Logs are one JSON object per line with a fixed set of keys; no alert content, prompt, model text, key or DSN is ever logged.

Timeouts: the `thread` mode runs the graph in a daemon thread and stops WAITING after the limit. Python cannot kill a thread, so an abandoned thread may finish later; its result is discarded because the job
is already recorded as failed/timed out, and the worker marks itself `abandoned` so a poll worker exits (exit code 75) and the supervisor restarts it with a clean state. Under Celery the `none` mode is used:
Celery's soft limit raises inside the task and its hard limit kills the process.
"""
import argparse
import json
import os
import signal
import socket
import sys
import threading
import time

from week5.db.repository import Week5PgRepository as PgRepository

from . import errors, queues, settings as settings_module
from .jobs import DbError, PgJobStore

EXIT_ABANDONED = 75          # sysexits EX_TEMPFAIL: "try again"; the supervisor restarts the worker
ENV_DB = "WEEK5_WORKER_DATABASE_URL"


def _log_to_stderr(event, **fields):
    allowed = {k: v for k, v in fields.items() if isinstance(v, (str, int, float, bool, type(None)))}
    allowed.update(event=event, ts=round(time.time(), 3))
    sys.stderr.write(json.dumps(allowed, sort_keys=True) + "\n")
    sys.stderr.flush()


class Worker:
    def __init__(self, settings, store, repository, runner, dispatcher=None, worker_id=None, timeout_mode="thread", log=None, clock=time.time, sleep=time.sleep):
        self.settings, self.store, self.repository, self.runner = settings, store, repository, runner
        self.dispatcher = dispatcher
        self.worker_id = worker_id or (socket.gethostname()[:40] + ":" + str(os.getpid()))
        if timeout_mode not in ("thread", "none"):
            raise ValueError("timeout_mode is thread or none")
        self.timeout_mode = timeout_mode
        self.log = log or _log_to_stderr
        self.clock, self.sleep = clock, sleep
        self.abandoned = False
        self.stop = threading.Event()
        self.heartbeat_path = None      # set by main() from WEEK5_HEARTBEAT_FILE; the container health check reads its modification time

    def beat(self):
        """Mark the loop alive. Never raises: a read-only or full disk must not stop a worker."""
        if not self.heartbeat_path:
            return
        try:
            with open(self.heartbeat_path, "w", encoding="ascii") as fh:
                fh.write(str(int(self.clock())))
        except OSError:
            pass

    # ------------------------------------------------------------------ one job
    def _run_limited(self, job, attempt):
        if self.timeout_mode == "none":
            return self.runner.run(job, attempt, job["max_attempts"])
        box = {}

        def target():
            try:
                box["out"] = self.runner.run(job, attempt, job["max_attempts"])
            except BaseException as error:      # handed back to the caller's thread; nothing is lost
                box["error"] = error

        thread = threading.Thread(target=target, name="job-" + str(job["job_id"])[:8], daemon=True)
        thread.start()
        thread.join(self.settings.job_timeout_seconds)
        if thread.is_alive():
            self.abandoned = True
            raise errors.JobTimeout("the job did not finish within its time limit")
        if "error" in box:
            raise box["error"]
        return box["out"]

    def _record_signals(self, job, outcome):
        """One audit event per kind of finding, codes only (never the withheld or flagged text): response_withheld when the guard removed model text, policy_violation when the model's text tried to
        steer the routing or carried control characters (the case is then never auto-closed)."""
        if not outcome.signals:
            return
        from .security import guard
        for event, codes in (("response_withheld", sorted({s.code for s in outcome.signals if s.code in guard.WITHHOLD_CODES})),
                             ("policy_violation", sorted({s.code for s in outcome.signals if s.code in guard.FLAG_CODES}))):
            if not codes:
                continue
            try:
                self.store.record_security_event("worker:" + self.worker_id, event, str(job["job_id"]), None,
                                                 {"job_id": str(job["job_id"]), "alert_id": job["alert_id"], "signals": codes, "attempt": job["attempts"]})
            except (DbError, ValueError):
                self.log("security_event_not_recorded", job_id=str(job["job_id"]))

    def process_claimed(self, job):
        """Run a job that this worker has claimed. Returns the final outcome string (also logged)."""
        job_id, attempt = str(job["job_id"]), int(job["attempts"])
        job = dict(job, lease_owner=job.get("lease_owner") or self.worker_id)
        started = self.clock()
        self.log("job_started", job_id=job_id, attempt=attempt, worker=self.worker_id)
        try:
            outcome = self._run_limited(job, attempt)
            self._record_signals(job, outcome)
            ingest = self.repository.ingest_case(outcome.payload)
            if ingest["outcome"] == "invalid" or not ingest.get("case_id"):
                raise errors.PermanentFailure("case_rejected_by_database", "the database refused the case: " + str(ingest.get("detail") or "invalid")[:200])
            result = dict(outcome.summary, ingest=ingest["outcome"])
            timings = dict(outcome.timings, attempt=attempt, wall_seconds=round(self.clock() - started, 6))
            done = self.store.complete(job_id, self.worker_id, ingest["case_id"], result, timings, outcome.usage)
            self.log("job_finished", job_id=job_id, attempt=attempt, outcome=done["outcome"], ingest=ingest["outcome"])
            return done["outcome"]
        except Exception as error:    
            # classified below; KeyboardInterrupt/SystemExit are not swallowed
            print(
        f"WORKER_ERROR job_id={job_id} "
        f"type={type(error).__name__} "
        f"sqlstate={getattr(error, 'sqlstate', None)} "
        f"error={error}",
        flush=True,
    )
            return self._fail(job, attempt, error)

    def _fail(self, job, attempt, error):
        job_id = str(job["job_id"])
        c = errors.classify(error, self.settings.job_timeout_seconds)
        delay = self.settings.backoff_for(attempt) if c.retryable else 0.0
        try:
            res = self.store.fail(job_id, self.worker_id, c.code, c.detail, c.retryable, delay, c.timed_out)
        except DbError:
            # The store itself is down: leave the lease to expire. The reaper requeues the job (or fails it when no attempts are left).
            self.log("job_fail_not_recorded", job_id=job_id, code=c.code)
            return "store_unavailable"
        self.log("job_failed", job_id=job_id, attempt=attempt, code=c.code, retryable=c.retryable, result=res["outcome"], status=res.get("status"))
        if res["outcome"] == "retry_scheduled" and self.dispatcher is not None:
            self.dispatcher.dispatch(job_id, countdown=delay)
        return res["outcome"]

    # ------------------------------------------------------------------ entry points
    def process_job_id(self, job_id):
        """Celery entry: claim this specific job if it is due, run it. A duplicate delivery or a job that is not due finds nothing to claim."""
        try:
            job = self.store.claim(self.worker_id, self.settings.lease_seconds, job_id)
        except DbError:
            self.log("claim_failed", job_id=str(job_id))
            raise      # let the broker redeliver; the job is still queued
        if job is None:
            self.log("nothing_to_claim", job_id=str(job_id))
            return "nothing_to_claim"
        return self.process_claimed(job)

    def run_once(self):
        """Poll entry: claim the oldest due job (any), run it. -> outcome string, or None when the queue is empty."""
        job = self.store.claim(self.worker_id, self.settings.lease_seconds)
        if job is None:
            return None
        return self.process_claimed(job)

    def maintenance(self):
        """Reap lost jobs, then publish unsent ones. Safe to run from any number of processes."""
        out = {"reaped": 0, "published": 0}
        try:
            reaped = self.store.reap_expired()
            out["reaped"] = len(reaped)
            for r in reaped:
                self.log("lease_expired", job_id=str(r["job_id"]), status=r["status"])
            if self.dispatcher is not None:
                out["published"] = self.dispatcher.sweep()
        except DbError:
            self.log("maintenance_failed")
        return out

    def run_forever(self, maintenance_every=None):
        """Poll loop. Returns EXIT_ABANDONED if a timed-out job left a thread running, 0 on a normal stop."""
        every = maintenance_every if maintenance_every is not None else self.settings.reap_interval_seconds
        last = 0.0
        while not self.stop.is_set():
            self.beat()
            if self.clock() - last >= every:
                self.maintenance()
                last = self.clock()
            try:
                outcome = self.run_once()
            except DbError:
                self.log("poll_failed")
                outcome = None
            if self.abandoned:
                self.log("worker_exit_after_timeout")
                return EXIT_ABANDONED
            if outcome is None:
                self.sleep(self.settings.poll_interval_seconds)
        return 0

    def run_sweeper_forever(self):
        """The sweeper role: only maintenance, no jobs. One small process in the compose file."""
        while not self.stop.is_set():
            self.beat()
            self.maintenance()
            self.sleep(self.settings.reap_interval_seconds)
        return 0


# ---------------------------------------------------------------------- construction + CLI
def _driver(env):
    dsn = env.get(ENV_DB) or env.get("WEEK4_DATABASE_URL")
    if not dsn:
        raise settings_module.ConfigError(ENV_DB + " is not set (the connection string of the worker's login role; see docs/WEEK5_BACKEND.md)")
    from .db.driver import ResilientDriver, choose_kind
    return ResilientDriver(choose_kind(), dsn)


def build_worker(settings=None, env=None, timeout_mode=None):
    env = os.environ if env is None else env
    settings = settings or settings_module.from_env(env)
    from .runner import GraphRunner
    driver = _driver(env)
    store = PgJobStore(driver)
    queue = queues.PostgresQueue(store)
    if settings.queue_backend == "celery":
        from . import celery_app
        queue = queues.CeleryQueue(celery_app.make_app(settings, env), settings.celery_queue)
    elif settings.queue_backend == "memory":
        raise settings_module.ConfigError("WEEK5_QUEUE_BACKEND=memory is for tests only and cannot be used by a worker process")
    dispatcher = queues.Dispatcher(store, queue, settings, log=_log_to_stderr)
    mode = timeout_mode or ("none" if settings.queue_backend == "celery" else "thread")
    repository = PgRepository(driver)
    return Worker(settings, store, repository, GraphRunner.from_settings(settings, env).attach_repository(repository), dispatcher, timeout_mode=mode)


ENV_HEARTBEAT = "WEEK5_HEARTBEAT_FILE"


def health_check(path, max_age, now=time.time):
    """-> 0 when `path` exists and was modified within max_age seconds, else 1. No output beyond one line, nothing secret."""
    try:
        age = now() - os.stat(path).st_mtime
    except (OSError, TypeError):
        print("unhealthy: no heartbeat file")
        return 1
    if age > max_age:
        print("unhealthy: heartbeat is %d s old" % age)
        return 1
    print("healthy")
    return 0


def install_stop_handlers(worker):
    """SIGTERM (docker stop) and SIGINT finish the current job and leave the loop. A job cut short by SIGKILL is requeued by its lease expiring, so nothing is lost either way."""
    def handler(_signum, _frame):
        worker.stop.set()
    for name in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass


def main(argv=None):
    p = argparse.ArgumentParser(description="Week 5 worker. python -m week5.worker --mode poll|sweep")
    p.add_argument("--mode", choices=("poll", "sweep"), default="poll")
    p.add_argument("--health", action="store_true", help="exit 0 if the heartbeat file was touched recently, else 1 (container health check)")
    p.add_argument("--max-age", type=float, default=120.0, help="with --health: the oldest acceptable heartbeat, in seconds")
    args = p.parse_args(argv)
    if args.health:
        return health_check(os.environ.get(ENV_HEARTBEAT), args.max_age)
    try:
        worker = build_worker()
    except (settings_module.ConfigError, DbError, RuntimeError, ImportError) as error:
        from week4.db.drivers import redact_dsn
        sys.stderr.write("STOPPED: " + redact_dsn(str(error)) + "\n")
        return 2
    if worker.settings.queue_backend == "celery" and args.mode == "poll":
        sys.stderr.write("STOPPED: with WEEK5_QUEUE_BACKEND=celery jobs are consumed by `celery -A week5.celery_app:app worker`, not by --mode poll. Use --mode sweep for the sweeper.\n")
        return 2
    worker.heartbeat_path = os.environ.get(ENV_HEARTBEAT) or None
    install_stop_handlers(worker)
    return worker.run_forever() if args.mode == "poll" else worker.run_sweeper_forever()


if __name__ == "__main__":
    sys.exit(main())

