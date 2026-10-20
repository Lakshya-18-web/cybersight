"""Queue backends and the dispatcher.

The job table (week5.jobs) holds the truth; a queue only tells a worker "job X is due". Three backends share one tiny interface:

  PostgresQueue   no broker at all. Workers poll soc.claim_job (FOR UPDATE SKIP LOCKED). Needs only the PostgreSQL you already run. publish() is a no-op because the row IS the queue entry.
  CeleryQueue     Celery with a Redis broker (the deployment backend). publish() sends the task `week5.process_job(job_id)`. Needs celery + redis packages and a Redis server.
  MemoryQueue     an in-process list, for tests and the in-process load test.

Delivery semantics, stated honestly:
  * AT LEAST ONCE. A message can be delivered twice (broker redelivery, a republish by the sweeper). That is harmless: the worker claims the job atomically (queued -> running), so a second delivery finds
    nothing to claim and does nothing. A message can also be LOST (Redis restart, flush): the sweeper re-publishes any due job that was never handed over or was handed over longer ago than
    WEEK5_REPUBLISH_AFTER_SECONDS and is still queued. A job is therefore never lost while its row exists.
  * A worker that dies mid-job leaves a lease; the reaper returns the job to the queue (or fails it when its attempts are used up). The retry may re-run the graph; storing the case is idempotent.
  * A job is never run by two workers at once while its lease holds. A lease that is shorter than the real run time would break that, so WEEK5_LEASE_SECONDS must exceed the job timeout (checked at start-up).
  * Not exactly-once: a model call can be made twice for one alert (a retry after a crash). The case and the proposed actions are stored once.
"""
import collections
import threading

from .jobs import DbError

TASK_NAME = "week5.process_job"


class QueueUnavailable(Exception):
    """The broker could not take the message. The job is safe in the database; the sweeper will publish it later."""


class QueueBackend:
    name = "base"
    implicit_dispatch = False      # True when a submitted job is immediately visible to workers (no message needed)

    def publish(self, job_id, countdown=0.0):
        raise NotImplementedError

    def ready(self):
        """-> (ok, detail). Must not raise and must not contain a secret."""
        raise NotImplementedError


class PostgresQueue(QueueBackend):
    name = "postgres"
    implicit_dispatch = True

    def __init__(self, store):
        self.store = store

    def publish(self, job_id, countdown=0.0):
        return None

    def ready(self):
        try:
            return (True, "the job table answered") if self.store.ping() else (False, "the job table did not answer")
        except DbError:
            return False, "the job table is not reachable"


class MemoryQueue(QueueBackend):
    name = "memory"

    def __init__(self):
        self.items = collections.deque()
        self.lock = threading.Lock()
        self.fail_next = 0        # tests: make the next N publishes fail (a broker outage)
        self.up = True

    def publish(self, job_id, countdown=0.0):
        with self.lock:
            if not self.up or self.fail_next > 0:
                if self.fail_next > 0:
                    self.fail_next -= 1
                raise QueueUnavailable("the broker is not reachable (simulated)")
            self.items.append(job_id)

    def pop(self):
        with self.lock:
            return self.items.popleft() if self.items else None

    def __len__(self):
        return len(self.items)

    def ready(self):
        return (True, "in-process queue") if self.up else (False, "the broker is not reachable (simulated)")


class CeleryQueue(QueueBackend):
    name = "celery"

    def __init__(self, app, queue_name):
        self.app, self.queue_name = app, queue_name

    def publish(self, job_id, countdown=0.0):
        try:
            self.app.send_task(TASK_NAME, args=[str(job_id)], queue=self.queue_name, countdown=max(0.0, float(countdown)) or None, retry=False, ignore_result=True)
        except Exception as error:      # kombu/redis raise a variety of types; only the type name is kept
            raise QueueUnavailable("the broker did not accept the message (" + type(error).__name__ + ")") from None

    def ready(self):
        try:
            with self.app.connection_for_write() as connection:
                connection.ensure_connection(max_retries=1, interval_start=0, interval_step=0.2, timeout=2)
            return True, "the broker answered"
        except Exception as error:
            return False, "the broker is not reachable (" + type(error).__name__ + ")"


class Dispatcher:
    """Hands due jobs to the queue and records the hand-over in the job table (the outbox pattern)."""

    def __init__(self, store, queue, settings, log=None):
        self.store, self.queue, self.settings = store, queue, settings
        self.log = log or (lambda *a, **k: None)

    def dispatch(self, job_id, countdown=0.0):
        """-> 'sent' | 'implicit' | 'pending'. 'pending' means the broker refused: the job stays queued and the sweeper will try again."""
        if self.queue.implicit_dispatch:
            return "implicit"
        try:
            self.queue.publish(job_id, countdown)
        except QueueUnavailable as error:
            self.log("publish_failed", job_id=str(job_id), reason=str(error))
            return "pending"
        try:
            self.store.mark_dispatched(job_id)
        except DbError:
            self.log("mark_dispatched_failed", job_id=str(job_id))
        return "sent"

    def sweep(self, limit=100):
        """Publish every due queued job that was never handed over (or whose hand-over is old). -> number published. No-op for polling backends."""
        if self.queue.implicit_dispatch:
            return 0
        sent = 0
        for job_id in self.store.undispatched(self.settings.republish_after_seconds, limit):
            if self.dispatch(job_id) == "sent":
                sent += 1
        return sent
