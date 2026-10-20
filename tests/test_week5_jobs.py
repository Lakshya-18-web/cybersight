"""Week 5 job store contract: the same tests run against MemoryJobStore (always) and against PgJobStore on a real scratch PostgreSQL (opt-in, WEEK4_TEST_PG=1).
Offline, fake data only. No model call, no network, no real or frozen data."""
import datetime
import unittest

from tests import week4_support as W4
from tests import week5_support as W5
from week4.db import drivers
from week5 import fixtures, jobs
from week5.jobs import DbError, MemoryJobStore, PgJobStore, public_job


class JobStoreContract:
    """Mixin. Subclasses provide make_store() and expire_lease(job_id)."""
    WORKER, OTHER = "w1", "w2"

    def make_store(self):
        raise NotImplementedError

    def expire_lease(self, job_id):
        raise NotImplementedError

    def new_case(self):
        """A case id that exists in this store's world (the database has a foreign key to soc.cases)."""
        raise NotImplementedError

    def setUp(self):
        self.store = self.make_store()

    def sub(self, i=0, **kw):
        return W5.submit(self.store, fixtures.make_alert(i), **kw)

    def claim(self, job_id=None, worker=None):
        return self.store.claim(worker or self.WORKER, 60, job_id)

    # ---- submit
    def test_submit_creates_a_queued_job(self):
        r = self.sub()
        self.assertEqual(r["outcome"], "created")
        j = self.store.get(r["job_id"])
        self.assertEqual((j["status"], j["attempts"], j["alert_id"], j["alert_set"], j["memory_mode"]), ("queued", 0, "SYN-000000", "synthetic", "off"))
        self.assertIsNone(j["case_id"])

    def test_same_submission_twice_is_a_duplicate(self):
        a, b = self.sub(), self.sub()
        self.assertEqual((a["outcome"], b["outcome"]), ("created", "duplicate"))
        self.assertEqual(a["job_id"], b["job_id"])
        self.assertEqual(len(self.store.list_jobs()["items"]), 1)

    def test_same_key_different_alert_is_a_conflict(self):
        a = self.sub(client_key="client-key-0001")
        b = W5.submit(self.store, fixtures.make_alert(1), client_key="client-key-0001")
        self.assertEqual((a["outcome"], b["outcome"]), ("created", "conflict"))
        self.assertEqual(a["job_id"], b["job_id"])

    def test_different_submitters_do_not_share_keys(self):
        a, b = self.sub(submitter="analyst1", client_key="shared-key-0001"), self.sub(submitter="analyst2", client_key="shared-key-0001")
        self.assertEqual((a["outcome"], b["outcome"]), ("created", "created"))
        self.assertNotEqual(a["job_id"], b["job_id"])

    def test_queue_full_is_refused_and_nothing_is_stored(self):
        self.assertEqual(self.sub(0, max_queue_depth=2)["outcome"], "created")
        self.assertEqual(self.sub(1, max_queue_depth=2)["outcome"], "created")
        r = self.sub(2, max_queue_depth=2)
        self.assertEqual(r["outcome"], "queue_full")
        self.assertEqual(len(self.store.list_jobs()["items"]), 2)

    def test_a_duplicate_is_still_answered_when_the_queue_is_full(self):
        self.sub(0, max_queue_depth=1)
        self.assertEqual(self.sub(0, max_queue_depth=1)["outcome"], "duplicate")

    def test_invalid_input_is_refused(self):
        alert = fixtures.make_alert(0)
        r = self.store.submit(alert, "frozen", "off", "analyst1", "analyst1:auto-" + "a" * 40, "b" * 64, 3) if isinstance(self.store, MemoryJobStore) else None
        if r is not None:
            self.assertEqual(r["outcome"], "invalid")
        with self.assertRaises((DbError, ValueError)):
            self.store.get("not-a-uuid")

    # ---- claim
    def test_claim_returns_none_when_empty(self):
        self.assertIsNone(self.claim())

    def test_claim_takes_the_oldest_and_marks_it_running(self):
        a, b = self.sub(0), self.sub(1)
        j = self.claim()
        self.assertEqual(j["job_id"], a["job_id"])
        self.assertEqual((j["status"], j["attempts"]), ("running", 1))
        self.assertEqual(self.claim()["job_id"], b["job_id"])
        self.assertIsNone(self.claim())

    def test_a_running_job_cannot_be_claimed_again(self):
        r = self.sub()
        self.assertIsNotNone(self.claim(r["job_id"]))
        self.assertIsNone(self.claim(r["job_id"], worker=self.OTHER))

    def test_claim_by_id_ignores_other_jobs(self):
        self.sub(0)
        b = self.sub(1)
        self.assertEqual(self.claim(b["job_id"])["alert_id"], "SYN-000001")

    def test_claim_validates_its_arguments(self):
        self.sub()
        with self.assertRaises(DbError):
            self.store.claim("", 60)
        with self.assertRaises(DbError):
            self.store.claim("w1", 1)

    # ---- complete
    def test_complete_records_the_case_and_is_final(self):
        r = self.sub()
        self.claim()
        case, other_case = self.new_case(), self.new_case()
        out = self.store.complete(r["job_id"], self.WORKER, case, {"routing_decision": "escalate"}, {"graph_seconds": 0.1}, {"model_calls": 1})
        self.assertEqual(out["outcome"], "completed")
        j = self.store.get(r["job_id"])
        self.assertEqual((j["status"], j["case_id"], j["result"]["routing_decision"], j["timings"]["graph_seconds"], j["usage"]["model_calls"]), ("succeeded", case, "escalate", 0.1, 1))
        self.assertIsNotNone(j["finished_at"])
        self.assertEqual(self.store.complete(r["job_id"], self.WORKER, case)["outcome"], "already_complete")
        self.assertEqual(self.store.complete(r["job_id"], self.WORKER, other_case)["outcome"], "not_owner")
        self.assertIsNone(self.claim())

    def test_only_the_owner_can_complete_or_fail(self):
        r = self.sub()
        self.claim()
        case = self.new_case()
        self.assertEqual(self.store.complete(r["job_id"], self.OTHER, case)["outcome"], "not_owner")
        self.assertEqual(self.store.fail(r["job_id"], self.OTHER, "worker_exception", "x", True)["outcome"], "not_owner")
        self.assertEqual(self.store.get(r["job_id"])["status"], "running")

    def test_complete_unknown_job(self):
        self.assertEqual(self.store.complete("33333333-3333-4333-8333-333333333333", self.WORKER, "11111111-1111-4111-8111-111111111111")["outcome"], "not_found")

    # ---- fail / retry
    def test_retryable_failure_requeues_with_a_delay_until_attempts_run_out(self):
        r = self.sub(max_attempts=2)
        self.claim()
        out = self.store.fail(r["job_id"], self.WORKER, "model_unavailable", "down", True, delay_seconds=3600)
        self.assertEqual((out["outcome"], out["status"]), ("retry_scheduled", "queued"))
        j = self.store.get(r["job_id"])
        self.assertEqual((j["status"], j["attempts"], j["error_code"]), ("queued", 1, "model_unavailable"))
        self.assertIsNone(self.claim(), "a retry is not due before its back-off has passed")
        self.assertEqual(self.store.undispatched(1), [])
        self.store.fail  # keep linter quiet
        # make it due, claim, fail again: attempts are used up -> final failure
        self.make_due(r["job_id"])
        j = self.claim()
        self.assertEqual(j["attempts"], 2)
        out = self.store.fail(r["job_id"], self.WORKER, "model_unavailable", "down", True)
        self.assertEqual((out["outcome"], out["status"]), ("failed", "failed"))
        self.assertEqual(self.store.get(r["job_id"])["status"], "failed")
        self.assertIsNone(self.claim())

    def test_non_retryable_failure_is_final_at_once(self):
        r = self.sub()
        self.claim()
        out = self.store.fail(r["job_id"], self.WORKER, "invalid_alert", "bad", False)
        self.assertEqual(out["status"], "failed")
        self.assertEqual(self.store.get(r["job_id"])["attempts"], 1)

    def test_timeout_on_the_last_attempt_is_timed_out(self):
        r = self.sub(max_attempts=1)
        self.claim()
        out = self.store.fail(r["job_id"], self.WORKER, "timeout", "slow", True, timed_out=True)
        self.assertEqual(out["status"], "timed_out")
        self.assertEqual(self.store.get(r["job_id"])["error_code"], "timeout")

    def test_failure_code_must_be_a_slug(self):
        r = self.sub()
        self.claim()
        with self.assertRaises(DbError):
            self.store.fail(r["job_id"], self.WORKER, "Bad Code!", "x", True)

    def test_error_detail_is_clipped(self):
        r = self.sub()
        self.claim()
        self.store.fail(r["job_id"], self.WORKER, "worker_exception", "x" * 5000, False)
        self.assertLessEqual(len(self.store.get(r["job_id"])["error_detail"]), jobs.DETAIL_MAX)

    # ---- leases
    def test_reaper_requeues_a_lost_job_and_fails_it_when_attempts_are_gone(self):
        r = self.sub(max_attempts=2)
        self.claim()
        self.assertEqual(self.store.reap_expired(), [])
        self.expire_lease(r["job_id"])
        reaped = self.store.reap_expired()
        self.assertEqual([(x["job_id"], x["status"]) for x in reaped], [(r["job_id"], "queued")])
        j = self.store.get(r["job_id"])
        self.assertEqual((j["status"], j["error_code"]), ("queued", "worker_lost"))
        # the old owner's late answer is refused
        self.assertEqual(self.store.complete(r["job_id"], self.WORKER, self.new_case())["outcome"], "not_owner")
        self.claim(worker=self.OTHER)
        self.expire_lease(r["job_id"])
        self.assertEqual(self.store.reap_expired()[0]["status"], "failed")
        self.assertEqual(self.store.get(r["job_id"])["status"], "failed")

    def test_heartbeat_extends_only_for_the_owner(self):
        r = self.sub()
        self.claim()
        self.assertTrue(self.store.heartbeat(r["job_id"], self.WORKER, 60))
        self.assertFalse(self.store.heartbeat(r["job_id"], self.OTHER, 60))

    # ---- outbox
    def test_outbox_lists_jobs_that_were_never_handed_over(self):
        a, b = self.sub(0), self.sub(1)
        self.assertEqual(sorted(self.store.undispatched(60)), sorted([a["job_id"], b["job_id"]]))
        self.assertTrue(self.store.mark_dispatched(a["job_id"]))
        self.assertEqual(self.store.undispatched(60), [b["job_id"]])
        self.claim(a["job_id"])
        self.assertFalse(self.store.mark_dispatched(a["job_id"]), "a running job is not queued any more")

    # ---- events, security events, stats, listing
    def test_events_are_recorded_in_order(self):
        r = self.sub()
        self.claim()
        self.store.fail(r["job_id"], self.WORKER, "model_unavailable", "x", True)
        names = [e["event"] for e in self.store.events(r["job_id"])]
        self.assertEqual(names, ["submitted", "claimed", "retry_scheduled"])

    def test_security_event_types_are_checked(self):
        self.store.record_security_event("api:analyst1", "ingest_rejected", "abc", None, {"code": "bad_field"})
        with self.assertRaises((DbError, ValueError)):
            self.store.record_security_event("api:analyst1", "something_else", "abc", None, {})

    def test_stats_and_listing_filters(self):
        a, b = self.sub(0), self.sub(1, submitter="analyst2")
        self.claim(a["job_id"])
        stats = self.store.stats()
        self.assertEqual((stats["queued"]["n"], stats["running"]["n"]), (1, 1))
        self.assertEqual([x["job_id"] for x in self.store.list_jobs(status="running")["items"]], [a["job_id"]])
        self.assertEqual([x["job_id"] for x in self.store.list_jobs(submitted_by="analyst2")["items"]], [b["job_id"]])
        self.assertEqual(self.store.list_jobs(limit=1)["total"], 2)
        with self.assertRaises((DbError, ValueError)):
            self.store.list_jobs(status="nonsense")

    def test_public_view_hides_internal_fields(self):
        r = self.sub()
        view = public_job(self.store.get(r["job_id"]))
        for hidden in ("idempotency_key", "payload_sha256", "lease_owner", "alert", "lease_expires_at", "dispatched_at"):
            self.assertNotIn(hidden, view)
        self.assertEqual(view["alert_id"], "SYN-000000")

    def test_ping(self):
        self.assertTrue(self.store.ping())


class MemoryJobStoreTests(JobStoreContract, unittest.TestCase):
    def make_store(self):
        self.now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        return MemoryJobStore(clock=lambda: self.now)

    def expire_lease(self, job_id):
        self.now += datetime.timedelta(seconds=10_000)

    def make_due(self, job_id):
        self.now += datetime.timedelta(seconds=10_000)

    def new_case(self):
        import uuid
        return str(uuid.uuid4())

    def test_a_database_outage_raises_db_error(self):
        self.store.fail_next = 1
        with self.assertRaises(DbError):
            self.store.ping()


_PG_OK, _PG_WHY = W5.pg_enabled()


@unittest.skipUnless(_PG_OK, _PG_WHY)
class PgJobStoreTests(JobStoreContract, unittest.TestCase):
    def make_store(self):
        self.db_name = W5.PgHarness5.new_database()
        self.addCleanup(W5.PgHarness5.drop, self.db_name)
        self.owner = W4.driver_for(self.db_name)
        return PgJobStore(self.owner)

    def expire_lease(self, job_id):
        self.owner.run_script("SET LOCAL session_replication_role = replica; UPDATE soc.jobs SET lease_expires_at = now() - interval '1 second' WHERE job_id = '%s'" % job_id)

    def new_case(self):
        from week4.db.repository import PgRepository
        return PgRepository(self.owner).ingest_case(W4.make_payload())["case_id"]

    def make_due(self, job_id):
        self.owner.run_script("UPDATE soc.jobs SET not_before = now() - interval '1 second' WHERE job_id = '%s'" % job_id)

    def test_terminal_state_cannot_be_changed_by_sql(self):
        r = self.sub()
        self.claim()
        self.store.complete(r["job_id"], self.WORKER, self.new_case())
        with self.assertRaises(DbError):
            self.owner.run_script("UPDATE soc.jobs SET status = 'queued' WHERE job_id = '%s'" % r["job_id"])

    def test_events_are_append_only(self):
        r = self.sub()
        with self.assertRaises(DbError):
            self.owner.run_script("DELETE FROM soc.job_events WHERE job_id = '%s'" % r["job_id"])
        with self.assertRaises(DbError):
            self.owner.run_script("UPDATE soc.job_events SET event = 'x' WHERE job_id = '%s'" % r["job_id"])

    def test_a_credential_shaped_key_in_an_alert_is_refused_by_the_database(self):
        alert = dict(fixtures.make_alert(0))
        alert["api_key"] = "x"
        with self.assertRaises(DbError):
            self.store.submit(alert, "synthetic", "off", "analyst1", "analyst1:auto-" + "c" * 40, "d" * 64, 3)

    def test_two_concurrent_claims_never_return_the_same_job(self):
        import threading
        for i in range(6):
            self.sub(i)
        got, lock = [], threading.Lock()

        def grab(name):
            store = PgJobStore(W4.driver_for(self.db_name))
            while True:
                j = store.claim(name, 60)
                if j is None:
                    return
                with lock:
                    got.append(j["job_id"])
        threads = [threading.Thread(target=grab, args=("w%d" % n,)) for n in range(4)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(len(got), 6)
        self.assertEqual(len(set(got)), 6)


if __name__ == "__main__":
    unittest.main()
