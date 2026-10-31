"""GET /actions: proposed actions with their decision and SIMULATED execution. Read-only; the filters are validated; viewers may read it. In memory always, on PostgreSQL when opted in."""
import unittest

from week4.db.repository import PgRepository
from week5.jobs import PgJobStore

from tests.week4_support import driver_for
from tests.week5_support import ApiRig, PgHarness5, pg_enabled


class Mixin:
    rig = None

    def setUp(self):
        for i in range(12):
            self.rig.post_alert(i)
        while self.rig.worker.run_once():
            pass
        pending = self.rig.call("pending_approvals", "carol").body["items"]
        self.assertGreaterEqual(len(pending), 4)
        self.a, self.b, self.c = (p["action_id"] for p in pending[:3])
        self.rig.call("decide", "alice", body={"decision": "approved", "reason": "ok"}, path={"action_id": self.a}, headers={"Idempotency-Key": "decision-0001"})
        self.rig.call("decide", "alice", body={"decision": "approved", "reason": "ok"}, path={"action_id": self.b}, headers={"Idempotency-Key": "decision-0002"})
        self.rig.call("decide", "alice", body={"decision": "rejected", "reason": "no"}, path={"action_id": self.c}, headers={"Idempotency-Key": "decision-0003"})
        self.assertEqual(self.rig.call("simulate_execution", "alice", path={"action_id": self.a}).status, 201)

    def lst(self, who="carol", **q):
        return self.rig.call("list_actions", who, query={k: str(v) for k, v in q.items()})

    def test_lists_decisions_and_marks_the_simulated_one(self):
        r = self.lst()
        self.assertEqual(r.status, 200, r.body)
        by_id = {x["action_id"]: x for x in r.body["items"]}
        self.assertTrue(by_id[self.a]["executed"])
        self.assertEqual(by_id[self.a]["execution_mode"], "simulated")
        self.assertEqual(by_id[self.a]["executed_by"], "alice")
        self.assertFalse(by_id[self.b]["executed"])
        self.assertIsNone(by_id[self.b]["executed_at"])
        self.assertEqual(by_id[self.c]["state"], "rejected")
        self.assertEqual(by_id[self.c]["decision_reason"], "no")
        self.assertTrue(by_id[self.a]["alert_id"])
        # newest activity first: the simulated execution happened last
        self.assertEqual(r.body["items"][0]["action_id"], self.a)

    def test_filters(self):
        self.assertEqual([x["action_id"] for x in self.lst(executed="true").body["items"]], [self.a])
        approved_not_run = self.lst(state="approved", executed="false").body["items"]
        self.assertEqual([x["action_id"] for x in approved_not_run], [self.b])
        self.assertEqual({x["state"] for x in self.lst(state="pending").body["items"]}, {"pending"})
        self.assertEqual(self.lst(state="rejected").body["total"], 1)

    def test_paging(self):
        total = self.lst().body["total"]
        page = self.lst(limit=2, offset=1).body
        self.assertEqual((page["total"], page["limit"], page["offset"], len(page["items"])), (total, 2, 1, min(2, total - 1)))

    def test_bad_filters_are_refused_without_echoing_the_value(self):
        for q in ({"state": "executed"}, {"executed": "maybe"}):
            r = self.lst(**q)
            self.assertEqual(r.status, 422, r.body)
            self.assertNotIn("maybe", str(r.body))
            self.assertNotIn("executed'", str(r.body.get("error", {}).get("message", "")).replace("executed must", ""))

    def test_viewer_may_read_and_a_missing_token_may_not(self):
        self.assertEqual(self.lst("carol").status, 200)
        self.assertEqual(self.rig.call("list_actions", None).status, 401)


class InMemory(Mixin, unittest.TestCase):
    def setUp(self):
        self.rig = ApiRig(sensor=True)
        Mixin.setUp(self)


@unittest.skipUnless(pg_enabled()[0], pg_enabled()[1])
class OnPostgres(Mixin, unittest.TestCase):
    def setUp(self):
        self.dbname = PgHarness5.new_database()
        self.addCleanup(PgHarness5.drop, self.dbname)
        driver = driver_for(self.dbname)
        self.rig = ApiRig(sensor=True, repo=PgRepository(driver), store=PgJobStore(driver))
        Mixin.setUp(self)


if __name__ == "__main__":
    unittest.main()
