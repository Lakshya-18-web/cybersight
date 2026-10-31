"""The PostgreSQL-backed Week 5 paths again, through a driver that enforces psycopg 3's parameter and result rules (tests/pg_strict_driver.py). Opt-in like the other PostgreSQL tests.
Why it exists: the psql driver used by the sandbox tests accepts a Python dict as a jsonb parameter and returns text; the psycopg 3 driver of the Docker stack does neither, and a job store bug of exactly that kind
was found only on the real stack. This is an emulation of the documented rules, not psycopg itself."""
import unittest

from week5.db.repository import Week5PgRepository
from week4.db.repository import PgRepository
from week5.jobs import PgJobStore

from tests.pg_strict_driver import StrictPsycopgDriver
from tests.test_week5_sensor_e2e import SensorE2E, SensorThreatIntel, make_rig
from tests.week4_support import driver_for
from tests.week5_support import PgHarness5, pg_enabled


class DriverSelfCheck(unittest.TestCase):
    """The emulation must actually refuse what psycopg 3 refuses, or the tests below prove nothing."""

    class Inner:
        def query(self, sql, params=()):
            return [["1"]]

        query_json = query
        scalar = lambda self, sql, params=(): "1"          # noqa: E731

    def test_a_dict_parameter_is_refused(self):
        from week4.db.drivers import DbError
        d = StrictPsycopgDriver(self.Inner())
        with self.assertRaises(DbError):
            d.query_json("SELECT * FROM soc.w5_ingest_sensor_batch(%s)", [{"a": 1}])
        with self.assertRaises(DbError):
            d.scalar("SELECT %s", [["x"]])

    def test_json_text_with_a_cast_is_accepted(self):
        d = StrictPsycopgDriver(self.Inner())
        self.assertEqual(d.scalar("SELECT %s::jsonb", ['{"a": 1}']), 1)

    def test_a_stray_percent_is_refused_but_an_escaped_one_is_not(self):
        from week4.db.drivers import DbError
        d = StrictPsycopgDriver(self.Inner())
        with self.assertRaises(DbError):
            d.query("SELECT 'a%x'", [])
        d.query("SELECT 'a%%x'", [])

    def test_the_week4_case_ingest_keeps_its_dict_parameter(self):
        d = StrictPsycopgDriver(self.Inner())
        d.query_json("SELECT * FROM soc.ingest_case(%s)", [{"a": 1}])

    def test_scalars_are_native(self):
        d = StrictPsycopgDriver(self.Inner())
        self.assertEqual(d.scalar("SELECT 1"), 1)


def strict_rig(testcase):
    testcase.dbname = PgHarness5.new_database()
    testcase.addCleanup(PgHarness5.drop, testcase.dbname)
    driver = StrictPsycopgDriver(driver_for(testcase.dbname))
    testcase.strict_driver = driver
    return make_rig(repo=Week5PgRepository(driver), store=PgJobStore(driver))


@unittest.skipUnless(pg_enabled()[0], pg_enabled()[1])
class StrictSensorE2E(SensorE2E, unittest.TestCase):
    def setUp(self):
        self.rig = strict_rig(self)


@unittest.skipUnless(pg_enabled()[0], pg_enabled()[1])
class StrictSensorTI(SensorThreatIntel, unittest.TestCase):
    def setUp(self):
        self.rig = strict_rig(self)


if __name__ == "__main__":
    unittest.main()

class CaseIngestJsonbRegression(unittest.TestCase):
    def test_ingest_case_passes_json_text_with_explicit_jsonb_cast(self):
        import json

        class RecordingDriver:
            def __init__(self):
                self.sql = None
                self.params = None

            def query_json(self, sql, params=()):
                self.sql = sql
                self.params = params
                return {
                    "outcome": "created",
                    "o_case_id": "test-id",
                    "o_status": "escalated",
                    "detail": None,
                }

        payload = {"alert": {"name": "test"}, "count": 3}
        driver = RecordingDriver()
        repo = Week5PgRepository(driver)

        result = repo.ingest_case(payload)

        self.assertIn("soc.ingest_case(%s::jsonb)", driver.sql)
        self.assertEqual(len(driver.params), 1)
        self.assertIsInstance(driver.params[0], str)
        self.assertEqual(json.loads(driver.params[0]), payload)
        self.assertEqual(result["outcome"], "created")
        self.assertEqual(result["case_id"], "test-id")
