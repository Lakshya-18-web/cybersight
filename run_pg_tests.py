import os
import unittest
from psycopg.conninfo import make_conninfo
from week4.db import drivers
from tests import week4_support as W4
from tests import week5_support as W5


def driver_for(database):
    dsn = make_conninfo(
        host="postgres",
        port=5432,
        user=os.environ["WEEK5_DB_OWNER"],
        password=os.environ["WEEK5_DB_PASSWORD"],
        dbname=database,
    )
    return drivers.PsycopgDriver(dsn)


def pg_enabled():
    try:
        driver_for("postgres").scalar("SELECT 1")
        return True, ""
    except Exception as error:
        return False, "PostgreSQL connection failed: " + type(error).__name__


W4.driver_for = driver_for
W4.pg_enabled = pg_enabled
W5.pg_enabled = pg_enabled

import tests.test_week5_psycopg_semantics as T

suite = unittest.defaultTestLoader.loadTestsFromModule(T)
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)