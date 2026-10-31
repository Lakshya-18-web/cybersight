"""PostgreSQL-level checks of the operational procedures in docs/WEEK5_OPERATIONS.md: upgrading an existing database with migration 0002, running the migrator twice, and pg_dump -> pg_restore into a second
database with the audit chain, privileges and data intact. Needs PostgreSQL (WEEK4_TEST_PG=1) and the pg_dump/pg_restore client tools. Docker itself is NOT exercised here."""
import os
import shutil
import subprocess
import tempfile
import unittest
import uuid

from week4.db import migrate as w4_migrate
from week4.db.repository import PgRepository
from week5 import eve, repo5
from week5.db import migrate as w5_migrate

from tests.week4_support import driver_for, make_payload, seed_analysts
from tests.week5_support import pg_enabled

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "eve", "eve_mixed.ndjson")


def only_first_migration(tmp):
    src = w5_migrate.MIGRATIONS_DIR
    for name in sorted(os.listdir(src))[:1]:
        shutil.copy(os.path.join(src, name), os.path.join(tmp, name))
    return tmp


def fresh_db(prefix):
    name = "%s_%s" % (prefix, uuid.uuid4().hex[:10])
    driver_for("postgres").run_script('CREATE DATABASE "%s"' % name)
    return name


def drop(name):
    try:
        driver_for("postgres").run_script('DROP DATABASE IF EXISTS "%s" WITH (FORCE)' % name)
    except Exception:
        pass


@unittest.skipUnless(pg_enabled()[0], pg_enabled()[1])
class Upgrade(unittest.TestCase):
    def test_an_existing_database_upgrades_in_place_and_keeps_its_rows(self):
        name = fresh_db("w5_up")
        self.addCleanup(drop, name)
        db = driver_for(name)
        w4_migrate.apply(db, say=lambda *_: None)
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        self.assertEqual(w5_migrate.apply(db, only_first_migration(tmp), say=lambda *_: None), ["0001"])
        repo = PgRepository(db)
        seed_analysts(repo)
        case = repo.ingest_case(make_payload())
        self.assertEqual(case["outcome"], "created")
        before = db.scalar("SELECT count(*) FROM soc.audit_events")
        self.assertEqual(w5_migrate.apply(db, say=lambda *_: None), ["0002"])
        self.assertEqual(w5_migrate.apply(db, say=lambda *_: None), [])          # idempotent
        ok, problems = w5_migrate.verify(db)
        self.assertTrue(ok, problems)
        self.assertEqual(db.scalar("SELECT count(*) FROM soc.audit_events"), before)          # the upgrade changed no existing audit row
        self.assertEqual(repo.get_case(case["case_id"])["alert_id"], make_payload()["alert"]["alert_id"])
        self.assertTrue(repo.verify_audit_chain()["ok"])
        r5 = repo5.wrap(repo)
        self.assertEqual(r5.sensor_stats()["events"], 0)
        self.assertEqual(r5.add_note(case["case_id"], "bob", "after the upgrade", "key-up-0001")["outcome"], "created")

    def test_the_migrator_checksums_refuse_an_edited_applied_migration(self):
        name = fresh_db("w5_ck")
        self.addCleanup(drop, name)
        db = driver_for(name)
        w4_migrate.apply(db, say=lambda *_: None)
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        first = only_first_migration(tmp)
        w5_migrate.apply(db, first, say=lambda *_: None)
        path = os.path.join(first, sorted(os.listdir(first))[0])
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n-- edited after it was applied\n")
        ok, problems = w5_migrate.verify(db, first)
        self.assertFalse(ok)
        self.assertTrue(problems)


@unittest.skipUnless(pg_enabled()[0] and shutil.which("pg_dump") and shutil.which("pg_restore"), "needs PostgreSQL and the pg_dump / pg_restore tools")
class BackupRestore(unittest.TestCase):
    def pg_env(self):
        e = dict(os.environ)
        e.setdefault("PGHOST", "127.0.0.1")
        return e

    def test_dump_and_restore_into_a_new_database_keeps_data_chain_and_privileges(self):
        src = fresh_db("w5_bk")
        dst = fresh_db("w5_rs")
        self.addCleanup(drop, src)
        self.addCleanup(drop, dst)
        db = driver_for(src)
        w4_migrate.apply(db, say=lambda *_: None)
        w5_migrate.apply(db, say=lambda *_: None)
        repo = PgRepository(db)
        seed_analysts(repo)
        r5 = repo5.wrap(repo)
        case = repo.ingest_case(make_payload())["case_id"]
        r5.add_note(case, "bob", "note before backup", "key-bk-0001")
        with open(SAMPLES, "rb") as fh:
            records, _, _ = eve.normalise_batch(eve.parse_ndjson(fh.read(), 10 ** 7), "sensor-lab-1")
        r5.ingest_sensor_batch("bob", "sensor-lab-1", [r for _, r in records])
        counts_before = {t: db.scalar("SELECT count(*) FROM soc.%s" % t) for t in ("cases", "audit_events", "sensor_events", "case_notes")}
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        dump = os.path.join(tmp, "soc.dump")
        subprocess.run(["pg_dump", "-U", os.environ.get("PGUSER", "postgres"), "-p", os.environ.get("PGPORT", "54329"), "-Fc", "-f", dump, src], check=True, env=self.pg_env())
        self.assertGreater(os.path.getsize(dump), 1000)
        subprocess.run(["pg_restore", "-U", os.environ.get("PGUSER", "postgres"), "-p", os.environ.get("PGPORT", "54329"), "--no-owner", "-d", dst, dump], check=True, env=self.pg_env())
        db2 = driver_for(dst)
        for t, n in counts_before.items():
            self.assertEqual(db2.scalar("SELECT count(*) FROM soc.%s" % t), n, t)
        repo2 = PgRepository(db2)
        self.assertTrue(repo2.verify_audit_chain()["ok"])                    # the hash chain survives a dump and restore
        self.assertEqual(db2.scalar("SELECT has_function_privilege('soc_api', 'soc.w5_add_note(uuid,text,text,text)', 'EXECUTE')"), "t")
        self.assertEqual(db2.scalar("SELECT has_table_privilege('soc_api', 'soc.sensor_events', 'INSERT')"), "f")
        ok, problems = w5_migrate.verify(db2)
        self.assertTrue(ok, problems)
        self.assertEqual(repo5.wrap(repo2).add_note(case, "bob", "note after restore", "key-bk-0002")["outcome"], "created")
        self.assertTrue(repo2.verify_audit_chain()["ok"])


if __name__ == "__main__":
    unittest.main()
