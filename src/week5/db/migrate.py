"""Week 5 database migrations: the same discipline as Week 4 (ordered files, checksums, advisory lock, no editing an applied file), in their own folder and their own tracking table.

  python -m week5.db.migrate status | apply | verify     [--driver psql|psycopg] [--dsn URL]   (the DSN defaults to WEEK4_DATABASE_URL: the OWNER connection, as for Week 4 migrations)

Why separate: the Week 4 lock records exactly four migrations in src/week4/db/migrations. Adding a fifth file there would change a locked artifact. Week 5 therefore lives in
src/week5/db/migrations and records itself in soc.schema_migrations_week5. Week 4 migrations 0001-0004 must already be applied and unchanged; this runner checks that first and stops otherwise.
"""
import argparse
import os
import sys

from week4.db import drivers
from week4.db import migrate as w4

MIGRATIONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "migrations")
TABLE = "soc.schema_migrations_week5"
LOCK_KEY = 7403005
TRACKING_DDL = """CREATE TABLE IF NOT EXISTS soc.schema_migrations_week5 (
    version    text PRIMARY KEY,
    name       text NOT NULL,
    checksum   text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);
"""
MigrationError = w4.MigrationError


def discover(directory=MIGRATIONS_DIR):
    return w4.discover(directory)


def week4_ready(driver):
    """Raises MigrationError unless Week 4 migrations are all applied and unchanged."""
    ok, problems = w4.verify(driver)
    if not ok:
        raise MigrationError("Week 4 migrations are not in place (" + "; ".join(problems) + "). Run: python -m week4.db.migrate apply")


def applied(driver):
    driver.run_script(TRACKING_DDL)
    rows = driver.query("SELECT version, name, checksum FROM " + TABLE + " ORDER BY version")
    return [{"version": r[0], "name": r[1], "checksum": r[2]} for r in rows]


def plan(driver, directory=MIGRATIONS_DIR):
    files = discover(directory)
    week4_ready(driver)
    done = applied(driver)
    by_version = {f["version"]: f for f in files}
    for i, row in enumerate(done):
        f = by_version.get(row["version"])
        if f is None:
            raise MigrationError("the database has Week 5 migration " + row["version"] + " but there is no such file")
        if f["checksum"] != row["checksum"]:
            raise MigrationError("Week 5 migration " + row["version"] + " (" + row["name"] + ") was changed after it was applied. Never edit an applied migration: add a new one.")
        if files[i]["version"] != row["version"]:
            raise MigrationError("applied Week 5 migrations are not a prefix of the migration files")
    pending = [f for f in files if f["version"] not in {r["version"] for r in done}]
    return files, done, pending


def script_for(f):
    quote = "$m5" + f["version"] + "$"
    guard = ("DO " + quote + " BEGIN IF EXISTS (SELECT 1 FROM " + TABLE + " WHERE version = '" + f["version"] + "') THEN "
             "RAISE EXCEPTION 'migration " + f["version"] + " is already applied' USING ERRCODE = 'duplicate_object'; END IF; END " + quote + ";\n")
    record = "INSERT INTO " + TABLE + " (version, name, checksum) VALUES ('" + f["version"] + "', '" + f["name"] + "', '" + f["checksum"] + "');\n"
    return "BEGIN;\nSELECT pg_advisory_xact_lock(" + str(LOCK_KEY) + ");\n" + guard + f["sql"].rstrip() + "\n" + record + "COMMIT;\n"


def apply(driver, directory=MIGRATIONS_DIR, say=print):
    _, _, pending = plan(driver, directory)
    done = []
    for f in pending:
        try:
            driver.run_script(script_for(f))
        except drivers.DbError as error:
            if error.sqlstate == "42710":
                say("migration " + f["version"] + " was applied by another process; skipping")
                continue
            raise MigrationError("Week 5 migration " + f["version"] + " (" + f["name"] + ") failed and was rolled back: " + str(error)) from None
        say("applied " + f["version"] + " " + f["name"])
        done.append(f["version"])
    return done


def verify(driver, directory=MIGRATIONS_DIR):
    try:
        _, _, pending = plan(driver, directory)
    except MigrationError as error:
        return False, [str(error)]
    return (not pending), (["pending migration " + f["version"] + " " + f["name"] for f in pending])


def main(argv=None):
    p = argparse.ArgumentParser(description="Week 5 database migrations")
    p.add_argument("action", choices=["status", "apply", "verify"])
    p.add_argument("--driver", choices=["psql", "psycopg"], default=None)
    p.add_argument("--dsn", default=None, help="owner connection string; default: WEEK4_DATABASE_URL (psql driver: the PG* variables when neither is set)")
    args = p.parse_args(argv)
    dsn = args.dsn or os.environ.get("WEEK4_DATABASE_URL")
    kind = args.driver
    if kind is None:
        try:
            import psycopg  # noqa: F401
            kind = "psycopg"
        except ImportError:
            kind = "psql"
    try:
        driver = drivers.make_driver(kind, dsn)
        if args.action == "apply":
            done = apply(driver)
            print("nothing to apply" if not done else "applied " + str(len(done)) + " migration(s)")
            return 0
        files, done, pending = plan(driver)
        if args.action == "status":
            names = {d["version"] for d in done}
            for f in files:
                print(("applied  " if f["version"] in names else "PENDING  ") + f["version"] + " " + f["name"])
            return 0
        ok, problems = verify(driver)
        print("Week 5 migrations match the files and none are pending" if ok else "NOT OK: " + "; ".join(problems))
        return 0 if ok else 1
    except (drivers.DbError, MigrationError) as error:
        print("STOPPED: " + drivers.redact_dsn(str(error)))
        return 2


if __name__ == "__main__":
    sys.exit(main())
