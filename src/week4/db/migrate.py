"""Versioned, checksummed database migrations.

  python -m week4.db.migrate status                  which migrations are applied / pending
  python -m week4.db.migrate apply                   apply every pending migration, in order, each in its own transaction
  python -m week4.db.migrate verify                  exit 0 only if every applied migration still matches its file and nothing is pending

  --driver psql|psycopg   (default psycopg when installed, else psql)       the connection string comes from --dsn or the WEEK4_DATABASE_URL environment variable

Rules: migrations are files db/migrations/NNNN_name.sql. They are applied in version order. An applied migration is never edited: its sha256 (line endings normalised) is stored and a changed file stops the run.
A gap or a duplicate version stops the run. Two migrators running at once are serialised by an advisory lock; the loser finds the version applied and skips it.
This module reads no credentials from files and never prints the connection string.
"""
import os
import re
import sys
import hashlib
import argparse

from . import drivers

MIGRATIONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "migrations")
NAME_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")
LOCK_KEY = 7403002
TRACKING_DDL = """CREATE SCHEMA IF NOT EXISTS soc;
CREATE TABLE IF NOT EXISTS soc.schema_migrations (
    version    text PRIMARY KEY,
    name       text NOT NULL,
    checksum   text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);
"""


class MigrationError(Exception):
    pass


def checksum_of(text):
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def discover(directory=MIGRATIONS_DIR):
    """[{version, name, file, sql, checksum}] in version order. Raises MigrationError for a duplicate version, a gap, a badly named .sql file or an empty file."""
    found = []
    for entry in sorted(os.listdir(directory)):
        if not entry.endswith(".sql"):
            continue
        m = NAME_RE.match(entry)
        if not m:
            raise MigrationError("migration file name must look like 0001_name.sql: " + entry)
        with open(os.path.join(directory, entry), "r", encoding="utf-8", newline="") as f:
            sql = f.read()
        if not sql.strip():
            raise MigrationError("empty migration " + entry)
        found.append({"version": m.group(1), "name": m.group(2), "file": entry, "sql": sql.replace("\r\n", "\n"), "checksum": checksum_of(sql)})
    versions = [f["version"] for f in found]
    if len(set(versions)) != len(versions):
        raise MigrationError("duplicate migration version")
    for i, v in enumerate(versions, 1):
        if int(v) != i:
            raise MigrationError("migration versions must be 0001, 0002, ... without gaps (found " + v + " at position " + str(i) + ")")
    return found


def applied(driver):
    driver.run_script(TRACKING_DDL)
    rows = driver.query("SELECT version, name, checksum FROM soc.schema_migrations ORDER BY version")
    return [{"version": r[0], "name": r[1], "checksum": r[2]} for r in rows]


def plan(driver, directory=MIGRATIONS_DIR):
    """(files, applied, pending). Raises MigrationError if an applied migration is unknown, out of order or changed."""
    files = discover(directory)
    done = applied(driver)
    by_version = {f["version"]: f for f in files}
    for i, row in enumerate(done):
        f = by_version.get(row["version"])
        if f is None:
            raise MigrationError("the database has migration " + row["version"] + " but there is no such file")
        if f["checksum"] != row["checksum"]:
            raise MigrationError("migration " + row["version"] + " (" + row["name"] + ") was changed after it was applied. Never edit an applied migration: add a new one.")
        if files[i]["version"] != row["version"]:
            raise MigrationError("applied migrations are not a prefix of the migration files")
    pending = [f for f in files if f["version"] not in {r["version"] for r in done}]
    return files, done, pending


def script_for(f):
    quote = "$m" + f["version"] + "$"
    guard = ("DO " + quote + " BEGIN IF EXISTS (SELECT 1 FROM soc.schema_migrations WHERE version = '" + f["version"] + "') THEN "
             "RAISE EXCEPTION 'migration " + f["version"] + " is already applied' USING ERRCODE = 'duplicate_object'; END IF; END " + quote + ";\n")
    record = ("INSERT INTO soc.schema_migrations (version, name, checksum) VALUES ('" + f["version"] + "', '" + f["name"] + "', '" + f["checksum"] + "');\n")
    return "BEGIN;\nSELECT pg_advisory_xact_lock(" + str(LOCK_KEY) + ");\n" + guard + f["sql"].rstrip() + "\n" + record + "COMMIT;\n"


def apply(driver, directory=MIGRATIONS_DIR, say=print):
    """Apply every pending migration. Returns the list of versions applied by this call."""
    _, _, pending = plan(driver, directory)
    done = []
    for f in pending:
        try:
            driver.run_script(script_for(f))
        except drivers.DbError as error:
            if error.sqlstate == "42710":   # duplicate_object: another migrator applied it first
                say("migration " + f["version"] + " was applied by another process; skipping")
                continue
            raise MigrationError("migration " + f["version"] + " (" + f["name"] + ") failed and was rolled back: " + str(error)) from None
        say("applied " + f["version"] + " " + f["name"])
        done.append(f["version"])
    return done


def verify(driver, directory=MIGRATIONS_DIR):
    """(ok, problems). ok only when every applied migration matches its file and nothing is pending."""
    try:
        _, _, pending = plan(driver, directory)
    except MigrationError as error:
        return False, [str(error)]
    return (not pending), (["pending migration " + f["version"] + " " + f["name"] for f in pending])


def main(argv=None):
    p = argparse.ArgumentParser(description="Week 4 database migrations")
    p.add_argument("action", choices=["status", "apply", "verify"])
    p.add_argument("--driver", choices=["psql", "psycopg"], default=None)
    p.add_argument("--dsn", default=None, help="connection string; default: the WEEK4_DATABASE_URL environment variable (psql driver: the PG* variables when neither is set)")
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
            for f in files:
                print(("applied  " if f["version"] in {d["version"] for d in done} else "PENDING  ") + f["version"] + " " + f["name"])
            return 0
        ok, problems = verify(driver)
        print("migrations match the files and none are pending" if ok else "NOT OK: " + "; ".join(problems))
        return 0 if ok else 1
    except (drivers.DbError, MigrationError) as error:
        print("STOPPED: " + drivers.redact_dsn(str(error)))
        return 2


if __name__ == "__main__":
    sys.exit(main())
