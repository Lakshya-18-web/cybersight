"""Week 5 database administration (run with the OWNER connection, never with a worker or API login).

  python -m week5.db.admin create-worker-login [--name soc_worker_login]   # password from WEEK5_WORKER_DB_PASSWORD, never from the command line, never printed
  python -m week5.db.admin job-stats                                       # counts by status and the age of the oldest job of each (no alert content)

The API login is made with the Week 4 command  python -m week4.db.admin create-api-login  (soc_api also received the job permissions in Week 5 migration 0001).
Connection: --dsn or WEEK4_ADMIN_DATABASE_URL, or the standard PG* variables.
"""
import argparse
import os
import re
import sys

from week4.db import drivers

from .driver import choose_kind

ROLE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
ENV_ADMIN_DSN = "WEEK4_ADMIN_DATABASE_URL"
ENV_WORKER_PASSWORD = "WEEK5_WORKER_DB_PASSWORD"
MIN_PASSWORD_CHARS = 16


class AdminError(Exception):
    pass


def worker_login_script(name, password):
    """SQL that creates (or re-passwords) a LOGIN role that is a member of soc_worker. The password travels only inside this script (stdin of psql / a bound statement)."""
    if not ROLE_NAME_RE.match(name):
        raise AdminError("the role name must be lower-case letters, digits and underscores, starting with a letter")
    if len(password or "") < MIN_PASSWORD_CHARS:
        raise AdminError("set " + ENV_WORKER_PASSWORD + " to a password of at least %d characters" % MIN_PASSWORD_CHARS)
    lit = drivers.sql_literal(password)
    return ("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%s') THEN CREATE ROLE %s LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; END IF; END $$;\n"
            "ALTER ROLE %s PASSWORD %s;\nGRANT soc_worker TO %s;" % (name, name, name, lit, name))


def main(argv=None):
    p = argparse.ArgumentParser(description="Week 5 database administration (owner connection)")
    p.add_argument("--driver", choices=["psql", "psycopg"], default=None)
    p.add_argument("--dsn", default=None)
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("create-worker-login")
    c.add_argument("--name", default="soc_worker_login")
    sub.add_parser("job-stats")
    args = p.parse_args(argv)
    try:
        driver = drivers.make_driver(args.driver or choose_kind(), args.dsn or os.environ.get(ENV_ADMIN_DSN))
        if args.command == "create-worker-login":
            driver.run_script(worker_login_script(args.name, os.environ.get(ENV_WORKER_PASSWORD, "")))
            print("login role " + args.name + " is a member of soc_worker (claim/complete/fail jobs and ingest cases only). Use it in WEEK5_WORKER_DATABASE_URL.")
        else:
            rows = driver.query("SELECT status, n, oldest_age_seconds FROM soc.job_stats ORDER BY status")
            if not rows:
                print("no jobs")
            for status, n, age in rows:
                print("%-10s %6s   oldest %s s" % (status, n, age))
    except AdminError as error:
        print("STOPPED: " + str(error))
        return 2
    except drivers.DbError as error:
        print("STOPPED: database error: " + drivers.redact_dsn(str(error)))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
