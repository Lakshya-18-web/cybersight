"""Small administration commands for the case database. Run with the OWNER connection (the one that applied the migrations), never with the API login role.

  python -m week4.db.admin add-analyst --id alice --role approver [--name "Alice A."] [--inactive]
  python -m week4.db.admin get-analyst --id alice
  python -m week4.db.admin create-api-login [--name soc_api_login]        # password is read from WEEK4_API_DB_PASSWORD, never from the command line, never printed
  python -m week4.db.admin verify-audit                                   # recomputes the audit hash chain; exit 0 only when intact

Connection: --dsn or WEEK4_ADMIN_DATABASE_URL (psycopg driver), or the standard PG* variables (psql driver). Nothing here is hard-coded and no secret is ever printed or stored.
"""
import argparse
import os
import re
import sys

from . import drivers
from .repository import PgRepository, ROLES

ROLE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
ENV_ADMIN_DSN = "WEEK4_ADMIN_DATABASE_URL"
ENV_API_PASSWORD = "WEEK4_API_DB_PASSWORD"
MIN_PASSWORD_CHARS = 16


class AdminError(Exception):
    pass


def make_repo(args):
    dsn = args.dsn or os.environ.get(ENV_ADMIN_DSN)
    kind = args.driver
    if kind is None:
        try:
            import psycopg  # noqa: F401
            kind = "psycopg"
        except ImportError:
            kind = "psql"
    return PgRepository(drivers.make_driver(kind, dsn))


def api_login_script(name, password):
    """SQL that creates (or re-passwords) a LOGIN role that is a member of soc_api. The password only travels inside this script (stdin of psql / a bound statement)."""
    if not ROLE_NAME_RE.match(name):
        raise AdminError("the role name must be lower-case letters, digits and underscores, starting with a letter")
    if len(password or "") < MIN_PASSWORD_CHARS:
        raise AdminError("set " + ENV_API_PASSWORD + " to a password of at least %d characters" % MIN_PASSWORD_CHARS)
    lit = drivers.sql_literal(password)
    return ("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%s') THEN CREATE ROLE %s LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; END IF; END $$;\n"
            "ALTER ROLE %s PASSWORD %s;\nGRANT soc_api TO %s;" % (name, name, name, lit, name))


def main(argv=None):
    p = argparse.ArgumentParser(description="Case database administration (owner connection)")
    p.add_argument("--driver", choices=["psql", "psycopg"], default=None)
    p.add_argument("--dsn", default=None)
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("add-analyst")
    a.add_argument("--id", required=True)
    a.add_argument("--role", required=True, choices=ROLES)
    a.add_argument("--name", default=None)
    a.add_argument("--inactive", action="store_true")
    g = sub.add_parser("get-analyst")
    g.add_argument("--id", required=True)
    c = sub.add_parser("create-api-login")
    c.add_argument("--name", default="soc_api_login")
    sub.add_parser("verify-audit")
    args = p.parse_args(argv)
    try:
        repo = make_repo(args)
        if args.command == "add-analyst":
            row = repo.upsert_analyst(args.id, args.role, display_name=args.name, active=not args.inactive, actor="system:admin-cli")
            print("analyst " + row["analyst_id"] + ": role " + row["role"] + ", " + ("active" if row["active"] else "inactive"))
        elif args.command == "get-analyst":
            row = repo.get_analyst(args.id)
            print("no such analyst" if row is None else "analyst %s: role %s, %s" % (row["analyst_id"], row["role"], "active" if row["active"] else "inactive"))
            return 0 if row else 1
        elif args.command == "create-api-login":
            repo.db.run_script(api_login_script(args.name, os.environ.get(ENV_API_PASSWORD, "")))
            print("login role " + args.name + " is a member of soc_api (read access + the four SECURITY DEFINER functions only). Use it in WEEK4_DATABASE_URL.")
        else:
            res = repo.verify_audit_chain()
            print("audit chain intact" if res["ok"] else "AUDIT CHAIN BROKEN at event " + str(res["first_bad_event_id"]))
            return 0 if res["ok"] else 1
    except (AdminError, ValueError) as error:
        print("STOPPED: " + str(error))
        return 2
    except drivers.DbError as error:
        print("STOPPED: database error: " + drivers.redact_dsn(str(error)))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
