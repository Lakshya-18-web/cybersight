"""Start the approval API.   python -m week4.api.serve [--host 127.0.0.1] [--port 8000]

Environment (nothing is hard-coded, and secrets are never printed):
  WEEK4_DATABASE_URL            connection string for the case store (use the least-privilege login role: see docs/WEEK4_OPERATIONS.md)
  WEEK4_API_TOKEN_HASHES[_FILE] token hashes (see week4.api.auth), or WEEK4_API_DEV_MODE=1 for a developer's own machine
Refuses to start when authentication is not configured, or when dev mode is combined with an address other than loopback.
Put TLS in front of it (a reverse proxy) before any use beyond localhost: bearer tokens are sent in a header.
"""
import argparse
import os
import sys

from week4.db import drivers

from . import auth
from .app import create_app
from .handlers import Api

LOOPBACK = ("127.0.0.1", "::1", "localhost")


def build(env=None, driver_kind=None):
    env = os.environ if env is None else env
    config = auth.from_env(env)
    dsn = env.get("WEEK4_DATABASE_URL")
    if not dsn:
        raise auth.ConfigError("WEEK4_DATABASE_URL is not set")
    from week4.db.repository import PgRepository
    kind = driver_kind
    if kind is None:
        try:
            import psycopg  # noqa: F401
            kind = "psycopg"
        except ImportError:
            kind = "psql"
    return config, Api(PgRepository(drivers.make_driver(kind, dsn)), config)


def main(argv=None):
    p = argparse.ArgumentParser(description="Approval API")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    args = p.parse_args(argv)
    try:
        config, api = build()
        if config.mode == "dev" and args.host not in LOOPBACK:
            raise auth.ConfigError("dev mode (no real authentication) may only listen on loopback, not on " + args.host)
        app = create_app(api)
    except (auth.ConfigError, ImportError) as error:
        print("STOPPED: " + str(error))
        return 2
    if config.mode == "dev":
        print("WARNING: DEV MODE. Anyone who can reach this port can act as any analyst. Loopback only.")
    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
