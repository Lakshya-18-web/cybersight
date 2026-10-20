"""Start the ingestion + approval API.   python -m week5.api.serve5 [--host 127.0.0.1] [--port 8000] [--check]

Environment (nothing is hard-coded, secrets are never printed):
  WEEK5_API_DATABASE_URL (or WEEK4_DATABASE_URL)   connection string of the API's login role (member of soc_api)
  WEEK4_API_TOKEN_HASHES[_FILE]                    token hashes (python -m week4.api.auth new-token), or WEEK4_API_DEV_MODE=1 on a developer's own machine, loopback only
  WEEK5_*                                          see week5.settings (queue backend, limits, ...)
  WEEK5_CELERY_BROKER_URL                          only for WEEK5_QUEUE_BACKEND=celery
--check validates the configuration and the database connection, prints one line and exits (0 ok, 2 not ok) without starting a server.
Put TLS in front of it (a reverse proxy) before any use beyond localhost: bearer tokens travel in a header.
"""
import argparse
import os
import sys

from week4.api import auth
from week4.db.repository import PgRepository

from week5 import jobs, queues, settings as settings_module
from week5.db.driver import ResilientDriver, choose_kind

LOOPBACK = ("127.0.0.1", "::1", "localhost")
ENV_DB = "WEEK5_API_DATABASE_URL"


def build(env=None, driver=None):
    """-> (auth_config, Api5). Raises auth.ConfigError / settings.ConfigError / RuntimeError (no secret in any message)."""
    from .api5 import Api5
    env = os.environ if env is None else env
    settings = settings_module.from_env(env)
    config = auth.from_env(env)
    if driver is None:
        dsn = env.get(ENV_DB) or env.get("WEEK4_DATABASE_URL")
        if not dsn:
            raise settings_module.ConfigError(ENV_DB + " is not set (the connection string of the API's login role)")
        driver = ResilientDriver(choose_kind(), dsn)
    store = jobs.PgJobStore(driver)
    if settings.queue_backend == "celery":
        from week5 import celery_app
        queue = queues.CeleryQueue(celery_app.make_app(settings, env), settings.celery_queue)
    elif settings.queue_backend == "postgres":
        queue = queues.PostgresQueue(store)
    else:
        raise settings_module.ConfigError("WEEK5_QUEUE_BACKEND=memory is for tests only and cannot be used by the API")
    dispatcher = queues.Dispatcher(store, queue, settings)
    repo = PgRepository(driver)
    repo.ping = lambda: driver.scalar("SELECT 1") in (1, "1")
    return config, Api5(repo, config, store, dispatcher, settings)


def main(argv=None):
    p = argparse.ArgumentParser(description="Ingestion and approval API")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--check", action="store_true")
    args = p.parse_args(argv)
    try:
        config, api = build()
        if config.mode == "dev" and args.host not in LOOPBACK:
            raise auth.ConfigError("dev mode (no real authentication) may only listen on loopback, not on " + args.host)
        if args.check:
            api.repo.ping()
            api.jobs.ping()
            print("OK: configuration valid, database reachable, queue backend " + api.dispatcher.queue.name + ", auth mode " + config.mode)
            return 0
        from .app5 import create_app5
        app = create_app5(api)
    except (auth.ConfigError, settings_module.ConfigError, RuntimeError, ImportError) as error:
        print("STOPPED: " + str(error))
        return 2
    except Exception as error:      # a database error: only its class name, the message may hold a host name
        print("STOPPED: " + type(error).__name__)
        return 2
    if config.mode == "dev":
        print("WARNING: DEV MODE. Anyone who can reach this port can act as any analyst. Loopback only.")
    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
