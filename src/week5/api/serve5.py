"""Start the ingestion + approval API.   python -m week5.api.serve5 [--host 127.0.0.1] [--port 8000] [--check]

Environment (nothing is hard-coded, secrets are never printed):
  WEEK5_API_DATABASE_URL (or WEEK4_DATABASE_URL)   connection string of the API's login role (member of soc_api)
  WEEK4_API_TOKEN_HASHES[_FILE]                    token hashes (python -m week4.api.auth new-token), or WEEK4_API_DEV_MODE=1 on a developer's own machine, loopback only.
                                                   Optional when web sign-in is on (the default): people then sign in with a username and password (migration 0003), tokens stay for machines.
  WEEK5_WEB_AUTH, WEEK5_ALLOWED_ORIGINS, WEEK5_BOOTSTRAP_TOKEN, ...   web sign-in: see week5.auth.settings and docs/AUTHENTICATION.md
  WEEK5_*                                          see week5.settings (queue backend, limits, ...)
  WEEK5_CELERY_BROKER_URL                          only for WEEK5_QUEUE_BACKEND=celery
--check validates the configuration and the database connection, prints one line and exits (0 ok, 2 not ok) without starting a server.
Put TLS in front of it (a reverse proxy) before any use beyond localhost: bearer tokens travel in a header.
"""
import argparse
import os
import sys

from week4.api import auth
from week5.auth import settings as auth_settings, web as auth_web
from week5.auth.service import AuthService
from week5.auth.store import PgAuthStore
from week5.db.repository import Week5PgRepository as PgRepository

from week5 import jobs, queues, settings as settings_module
from week5.db.driver import ResilientDriver, choose_kind

LOOPBACK = ("127.0.0.1", "::1", "localhost")
ENV_DB = "WEEK5_API_DATABASE_URL"


def build(env=None, driver=None):
    """-> (auth_config, Api5). Raises auth.ConfigError / settings.ConfigError / RuntimeError (no secret in any message)."""
    from .api5 import Api5
    env = os.environ if env is None else env
    settings = settings_module.from_env(env)
    web_on = auth_settings.enabled(env)
    web_settings = auth_settings.from_env(env) if web_on else None
    try:
        config = auth.from_env(env)
    except auth.ConfigError:
        if not web_on:
            raise
        config = auth_web.NoBearer()          # no API token and no dev mode: only browser sessions can sign in (this is the normal setup of the console)
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
    repo.ping = lambda: driver.scalar("SELECT 1") in (1, "1")      # kept from the live repository: psycopg returns an int, the psql driver a string
    web = None
    if web_on:
        web = AuthService(PgAuthStore(driver), web_settings)         # raises RuntimeError at start-up when Argon2 is configured but argon2-cffi is not installed
        config = auth_web.SessionAuth(config, web)
    api = Api5(repo, config, store, dispatcher, settings, web_auth=web)
    # Non-secret context for the typed case analysis, /providers, /diagnostics and /evaluation/reports. The API never holds the model or threat-intelligence keys (the worker does),
    # so api.threat_intel stays None and /providers says so; the lookup outcomes it shows come from the stored cases.
    from week4 import policy as w4_policy
    from week5 import evidence_policy
    api.risk_policy = w4_policy.load_policy(None)
    api.evidence = evidence_policy.load(env.get(evidence_policy.ENV_PATH) or None)
    if settings.model_mode == "gemini":
        import llm_config
        api.model_name = llm_config.models().get("small")
    else:
        api.model_name = "fake (no model is called)"
    return config, api


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
            line = "OK: configuration valid, database reachable, queue backend " + api.dispatcher.queue.name + ", auth mode " + config.mode
            if api.web_auth is not None:
                try:
                    line += ", web sign-in on (setup %s)" % ("OPEN: create the first administrator" if api.web_auth.bootstrap_available() else "closed or disabled")
                except Exception:
                    print("STOPPED: web sign-in is on but the database has no sign-in tables. Apply Week 5 migration 0003 (see docs/AUTHENTICATION.md).")
                    return 2
            else:
                line += ", web sign-in off"
            print(line)
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

