"""The Celery application (deployment backend: Redis broker).

    celery -A week5.celery_app:app worker -Q soc_triage --concurrency 2 --loglevel INFO        (see docs/WEEK5_BACKEND.md and docker-compose.week5.yml)

Celery and the redis client are NOT imported when this module is only read by tests: make_app() imports them and raises a clear error when they are missing. The broker URL comes from
WEEK5_CELERY_BROKER_URL (it may contain a password; it is never logged or stored). Results are not kept (task_ignore_result): the job table is the only record of a job's state.

Settings that matter for correctness (celery_config): acks_late + reject_on_worker_lost (a task whose worker died is redelivered, and the claim makes that safe); prefetch 1 (a worker holds one job);
a soft time limit equal to the job timeout and a hard limit a little above it (the child process is killed, which a thread timeout cannot do); the Redis visibility timeout above the hard limit (or a long
job would be redelivered while still running).
"""
import os

from . import queues, settings as settings_module

ENV_BROKER = "WEEK5_CELERY_BROKER_URL"


def celery_config(settings, broker_url):
    visibility = max(settings.lease_seconds, int(settings.job_timeout_seconds) + settings.celery_hard_limit_slack_seconds) + 60
    return {
        "broker_url": broker_url,
        "result_backend": None,
        "task_ignore_result": True,
        "task_serializer": "json",
        "accept_content": ["json"],
        "timezone": "UTC",
        "enable_utc": True,
        "task_default_queue": settings.celery_queue,
        "task_acks_late": True,
        "task_reject_on_worker_lost": True,
        "worker_prefetch_multiplier": 1,
        "task_soft_time_limit": int(settings.job_timeout_seconds),
        "task_time_limit": int(settings.job_timeout_seconds) + settings.celery_hard_limit_slack_seconds,
        "broker_connection_retry_on_startup": True,
        "broker_transport_options": {"visibility_timeout": visibility, "socket_connect_timeout": 5, "socket_timeout": 10, "retry_on_timeout": True},
        "worker_hijack_root_logger": False,
        "task_track_started": False,
        "worker_send_task_events": False,
    }


def make_app(settings=None, env=None):
    """Build the Celery app. Raises RuntimeError (no secret in the message) when celery is not installed or the broker URL is missing."""
    env = os.environ if env is None else env
    settings = settings or settings_module.from_env(env)
    broker = (env.get(ENV_BROKER) or "").strip()
    if not broker:
        raise RuntimeError(ENV_BROKER + " is not set (for example redis://redis:6379/0, with the password from your environment)")
    try:
        from celery import Celery
    except ImportError as error:
        raise RuntimeError("celery is not installed. Install it with: pip install -r requirements-week5.txt") from error
    app = Celery("soc_triage")
    app.conf.update(celery_config(settings, broker))
    return app


def register_tasks(app, worker_factory):
    """Register week5.process_job on app. worker_factory() -> the process's single Worker (built lazily, so importing this module opens no connection)."""
    state = {"worker": None}

    @app.task(name=queues.TASK_NAME, acks_late=True, ignore_result=True)
    def process_job(job_id):
        if state["worker"] is None:
            state["worker"] = worker_factory()
        return state["worker"].process_job_id(job_id)

    return process_job


def build_for_worker(env=None):
    """Used by `celery -A week5.celery_app:app`. Builds settings, the Celery app and the task; the worker (database + graph + provider) is built on first use."""
    env = os.environ if env is None else env
    settings = settings_module.from_env(env)
    app = make_app(settings, env)
    from . import worker as worker_module
    register_tasks(app, lambda: worker_module.build_worker(settings, env))
    return app


def __getattr__(name):
    # `app` is built on first access so that `import week5.celery_app` (tests, docs) never needs Celery or a broker URL.
    if name == "app":
        built = build_for_worker()
        globals()["app"] = built
        return built
    raise AttributeError(name)
