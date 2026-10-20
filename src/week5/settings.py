"""Week 5 settings: every tunable in one place, read from WEEK5_* environment variables, validated before anything starts.

Nothing secret lives here. Database passwords, the broker URL and the model key are read from the environment by the code that needs them (week4.db.drivers, the Celery app, llm_config)
and are never stored in a Settings object, never part of its repr, and never written to a log or a job record.

Defaults are conservative: fake model, no live API call, PostgreSQL as the queue, 3 attempts, a 120 s timeout per attempt, a bounded queue and a small request size limit.
"""
import os
from dataclasses import dataclass, fields

QUEUE_BACKENDS = ("postgres", "celery", "memory")
ENGINES = ("langgraph", "instrumented")
MODEL_MODES = ("fake", "gemini")
ALERT_SETS = ("synthetic", "dev")
FLOW_STORES = ("dev", "none", "fixture")      # fixture = the small invented traffic table in week5.fixtures (Docker demo, no data files needed)
MEMORY_MODES = ("off", "on")


class ConfigError(Exception):
    """The configuration is not valid. The message lists every problem and never contains a secret."""


def _int(env, name, default, low, high, problems):
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        problems.append(name + " must be a whole number")
        return default
    if not low <= value <= high:
        problems.append("%s must be from %d to %d" % (name, low, high))
    return value


def _float(env, name, default, low, high, problems):
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw.strip())
    except ValueError:
        problems.append(name + " must be a number")
        return default
    if not (low <= value <= high) or value != value:
        problems.append("%s must be from %s to %s" % (name, low, high))
    return value


def _choice(env, name, default, allowed, problems):
    raw = (env.get(name) or "").strip().lower()
    if raw == "":
        return default
    if raw not in allowed:
        problems.append(name + " must be one of: " + ", ".join(allowed))
        return default
    return raw


def _flag(env, name, default, problems):
    raw = (env.get(name) or "").strip()
    if raw == "":
        return default
    if raw not in ("0", "1"):
        problems.append(name + " must be 0 or 1")
        return default
    return raw == "1"


def _backoff(env, name, default, problems):
    raw = (env.get(name) or "").strip()
    if raw == "":
        return default
    out = []
    for part in raw.split(","):
        try:
            seconds = float(part.strip())
        except ValueError:
            problems.append(name + " must be comma-separated seconds, for example 5,20,60")
            return default
        if not 0 <= seconds <= 3600:
            problems.append(name + " entries must be from 0 to 3600 seconds")
            return default
        out.append(seconds)
    return tuple(out) if out else default


@dataclass(frozen=True)
class Settings:
    queue_backend: str = "postgres"
    engine: str = "langgraph"
    model_mode: str = "fake"
    allow_live_model: bool = False
    alert_set: str = "synthetic"
    flow_store: str = "dev"
    alias_ids: bool = True
    default_memory: str = "off"
    memory_dir: str = ""
    memory_k: int = 5
    max_body_bytes: int = 16384
    max_attempts: int = 3
    job_timeout_seconds: float = 120.0
    lease_seconds: int = 300
    retry_backoff_seconds: tuple = (5.0, 20.0, 60.0)
    max_queue_depth: int = 1000
    rate_limit_per_minute: int = 120
    rate_burst: int = 30
    poll_interval_seconds: float = 1.0
    reap_interval_seconds: float = 15.0
    republish_after_seconds: int = 60
    model_rpm: float = 10.0
    celery_queue: str = "soc_triage"
    celery_hard_limit_slack_seconds: int = 30

    def backoff_for(self, attempt):
        """Seconds to wait before attempt number attempt+1, after attempt (1-based) failed. The last entry repeats."""
        if attempt < 1:
            return 0.0
        i = min(attempt - 1, len(self.retry_backoff_seconds) - 1)
        return float(self.retry_backoff_seconds[i])

    def public(self):
        """A plain dict for health output and reports. Contains no secret (there is none in a Settings object)."""
        return {f.name: (list(getattr(self, f.name)) if isinstance(getattr(self, f.name), tuple) else getattr(self, f.name)) for f in fields(self)}


def from_env(env=None):
    env = os.environ if env is None else env
    problems = []
    d = Settings()
    s = Settings(
        queue_backend=_choice(env, "WEEK5_QUEUE_BACKEND", d.queue_backend, QUEUE_BACKENDS, problems),
        engine=_choice(env, "WEEK5_ENGINE", d.engine, ENGINES, problems),
        model_mode=_choice(env, "WEEK5_MODEL_MODE", d.model_mode, MODEL_MODES, problems),
        allow_live_model=(env.get("WEEK5_ALLOW_LIVE_MODEL") or "").strip() == "1",
        alert_set=_choice(env, "WEEK5_ALERT_SET", d.alert_set, ALERT_SETS, problems),
        flow_store=_choice(env, "WEEK5_FLOW_STORE", d.flow_store, FLOW_STORES, problems),
        alias_ids=_flag(env, "WEEK5_ALIAS_IDS", True, problems),
        default_memory=_choice(env, "WEEK5_DEFAULT_MEMORY", d.default_memory, MEMORY_MODES, problems),
        memory_dir=(env.get("WEEK5_MEMORY_DIR") or "").strip(),
        memory_k=_int(env, "WEEK5_MEMORY_K", d.memory_k, 1, 50, problems),
        max_body_bytes=_int(env, "WEEK5_MAX_BODY_BYTES", d.max_body_bytes, 512, 1048576, problems),
        max_attempts=_int(env, "WEEK5_MAX_ATTEMPTS", d.max_attempts, 1, 10, problems),
        job_timeout_seconds=_float(env, "WEEK5_JOB_TIMEOUT_SECONDS", d.job_timeout_seconds, 1, 3600, problems),
        lease_seconds=_int(env, "WEEK5_LEASE_SECONDS", d.lease_seconds, 5, 86400, problems),
        retry_backoff_seconds=_backoff(env, "WEEK5_RETRY_BACKOFF_SECONDS", d.retry_backoff_seconds, problems),
        max_queue_depth=_int(env, "WEEK5_MAX_QUEUE_DEPTH", d.max_queue_depth, 1, 1000000, problems),
        rate_limit_per_minute=_int(env, "WEEK5_RATE_LIMIT_PER_MINUTE", d.rate_limit_per_minute, 0, 100000, problems),
        rate_burst=_int(env, "WEEK5_RATE_BURST", d.rate_burst, 1, 10000, problems),
        poll_interval_seconds=_float(env, "WEEK5_POLL_INTERVAL_SECONDS", d.poll_interval_seconds, 0.05, 60, problems),
        reap_interval_seconds=_float(env, "WEEK5_REAP_INTERVAL_SECONDS", d.reap_interval_seconds, 0.5, 3600, problems),
        republish_after_seconds=_int(env, "WEEK5_REPUBLISH_AFTER_SECONDS", d.republish_after_seconds, 1, 86400, problems),
        model_rpm=_float(env, "WEEK5_MODEL_RPM", d.model_rpm, 0.1, 6000, problems),
        celery_queue=(env.get("WEEK5_CELERY_QUEUE") or d.celery_queue).strip(),
        celery_hard_limit_slack_seconds=_int(env, "WEEK5_CELERY_HARD_LIMIT_SLACK_SECONDS", d.celery_hard_limit_slack_seconds, 1, 3600, problems),
    )
    problems.extend(cross_checks(s))
    if problems:
        raise ConfigError("invalid Week 5 configuration: " + "; ".join(problems))
    return s


def cross_checks(s):
    """Problems that involve more than one setting."""
    out = []
    if s.lease_seconds < s.job_timeout_seconds + 30:
        out.append("WEEK5_LEASE_SECONDS (%d) must be at least WEEK5_JOB_TIMEOUT_SECONDS + 30, or a slow job could be taken by a second worker while the first is still running" % s.lease_seconds)
    if s.model_mode == "gemini" and not s.allow_live_model:
        out.append("WEEK5_MODEL_MODE=gemini makes real Gemini calls (cost, quota). It needs WEEK5_ALLOW_LIVE_MODEL=1, which you set only after deciding to spend that")
    if s.default_memory == "on" and not s.memory_dir:
        out.append("WEEK5_DEFAULT_MEMORY=on needs WEEK5_MEMORY_DIR (the seeded memory_store folder)")
    if not s.celery_queue or len(s.celery_queue) > 60 or not all(c.isalnum() or c in "_-." for c in s.celery_queue):
        out.append("WEEK5_CELERY_QUEUE must be 1-60 letters, digits, _ - .")
    return out
