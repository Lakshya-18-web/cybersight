"""Web sign-in settings, read from WEEK5_* environment variables and validated at start-up (ConfigError lists every problem; no message contains a secret).

  WEEK5_WEB_AUTH                  1 (default) enables /auth/* and cookie sessions; 0 turns the feature off (the API then behaves as before: bearer tokens only)
  WEEK5_ALLOWED_ORIGINS           comma-separated EXACT origins of the console (scheme://host[:port], no path, no wildcard). Used for CORS and for the Origin check.
                                  Default: https://cybersight-nine.vercel.app.  http:// is accepted only for localhost / 127.0.0.1 (local development).
  WEEK5_COOKIE_SECURE             1 (default). 0 only for local development over plain http.
  WEEK5_COOKIE_SAMESITE           None (default; the console and the API are on different sites, so the cookie must be sent cross-site; needs Secure) | Lax | Strict
  WEEK5_SESSION_IDLE_SECONDS      43200 (12 h) of inactivity ends a session
  WEEK5_SESSION_ABSOLUTE_SECONDS  604800 (7 days) after which every session ends, however active
  WEEK5_SESSION_MAX_PER_USER      10 concurrent sessions per account; the oldest are revoked beyond that
  WEEK5_PASSWORD_HASH             argon2id (default) | scrypt
  WEEK5_ARGON2_TIME_COST / WEEK5_ARGON2_MEMORY_KIB / WEEK5_ARGON2_PARALLELISM    3 / 19456 / 1 (raise on a bigger server; old hashes keep working and are upgraded at next sign-in)
  WEEK5_LOGIN_LIMIT_PAIR / _IP / _SUBJECT / WEEK5_LOGIN_LIMIT_WINDOW_SECONDS      5 / 40 / 20 failures per 900 s (username+address / address / username)
  WEEK5_BOOTSTRAP_TOKEN           a random secret of at least 32 characters that enables POST /auth/bootstrap (create the first administrator). Unset = bootstrap disabled.
                                  Only its SHA-256 is kept in memory. Remove it from the environment once the administrator exists.
  WEEK5_TRUSTED_PROXY_HOPS        1 (default): how many reverse proxies append to X-Forwarded-For before the request reaches the API (0 = use the socket address)
  WEEK5_AUTH_ATTEMPT_SALT         optional secret that keys the hashes of addresses and usernames in soc.auth_attempts (they are SHA-256 of salt|value). Default: a fixed public label.
  WEEK5_ALLOW_BEARER_TOKENS       1 (default): API tokens (Authorization: Bearer, from WEEK4_API_TOKEN_HASHES) still work, for sensors and scripts. 0: browser sessions only.
"""
import hashlib
from dataclasses import dataclass
from urllib.parse import urlsplit

from week5.settings import ConfigError, _choice, _flag, _int

DEFAULT_ORIGIN = "https://cybersight-nine.vercel.app"
LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]")
MIN_BOOTSTRAP_CHARS = 32
COOKIE_BASE = "cybersight_session"


@dataclass(frozen=True)
class AuthSettings:
    enabled: bool = True
    allowed_origins: tuple = (DEFAULT_ORIGIN,)
    cookie_secure: bool = True
    cookie_samesite: str = "None"
    idle_seconds: int = 43200
    absolute_seconds: int = 604800
    max_sessions: int = 10
    password_scheme: str = "argon2id"
    argon2_time_cost: int = 3
    argon2_memory_kib: int = 19456
    argon2_parallelism: int = 1
    limit_pair: int = 5
    limit_ip: int = 40
    limit_subject: int = 20
    limit_window_seconds: int = 900
    bootstrap_digest: str = ""
    trusted_proxy_hops: int = 1
    attempt_salt: str = "cybersight-auth-attempts-v1"
    allow_bearer: bool = True
    max_concurrent_hashes: int = 4

    @property
    def cookie_name(self):
        """The __Host- prefix makes a browser accept the cookie only if it is Secure, has Path=/ and no Domain: it cannot be planted by a sibling sub-domain."""
        return ("__Host-" if self.cookie_secure else "") + COOKIE_BASE

    @property
    def bootstrap_enabled(self):
        return bool(self.bootstrap_digest)


def enabled(env):
    return (env.get("WEEK5_WEB_AUTH") or "1").strip() != "0"


def _origins(raw, problems):
    out = []
    for part in (raw or "").split(","):
        item = part.strip().rstrip("/")
        if not item:
            continue
        if "*" in item:
            problems.append("WEEK5_ALLOWED_ORIGINS must list exact origins; a wildcard is not allowed")
            continue
        try:
            u = urlsplit(item)
            host = u.hostname or ""
            ok = u.scheme in ("https", "http") and host and not u.path and not u.query and not u.fragment and not u.username and u.netloc.lower() == (host + (":%d" % u.port if u.port else "")).lower()
        except ValueError:
            ok = False
        if not ok:
            problems.append("WEEK5_ALLOWED_ORIGINS entries must look like https://host or http://localhost:5173 (scheme, host, optional port; nothing else)")
            continue
        if u.scheme == "http" and host not in ("localhost", "127.0.0.1", "::1"):
            problems.append("WEEK5_ALLOWED_ORIGINS: http:// is only allowed for localhost and 127.0.0.1")
            continue
        out.append(item.lower())
    return tuple(dict.fromkeys(out))


def from_env(env):
    problems = []
    d = AuthSettings()
    secure = _flag(env, "WEEK5_COOKIE_SECURE", True, problems)
    raw_origins = (env.get("WEEK5_ALLOWED_ORIGINS") or "").strip()
    origins = _origins(raw_origins, problems) if raw_origins else d.allowed_origins
    if raw_origins and not origins and not problems:
        problems.append("WEEK5_ALLOWED_ORIGINS lists no origin")
    samesite = {"none": "None", "lax": "Lax", "strict": "Strict"}.get((env.get("WEEK5_COOKIE_SAMESITE") or "None").strip().lower())
    if samesite is None:
        problems.append("WEEK5_COOKIE_SAMESITE must be None, Lax or Strict")
        samesite = "None"
    if samesite == "None" and not secure:
        problems.append("WEEK5_COOKIE_SAMESITE=None needs WEEK5_COOKIE_SECURE=1 (browsers refuse the cookie otherwise); for plain-http local development use Lax")
    idle = _int(env, "WEEK5_SESSION_IDLE_SECONDS", d.idle_seconds, 300, 30 * 86400, problems)
    absolute = _int(env, "WEEK5_SESSION_ABSOLUTE_SECONDS", d.absolute_seconds, 600, 90 * 86400, problems)
    if idle > absolute:
        problems.append("WEEK5_SESSION_IDLE_SECONDS must not be longer than WEEK5_SESSION_ABSOLUTE_SECONDS")
    scheme = _choice(env, "WEEK5_PASSWORD_HASH", d.password_scheme, ("argon2id", "scrypt"), problems)
    token = (env.get("WEEK5_BOOTSTRAP_TOKEN") or "").strip()
    if token and len(token) < MIN_BOOTSTRAP_CHARS:
        problems.append("WEEK5_BOOTSTRAP_TOKEN must be at least %d characters (use a random value: python -c \"import secrets; print(secrets.token_urlsafe(48))\")" % MIN_BOOTSTRAP_CHARS)
        token = ""
    s = AuthSettings(
        enabled=True, allowed_origins=origins, cookie_secure=secure, cookie_samesite=samesite, idle_seconds=idle, absolute_seconds=absolute,
        max_sessions=_int(env, "WEEK5_SESSION_MAX_PER_USER", d.max_sessions, 1, 100, problems), password_scheme=scheme,
        argon2_time_cost=_int(env, "WEEK5_ARGON2_TIME_COST", d.argon2_time_cost, 1, 20, problems),
        argon2_memory_kib=_int(env, "WEEK5_ARGON2_MEMORY_KIB", d.argon2_memory_kib, 8192, 1048576, problems),
        argon2_parallelism=_int(env, "WEEK5_ARGON2_PARALLELISM", d.argon2_parallelism, 1, 16, problems),
        limit_pair=_int(env, "WEEK5_LOGIN_LIMIT_PAIR", d.limit_pair, 1, 1000, problems), limit_ip=_int(env, "WEEK5_LOGIN_LIMIT_IP", d.limit_ip, 1, 10000, problems),
        limit_subject=_int(env, "WEEK5_LOGIN_LIMIT_SUBJECT", d.limit_subject, 1, 10000, problems),
        limit_window_seconds=_int(env, "WEEK5_LOGIN_LIMIT_WINDOW_SECONDS", d.limit_window_seconds, 60, 86400, problems),
        bootstrap_digest=hashlib.sha256(token.encode("utf-8")).hexdigest() if token else "",
        trusted_proxy_hops=_int(env, "WEEK5_TRUSTED_PROXY_HOPS", d.trusted_proxy_hops, 0, 5, problems),
        attempt_salt=(env.get("WEEK5_AUTH_ATTEMPT_SALT") or "").strip() or d.attempt_salt,
        allow_bearer=_flag(env, "WEEK5_ALLOW_BEARER_TOKENS", True, problems))
    if problems:
        raise ConfigError("web sign-in configuration is not valid: " + "; ".join(problems))
    return s
