"""The browser-facing rules, with no database: the session cookie, the origin check, the CSRF check, the client address and the authenticator Api5 uses.

Cookie: HttpOnly (script cannot read it), Secure, Path=/, no Domain (a __Host- prefix cookie is bound to this one host), SameSite=None by default because the console and the API are on different sites.
Because a cookie travels with every request, a page on another site could make the browser send a state-changing request. Two independent checks stop that (CORS is not one of them):
  1. Origin: a state-changing request that carries the session cookie must come with an Origin header equal to one of the configured origins. A missing Origin is refused.
  2. CSRF token: it must also carry X-CSRF-Token equal to the token derived from its session (service.csrf_token); the page learns it from the sign-in or GET /auth/session response.
Requests that authenticate with an Authorization header (API tokens) do not use the cookie and are not subject to either check.
"""
import hmac
from http.cookies import SimpleCookie

from . import service

CSRF_HEADER = "x-csrf-token"
CLIENT_IP_HEADER = "x-cs-client-ip"          # set by the web layer after it removes any value the caller sent; never trusted from outside
UNSAFE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def cookie_value(headers, name):
    """The value of one cookie from a lower-cased header dict, or None."""
    raw = headers.get("cookie")
    if not raw or len(raw) > 8192:
        return None
    jar = SimpleCookie()
    try:
        jar.load(raw)
    except Exception:         # a malformed Cookie header is simply "no cookie"
        return None
    morsel = jar.get(name)
    return morsel.value if morsel is not None else None


def _attributes(settings):
    parts = ["Path=/", "HttpOnly", "SameSite=" + settings.cookie_samesite]
    if settings.cookie_secure:
        parts.append("Secure")
    return parts


def session_cookie(settings, token):
    """The Set-Cookie header value that stores a session token. Max-Age is the absolute lifetime; the server decides when a session really ends."""
    return "; ".join(["%s=%s" % (settings.cookie_name, token), "Max-Age=%d" % settings.absolute_seconds] + _attributes(settings))


def clear_cookie(settings):
    return "; ".join(["%s=" % settings.cookie_name, "Max-Age=0", "Expires=Thu, 01 Jan 1970 00:00:00 GMT"] + _attributes(settings))


def origin_allowed(settings, headers):
    origin = (headers.get("origin") or "").strip().lower()
    return bool(origin) and origin in settings.allowed_origins


def csrf_ok(token, headers):
    given = headers.get(CSRF_HEADER) or ""
    return bool(token) and bool(given) and hmac.compare_digest(given.encode("utf-8", "replace"), service.csrf_token(token).encode("ascii"))


def client_ip(forwarded_for, peer, hops):
    """The caller's address. hops = how many trusted reverse proxies append to X-Forwarded-For: the address they saw is the entry that many places from the END
    (earlier entries are whatever the caller claimed). hops 0, or a header that is too short, falls back to the socket peer."""
    if hops > 0 and forwarded_for:
        items = [part.strip() for part in forwarded_for.split(",") if part.strip()]
        if len(items) >= hops:
            return items[-hops][:64]
    return (peer or "unknown")[:64]


class SessionAuth:
    """Drop-in for week4.api.auth.AuthConfig: authenticate(headers) -> analyst id or None. Bearer tokens and the dev header (machines, local development) are used when the request carries them
    (and WEEK5_ALLOW_BEARER_TOKENS is on); otherwise the session cookie. `mode` is what /health reports."""

    def __init__(self, legacy, auth_service):
        self.legacy, self.web = legacy, auth_service
        self.mode = legacy.mode if (getattr(legacy, "token_hashes", None) or legacy.mode == "dev") else "session"
        self.token_hashes = getattr(legacy, "token_hashes", {})

    def kind(self, headers):
        """'bearer' when the request carries an Authorization or dev header, 'cookie' when it carries only the session cookie, else None."""
        if headers.get("authorization") or headers.get("x-dev-analyst"):
            return "bearer"
        return "cookie" if self.token(headers) else None

    def token(self, headers):
        return cookie_value(headers, self.web.settings.cookie_name)

    def authenticate(self, headers):
        kind = self.kind(headers)
        if kind == "bearer":
            return self.legacy.authenticate(headers) if self.web.settings.allow_bearer else None
        if kind == "cookie":
            row = self.web.session(self.token(headers))
            return row["user"]["analyst_id"] if row else None
        return None


class NoBearer:
    """The legacy authenticator when no API token and no dev mode is configured (browser sessions only)."""
    mode = "session"
    token_hashes = {}

    def authenticate(self, headers):
        return None
