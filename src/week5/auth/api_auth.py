"""The HTTP behaviour of the sign-in routes, as a mixin for Api5 (framework-free like the rest: dispatch -> Response). Uses self.web_auth (an AuthService), self.auth (a SessionAuth),
self.settings and the helpers of the Week 4/5 Api. Order of checks for a route here:
  web sign-in on (404) -> origin allowed for state-changing requests (403) -> session valid when the route needs one (401) -> CSRF token valid when a cookie is present (403)
  -> admin role when the route needs it (403) -> body validation (415/413/400/422) -> the rule in AuthService (its refusals carry their own status).
Responses never contain a hash or a session token; the only place a token appears is the Set-Cookie header of a successful sign-in."""
from week4.api import handlers as h
from week4.db.drivers import DbError
from week4.db.repository import ANALYST_ID_RE

from . import web
from .service import AuthFailure


class _Refused(Exception):
    def __init__(self, response):
        super().__init__("refused")
        self.response = response


class AuthApiMixin:
    web_auth = None

    # ------------------------------------------------------------------ the gate for the existing (non-auth) routes
    def web_gate(self, name, headers):
        """For an existing route that changes state and is reached with only the session cookie: Origin and CSRF must be right. -> a Response, or None to go on."""
        from week4.api import routes
        from week5.api import routes5
        route = routes5.BY_NAME5.get(name) or routes.BY_NAME.get(name)
        if route is None or route.method not in web.UNSAFE_METHODS:
            return None
        auth = self.auth
        if not hasattr(auth, "kind") or auth.kind(headers) != "cookie":
            return None
        return self._request_refusal(headers, auth.token(headers))

    def _request_refusal(self, headers, token):
        if not web.origin_allowed(self.web_auth.settings, headers):
            return self._refuse(403, "origin_not_allowed", "this request did not come from an allowed site")
        if token is not None and not web.csrf_ok(token, headers):
            return self._refuse(403, "csrf_failed", "the request is missing a valid CSRF token; reload the page")
        return None

    @staticmethod
    def _refuse(status, code, message, headers=None):
        return h.error(status, code, message, dict(web.NO_STORE, **(headers or {})))

    # ------------------------------------------------------------------ dispatch for /auth/*
    def _dispatch_auth(self, name, headers, query, path_params, body, raw_body):
        ws = self.web_auth
        if ws is None:
            return h.error(404, "not_found", "web sign-in is not enabled")
        from week5.api import routes5
        route = routes5.BY_NAME5[name]
        settings = ws.settings
        unsafe = route.method in web.UNSAFE_METHODS
        if unsafe and not web.origin_allowed(settings, headers):
            return self._refuse(403, "origin_not_allowed", "this request did not come from an allowed site")
        token = web.cookie_value(headers, settings.cookie_name)
        session = None
        try:
            if route.role in ("session", "admin") or name == "auth_logout":
                session = ws.session(token) if token else None
                if route.role in ("session", "admin") and session is None:
                    return self._refuse(401, "unauthenticated", "sign in to continue")
                if unsafe and token and not web.csrf_ok(token, headers):
                    return self._refuse(403, "csrf_failed", "the request is missing a valid CSRF token; reload the page")
            if route.role == "admin" and not session["user"]["permissions"]["admin"]:
                return self._refuse(403, "forbidden", "your role does not allow this")
            ctx = {"session": session, "token": token, "ip": headers.get(web.CLIENT_IP_HEADER) or "unknown", "agent": (headers.get("user-agent") or "")[:200]}
            return getattr(self, "_" + name)(ctx, headers, query, path_params, body, raw_body)
        except _Refused as refused:
            return refused.response
        except AuthFailure as failure:
            extra = {"Retry-After": str(failure.retry_after)} if failure.retry_after else {}
            return self._refuse(failure.status, failure.code, failure.message, extra)
        except DbError as exc:
            print("DATABASE_ERROR route=%s type=%s sqlstate=%s" % (name, type(exc).__name__, getattr(exc, "sqlstate", None)), flush=True)
            return self._refuse(503, "store_unavailable", "sign-in is not available right now")

    @staticmethod
    def _session_body(session):
        return {"user": session["user"], "csrf_token": session["csrf_token"], "idle_expires_at": session["idle_expires_at"], "absolute_expires_at": session["absolute_expires_at"]}

    def _fields(self, headers, raw_body, body, allowed, required=()):
        parsed, refusal = self._json_body(headers, raw_body, body, allowed, required)
        if refusal is not None:
            raise _Refused(h.Response(refusal.status, refusal.body, dict(web.NO_STORE, **refusal.headers)))
        return parsed

    # ------------------------------------------------------------------ handlers
    def _auth_status(self, ctx, headers, query, path_params, body, raw_body):
        return h.Response(200, {"web_auth": True, "bootstrap_available": self.web_auth.bootstrap_available()}, dict(web.NO_STORE))

    def _auth_login(self, ctx, headers, query, path_params, body, raw_body):
        f = self._fields(headers, raw_body, body, {"username", "password"}, ("username", "password"))
        result = self.web_auth.login(f["username"], f["password"], ctx["ip"], ctx["agent"])
        reply = {k: result[k] for k in ("user", "csrf_token", "idle_expires_at", "absolute_expires_at")}
        return h.Response(200, reply, dict(web.NO_STORE, **{"Set-Cookie": web.session_cookie(self.web_auth.settings, result["token"])}))

    def _auth_logout(self, ctx, headers, query, path_params, body, raw_body):
        if ctx["token"]:
            self.web_auth.logout(ctx["token"])
        return h.Response(200, {"status": "signed_out"}, dict(web.NO_STORE, **{"Set-Cookie": web.clear_cookie(self.web_auth.settings)}))

    def _auth_session(self, ctx, headers, query, path_params, body, raw_body):
        return h.Response(200, self._session_body(ctx["session"]), dict(web.NO_STORE))

    def _auth_bootstrap(self, ctx, headers, query, path_params, body, raw_body):
        if not self.web_auth.bootstrap_enabled():
            raise AuthFailure(404, "not_found", "no such route")
        f = self._fields(headers, raw_body, body, {"bootstrap_secret", "username", "display_name", "password"}, ("bootstrap_secret", "username", "password"))
        made = self.web_auth.bootstrap(f["bootstrap_secret"], f["username"], f.get("display_name"), f["password"], ctx["ip"])
        print("BOOTSTRAP first administrator created", flush=True)
        return h.Response(201, made, dict(web.NO_STORE))

    def _auth_change_password(self, ctx, headers, query, path_params, body, raw_body):
        f = self._fields(headers, raw_body, body, {"current_password", "new_password"}, ("current_password", "new_password"))
        self.web_auth.change_password(ctx["session"]["user"], ctx["token"], f["current_password"], f["new_password"], ctx["ip"])
        return h.Response(200, {"status": "password_changed"}, dict(web.NO_STORE))

    def _auth_users(self, ctx, headers, query, path_params, body, raw_body):
        rows = self.web_auth.list_users(ctx["session"]["user"]["analyst_id"])
        items = [{key[2:]: value for key, value in row.items()} for row in rows]
        return h.Response(200, {"items": items}, dict(web.NO_STORE))

    def _auth_create_user(self, ctx, headers, query, path_params, body, raw_body):
        f = self._fields(headers, raw_body, body, {"username", "display_name", "role", "password"}, ("username", "role", "password"))
        made = self.web_auth.create_user(ctx["session"]["user"]["analyst_id"], f["username"], f.get("display_name"), f["role"], f["password"])
        return h.Response(201, made, dict(web.NO_STORE))

    @staticmethod
    def _target(path_params):
        target = path_params.get("username")
        if not isinstance(target, str) or not ANALYST_ID_RE.match(target):
            raise AuthFailure(404, "not_found", "no such account")
        return target

    def _auth_update_user(self, ctx, headers, query, path_params, body, raw_body):
        target = self._target(path_params)
        f = self._fields(headers, raw_body, body, {"role", "active", "display_name"})
        done = self.web_auth.update_user(ctx["session"]["user"]["analyst_id"], target, f.get("role"), f.get("active"), f.get("display_name"))
        return h.Response(200, done, dict(web.NO_STORE))

    def _auth_reset_password(self, ctx, headers, query, path_params, body, raw_body):
        target = self._target(path_params)
        f = self._fields(headers, raw_body, body, {"password"}, ("password",))
        done = self.web_auth.reset_password(ctx["session"]["user"]["analyst_id"], target, f["password"])
        return h.Response(200, done, dict(web.NO_STORE))

    def _auth_revoke_sessions(self, ctx, headers, query, path_params, body, raw_body):
        target = self._target(path_params)
        done = self.web_auth.revoke_sessions(ctx["session"]["user"]["analyst_id"], target)
        return h.Response(200, done, dict(web.NO_STORE))
