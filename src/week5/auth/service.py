"""Sign-in, sessions, one-time bootstrap and account administration. No HTTP and no SQL in here: callers pass plain values, the store does the database work.

Rules kept here (each tested):
  * a failed sign-in never says which part was wrong: unknown user, wrong password and inactive account give the same answer, and an unknown user costs about the same time (a dummy hash is checked)
  * throttling runs BEFORE any password is checked; a throttled request records nothing, so it cannot extend a block
  * a session token is 256 random bits; only its SHA-256 leaves this process (to the database); the CSRF token is derived from it and never stored
  * the number of password hashes running at once is bounded, so a flood of sign-ins cannot exhaust memory (Argon2 is memory-hard)
  * nothing here logs or returns a password or a hash; login() returns the new session token once, for the cookie
"""
import hashlib
import hmac
import re
import secrets
import threading

from week4.db.drivers import DbError

from . import passwords

TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}", re.ASCII)
ROLES = ("viewer", "analyst", "approver", "admin")
GENERIC_LOGIN = "Invalid username or password."
MAX_LOGIN_PASSWORD = 1024
DISPLAY_MAX = 100


class AuthFailure(Exception):
    """A refusal with an HTTP-shaped meaning. message is safe to show."""
    def __init__(self, status, code, message, retry_after=None):
        super().__init__(message)
        self.status, self.code, self.message, self.retry_after = status, code, message, retry_after


def token_hash(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def csrf_token(token):
    """The synchronizer token for a session: an HMAC keyed by the session token itself. Unguessable without the cookie, nothing to store, changes when the session changes."""
    return hmac.new(token.encode("ascii"), b"cybersight-csrf-v1", hashlib.sha256).hexdigest()


def permissions_for(role):
    return {"read": role in ROLES, "submit": role in ("analyst", "approver", "admin"), "decide": role in ("approver", "admin"), "admin": role == "admin"}


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AuthService:
    def __init__(self, store, settings, hasher=None, ceiling=None):
        self.store, self.settings = store, settings
        self.hasher = hasher or passwords.PasswordHasher(settings.password_scheme, settings.argon2_time_cost, settings.argon2_memory_kib, settings.argon2_parallelism)
        self._gate = threading.BoundedSemaphore(ceiling or settings.max_concurrent_hashes)
        self._dummy = None
        self._dummy_lock = threading.Lock()

    # ------------------------------------------------------------------ helpers
    def _address_hash(self, ip):
        return _digest(self.settings.attempt_salt + "|" + (ip or "unknown"))

    def _hash_password(self, password):
        if not self._gate.acquire(timeout=5):
            raise AuthFailure(503, "busy", "the server is busy; try again in a moment")
        try:
            return self.hasher.hash(password)
        finally:
            self._gate.release()

    def _check_password(self, password, stored):
        if not self._gate.acquire(timeout=5):
            raise AuthFailure(503, "busy", "the server is busy; try again in a moment")
        try:
            return self.hasher.verify(password, stored)
        finally:
            self._gate.release()

    def _dummy_hash(self):
        with self._dummy_lock:
            if self._dummy is None:
                self._dummy = self.hasher.dummy_hash()
            return self._dummy

    def _throttle(self, kind, subject, ip_hash):
        s = self.settings
        wait = self.store.throttle_check(kind, subject, ip_hash, s.limit_pair, s.limit_ip, s.limit_subject, s.limit_window_seconds)
        if wait > 0:
            raise AuthFailure(429, "rate_limited", "too many attempts; try again later", retry_after=wait)

    @staticmethod
    def _policy(check, *args):
        try:
            return check(*args)
        except passwords.PasswordError as error:
            raise AuthFailure(422, "invalid_input", str(error)) from None

    @staticmethod
    def _user(analyst_id, username, display_name, role):
        return {"analyst_id": analyst_id, "username": username, "display_name": display_name, "role": role, "permissions": permissions_for(role)}

    # ------------------------------------------------------------------ sign in
    def login(self, username, password, ip, user_agent):
        """-> {token, csrf_token, user, idle_expires_at, absolute_expires_at}. Raises AuthFailure (401 generic, 429 throttled, 503 busy); DbError when the store is down."""
        name = passwords.normalize_username(username)
        if name is None or not passwords.USERNAME_RE.fullmatch(name) or not isinstance(password, str) or not password or len(password) > MAX_LOGIN_PASSWORD:
            raise AuthFailure(401, "invalid_credentials", GENERIC_LOGIN)
        subject, ip_hash = _digest("login:" + name), self._address_hash(ip)
        self._throttle("login", subject, ip_hash)
        cred = self.store.get_credential(name)
        stored = cred["o_password_hash"] if cred else self._dummy_hash()
        matched = self._check_password(password, stored)
        if not (cred and matched and cred["o_active"]):
            self.store.record_attempt("login", subject, ip_hash, False)
            raise AuthFailure(401, "invalid_credentials", GENERIC_LOGIN)
        s = self.settings
        raw = secrets.token_urlsafe(32)
        session = self.store.create_session(cred["o_analyst_id"], token_hash(raw), s.idle_seconds, s.absolute_seconds, user_agent, s.max_sessions)
        if not session:
            self.store.record_attempt("login", subject, ip_hash, False)
            raise AuthFailure(401, "invalid_credentials", GENERIC_LOGIN)
        self.store.record_attempt("login", subject, ip_hash, True)
        try:
            if self.hasher.needs_rehash(stored):
                self.store.upgrade_hash(cred["o_analyst_id"], stored, self._hash_password(password))
        except (DbError, AuthFailure):
            pass                                  # the upgrade is an improvement, not a requirement: the person is signed in either way
        return {"token": raw, "csrf_token": csrf_token(raw), "idle_expires_at": session["o_idle_expires_at"], "absolute_expires_at": session["o_absolute_expires_at"],
                "user": self._user(cred["o_analyst_id"], name, cred["o_display_name"], cred["o_role"])}

    # ------------------------------------------------------------------ sessions
    def session(self, token):
        """The live session for a cookie value, or None (unknown, expired, revoked, account inactive). Slides the idle expiry. DbError when the store is down."""
        if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
            return None
        row = self.store.validate_session(token_hash(token), self.settings.idle_seconds)
        if not row:
            return None
        return {"session_id": row["o_session_id"], "csrf_token": csrf_token(token), "idle_expires_at": row["o_idle_expires_at"], "absolute_expires_at": row["o_absolute_expires_at"],
                "user": self._user(row["o_analyst_id"], row["o_username"], row["o_display_name"], row["o_role"])}

    def logout(self, token):
        if isinstance(token, str) and TOKEN_RE.fullmatch(token):
            self.store.revoke_session(token_hash(token))

    def change_password(self, user, token, current, new, ip):
        """The signed-in person changes their own password. Other sessions of the account end; this one stays."""
        if not isinstance(current, str) or not isinstance(new, str):
            raise AuthFailure(422, "invalid_input", "both passwords are required")
        subject, ip_hash = _digest("login:" + user["username"]), self._address_hash(ip)
        self._throttle("login", subject, ip_hash)
        cred = self.store.get_credential(user["username"])
        if not cred or not self._check_password(current, cred["o_password_hash"]):
            self.store.record_attempt("login", subject, ip_hash, False)
            raise AuthFailure(403, "invalid_credentials", "The current password is not correct.")
        self.store.record_attempt("login", subject, ip_hash, True)
        if new == current:
            raise AuthFailure(422, "invalid_input", "choose a password different from the current one")
        self._policy(passwords.check_password, new, user["username"])
        if not self.store.change_own_password(user["analyst_id"], self._hash_password(new), token_hash(token)):
            raise AuthFailure(404, "not_found", "no password account")

    # ------------------------------------------------------------------ first administrator
    def bootstrap_enabled(self):
        return self.settings.bootstrap_enabled

    def bootstrap_available(self):
        """True only while the one-time bootstrap is enabled by the environment AND no administrator with a password exists."""
        return self.settings.bootstrap_enabled and self.store.bootstrap_open()

    def bootstrap(self, secret, username, display_name, password, ip):
        """Create the first administrator. 404 when the environment does not enable it; 403 for a wrong secret (throttled, compared in constant time); 409 once an administrator exists."""
        if not self.settings.bootstrap_enabled:
            raise AuthFailure(404, "not_found", "no such route")
        ip_hash = self._address_hash(ip)
        subject = _digest("bootstrap")
        self._throttle("bootstrap", subject, ip_hash)
        if not isinstance(secret, str) or not hmac.compare_digest(_digest(secret), self.settings.bootstrap_digest):
            self.store.record_attempt("bootstrap", subject, ip_hash, False)
            raise AuthFailure(403, "bootstrap_forbidden", "the setup secret is not correct")
        if not self.store.bootstrap_open():
            raise AuthFailure(409, "already_bootstrapped", "an administrator already exists; sign in instead")
        name = self._policy(passwords.check_username, username)
        self._policy(passwords.check_password, password, name)
        outcome = self.store.bootstrap_admin(name, self._display(display_name), self._hash_password(password))
        if outcome == "already_bootstrapped":
            raise AuthFailure(409, "already_bootstrapped", "an administrator already exists; sign in instead")
        if outcome != "created":
            raise AuthFailure(422, "invalid_input", "the first administrator could not be created from these values")
        self.store.record_attempt("bootstrap", subject, ip_hash, True)
        return {"username": name, "role": "admin"}

    # ------------------------------------------------------------------ administration
    @staticmethod
    def _display(value):
        if value is None:
            return None
        if not isinstance(value, str):
            raise AuthFailure(422, "invalid_input", "display_name must be text")
        value = " ".join(value.split())
        if len(value) > DISPLAY_MAX:
            raise AuthFailure(422, "invalid_input", "display_name is at most %d characters" % DISPLAY_MAX)
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise AuthFailure(422, "invalid_input", "display_name contains a character that is not allowed")
        return value or None

    @staticmethod
    def _role(value, required):
        if value is None and not required:
            return None
        if value not in ROLES:
            raise AuthFailure(422, "invalid_input", "role must be one of: " + ", ".join(ROLES))
        return value

    @staticmethod
    def _denied(error):
        if getattr(error, "sqlstate", None) == "42501":
            return AuthFailure(403, "forbidden", "your role does not allow this")
        return error

    def list_users(self, actor):
        try:
            return self.store.list_users(actor)
        except DbError as error:
            raise self._denied(error) from None

    def create_user(self, actor, username, display_name, role, password):
        name = self._policy(passwords.check_username, username)
        role = self._role(role, True)
        display = self._display(display_name)
        self._policy(passwords.check_password, password, name)
        outcome = self.store.create_user(actor, name, display, role, self._hash_password(password))
        if outcome in ("created", "attached"):
            return {"username": name, "role": role, "status": outcome}
        raise {"exists": AuthFailure(409, "exists", "that username already has a password account"), "forbidden": AuthFailure(403, "forbidden", "your role does not allow this")}.get(
            outcome, AuthFailure(422, "invalid_input", "the account could not be created from these values"))

    def update_user(self, actor, target, role, active, display_name):
        role = self._role(role, False)
        if active is not None and not isinstance(active, bool):
            raise AuthFailure(422, "invalid_input", "active must be true or false")
        display = self._display(display_name)
        if role is None and active is None and display is None:
            raise AuthFailure(422, "invalid_input", "nothing to change: send role, active or display_name")
        outcome = self.store.update_user(actor, target, role, active, display)
        if outcome == "updated":
            return {"username": target, "status": "updated"}
        raise {"not_found": AuthFailure(404, "not_found", "no such account"), "forbidden": AuthFailure(403, "forbidden", "your role does not allow this"),
               "self_change": AuthFailure(409, "self_change", "you cannot change your own role or deactivate your own account"),
               "last_admin": AuthFailure(409, "last_admin", "this is the last active administrator; make another administrator first")}.get(
            outcome, AuthFailure(422, "invalid_input", "the account could not be changed from these values"))

    def reset_password(self, actor, target, password):
        self._policy(passwords.check_password, password, target)
        outcome = self.store.reset_password(actor, target, self._hash_password(password))
        if outcome == "reset":
            return {"username": target, "status": "reset"}
        raise {"not_found": AuthFailure(404, "not_found", "no password account with that username"), "forbidden": AuthFailure(403, "forbidden", "your role does not allow this")}.get(
            outcome, AuthFailure(422, "invalid_input", "the password could not be set"))

    def revoke_sessions(self, actor, target):
        count = self.store.revoke_sessions(actor, target)
        if count == -1:
            raise AuthFailure(403, "forbidden", "your role does not allow this")
        if count == -2:
            raise AuthFailure(404, "not_found", "no such account")
        return {"username": target, "revoked": count}
