"""The sign-in routes (Week 5). Roles here: None = public, "session" = any signed-in person, "admin" = signed-in administrator. Appended to ROUTES5 by week5.api.routes5."""

AUTH_ROUTES_SPEC = [
    ("POST", "/auth/login", "auth_login", None, "Sign in with a username and password. Sets the session cookie (HttpOnly) and returns the user and the CSRF token."),
    ("POST", "/auth/logout", "auth_logout", None, "End the current session on the server and clear the cookie. Safe to call when not signed in."),
    ("GET", "/auth/session", "auth_session", "session", "The current session: user, role, permissions, expiry and the CSRF token. Used to restore a session after a page reload."),
    ("GET", "/auth/status", "auth_status", None, "Whether web sign-in is on and whether first-time setup (creating the first administrator) is open."),
    ("POST", "/auth/bootstrap", "auth_bootstrap", None, "Create the first administrator. Needs the one-time setup secret from the server's environment; works only while no administrator exists."),
    ("POST", "/auth/change-password", "auth_change_password", "session", "Change your own password (needs the current one). Your other sessions end."),
    ("GET", "/auth/users", "auth_users", "admin", "List accounts: role, active, last sign-in, number of live sessions. Never returns a password hash. Administrators only."),
    ("POST", "/auth/users", "auth_create_user", "admin", "Create an account with an initial password. Administrators only."),
    ("PATCH", "/auth/users/{username}", "auth_update_user", "admin", "Change an account's role, active state or display name. Deactivating ends its sessions. Administrators only."),
    ("POST", "/auth/users/{username}/reset-password", "auth_reset_password", "admin", "Set a new password for an account and end all its sessions. Administrators only."),
    ("POST", "/auth/users/{username}/revoke-sessions", "auth_revoke_sessions", "admin", "End every session of an account. Administrators only."),
]
AUTH_NAMES = frozenset(spec[2] for spec in AUTH_ROUTES_SPEC)


def build(Route):
    return [Route(method, path, name, role, summary, []) for method, path, name, role, summary in AUTH_ROUTES_SPEC]
