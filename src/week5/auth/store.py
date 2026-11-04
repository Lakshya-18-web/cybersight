"""PostgreSQL access for sign-in: one method per SECURITY DEFINER function of migration 0003 and nothing else. There is no table access here and no SQL assembled from user input: every value is a
bound parameter (%s). Results come back as plain dicts (column names as the functions declare them: o_*). DbError propagates; callers must not put its text in a response."""


def _rows(driver, call, params):
    """Run `SELECT * FROM <function call>` and return its rows as a list of dicts."""
    value = driver.query_json("SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM " + call + " AS t", params)
    return value or []


def _one(driver, call, params):
    rows = _rows(driver, call, params)
    return rows[0] if rows else None


def _scalar(driver, call, params):
    return driver.query_json("SELECT to_jsonb(" + call + ")", params)


class PgAuthStore:
    def __init__(self, driver):
        self.driver = driver

    # ------------------------------------------------------------------ rate limit
    def throttle_check(self, kind, subject_hash, ip_hash, pair_limit, ip_limit, subject_limit, window):
        return int(_scalar(self.driver, "soc.auth_throttle_check(%s, %s, %s, %s, %s, %s, %s)", (kind, subject_hash, ip_hash, pair_limit, ip_limit, subject_limit, window)) or 0)

    def record_attempt(self, kind, subject_hash, ip_hash, success):
        self.driver.query("SELECT soc.auth_record_attempt(%s, %s, %s, %s)", (kind, subject_hash, ip_hash, bool(success)))

    # ------------------------------------------------------------------ sign in, sessions
    def get_credential(self, username):
        return _one(self.driver, "soc.auth_get_credential(%s)", (username,))

    def upgrade_hash(self, analyst_id, old_hash, new_hash):
        return bool(_scalar(self.driver, "soc.auth_upgrade_hash(%s, %s, %s)", (analyst_id, old_hash, new_hash)))

    def create_session(self, analyst_id, token_hash, idle, absolute, user_agent, max_sessions):
        return _one(self.driver, "soc.auth_create_session(%s, %s, %s, %s, %s, %s)", (analyst_id, token_hash, idle, absolute, user_agent or None, max_sessions))

    def validate_session(self, token_hash, idle):
        return _one(self.driver, "soc.auth_validate_session(%s, %s)", (token_hash, idle))

    def revoke_session(self, token_hash):
        return bool(_scalar(self.driver, "soc.auth_revoke_session(%s)", (token_hash,)))

    def change_own_password(self, analyst_id, new_hash, keep_token_hash):
        return bool(_scalar(self.driver, "soc.auth_change_own_password(%s, %s, %s)", (analyst_id, new_hash, keep_token_hash)))

    # ------------------------------------------------------------------ bootstrap and administration
    def bootstrap_open(self):
        return bool(_scalar(self.driver, "soc.auth_bootstrap_open()", ()))

    def bootstrap_admin(self, username, display_name, password_hash):
        return _scalar(self.driver, "soc.auth_bootstrap_admin(%s, %s, %s)", (username, display_name, password_hash))

    def list_users(self, actor):
        return _rows(self.driver, "soc.auth_admin_list_users(%s)", (actor,))

    def create_user(self, actor, username, display_name, role, password_hash):
        return _scalar(self.driver, "soc.auth_admin_create_user(%s, %s, %s, %s, %s)", (actor, username, display_name, role, password_hash))

    def update_user(self, actor, target, role, active, display_name):
        return _scalar(self.driver, "soc.auth_admin_update_user(%s, %s, %s, %s, %s)", (actor, target, role, active, display_name))

    def reset_password(self, actor, target, password_hash):
        return _scalar(self.driver, "soc.auth_admin_reset_password(%s, %s, %s)", (actor, target, password_hash))

    def revoke_sessions(self, actor, target):
        return int(_scalar(self.driver, "soc.auth_admin_revoke_sessions(%s, %s)", (actor, target)))
