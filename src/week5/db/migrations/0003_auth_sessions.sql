-- Week 5, migration 0003: username + password sign-in with server-side sessions.
-- Tracked in soc.schema_migrations_week5 (Week 4 migrations 0001-0004 and Week 5 0001-0002 must already be applied; none of them is edited).
--
-- What this adds
--   soc.auth_credentials  one row per account that may sign in with a password (the password HASH only: Argon2id or scrypt, self-describing, salted per password)
--   soc.web_sessions      server-side sessions; only the SHA-256 of the random session token is stored, never the token
--   soc.auth_attempts     persistent sign-in attempt log (hashed subject, hashed address) behind the rate limit
--   soc.auth_* functions  the ONLY write path. SECURITY DEFINER, owner = the migration role, fixed search_path, EXECUTE revoked from PUBLIC and granted to soc_api alone.
-- The API login role (soc_api) gets NO privilege on the three tables: it cannot read a hash or a session row, it can only call the functions below.
-- Accounts reuse soc.analysts (role, active, display name), so every existing role check, approval rule and audit entry keeps working unchanged.
-- Failed sign-ins are NOT written to the hash-chained audit log (it serialises writers behind one lock; an attacker could use that to slow the whole API). Successful sign-ins, account
-- changes and the bootstrap are audited. Audit payloads never contain a hash, a token or a password.
-- Rollback: src/week5/db/rollback/0003_auth_sessions_rollback.sql.

-- ---------------------------------------------------------------- tables
CREATE TABLE soc.auth_credentials (
    analyst_id          text PRIMARY KEY REFERENCES soc.analysts (analyst_id),
    username            text NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9][a-z0-9_.-]{2,31}$'),
    password_hash       text NOT NULL CHECK (password_hash ~ '^\$(argon2id|scrypt)\$' AND length(password_hash) BETWEEN 40 AND 400),
    password_changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_login_at       timestamptz,
    created_by          text NOT NULL CHECK (length(created_by) BETWEEN 1 AND 200),
    created_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (username = analyst_id)
);

CREATE TABLE soc.web_sessions (
    session_id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash          text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    analyst_id          text NOT NULL REFERENCES soc.analysts (analyst_id),
    created_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_seen_at        timestamptz NOT NULL DEFAULT clock_timestamp(),
    idle_expires_at     timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at          timestamptz,
    revoked_reason      text CHECK (revoked_reason IN ('logout', 'limit', 'deactivated', 'password_changed', 'password_reset', 'admin_revoked')),
    user_agent          text CHECK (user_agent IS NULL OR length(user_agent) <= 200),
    CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL)),
    CHECK (idle_expires_at > created_at AND absolute_expires_at > created_at AND idle_expires_at <= absolute_expires_at)
);
CREATE INDEX web_sessions_analyst_idx ON soc.web_sessions (analyst_id, created_at DESC) WHERE revoked_at IS NULL;
CREATE INDEX web_sessions_expiry_idx ON soc.web_sessions (absolute_expires_at);

CREATE TABLE soc.auth_attempts (
    attempt_id   bigserial PRIMARY KEY,
    kind         text NOT NULL CHECK (kind IN ('login', 'bootstrap')),
    subject_hash text NOT NULL CHECK (subject_hash ~ '^[0-9a-f]{64}$'),
    ip_hash      text NOT NULL CHECK (ip_hash ~ '^[0-9a-f]{64}$'),
    success      boolean NOT NULL,
    attempted_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX auth_attempts_pair_idx ON soc.auth_attempts (kind, subject_hash, ip_hash, attempted_at DESC);
CREATE INDEX auth_attempts_ip_idx ON soc.auth_attempts (kind, ip_hash, attempted_at DESC);
CREATE INDEX auth_attempts_subject_idx ON soc.auth_attempts (kind, subject_hash, attempted_at DESC);
CREATE INDEX auth_attempts_time_idx ON soc.auth_attempts (attempted_at);

REVOKE ALL ON TABLE soc.auth_credentials, soc.web_sessions, soc.auth_attempts FROM PUBLIC;
REVOKE ALL ON TABLE soc.auth_credentials, soc.web_sessions, soc.auth_attempts FROM soc_api;
REVOKE ALL ON SEQUENCE soc.auth_attempts_attempt_id_seq FROM PUBLIC;

-- ---------------------------------------------------------------- rate limit
-- Three independent limits over the failures in the last p_window seconds. Returns the number of seconds to wait (0 = go ahead).
--   pair     failures of THIS username from THIS address (cleared by a successful sign-in from that pair)
--   ip       failures from this address against any username (password spraying)
--   subject  failures against this username from any address; skipped for an address that signed in successfully in the last 30 days, so a person on their usual
--            network is not locked out of their own account by someone elsewhere guessing (no trivial lock-out of a user, no permanent lock-out of anyone: everything expires).
-- A request that is refused here is recorded nowhere, so repeating it can never lengthen a block.
CREATE FUNCTION soc.auth_throttle_check(p_kind text, p_subject text, p_ip text, p_pair_limit integer, p_ip_limit integer, p_subject_limit integer, p_window integer) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE
    now_ timestamptz := clock_timestamp();
    wait_ integer := 0;
    cutoff timestamptz := now_ - make_interval(secs => p_window);
    nth timestamptz;
    known boolean;
BEGIN
    IF p_pair_limit > 0 THEN
        SELECT attempted_at INTO nth FROM soc.auth_attempts
         WHERE kind = p_kind AND subject_hash = p_subject AND ip_hash = p_ip AND NOT success AND attempted_at > cutoff
         ORDER BY attempted_at DESC OFFSET p_pair_limit - 1 LIMIT 1;
        IF FOUND THEN wait_ := greatest(wait_, ceil(extract(epoch FROM nth + make_interval(secs => p_window) - now_))::integer); END IF;
    END IF;
    IF p_ip_limit > 0 THEN
        SELECT attempted_at INTO nth FROM soc.auth_attempts
         WHERE kind = p_kind AND ip_hash = p_ip AND NOT success AND attempted_at > cutoff
         ORDER BY attempted_at DESC OFFSET p_ip_limit - 1 LIMIT 1;
        IF FOUND THEN wait_ := greatest(wait_, ceil(extract(epoch FROM nth + make_interval(secs => p_window) - now_))::integer); END IF;
    END IF;
    IF p_subject_limit > 0 THEN
        SELECT EXISTS (SELECT 1 FROM soc.auth_attempts WHERE kind = p_kind AND subject_hash = p_subject AND ip_hash = p_ip AND success AND attempted_at > now_ - interval '30 days') INTO known;
        IF NOT known THEN
            SELECT attempted_at INTO nth FROM soc.auth_attempts
             WHERE kind = p_kind AND subject_hash = p_subject AND NOT success AND attempted_at > cutoff
             ORDER BY attempted_at DESC OFFSET p_subject_limit - 1 LIMIT 1;
            IF FOUND THEN wait_ := greatest(wait_, ceil(extract(epoch FROM nth + make_interval(secs => p_window) - now_))::integer); END IF;
        END IF;
    END IF;
    RETURN greatest(wait_, 0);
END $$;

CREATE FUNCTION soc.auth_record_attempt(p_kind text, p_subject text, p_ip text, p_success boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
BEGIN
    IF p_success THEN
        DELETE FROM soc.auth_attempts WHERE kind = p_kind AND subject_hash = p_subject AND ip_hash = p_ip AND NOT success;
    END IF;
    INSERT INTO soc.auth_attempts (kind, subject_hash, ip_hash, success) VALUES (p_kind, p_subject, p_ip, p_success);
    IF random() < 0.02 THEN
        DELETE FROM soc.auth_attempts WHERE attempted_at < clock_timestamp() - interval '30 days';
        DELETE FROM soc.auth_attempts WHERE NOT success AND attempted_at < clock_timestamp() - interval '2 days';
    END IF;
END $$;

-- ---------------------------------------------------------------- sign in and sessions
CREATE FUNCTION soc.auth_get_credential(p_username text) RETURNS TABLE (o_analyst_id text, o_password_hash text, o_display_name text, o_role text, o_active boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = soc, pg_temp AS $$
    SELECT a.analyst_id, c.password_hash, a.display_name, a.role, a.active
    FROM soc.auth_credentials c JOIN soc.analysts a USING (analyst_id)
    WHERE c.username = p_username
$$;

-- Replace a hash with a stronger one after a successful sign-in; only if the stored hash is still the one that was verified (compare and set).
CREATE FUNCTION soc.auth_upgrade_hash(p_analyst text, p_old text, p_new text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
BEGIN
    IF p_new !~ '^\$(argon2id|scrypt)\$' THEN RETURN false; END IF;
    UPDATE soc.auth_credentials SET password_hash = p_new, updated_at = clock_timestamp() WHERE analyst_id = p_analyst AND password_hash = p_old;
    RETURN FOUND;
END $$;

CREATE FUNCTION soc.auth_create_session(p_analyst text, p_token_hash text, p_idle integer, p_abs integer, p_ua text, p_max integer)
RETURNS TABLE (o_session_id uuid, o_idle_expires_at timestamptz, o_absolute_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE
    now_ timestamptz := clock_timestamp();
    sid uuid;
BEGIN
    IF p_idle < 60 OR p_abs < p_idle OR p_max < 1 THEN RAISE EXCEPTION 'invalid session limits' USING ERRCODE = 'invalid_parameter_value'; END IF;
    IF NOT EXISTS (SELECT 1 FROM soc.analysts a JOIN soc.auth_credentials c USING (analyst_id) WHERE a.analyst_id = p_analyst AND a.active) THEN RETURN; END IF;
    INSERT INTO soc.web_sessions (token_hash, analyst_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at, user_agent)
    VALUES (p_token_hash, p_analyst, now_, now_, now_ + make_interval(secs => p_idle), now_ + make_interval(secs => p_abs), left(p_ua, 200))
    RETURNING session_id INTO sid;
    UPDATE soc.web_sessions SET revoked_at = now_, revoked_reason = 'limit'
     WHERE session_id IN (SELECT session_id FROM soc.web_sessions
                           WHERE analyst_id = p_analyst AND revoked_at IS NULL AND idle_expires_at > now_ AND absolute_expires_at > now_
                           ORDER BY created_at DESC OFFSET p_max);
    UPDATE soc.auth_credentials SET last_login_at = now_ WHERE analyst_id = p_analyst;
    IF random() < 0.05 THEN
        DELETE FROM soc.web_sessions WHERE absolute_expires_at < now_ - interval '30 days' OR (revoked_at IS NOT NULL AND revoked_at < now_ - interval '30 days');
    END IF;
    PERFORM soc.audit(p_analyst, 'login_succeeded', 'session', sid::text, NULL, jsonb_build_object('method', 'password'));
    RETURN QUERY SELECT s.session_id, s.idle_expires_at, s.absolute_expires_at FROM soc.web_sessions s WHERE s.session_id = sid;
END $$;

-- The live session for a token hash, or no row: unknown, revoked, idle-expired, absolutely expired, or the account is inactive. The idle window slides, but it is written at most
-- every 30 seconds so reads stay cheap, and it can never pass the absolute expiry.
CREATE FUNCTION soc.auth_validate_session(p_token_hash text, p_idle integer)
RETURNS TABLE (o_session_id uuid, o_analyst_id text, o_username text, o_display_name text, o_role text, o_idle_expires_at timestamptz, o_absolute_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE
    now_ timestamptz := clock_timestamp();
    s soc.web_sessions;
    a soc.analysts;
BEGIN
    SELECT * INTO s FROM soc.web_sessions WHERE token_hash = p_token_hash;
    IF NOT FOUND OR s.revoked_at IS NOT NULL OR s.idle_expires_at <= now_ OR s.absolute_expires_at <= now_ THEN RETURN; END IF;
    SELECT * INTO a FROM soc.analysts WHERE analyst_id = s.analyst_id;
    IF NOT FOUND OR NOT a.active THEN RETURN; END IF;
    IF s.last_seen_at < now_ - interval '30 seconds' THEN
        UPDATE soc.web_sessions SET last_seen_at = now_, idle_expires_at = least(now_ + make_interval(secs => p_idle), s.absolute_expires_at)
         WHERE session_id = s.session_id RETURNING idle_expires_at INTO s.idle_expires_at;
    END IF;
    RETURN QUERY SELECT s.session_id, a.analyst_id, a.analyst_id, a.display_name, a.role, s.idle_expires_at, s.absolute_expires_at;
END $$;

CREATE FUNCTION soc.auth_revoke_session(p_token_hash text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE s soc.web_sessions;
BEGIN
    UPDATE soc.web_sessions SET revoked_at = clock_timestamp(), revoked_reason = 'logout' WHERE token_hash = p_token_hash AND revoked_at IS NULL RETURNING * INTO s;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM soc.audit(s.analyst_id, 'logout', 'session', s.session_id::text, NULL, '{}'::jsonb);
    RETURN true;
END $$;

-- The caller has already verified the current password. Every other session of the account is revoked; the one making the change (p_keep) stays.
CREATE FUNCTION soc.auth_change_own_password(p_analyst text, p_new_hash text, p_keep text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE n integer;
BEGIN
    IF p_new_hash !~ '^\$(argon2id|scrypt)\$' THEN RETURN false; END IF;
    UPDATE soc.auth_credentials SET password_hash = p_new_hash, password_changed_at = clock_timestamp(), updated_at = clock_timestamp() WHERE analyst_id = p_analyst;
    IF NOT FOUND THEN RETURN false; END IF;
    UPDATE soc.web_sessions SET revoked_at = clock_timestamp(), revoked_reason = 'password_changed'
     WHERE analyst_id = p_analyst AND revoked_at IS NULL AND token_hash <> coalesce(p_keep, '');
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM soc.audit(p_analyst, 'password_changed', 'account', p_analyst, NULL, jsonb_build_object('sessions_revoked', n));
    RETURN true;
END $$;

-- ---------------------------------------------------------------- first administrator
-- Open only while no ACTIVE admin has a password. The caller (the API) has already checked the one-time bootstrap secret; this function is the race-safe, atomic part:
-- a transaction-level advisory lock serialises concurrent attempts, so exactly one can create the administrator. Afterwards it always answers already_bootstrapped.
CREATE FUNCTION soc.auth_bootstrap_open() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = soc, pg_temp AS $$
    SELECT NOT EXISTS (SELECT 1 FROM soc.analysts a JOIN soc.auth_credentials c USING (analyst_id) WHERE a.role = 'admin' AND a.active)
$$;

CREATE FUNCTION soc.auth_bootstrap_admin(p_username text, p_display text, p_hash text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(7403006);
    IF NOT soc.auth_bootstrap_open() THEN RETURN 'already_bootstrapped'; END IF;
    IF p_username !~ '^[a-z0-9][a-z0-9_.-]{2,31}$' OR p_hash !~ '^\$(argon2id|scrypt)\$' THEN RETURN 'invalid'; END IF;
    INSERT INTO soc.analysts (analyst_id, display_name, role, active) VALUES (p_username, p_display, 'admin', true)
    ON CONFLICT (analyst_id) DO UPDATE SET role = 'admin', active = true, display_name = coalesce(excluded.display_name, soc.analysts.display_name);
    INSERT INTO soc.auth_credentials (analyst_id, username, password_hash, created_by) VALUES (p_username, p_username, p_hash, 'system:bootstrap')
    ON CONFLICT (analyst_id) DO UPDATE SET password_hash = excluded.password_hash, password_changed_at = clock_timestamp(), updated_at = clock_timestamp();
    PERFORM soc.audit('system:bootstrap', 'bootstrap_admin_created', 'account', p_username, NULL, jsonb_build_object('role', 'admin'));
    RETURN 'created';
END $$;

-- ---------------------------------------------------------------- administration (every function re-checks that the caller is an active admin with a password)
CREATE FUNCTION soc.auth_is_admin(p_actor text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = soc, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM soc.analysts a JOIN soc.auth_credentials c USING (analyst_id) WHERE a.analyst_id = p_actor AND a.role = 'admin' AND a.active)
$$;

CREATE FUNCTION soc.auth_admin_list_users(p_actor text)
RETURNS TABLE (o_analyst_id text, o_username text, o_display_name text, o_role text, o_active boolean, o_has_password boolean, o_last_login_at timestamptz, o_created_at timestamptz, o_active_sessions integer)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = soc, pg_temp AS $$
BEGIN
    IF NOT soc.auth_is_admin(p_actor) THEN RAISE EXCEPTION 'administrator required' USING ERRCODE = 'insufficient_privilege'; END IF;
    RETURN QUERY
    SELECT a.analyst_id, c.username, a.display_name, a.role, a.active, c.analyst_id IS NOT NULL, c.last_login_at, a.created_at,
           (SELECT count(*)::integer FROM soc.web_sessions s WHERE s.analyst_id = a.analyst_id AND s.revoked_at IS NULL AND s.idle_expires_at > clock_timestamp() AND s.absolute_expires_at > clock_timestamp())
    FROM soc.analysts a LEFT JOIN soc.auth_credentials c USING (analyst_id)
    ORDER BY a.analyst_id;
END $$;

-- -> created | attached (an existing analyst without a password now has one) | exists | forbidden | invalid
CREATE FUNCTION soc.auth_admin_create_user(p_actor text, p_username text, p_display text, p_role text, p_hash text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE had boolean;
BEGIN
    PERFORM pg_advisory_xact_lock(7403006);
    IF NOT soc.auth_is_admin(p_actor) THEN RETURN 'forbidden'; END IF;
    IF p_username !~ '^[a-z0-9][a-z0-9_.-]{2,31}$' OR p_role NOT IN ('viewer', 'analyst', 'approver', 'admin') OR p_hash !~ '^\$(argon2id|scrypt)\$' THEN RETURN 'invalid'; END IF;
    IF EXISTS (SELECT 1 FROM soc.auth_credentials WHERE analyst_id = p_username) THEN RETURN 'exists'; END IF;
    SELECT EXISTS (SELECT 1 FROM soc.analysts WHERE analyst_id = p_username) INTO had;
    INSERT INTO soc.analysts (analyst_id, display_name, role, active) VALUES (p_username, p_display, p_role, true)
    ON CONFLICT (analyst_id) DO UPDATE SET role = excluded.role, active = true, display_name = coalesce(excluded.display_name, soc.analysts.display_name);
    INSERT INTO soc.auth_credentials (analyst_id, username, password_hash, created_by) VALUES (p_username, p_username, p_hash, p_actor);
    PERFORM soc.audit(p_actor, 'account_created', 'account', p_username, NULL, jsonb_build_object('role', p_role, 'attached_to_existing', had));
    RETURN CASE WHEN had THEN 'attached' ELSE 'created' END;
END $$;

-- p_role / p_active / p_display: NULL = leave as is. -> updated | not_found | forbidden | invalid | self_change | last_admin
-- An administrator cannot change their own role or deactivate themselves, and the last active administrator cannot be demoted or deactivated by anyone.
-- Deactivating an account revokes all of its sessions at once.
CREATE FUNCTION soc.auth_admin_update_user(p_actor text, p_target text, p_role text, p_active boolean, p_display text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE t soc.analysts; others integer; losing boolean;
BEGIN
    PERFORM pg_advisory_xact_lock(7403006);
    IF NOT soc.auth_is_admin(p_actor) THEN RETURN 'forbidden'; END IF;
    IF p_role IS NOT NULL AND p_role NOT IN ('viewer', 'analyst', 'approver', 'admin') THEN RETURN 'invalid'; END IF;
    IF p_display IS NOT NULL AND length(p_display) > 100 THEN RETURN 'invalid'; END IF;
    SELECT * INTO t FROM soc.analysts WHERE analyst_id = p_target FOR UPDATE;
    IF NOT FOUND THEN RETURN 'not_found'; END IF;
    IF p_target = p_actor AND ((p_role IS NOT NULL AND p_role <> t.role) OR p_active IS FALSE) THEN RETURN 'self_change'; END IF;
    losing := t.role = 'admin' AND t.active AND ((p_role IS NOT NULL AND p_role <> 'admin') OR p_active IS FALSE);
    IF losing THEN
        SELECT count(*) INTO others FROM soc.analysts a JOIN soc.auth_credentials c USING (analyst_id) WHERE a.role = 'admin' AND a.active AND a.analyst_id <> p_target;
        IF others = 0 THEN RETURN 'last_admin'; END IF;
    END IF;
    UPDATE soc.analysts SET role = coalesce(p_role, role), active = coalesce(p_active, active), display_name = coalesce(p_display, display_name) WHERE analyst_id = p_target;
    IF p_active IS FALSE THEN
        UPDATE soc.web_sessions SET revoked_at = clock_timestamp(), revoked_reason = 'deactivated' WHERE analyst_id = p_target AND revoked_at IS NULL;
    END IF;
    PERFORM soc.audit(p_actor, 'account_updated', 'account', p_target, NULL, jsonb_build_object('role', p_role, 'active', p_active, 'display_changed', p_display IS NOT NULL));
    RETURN 'updated';
END $$;

-- -> reset | not_found (no password account) | forbidden | invalid. All sessions of the account are revoked.
CREATE FUNCTION soc.auth_admin_reset_password(p_actor text, p_target text, p_hash text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(7403006);
    IF NOT soc.auth_is_admin(p_actor) THEN RETURN 'forbidden'; END IF;
    IF p_hash !~ '^\$(argon2id|scrypt)\$' THEN RETURN 'invalid'; END IF;
    UPDATE soc.auth_credentials SET password_hash = p_hash, password_changed_at = clock_timestamp(), updated_at = clock_timestamp() WHERE analyst_id = p_target;
    IF NOT FOUND THEN RETURN 'not_found'; END IF;
    UPDATE soc.web_sessions SET revoked_at = clock_timestamp(), revoked_reason = 'password_reset' WHERE analyst_id = p_target AND revoked_at IS NULL;
    PERFORM soc.audit(p_actor, 'password_reset', 'account', p_target, NULL, '{}'::jsonb);
    RETURN 'reset';
END $$;

-- -> number of sessions revoked | -1 forbidden | -2 not_found
CREATE FUNCTION soc.auth_admin_revoke_sessions(p_actor text, p_target text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE n integer;
BEGIN
    IF NOT soc.auth_is_admin(p_actor) THEN RETURN -1; END IF;
    IF NOT EXISTS (SELECT 1 FROM soc.analysts WHERE analyst_id = p_target) THEN RETURN -2; END IF;
    UPDATE soc.web_sessions SET revoked_at = clock_timestamp(), revoked_reason = 'admin_revoked' WHERE analyst_id = p_target AND revoked_at IS NULL;
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM soc.audit(p_actor, 'sessions_revoked', 'account', p_target, NULL, jsonb_build_object('count', n));
    RETURN n;
END $$;

-- ---------------------------------------------------------------- privileges: the API login can only EXECUTE these
REVOKE ALL ON FUNCTION
    soc.auth_throttle_check(text, text, text, integer, integer, integer, integer), soc.auth_record_attempt(text, text, text, boolean), soc.auth_get_credential(text),
    soc.auth_upgrade_hash(text, text, text), soc.auth_create_session(text, text, integer, integer, text, integer), soc.auth_validate_session(text, integer),
    soc.auth_revoke_session(text), soc.auth_change_own_password(text, text, text), soc.auth_bootstrap_open(), soc.auth_bootstrap_admin(text, text, text),
    soc.auth_is_admin(text), soc.auth_admin_list_users(text), soc.auth_admin_create_user(text, text, text, text, text), soc.auth_admin_update_user(text, text, text, boolean, text),
    soc.auth_admin_reset_password(text, text, text), soc.auth_admin_revoke_sessions(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    soc.auth_throttle_check(text, text, text, integer, integer, integer, integer), soc.auth_record_attempt(text, text, text, boolean), soc.auth_get_credential(text),
    soc.auth_upgrade_hash(text, text, text), soc.auth_create_session(text, text, integer, integer, text, integer), soc.auth_validate_session(text, integer),
    soc.auth_revoke_session(text), soc.auth_change_own_password(text, text, text), soc.auth_bootstrap_open(), soc.auth_bootstrap_admin(text, text, text),
    soc.auth_is_admin(text), soc.auth_admin_list_users(text), soc.auth_admin_create_user(text, text, text, text, text), soc.auth_admin_update_user(text, text, text, boolean, text),
    soc.auth_admin_reset_password(text, text, text), soc.auth_admin_revoke_sessions(text, text) TO soc_api;
