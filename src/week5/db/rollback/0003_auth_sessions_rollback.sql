-- Rollback of Week 5 migration 0003 (username + password sign-in). Run as the database OWNER (the role that ran the migrations), for example:
--   psql "$OWNER_DATABASE_URL" -v ON_ERROR_STOP=1 -f src/week5/db/rollback/0003_auth_sessions_rollback.sql
-- It removes the three auth tables (credentials, sessions, attempts) and the auth functions, then forgets the migration so it can be applied again.
-- It does NOT touch soc.analysts, the audit log, or any Week 4 / Week 5 0001-0002 object. Accounts created through the web console stay in soc.analysts (roles, display names);
-- only their passwords and sessions are deleted. After a rollback, set WEEK5_WEB_AUTH=0 (or redeploy the previous API version) so the API stops calling the removed functions.
-- DESTRUCTIVE: every password hash and session is lost. Take a backup first if you may want them again. Audit rows written by the auth functions remain (the audit log is append-only).
BEGIN;
DROP FUNCTION IF EXISTS soc.auth_admin_revoke_sessions(text, text), soc.auth_admin_reset_password(text, text, text), soc.auth_admin_update_user(text, text, text, boolean, text),
    soc.auth_admin_create_user(text, text, text, text, text), soc.auth_admin_list_users(text), soc.auth_is_admin(text), soc.auth_bootstrap_admin(text, text, text),
    soc.auth_bootstrap_open(), soc.auth_change_own_password(text, text, text), soc.auth_revoke_session(text), soc.auth_validate_session(text, integer),
    soc.auth_create_session(text, text, integer, integer, text, integer), soc.auth_upgrade_hash(text, text, text), soc.auth_get_credential(text),
    soc.auth_record_attempt(text, text, text, boolean), soc.auth_throttle_check(text, text, text, integer, integer, integer, integer);
DROP TABLE IF EXISTS soc.auth_attempts, soc.web_sessions, soc.auth_credentials;
DELETE FROM soc.schema_migrations_week5 WHERE version = '0003';
COMMIT;
