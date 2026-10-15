-- Week 4, migration 0004: least-privilege access and read views.
-- soc_api is a NOLOGIN group role. Give it to the login role the API uses:   GRANT soc_api TO <your_api_login_role>;
-- It can read, and it can write only by calling the SECURITY DEFINER functions of migration 0003. A direct INSERT/UPDATE/DELETE is refused by the database.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'soc_api') THEN
        CREATE ROLE soc_api NOLOGIN;
    END IF;
END $$;

CREATE VIEW soc.pending_approvals AS
    SELECT a.action_id, a.case_id, a.action_type, a.target, a.parameters, a.rationale, a.created_at, a.proposed_by,
           c.alert_id, c.alert_set, c.run_name, c.memory_mode, c.status AS case_status,
           v.status AS verdict_status, v.attack_type, v.severity, r.risk_level, r.decision AS routing_decision
    FROM soc.proposed_actions a
    JOIN soc.cases c USING (case_id)
    LEFT JOIN soc.verdicts v USING (case_id)
    LEFT JOIN soc.routing_decisions r USING (case_id)
    WHERE a.state = 'pending';

REVOKE ALL ON SCHEMA soc FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA soc FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA soc FROM PUBLIC;
GRANT USAGE ON SCHEMA soc TO soc_api;
GRANT SELECT ON ALL TABLES IN SCHEMA soc TO soc_api;
GRANT EXECUTE ON FUNCTION soc.ingest_case(jsonb), soc.decide_action(uuid, text, text, text, text), soc.simulate_execution(uuid, text), soc.verify_audit_chain() TO soc_api;
