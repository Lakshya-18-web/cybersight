-- Week 4, migration 0002: database-level guards. The rules that matter for safety live here so that no application bug can break them:
--   * evidence, verdicts, routing, decisions, executions and the audit trail are append-only;
--   * a proposed action can only go pending -> approved or pending -> rejected, once;
--   * a simulated execution can only be recorded for an approved action;
--   * the audit trail is hash-chained (tamper-evident) and refuses payloads that look like credentials.

CREATE FUNCTION soc.contains_secret_key(j jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT j::text ~* '"[^"]*(password|passwd|secret|api[_-]?key|authorization|bearer|access[_-]?token|auth[_-]?token|private[_-]?key|credential)[^"]*"\s*:'
$$;

ALTER TABLE soc.cases            ADD CONSTRAINT cases_alert_no_secrets      CHECK (NOT soc.contains_secret_key(alert));
ALTER TABLE soc.cases            ADD CONSTRAINT cases_provenance_no_secrets CHECK (NOT soc.contains_secret_key(provenance));
ALTER TABLE soc.evidence_items   ADD CONSTRAINT evidence_no_secrets         CHECK (NOT soc.contains_secret_key(payload));
ALTER TABLE soc.proposed_actions ADD CONSTRAINT actions_no_secrets          CHECK (NOT soc.contains_secret_key(parameters));
ALTER TABLE soc.executed_actions ADD CONSTRAINT executed_no_secrets         CHECK (NOT soc.contains_secret_key(result));
ALTER TABLE soc.audit_events     ADD CONSTRAINT audit_no_secrets            CHECK (NOT soc.contains_secret_key(payload));

-- ---------------------------------------------------------------- append-only tables
CREATE FUNCTION soc.forbid_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% on soc.% is not allowed: the table is append-only', TG_OP, TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END $$;

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['verdicts', 'evidence_items', 'memory_hits', 'routing_decisions', 'approval_decisions', 'executed_actions', 'audit_events']
    LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON soc.%I FOR EACH ROW EXECUTE FUNCTION soc.forbid_change()', t || '_append_only', t);
        EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON soc.%I FOR EACH STATEMENT EXECUTE FUNCTION soc.forbid_change()', t || '_no_truncate', t);
    END LOOP;
END $$;

-- cases: only status and updated_at may change, and a closed case stays closed
CREATE FUNCTION soc.guard_case_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' OR TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'a case cannot be deleted' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (NEW.case_id, NEW.idempotency_key, NEW.payload_sha256, NEW.alert_set, NEW.alert_id, NEW.run_name, NEW.graph_version, NEW.memory_mode, NEW.alert, NEW.provenance, NEW.created_at)
       IS DISTINCT FROM
       (OLD.case_id, OLD.idempotency_key, OLD.payload_sha256, OLD.alert_set, OLD.alert_id, OLD.run_name, OLD.graph_version, OLD.memory_mode, OLD.alert, OLD.provenance, OLD.created_at) THEN
        RAISE EXCEPTION 'only the status of a case may change' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (OLD.status IN ('escalated', 'needs_review') AND NEW.status = 'resolved') THEN
        RAISE EXCEPTION 'illegal case status change % -> %', OLD.status, NEW.status USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER cases_guard BEFORE UPDATE OR DELETE ON soc.cases FOR EACH ROW EXECUTE FUNCTION soc.guard_case_update();
CREATE TRIGGER cases_no_truncate BEFORE TRUNCATE ON soc.cases FOR EACH STATEMENT EXECUTE FUNCTION soc.forbid_change();

-- proposed_actions: the approval state machine. pending -> approved | rejected, once. Everything else about a proposal is immutable.
CREATE FUNCTION soc.guard_action_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'a proposed action cannot be deleted' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (NEW.action_id, NEW.case_id, NEW.action_type, NEW.target, NEW.parameters, NEW.rationale, NEW.requires_approval, NEW.proposed_by, NEW.created_at)
       IS DISTINCT FROM
       (OLD.action_id, OLD.case_id, OLD.action_type, OLD.target, OLD.parameters, OLD.rationale, OLD.requires_approval, OLD.proposed_by, OLD.created_at) THEN
        RAISE EXCEPTION 'a proposed action cannot be edited' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.state <> 'pending' THEN
        RAISE EXCEPTION 'the proposal is already % and cannot change', OLD.state USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.state NOT IN ('approved', 'rejected') THEN
        RAISE EXCEPTION 'illegal state change % -> %', OLD.state, NEW.state USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    NEW.row_version := OLD.row_version + 1;
    RETURN NEW;
END $$;
CREATE TRIGGER proposed_actions_guard BEFORE UPDATE OR DELETE ON soc.proposed_actions FOR EACH ROW EXECUTE FUNCTION soc.guard_action_update();
CREATE TRIGGER proposed_actions_no_truncate BEFORE TRUNCATE ON soc.proposed_actions FOR EACH STATEMENT EXECUTE FUNCTION soc.forbid_change();

-- a decision row must agree with the proposal it decides, and must come from an active approver or admin
CREATE FUNCTION soc.guard_decision_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a soc.proposed_actions; who soc.analysts;
BEGIN
    SELECT * INTO a FROM soc.proposed_actions WHERE action_id = NEW.action_id;
    IF NOT FOUND OR a.state <> NEW.decision OR a.decided_by IS DISTINCT FROM NEW.decided_by THEN
        RAISE EXCEPTION 'the decision does not match the proposal state' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    SELECT * INTO who FROM soc.analysts WHERE analyst_id = NEW.decided_by;
    IF NOT FOUND OR NOT who.active OR who.role NOT IN ('approver', 'admin') THEN
        RAISE EXCEPTION 'the decider is not an active approver' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER approval_decisions_guard BEFORE INSERT ON soc.approval_decisions FOR EACH ROW EXECUTE FUNCTION soc.guard_decision_insert();

-- a simulated execution can only be recorded for an approved proposal that has its approval decision on file. Pending and rejected proposals can never have one.
CREATE FUNCTION soc.guard_execution_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE s text;
BEGIN
    SELECT state INTO s FROM soc.proposed_actions WHERE action_id = NEW.action_id;
    -- the state alone is not trusted: an approval decision row, written by decide_action, must exist as well
    IF s IS DISTINCT FROM 'approved' OR NOT EXISTS (SELECT 1 FROM soc.approval_decisions WHERE action_id = NEW.action_id AND decision = 'approved') THEN
        RAISE EXCEPTION 'an action in state % cannot be executed (only approved actions can be, and only as a simulation)', coalesce(s, 'unknown') USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER executed_actions_guard BEFORE INSERT ON soc.executed_actions FOR EACH ROW EXECUTE FUNCTION soc.guard_execution_insert();

-- ---------------------------------------------------------------- audit hash chain
-- The chain is built under a global advisory lock, taken before the event id is assigned, so two concurrent writers extend one chain in one order.
CREATE FUNCTION soc.audit_chain_hash(prev text, id bigint, at timestamptz, actor text, kind text, etype text, eid text, cid uuid, payload jsonb) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
    SELECT encode(sha256(convert_to(jsonb_build_array(prev, id, at::text, actor, kind, etype, eid, cid, payload)::text, 'UTF8')), 'hex')
$$;

CREATE FUNCTION soc.audit_before_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE last_hash text;
BEGIN
    PERFORM pg_advisory_xact_lock(7403001);
    SELECT event_hash INTO last_hash FROM soc.audit_events ORDER BY event_id DESC LIMIT 1;
    NEW.event_id := nextval('soc.audit_events_seq');
    NEW.prev_hash := coalesce(last_hash, 'GENESIS');
    NEW.event_hash := soc.audit_chain_hash(NEW.prev_hash, NEW.event_id, NEW.occurred_at, NEW.actor, NEW.event_type, NEW.entity_type, NEW.entity_id, NEW.case_id, NEW.payload);
    RETURN NEW;
END $$;
CREATE TRIGGER audit_events_chain BEFORE INSERT ON soc.audit_events FOR EACH ROW EXECUTE FUNCTION soc.audit_before_insert();

-- Recomputes the whole chain. Returns (true, null) when intact, else (false, first event id whose hash or link is wrong).
CREATE FUNCTION soc.verify_audit_chain() RETURNS TABLE (ok boolean, first_bad_event_id bigint) LANGUAGE plpgsql STABLE AS $$
DECLARE r record; expected_prev text := 'GENESIS';
BEGIN
    FOR r IN SELECT * FROM soc.audit_events ORDER BY event_id LOOP
        IF r.prev_hash <> expected_prev
           OR r.event_hash <> soc.audit_chain_hash(r.prev_hash, r.event_id, r.occurred_at, r.actor, r.event_type, r.entity_type, r.entity_id, r.case_id, r.payload) THEN
            ok := false; first_bad_event_id := r.event_id; RETURN NEXT; RETURN;
        END IF;
        expected_prev := r.event_hash;
    END LOOP;
    ok := true; first_bad_event_id := NULL; RETURN NEXT;
END $$;
