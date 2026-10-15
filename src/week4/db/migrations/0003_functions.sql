-- Week 4, migration 0003: the only write paths used by the application. Each function is one transaction, so a case and everything under it
-- is stored all-or-nothing, and a decision is checked and applied under a row lock.
-- Expected business outcomes (duplicate, conflict, unauthorized ...) are RETURNED, not raised, so the audit event that records the attempt is committed with it.
-- SECURITY DEFINER + a fixed search_path: the API role (migration 0004) can call these but cannot write the tables directly.

CREATE FUNCTION soc.audit(p_actor text, p_type text, p_entity_type text, p_entity_id text, p_case uuid, p_payload jsonb) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
    INSERT INTO soc.audit_events (actor, event_type, entity_type, entity_id, case_id, payload, prev_hash, event_hash)
    VALUES (coalesce(p_actor, 'unknown'), p_type, p_entity_type, p_entity_id, p_case, coalesce(p_payload, '{}'::jsonb), '', '')
$$;

-- ---------------------------------------------------------------- ingest_case
-- Duplicate-submission rules: the same idempotency_key with the same payload_sha256 is 'duplicate' (nothing is written, the existing case is returned);
-- the same key with a different payload_sha256 is 'conflict' (nothing is written). A malformed payload is 'invalid'.
CREATE FUNCTION soc.ingest_case(p jsonb) RETURNS TABLE (outcome text, o_case_id uuid, o_status text, detail text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE
    existing soc.cases;
    new_id uuid;
    v jsonb; r jsonb; act jsonb;
    decision text; case_status text; n_actions integer;
BEGIN
    IF p IS NULL OR jsonb_typeof(p) <> 'object' OR NOT (p ?& ARRAY['idempotency_key', 'payload_sha256', 'alert_set', 'alert_id', 'run_name', 'graph_version', 'memory_mode', 'alert', 'routing']) THEN
        outcome := 'invalid'; o_case_id := NULL; o_status := NULL; detail := 'the case payload is missing required keys'; RETURN NEXT; RETURN;
    END IF;
    v := p -> 'verdict';
    r := p -> 'routing';
    decision := r ->> 'decision';
    n_actions := CASE WHEN jsonb_typeof(p -> 'actions') = 'array' THEN jsonb_array_length(p -> 'actions') ELSE 0 END;
    IF decision NOT IN ('auto_close', 'escalate', 'needs_review') THEN
        outcome := 'invalid'; detail := 'unknown routing decision'; RETURN NEXT; RETURN;
    END IF;
    -- fail closed: a case is only auto-closed on a complete, benign verdict, and an auto-closed case carries no proposed action
    IF decision = 'auto_close' AND (v IS NULL OR v ->> 'status' IS DISTINCT FROM 'ok' OR (v ->> 'is_malicious')::boolean IS DISTINCT FROM false) THEN
        outcome := 'invalid'; detail := 'auto_close needs a complete benign verdict'; RETURN NEXT; RETURN;
    END IF;
    IF decision <> 'escalate' AND n_actions > 0 THEN
        outcome := 'invalid'; detail := 'only an escalated case may carry proposed actions'; RETURN NEXT; RETURN;
    END IF;

    new_id := gen_random_uuid();
    case_status := CASE decision WHEN 'auto_close' THEN 'auto_closed' WHEN 'escalate' THEN 'escalated' ELSE 'needs_review' END;
    INSERT INTO soc.cases AS c (case_id, idempotency_key, payload_sha256, alert_set, alert_id, run_name, graph_version, memory_mode, alert, provenance, status)
    VALUES (new_id, p ->> 'idempotency_key', p ->> 'payload_sha256', p ->> 'alert_set', p ->> 'alert_id', p ->> 'run_name', p ->> 'graph_version', p ->> 'memory_mode',
            p -> 'alert', coalesce(p -> 'provenance', '{}'::jsonb), case_status)
    ON CONFLICT (idempotency_key) DO NOTHING;
    IF NOT FOUND THEN
        SELECT * INTO existing FROM soc.cases WHERE idempotency_key = p ->> 'idempotency_key';
        outcome := CASE WHEN existing.payload_sha256 = p ->> 'payload_sha256' THEN 'duplicate' ELSE 'conflict' END;
        o_case_id := existing.case_id; o_status := existing.status;
        detail := CASE outcome WHEN 'duplicate' THEN 'the same case was already stored; nothing was written'
                               ELSE 'the idempotency key exists with a different payload; nothing was written' END;
        PERFORM soc.audit(coalesce(p ->> 'ingested_by', 'system:ingest'), 'case_' || outcome, 'case', existing.case_id::text, existing.case_id, jsonb_build_object('idempotency_key', p ->> 'idempotency_key'));
        RETURN NEXT; RETURN;
    END IF;

    IF v IS NOT NULL AND jsonb_typeof(v) = 'object' THEN
        INSERT INTO soc.verdicts (case_id, status, is_malicious, attack_type, mitre_technique, severity, evidence_text, prompt_version, prompt_sha256, model, error_code)
        VALUES (new_id, v ->> 'status', (v ->> 'is_malicious')::boolean, v ->> 'attack_type', v ->> 'mitre_technique', v ->> 'severity', v ->> 'evidence_text',
                v ->> 'prompt_version', v ->> 'prompt_sha256', v ->> 'model', v ->> 'error_code');
    ELSE
        INSERT INTO soc.verdicts (case_id, status) VALUES (new_id, 'missing');
    END IF;

    INSERT INTO soc.routing_decisions (case_id, decision, risk_level, reasons, policy_version, policy_sha256, memory_raised_risk)
    VALUES (new_id, decision, r ->> 'risk_level', r -> 'reasons', r ->> 'policy_version', r ->> 'policy_sha256', coalesce((r ->> 'memory_raised_risk')::boolean, false));

    INSERT INTO soc.evidence_items (case_id, kind, ordinal, source, payload, payload_sha256)
    SELECT new_id, e.kind, e.ordinal, e.source, e.payload, e.payload_sha256
    FROM jsonb_to_recordset(coalesce(p -> 'evidence', '[]'::jsonb)) AS e (kind text, ordinal integer, source text, payload jsonb, payload_sha256 text);

    INSERT INTO soc.memory_hits (case_id, rank, memory_id, distance, label, source_split, source_ref, manifest_sha256)
    SELECT new_id, h.rank, h.memory_id, h.distance, h.label, h.source_split, h.source_ref, h.manifest_sha256
    FROM jsonb_to_recordset(coalesce(p -> 'memory_hits', '[]'::jsonb)) AS h (rank integer, memory_id text, distance double precision, label text, source_split text, source_ref jsonb, manifest_sha256 text);

    FOR act IN SELECT * FROM jsonb_array_elements(coalesce(p -> 'actions', '[]'::jsonb)) LOOP
        INSERT INTO soc.proposed_actions (case_id, action_type, target, parameters, rationale, proposed_by)
        VALUES (new_id, act ->> 'action_type', act ->> 'target', coalesce(act -> 'parameters', '{}'::jsonb), act ->> 'rationale', coalesce(p ->> 'proposed_by', 'agent:graph-v2'));
        PERFORM soc.audit(coalesce(p ->> 'proposed_by', 'agent:graph-v2'), 'action_proposed', 'case', new_id::text, new_id,
                          jsonb_build_object('action_type', act ->> 'action_type', 'target', act ->> 'target'));
    END LOOP;

    PERFORM soc.audit(coalesce(p ->> 'ingested_by', 'system:ingest'), 'case_ingested', 'case', new_id::text, new_id,
                      jsonb_build_object('decision', decision, 'status', case_status, 'proposed_actions', n_actions, 'idempotency_key', p ->> 'idempotency_key'));
    outcome := 'created'; o_case_id := new_id; o_status := case_status; detail := NULL;
    RETURN NEXT;
END $$;

-- ---------------------------------------------------------------- decide_action
-- Outcomes: applied | replayed | conflict | unauthorized | not_found | invalid.
--   applied      the proposal was pending and is now approved or rejected, by this call
--   replayed     this exact request (same idempotency key, decision and person) was already applied; the stored result is returned, nothing changes
--   conflict     the proposal is already decided (by anyone, with any key), or the key was used for another request: nothing changes, the stored decision is returned
--   unauthorized the caller is not an active approver/admin; nothing changes (the attempt is audited)
-- Concurrent calls for the same proposal queue on the row lock; the second sees the first's decision and gets 'conflict' or 'replayed'.
CREATE FUNCTION soc.decide_action(p_action uuid, p_decision text, p_actor text, p_reason text, p_idem text)
RETURNS TABLE (outcome text, o_action_id uuid, o_state text, o_decided_by text, o_decided_at timestamptz, detail text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE a soc.proposed_actions; who soc.analysts; d soc.approval_decisions; pending_left integer;
BEGIN
    o_action_id := p_action;
    IF p_decision IS NULL OR p_decision NOT IN ('approved', 'rejected') OR p_actor IS NULL OR btrim(p_actor) = ''
       OR p_reason IS NULL OR btrim(p_reason) = '' OR p_idem IS NULL OR length(p_idem) < 8 OR length(p_idem) > 200 THEN
        outcome := 'invalid'; detail := 'decision must be approved or rejected, with an actor, a reason and an idempotency key of 8 to 200 characters'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO who FROM soc.analysts WHERE analyst_id = p_actor;
    IF NOT FOUND OR NOT who.active OR who.role NOT IN ('approver', 'admin') THEN
        PERFORM soc.audit(p_actor, 'approval_denied', 'action', p_action::text, (SELECT case_id FROM soc.proposed_actions WHERE action_id = p_action),
                          jsonb_build_object('attempted', p_decision, 'why', 'not an active approver'));
        outcome := 'unauthorized'; detail := 'the caller is not an active approver'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO a FROM soc.proposed_actions WHERE action_id = p_action FOR UPDATE;
    IF NOT FOUND THEN
        outcome := 'not_found'; detail := 'no such proposed action'; RETURN NEXT; RETURN;
    END IF;

    IF a.state = 'pending' THEN
        IF EXISTS (SELECT 1 FROM soc.approval_decisions WHERE idempotency_key = p_idem) THEN
            PERFORM soc.audit(p_actor, 'decision_conflict', 'action', p_action::text, a.case_id, jsonb_build_object('attempted', p_decision, 'why', 'idempotency key used for another request'));
            outcome := 'conflict'; o_state := a.state; detail := 'the idempotency key was already used for another request'; RETURN NEXT; RETURN;
        END IF;
        UPDATE soc.proposed_actions SET state = p_decision, decided_at = now(), decided_by = p_actor, decision_reason = p_reason WHERE action_id = p_action
        RETURNING * INTO a;
        INSERT INTO soc.approval_decisions (action_id, decision, decided_by, reason, idempotency_key, decided_at) VALUES (p_action, p_decision, p_actor, p_reason, p_idem, a.decided_at);
        PERFORM soc.audit(p_actor, CASE p_decision WHEN 'approved' THEN 'action_approved' ELSE 'action_rejected' END, 'action', p_action::text, a.case_id,
                          jsonb_build_object('action_type', a.action_type, 'target', a.target, 'reason', p_reason, 'idempotency_key', p_idem));
        SELECT count(*) INTO pending_left FROM soc.proposed_actions WHERE case_id = a.case_id AND state = 'pending';
        IF pending_left = 0 THEN
            UPDATE soc.cases SET status = 'resolved', updated_at = now() WHERE case_id = a.case_id AND status IN ('escalated', 'needs_review');
        END IF;
        outcome := 'applied'; o_state := a.state; o_decided_by := a.decided_by; o_decided_at := a.decided_at; RETURN NEXT; RETURN;
    END IF;

    SELECT * INTO d FROM soc.approval_decisions WHERE action_id = p_action;
    o_state := a.state; o_decided_by := a.decided_by; o_decided_at := a.decided_at;
    IF d.idempotency_key = p_idem AND d.decision = p_decision AND d.decided_by = p_actor THEN
        PERFORM soc.audit(p_actor, 'decision_replayed', 'action', p_action::text, a.case_id, jsonb_build_object('decision', p_decision, 'idempotency_key', p_idem));
        outcome := 'replayed'; detail := 'this request was already applied'; RETURN NEXT; RETURN;
    END IF;
    PERFORM soc.audit(p_actor, 'decision_conflict', 'action', p_action::text, a.case_id,
                      jsonb_build_object('attempted', p_decision, 'existing', a.state, 'existing_decided_by', a.decided_by));
    outcome := 'conflict'; detail := 'the proposal is already ' || a.state; RETURN NEXT;
END $$;

-- ---------------------------------------------------------------- simulate_execution
-- Records a SIMULATED execution of an APPROVED proposal. There is no live containment code anywhere in this project; this is bookkeeping only.
-- Outcomes: simulated | already_simulated | not_approved | unauthorized | not_found
CREATE FUNCTION soc.simulate_execution(p_action uuid, p_actor text) RETURNS TABLE (outcome text, o_execution_id uuid, o_state text, detail text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE a soc.proposed_actions; who soc.analysts; ex uuid;
BEGIN
    SELECT * INTO who FROM soc.analysts WHERE analyst_id = p_actor;
    IF p_actor IS NULL OR NOT FOUND OR NOT who.active OR who.role NOT IN ('approver', 'admin') THEN
        PERFORM soc.audit(p_actor, 'execution_denied', 'action', p_action::text, (SELECT case_id FROM soc.proposed_actions WHERE action_id = p_action), jsonb_build_object('why', 'not an active approver'));
        outcome := 'unauthorized'; detail := 'the caller is not an active approver'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO a FROM soc.proposed_actions WHERE action_id = p_action FOR SHARE;
    IF NOT FOUND THEN
        outcome := 'not_found'; detail := 'no such proposed action'; RETURN NEXT; RETURN;
    END IF;
    o_state := a.state;
    IF a.state <> 'approved' THEN
        PERFORM soc.audit(p_actor, 'execution_blocked', 'action', p_action::text, a.case_id, jsonb_build_object('state', a.state));
        outcome := 'not_approved'; detail := 'only an approved action can be executed (state is ' || a.state || ')'; RETURN NEXT; RETURN;
    END IF;
    INSERT INTO soc.executed_actions (action_id, mode, executed_by, result)
    VALUES (p_action, 'simulated', p_actor, jsonb_build_object('simulated', true, 'action_type', a.action_type, 'target', a.target, 'note', 'no live containment was performed'))
    ON CONFLICT (action_id) DO NOTHING
    RETURNING execution_id INTO ex;
    IF ex IS NULL THEN
        SELECT execution_id INTO ex FROM soc.executed_actions WHERE action_id = p_action;
        outcome := 'already_simulated'; o_execution_id := ex; detail := 'a simulated execution was already recorded'; RETURN NEXT; RETURN;
    END IF;
    PERFORM soc.audit(p_actor, 'execution_simulated', 'action', p_action::text, a.case_id, jsonb_build_object('action_type', a.action_type, 'target', a.target));
    outcome := 'simulated'; o_execution_id := ex; detail := NULL; RETURN NEXT;
END $$;
