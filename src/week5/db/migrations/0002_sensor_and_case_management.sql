-- Week 5, migration 0002: sensor (Suricata EVE) ingestion, analyst notes, analyst feedback and case resolution.
-- Requires Week 4 migrations 0001-0004 and Week 5 migration 0001. Never edit this file after it has been applied anywhere: add a new migration instead.
--
-- Rules the database enforces (whatever the application does):
--   * sensor events are append-only and de-duplicated by a SHA-256 of their normalised content;
--   * notes and feedback are append-only; only an active analyst, approver or admin may write them;
--   * a case can only be resolved from escalated / needs_review (the Week 4 case guard), never while a proposed action is still pending, and only by an authorised person;
--   * every write goes through a SECURITY DEFINER function that also writes the tamper-evident audit trail; the API login cannot write these tables directly;
--   * no credential-shaped key is accepted in any stored JSON.

-- ---------------------------------------------------------------- 1. a third alert source
-- 'sensor' = an alert that arrived from a real sensor (Suricata EVE). It is neither the dev set nor synthetic data, and the two must not be mixed up in a report.
-- 'frozen' is still deliberately not allowed: the frozen evaluation set never enters the case store.
ALTER TABLE soc.cases DROP CONSTRAINT cases_alert_set_check;
ALTER TABLE soc.cases ADD CONSTRAINT cases_alert_set_check CHECK (alert_set IN ('dev', 'synthetic', 'sensor'));
ALTER TABLE soc.jobs DROP CONSTRAINT jobs_alert_set_check;
ALTER TABLE soc.jobs ADD CONSTRAINT jobs_alert_set_check CHECK (alert_set IN ('dev', 'synthetic', 'sensor'));

-- ---------------------------------------------------------------- 2. sensor events
-- One row per normalised event (a flow record or an alert record). `record` holds only the fields week5.eve kept; fields the sensor did not send are absent, never filled in.
CREATE TABLE soc.sensor_events (
    event_id      bigserial PRIMARY KEY,
    event_sha256  text NOT NULL UNIQUE CHECK (event_sha256 ~ '^[0-9a-f]{64}$'),
    sensor        text NOT NULL CHECK (sensor ~ '^[A-Za-z0-9_.:-]{1,64}$'),
    event_type    text NOT NULL CHECK (event_type IN ('flow', 'alert')),
    flow_ref      text NOT NULL CHECK (flow_ref ~ '^[0-9A-Za-z_.:-]{1,64}$'),
    event_time    timestamptz NOT NULL,
    src_ip        inet NOT NULL,
    src_port      integer CHECK (src_port IS NULL OR src_port BETWEEN 0 AND 65535),
    dst_ip        inet NOT NULL,
    dst_port      integer CHECK (dst_port IS NULL OR dst_port BETWEEN 0 AND 65535),
    protocol      integer CHECK (protocol IS NULL OR protocol BETWEEN 0 AND 255),
    record        jsonb NOT NULL CHECK (jsonb_typeof(record) = 'object' AND NOT soc.contains_secret_key(record)),
    received_by   text NOT NULL CHECK (length(received_by) BETWEEN 1 AND 200),
    received_at   timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX sensor_events_flow_idx ON soc.sensor_events (sensor, flow_ref, event_type);
CREATE INDEX sensor_events_src_idx ON soc.sensor_events (src_ip, event_time) WHERE event_type = 'flow';
CREATE INDEX sensor_events_dst_idx ON soc.sensor_events (dst_ip, event_time) WHERE event_type = 'flow';
CREATE UNIQUE INDEX sensor_events_alert_id_idx ON soc.sensor_events ((record ->> 'alert_id')) WHERE event_type = 'alert';
CREATE INDEX sensor_events_received_idx ON soc.sensor_events (received_at DESC);
CREATE TRIGGER sensor_events_append_only BEFORE UPDATE OR DELETE ON soc.sensor_events FOR EACH ROW EXECUTE FUNCTION soc.forbid_change();
CREATE TRIGGER sensor_events_no_truncate BEFORE TRUNCATE ON soc.sensor_events FOR EACH STATEMENT EXECUTE FUNCTION soc.forbid_change();

-- ---------------------------------------------------------------- 3. notes and feedback
CREATE TABLE soc.case_notes (
    note_id         bigserial PRIMARY KEY,
    case_id         uuid NOT NULL REFERENCES soc.cases (case_id),
    kind            text NOT NULL DEFAULT 'note' CHECK (kind IN ('note', 'resolution')),
    author          text NOT NULL REFERENCES soc.analysts (analyst_id),
    body            text NOT NULL CHECK (length(btrim(body)) BETWEEN 1 AND 4000),
    idempotency_key text CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 8 AND 200),
    created_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (author, idempotency_key)
);
CREATE INDEX case_notes_case_idx ON soc.case_notes (case_id, note_id);

CREATE TABLE soc.case_feedback (
    feedback_id        bigserial PRIMARY KEY,
    case_id            uuid NOT NULL REFERENCES soc.cases (case_id),
    author             text NOT NULL REFERENCES soc.analysts (analyst_id),
    verdict_assessment text NOT NULL CHECK (verdict_assessment IN ('correct', 'incorrect', 'unsure')),
    disposition        text CHECK (disposition IS NULL OR disposition IN ('true_positive', 'false_positive', 'true_negative', 'false_negative', 'inconclusive')),
    comment            text CHECK (comment IS NULL OR length(comment) <= 2000),
    idempotency_key    text CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 8 AND 200),
    created_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (author, idempotency_key)
);
CREATE INDEX case_feedback_case_idx ON soc.case_feedback (case_id, feedback_id);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['case_notes', 'case_feedback']
    LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON soc.%I FOR EACH ROW EXECUTE FUNCTION soc.forbid_change()', t || '_append_only', t);
        EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON soc.%I FOR EACH STATEMENT EXECUTE FUNCTION soc.forbid_change()', t || '_no_truncate', t);
    END LOOP;
END $$;

-- ---------------------------------------------------------------- 4. write paths
-- the role of an ACTIVE analyst, or NULL
CREATE FUNCTION soc.w5_writer_role(p_actor text) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = soc, pg_temp AS $$
    SELECT role FROM soc.analysts WHERE analyst_id = p_actor AND active AND role IN ('analyst', 'approver', 'admin')
$$;

-- w5_ingest_sensor_batch(p): p = {actor, sensor, events:[{event_sha256, event_type, flow_ref, event_time, src_ip, src_port, dst_ip, dst_port, protocol, record}]}
-- One transaction: the whole batch is stored or none of it is. A repeated event is reported as 'duplicate' and writes nothing. One audit row per batch (counts only).
CREATE FUNCTION soc.w5_ingest_sensor_batch(p jsonb) RETURNS TABLE (o_index integer, outcome text, o_event_id bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE e jsonb; i integer := 0; new_id bigint; stored integer := 0; dups integer := 0; who text;
BEGIN
    IF p IS NULL OR jsonb_typeof(p) <> 'object' OR NOT (p ?& ARRAY['actor', 'sensor', 'events']) OR jsonb_typeof(p -> 'events') <> 'array' THEN
        RAISE EXCEPTION 'the batch is missing required keys' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    who := p ->> 'actor';
    IF soc.w5_writer_role(who) IS NULL THEN
        -- reported as a row, not raised: an exception would roll the audit row back with everything else
        PERFORM soc.audit(coalesce(who, 'unknown'), 'sensor_batch_refused', 'sensor', coalesce(p ->> 'sensor', 'unknown'), NULL, jsonb_build_object('reason', 'not an active analyst'));
        o_index := -1; outcome := 'unauthorized'; o_event_id := NULL; RETURN NEXT; RETURN;
    END IF;
    FOR e IN SELECT * FROM jsonb_array_elements(p -> 'events') LOOP
        INSERT INTO soc.sensor_events (event_sha256, sensor, event_type, flow_ref, event_time, src_ip, src_port, dst_ip, dst_port, protocol, record, received_by)
        VALUES (e ->> 'event_sha256', p ->> 'sensor', e ->> 'event_type', e ->> 'flow_ref', (e ->> 'event_time')::timestamptz, (e ->> 'src_ip')::inet,
                nullif(e ->> 'src_port', '')::integer, (e ->> 'dst_ip')::inet, nullif(e ->> 'dst_port', '')::integer, nullif(e ->> 'protocol', '')::integer, e -> 'record', who)
        ON CONFLICT (event_sha256) DO NOTHING
        RETURNING event_id INTO new_id;
        o_index := i;
        IF new_id IS NULL THEN
            outcome := 'duplicate'; o_event_id := NULL; dups := dups + 1;
        ELSE
            outcome := 'stored'; o_event_id := new_id; stored := stored + 1;
        END IF;
        new_id := NULL;
        i := i + 1;
        RETURN NEXT;
    END LOOP;
    PERFORM soc.audit(who, 'sensor_batch_ingested', 'sensor', p ->> 'sensor', NULL, jsonb_build_object('received', i, 'stored', stored, 'duplicates', dups));
END $$;

-- w5_add_note: outcome created | replayed | conflict | unauthorized | not_found | invalid
CREATE FUNCTION soc.w5_add_note(p_case uuid, p_actor text, p_body text, p_key text) RETURNS TABLE (outcome text, o_note_id bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE existing soc.case_notes; new_id bigint;
BEGIN
    IF soc.w5_writer_role(p_actor) IS NULL THEN
        PERFORM soc.audit(coalesce(p_actor, 'unknown'), 'case_note_refused', 'case', coalesce(p_case::text, 'none'), (SELECT case_id FROM soc.cases WHERE case_id = p_case), jsonb_build_object('reason', 'unauthorized'));
        outcome := 'unauthorized'; RETURN NEXT; RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM soc.cases WHERE case_id = p_case) THEN
        outcome := 'not_found'; RETURN NEXT; RETURN;
    END IF;
    IF p_body IS NULL OR length(btrim(p_body)) NOT BETWEEN 1 AND 4000 THEN
        outcome := 'invalid'; RETURN NEXT; RETURN;
    END IF;
    IF p_key IS NOT NULL THEN
        SELECT * INTO existing FROM soc.case_notes WHERE author = p_actor AND idempotency_key = p_key;
        IF FOUND THEN
            outcome := CASE WHEN existing.case_id = p_case AND existing.body = p_body THEN 'replayed' ELSE 'conflict' END;
            o_note_id := existing.note_id; RETURN NEXT; RETURN;
        END IF;
    END IF;
    INSERT INTO soc.case_notes (case_id, kind, author, body, idempotency_key) VALUES (p_case, 'note', p_actor, p_body, p_key) RETURNING note_id INTO new_id;
    PERFORM soc.audit(p_actor, 'case_note_added', 'case', p_case::text, p_case, jsonb_build_object('note_id', new_id, 'length', length(p_body)));
    outcome := 'created'; o_note_id := new_id; RETURN NEXT;
END $$;

-- w5_add_feedback: the analyst's judgement of the system's verdict. outcome created | replayed | conflict | unauthorized | not_found | invalid
CREATE FUNCTION soc.w5_add_feedback(p_case uuid, p_actor text, p_assessment text, p_disposition text, p_comment text, p_key text) RETURNS TABLE (outcome text, o_feedback_id bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE existing soc.case_feedback; new_id bigint;
BEGIN
    IF soc.w5_writer_role(p_actor) IS NULL THEN
        PERFORM soc.audit(coalesce(p_actor, 'unknown'), 'case_feedback_refused', 'case', coalesce(p_case::text, 'none'), (SELECT case_id FROM soc.cases WHERE case_id = p_case), jsonb_build_object('reason', 'unauthorized'));
        outcome := 'unauthorized'; RETURN NEXT; RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM soc.cases WHERE case_id = p_case) THEN
        outcome := 'not_found'; RETURN NEXT; RETURN;
    END IF;
    IF p_assessment IS NULL OR p_assessment NOT IN ('correct', 'incorrect', 'unsure')
       OR (p_disposition IS NOT NULL AND p_disposition NOT IN ('true_positive', 'false_positive', 'true_negative', 'false_negative', 'inconclusive'))
       OR (p_comment IS NOT NULL AND length(p_comment) > 2000) THEN
        outcome := 'invalid'; RETURN NEXT; RETURN;
    END IF;
    IF p_key IS NOT NULL THEN
        SELECT * INTO existing FROM soc.case_feedback WHERE author = p_actor AND idempotency_key = p_key;
        IF FOUND THEN
            outcome := CASE WHEN existing.case_id = p_case AND existing.verdict_assessment = p_assessment AND existing.disposition IS NOT DISTINCT FROM p_disposition
                                 AND existing.comment IS NOT DISTINCT FROM p_comment THEN 'replayed' ELSE 'conflict' END;
            o_feedback_id := existing.feedback_id; RETURN NEXT; RETURN;
        END IF;
    END IF;
    INSERT INTO soc.case_feedback (case_id, author, verdict_assessment, disposition, comment, idempotency_key) VALUES (p_case, p_actor, p_assessment, p_disposition, p_comment, p_key)
    RETURNING feedback_id INTO new_id;
    PERFORM soc.audit(p_actor, 'case_feedback_added', 'case', p_case::text, p_case, jsonb_build_object('feedback_id', new_id, 'assessment', p_assessment, 'disposition', p_disposition));
    outcome := 'created'; o_feedback_id := new_id; RETURN NEXT;
END $$;

-- w5_resolve_case: escalated | needs_review -> resolved (NOTE: Week 4 already moves a case to resolved when its LAST pending proposal is decided; this is for cases with no proposals, or to close one by hand), with a reason (stored as a 'resolution' note) and an optional disposition (stored as feedback).
-- outcome resolved | replayed | conflict (already resolved or auto_closed) | pending_actions (a proposal still awaits its decision) | unauthorized | not_found | invalid
CREATE FUNCTION soc.w5_resolve_case(p_case uuid, p_actor text, p_disposition text, p_reason text, p_key text) RETURNS TABLE (outcome text, o_status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE c soc.cases; existing soc.case_notes;
BEGIN
    IF soc.w5_writer_role(p_actor) IS NULL THEN
        PERFORM soc.audit(coalesce(p_actor, 'unknown'), 'case_resolve_refused', 'case', coalesce(p_case::text, 'none'), (SELECT case_id FROM soc.cases WHERE case_id = p_case), jsonb_build_object('reason', 'unauthorized'));
        outcome := 'unauthorized'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO c FROM soc.cases WHERE case_id = p_case FOR UPDATE;
    IF NOT FOUND THEN
        outcome := 'not_found'; RETURN NEXT; RETURN;
    END IF;
    IF p_reason IS NULL OR length(btrim(p_reason)) NOT BETWEEN 1 AND 1000
       OR (p_disposition IS NOT NULL AND p_disposition NOT IN ('true_positive', 'false_positive', 'true_negative', 'false_negative', 'inconclusive')) THEN
        outcome := 'invalid'; o_status := c.status; RETURN NEXT; RETURN;
    END IF;
    IF c.status = 'resolved' THEN
        SELECT * INTO existing FROM soc.case_notes WHERE case_id = p_case AND kind = 'resolution' AND author = p_actor AND idempotency_key IS NOT DISTINCT FROM p_key AND p_key IS NOT NULL;
        outcome := CASE WHEN FOUND THEN 'replayed' ELSE 'conflict' END; o_status := c.status; RETURN NEXT; RETURN;
    END IF;
    IF c.status NOT IN ('escalated', 'needs_review') THEN
        PERFORM soc.audit(p_actor, 'case_resolve_refused', 'case', p_case::text, p_case, jsonb_build_object('reason', 'status', 'status', c.status));
        outcome := 'conflict'; o_status := c.status; RETURN NEXT; RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM soc.proposed_actions WHERE case_id = p_case AND state = 'pending') THEN
        PERFORM soc.audit(p_actor, 'case_resolve_refused', 'case', p_case::text, p_case, jsonb_build_object('reason', 'pending_actions'));
        outcome := 'pending_actions'; o_status := c.status; RETURN NEXT; RETURN;
    END IF;
    INSERT INTO soc.case_notes (case_id, kind, author, body, idempotency_key) VALUES (p_case, 'resolution', p_actor, p_reason, p_key);
    IF p_disposition IS NOT NULL THEN
        INSERT INTO soc.case_feedback (case_id, author, verdict_assessment, disposition, comment) VALUES (p_case, p_actor, 'unsure', p_disposition, 'recorded when the case was resolved');
    END IF;
    UPDATE soc.cases SET status = 'resolved', updated_at = clock_timestamp() WHERE case_id = p_case;
    PERFORM soc.audit(p_actor, 'case_resolved', 'case', p_case::text, p_case, jsonb_build_object('from_status', c.status, 'disposition', p_disposition));
    outcome := 'resolved'; o_status := 'resolved'; RETURN NEXT;
END $$;

-- ---------------------------------------------------------------- 5. privileges
REVOKE ALL ON TABLE soc.sensor_events, soc.case_notes, soc.case_feedback FROM PUBLIC;
REVOKE ALL ON FUNCTION soc.w5_writer_role(text), soc.w5_ingest_sensor_batch(jsonb), soc.w5_add_note(uuid, text, text, text),
    soc.w5_add_feedback(uuid, text, text, text, text, text), soc.w5_resolve_case(uuid, text, text, text, text) FROM PUBLIC;
GRANT SELECT ON soc.sensor_events, soc.case_notes, soc.case_feedback TO soc_api;
GRANT EXECUTE ON FUNCTION soc.w5_ingest_sensor_batch(jsonb), soc.w5_add_note(uuid, text, text, text), soc.w5_add_feedback(uuid, text, text, text, text, text),
    soc.w5_resolve_case(uuid, text, text, text, text) TO soc_api;
-- the worker only READS sensor events (flows for the analysis agents); it cannot write them
GRANT SELECT ON soc.sensor_events TO soc_worker;
