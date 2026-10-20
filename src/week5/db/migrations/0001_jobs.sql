-- Week 5, migration 0001: the durable job table behind asynchronous alert ingestion.
-- The table is the SOURCE OF TRUTH for a job's state. A broker (Redis/Celery) only carries "job X exists" messages; losing a message loses nothing, because
-- a job that stays queued and undispatched is found again (soc.undispatched_jobs) and re-sent. Delivery is at-least-once; processing is exactly-once-per-claim:
-- soc.claim_job moves a job queued -> running under a row lock (FOR UPDATE SKIP LOCKED), so two workers can never both own it, and a duplicate message finds nothing to claim.
-- A worker that dies leaves a lease that expires; soc.reap_expired puts the job back in the queue (or fails it when its attempts are used up).
-- Rules the database enforces, whatever the application does: terminal states never change; identity fields are immutable; a running job always has an owner;
-- events are append-only; the API login can only submit jobs and read them; no credential-shaped key is accepted in the alert or the result.
-- Requires Week 4 migrations 0001-0004 (soc.cases, soc.audit, soc.forbid_change, soc.contains_secret_key, soc_api).

CREATE TABLE soc.jobs (
    job_id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    idempotency_key  text NOT NULL UNIQUE CHECK (length(idempotency_key) BETWEEN 8 AND 200),
    payload_sha256   text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    alert_id         text NOT NULL CHECK (length(alert_id) BETWEEN 1 AND 200),
    alert_set        text NOT NULL CHECK (alert_set IN ('dev', 'synthetic')),
    memory_mode      text NOT NULL CHECK (memory_mode IN ('off', 'on')),
    alert            jsonb NOT NULL CHECK (jsonb_typeof(alert) = 'object' AND NOT soc.contains_secret_key(alert)),
    submitted_by     text NOT NULL CHECK (length(submitted_by) BETWEEN 1 AND 200),
    status           text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'timed_out')),
    attempts         integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts     integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 10),
    not_before       timestamptz NOT NULL DEFAULT clock_timestamp(),
    enqueued_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    dispatched_at    timestamptz,
    first_started_at timestamptz,
    started_at       timestamptz,
    finished_at      timestamptz,
    lease_owner      text,
    lease_expires_at timestamptz,
    case_id          uuid REFERENCES soc.cases (case_id),
    error_code       text CHECK (error_code IS NULL OR error_code ~ '^[a-z0-9_]{1,64}$'),
    error_detail     text CHECK (error_detail IS NULL OR length(error_detail) <= 500),
    result           jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(result) = 'object' AND NOT soc.contains_secret_key(result)),
    timings          jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(timings) = 'object'),
    usage            jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(usage) = 'object'),
    row_version      integer NOT NULL DEFAULT 1,
    CHECK ((status = 'running') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK (status <> 'succeeded' OR case_id IS NOT NULL),
    CHECK (status NOT IN ('succeeded', 'failed', 'timed_out') OR finished_at IS NOT NULL),
    CHECK (attempts <= max_attempts)
);
CREATE INDEX jobs_claim_idx ON soc.jobs (not_before, enqueued_at) WHERE status = 'queued';
CREATE INDEX jobs_lease_idx ON soc.jobs (lease_expires_at) WHERE status = 'running';
CREATE INDEX jobs_status_idx ON soc.jobs (status, enqueued_at DESC, job_id);
CREATE INDEX jobs_submitter_idx ON soc.jobs (submitted_by, enqueued_at DESC);

CREATE TABLE soc.job_events (
    event_id    bigserial PRIMARY KEY,
    job_id      uuid NOT NULL REFERENCES soc.jobs (job_id),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    event       text NOT NULL CHECK (event ~ '^[a-z_]{1,40}$'),
    attempt     integer NOT NULL DEFAULT 0,
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(detail) = 'object' AND NOT soc.contains_secret_key(detail))
);
CREATE INDEX job_events_job_idx ON soc.job_events (job_id, event_id);
CREATE TRIGGER job_events_append_only BEFORE UPDATE OR DELETE ON soc.job_events FOR EACH ROW EXECUTE FUNCTION soc.forbid_change();
CREATE TRIGGER job_events_no_truncate BEFORE TRUNCATE ON soc.job_events FOR EACH STATEMENT EXECUTE FUNCTION soc.forbid_change();

-- ---------------------------------------------------------------- guard: what may change on a job
CREATE FUNCTION soc.guard_job_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'a job cannot be deleted' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (NEW.job_id, NEW.idempotency_key, NEW.payload_sha256, NEW.alert_id, NEW.alert_set, NEW.memory_mode, NEW.alert, NEW.submitted_by, NEW.enqueued_at, NEW.max_attempts)
       IS DISTINCT FROM
       (OLD.job_id, OLD.idempotency_key, OLD.payload_sha256, OLD.alert_id, OLD.alert_set, OLD.memory_mode, OLD.alert, OLD.submitted_by, OLD.enqueued_at, OLD.max_attempts) THEN
        RAISE EXCEPTION 'the identity of a job cannot be edited' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.status IN ('succeeded', 'failed', 'timed_out') THEN
        RAISE EXCEPTION 'the job is already % and cannot change', OLD.status USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
           (OLD.status = 'queued'  AND NEW.status = 'running')
        OR (OLD.status = 'running' AND NEW.status IN ('queued', 'succeeded', 'failed', 'timed_out'))) THEN
        RAISE EXCEPTION 'illegal job status change % -> %', OLD.status, NEW.status USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.attempts < OLD.attempts THEN
        RAISE EXCEPTION 'attempts can only grow' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    NEW.row_version := OLD.row_version + 1;
    RETURN NEW;
END $$;
CREATE TRIGGER jobs_guard BEFORE UPDATE OR DELETE ON soc.jobs FOR EACH ROW EXECUTE FUNCTION soc.guard_job_update();
CREATE TRIGGER jobs_no_truncate BEFORE TRUNCATE ON soc.jobs FOR EACH STATEMENT EXECUTE FUNCTION soc.forbid_change();

-- ---------------------------------------------------------------- functions (the only write paths)
-- submit_job(p): p holds idempotency_key, payload_sha256, alert, alert_id, alert_set, memory_mode, submitted_by, max_attempts, max_queue_depth (optional), dispatched (optional boolean).
-- outcome: created | duplicate (same key, same payload: the existing job is returned, nothing is written) | conflict (same key, different payload) | queue_full | invalid
CREATE FUNCTION soc.submit_job(p jsonb) RETURNS TABLE (outcome text, o_job_id uuid, o_status text, detail text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE existing soc.jobs; new_id uuid; depth integer; max_depth integer;
BEGIN
    IF p IS NULL OR jsonb_typeof(p) <> 'object' OR NOT (p ?& ARRAY['idempotency_key', 'payload_sha256', 'alert', 'alert_id', 'alert_set', 'memory_mode', 'submitted_by', 'max_attempts']) THEN
        outcome := 'invalid'; detail := 'the job payload is missing required keys'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO existing FROM soc.jobs WHERE idempotency_key = p ->> 'idempotency_key';
    IF FOUND THEN
        outcome := CASE WHEN existing.payload_sha256 = p ->> 'payload_sha256' THEN 'duplicate' ELSE 'conflict' END;
        o_job_id := existing.job_id; o_status := existing.status;
        detail := CASE outcome WHEN 'duplicate' THEN 'the same alert was already submitted; nothing new was queued'
                               ELSE 'the idempotency key was already used with a different alert; nothing was queued' END;
        PERFORM soc.audit(p ->> 'submitted_by', 'job_' || outcome, 'job', existing.job_id::text, NULL, jsonb_build_object('alert_id', existing.alert_id));
        RETURN NEXT; RETURN;
    END IF;
    max_depth := nullif(p ->> 'max_queue_depth', '')::integer;
    IF max_depth IS NOT NULL THEN
        SELECT count(*) INTO depth FROM soc.jobs WHERE status IN ('queued', 'running');
        IF depth >= max_depth THEN
            outcome := 'queue_full'; detail := 'the queue is full; try again later'; RETURN NEXT; RETURN;
        END IF;
    END IF;
    new_id := gen_random_uuid();
    BEGIN
        INSERT INTO soc.jobs (job_id, idempotency_key, payload_sha256, alert_id, alert_set, memory_mode, alert, submitted_by, max_attempts, dispatched_at)
        VALUES (new_id, p ->> 'idempotency_key', p ->> 'payload_sha256', p ->> 'alert_id', p ->> 'alert_set', p ->> 'memory_mode', p -> 'alert', p ->> 'submitted_by',
                (p ->> 'max_attempts')::integer, CASE WHEN coalesce((p ->> 'dispatched')::boolean, false) THEN clock_timestamp() ELSE NULL END);
    EXCEPTION WHEN unique_violation THEN
        -- two identical submissions raced: the loser reports the winner
        SELECT * INTO existing FROM soc.jobs WHERE idempotency_key = p ->> 'idempotency_key';
        outcome := CASE WHEN existing.payload_sha256 = p ->> 'payload_sha256' THEN 'duplicate' ELSE 'conflict' END;
        o_job_id := existing.job_id; o_status := existing.status; detail := 'a concurrent submission with the same key won'; RETURN NEXT; RETURN;
    END;
    INSERT INTO soc.job_events (job_id, event, attempt, detail) VALUES (new_id, 'submitted', 0, jsonb_build_object('submitted_by', p ->> 'submitted_by'));
    PERFORM soc.audit(p ->> 'submitted_by', 'job_submitted', 'job', new_id::text, NULL, jsonb_build_object('alert_id', p ->> 'alert_id', 'memory_mode', p ->> 'memory_mode'));
    outcome := 'created'; o_job_id := new_id; o_status := 'queued'; detail := 'queued'; RETURN NEXT;
END $$;

-- claim_job(worker, lease seconds, optional job id): moves ONE due queued job to running for this worker. Returns zero rows when nothing is due or another worker holds it.
CREATE FUNCTION soc.claim_job(p_worker text, p_lease_seconds integer, p_job uuid DEFAULT NULL) RETURNS SETOF soc.jobs
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE j soc.jobs;
BEGIN
    IF p_worker IS NULL OR length(p_worker) NOT BETWEEN 1 AND 200 OR p_lease_seconds IS NULL OR p_lease_seconds NOT BETWEEN 5 AND 86400 THEN
        RAISE EXCEPTION 'a worker id and a lease of 5 to 86400 seconds are required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT * INTO j FROM soc.jobs
     WHERE status = 'queued' AND not_before <= clock_timestamp() AND (p_job IS NULL OR job_id = p_job)
     ORDER BY not_before, enqueued_at LIMIT 1 FOR UPDATE SKIP LOCKED;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    UPDATE soc.jobs SET status = 'running', attempts = attempts + 1, lease_owner = p_worker, lease_expires_at = clock_timestamp() + make_interval(secs => p_lease_seconds),
                        started_at = clock_timestamp(), first_started_at = coalesce(first_started_at, clock_timestamp())
     WHERE job_id = j.job_id RETURNING * INTO j;
    INSERT INTO soc.job_events (job_id, event, attempt, detail) VALUES (j.job_id, 'claimed', j.attempts, jsonb_build_object('worker', p_worker));
    RETURN NEXT j;
END $$;

CREATE FUNCTION soc.heartbeat_job(p_job uuid, p_worker text, p_lease_seconds integer) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE n integer;
BEGIN
    UPDATE soc.jobs SET lease_expires_at = clock_timestamp() + make_interval(secs => p_lease_seconds)
     WHERE job_id = p_job AND status = 'running' AND lease_owner = p_worker AND p_lease_seconds BETWEEN 5 AND 86400;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n = 1;
END $$;

-- complete_job: only the current owner of a running job may complete it. Repeating the call for a job already succeeded with the same case is acknowledged.
CREATE FUNCTION soc.complete_job(p_job uuid, p_worker text, p_case uuid, p_result jsonb, p_timings jsonb, p_usage jsonb) RETURNS TABLE (outcome text, o_status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE j soc.jobs;
BEGIN
    SELECT * INTO j FROM soc.jobs WHERE job_id = p_job FOR UPDATE;
    IF NOT FOUND THEN
        outcome := 'not_found'; RETURN NEXT; RETURN;
    END IF;
    IF j.status = 'succeeded' AND j.case_id IS NOT DISTINCT FROM p_case THEN
        outcome := 'already_complete'; o_status := j.status; RETURN NEXT; RETURN;
    END IF;
    IF j.status <> 'running' OR j.lease_owner IS DISTINCT FROM p_worker THEN
        outcome := 'not_owner'; o_status := j.status; RETURN NEXT; RETURN;
    END IF;
    UPDATE soc.jobs SET status = 'succeeded', case_id = p_case, finished_at = clock_timestamp(), lease_owner = NULL, lease_expires_at = NULL, error_code = NULL, error_detail = NULL,
                        result = coalesce(p_result, '{}'::jsonb), timings = coalesce(p_timings, '{}'::jsonb), usage = coalesce(p_usage, '{}'::jsonb)
     WHERE job_id = p_job;
    INSERT INTO soc.job_events (job_id, event, attempt, detail) VALUES (p_job, 'succeeded', j.attempts, jsonb_build_object('case_id', p_case));
    PERFORM soc.audit('worker:' || p_worker, 'job_succeeded', 'job', p_job::text, p_case, jsonb_build_object('attempts', j.attempts));
    outcome := 'completed'; o_status := 'succeeded'; RETURN NEXT;
END $$;

-- fail_job: record a failed attempt. retryable and attempts left -> back to queued after a delay; otherwise terminal (failed, or timed_out when p_timed_out).
CREATE FUNCTION soc.fail_job(p_job uuid, p_worker text, p_code text, p_detail text, p_retryable boolean, p_delay_seconds integer, p_timed_out boolean DEFAULT false) RETURNS TABLE (outcome text, o_status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE j soc.jobs; final_status text;
BEGIN
    IF p_code IS NULL OR p_code !~ '^[a-z0-9_]{1,64}$' THEN
        RAISE EXCEPTION 'error code must be lower-case letters, digits and underscores' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT * INTO j FROM soc.jobs WHERE job_id = p_job FOR UPDATE;
    IF NOT FOUND THEN
        outcome := 'not_found'; RETURN NEXT; RETURN;
    END IF;
    IF j.status <> 'running' OR j.lease_owner IS DISTINCT FROM p_worker THEN
        outcome := 'not_owner'; o_status := j.status; RETURN NEXT; RETURN;
    END IF;
    IF coalesce(p_retryable, false) AND j.attempts < j.max_attempts THEN
        UPDATE soc.jobs SET status = 'queued', lease_owner = NULL, lease_expires_at = NULL, dispatched_at = NULL, error_code = p_code, error_detail = left(p_detail, 500),
                            not_before = clock_timestamp() + make_interval(secs => greatest(coalesce(p_delay_seconds, 0), 0))
         WHERE job_id = p_job;
        INSERT INTO soc.job_events (job_id, event, attempt, detail) VALUES (p_job, 'retry_scheduled', j.attempts, jsonb_build_object('code', p_code, 'delay_seconds', greatest(coalesce(p_delay_seconds, 0), 0)));
        outcome := 'retry_scheduled'; o_status := 'queued'; RETURN NEXT; RETURN;
    END IF;
    final_status := CASE WHEN coalesce(p_timed_out, false) THEN 'timed_out' ELSE 'failed' END;
    UPDATE soc.jobs SET status = final_status, lease_owner = NULL, lease_expires_at = NULL, finished_at = clock_timestamp(), error_code = p_code, error_detail = left(p_detail, 500)
     WHERE job_id = p_job;
    INSERT INTO soc.job_events (job_id, event, attempt, detail)
    VALUES (p_job, final_status, j.attempts, jsonb_build_object('code', p_code, 'retries_exhausted', coalesce(p_retryable, false) AND j.attempts >= j.max_attempts));
    PERFORM soc.audit('worker:' || p_worker, 'job_' || final_status, 'job', p_job::text, NULL, jsonb_build_object('code', p_code, 'attempts', j.attempts));
    outcome := 'failed'; o_status := final_status; RETURN NEXT;
END $$;

-- reap_expired: running jobs whose lease ran out (the worker died or hung). Re-queue them, or fail them when attempts are used up.
CREATE FUNCTION soc.reap_expired(p_limit integer DEFAULT 100) RETURNS TABLE (o_job_id uuid, o_status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE j soc.jobs;
BEGIN
    FOR j IN SELECT * FROM soc.jobs WHERE status = 'running' AND lease_expires_at < clock_timestamp() ORDER BY lease_expires_at LIMIT greatest(p_limit, 1) FOR UPDATE SKIP LOCKED LOOP
        IF j.attempts < j.max_attempts THEN
            UPDATE soc.jobs SET status = 'queued', lease_owner = NULL, lease_expires_at = NULL, dispatched_at = NULL, error_code = 'worker_lost', error_detail = 'the worker stopped before finishing; the job was queued again',
                                not_before = clock_timestamp()
             WHERE job_id = j.job_id;
            INSERT INTO soc.job_events (job_id, event, attempt, detail) VALUES (j.job_id, 'lease_expired_requeued', j.attempts, jsonb_build_object('worker', j.lease_owner));
            o_job_id := j.job_id; o_status := 'queued'; RETURN NEXT;
        ELSE
            UPDATE soc.jobs SET status = 'failed', lease_owner = NULL, lease_expires_at = NULL, finished_at = clock_timestamp(), error_code = 'worker_lost',
                                error_detail = 'the worker stopped before finishing and no attempts were left'
             WHERE job_id = j.job_id;
            INSERT INTO soc.job_events (job_id, event, attempt, detail) VALUES (j.job_id, 'lease_expired_failed', j.attempts, jsonb_build_object('worker', j.lease_owner));
            PERFORM soc.audit('system:reaper', 'job_failed', 'job', j.job_id::text, NULL, jsonb_build_object('code', 'worker_lost', 'attempts', j.attempts));
            o_job_id := j.job_id; o_status := 'failed'; RETURN NEXT;
        END IF;
    END LOOP;
END $$;

-- dispatch bookkeeping (outbox): mark a job as handed to the broker; list jobs that are due but were never handed over, or not for p_older_than_seconds.
CREATE FUNCTION soc.mark_dispatched(p_job uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
DECLARE n integer;
BEGIN
    UPDATE soc.jobs SET dispatched_at = clock_timestamp() WHERE job_id = p_job AND status = 'queued';
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n = 1;
END $$;

CREATE FUNCTION soc.undispatched_jobs(p_older_than_seconds integer, p_limit integer DEFAULT 100) RETURNS TABLE (o_job_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = soc, pg_temp AS $$
    SELECT job_id FROM soc.jobs
     WHERE status = 'queued' AND not_before <= clock_timestamp()
       AND (dispatched_at IS NULL OR dispatched_at < clock_timestamp() - make_interval(secs => greatest(p_older_than_seconds, 1)))
     ORDER BY enqueued_at LIMIT greatest(p_limit, 1)
$$;

-- record_security_event: the way the application writes a refusal or a policy violation to the tamper-evident audit trail. Only three event types are accepted, the payload
-- may not contain credential-shaped keys (the audit table refuses them), and callers pass hashes and codes, never the rejected content itself.
CREATE FUNCTION soc.record_security_event(p_actor text, p_type text, p_entity_id text, p_case uuid, p_payload jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = soc, pg_temp AS $$
BEGIN
    IF p_type IS NULL OR p_type NOT IN ('ingest_rejected', 'response_withheld', 'policy_violation') THEN
        RAISE EXCEPTION 'unknown security event type' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM soc.audit(left(coalesce(p_actor, 'unknown'), 200), p_type, 'security', left(coalesce(p_entity_id, 'none'), 200), p_case,
                      CASE WHEN jsonb_typeof(p_payload) = 'object' THEN p_payload ELSE '{}'::jsonb END);
END $$;

-- one row per status with the age of the oldest job in it (for readiness checks and the load tester)
CREATE VIEW soc.job_stats AS
    SELECT status, count(*) AS n, extract(epoch FROM clock_timestamp() - min(enqueued_at)) AS oldest_age_seconds
    FROM soc.jobs GROUP BY status;

-- ---------------------------------------------------------------- roles
-- soc_api (Week 4) may submit jobs and read them. soc_worker is a NOLOGIN group role: give it to the worker's login role  GRANT soc_worker TO <worker_login>;
-- It may run the job functions and soc.ingest_case; it cannot write any table directly.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'soc_worker') THEN
        CREATE ROLE soc_worker NOLOGIN;
    END IF;
END $$;

REVOKE ALL ON TABLE soc.jobs, soc.job_events, soc.job_stats FROM PUBLIC;
REVOKE ALL ON FUNCTION soc.guard_job_update(), soc.submit_job(jsonb), soc.claim_job(text, integer, uuid), soc.heartbeat_job(uuid, text, integer),
    soc.complete_job(uuid, text, uuid, jsonb, jsonb, jsonb), soc.fail_job(uuid, text, text, text, boolean, integer, boolean), soc.reap_expired(integer),
    soc.mark_dispatched(uuid), soc.undispatched_jobs(integer, integer), soc.record_security_event(text, text, text, uuid, jsonb) FROM PUBLIC;
GRANT SELECT ON soc.jobs, soc.job_events, soc.job_stats TO soc_api;
GRANT EXECUTE ON FUNCTION soc.submit_job(jsonb), soc.mark_dispatched(uuid), soc.record_security_event(text, text, text, uuid, jsonb) TO soc_api;
GRANT USAGE ON SCHEMA soc TO soc_worker;
GRANT SELECT ON soc.jobs, soc.job_stats TO soc_worker;
GRANT EXECUTE ON FUNCTION soc.claim_job(text, integer, uuid), soc.heartbeat_job(uuid, text, integer), soc.complete_job(uuid, text, uuid, jsonb, jsonb, jsonb),
    soc.fail_job(uuid, text, text, text, boolean, integer, boolean), soc.reap_expired(integer), soc.mark_dispatched(uuid), soc.undispatched_jobs(integer, integer),
    soc.record_security_event(text, text, text, uuid, jsonb), soc.ingest_case(jsonb) TO soc_worker;
