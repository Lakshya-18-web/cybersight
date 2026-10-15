-- Week 4, migration 0001: core schema for cases, verdicts, evidence, memory provenance, routing, proposed actions, approvals and execution records.
-- Versioned and checksummed by week4/db/migrate.py. NEVER edit this file after it has been applied anywhere: add a new migration instead.
-- No credentials or secrets are stored. Identities are analyst ids only; tokens live in the API environment, never in the database.

CREATE SCHEMA IF NOT EXISTS soc;

-- Human identities that may act on proposals. Roles are enforced here (by the decision function) and again in the API.
CREATE TABLE soc.analysts (
    analyst_id   text PRIMARY KEY CHECK (analyst_id ~ '^[A-Za-z0-9_.@-]{1,64}$'),
    display_name text,
    role         text NOT NULL CHECK (role IN ('viewer', 'analyst', 'approver', 'admin')),
    active       boolean NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- One case per (run, alert, memory mode). idempotency_key is derived by the ingester from those; payload_sha256 detects a changed resubmission.
CREATE TABLE soc.cases (
    case_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    idempotency_key text NOT NULL UNIQUE CHECK (length(idempotency_key) BETWEEN 8 AND 200),
    payload_sha256  text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    -- 'frozen' is deliberately not allowed: the frozen evaluation set never enters the case store.
    alert_set       text NOT NULL CHECK (alert_set IN ('dev', 'synthetic')),
    alert_id        text NOT NULL CHECK (length(alert_id) BETWEEN 1 AND 200),
    run_name        text NOT NULL,
    graph_version   text NOT NULL,
    memory_mode     text NOT NULL CHECK (memory_mode IN ('off', 'on')),
    -- the label-free alert exactly as the model saw it; answer-bearing keys are refused
    alert           jsonb NOT NULL CHECK (jsonb_typeof(alert) = 'object'
                                          AND NOT (alert ?| ARRAY['label', 'Label', 'is_attack', 'source_file', 'original_row', 'source_alert_id',
                                                                   'mitre_tactic', 'mitre_technique_id', 'mitre_accepted_ids'])),
    provenance      jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(provenance) = 'object'),
    status          text NOT NULL CHECK (status IN ('auto_closed', 'escalated', 'needs_review', 'resolved')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX cases_status_created_idx ON soc.cases (status, created_at DESC, case_id);
CREATE INDEX cases_alert_idx ON soc.cases (alert_set, alert_id);
CREATE INDEX cases_run_idx ON soc.cases (run_name, memory_mode);

CREATE TABLE soc.verdicts (
    verdict_id     bigserial PRIMARY KEY,
    case_id        uuid NOT NULL UNIQUE REFERENCES soc.cases (case_id),
    status         text NOT NULL CHECK (status IN ('ok', 'parse_failed', 'model_error', 'missing')),
    is_malicious   boolean,
    attack_type    text,
    mitre_technique text,
    severity       text CHECK (severity IS NULL OR severity IN ('none', 'low', 'medium', 'high', 'critical')),
    evidence_text  text CHECK (evidence_text IS NULL OR length(evidence_text) <= 2000),
    prompt_version text,
    prompt_sha256  text,
    model          text,
    error_code     text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    -- a verdict is only "ok" when every field is there; a failed verdict carries no invented fields
    CHECK ((status = 'ok' AND is_malicious IS NOT NULL AND attack_type IS NOT NULL AND mitre_technique IS NOT NULL AND severity IS NOT NULL)
           OR (status <> 'ok' AND is_malicious IS NULL AND attack_type IS NULL AND mitre_technique IS NULL AND severity IS NULL))
);

CREATE TABLE soc.evidence_items (
    evidence_id    bigserial PRIMARY KEY,
    case_id        uuid NOT NULL REFERENCES soc.cases (case_id),
    kind           text NOT NULL CHECK (kind IN ('tool_call', 'specialist_finding', 'memory_summary', 'graph_error', 'routing_step')),
    ordinal        integer NOT NULL CHECK (ordinal >= 0),
    source         text NOT NULL,
    payload        jsonb NOT NULL,
    payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    UNIQUE (case_id, kind, ordinal)
);

-- Which prior incidents the memory step showed for a case. source_split is pinned to 'train' by the database itself.
CREATE TABLE soc.memory_hits (
    hit_id          bigserial PRIMARY KEY,
    case_id         uuid NOT NULL REFERENCES soc.cases (case_id),
    rank            integer NOT NULL CHECK (rank >= 1),
    memory_id       text NOT NULL,
    distance        double precision NOT NULL CHECK (distance >= 0),
    label           text NOT NULL,
    source_split    text NOT NULL CHECK (source_split = 'train'),
    source_ref      jsonb NOT NULL CHECK (jsonb_typeof(source_ref) = 'object'),
    manifest_sha256 text NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
    UNIQUE (case_id, rank),
    UNIQUE (case_id, memory_id)
);

CREATE TABLE soc.routing_decisions (
    case_id           uuid PRIMARY KEY REFERENCES soc.cases (case_id),
    decision          text NOT NULL CHECK (decision IN ('auto_close', 'escalate', 'needs_review')),
    risk_level        text NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'unknown')),
    reasons           jsonb NOT NULL CHECK (jsonb_typeof(reasons) = 'array' AND jsonb_array_length(reasons) >= 1),
    policy_version    text NOT NULL,
    policy_sha256     text NOT NULL CHECK (policy_sha256 ~ '^[0-9a-f]{64}$'),
    memory_raised_risk boolean NOT NULL DEFAULT false,
    decided_at        timestamptz NOT NULL DEFAULT now()
);

-- Proposals only. Nothing here is executed; executed_actions (below) records SIMULATED runs of approved proposals.
CREATE TABLE soc.proposed_actions (
    action_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id          uuid NOT NULL REFERENCES soc.cases (case_id),
    action_type      text NOT NULL CHECK (action_type IN ('block_source_ip', 'isolate_host', 'rate_limit_source', 'increase_monitoring')),
    target           text NOT NULL CHECK (length(target) BETWEEN 1 AND 200),
    parameters       jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(parameters) = 'object'),
    rationale        text NOT NULL,
    requires_approval boolean NOT NULL DEFAULT true CHECK (requires_approval IS TRUE),
    state            text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'rejected')),
    proposed_by      text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    decided_at       timestamptz,
    decided_by       text REFERENCES soc.analysts (analyst_id),
    decision_reason  text,
    row_version      integer NOT NULL DEFAULT 0,
    UNIQUE (case_id, action_type, target),
    CHECK ((state = 'pending' AND decided_at IS NULL AND decided_by IS NULL AND decision_reason IS NULL)
           OR (state <> 'pending' AND decided_at IS NOT NULL AND decided_by IS NOT NULL AND decision_reason IS NOT NULL))
);
CREATE INDEX proposed_actions_state_idx ON soc.proposed_actions (state, created_at, action_id);
CREATE INDEX proposed_actions_case_idx ON soc.proposed_actions (case_id);

-- Exactly one decision per proposal. Approval is terminal: there is no way back from approved or rejected.
CREATE TABLE soc.approval_decisions (
    decision_id     bigserial PRIMARY KEY,
    action_id       uuid NOT NULL UNIQUE REFERENCES soc.proposed_actions (action_id),
    decision        text NOT NULL CHECK (decision IN ('approved', 'rejected')),
    decided_by      text NOT NULL REFERENCES soc.analysts (analyst_id),
    reason          text NOT NULL CHECK (length(btrim(reason)) >= 1),
    idempotency_key text NOT NULL UNIQUE CHECK (length(idempotency_key) BETWEEN 8 AND 200),
    decided_at      timestamptz NOT NULL DEFAULT now()
);

-- SIMULATED execution records. mode is pinned to 'simulated': this sprint has no live containment, and the schema refuses anything else.
CREATE TABLE soc.executed_actions (
    execution_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id    uuid NOT NULL UNIQUE REFERENCES soc.proposed_actions (action_id),
    mode         text NOT NULL CHECK (mode = 'simulated'),
    executed_by  text NOT NULL,
    executed_at  timestamptz NOT NULL DEFAULT now(),
    result       jsonb NOT NULL DEFAULT '{}'::jsonb
);

-- Append-only, hash-chained audit trail (triggers in migration 0002). payload never carries credentials (checked in 0002).
-- event_id has no column default: the audit trigger (migration 0002) assigns it from this sequence AFTER taking the chain lock,
-- so ids and chain order always agree even with concurrent writers.
CREATE SEQUENCE soc.audit_events_seq;
CREATE TABLE soc.audit_events (
    event_id    bigint PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    actor       text NOT NULL,
    event_type  text NOT NULL,
    entity_type text NOT NULL,
    entity_id   text NOT NULL,
    case_id     uuid REFERENCES soc.cases (case_id),
    payload     jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(payload) = 'object'),
    prev_hash   text NOT NULL,
    event_hash  text NOT NULL
);
CREATE INDEX audit_events_case_idx ON soc.audit_events (case_id, event_id);
CREATE INDEX audit_events_entity_idx ON soc.audit_events (entity_type, entity_id, event_id);
