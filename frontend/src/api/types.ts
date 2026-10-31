// Response shapes of the backend (week4 API + week5 layer). Values the UI does not control are typed loosely on purpose: an unknown
// status or severity renders as plain text rather than breaking the page.

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
  next_offset: number | null;
}

export type CaseStatus = 'auto_closed' | 'escalated' | 'needs_review' | 'resolved';
export const CASE_STATUSES: readonly CaseStatus[] = ['auto_closed', 'escalated', 'needs_review', 'resolved'];

export interface CaseSummary {
  case_id: string;
  alert_set: string;
  alert_id: string;
  run_name: string;
  graph_version: string;
  memory_mode: string;
  status: string;
  created_at: string;
  updated_at: string;
  verdict_status: string | null;
  attack_type: string | null;
  severity: string | null;
  is_malicious: boolean | null;
  routing_decision: string | null;
  risk_level: string | null;
  pending_actions: number;
}

export interface Verdict {
  case_id: string;
  status: string;
  is_malicious: boolean | null;
  attack_type: string | null;
  mitre_technique: string | null;
  severity: string | null;
  evidence_text: string | null;
  prompt_version: string | null;
  prompt_sha256: string | null;
  model: string | null;
  error_code: string | null;
  created_at: string;
}

export interface Routing {
  case_id: string;
  decision: string;
  risk_level: string | null;
  reasons: string[];
  policy_version: string | null;
  policy_sha256: string | null;
  memory_raised_risk: boolean | null;
  decided_at: string;
}

export type ActionState = 'pending' | 'approved' | 'rejected';

export interface ProposedAction {
  action_id: string;
  case_id?: string;
  action_type: string;
  target: string | null;
  parameters: Record<string, unknown> | null;
  rationale: string | null;
  requires_approval: boolean;
  state: string;
  proposed_by: string;
  created_at: string;
  decided_at: string | null;
  decided_by: string | null;
  decision_reason: string | null;
}

export interface Provenance {
  graph_status?: string;
  graph_version?: string;
  model?: string;
  policy_version?: string;
  policy_sha256?: string;
  prompt_version?: string;
  prompt_sha256?: string;
  supervisor_visits?: number;
  week4_version?: string;
  memory?: { backend: string | null; enabled: boolean; manifest_sha256: string | null; status: string | null } | null;
  week5?: { job_id?: string; engine?: string; fake_model?: boolean; guard_signals?: unknown[] } | null;
  [key: string]: unknown;
}

export interface CaseDetail {
  case_id: string;
  alert_set: string;
  alert_id: string;
  run_name: string;
  graph_version: string;
  memory_mode: string;
  alert: Record<string, string | number | null>;
  provenance: Provenance | null;
  status: string;
  created_at: string;
  updated_at: string;
  verdict: Verdict | null;
  routing: Routing | null;
  actions: ProposedAction[];
}

export interface EvidenceItem {
  case_id: string;
  kind: string;
  ordinal: number;
  source: string;
  payload: unknown;
  payload_sha256: string;
}
export interface EvidenceResponse { case_id: string; items: EvidenceItem[] }

export interface MemoryHit {
  rank: number;
  memory_id: string;
  distance: number | null;
  label: string | null;
  source_split: string | null;
  source_ref: string | null;
  manifest_sha256: string | null;
}
export interface MemoryResponse {
  case_id: string;
  memory_mode: string;
  memory: { backend: string | null; enabled: boolean; manifest_sha256: string | null; status: string | null } | null;
  hits: MemoryHit[];
}

export interface HistoryEvent {
  event_id: number;
  occurred_at: string;
  actor: string;
  event_type: string;
  entity_type: string;
  entity_id: string;
  case_id: string | null;
  payload: Record<string, unknown> | null;
  prev_hash: string | null;
  event_hash: string;
}
export interface HistoryResponse { case_id: string; events: HistoryEvent[] }

export interface PendingAction {
  action_id: string;
  case_id: string;
  action_type: string;
  target: string | null;
  parameters: Record<string, unknown> | null;
  rationale: string | null;
  created_at: string;
  proposed_by: string;
  alert_id: string;
  alert_set: string;
  run_name: string;
  memory_mode: string;
  case_status: string;
  verdict_status: string | null;
  attack_type: string | null;
  severity: string | null;
  risk_level: string | null;
  routing_decision: string | null;
}

export interface DecisionRecord {
  action_id: string;
  decision: string;
  decided_by: string;
  reason: string;
  idempotency_key?: string;
  decided_at: string;
}
export interface ExecutionRecord {
  execution_id: string;
  action_id: string;
  mode: string;
  executed_by: string;
  executed_at: string;
  result: Record<string, unknown> | null;
}
export interface ActionDetail {
  action: ProposedAction;
  decision: DecisionRecord | null;
  execution: ExecutionRecord | null;
  history: HistoryEvent[];
}
export interface DecisionResult {
  outcome: 'applied' | 'replayed';
  replayed: boolean;
  action: ProposedAction;
  decision: DecisionRecord | null;
  execution: ExecutionRecord | null;
}
export interface SimulationResult {
  outcome: 'simulated' | 'already_simulated';
  mode: string;
  action: ProposedAction;
  execution: ExecutionRecord | null;
}

export type JobStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'timed_out';
export const JOB_STATUSES: readonly JobStatus[] = ['queued', 'running', 'succeeded', 'failed', 'timed_out'];
export const TERMINAL_JOB_STATUSES: readonly string[] = ['succeeded', 'failed', 'timed_out'];

export interface JobView {
  job_id: string;
  status: string;
  attempts: number;
  max_attempts: number;
  alert_id: string;
  alert_set: string;
  memory_mode: string;
  submitted_by: string;
  enqueued_at: string | null;
  first_started_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  not_before: string | null;
  case_id: string | null;
  error_code: string | null;
  error_detail: string | null;
  result: {
    graph_status?: string;
    verdict_status?: string;
    routing_decision?: string;
    risk_level?: string;
    proposed_actions?: number;
    memory_mode?: string;
    fake_model?: boolean;
    guard_signals?: unknown[];
    ingest?: string;
    [key: string]: unknown;
  } | null;
  timings: {
    graph_seconds?: number;
    model_seconds?: number;
    wall_seconds?: number;
    attempt?: number;
    nodes?: Record<string, { calls: number; seconds: number }>;
    [key: string]: unknown;
  } | null;
  usage: {
    model_calls?: number;
    model_seconds?: number;
    prompt_tokens: number | null;
    output_tokens: number | null;
    thinking_tokens: number | null;
    total_tokens: number | null;
    tokens_available?: boolean;
    tokens_note?: string;
  } | null;
  case_url?: string | null;
}

export interface Health { status: string; auth_mode: string }
export interface HealthReady { status: string; database: boolean; broker: boolean; queue_backend: string }

export interface Me {
  analyst_id: string;
  role: string;
  active: boolean;
  permissions: { read: boolean; submit: boolean; decide: boolean };
}

export interface SubmitResult {
  job_id: string;
  status: string;
  duplicate: boolean;
  dispatch: string;
  status_url: string;
}

/** The body of POST /alerts. The server accepts exactly these two keys. */
export interface SubmitBody {
  alert: Record<string, string | number>;
  memory: 'off' | 'on';
}

// ---------------------------------------------------------------------------------------------------------------------
// Week 5 phase 2 routes: sensor ingestion, search, analysis, notes / feedback / resolution, overview, providers, diagnostics, evaluation reports.
// Anything the server may leave out or change is optional or loosely typed, so a newer server cannot break a page.

export const RISK_LEVELS = ['low', 'medium', 'high', 'unknown'] as const;
export const ROUTING_DECISIONS = ['auto_close', 'needs_review', 'escalate'] as const;
export const ALERT_SETS = ['dev', 'synthetic', 'sensor'] as const;
export const VERDICT_STATUSES = ['ok', 'parse_failed', 'model_error', 'missing'] as const;
export const ASSESSMENTS = ['correct', 'incorrect', 'unsure'] as const;
export const DISPOSITIONS = ['true_positive', 'false_positive', 'true_negative', 'false_negative', 'inconclusive'] as const;
export type Assessment = (typeof ASSESSMENTS)[number];
export type Disposition = (typeof DISPOSITIONS)[number];

export const SEARCH_SORTS = ['created_desc', 'created_asc', 'updated_desc', 'severity_desc', 'risk_desc'] as const;
export type SearchSort = (typeof SEARCH_SORTS)[number];


/** A row of /search/cases: the case list row plus the network endpoints, note count and latest feedback. */
export interface SearchRow extends CaseSummary {
  src_ip?: string | null;
  dst_ip?: string | null;
  dst_port?: string | number | null;
  notes_count?: number;
  /** The assessment (correct | incorrect | unsure) of the newest feedback, if any. */
  latest_feedback?: string | null;
}
export interface SearchPage extends Page<SearchRow> { filters?: Record<string, string | null> }

export interface SensorStats {
  events: number;
  flows: number;
  alerts: number;
  sensors: number;
  last_received_at: string | null;
  note?: string;
}

export interface Overview {
  cases_total: number;
  cases_last_24h: number;
  by_status: Record<string, number>;
  by_source: Record<string, number>;
  by_severity: Record<string, number>;
  by_routing: Record<string, number>;
  by_risk: Record<string, number>;
  by_verdict_status: Record<string, number>;
  pending_actions: number;
  actions_by_state: Record<string, number>;
  simulated_executions: number;
  feedback_by_assessment: Record<string, number>;
  notes_total: number;
  jobs: Record<string, number>;
  oldest_unfinished_job_age_seconds: number | null;
  sensor_events: SensorStats;
}

export interface Finding { kind?: string; statement?: string; metrics?: Record<string, unknown>; evidence_index?: number; source_tool?: string; basis?: string }
export interface SpecialistFindings {
  analyst?: string; agent?: string; status?: string; assessment?: string; beacon_candidate?: boolean; candidate_reason?: string; basis?: string;
  findings?: Finding[]; limits?: string[]; tool_calls?: number; tool_errors?: number; window_minutes?: number;
}
export interface FlowToolCall { tool: string; ok: boolean | null; arguments?: Record<string, unknown> | null; n_flows?: number | null; error_code?: string | null }

export interface SensorEvidence {
  sensor?: string; signature_id?: number; rev?: number; gid?: number; severity?: number; category?: string | null; action?: string | null; app_proto?: string | null;
  display?: { signature?: string | null; category?: string | null };
  flow_linked?: boolean; flow_ref?: string | null; flow_source?: string | null; flows_in_window?: number;
  event_time?: string; received_at?: string; adapter_version?: string; unavailable_fields?: string[];
}

/** One reputation lookup. Only fields the server sanitised; `status` says whether the answer can be trusted as "no data" or as a real score. */
export interface ThreatIntelRecord {
  ip: string;
  role?: string;
  provider?: string;
  status: string;
  reason?: string | null;
  cache_hit?: boolean;
  checked_at?: string | null;
  source?: string | null;
  reputation?: {
    abuse_confidence_score?: number | null; total_reports?: number | null; last_reported_at?: string | null;
    country_code?: string | null; usage_type?: string | null; is_whitelisted?: boolean | null;
  } | null;
}

export interface EvidencePolicyStep {
  version?: string; sha256?: string; decision_before?: string; decision_after?: string; raised?: boolean; rules_checked?: string[];
  fired?: { rule: string; name: string; detail: string; floor: string; risk: string | null; source: string }[];
}

export interface AnalysisNote { note_id: number; kind: string; author: string; body: string; created_at: string }
export interface AnalysisFeedback { feedback_id: number; author: string; verdict_assessment: string; disposition: string | null; comment: string | null; created_at: string }
export interface TimelineEvent { at: string; actor: string; kind: string; summary: string; detail: Record<string, string | number | boolean | null> }

export interface CaseAnalysis {
  case: Pick<CaseSummary, 'case_id' | 'alert_set' | 'alert_id' | 'run_name' | 'graph_version' | 'memory_mode' | 'status' | 'created_at' | 'updated_at'>;
  evidence_classes: {
    observed: {
      alert: Record<string, string | number | null>;
      unavailable_fields: string[];
      sensor?: SensorEvidence | null;
      specialist_findings: { traffic_analyst?: SpecialistFindings | null; c2_beacon_analyst?: SpecialistFindings | null };
      flow_tool_calls: FlowToolCall[];
      description?: string;
    };
    external_enrichment: {
      reference_context: SpecialistFindings | null;
      threat_intel: { status: string; records: ThreatIntelRecord[]; reason?: string };
      description?: string;
    };
    model_hypothesis: { verdict: Verdict | null; model?: string | null; fake_model?: boolean | null; prompt_version?: string | null; description?: string };
    policy_decision: { routing: Routing | null; evidence_policy: EvidencePolicyStep | null; guard_signals: unknown[]; actions: ProposedAction[]; description?: string };
  };
  mitre: { model_technique: string | null; from: string; reference: Finding[]; note?: string };
  notes: AnalysisNote[];
  feedback: AnalysisFeedback[];
  timeline: TimelineEvent[];
  job: JobView | null;
  provenance: {
    week4_version?: string; graph_version?: string; memory?: Record<string, unknown> | null;
    risk_policy?: { version?: string; sha256?: string } | null;
    evidence_policy?: { version?: string | null; sha256?: string | null };
  };
}

export interface OutcomeResult { outcome: string; replayed: boolean; note_id?: number; feedback_id?: number; status?: string }

export interface ProviderHealth {
  model: { mode: string; live_calls_allowed: boolean; configured_model: string | null; status: string; status_note?: string; verdicts_by_status: Record<string, number>; model_errors_total: number };
  threat_intel: {
    status: { configured?: boolean | null; note?: string; provider?: string; alert_sets?: string[]; daily_budget?: number; used_last_24h?: number; timeout_seconds?: number; cache_ttl_seconds?: number; cache_entries?: number };
    lookups_last_24h: { by_status: Record<string, number>; last_lookup_at: string | null; hours: number };
    enabled_for: string[] | null;
  };
  queue: { backend: string; broker_ready: boolean; detail: string | null };
  database: { reachable: boolean };
  jobs: Record<string, { count: number; oldest_age_seconds: number | null }>;
  workers: { status: string; reason?: string };
}

export interface Diagnostics {
  versions: Record<string, string>;
  policies: { risk_policy?: { version: string; sha256: string }; evidence_policy?: { version: string; sha256: string }; error?: string };
  audit_chain: { ok?: boolean; checked?: boolean; first_bad_event_id?: number | null; reason?: string; [k: string]: unknown };
  migrations: { week4?: (string | number)[][]; week5?: (string | number)[][]; status?: string; reason?: string };
  settings: Record<string, unknown>;
  auth_mode: string;
}

export interface ReportList { available: boolean; reason?: string; items: { name: string; bytes: number; modified: number }[] }
export interface ReportDocument { name: string; format: 'json' | 'markdown'; content: unknown }

export interface ActionRow {
  action_id: string; case_id: string; alert_id: string | null; action_type: string; target: string | null; state: string; proposed_by: string;
  created_at: string; decided_at: string | null; decided_by: string | null; decision_reason: string | null;
  executed: boolean; execution_mode: string | null; executed_by: string | null; executed_at: string | null;
}
