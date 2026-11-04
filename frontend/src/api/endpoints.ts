import type { HttpClient } from './client';
import type {
  ActionDetail, ActionRow, CaseAnalysis, CaseDetail, CaseSummary, DecisionResult, EvidenceResponse, Health, HealthReady, HistoryResponse, JobView, Me, MemoryResponse, Page,
  PendingAction, SimulationResult, SubmitBody, SubmitResult,
  AccountRow, AuthSession, AuthStatus, BootstrapBody, CreateAccountBody, UpdateAccountBody,
  Diagnostics, Overview, OutcomeResult, ProviderHealth, ReportDocument, ReportList, SearchPage, SensorStats, Assessment, Disposition,
} from './types';

export interface PageQuery { limit?: number; offset?: number }
export interface CaseQuery extends PageQuery { status?: string; memory_mode?: string; alert_set?: string }
export interface JobQuery extends PageQuery { status?: string }
export interface SearchQuery extends PageQuery {
  q?: string; status?: string; severity?: string; risk_level?: string; routing_decision?: string; alert_set?: string; verdict_status?: string;
  is_malicious?: string; has_pending?: string; created_from?: string; created_to?: string; sort?: string;
}
export interface ActionQuery extends PageQuery { state?: string; executed?: string }
export interface FeedbackBody { assessment: Assessment; disposition?: Disposition; comment?: string }
type Opts = { signal?: AbortSignal | undefined };

/** One function per backend route, typed. Nothing else in the app builds a URL. */
export function createApi(client: HttpClient) {
  const get = async <T>(path: string, query?: Record<string, string | number | undefined>, signal?: AbortSignal) =>
    (await client.request<T>('GET', path, { query, signal })).data;
  const id = encodeURIComponent;

  return {
    health: (o: Opts = {}) => get<Health>('/health', undefined, o.signal),
    healthReady: async (o: Opts = {}) => {
      // /health/ready answers 503 with an error body when the database is down; the caller wants that as "down", so it is left to throw.
      return get<HealthReady>('/health/ready', undefined, o.signal);
    },
    me: (o: Opts = {}) => get<Me>('/me', undefined, o.signal),

    // ---- sign-in (docs/AUTHENTICATION.md). Credentials are sent to the server once; what comes back is a session cookie the page cannot read, plus the CSRF token.
    auth: {
      status: async (o: Opts = {}) => (await client.request<AuthStatus>('GET', '/auth/status', { signal: o.signal, anonymous: true })).data,
      /** quiet: a 401 here means "not signed in", which is an ordinary answer at start-up. */
      session: async (o: Opts & { quiet?: boolean } = {}) => (await client.request<AuthSession>('GET', '/auth/session', { signal: o.signal, anonymous: o.quiet ?? false })).data,
      login: async (username: string, password: string, o: Opts = {}) =>
        (await client.request<AuthSession>('POST', '/auth/login', { body: { username, password }, signal: o.signal, anonymous: true })).data,
      logout: async (o: Opts = {}) => (await client.request<{ status: string }>('POST', '/auth/logout', { body: {}, signal: o.signal, anonymous: true })).data,
      bootstrap: async (body: BootstrapBody, o: Opts = {}) => (await client.request<{ username: string; role: string }>('POST', '/auth/bootstrap', { body, signal: o.signal, anonymous: true })).data,
      changePassword: async (currentPassword: string, newPassword: string, o: Opts = {}) =>
        (await client.request<{ status: string }>('POST', '/auth/change-password', { body: { current_password: currentPassword, new_password: newPassword }, signal: o.signal })).data,
      users: async (o: Opts = {}) => (await client.request<{ items: AccountRow[] }>('GET', '/auth/users', { signal: o.signal })).data,
      createUser: async (body: CreateAccountBody, o: Opts = {}) => (await client.request<{ username: string; role: string; status: string }>('POST', '/auth/users', { body, signal: o.signal })).data,
      updateUser: async (username: string, body: UpdateAccountBody, o: Opts = {}) =>
        (await client.request<{ username: string; status: string }>('PATCH', `/auth/users/${id(username)}`, { body, signal: o.signal })).data,
      resetPassword: async (username: string, password: string, o: Opts = {}) =>
        (await client.request<{ username: string; status: string }>('POST', `/auth/users/${id(username)}/reset-password`, { body: { password }, signal: o.signal })).data,
      revokeSessions: async (username: string, o: Opts = {}) =>
        (await client.request<{ username: string; revoked: number }>('POST', `/auth/users/${id(username)}/revoke-sessions`, { body: {}, signal: o.signal })).data,
    },

    listCases: (q: CaseQuery = {}, o: Opts = {}) => get<Page<CaseSummary>>('/cases', { ...q }, o.signal),
    getCase: (caseId: string, o: Opts = {}) => get<CaseDetail>(`/cases/${id(caseId)}`, undefined, o.signal),
    caseEvidence: (caseId: string, o: Opts = {}) => get<EvidenceResponse>(`/cases/${id(caseId)}/evidence`, undefined, o.signal),
    caseMemory: (caseId: string, o: Opts = {}) => get<MemoryResponse>(`/cases/${id(caseId)}/memory`, undefined, o.signal),
    caseHistory: (caseId: string, o: Opts = {}) => get<HistoryResponse>(`/cases/${id(caseId)}/history`, undefined, o.signal),

    pendingApprovals: (q: PageQuery = {}, o: Opts = {}) => get<Page<PendingAction>>('/approvals/pending', { ...q }, o.signal),
    getAction: (actionId: string, o: Opts = {}) => get<ActionDetail>(`/actions/${id(actionId)}`, undefined, o.signal),
    decide: async (actionId: string, decision: 'approved' | 'rejected', reason: string, idempotencyKey: string, o: Opts = {}) =>
      (await client.request<DecisionResult>('POST', `/actions/${id(actionId)}/decision`, {
        body: { decision, reason }, headers: { 'Idempotency-Key': idempotencyKey }, signal: o.signal,
      })).data,
    simulateExecution: async (actionId: string, o: Opts = {}) =>
      (await client.request<SimulationResult>('POST', `/actions/${id(actionId)}/simulate-execution`, { body: {}, signal: o.signal })).data,

    /** Without an Idempotency-Key the server recognises an identical alert by its content, so a retry (or a second click) never queues it twice. */
    submitAlert: async (body: SubmitBody, idempotencyKey?: string, o: Opts = {}) => {
      const res = await client.request<SubmitResult>('POST', '/alerts', { body, headers: idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}, signal: o.signal });
      return { ...res.data, httpStatus: res.status };
    },

    // ---- phase 2 routes ----
    searchCases: (q: SearchQuery = {}, o: Opts = {}) => get<SearchPage>('/search/cases', { ...q }, o.signal),
    /** Decided and simulated actions. A simulated execution is an audit record only; nothing is executed against any system. */
    listActions: (q: ActionQuery = {}, o: Opts = {}) => get<Page<ActionRow>>('/actions', { ...q }, o.signal),
    overview: (o: Opts = {}) => get<Overview>('/overview', undefined, o.signal),
    sensors: (o: Opts = {}) => get<SensorStats>('/sensors', undefined, o.signal),
    caseAnalysis: (caseId: string, o: Opts = {}) => get<CaseAnalysis>(`/cases/${id(caseId)}/analysis`, undefined, o.signal),
    /** Notes, feedback and resolution are never sent to a model and change no verdict or routing. The Idempotency-Key makes a retry safe. */
    addNote: async (caseId: string, body: string, idempotencyKey: string, o: Opts = {}) =>
      (await client.request<OutcomeResult>('POST', `/cases/${id(caseId)}/notes`, { body: { body }, headers: { 'Idempotency-Key': idempotencyKey }, signal: o.signal })).data,
    addFeedback: async (caseId: string, body: FeedbackBody, idempotencyKey: string, o: Opts = {}) =>
      (await client.request<OutcomeResult>('POST', `/cases/${id(caseId)}/feedback`, { body, headers: { 'Idempotency-Key': idempotencyKey }, signal: o.signal })).data,
    resolveCase: async (caseId: string, reason: string, disposition: Disposition | undefined, idempotencyKey: string, o: Opts = {}) =>
      (await client.request<OutcomeResult>('POST', `/cases/${id(caseId)}/resolve`, {
        body: disposition ? { reason, disposition } : { reason }, headers: { 'Idempotency-Key': idempotencyKey }, signal: o.signal,
      })).data,
    providers: (o: Opts = {}) => get<ProviderHealth>('/providers', undefined, o.signal),
    diagnostics: (o: Opts = {}) => get<Diagnostics>('/diagnostics', undefined, o.signal),
    evaluationReports: (o: Opts = {}) => get<ReportList>('/evaluation/reports', undefined, o.signal),
    evaluationReport: (name: string, o: Opts = {}) => get<ReportDocument>(`/evaluation/reports/${id(name)}`, undefined, o.signal),

    getJob: (jobId: string, o: Opts = {}) => get<JobView>(`/jobs/${id(jobId)}`, undefined, o.signal),
    listJobs: (q: JobQuery = {}, o: Opts = {}) => get<Page<JobView>>('/jobs', { ...q }, o.signal),
  };
}

export type Api = ReturnType<typeof createApi>;
