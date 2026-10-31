"""Routes added in Week 5 phase 2: sensor ingestion, case search, analyst notes / feedback / resolution, the typed case analysis, the overview, provider health, diagnostics and evaluation reports.
Same Route type and roles as routes5. Appended to ROUTES5 so the web layer, the test stub and the OpenAPI document pick them up without further wiring."""
SEARCH_QUERY = [("q", "text in alert id, case id, source or destination address, or attack type (up to 100 characters)"), ("status", "auto_closed | escalated | needs_review | resolved"),
                ("severity", "none | low | medium | high | critical"), ("risk_level", "low | medium | high | unknown"), ("routing_decision", "auto_close | escalate | needs_review"),
                ("alert_set", "dev | synthetic | sensor"), ("verdict_status", "ok | parse_failed | model_error | missing"), ("is_malicious", "true | false"), ("has_pending", "true | false"),
                ("created_from", "date or date-time, inclusive"), ("created_to", "date or date-time, exclusive"),
                ("sort", "created_desc | created_asc | updated_desc | severity_desc | risk_desc"), ("limit", "page size, 1 to 200"), ("offset", "rows to skip")]

def build(Route):
    return [
        Route("POST", "/sensors/{sensor}/eve", "ingest_eve", "submit",
              'Send Suricata EVE JSON events from the sensor named in the path. Body: {"events": [...up to 500 EVE objects...], "analyze": true|false} (application/json) or newline-delimited EVE lines (application/x-ndjson). '
              "Only alert and flow events are used. Events are validated, de-duplicated and stored; every alert event gets one analysis job. Replaying a batch creates nothing new.", [("analyze", "true | false; NDJSON bodies only (a JSON body has its own analyze field)")]),
        Route("GET", "/sensors", "list_sensors", "read", "How many sensor events are stored (flows and alerts), how many sensors have sent events, and when the last one arrived.", []),
        Route("GET", "/search/cases", "search_cases", "read", "Search and filter cases (text, status, severity, risk, routing, source, verdict status, dates), sorted, with pagination.", SEARCH_QUERY),
        Route("GET", "/actions", "list_actions", "read", "Proposed actions with their decision and any SIMULATED execution, newest activity first. Nothing listed here was executed against a real system.",
              [("state", "pending | approved | rejected"), ("executed", "true | false: whether a simulated execution was recorded"), ("limit", "page size, 1 to 200"), ("offset", "rows to skip")]),
        Route("GET", "/overview", "get_overview", "read", "Counts for the dashboard: cases by status, source, severity, routing and risk; pending approvals; simulated executions; jobs; sensor events; feedback. Every number is computed from stored records.", []),
        Route("GET", "/cases/{case_id}/analysis", "case_analysis", "read",
              "One case with its evidence kept apart by kind: observed (alert, flow records, specialist findings), external enrichment (reference tables, threat intelligence with provider, status and time), "
              "the model's hypothesis (verdict) and the policy decisions (routing, evidence policy, guard signals, proposed actions); plus notes, feedback and the audit timeline.", []),
        Route("POST", "/cases/{case_id}/notes", "add_note", "submit", 'Add an analyst note. Body: {"body": "text up to 4000 characters"}. Optional Idempotency-Key makes a retry safe. Notes are never given to the model.', []),
        Route("POST", "/cases/{case_id}/feedback", "add_feedback", "submit",
              'Record your judgement of the system\'s verdict. Body: {"assessment": "correct|incorrect|unsure", "disposition": "true_positive|false_positive|true_negative|false_negative|inconclusive" (optional), "comment": "..." (optional)}. '
              "Feedback is stored for evaluation and review; it never changes the verdict or the routing and is never given to the model.", []),
        Route("POST", "/cases/{case_id}/resolve", "resolve_case", "submit",
              'Close an escalated or needs_review case that has no pending proposals. Body: {"reason": "text", "disposition": "..." (optional)}. Resolving records your decision; it approves, rejects and executes nothing.', []),
        Route("GET", "/providers", "get_providers", "read", "Health of the services the pipeline depends on: model provider mode, threat-intelligence provider and its recent outcomes, queue, database, jobs.", []),
        Route("GET", "/diagnostics", "get_diagnostics", "read", "Versions, policy identities, audit-chain check, applied migrations and the non-secret settings.", []),
        Route("GET", "/evaluation/reports", "list_evaluation_reports", "read", "Evaluation reports available to this server (files in the configured report folder).", []),
        Route("GET", "/evaluation/reports/{name}", "get_evaluation_report", "read", "One evaluation report: JSON is returned parsed, Markdown as text.", []),
]
