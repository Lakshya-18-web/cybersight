"""The route table: the single list of endpoints. The role each needs is stated here, once. Roles: None = public, "read" = any active analyst, "decide" = active approver or admin."""
from collections import namedtuple

Route = namedtuple("Route", "method path name role summary query")

LIST_QUERY = [("limit", "page size, 1 to 200 (default 50)"), ("offset", "rows to skip (default 0)")]
CASE_QUERY = [("status", "auto_closed | escalated | needs_review | resolved"), ("memory_mode", "off | on"), ("alert_set", "dev | synthetic")] + LIST_QUERY

ROUTES = [
    Route("GET", "/health", "health", None, "Liveness and database check. Returns no case data.", []),
    Route("GET", "/cases", "list_cases", "read", "List cases, newest first, with filters and pagination.", CASE_QUERY),
    Route("GET", "/cases/{case_id}", "get_case", "read", "One case: alert, verdict, routing decision and proposed actions.", []),
    Route("GET", "/cases/{case_id}/evidence", "case_evidence", "read", "The evidence recorded for a case: tool calls, specialist findings, memory result, errors, supervisor steps.", []),
    Route("GET", "/cases/{case_id}/memory", "case_memory", "read", "Incident-memory provenance for a case: which training records were shown, their split, source and the memory manifest hash.", []),
    Route("GET", "/cases/{case_id}/history", "case_history", "read", "The audit trail for a case, oldest first.", []),
    Route("GET", "/approvals/pending", "pending_approvals", "read", "Proposed actions waiting for a decision, oldest first.", LIST_QUERY),
    Route("GET", "/actions/{action_id}", "get_action", "read", "One proposed action with its decision, any simulated execution and its audit history.", []),
    Route("POST", "/actions/{action_id}/decision", "decide", "decide",
          "Approve or reject a proposed action. Needs an Idempotency-Key header. A decision is final and is recorded, not executed.", []),
    Route("POST", "/actions/{action_id}/simulate-execution", "simulate_execution", "decide",
          "Record a SIMULATED execution of an approved action. Nothing is carried out against any system.", []),
]

BY_NAME = {r.name: r for r in ROUTES}
APPROVAL_ROUTES = [r for r in ROUTES if r.role == "decide"]
