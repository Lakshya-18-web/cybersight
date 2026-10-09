"""Supervisor for graph v0: a deterministic router. No LLM call.

Policy (a pure function of the state):
  1. First visit, traffic analyst not yet run      -> route to "traffic_analyst", status "running".
  2. Traffic analyst has run (findings present)    -> route to "end" and set the final status from the analyst's status:
        ok -> completed, partial -> completed_with_errors, anything else -> failed.
  3. The supervisor has already run MAX_SUPERVISOR_VISITS times -> route to "end", status "failed", error code loop_guard.
  4. A state that is already terminal              -> route to "end", status unchanged.
The analyst is never routed to twice, so the graph cannot loop: supervisor -> traffic_analyst -> supervisor -> end.
"""
from . import state as S

ANALYST_STATUS_TO_FINAL = {"ok": S.STATUS_COMPLETED, "partial": S.STATUS_COMPLETED_WITH_ERRORS}


def decide(state):
    """The routing decision and the status after it, as a pair: (route, status). Reads the state, changes nothing."""
    if state["status"] in S.TERMINAL_STATUSES:
        return S.ROUTE_END, state["status"]
    if state["supervisor_visits"] >= S.MAX_SUPERVISOR_VISITS:
        return S.ROUTE_END, S.STATUS_FAILED
    findings = state["traffic_findings"]
    if findings is None:
        if S.NODE_TRAFFIC_ANALYST in state["trace"]:  # the analyst ran and left nothing behind: do not send it again
            return S.ROUTE_END, S.STATUS_FAILED
        return S.NODE_TRAFFIC_ANALYST, S.STATUS_RUNNING
    return S.ROUTE_END, ANALYST_STATUS_TO_FINAL.get(findings.get("status"), S.STATUS_FAILED)


def supervisor_node(state):
    """Graph node. Returns only the fields it changes."""
    route, status = decide(state)
    visits = state["supervisor_visits"] + 1
    errors = list(state["errors"])
    if state["supervisor_visits"] >= S.MAX_SUPERVISOR_VISITS and state["status"] not in S.TERMINAL_STATUSES:
        errors.append({"node": S.NODE_SUPERVISOR, "code": "loop_guard", "message": "the supervisor ran " + str(state["supervisor_visits"]) + " times; the graph was stopped"})
    elif route == S.ROUTE_END and status == S.STATUS_FAILED and state["status"] not in S.TERMINAL_STATUSES:
        findings = state["traffic_findings"]
        if findings is None:
            errors.append({"node": S.NODE_SUPERVISOR, "code": "no_findings", "message": "the traffic analyst left no findings"})
    return {"next_node": route, "status": status, "supervisor_visits": visits, "errors": errors, "trace": list(state["trace"]) + [S.NODE_SUPERVISOR]}


def route_from_supervisor(state):
    """The conditional edge: reads the decision the supervisor stored."""
    return state["next_node"] if state["next_node"] in S.ROUTES else S.ROUTE_END
