"""Supervisor for graph v0.1: a deterministic router. No LLM call.

The decision is a pure function of the state, re-derived at every visit. Rules, in order:
  0. State already terminal                                  -> end, status unchanged.
  1. Supervisor already ran MAX_SUPERVISOR_VISITS times      -> end, failed, error loop_guard.
  2. Traffic analyst not run yet                             -> traffic_analyst. (If it ran and left no findings: end, failed, error no_findings.)
  3. Traffic analyst failed                                  -> end, failed. There is no flow evidence to build on, so no other agent runs.
  4. Repeat contact, C2 beaconing analyst not run yet        -> c2_beacon_analyst.
        Repeat contact = the traffic analyst's source summary shows at least REPEAT_CONTACT_MIN_FLOWS flows from the alert source to the alert destination.
        This is a routing gate that saves work. It is not a detection threshold. With no repeat contact, or if the count is unknown, the beaconing analyst is skipped and the reason is logged.
  5. Enrichment agent not run yet                            -> enrichment_agent.
  6. Otherwise                                               -> end: completed if every agent that ran finished ok, else completed_with_errors.
An agent that ran but left no findings behind is recorded as an error and is never routed to again.
Every agent is routed to at most once, so the longest path is supervisor, traffic, supervisor, beacon, supervisor, enrichment, supervisor, end (4 visits).
Every decision is appended to state["routing"] with its reason.
"""
from . import state as S

REPEAT_CONTACT_MIN_FLOWS = 2
AGENT_FINDINGS = {S.NODE_TRAFFIC_ANALYST: "traffic_findings", S.NODE_C2_BEACON_ANALYST: "beacon_findings", S.NODE_ENRICHMENT_AGENT: "enrichment_findings"}


def repeat_contact_flows(state):
    """Flows from the alert source to the alert destination in the traffic window, read from the traffic analyst's own evidence. None when it cannot be told."""
    destination = state["alert"].get("dst_ip")
    for entry in state["evidence"]:
        if not isinstance(entry, dict) or entry.get("tool") != "summarize_flows" or entry.get("ok") is not True:
            continue
        if (entry.get("arguments") or {}).get("direction") != "src" or not isinstance(entry.get("data"), dict):
            continue
        data = entry["data"]
        tops = data.get("top_destination_ips")
        if not isinstance(tops, list):
            return None
        for row in tops:
            if isinstance(row, dict) and row.get("dst_ip") == destination:
                flows = row.get("flows")
                return flows if isinstance(flows, int) and not isinstance(flows, bool) else None
        distinct = data.get("distinct_destination_ips")
        if isinstance(distinct, int) and not isinstance(distinct, bool) and distinct <= len(tops):
            return 0   # the table lists every destination, and this one is not in it
        return None    # the table is cut off, so the count for this destination is unknown
    return None


def _missing(state, agent):
    """The error for an agent that ran but left nothing behind."""
    names = {S.NODE_TRAFFIC_ANALYST: "traffic analyst", S.NODE_C2_BEACON_ANALYST: "C2 beaconing analyst", S.NODE_ENRICHMENT_AGENT: "enrichment agent"}
    return {"node": S.NODE_SUPERVISOR, "code": "no_findings", "message": "the " + names[agent] + " left no findings"}


def decide(state):
    """The decision as a dict: route, status, reason, errors (new errors to add). Reads the state, changes nothing."""
    def result(route, status, reason, errors=None):
        return {"route": route, "status": status, "reason": reason, "errors": errors or []}

    if state["status"] in S.TERMINAL_STATUSES:
        return result(S.ROUTE_END, state["status"], "the run is already finished")
    if state["supervisor_visits"] >= S.MAX_SUPERVISOR_VISITS:
        return result(S.ROUTE_END, S.STATUS_FAILED, "loop guard: the supervisor ran " + str(state["supervisor_visits"]) + " times",
                      [{"node": S.NODE_SUPERVISOR, "code": "loop_guard", "message": "the supervisor ran " + str(state["supervisor_visits"]) + " times; the graph was stopped"}])
    traffic = state["traffic_findings"]
    if traffic is None:
        if S.NODE_TRAFFIC_ANALYST in state["trace"]:
            return result(S.ROUTE_END, S.STATUS_FAILED, "the traffic analyst ran and left no findings", [_missing(state, S.NODE_TRAFFIC_ANALYST)])
        return result(S.NODE_TRAFFIC_ANALYST, S.STATUS_RUNNING, "every alert starts with the traffic analyst")
    if traffic.get("status") not in ("ok", "partial"):
        return result(S.ROUTE_END, S.STATUS_FAILED, "the traffic analysis produced no usable flow evidence, so no other agent was run")

    skipped = ""
    if state["beacon_findings"] is None and S.NODE_C2_BEACON_ANALYST not in state["trace"]:
        flows = repeat_contact_flows(state)
        if flows is not None and flows >= REPEAT_CONTACT_MIN_FLOWS:
            return result(S.NODE_C2_BEACON_ANALYST, S.STATUS_RUNNING, str(flows) + " flows from the source to the destination in the traffic window (gate: at least "
                          + str(REPEAT_CONTACT_MIN_FLOWS) + "), so the timing is worth examining")
        skipped = ("C2 beaconing analyst skipped: " + ("the source-to-destination flow count could not be read from the traffic evidence" if flows is None
                   else "only " + str(flows) + " flow(s) from the source to the destination in the traffic window (gate: at least " + str(REPEAT_CONTACT_MIN_FLOWS) + ")") + ". ")
    if state["enrichment_findings"] is None and S.NODE_ENRICHMENT_AGENT not in state["trace"]:
        return result(S.NODE_ENRICHMENT_AGENT, S.STATUS_RUNNING, skipped + "enrichment runs once after the specialists")

    errors, healthy = [], True
    for agent in (S.NODE_C2_BEACON_ANALYST, S.NODE_ENRICHMENT_AGENT, S.NODE_TRAFFIC_ANALYST):
        output = state[AGENT_FINDINGS[agent]]
        if agent in state["trace"] and output is None:
            healthy = False
            if agent != S.NODE_TRAFFIC_ANALYST:
                errors.append(_missing(state, agent))
        elif output is not None and output.get("status") != "ok":
            healthy = False
    known = [(e["code"], e["message"]) for e in state["errors"]]
    errors = [e for e in errors if (e["code"], e["message"]) not in known]
    return result(S.ROUTE_END, S.STATUS_COMPLETED if healthy else S.STATUS_COMPLETED_WITH_ERRORS, skipped + "every applicable agent has run", errors)


def supervisor_node(state):
    """Graph node. Returns only the fields it changes."""
    decision = decide(state)
    visits = state["supervisor_visits"] + 1
    routing = list(state["routing"]) + [{"visit": visits, "route": decision["route"], "reason": decision["reason"]}]
    return {"next_node": decision["route"], "status": decision["status"], "supervisor_visits": visits, "routing": routing,
            "errors": list(state["errors"]) + decision["errors"], "trace": list(state["trace"]) + [S.NODE_SUPERVISOR]}


def route_from_supervisor(state):
    """The conditional edge: reads the decision the supervisor stored."""
    return state["next_node"] if state["next_node"] in S.ROUTES else S.ROUTE_END
