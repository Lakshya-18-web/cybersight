"""Supervisor for graph v0.1: a deterministic router. No LLM call.

The decision is a pure function of the state, re-derived at every visit. Rules, in order:
  0. State already terminal                                  -> end, status unchanged.
  1. Supervisor already ran MAX_SUPERVISOR_VISITS times      -> end, failed, error loop_guard.
  2. Traffic analyst not run yet                             -> traffic_analyst. (If it ran and left no findings: end, failed, error no_findings.)
  3. Traffic analyst failed                                  -> end, failed. There is no flow evidence to build on, so no other analyst runs.
        (Day 5: with the verdict step enabled, the verdict node still runs once first, so the run has a recorded outcome for the alert. It is told what failed. The final status stays failed.)
  4. Repeat contact, C2 beaconing analyst not run yet        -> c2_beacon_analyst.
        Repeat contact = the traffic analyst's source summary shows at least REPEAT_CONTACT_MIN_FLOWS flows from the alert source to the alert destination.
        This is a routing gate that saves work. It is not a detection threshold. With no repeat contact, or if the count is unknown, the beaconing analyst is skipped and the reason is logged.
  5. Enrichment agent not run yet                            -> enrichment_agent.
  6. Verdict step enabled (state["verdict_enabled"]) and not run yet -> verdict_node. Off by default; the Day 3/4 offline flows never reach this rule.
  7. Otherwise                                               -> end: completed if every agent that ran (the verdict node included, when enabled) finished ok, else completed_with_errors.
An agent that ran but left no findings behind is recorded as an error and is never routed to again.
Every agent is routed to at most once, so the longest path is supervisor, traffic, supervisor, beacon, supervisor, enrichment, supervisor, verdict, supervisor, end (5 visits with the verdict step, 4 without).
If the graph ends before the verdict node ran (loop guard, or an agent left no findings), state["verdict"] stays None: the supervisor never makes up a verdict.
Every decision is appended to state["routing"] with its reason.

Day 6 (optional, default off): a set of DISABLED specialists can be given to decide() / make_supervisor_node(). A disabled specialist is never routed to and its absence is not an error.
The configuration lives here, in the supervisor, not in the state, so the state shape and every default-off decision are exactly as before. When the set is not empty, each routing entry also
carries "disabled": [names], which is how the verdict prompt knows a specialist was switched off rather than skipped. Disabling the traffic analyst also removes the C2 beaconing analyst:
the repeat-contact gate reads the traffic analyst's evidence, there is none, so the gate cannot open (reason logged). See agents/ablation.py.
"""
import ablation_config as ablation

from . import state as S

REPEAT_CONTACT_MIN_FLOWS = 2
AGENT_FINDINGS = {S.NODE_TRAFFIC_ANALYST: "traffic_findings", S.NODE_C2_BEACON_ANALYST: "beacon_findings", S.NODE_ENRICHMENT_AGENT: "enrichment_findings", S.NODE_VERDICT: "verdict"}


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


def _verdict_due(state):
    """True when the optional verdict step is enabled and has not run yet."""
    return state["verdict_enabled"] is True and state["verdict"] is None and S.NODE_VERDICT not in state["trace"]


def _missing(state, agent):
    """The error for an agent that ran but left nothing behind."""
    names = {S.NODE_TRAFFIC_ANALYST: "traffic analyst", S.NODE_C2_BEACON_ANALYST: "C2 beaconing analyst", S.NODE_ENRICHMENT_AGENT: "enrichment agent", S.NODE_VERDICT: "verdict node"}
    return {"node": S.NODE_SUPERVISOR, "code": "no_findings", "message": "the " + names[agent] + " left no findings"}


DISPLAY_NAMES = {S.NODE_TRAFFIC_ANALYST: "traffic analyst", S.NODE_C2_BEACON_ANALYST: "C2 beaconing analyst", S.NODE_ENRICHMENT_AGENT: "enrichment agent", S.NODE_VERDICT: "verdict node"}


def decide(state, disabled=()):
    """The decision as a dict: route, status, reason, errors (new errors to add). Reads the state, changes nothing.
    disabled: specialists that must not run (default none). Names as in agents/ablation.py."""
    off = ablation.normalize(disabled)
    traffic_off, beacon_off, enrichment_off = (S.NODE_TRAFFIC_ANALYST in off), (S.NODE_C2_BEACON_ANALYST in off), (S.NODE_ENRICHMENT_AGENT in off)
    disabled_note = "".join(DISPLAY_NAMES[name] + " " + ablation.DISABLED_REASON + ". " for name in off)

    def result(route, status, reason, errors=None):
        return {"route": route, "status": status, "reason": reason, "errors": errors or []}

    if state["status"] in S.TERMINAL_STATUSES:
        return result(S.ROUTE_END, state["status"], "the run is already finished")
    if state["supervisor_visits"] >= S.MAX_SUPERVISOR_VISITS:
        return result(S.ROUTE_END, S.STATUS_FAILED, "loop guard: the supervisor ran " + str(state["supervisor_visits"]) + " times",
                      [{"node": S.NODE_SUPERVISOR, "code": "loop_guard", "message": "the supervisor ran " + str(state["supervisor_visits"]) + " times; the graph was stopped"}])
    traffic = state["traffic_findings"]
    if traffic is None and not traffic_off:
        if S.NODE_TRAFFIC_ANALYST in state["trace"]:
            return result(S.ROUTE_END, S.STATUS_FAILED, "the traffic analyst ran and left no findings", [_missing(state, S.NODE_TRAFFIC_ANALYST)])
        return result(S.NODE_TRAFFIC_ANALYST, S.STATUS_RUNNING, "every alert starts with the traffic analyst")
    if traffic is not None and traffic.get("status") not in ("ok", "partial"):
        if _verdict_due(state):
            return result(S.NODE_VERDICT, S.STATUS_RUNNING, "the traffic analysis produced no usable flow evidence, so no other analyst was run; the verdict step runs once to record the outcome with that gap")
        return result(S.ROUTE_END, S.STATUS_FAILED, "the traffic analysis produced no usable flow evidence, so no other agent was run")

    skipped = disabled_note
    if state["beacon_findings"] is None and S.NODE_C2_BEACON_ANALYST not in state["trace"] and not beacon_off:
        flows = None if traffic_off else repeat_contact_flows(state)
        if flows is not None and flows >= REPEAT_CONTACT_MIN_FLOWS:
            return result(S.NODE_C2_BEACON_ANALYST, S.STATUS_RUNNING, str(flows) + " flows from the source to the destination in the traffic window (gate: at least "
                          + str(REPEAT_CONTACT_MIN_FLOWS) + "), so the timing is worth examining")
        if traffic_off:
            why = "the traffic analyst is disabled in this configuration, so the source-to-destination flow count is not available"
        elif flows is None:
            why = "the source-to-destination flow count could not be read from the traffic evidence"
        else:
            why = "only " + str(flows) + " flow(s) from the source to the destination in the traffic window (gate: at least " + str(REPEAT_CONTACT_MIN_FLOWS) + ")"
        skipped = skipped + "C2 beaconing analyst skipped: " + why + ". "
    if state["enrichment_findings"] is None and S.NODE_ENRICHMENT_AGENT not in state["trace"] and not enrichment_off:
        return result(S.NODE_ENRICHMENT_AGENT, S.STATUS_RUNNING, skipped + "enrichment runs once after the specialists")

    if _verdict_due(state):
        return result(S.NODE_VERDICT, S.STATUS_RUNNING, skipped + "the verdict step runs once after the specialists")

    errors, healthy = [], True
    for agent in (S.NODE_C2_BEACON_ANALYST, S.NODE_ENRICHMENT_AGENT, S.NODE_TRAFFIC_ANALYST, S.NODE_VERDICT):
        if agent == S.NODE_VERDICT and not state["verdict_enabled"]:
            continue
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


def make_supervisor_node(disabled=()):
    """The graph node for a given set of disabled specialists (default none). Returns only the fields it changes."""
    off = ablation.normalize(disabled)

    def node(state):
        decision = decide(state, off)
        visits = state["supervisor_visits"] + 1
        entry = {"visit": visits, "route": decision["route"], "reason": decision["reason"]}
        if off:
            entry["disabled"] = list(off)   # only when something is disabled, so default-off routing records are exactly as before
        routing = list(state["routing"]) + [entry]
        return {"next_node": decision["route"], "status": decision["status"], "supervisor_visits": visits, "routing": routing,
                "errors": list(state["errors"]) + decision["errors"], "trace": list(state["trace"]) + [S.NODE_SUPERVISOR]}
    return node


supervisor_node = make_supervisor_node(())


def route_from_supervisor(state):
    """The conditional edge: reads the decision the supervisor stored."""
    return state["next_node"] if state["next_node"] in S.ROUTES else S.ROUTE_END
