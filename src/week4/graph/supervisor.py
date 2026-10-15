"""Supervisor for graph v2: the v0.1 rules, unchanged, plus one rule.

  Memory enabled, the v0.1 rules would route to the verdict step, and the memory step has not run -> memory_node (once). Then the verdict step as before.

Everything else is delegated to agents.supervisor.decide, so with memory off every decision (route, status, reason, errors) is the v0.1 decision, byte for byte.
The v0.1 loop guard counts supervisor visits; the memory step adds one visit, which is subtracted before delegating so the v0.1 guard keeps its meaning, and v2 enforces its own limit of 6.
If memory was enabled and its step failed, a run that v0.1 would call "completed" ends as "completed_with_errors".
"""
import ablation_config as ablation
from agents import state as S1
from agents import supervisor as V1

from . import state as S2


def decide(state, disabled=()):
    """The v2 decision: {route, status, reason, errors}. Reads the state, changes nothing."""
    off = ablation.normalize(disabled)
    visits = state["supervisor_visits"]
    memory_ran = S2.NODE_MEMORY in state["trace"]
    terminal = state["status"] in S1.TERMINAL_STATUSES
    if not terminal and visits >= S2.MAX_SUPERVISOR_VISITS:
        text = "the supervisor ran " + str(visits) + " times"
        return {"route": S1.ROUTE_END, "status": S1.STATUS_FAILED, "reason": "loop guard: " + text, "errors": [{"node": S1.NODE_SUPERVISOR, "code": "loop_guard", "message": text + "; the graph was stopped"}]}
    view = dict(state, supervisor_visits=visits - (1 if memory_ran else 0), graph_version=S1.GRAPH_VERSION)
    decision = V1.decide(view, off)
    if decision["route"] == S1.NODE_VERDICT and state["memory_enabled"] and not memory_ran:
        return {"route": S2.NODE_MEMORY, "status": S1.STATUS_RUNNING, "errors": [],
                "reason": "incident memory is enabled: similar past training incidents are retrieved once before the verdict step. " + decision["reason"]}
    if decision["route"] == S1.ROUTE_END and decision["status"] == S1.STATUS_COMPLETED and state["memory_enabled"] and isinstance(state.get("memory"), dict) and state["memory"].get("status") == "error":
        return dict(decision, status=S1.STATUS_COMPLETED_WITH_ERRORS, reason=decision["reason"] + " The memory step failed (" + str(state["memory"].get("error_code")) + ").")
    return decision


def make_supervisor_node(disabled=()):
    off = ablation.normalize(disabled)

    def node(state):
        decision = decide(state, off)
        visits = state["supervisor_visits"] + 1
        entry = {"visit": visits, "route": decision["route"], "reason": decision["reason"]}
        if off:
            entry["disabled"] = list(off)
        return {"next_node": decision["route"], "status": decision["status"], "supervisor_visits": visits, "routing": list(state["routing"]) + [entry],
                "errors": list(state["errors"]) + decision["errors"], "trace": list(state["trace"]) + [S1.NODE_SUPERVISOR]}
    return node


supervisor_node = make_supervisor_node(())


def route_from_supervisor(state):
    return state["next_node"] if state["next_node"] in S2.ROUTES else S1.ROUTE_END
