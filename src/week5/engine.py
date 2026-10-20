"""The 'instrumented' graph engine: the Week 4 graph's edges driven by a plain loop, with a timer around every node.

week4.graph.build.run_offline already drives the same nodes and edges without LangGraph (it is the reference path of the Week 4 tests). This copy adds timing so a load test can report
per-agent time, and takes no decision of its own: the supervisor decides every step. A test checks that its final state equals run_offline's for the same alert and model.
The default engine for a real deployment is 'langgraph' (week4.graph.build.build_graph), which gives no per-node timing.
"""
import time

import ablation_config as ablation
from agents import state as S1
from week4.graph import build as B
from week4.graph import state as S2
from week4.graph.memory_node import memory_not_configured_node
from week4.graph.supervisor import make_supervisor_node, route_from_supervisor
from agents.verdict_node import verdict_not_configured_node


def run_instrumented(registry, alert, verdict_node=None, memory_node=None, memory_enabled=False, disabled=(), clock=time.perf_counter):
    """-> (final state, {node: {"calls": n, "seconds": s}}). Raises like run_offline."""
    disabled = ablation.normalize(disabled)
    nodes = B.specialist_nodes(registry)
    nodes[S2.NODE_MEMORY] = memory_node if memory_node is not None else memory_not_configured_node
    nodes[S1.NODE_VERDICT] = verdict_node if verdict_node is not None else verdict_not_configured_node
    supervisor = make_supervisor_node(disabled)
    timings = {}

    def timed(name, fn, state):
        started = clock()
        try:
            return fn(state)
        finally:
            entry = timings.setdefault(name, {"calls": 0, "seconds": 0.0})
            entry["calls"] += 1
            entry["seconds"] += clock() - started

    state = S2.new_state(alert, memory_enabled=memory_enabled)
    for _ in range(S2.RECURSION_LIMIT):
        state = {**state, **timed(S1.NODE_SUPERVISOR, supervisor, state)}
        route = route_from_supervisor(state)
        if route == S1.ROUTE_END:
            return S2.validate_state(state), {k: {"calls": v["calls"], "seconds": round(v["seconds"], 6)} for k, v in timings.items()}
        state = {**state, **timed(route, nodes[route], state)}
    raise RuntimeError("the instrumented driver hit the recursion limit")
