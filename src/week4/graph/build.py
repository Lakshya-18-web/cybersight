"""Wiring and running graph v2.

  build_graph(registry, verdict_node, memory_node, disabled)   the LangGraph graph (LangGraph is imported here, so everything else works without it)
  run_alert(graph, alert, memory_enabled)                      one alert through a compiled graph -> final v2 state
  run_offline(registry, alert, ...)                            the same edges driven by a plain loop (no LangGraph): the reference path for offline tests

      START -> supervisor --(route)--> traffic_analyst | c2_beacon_analyst | enrichment_agent | memory_node | verdict_node -> supervisor ... -> END

Risk routing and proposals are NOT graph nodes: route_final() applies the policy to the finished state (pure function), so the graph keeps its v0.1 shape plus the one memory node.
"""
import ablation_config as ablation
from agents import state as S1
from agents.c2_beacon_analyst import make_c2_beacon_analyst
from agents.enrichment_agent import make_enrichment_agent
from agents.traffic_analyst import make_traffic_analyst
from agents.verdict_node import verdict_not_configured_node

from week4 import policy as policy_module

from . import state as S2
from .memory_node import memory_not_configured_node
from .supervisor import make_supervisor_node, route_from_supervisor


def specialist_nodes(registry):
    return {S1.NODE_TRAFFIC_ANALYST: make_traffic_analyst(registry), S1.NODE_C2_BEACON_ANALYST: make_c2_beacon_analyst(registry),
            S1.NODE_ENRICHMENT_AGENT: make_enrichment_agent(registry)}


def build_graph(registry, verdict_node=None, memory_node=None, disabled=()):
    disabled = ablation.normalize(disabled)
    try:
        from langgraph.graph import StateGraph, START, END
    except ImportError as error:
        raise ImportError("LangGraph is not installed. Install it with: pip install -r requirements-week3.txt") from error
    nodes = specialist_nodes(registry)
    builder = StateGraph(S2.GraphStateV2)
    builder.add_node(S1.NODE_SUPERVISOR, make_supervisor_node(disabled))
    for name, fn in nodes.items():
        builder.add_node(name, fn)
    builder.add_node(S2.NODE_MEMORY, memory_node if memory_node is not None else memory_not_configured_node)
    builder.add_node(S1.NODE_VERDICT, verdict_node if verdict_node is not None else verdict_not_configured_node)
    builder.add_edge(START, S1.NODE_SUPERVISOR)
    mapping = {name: name for name in S2.ROUTES if name != S1.ROUTE_END}
    mapping[S1.ROUTE_END] = END
    builder.add_conditional_edges(S1.NODE_SUPERVISOR, route_from_supervisor, mapping)
    for name in list(nodes) + [S2.NODE_MEMORY, S1.NODE_VERDICT]:
        builder.add_edge(name, S1.NODE_SUPERVISOR)
    return builder.compile()


def run_alert(graph, alert, memory_enabled=False):
    state = S2.new_state(alert, memory_enabled=memory_enabled)
    final = graph.invoke(state, config={"recursion_limit": S2.RECURSION_LIMIT})
    return S2.validate_state(dict(final))


def run_offline(registry, alert, verdict_node=None, memory_node=None, memory_enabled=False, disabled=()):
    """The graph's edges by hand: supervisor, then the routed node, until 'end'. Same nodes, same state, no LangGraph."""
    disabled = ablation.normalize(disabled)
    nodes = specialist_nodes(registry)
    nodes[S2.NODE_MEMORY] = memory_node if memory_node is not None else memory_not_configured_node
    nodes[S1.NODE_VERDICT] = verdict_node if verdict_node is not None else verdict_not_configured_node
    supervisor = make_supervisor_node(disabled)
    state = S2.new_state(alert, memory_enabled=memory_enabled)
    for _ in range(S2.RECURSION_LIMIT):
        state = {**state, **supervisor(state)}
        route = route_from_supervisor(state)
        if route == S1.ROUTE_END:
            return S2.validate_state(state)
        state = {**state, **nodes[route](state)}
    raise RuntimeError("the offline driver hit the recursion limit")


def route_final(policy, state):
    """Apply the risk policy to a finished state. -> {routing, actions, inputs}. Raises PolicyError when no policy is given (fail closed)."""
    return policy_module.route_case(policy, state)
