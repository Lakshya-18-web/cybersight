"""Graph v0.1, wired with LangGraph.

    START -> supervisor --(route)--> traffic_analyst    -> supervisor
                                 --> c2_beacon_analyst  -> supervisor
                                 --> enrichment_agent   -> supervisor
                                 --> END

The supervisor decides each time (see supervisor.py for the rules); every agent always returns to the supervisor; the supervisor ends the run. LangGraph is imported when the
graph is built, so the nodes and state can be used and tested without it. Install it with:  pip install -r requirements-week3.txt
"""
from . import state as S
from .supervisor import supervisor_node, route_from_supervisor
from .traffic_analyst import make_traffic_analyst
from .c2_beacon_analyst import make_c2_beacon_analyst
from .enrichment_agent import make_enrichment_agent

# The longest normal path is 4 supervisor visits and 3 agent runs (7 steps); the guard allows MAX_SUPERVISOR_VISITS. This limit leaves room and still stops a runaway.
RECURSION_LIMIT = 2 * S.MAX_SUPERVISOR_VISITS + 4


def build_graph(registry):
    """Compile graph v0 around a tool registry. Raises ImportError with the install command if LangGraph is missing."""
    try:
        from langgraph.graph import StateGraph, START, END
    except ImportError as error:
        raise ImportError("LangGraph is not installed. Install it with: pip install -r requirements-week3.txt") from error
    builder = StateGraph(S.GraphState)
    builder.add_node(S.NODE_SUPERVISOR, supervisor_node)
    builder.add_node(S.NODE_TRAFFIC_ANALYST, make_traffic_analyst(registry))
    builder.add_node(S.NODE_C2_BEACON_ANALYST, make_c2_beacon_analyst(registry))
    builder.add_node(S.NODE_ENRICHMENT_AGENT, make_enrichment_agent(registry))
    builder.add_edge(START, S.NODE_SUPERVISOR)
    builder.add_conditional_edges(S.NODE_SUPERVISOR, route_from_supervisor, {S.NODE_TRAFFIC_ANALYST: S.NODE_TRAFFIC_ANALYST, S.NODE_C2_BEACON_ANALYST: S.NODE_C2_BEACON_ANALYST,
                                                                                  S.NODE_ENRICHMENT_AGENT: S.NODE_ENRICHMENT_AGENT, S.ROUTE_END: END})
    for agent in (S.NODE_TRAFFIC_ANALYST, S.NODE_C2_BEACON_ANALYST, S.NODE_ENRICHMENT_AGENT):
        builder.add_edge(agent, S.NODE_SUPERVISOR)
    return builder.compile()


def run_alert(graph, alert):
    """Run one alert through a compiled graph. Returns the final state. Raises ValueError for an unusable alert, before the graph starts."""
    state = S.new_state(alert)
    final = graph.invoke(state, config={"recursion_limit": RECURSION_LIMIT})
    return S.validate_state(dict(final))
