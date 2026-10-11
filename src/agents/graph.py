"""Graph v0.1, wired with LangGraph.

    START -> supervisor --(route)--> traffic_analyst    -> supervisor
                                 --> c2_beacon_analyst  -> supervisor
                                 --> enrichment_agent   -> supervisor
                                 --> verdict_node       -> supervisor     (Day 5, optional: only reached when the state has verdict_enabled)
                                 --> END

The supervisor decides each time (see supervisor.py for the rules); every agent always returns to the supervisor; the supervisor ends the run. LangGraph is imported when the
graph is built, so the nodes and state can be used and tested without it. Install it with:  pip install -r requirements-week3.txt
"""
import ablation_config as ablation

from . import state as S
from .supervisor import supervisor_node, make_supervisor_node, route_from_supervisor
from .traffic_analyst import make_traffic_analyst
from .c2_beacon_analyst import make_c2_beacon_analyst
from .enrichment_agent import make_enrichment_agent
from .verdict_node import verdict_not_configured_node

# The longest normal path is 5 supervisor visits and 4 agent runs (9 steps, with the verdict step); the guard allows MAX_SUPERVISOR_VISITS. This limit leaves room and still stops a runaway.
RECURSION_LIMIT = 2 * S.MAX_SUPERVISOR_VISITS + 4


def build_graph(registry, verdict_node=None, disabled=()):
    """Compile the graph around a tool registry. verdict_node is the Day 5 node from make_verdict_node (it holds the injected model call); without it,
    the verdict slot records an explicit "verdict_not_configured" failure if a state asks for a verdict. The graph is the same either way.
    disabled (Day 6, default none): specialists the supervisor must never route to (agents/ablation.py). The graph's nodes and edges do not change; only the supervisor's decisions do.
    Raises ValueError for a name that cannot be disabled, and ImportError with the install command if LangGraph is missing."""
    disabled = ablation.normalize(disabled)
    try:
        from langgraph.graph import StateGraph, START, END
    except ImportError as error:
        raise ImportError("LangGraph is not installed. Install it with: pip install -r requirements-week3.txt") from error
    builder = StateGraph(S.GraphState)
    builder.add_node(S.NODE_SUPERVISOR, supervisor_node if not disabled else make_supervisor_node(disabled))
    builder.add_node(S.NODE_TRAFFIC_ANALYST, make_traffic_analyst(registry))
    builder.add_node(S.NODE_C2_BEACON_ANALYST, make_c2_beacon_analyst(registry))
    builder.add_node(S.NODE_ENRICHMENT_AGENT, make_enrichment_agent(registry))
    builder.add_node(S.NODE_VERDICT, verdict_node if verdict_node is not None else verdict_not_configured_node)
    builder.add_edge(START, S.NODE_SUPERVISOR)
    builder.add_conditional_edges(S.NODE_SUPERVISOR, route_from_supervisor, {S.NODE_TRAFFIC_ANALYST: S.NODE_TRAFFIC_ANALYST, S.NODE_C2_BEACON_ANALYST: S.NODE_C2_BEACON_ANALYST,
                                                                                  S.NODE_ENRICHMENT_AGENT: S.NODE_ENRICHMENT_AGENT, S.NODE_VERDICT: S.NODE_VERDICT, S.ROUTE_END: END})
    for agent in (S.NODE_TRAFFIC_ANALYST, S.NODE_C2_BEACON_ANALYST, S.NODE_ENRICHMENT_AGENT, S.NODE_VERDICT):
        builder.add_edge(agent, S.NODE_SUPERVISOR)
    return builder.compile()


def run_alert(graph, alert, verdict_enabled=False):
    """Run one alert through a compiled graph. Returns the final state. Raises ValueError for an unusable alert, before the graph starts.
    verdict_enabled=True turns on the verdict step for this alert (default off, so the offline Day 3/4 runs are unchanged)."""
    state = S.new_state(alert, verdict_enabled=verdict_enabled)
    final = graph.invoke(state, config={"recursion_limit": RECURSION_LIMIT})
    return S.validate_state(dict(final))
