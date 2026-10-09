"""Shared state for graph v0.1 (Day 4): everything the graph knows about ONE alert.

Rules the whole graph follows:
  * Nodes receive the state and return a dict with only the keys they change. They never mutate the state they were given.
  * Every field is overwritten, not merged. A node that extends a list returns the whole new list.
  * The alert is label-free. Labels, the answer key and the frozen set are not reachable from this package.

Fields (nothing is reserved for later agents):
  alert_id           text    id of the alert, copied from the alert record
  alert              dict    the label-free alert record the model would see (addresses, ports, protocol, time, detector score, features)
  status             text    "pending" -> "running" -> "completed" | "completed_with_errors" | "failed"   (the final graph status)
  next_node          text    the supervisor's last routing decision: "traffic_analyst", "c2_beacon_analyst", "enrichment_agent" or "end"
  supervisor_visits  int     how many times the supervisor ran. The loop guard stops the graph past MAX_SUPERVISOR_VISITS.
  routing            list    one entry per supervisor decision: {visit, route, reason}. Why each agent ran, was skipped, or the graph ended.
  evidence           list    one entry per tool call, in call order: {index, tool, arguments, ok, error, data}. Only what a tool returned.
  traffic_findings   dict    the traffic analyst's output, or None until it has run: {analyst, status, findings, tool_calls, tool_errors}
  beacon_findings    dict    the C2 beaconing analyst's output, or None if it did not run: {analyst, status, assessment, beacon_candidate, candidate_reason, basis, window_minutes, findings, limits, tool_calls, tool_errors}
  enrichment_findings dict   the enrichment agent's output, or None if it did not run: {agent, status, findings, not_consulted, unavailable, tool_calls, tool_errors}
  errors             list    {node, code, message[, tool]} for every node or tool failure. Empty on a clean run.
  trace              list    node names in the order they ran, for example ["supervisor", "traffic_analyst", "supervisor"]
  graph_version      text    "v0.1"
"""
from typing import Any, Dict, List, Optional, TypedDict

import triage_inputs

GRAPH_VERSION = "v0.1"
MAX_SUPERVISOR_VISITS = 5   # the longest normal path needs 4 visits: traffic, beacon, enrichment, end

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_COMPLETED_WITH_ERRORS = "completed_with_errors"
STATUS_FAILED = "failed"
TERMINAL_STATUSES = (STATUS_COMPLETED, STATUS_COMPLETED_WITH_ERRORS, STATUS_FAILED)
ALL_STATUSES = (STATUS_PENDING, STATUS_RUNNING) + TERMINAL_STATUSES

NODE_SUPERVISOR = "supervisor"
NODE_TRAFFIC_ANALYST = "traffic_analyst"
NODE_C2_BEACON_ANALYST = "c2_beacon_analyst"
NODE_ENRICHMENT_AGENT = "enrichment_agent"
ROUTE_END = "end"
ROUTES = (NODE_TRAFFIC_ANALYST, NODE_C2_BEACON_ANALYST, NODE_ENRICHMENT_AGENT, ROUTE_END)

REQUIRED_ALERT_KEYS = ("alert_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp")


class GraphState(TypedDict):
    alert_id: str
    alert: Dict[str, Any]
    status: str
    next_node: Optional[str]
    supervisor_visits: int
    routing: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    traffic_findings: Optional[Dict[str, Any]]
    beacon_findings: Optional[Dict[str, Any]]
    enrichment_findings: Optional[Dict[str, Any]]
    errors: List[Dict[str, Any]]
    trace: List[str]
    graph_version: str


STATE_KEYS = tuple(GraphState.__annotations__)


def alert_record(alert_row, store=None):
    """The label-free alert dict for one alert row (a pandas Series). Uses the Week 2 input builder, so hidden and forbidden columns are dropped."""
    if store is None:
        raise ValueError("a flow store is needed to build the alert record")
    return triage_inputs.build_model_input(alert_row, store)["alert"]


def new_state(alert):
    """A fresh state for one alert (a plain dict). Raises ValueError if the alert is unusable or carries an answer-bearing field."""
    if not isinstance(alert, dict):
        raise ValueError("alert must be a dict")
    missing = [k for k in REQUIRED_ALERT_KEYS if k not in alert or alert[k] is None]
    if missing:
        raise ValueError("alert is missing: " + ", ".join(missing))
    forbidden = sorted(k for k in alert if str(k).lower() in triage_inputs.FORBIDDEN_COLUMNS)
    if forbidden:
        raise ValueError("alert contains answer-bearing fields and was not accepted: " + ", ".join(forbidden))
    alert_id = alert["alert_id"]
    if not isinstance(alert_id, str) or alert_id.strip() == "":
        raise ValueError("alert_id must be non-empty text")
    return {"alert_id": alert_id, "alert": dict(alert), "status": STATUS_PENDING, "next_node": None, "supervisor_visits": 0, "routing": [], "evidence": [],
            "traffic_findings": None, "beacon_findings": None, "enrichment_findings": None, "errors": [], "trace": [], "graph_version": GRAPH_VERSION}


def validate_state(state):
    """Check the shape of a state. Returns the state, or raises ValueError naming the first problem."""
    if not isinstance(state, dict):
        raise ValueError("state must be a dict")
    missing = [k for k in STATE_KEYS if k not in state]
    if missing:
        raise ValueError("state is missing: " + ", ".join(missing))
    extra = sorted(set(state) - set(STATE_KEYS))
    if extra:
        raise ValueError("state has unknown fields: " + ", ".join(str(e) for e in extra))
    if not isinstance(state["alert_id"], str) or state["alert_id"] == "":
        raise ValueError("alert_id must be non-empty text")
    if not isinstance(state["alert"], dict):
        raise ValueError("alert must be a dict")
    if state["status"] not in ALL_STATUSES:
        raise ValueError("status must be one of: " + ", ".join(ALL_STATUSES))
    if state["next_node"] is not None and state["next_node"] not in ROUTES:
        raise ValueError("next_node must be None or one of: " + ", ".join(ROUTES))
    if isinstance(state["supervisor_visits"], bool) or not isinstance(state["supervisor_visits"], int) or state["supervisor_visits"] < 0:
        raise ValueError("supervisor_visits must be a non-negative integer")
    for name in ("routing", "evidence", "errors", "trace"):
        if not isinstance(state[name], list):
            raise ValueError(name + " must be a list")
    for name in ("traffic_findings", "beacon_findings", "enrichment_findings"):
        if state[name] is not None and not isinstance(state[name], dict):
            raise ValueError(name + " must be None or a dict")
    if state["graph_version"] != GRAPH_VERSION:
        raise ValueError("graph_version must be " + GRAPH_VERSION)
    return state
