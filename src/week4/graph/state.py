"""State for graph v2: every v0.1 field (unchanged meaning) plus two typed fields.

  memory_enabled  bool   the per-alert memory switch. False reproduces Week 3 behaviour.
  memory          dict   the incident-memory result, or None until the memory step ran (see validate_memory):
        {status "ok"|"empty"|"error"|"disabled", k_requested, k_returned,
         hits [{rank, memory_id, distance, label, source_split "train", source_ref {split, source_file, original_row}, manifest_sha256}],
         label_counts {label: n}, nearest_distance, filtered {...}, store {manifest_sha256, backend, ...}}
        or, for status "error": {status, error_code, error_detail}.   Memory is untrusted evidence: it never decides, closes or authorises anything.
  graph_version   "v2.0"
Limits: the supervisor may run MAX_SUPERVISOR_VISITS (6) times: traffic, beacon, enrichment, memory, verdict, end. v0.1 allowed 5; the one extra visit is the memory step.
"""
from typing import Any, Dict, List, Optional, TypedDict

from agents import state as S1

GRAPH_VERSION = "v2.0"
NODE_MEMORY = "memory_node"
MAX_SUPERVISOR_VISITS = 6
RECURSION_LIMIT = 2 * MAX_SUPERVISOR_VISITS + 4
ROUTES = S1.ROUTES + (NODE_MEMORY,)
MEMORY_STATUSES = ("disabled", "ok", "empty", "error")
HIT_KEYS = {"rank", "memory_id", "distance", "label", "source_split", "source_ref", "manifest_sha256"}
MEMORY_ERROR_CODES = ("bad_query", "isolation_violation", "store_error", "memory_exception", "memory_not_configured", "invalid_result")


class GraphStateV2(TypedDict):
    alert_id: str
    alert: Dict[str, Any]
    status: str
    verdict_enabled: bool
    next_node: Optional[str]
    supervisor_visits: int
    routing: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    traffic_findings: Optional[Dict[str, Any]]
    beacon_findings: Optional[Dict[str, Any]]
    enrichment_findings: Optional[Dict[str, Any]]
    verdict: Optional[Dict[str, Any]]
    errors: List[Dict[str, Any]]
    trace: List[str]
    graph_version: str
    memory_enabled: bool
    memory: Optional[Dict[str, Any]]


STATE_KEYS = tuple(GraphStateV2.__annotations__)
V1_KEYS = tuple(S1.STATE_KEYS)


def new_state(alert, memory_enabled=False):
    """A fresh v2 state (verdict step always on: a v2 run exists to produce a verdict). Raises ValueError for an unusable alert or a non-bool switch."""
    if not isinstance(memory_enabled, bool):
        raise ValueError("memory_enabled must be True or False")
    state = S1.new_state(alert, verdict_enabled=True)
    state["graph_version"] = GRAPH_VERSION
    state["memory_enabled"] = memory_enabled
    state["memory"] = None
    return state


def validate_memory(memory):
    """None, or a well-formed memory result. Returns it, or raises ValueError naming the first problem."""
    if memory is None:
        return None
    if not isinstance(memory, dict):
        raise ValueError("memory must be None or a dict")
    status = memory.get("status")
    if status not in MEMORY_STATUSES:
        raise ValueError("memory.status must be one of: " + ", ".join(MEMORY_STATUSES))
    if status == "disabled":
        return memory
    if status == "error":
        if memory.get("error_code") not in MEMORY_ERROR_CODES or not isinstance(memory.get("error_detail"), str):
            raise ValueError("a failed memory step needs a known error_code and a text error_detail")
        return memory
    hits = memory.get("hits")
    if not isinstance(hits, list) or not isinstance(memory.get("label_counts"), dict) or not isinstance(memory.get("store"), dict):
        raise ValueError("memory needs hits, label_counts and store")
    if (status == "ok") != bool(hits):
        raise ValueError("memory.status must be ok exactly when there are hits")
    if memory.get("k_returned") != len(hits) or not isinstance(memory.get("k_requested"), int):
        raise ValueError("memory.k_returned must equal the number of hits")
    for rank, hit in enumerate(hits, 1):
        if not isinstance(hit, dict) or set(hit) != HIT_KEYS or hit["rank"] != rank:
            raise ValueError("memory hit " + str(rank) + " is malformed")
        if hit["source_split"] != "train" or (hit["source_ref"] or {}).get("split") != "train":
            raise ValueError("memory hit " + str(rank) + " is not from the train split")
    if sum(memory["label_counts"].values()) != len(hits):
        raise ValueError("memory.label_counts does not add up to the number of hits")
    if not isinstance(memory["store"].get("manifest_sha256"), str):
        raise ValueError("memory.store needs the manifest hash")
    return memory


def validate_state(state):
    """Check the shape of a v2 state. Returns it, or raises ValueError naming the first problem."""
    if not isinstance(state, dict):
        raise ValueError("state must be a dict")
    missing = [k for k in STATE_KEYS if k not in state]
    if missing:
        raise ValueError("state is missing: " + ", ".join(missing))
    extra = sorted(set(state) - set(STATE_KEYS))
    if extra:
        raise ValueError("state has unknown fields: " + ", ".join(str(e) for e in extra))
    if state["graph_version"] != GRAPH_VERSION:
        raise ValueError("graph_version must be " + GRAPH_VERSION)
    if state["next_node"] is not None and state["next_node"] not in ROUTES:
        raise ValueError("next_node must be None or one of: " + ", ".join(ROUTES))
    if not isinstance(state["memory_enabled"], bool):
        raise ValueError("memory_enabled must be True or False")
    if state["verdict_enabled"] is not True:
        raise ValueError("a v2 state always has verdict_enabled True")
    visits = state["supervisor_visits"]
    if isinstance(visits, int) and not isinstance(visits, bool) and visits > MAX_SUPERVISOR_VISITS:
        raise ValueError("supervisor_visits is above the v2 limit")
    validate_memory(state["memory"])
    if state["memory"] is not None and not state["memory_enabled"] and state["memory"].get("status") != "disabled":
        raise ValueError("memory results are only allowed when memory is enabled")
    view = {k: state[k] for k in V1_KEYS}
    view["graph_version"] = S1.GRAPH_VERSION
    if view["next_node"] == NODE_MEMORY:
        view["next_node"] = None
    S1.validate_state(view)
    return state
