"""The traffic analyst for graph v0: one node, deterministic, no LLM call.

It calls the Day 1 tools through the registry and turns what they returned into factual findings. A finding states a count or a share
that a tool returned, plus the index of the evidence entry it came from. It does not name an attack, pick a MITRE technique or give a verdict.

Tool calls (both over the alert's time window, default 5 minutes each side, the Week 2 context window):
  0. summarize_flows  ip = alert source, direction = src   what the source host did around the alert
  1. summarize_flows  ip = alert destination, direction = dst   who else was talking to the destination
A failed call is recorded as evidence and as an error. The analyst still reports what the other call returned.
Analyst status: "ok" (every call succeeded), "partial" (some did), "failed" (none did, or the node itself raised).
"""
import triage_inputs

from . import state as S

ANALYST_NAME = "traffic_analyst"
WINDOW_MINUTES = triage_inputs.CONTEXT_WINDOW_MINUTES


def plan_calls(alert):
    """The tool calls this analyst makes for one alert: a list of (tool, arguments). Pure; the same alert gives the same list."""
    around = alert["timestamp"]
    return [
        ("summarize_flows", {"ip": alert["src_ip"], "direction": "src", "around": around, "window_minutes": WINDOW_MINUTES}),
        ("summarize_flows", {"ip": alert["dst_ip"], "direction": "dst", "around": around, "window_minutes": WINDOW_MINUTES}),
    ]


def run_tools(registry, alert):
    """Make the planned calls. Returns (evidence, errors). Tools never raise; a failed envelope becomes an error entry."""
    evidence, errors = [], []
    for index, (tool, arguments) in enumerate(plan_calls(alert)):
        result = registry.call(tool, arguments)
        evidence.append({"index": index, "tool": tool, "arguments": arguments, "ok": bool(result.get("ok")), "error": result.get("error"), "data": result.get("data")})
        if not result.get("ok"):
            error = result.get("error") or {}
            errors.append({"node": ANALYST_NAME, "tool": tool, "code": error.get("code", "unknown"), "message": error.get("message", "")})
    return evidence, errors


def _share(part, whole):
    return round(part / whole, 4) if whole else None


def findings_from_evidence(alert, evidence):
    """Factual findings from the evidence that succeeded. Every number comes from a tool result."""
    findings = []
    for entry in evidence:
        if not entry["ok"] or entry["data"] is None:
            continue
        data, index, ip = entry["data"], entry["index"], entry["arguments"]["ip"]
        n = data["n_flows"]
        window = str(WINDOW_MINUTES) + " minutes either side of " + str(alert["timestamp"])
        if entry["arguments"]["direction"] == "src":
            if n == 0:
                findings.append({"kind": "no_source_flows", "evidence_index": index, "metrics": {"n_flows": 0},
                                 "statement": "The flow log has no flows from " + ip + " within " + window + "."})
                continue
            ports = data["top_destination_ports"]
            top = ports[0] if ports else None
            findings.append({"kind": "source_activity", "evidence_index": index,
                             "metrics": {"n_flows": n, "distinct_destination_ips": data["distinct_destination_ips"], "distinct_destination_ports": data["distinct_destination_ports"],
                                         "protocol_counts": data["protocol_counts"]},
                             "statement": ip + " started " + str(n) + " flow(s) within " + window + ", to " + str(data["distinct_destination_ips"]) + " destination address(es) and "
                                          + str(data["distinct_destination_ports"]) + " destination port(s)."})
            if top is not None:
                findings.append({"kind": "port_concentration", "evidence_index": index,
                                 "metrics": {"top_port": top["dst_port"], "top_port_flows": top["flows"], "top_port_share": _share(top["flows"], n)},
                                 "statement": "Destination port " + str(top["dst_port"]) + " took " + str(top["flows"]) + " of those " + str(n) + " flow(s)."})
        else:
            if n == 0:
                findings.append({"kind": "no_destination_flows", "evidence_index": index, "metrics": {"n_flows": 0},
                                 "statement": "The flow log has no flows to " + ip + " within " + window + "."})
                continue
            findings.append({"kind": "destination_fan_in", "evidence_index": index,
                             "metrics": {"n_flows": n, "distinct_source_ips": data["distinct_source_ips"]},
                             "statement": str(n) + " flow(s) went to " + ip + " within " + window + ", from " + str(data["distinct_source_ips"]) + " distinct source address(es)."})
    return findings


def analyst_status(evidence):
    ok = sum(1 for e in evidence if e["ok"])
    if ok == 0:
        return "failed"
    return "ok" if ok == len(evidence) else "partial"


def make_traffic_analyst(registry):
    """Build the graph node around a tool registry. The node never raises: a failure becomes a state update."""

    def traffic_analyst_node(state):
        evidence, errors = [], []
        try:
            evidence, errors = run_tools(registry, state["alert"])
            findings = findings_from_evidence(state["alert"], evidence)
            status = analyst_status(evidence)
        except Exception as error:  # the type is recorded, nothing else, so a bug cannot leak data into the state
            findings, status = [], "failed"
            errors = errors + [{"node": ANALYST_NAME, "code": "node_exception", "message": "the traffic analyst failed unexpectedly (" + type(error).__name__ + ")"}]
        output = {"analyst": ANALYST_NAME, "status": status, "findings": findings, "tool_calls": len(evidence), "tool_errors": len(errors)}
        return {"evidence": list(state["evidence"]) + evidence, "traffic_findings": output, "errors": list(state["errors"]) + errors,
                "trace": list(state["trace"]) + [S.NODE_TRAFFIC_ANALYST]}

    return traffic_analyst_node
