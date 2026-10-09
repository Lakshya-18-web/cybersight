"""The C2 beaconing analyst for graph v0.1: one node, deterministic, no LLM call.

It looks at the timing of repeated contact between the alert source and destination, using only the beacon_stats tool, and says what that timing
does and does not support. It never says that command-and-control (C2) is confirmed: regular timing is also what update checks, monitoring agents
and keep-alives look like, and flow timing alone cannot tell them apart.

Tool calls (window: BEACON_WINDOW_MINUTES either side of the alert time, wider than the traffic analyst's because beacons can be slow):
  0. beacon_stats  src_ip, dst_ip                      all ports between the pair
  1. beacon_stats  src_ip, dst_ip, dst_port = alert's  the same pair on the alert's destination port
The assessment uses the first call that succeeded, so one failed call does not lose the analysis. Assessments:
  no_flows, insufficient_data (fewer than 4 flows, the tool's own limit), inconclusive (timestamps too coarse or statistics undefined),
  regular_intervals, mixed_intervals, irregular_intervals.
The cut-offs below are fixed descriptive constants chosen in advance. They were not tuned on any alert or label, and they are not detection thresholds.

beacon_candidate (true/false) is a stricter flag the enrichment agent uses to decide whether ATT&CK reference material is worth looking up. It is true only when the
assessment is regular_intervals AND at least PORT_CONSISTENCY_MIN_SHARE of the pair's flows used the alert's destination port. Regular timing alone is not enough:
an automated scan sends flows at a steady rate too, but spreads them over many ports. "Candidate" means "worth a closer look", never "confirmed".
"""
from . import state as S
from . import common

ANALYST_NAME = "c2_beacon_analyst"
BEACON_WINDOW_MINUTES = 60
REGULAR_CV_MAX = 0.2         # coefficient of variation of the gaps at or below this ...
REGULAR_SHARE_MIN = 0.8      # ... and at least this share of gaps within 10% of the median -> regular_intervals
IRREGULAR_CV_MIN = 0.5       # coefficient of variation at or above this ...
IRREGULAR_SHARE_MAX = 0.5    # ... and at most this share within 10% of the median -> irregular_intervals
PORT_CONSISTENCY_MIN_SHARE = 0.5   # beacon_candidate also needs at least this share of the pair's flows on the alert's destination port

LIMITS = [
    "Only flow timing and flow size were examined. No payload, destination reputation, process or user information was available.",
    "Periodic timing alone does not establish command-and-control activity; software updates, monitoring and keep-alive traffic are also periodic.",
    "Only flows within " + str(BEACON_WINDOW_MINUTES) + " minutes either side of the alert time were examined.",
]
DISCLAIMER = "This does not show that the traffic is command-and-control."


def plan_calls(alert):
    """The tool calls for one alert. Pure; the same alert gives the same list."""
    pair = {"src_ip": alert["src_ip"], "dst_ip": alert["dst_ip"], "around": alert["timestamp"], "window_minutes": BEACON_WINDOW_MINUTES}
    return [("beacon_stats", dict(pair)), ("beacon_stats", dict(pair, dst_port=int(alert["dst_port"]) if float(alert["dst_port"]).is_integer() else alert["dst_port"]))]


def valid_beacon_data(data):
    """True when a beacon_stats answer has the fields the analysis reads."""
    if not isinstance(data, dict):
        return False
    if isinstance(data.get("n_flows"), bool) or not isinstance(data.get("n_flows"), int) or data["n_flows"] < 0:
        return False
    if not isinstance(data.get("sufficient_for_interval_stats"), bool):
        return False
    intervals = data.get("intervals_seconds")
    return intervals is None or isinstance(intervals, dict)


def assess(data):
    """(assessment, reason) from one valid beacon_stats answer."""
    n = data["n_flows"]
    if n == 0:
        return "no_flows", "no flows between the pair in the window"
    if not data["sufficient_for_interval_stats"] or data["intervals_seconds"] is None:
        return "insufficient_data", "only " + str(n) + " flow(s); at least 4 are needed to describe interval regularity"
    iv = data["intervals_seconds"]
    cv, share = common.as_number(iv.get("cv")), common.as_number(iv.get("share_within_10pct_of_median"))
    if iv.get("caveat"):
        return "inconclusive", "timestamps are too coarse for interval statistics (" + str(iv["caveat"]) + ")"
    if cv is None or share is None:
        return "inconclusive", "the interval statistics are not defined for these flows"
    if cv <= REGULAR_CV_MAX and share >= REGULAR_SHARE_MIN:
        return "regular_intervals", "low variation in the gaps between flows"
    if cv >= IRREGULAR_CV_MIN and share <= IRREGULAR_SHARE_MAX:
        return "irregular_intervals", "high variation in the gaps between flows"
    return "mixed_intervals", "the gaps vary more than a fixed timer would give, but not wildly"


def _statement(assessment, alert, data, reason):
    pair = alert["src_ip"] + " and " + alert["dst_ip"]
    n = data["n_flows"]
    if assessment in ("no_flows", "insufficient_data", "inconclusive"):
        return "Between " + pair + ": " + reason + ". Nothing can be said about periodicity from this."
    iv = data["intervals_seconds"]
    detail = (str(n) + " flows between " + pair + " have gaps with median " + str(iv.get("median")) + " s, coefficient of variation " + str(iv.get("cv"))
              + "; the share of gaps within 10% of the median is " + str(iv.get("share_within_10pct_of_median")))
    if assessment == "regular_intervals":
        return detail + ". That timing is consistent with periodic traffic. " + DISCLAIMER
    if assessment == "irregular_intervals":
        return detail + ". That timing does not look periodic."
    return detail + ". That timing is neither clearly periodic nor clearly irregular."


def _derived_cv(stats):
    if not isinstance(stats, dict):
        return None
    mean, std = common.as_number(stats.get("mean")), common.as_number(stats.get("std"))
    if mean is None or std is None or mean <= 0:
        return None
    return round(std / mean, 4)


def build_findings(alert, evidence):
    """(assessment, basis, findings, candidate, candidate_reason) from the evidence. Only successful, valid calls are used; every number comes from a tool answer."""
    usable = [e for e in evidence if e["ok"] and valid_beacon_data(e["data"])]
    findings, port_share = [], None
    if not usable:
        return "inconclusive", None, findings, False, "no usable beacon_stats answer"
    chosen = usable[0]
    basis = "pair" if "dst_port" not in chosen["arguments"] else "pair_on_destination_port"
    data = chosen["data"]
    assessment, reason = assess(data)
    iv = data.get("intervals_seconds") or {}
    metrics = {"n_flows": data["n_flows"], "interval_count": iv.get("count"), "mean_seconds": iv.get("mean"), "median_seconds": iv.get("median"), "std_seconds": iv.get("std"),
               "cv": iv.get("cv"), "share_within_10pct_of_median": iv.get("share_within_10pct_of_median"), "zero_length_intervals": iv.get("zero_length_intervals"),
               "span_seconds": data.get("span_seconds")}
    findings.append({"kind": "beacon_timing", "evidence_index": chosen["index"], "basis": basis, "metrics": metrics,
                     "statement": "Timing of flows between " + alert["src_ip"] + " and " + alert["dst_ip"] + (" on port " + str(alert["dst_port"]) if basis != "pair" else "")
                                  + " within " + str(BEACON_WINDOW_MINUTES) + " minutes either side of the alert: " + str(data["n_flows"]) + " flow(s)."})
    fb = data.get("forward_bytes")
    cv_bytes = _derived_cv(fb)
    if cv_bytes is not None:
        findings.append({"kind": "beacon_size_regularity", "evidence_index": chosen["index"], "basis": basis,
                         "metrics": {"forward_bytes_mean": fb.get("mean"), "forward_bytes_std": fb.get("std"), "forward_bytes_cv": cv_bytes, "cv_source": "std divided by mean, both from the tool"},
                         "statement": "Forward bytes per flow have mean " + str(fb.get("mean")) + " and a coefficient of variation of " + str(cv_bytes) + "."})
    if len(usable) == 2:
        pair_n, port_n = usable[0]["data"]["n_flows"], usable[1]["data"]["n_flows"]
        if "dst_port" not in usable[0]["arguments"] and "dst_port" in usable[1]["arguments"] and pair_n > 0:
            port_share = round(port_n / pair_n, 4)
            findings.append({"kind": "port_scope", "evidence_index": usable[1]["index"], "basis": "pair_on_destination_port",
                             "metrics": {"pair_flows": pair_n, "pair_flows_on_alert_port": port_n, "share_on_alert_port": round(port_n / pair_n, 4)},
                             "statement": str(port_n) + " of the " + str(pair_n) + " flows between the pair used destination port " + str(alert["dst_port"]) + "."})
    candidate, candidate_reason = False, "the assessment is " + assessment + ", not regular_intervals"
    if assessment == "regular_intervals":
        if port_share is None:
            candidate_reason = "regular intervals, but the share of flows on the alert's destination port is unknown"
        elif port_share < PORT_CONSISTENCY_MIN_SHARE:
            candidate_reason = "regular intervals, but only " + str(port_share) + " of the pair's flows used the alert's destination port, so the traffic is spread over several ports"
        else:
            candidate, candidate_reason = True, "regular intervals on a consistent destination port (share " + str(port_share) + ")"
    findings.append({"kind": "beacon_assessment", "evidence_index": chosen["index"], "basis": basis, "metrics": {"assessment": assessment, "reason": reason, "beacon_candidate": candidate},
                     "statement": _statement(assessment, alert, data, reason)})
    return assessment, basis, findings, candidate, candidate_reason


def make_c2_beacon_analyst(registry):
    """Build the graph node around a tool registry. The node never raises: a failure becomes a state update."""

    def c2_beacon_analyst_node(state):
        offset = len(state["evidence"])
        evidence, errors = [], []
        try:
            for i, (tool, arguments) in enumerate(plan_calls(state["alert"])):
                entry, error = common.call_tool(registry, ANALYST_NAME, tool, arguments, offset + i)
                if entry["ok"] and not valid_beacon_data(entry["data"]):
                    entry, error = (dict(entry, ok=False, error={"code": common.CODE_INVALID_RESULT, "message": "the beacon_stats answer is missing fields"}, data=None),
                                    {"node": ANALYST_NAME, "tool": tool, "code": common.CODE_INVALID_RESULT, "message": "the beacon_stats answer is missing fields"})
                evidence.append(entry)
                if error is not None:
                    errors.append(error)
            assessment, basis, findings, candidate, candidate_reason = build_findings(state["alert"], evidence)
            status = common.agent_status(evidence)
        except Exception as error:  # the type is recorded, nothing else
            assessment, basis, findings, status, candidate, candidate_reason = "inconclusive", None, [], "failed", False, "the analysis did not complete"
            errors = errors + [{"node": ANALYST_NAME, "code": "node_exception", "message": "the C2 beaconing analyst failed unexpectedly (" + type(error).__name__ + ")"}]
        output = {"analyst": ANALYST_NAME, "status": status, "assessment": assessment, "beacon_candidate": candidate, "candidate_reason": candidate_reason, "basis": basis, "window_minutes": BEACON_WINDOW_MINUTES, "findings": findings,
                  "limits": list(LIMITS), "tool_calls": len(evidence), "tool_errors": len(errors)}
        return {"evidence": list(state["evidence"]) + evidence, "beacon_findings": output, "errors": list(state["errors"]) + errors, "trace": list(state["trace"]) + [S.NODE_C2_BEACON_ANALYST]}

    return c2_beacon_analyst_node


