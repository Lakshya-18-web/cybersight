"""Risk routing: a transparent, configurable policy that decides, for one finished case, auto_close | escalate | needs_review, and which containment actions to PROPOSE.

Nothing here calls a model, a database or the network. The decision is a pure function of the inputs and the policy file (config/risk_policy.json), so it can be replayed and audited.
Every decision carries the rule ids that fired, the policy version and the policy file's sha256.

Principles (each is tested):
  * Fail closed. A missing, unreadable or invalid policy raises PolicyError; there is no built-in fallback policy. An unusable verdict, a missing detector score, an evidence gap or a graph error
    never produces auto_close: the case goes to a person (needs_review).
  * Auto-close is narrow: only a complete BENIGN verdict, a detector score at or below the policy ceiling, healthy specialists, no graph errors, and (when memory is on) a working memory step.
  * Memory can only RAISE caution. If the retrieved neighbours look like attacks and the verdict is benign, the case is escalated. Nothing in memory can lower a decision, close a case or create a
    containment action: proposals come from the verdict alone.
  * Proposals are only proposals. A proposal needs a human approval (approval.py) and is never executed against a real system; there is no such code in this project.
"""
import hashlib
import json
import math
import os

import verdict_schema

POLICY_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "config", "risk_policy.json")

AUTO_CLOSE, ESCALATE, NEEDS_REVIEW = "auto_close", "escalate", "needs_review"
DECISIONS = (AUTO_CLOSE, ESCALATE, NEEDS_REVIEW)
RISKS = ("low", "medium", "high", "unknown")
ACTION_TYPES = ("block_source_ip", "isolate_host", "rate_limit_source", "increase_monitoring")
SEVERITY_ORDER = ("none", "low", "medium", "high", "critical")
CAUTION = {AUTO_CLOSE: 0, NEEDS_REVIEW: 1, ESCALATE: 2}
SPECIALIST_STATUSES = ("ok", "partial", "failed", "not_run", "disabled")


class PolicyError(Exception):
    """The policy is missing or invalid. Routing refuses to run without one."""


def _normalised_bytes(raw):
    return raw.replace(b"\r\n", b"\n")


class Policy:
    def __init__(self, data, sha256):
        self.data = data
        self.sha256 = sha256
        self.version = data["policy_version"]

    def __getitem__(self, key):
        return self.data[key]


def _need(cond, message):
    if not cond:
        raise PolicyError("invalid risk policy: " + message)


def _exact_keys(obj, keys, where):
    _need(isinstance(obj, dict), where + " must be an object")
    missing, extra = sorted(set(keys) - set(obj)), sorted(set(obj) - set(keys))
    _need(not missing, where + " is missing " + ", ".join(missing))
    _need(not extra, where + " has unknown keys " + ", ".join(extra))


def _unit_number(value, where):
    _need(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0 <= value <= 1, where + " must be a number from 0 to 1")


def validate(data):
    _exact_keys(data, ["policy_version", "description", "auto_close", "memory", "severity_to_risk", "containment_proposals"], "policy")
    _need(isinstance(data["policy_version"], str) and data["policy_version"].strip(), "policy_version must be text")
    ac = data["auto_close"]
    _exact_keys(ac, ["max_detector_score", "require_verdict_status", "require_traffic_status", "allowed_beacon_statuses", "allowed_enrichment_statuses", "max_graph_errors",
                     "require_memory_ok_when_enabled"], "auto_close")
    _unit_number(ac["max_detector_score"], "auto_close.max_detector_score")
    _need(ac["require_verdict_status"] == "ok", "auto_close.require_verdict_status must be 'ok'")
    for key in ("require_traffic_status", "allowed_beacon_statuses", "allowed_enrichment_statuses"):
        _need(isinstance(ac[key], list) and ac[key] and all(s in SPECIALIST_STATUSES for s in ac[key]), "auto_close." + key + " must list known specialist statuses")
    _need("failed" not in ac["require_traffic_status"], "a failed traffic analysis can never allow auto_close")
    _need(isinstance(ac["max_graph_errors"], int) and not isinstance(ac["max_graph_errors"], bool) and ac["max_graph_errors"] >= 0, "auto_close.max_graph_errors must be an integer >= 0")
    _need(isinstance(ac["require_memory_ok_when_enabled"], bool), "auto_close.require_memory_ok_when_enabled must be true or false")
    mem = data["memory"]
    _exact_keys(mem, ["min_hits", "min_attack_neighbour_share", "can_only_raise_risk"], "memory")
    _need(isinstance(mem["min_hits"], int) and not isinstance(mem["min_hits"], bool) and mem["min_hits"] >= 1, "memory.min_hits must be an integer >= 1")
    _unit_number(mem["min_attack_neighbour_share"], "memory.min_attack_neighbour_share")
    _need(mem["can_only_raise_risk"] is True, "memory.can_only_raise_risk must be true: memory may never lower caution")
    s2r = data["severity_to_risk"]
    _exact_keys(s2r, list(SEVERITY_ORDER), "severity_to_risk")
    _need(all(v in ("low", "medium", "high") for v in s2r.values()), "severity_to_risk values must be low, medium or high")
    cp = data["containment_proposals"]
    _exact_keys(cp, ["min_severity_for_containment", "monitoring_action", "by_attack_type"], "containment_proposals")
    _need(cp["min_severity_for_containment"] in SEVERITY_ORDER[2:], "containment_proposals.min_severity_for_containment must be medium, high or critical")
    _need(cp["monitoring_action"] in ACTION_TYPES, "containment_proposals.monitoring_action is not a known action type")
    _need(isinstance(cp["by_attack_type"], dict), "containment_proposals.by_attack_type must be an object")
    for attack, action in cp["by_attack_type"].items():
        _need(attack in verdict_schema.ATTACK_TYPES and attack != "BENIGN", "containment_proposals.by_attack_type has an unknown attack type: " + str(attack))
        _need(action in ACTION_TYPES, "containment_proposals.by_attack_type[" + attack + "] is not a known action type")
    return data


def load_policy(path=None):
    """Read, validate and hash the policy file. Raises PolicyError (never falls back to a default)."""
    path = path or os.environ.get("WEEK4_RISK_POLICY") or POLICY_PATH
    try:
        with open(path, "rb") as fh:
            raw = _normalised_bytes(fh.read())
    except OSError:
        raise PolicyError("the risk policy file could not be read: " + str(path)) from None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise PolicyError("the risk policy file is not valid JSON: " + str(path)) from None
    validate(data)
    return Policy(data, hashlib.sha256(raw).hexdigest())


# ---------------------------------------------------------------------------------------------- inputs
def _finite(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def inputs_from_state(state):
    """The policy's inputs, read from a finished graph state (v0.1 or v2). Missing pieces become None/'missing' and are treated as gaps, never guessed."""
    verdict_record = state.get("verdict") if isinstance(state.get("verdict"), dict) else None
    verdict = verdict_record.get("verdict") if verdict_record and isinstance(verdict_record.get("verdict"), dict) else None
    upstream = (verdict_record or {}).get("upstream") if verdict_record else None

    def status_of(key, trace_name):
        out = state.get(key)
        if isinstance(out, dict):
            return out.get("status")
        return "not_run"
    if isinstance(upstream, dict):
        up = {"traffic": upstream.get("traffic"), "beacon": upstream.get("beacon"), "enrichment": upstream.get("enrichment")}
    else:
        up = {"traffic": status_of("traffic_findings", "traffic_analyst"), "beacon": status_of("beacon_findings", "c2_beacon_analyst"),
              "enrichment": status_of("enrichment_findings", "enrichment_agent")}
    memory = state.get("memory") if isinstance(state.get("memory"), dict) else None
    alert = state.get("alert") if isinstance(state.get("alert"), dict) else {}
    return {
        "verdict_status": verdict_record.get("status") if verdict_record else "missing",
        "is_malicious": verdict.get("is_malicious") if verdict else None,
        "attack_type": verdict.get("attack_type") if verdict else None,
        "severity": verdict.get("severity") if verdict else None,
        "detector_score": alert.get("detector_score"),
        "upstream": up,
        "graph_errors": len(state.get("errors") or []),
        "memory_enabled": bool(state.get("memory_enabled")),
        "memory": memory,
        "src_ip": alert.get("src_ip"), "dst_ip": alert.get("dst_ip"), "dst_port": alert.get("dst_port"),
    }


def memory_attack_share(memory):
    """(hits, share of attack-labelled neighbours) from a memory result, or (0, None) when the result is missing or not ok."""
    if not isinstance(memory, dict) or memory.get("status") != "ok":
        return 0, None
    counts = memory.get("label_counts")
    if not isinstance(counts, dict) or not counts:
        return 0, None
    total = sum(v for v in counts.values() if isinstance(v, int) and not isinstance(v, bool))
    if total <= 0:
        return 0, None
    attacks = sum(v for k, v in counts.items() if k != "BENIGN" and isinstance(v, int) and not isinstance(v, bool))
    return total, attacks / total


# ---------------------------------------------------------------------------------------------- the decision
def _core(policy, x, use_memory):
    """(decision, risk, reasons, memory_rule_fired)."""
    ac, mem = policy["auto_close"], policy["memory"]
    reasons = []
    if x["verdict_status"] != "ok" or x["is_malicious"] is None:
        reasons.append("R1 verdict_unavailable: the verdict step ended as '%s'; a case without a usable verdict is never decided automatically" % x["verdict_status"])
        return NEEDS_REVIEW, "unknown", reasons, False
    if x["is_malicious"] is True:
        severity = x["severity"] if x["severity"] in SEVERITY_ORDER else "high"
        reasons.append("R2 malicious_verdict: the verdict says %s with severity %s" % (x["attack_type"], x["severity"]))
        return ESCALATE, policy["severity_to_risk"][severity], reasons, False

    escalate, review, memory_fired = [], [], False
    score = x["detector_score"]
    if not _finite(score):
        review.append("R3 detector_score_missing: the alert has no usable detector score")
    elif score > ac["max_detector_score"]:
        escalate.append("R4 detector_disagrees: benign verdict, but the detector score %.4g is above the auto-close ceiling %.4g" % (score, ac["max_detector_score"]))
    up = x["upstream"] or {}
    if up.get("traffic") not in ac["require_traffic_status"]:
        review.append("R5 evidence_gap: traffic analysis status is '%s' (needs %s)" % (up.get("traffic"), "/".join(ac["require_traffic_status"])))
    if up.get("beacon") not in ac["allowed_beacon_statuses"]:
        review.append("R5 evidence_gap: C2 beaconing analysis status is '%s'" % up.get("beacon"))
    if up.get("enrichment") not in ac["allowed_enrichment_statuses"]:
        review.append("R5 evidence_gap: enrichment status is '%s'" % up.get("enrichment"))
    if x["graph_errors"] > ac["max_graph_errors"]:
        review.append("R6 graph_errors: %d error(s) were recorded during the run (allowed: %d)" % (x["graph_errors"], ac["max_graph_errors"]))
    if use_memory and x["memory_enabled"]:
        m = x["memory"]
        if ac["require_memory_ok_when_enabled"] and not (isinstance(m, dict) and m.get("status") == "ok"):
            review.append("R7 memory_unavailable: memory is enabled but its step ended as '%s'" % (m.get("status") if isinstance(m, dict) else "missing"))
        hits, share = memory_attack_share(m)
        if share is not None and hits >= mem["min_hits"] and share >= mem["min_attack_neighbour_share"]:
            escalate.append("R8 memory_neighbours_attack: %.0f%% of the %d similar past incidents were attacks (threshold %.0f%% of at least %d); memory raises caution only"
                            % (100 * share, hits, 100 * mem["min_attack_neighbour_share"], mem["min_hits"]))
            memory_fired = True
    if escalate:
        return ESCALATE, "medium", escalate + review, memory_fired
    if review:
        return NEEDS_REVIEW, "unknown", review, memory_fired
    return AUTO_CLOSE, "low", ["R9 auto_close: benign verdict, detector score %.4g <= %.4g, specialists healthy, no errors" % (score, ac["max_detector_score"])], False


def decide(policy, x):
    """The routing decision for one set of inputs: {decision, risk_level, reasons, policy_version, policy_sha256, memory_raised_risk}."""
    if not isinstance(policy, Policy):
        raise PolicyError("routing needs a loaded policy")
    decision, risk, reasons, mem_fired = _core(policy, x, use_memory=True)
    without, _, _, _ = _core(policy, x, use_memory=False)
    raised = bool(mem_fired and CAUTION[decision] > CAUTION[without])
    if raised:
        reasons = reasons + ["R8b memory_raised_risk: without the memory step this case would have been '%s'" % without]
    return {"decision": decision, "risk_level": risk, "reasons": reasons, "policy_version": policy.version, "policy_sha256": policy.sha256, "memory_raised_risk": raised}


def propose_actions(policy, x, decision):
    """Containment PROPOSALS (never executions). Only for an escalated case with a complete malicious verdict; built from the verdict and the alert, never from memory."""
    if decision["decision"] != ESCALATE or x["verdict_status"] != "ok" or x["is_malicious"] is not True:
        return []
    src = x.get("src_ip")
    if not isinstance(src, str) or not src:
        return []
    cp = policy["containment_proposals"]
    severity = x["severity"] if x["severity"] in SEVERITY_ORDER else "none"
    strong = SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(cp["min_severity_for_containment"])
    contain = cp["by_attack_type"].get(x["attack_type"])
    if strong and contain:
        action, why = contain, "R10 containment_proposal: %s with severity %s (policy minimum %s) maps to %s" % (x["attack_type"], severity, cp["min_severity_for_containment"], contain)
    else:
        action, why = cp["monitoring_action"], "R11 monitoring_proposal: %s with severity %s is below the containment minimum %s or has no containment mapping" % (x["attack_type"], severity, cp["min_severity_for_containment"])
    return [{"action_type": action, "target": src, "rationale": why + ". Proposed only: a person must approve it, and it is never executed against a real system.",
             "parameters": {"attack_type": x["attack_type"], "severity": severity, "dst_ip": x.get("dst_ip"), "dst_port": x.get("dst_port")}}]


def route_case(policy, state):
    """Policy decision and proposals for a finished graph state. Returns {routing: {...}, actions: [...], inputs: {...}}."""
    x = inputs_from_state(state)
    routing = decide(policy, x)
    return {"routing": routing, "actions": propose_actions(policy, x, routing), "inputs": x}
