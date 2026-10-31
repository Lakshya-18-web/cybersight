"""RR-1: the deterministic evidence veto. A model's "benign" can never close a case that the evidence contradicts.

Order of control for one case:  Week 4 risk policy (R1-R11)  ->  response guard  ->  THIS evidence policy  ->  case stored, proposals pending, humans decide.

What it reads: only structured evidence the system observed or fetched, never the model's words.
  observed   the sensor's alert record (numeric severity, signature id, rule category matched against a fixed list, whether a flow record is linked) and the flow-derived specialist findings
             (beaconing candidate, many flows to many ports from the source)
  external   the threat-intelligence lookup records (abuse confidence score, report count) when a lookup succeeded
What it does: it can raise the decision to needs_review or escalate and append the rule that fired. Nothing else.
What it cannot do (each is a test): lower a decision; turn needs_review or escalate into auto_close; create, approve or execute an action; read free text from a sensor or a provider; make a missing
or failed lookup count as "clean" (a score of 0, a disabled provider and an unavailable provider all change nothing).

Rules (ids are stable; the file is versioned and hashed like the Week 4 policy; a missing or invalid file raises PolicyError, there is no built-in fallback):
  E1 sensor_severity       Suricata severity <= escalate_severity_max -> escalate; <= review_severity_max -> needs_review
  E2 sensor_category       the rule's category is on the fixed escalate list (exact match) -> escalate
  E3 beacon_candidate      the beaconing analyst flagged a candidate (regular timing on a consistent port) -> needs_review
  E4 scan_like_source      the source started >= N flows to >= N distinct ports in the window -> needs_review
  E5 threat_intel_high     a successful lookup with score >= escalate_min_score and enough reports -> escalate; score >= review_min_score -> needs_review
  E6 sensor_without_flow   a sensor alert with no linked flow record cannot be auto-closed -> needs_review (the Week 1 detector does not score EVE records either, so Week 4 R3 also applies)

The combined policy identity stored with every case is  "<risk policy version>+<evidence policy version>"  and sha256(risk sha + ":" + evidence sha).
"""
import copy
import hashlib
import json
import math
import os

from week4 import policy as w4_policy

POLICY_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "config", "evidence_policy.json")
ENV_PATH = "WEEK5_EVIDENCE_POLICY"
AUTO_CLOSE, NEEDS_REVIEW, ESCALATE = w4_policy.AUTO_CLOSE, w4_policy.NEEDS_REVIEW, w4_policy.ESCALATE
CAUTION = w4_policy.CAUTION
RULE_IDS = ("E1", "E2", "E3", "E4", "E5", "E6")
FLOORS = (NEEDS_REVIEW, ESCALATE)
RISK_RANK = {"low": 0, "unknown": 1, "medium": 2, "high": 3}


class EvidencePolicyError(w4_policy.PolicyError):
    pass


class EvidencePolicy:
    def __init__(self, data, sha256):
        self.data, self.sha256, self.version = data, sha256, data["evidence_policy_version"]

    def __getitem__(self, key):
        return self.data[key]


def _need(cond, message):
    if not cond:
        raise EvidencePolicyError("invalid evidence policy: " + message)


def _keys(obj, keys, where):
    _need(isinstance(obj, dict), where + " must be an object")
    missing, extra = sorted(set(keys) - set(obj)), sorted(set(obj) - set(keys))
    _need(not missing, where + " is missing " + ", ".join(missing))
    _need(not extra, where + " has unknown keys " + ", ".join(extra))


def _int(value, where, low, high):
    _need(isinstance(value, int) and not isinstance(value, bool) and low <= value <= high, "%s must be a whole number from %d to %d" % (where, low, high))


def validate(data):
    _keys(data, ["evidence_policy_version", "description", "sensor", "beacon", "scan", "threat_intel"], "policy")
    _need(isinstance(data["evidence_policy_version"], str) and data["evidence_policy_version"].strip(), "evidence_policy_version must be text")
    s = data["sensor"]
    _keys(s, ["escalate_severity_max", "review_severity_max", "escalate_categories", "require_flow_for_auto_close"], "sensor")
    _int(s["escalate_severity_max"], "sensor.escalate_severity_max", 0, 255)
    _int(s["review_severity_max"], "sensor.review_severity_max", 0, 255)
    _need(s["escalate_severity_max"] <= s["review_severity_max"], "sensor.escalate_severity_max must not exceed review_severity_max")
    _need(isinstance(s["escalate_categories"], list) and all(isinstance(c, str) and 1 <= len(c) <= 200 for c in s["escalate_categories"]), "sensor.escalate_categories must be a list of text")
    _need(s["require_flow_for_auto_close"] is True, "sensor.require_flow_for_auto_close must be true: a sensor alert without flow evidence is never closed automatically")
    _keys(data["beacon"], ["candidate_floor"], "beacon")
    _need(data["beacon"]["candidate_floor"] in FLOORS, "beacon.candidate_floor must be needs_review or escalate")
    _keys(data["scan"], ["min_flows", "min_distinct_destination_ports", "floor"], "scan")
    _int(data["scan"]["min_flows"], "scan.min_flows", 2, 10 ** 6)
    _int(data["scan"]["min_distinct_destination_ports"], "scan.min_distinct_destination_ports", 2, 65535)
    _need(data["scan"]["floor"] in FLOORS, "scan.floor must be needs_review or escalate")
    t = data["threat_intel"]
    _keys(t, ["escalate_min_score", "escalate_min_reports", "review_min_score"], "threat_intel")
    _int(t["escalate_min_score"], "threat_intel.escalate_min_score", 1, 100)
    _int(t["review_min_score"], "threat_intel.review_min_score", 1, 100)
    _int(t["escalate_min_reports"], "threat_intel.escalate_min_reports", 0, 10 ** 6)
    _need(t["review_min_score"] <= t["escalate_min_score"], "threat_intel.review_min_score must not exceed escalate_min_score")
    return data


def load(path=None):
    path = path or os.environ.get(ENV_PATH) or POLICY_PATH
    try:
        with open(path, "rb") as fh:
            raw = fh.read().replace(b"\r\n", b"\n")
    except OSError:
        raise EvidencePolicyError("the evidence policy file could not be read: " + str(path)) from None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise EvidencePolicyError("the evidence policy file is not valid JSON: " + str(path)) from None
    validate(data)
    return EvidencePolicy(data, hashlib.sha256(raw).hexdigest())


def combined_identity(risk_policy, evidence_policy):
    """-> (version text, sha256) stored in routing.policy_version / policy_sha256."""
    return ("%s+%s" % (risk_policy.version, evidence_policy.version), hashlib.sha256((risk_policy.sha256 + ":" + evidence_policy.sha256).encode("utf-8")).hexdigest())


# ------------------------------------------------------------------ facts
def _num(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else None


def _finding_metrics(output, kind):
    if not isinstance(output, dict):
        return None
    for f in output.get("findings") or []:
        if isinstance(f, dict) and f.get("kind") == kind and isinstance(f.get("metrics"), dict):
            return f["metrics"]
    return None


def facts_from(state, sensor=None, threat_intel=None):
    """The only inputs of the evidence policy. sensor: {severity, signature_id, category, action, flow_linked} or None. threat_intel: list of lookup records or None. Everything else comes from the state's
    specialist findings. A value that is missing stays None."""
    beacon = state.get("beacon_findings") if isinstance(state.get("beacon_findings"), dict) else None
    source = _finding_metrics(state.get("traffic_findings"), "source_activity")
    return {"sensor": sensor, "threat_intel": threat_intel or [],
            "beacon_candidate": True if (beacon and beacon.get("beacon_candidate") is True) else False,
            "source_activity": None if source is None else {"n_flows": _num(source.get("n_flows")), "distinct_destination_ports": _num(source.get("distinct_destination_ports"))}}


def evaluate(ev, facts):
    """-> list of fired rules [{rule, name, floor, risk, detail, source}] in rule order. Pure."""
    fired = []

    def fire(rule, name, floor, detail, source, risk=None):
        fired.append({"rule": rule, "name": name, "floor": floor, "risk": risk, "detail": detail, "source": source})
    s = facts.get("sensor")
    cfg = ev["sensor"]
    if s:
        sev = s.get("severity")
        if isinstance(sev, int) and not isinstance(sev, bool):
            if sev <= cfg["escalate_severity_max"]:
                fire("E1", "sensor_severity", ESCALATE, "the sensor rated this alert severity %d (policy: escalate at %d or below)" % (sev, cfg["escalate_severity_max"]), "observed", "high")
            elif sev <= cfg["review_severity_max"]:
                fire("E1", "sensor_severity", NEEDS_REVIEW, "the sensor rated this alert severity %d (policy: review at %d or below)" % (sev, cfg["review_severity_max"]), "observed", None)
        if s.get("category") in cfg["escalate_categories"]:
            fire("E2", "sensor_category", ESCALATE, "the sensor rule's category is on the escalation list", "observed", "high")
    if facts.get("beacon_candidate"):
        fire("E3", "beacon_candidate", ev["beacon"]["candidate_floor"], "regular timing on a consistent destination port was found in the flow records", "observed", None)
    sa = facts.get("source_activity")
    if sa and sa["n_flows"] is not None and sa["distinct_destination_ports"] is not None:
        if sa["n_flows"] >= ev["scan"]["min_flows"] and sa["distinct_destination_ports"] >= ev["scan"]["min_distinct_destination_ports"]:
            fire("E4", "scan_like_source", ev["scan"]["floor"], "the source started %d flows to %d distinct destination ports in the window" % (sa["n_flows"], sa["distinct_destination_ports"]), "observed", None)
    t = ev["threat_intel"]
    best = None
    for rec in facts.get("threat_intel") or []:
        rep = rec.get("reputation") if isinstance(rec, dict) and rec.get("status") == "ok" else None
        score = _num(rep.get("abuse_confidence_score")) if isinstance(rep, dict) else None
        if score is None:
            continue
        reports = _num(rep.get("total_reports")) or 0
        if best is None or score > best[0]:
            best = (score, reports, rec.get("ip"))
    if best is not None:
        score, reports, ip = best
        if score >= t["escalate_min_score"] and reports >= t["escalate_min_reports"]:
            fire("E5", "threat_intel_high", ESCALATE, "an external lookup scored %s at %d with %d report(s)" % (ip, score, reports), "external_enrichment", "high")
        elif score >= t["review_min_score"]:
            fire("E5", "threat_intel_high", NEEDS_REVIEW, "an external lookup scored %s at %d" % (ip, score), "external_enrichment", None)
    if s and cfg["require_flow_for_auto_close"] and not s.get("flow_linked"):
        fire("E6", "sensor_without_flow", NEEDS_REVIEW, "no flow record is linked to this sensor alert, so there is no observed traffic to check the verdict against", "observed", None)
    return fired


def apply(ev, routed, facts):
    """-> (routed copy, result). The routing is only ever made more cautious. result = {version, sha256, rules_checked, fired, decision_before, decision_after, raised}."""
    before = routed["routing"]["decision"]
    fired = evaluate(ev, facts)
    after = before
    for f in fired:
        if CAUTION[f["floor"]] > CAUTION[after]:
            after = f["floor"]
    result = {"version": ev.version, "sha256": ev.sha256, "rules_checked": list(RULE_IDS), "fired": fired, "decision_before": before, "decision_after": after, "raised": after != before}
    if not fired:
        return routed, result
    new = copy.deepcopy(routed)
    # every fired rule is recorded as a reason (also when the decision was already at least that cautious: corroboration is useful to the analyst)
    new["routing"]["reasons"] = list(new["routing"]["reasons"]) + ["%s %s: %s [%s]" % (f["rule"], f["name"], f["detail"], f["source"]) for f in fired]
    if after != before:
        new["routing"]["decision"] = after
        risk = new["routing"]["risk_level"]
        wanted = "high" if any(f["risk"] == "high" for f in fired if f["floor"] == after) and after == ESCALATE else None
        if after == ESCALATE:
            new["routing"]["risk_level"] = wanted or (risk if RISK_RANK.get(risk, 1) >= RISK_RANK["medium"] else "medium")
        elif risk == "low":
            new["routing"]["risk_level"] = "unknown"
        if before == AUTO_CLOSE:
            new["actions"] = []          # nothing was proposed for an auto-closed case; a vetoed one still proposes nothing: proposals come from a malicious verdict, never from this rule set
    return new, result
