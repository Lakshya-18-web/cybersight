"""The verdict prompt for the agent graph (Day 5). Registered here, under its own version and hash. No LLM call, no network, no labels.

  agent_v1   the verdict analyst prompt. The system prompt is written for the agent setting (the model sees the alert AND the specialist findings).
             It reuses the general attack-class guidance and the output contract from baseline_v3 word for word, so the two prompts share
             the same class vocabulary and the same answer format. The difference between the baseline and the agent is the evidence the model is shown.

The hash is computed the same way as every Week 2 prompt:  sha256( version + "\\n" + system prompt + "\\n----\\n" + user template ).
src/prompt_registry.py and the locked baseline_v3 prompt are imported and never changed. This module holds no dev alert values, no labels,
no class-to-technique table. Nothing here decides anything: it only lays out what the specialists reported.

What the user prompt contains (build_user_prompt):
  alert      the label-free alert, restricted to baseline_prompt.ALERT_FIELDS (the same flow fields the baseline sees)
  findings   what each specialist reported, in graph state: status and the factual statements; whether each ran; evidence gaps (errors)
The baseline also sees a four-number context summary. The agent does not get it separately; the traffic analyst reports the same kind of
counts (flows from the source, destinations, ports) over the same 5-minute window, as findings.
"""
import json

import baseline_prompt
import prompt_registry
import verdict_schema

from . import state as S

VERSION = "agent_v1"

SYSTEM_PROMPT = (
    "You are the verdict analyst in a network alert triage pipeline.\n"
    "A detector flagged one network flow as suspicious. Its alerts include both real attacks and false alarms. "
    "Decide whether this flow is malicious and, if it is, which kind of attack it is.\n"
    "\n"
    "You are given the alert as JSON and the findings of specialist analysts, also as JSON. The specialists are deterministic tools that "
    "already ran on the flow log. They report measurements; they do not decide. You have no other data and no tools. "
    "Use only what is shown, and do not assume anything about a specialist that did not report.\n"
    "\n"
    "Notes on the alert fields:\n"
    "- timestamp is when the flow started. Fwd is the direction from source to destination, Bwd is the reverse.\n"
    "- Flow Duration is in microseconds. Flow Bytes/s and Flow Packets/s are rates. Flow IAT Mean is the mean time between packets, in microseconds.\n"
    "- SYN Flag Count and ACK Flag Count count packets with that TCP flag.\n"
    "- detector_score is between 0 and 1 and comes from a detector that only separates attack from normal traffic. "
    "Higher means more suspicious. It does not name an attack type.\n"
    "\n"
    "Notes on the findings:\n"
    "- Each specialist has a status: ok (every call worked), partial (some calls failed), failed (none worked), or not_run (it was not needed or not applicable; the reason is given). "
    "A failed or not_run specialist gives you no evidence either way.\n"
    "- traffic_analyst: counts of flows from the alert source and to the alert destination in a window of 5 minutes before and after the alert, including the destination ports they used.\n"
    "- c2_beacon_analyst: runs only when the source contacted the destination at least twice in that window. It then looks at the flows between the pair in a window of 60 minutes before and after the alert "
    "and reports their timing as an assessment: regular_intervals, irregular_intervals, mixed_intervals, inconclusive, insufficient_data or no_flows. "
    "beacon_candidate is true only when the timing is regular and at least half of the pair's flows use the alert's destination port. "
    "Regular timing alone is not proof of anything; port scans and automated clients are regular too.\n"
    "- enrichment_agent: reference context, such as the address type, the port category, usual services for the port and ATT&CK reference entries. "
    "ATT&CK entries here are reference material only: an entry being listed is not evidence that the flow is that technique. "
    "Reputation lookup was not consulted, so no address is known to be good or bad from outside data.\n"
    "- errors lists steps that failed. Treat each one as a gap in the evidence.\n"
    "- The findings are measurements of the flow log. They are neither a verdict nor a hint about the right answer.\n"
    "\n"
    "Answer with one JSON object and nothing else (no markdown, no extra text), with exactly these keys:\n"
    "- is_malicious: true or false\n"
    "- attack_type: BENIGN, or exactly one of: " + ", ".join([name for name in verdict_schema.ATTACK_TYPES if name != "BENIGN"]) + "\n"
    "- mitre_technique: the MITRE ATT&CK technique id that best fits, written as T followed by 4 digits and optionally a dot and 3 digits "
    "(for example T1059 or T1059.001), or NONE when the flow is benign\n"
    "- severity: " + ", ".join(verdict_schema.SEVERITIES) + " (none only when the flow is benign; otherwise low, medium, high or critical, "
    "by how serious it would be for a defender)\n"
    "- evidence: one or two sentences, under 400 characters, citing specific values from the alert or the findings\n"
    "\n"
    "If is_malicious is false, attack_type must be BENIGN, mitre_technique NONE and severity none. "
    "If is_malicious is true, attack_type must be an attack class, with a technique id and a severity other than none. "
    "Do not include the alert id."
    + prompt_registry.CLASS_GUIDANCE_BLOCK
    + prompt_registry.OUTPUT_CONTRACT_BLOCK
)

USER_TEMPLATE = "Alert:\n{alert_json}\n\nSpecialist findings:\n{findings_json}\n\nReply with the JSON object only: exactly the five keys, nothing else."

NOT_RUN = "not_run"
BEACON_SKIP_MARKER = "C2 beaconing analyst skipped: "


def _spec():
    return prompt_registry.PromptSpec(VERSION, SYSTEM_PROMPT, USER_TEMPLATE)


REGISTRY = {VERSION: _spec()}


def list_versions():
    return list(REGISTRY)


def get_prompt(version=None):
    if version is None:
        version = VERSION
    if version not in REGISTRY:
        raise KeyError("unknown agent prompt version '" + str(version) + "'. Registered: " + ", ".join(REGISTRY))
    return REGISTRY[version]


def prompt_sha256():
    return REGISTRY[VERSION].sha256


def _skip_reason(state, agent):
    """Why an agent did not run, in the supervisor's own words when it logged them, else a plain statement."""
    if agent == S.NODE_C2_BEACON_ANALYST:
        for step in state["routing"]:
            reason = step.get("reason") if isinstance(step, dict) else None
            if isinstance(reason, str) and BEACON_SKIP_MARKER in reason:
                rest = reason.split(BEACON_SKIP_MARKER, 1)[1]
                return rest.split(". ", 1)[0].rstrip(".")
    return "the supervisor did not run it"


def _statements(findings):
    out = []
    for finding in findings if isinstance(findings, list) else []:
        if isinstance(finding, dict) and isinstance(finding.get("statement"), str):
            out.append({"kind": finding.get("kind"), "statement": finding["statement"]})
    return out


def findings_payload(state):
    """The specialist findings as a plain dict for the prompt. Deterministic: the same state gives the same dict. Only what the specialists reported, nothing added."""
    payload = {}
    traffic = state.get("traffic_findings")
    payload["traffic_analyst"] = ({"status": NOT_RUN, "reason": "the supervisor did not run it"} if traffic is None else
                                  {"status": traffic.get("status"), "findings": _statements(traffic.get("findings")), "failed_tool_calls": traffic.get("tool_errors")})
    beacon = state.get("beacon_findings")
    if beacon is None:
        payload["c2_beacon_analyst"] = {"status": NOT_RUN, "reason": _skip_reason(state, S.NODE_C2_BEACON_ANALYST)}
    else:
        payload["c2_beacon_analyst"] = {"status": beacon.get("status"), "assessment": beacon.get("assessment"), "beacon_candidate": beacon.get("beacon_candidate"),
                                        "candidate_reason": beacon.get("candidate_reason"), "findings": _statements(beacon.get("findings")),
                                        "limits": list(beacon.get("limits") or []), "failed_tool_calls": beacon.get("tool_errors")}
    enrichment = state.get("enrichment_findings")
    if enrichment is None:
        payload["enrichment_agent"] = {"status": NOT_RUN, "reason": "the supervisor did not run it"}
    else:
        payload["enrichment_agent"] = {"status": enrichment.get("status"), "findings": _statements(enrichment.get("findings")),
                                       "not_consulted": [{"source": n.get("source"), "reason": n.get("reason")} for n in enrichment.get("not_consulted", []) if isinstance(n, dict)],
                                       "unavailable": [{"source": u.get("source"), "code": u.get("code")} for u in enrichment.get("unavailable", []) if isinstance(u, dict)],
                                       "failed_tool_calls": enrichment.get("tool_errors")}
    payload["errors"] = [{"node": e.get("node"), "code": e.get("code"), "message": e.get("message")} for e in state.get("errors", []) if isinstance(e, dict)]
    return payload


def check_alert(alert):
    """The alert shown to the model must be exactly the Week 2 alert fields: nothing extra (so no label-like field can slip in) and nothing missing."""
    if not isinstance(alert, dict):
        raise ValueError("alert must be a dict")
    extra = sorted(str(k) for k in alert if k not in baseline_prompt.ALERT_FIELDS)
    if extra:
        raise ValueError("alert has fields that are not on the allowed list: " + ", ".join(extra))
    missing = [k for k in baseline_prompt.ALERT_FIELDS if k not in alert]
    if missing:
        raise ValueError("alert is missing fields: " + ", ".join(missing))
    return alert


def build_user_prompt(state, spec=None):
    """The user prompt for one state. Raises ValueError for an alert that is not exactly the allowed fields or that holds a missing or infinite number."""
    spec = spec or get_prompt()
    alert = check_alert(state["alert"])
    try:
        alert_json = json.dumps({"alert": alert}, sort_keys=True, allow_nan=False)
        findings_json = json.dumps(findings_payload(state), sort_keys=True, allow_nan=False)
    except ValueError:
        raise ValueError("alert " + str(alert.get("alert_id")) + " has a missing or infinite number")
    return spec.user_template.replace("{alert_json}", alert_json).replace("{findings_json}", findings_json)


def snapshot_text(spec, first_alert_id, first_user_prompt):
    """The prompt_snapshot.txt text, in the same layout the Week 2 runs use for registered prompts."""
    return prompt_registry.snapshot_text(spec, first_alert_id, first_user_prompt)
