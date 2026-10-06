import json
import hashlib

import verdict_schema
import triage_inputs

PROMPT_VERSION = "baseline_v1"

ALERT_FIELDS = [
    "alert_id", "timestamp", "flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "detector_score",
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Flow Bytes/s", "Flow Packets/s", "Fwd Packet Length Mean",
    "Bwd Packet Length Mean", "Flow IAT Mean", "SYN Flag Count", "ACK Flag Count",
]
CONTEXT_FIELDS = ["window_minutes", "flows_from_same_source", "distinct_destination_ports", "distinct_destination_ips"]

SYSTEM_PROMPT = (
    "You are a security analyst triaging alerts from a network intrusion detector.\n"
    "The detector flagged one network flow as suspicious. Its alerts include both real attacks and false alarms. "
    "Decide whether this flow is malicious and, if it is, which kind of attack it is.\n"
    "\n"
    "You are given one alert as JSON: the flagged flow and a small context summary. You have no other data and no tools. "
    "Use only what is shown.\n"
    "\n"
    "Notes on the fields:\n"
    "- timestamp is when the flow started. Fwd is the direction from source to destination, Bwd is the reverse.\n"
    "- Flow Duration is in microseconds. Flow Bytes/s and Flow Packets/s are rates. Flow IAT Mean is the mean time between packets, in microseconds.\n"
    "- SYN Flag Count and ACK Flag Count count packets with that TCP flag.\n"
    "- detector_score is between 0 and 1 and comes from a detector that only separates attack from normal traffic. "
    "Higher means more suspicious. It does not name an attack type.\n"
    "- context counts flows from the same source IP within window_minutes minutes before or after this flow (this flow included): "
    "flows_from_same_source, distinct_destination_ports and distinct_destination_ips.\n"
    "\n"
    "Answer with one JSON object and nothing else (no markdown, no extra text), with exactly these keys:\n"
    "- is_malicious: true or false\n"
    "- attack_type: BENIGN, or exactly one of: " + ", ".join([name for name in verdict_schema.ATTACK_TYPES if name != "BENIGN"]) + "\n"
    "- mitre_technique: the MITRE ATT&CK technique id that best fits, written as T followed by 4 digits and optionally a dot and 3 digits "
    "(for example T1059 or T1059.001), or NONE when the flow is benign\n"
    "- severity: " + ", ".join(verdict_schema.SEVERITIES) + " (none only when the flow is benign; otherwise low, medium, high or critical, "
    "by how serious it would be for a defender)\n"
    "- evidence: one or two sentences, under 400 characters, citing specific values from the alert or context\n"
    "\n"
    "If is_malicious is false, attack_type must be BENIGN, mitre_technique NONE and severity none. "
    "If is_malicious is true, attack_type must be an attack class, with a technique id and a severity other than none. "
    "Do not include the alert id."
)

USER_TEMPLATE = "Alert:\n{alert_json}\n\nReply with the JSON object only."


def prompt_sha256():
    text = PROMPT_VERSION + "\n" + SYSTEM_PROMPT + "\n----\n" + USER_TEMPLATE
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_model_input(model_input):
    if sorted(model_input.keys()) != ["alert", "context"]:
        raise ValueError("model input must have exactly the keys alert and context")
    extra = [name for name in model_input["alert"] if name not in ALERT_FIELDS]
    if len(extra) > 0:
        raise ValueError("alert has fields that are not on the allowed list: " + ", ".join(sorted(extra)))
    missing = [name for name in ALERT_FIELDS if name not in model_input["alert"]]
    if len(missing) > 0:
        raise ValueError("alert is missing fields: " + ", ".join(missing))
    extra_context = [name for name in model_input["context"] if name not in CONTEXT_FIELDS]
    if len(extra_context) > 0:
        raise ValueError("context has fields that are not on the allowed list: " + ", ".join(sorted(extra_context)))
    return model_input


def build_user_prompt(model_input):
    check_model_input(model_input)
    try:
        alert_json = json.dumps(model_input, sort_keys=True, allow_nan=False)
    except ValueError:
        raise ValueError("alert " + str(model_input["alert"].get("alert_id")) + " has a missing or infinite number")
    return USER_TEMPLATE.replace("{alert_json}", alert_json)


def build_prompt_for_row(alert_row, store):
    model_input = triage_inputs.build_model_input(alert_row, store)
    return model_input, build_user_prompt(model_input)
