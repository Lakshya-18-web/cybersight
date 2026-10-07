"""Week 2 Day 5: the prompt registry.

Three prompt versions are registered, and only these three:

  baseline_v1  the Day 3 prompt, taken unchanged from baseline_prompt.py (its hash is pinned: 0208c856...).
  baseline_v2  v1 plus an output-contract block. It targets the extra-field failures seen in the Day 3 run.
  baseline_v3  v1 plus general attack-class guidance plus the same output-contract block as v2.

Nothing here edits baseline_v1. v2 and v3 are built by adding text to the v1 system prompt, so the v1 text is a
prefix of both, and the classification vocabulary (the 11 attack classes, the severities, the field rules) is
the one the verdict schema defines. The hash of every version is computed the same way as baseline_v1's:

  sha256( version + "\n" + system prompt + "\n----\n" + user template )

This module reads no labels, no MITRE answer key and no evaluation file, and it never touches the frozen set.
The v3 guidance is general, public knowledge about each attack type. It holds no dev alert values and no
class-to-technique table.
"""
import json
import hashlib

import baseline_prompt
import verdict_schema

V1 = "baseline_v1"
V2 = "baseline_v2"
V3 = "baseline_v3"
DEFAULT_VERSION = V1

FIELD_NAMES = list(verdict_schema.FIELDS)

# Added after the v1 text in v2 and v3. The structural example uses placeholders only.
OUTPUT_CONTRACT_BLOCK = (
    "\n\n"
    "OUTPUT CONTRACT (this overrides anything above if they seem to differ):\n"
    "- Output exactly ONE JSON object and nothing else: no markdown fences, no text before or after it, no second object.\n"
    "- The object has exactly these five keys and no others: is_malicious, attack_type, mitre_technique, severity, evidence.\n"
    "- Any other key makes the whole reply invalid. Do not add MITRE tactic, name, url, version or any other MITRE metadata as keys.\n"
    "- Do not copy alert or context fields (timestamp, ports, addresses, scores, counts) into new keys. Cite them inside evidence instead.\n"
    "- The MITRE technique id goes only in mitre_technique. Any explanation goes only inside evidence.\n"
    "- evidence is one or two sentences, under 400 characters.\n"
    "Shape of a valid reply (placeholders only, not a real answer):\n"
    '{"is_malicious": <true or false>, "attack_type": "<allowed attack_type>", "mitre_technique": "<technique id or NONE>", '
    '"severity": "<allowed severity>", "evidence": "<one or two sentences>"}'
)

# Added between the v1 text and the output contract in v3. General guidance only.
CLASS_GUIDANCE_BLOCK = (
    "\n\n"
    "GUIDANCE ON THE ATTACK CLASSES (general characteristics of each attack type, to help you choose. "
    "Judge each flow on the values it shows; a flow need not match every point):\n"
    "- BENIGN: ordinary traffic that the detector flagged by mistake. Typically balanced traffic in both directions, "
    "a normal duration and packet sizes, a common service port, and no repeated pattern from the same source.\n"
    "- Bot: a compromised host talking to a remote controller. Typically small, regular, repeated flows from one internal host "
    "to the same remote server over a common web port, like beaconing. It does not sweep many ports and it is not a flood.\n"
    "- DDoS: many sources flooding one target to use up its capacity. Typically very high packet or byte rates toward one "
    "destination and port, and large counts of flows or packets.\n"
    "- DoS Hulk: a fast flood of complete, varied HTTP requests at a web server. Typically many short connections with a high "
    "rate and real data in both directions.\n"
    "- DoS GoldenEye: an HTTP flood that keeps connections alive and reuses them. Typically fewer, longer connections than a "
    "Hulk-style flood, still with real request and response data.\n"
    "- DoS slowloris: a low-bandwidth attack that holds many web connections open by sending partial HTTP headers very slowly. "
    "Typically long flows with very few bytes, almost nothing coming back, and large gaps between packets.\n"
    "- DoS Slowhttptest: a family of slow HTTP attacks (slow headers, slow request body, slow reading of the response). "
    "It looks much like slowloris. Choose it over slowloris when the flow shows a slowly sent request body or a slowly "
    "read response and not only partial headers.\n"
    "- FTP-Patator: password guessing against FTP. Typically many short, similar connections from one source to one server "
    "on the FTP port (21).\n"
    "- SSH-Patator: password guessing against SSH. Typically many short, similar connections from one source to one server "
    "on the SSH port (22).\n"
    "- PortScan: probing for open ports. Typically very many tiny flows with one or two packets and almost no data, "
    "to many different destination ports or hosts, often with SYN packets and no completed exchange.\n"
    "- Web Attack - Brute Force: repeated login guesses against a web application. Typically many similar, complete HTTP "
    "request and response exchanges from one source to one web server at a moderate rate.\n"
    "- Web Attack - XSS/SQLi: injection payloads sent to a web application. Typically a small number of ordinary-looking "
    "complete HTTP exchanges with a forward payload that is not tiny, and no flood and no deliberately slow behavior.\n"
    "\n"
    "How to choose:\n"
    "- Traffic to a web port is not by itself a denial-of-service attack. Choose a DoS class only when the flow shows "
    "flooding (very high rates or volume) or deliberately slow, long-held connections that carry almost no data. "
    "Complete exchanges at a modest rate point to a web attack, or to benign traffic, rather than to slowloris.\n"
    "- Separate floods (high rate, real data in both directions) from slow attacks (low rate, almost no data, long flows) "
    "before choosing within each group.\n"
    "- Do not choose a class just because its name is familiar. Use the values in the alert and its context.\n"
    "\n"
    "Guidance on mitre_technique:\n"
    "- Choose the ATT&CK technique that matches the behavior you observe in the flow, not the name of the class.\n"
    "- Denial of service has two families in ATT&CK. Network denial of service (T1498) exhausts network bandwidth or "
    "capacity with volume, for example a direct flood or a reflected flood. Endpoint denial of service (T1499) exhausts "
    "a host or one of its services, for example by flooding a service with requests or by holding its connections "
    "or application resources open. Pick the family that matches how the flow works.\n"
    "- Use a sub-technique id (T####.###) when one clearly fits, and the parent id (T####) otherwise.\n"
    "- Use NONE only together with BENIGN, as the rules above say. If you cannot name any technique that fits what the "
    "flow shows, treat that as a sign the flow may be benign and reconsider, and do not invent a technique."
)

USER_TEMPLATE_V1 = baseline_prompt.USER_TEMPLATE
USER_TEMPLATE_V2 = "Alert:\n{alert_json}\n\nReply with the JSON object only: exactly the five keys, nothing else."


class PromptSpec:
    """One registered prompt: version, system prompt, user template and SHA-256."""

    def __init__(self, version, system_prompt, user_template, sha_fn=None):
        self.version = version
        self.system_prompt = system_prompt
        self.user_template = user_template
        self._sha_fn = sha_fn

    @property
    def sha256(self):
        if self._sha_fn is not None:
            return self._sha_fn()
        return compute_sha256(self.version, self.system_prompt, self.user_template)

    def __repr__(self):
        return "PromptSpec(" + self.version + ", sha256=" + self.sha256[:12] + ")"


def compute_sha256(version, system_prompt, user_template):
    text = version + "\n" + system_prompt + "\n----\n" + user_template
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _registry():
    v1 = PromptSpec(V1, baseline_prompt.SYSTEM_PROMPT, USER_TEMPLATE_V1, sha_fn=lambda: baseline_prompt.prompt_sha256())
    v2 = PromptSpec(V2, baseline_prompt.SYSTEM_PROMPT + OUTPUT_CONTRACT_BLOCK, USER_TEMPLATE_V2)
    v3 = PromptSpec(V3, baseline_prompt.SYSTEM_PROMPT + CLASS_GUIDANCE_BLOCK + OUTPUT_CONTRACT_BLOCK, USER_TEMPLATE_V2)
    return {V1: v1, V2: v2, V3: v3}


REGISTRY = _registry()


def list_versions():
    return list(REGISTRY)


def get_prompt(version=None):
    if version is None:
        version = DEFAULT_VERSION
    if version not in REGISTRY:
        raise KeyError("unknown prompt version '" + str(version) + "'. Registered: " + ", ".join(REGISTRY))
    return REGISTRY[version]


def build_user_prompt(spec, model_input):
    """Same checks and the same JSON encoding as baseline_prompt.build_user_prompt, with the spec's user template."""
    baseline_prompt.check_model_input(model_input)
    try:
        alert_json = json.dumps(model_input, sort_keys=True, allow_nan=False)
    except ValueError:
        raise ValueError("alert " + str(model_input["alert"].get("alert_id")) + " has a missing or infinite number")
    return spec.user_template.replace("{alert_json}", alert_json)


def build_prompt_for_row(spec, alert_row, store):
    import triage_inputs
    model_input = triage_inputs.build_model_input(alert_row, store)
    return model_input, build_user_prompt(spec, model_input)


def snapshot_text(spec, first_alert_id, first_user_prompt):
    """The prompt_snapshot.txt text. For baseline_v1 it is exactly the Day 3 format, so v1 runs stay reproducible."""
    head = "PROMPT " + spec.version + " sha256 " + spec.sha256 + "\n\n=== system prompt ===\n" + spec.system_prompt
    if spec.version == V1:
        return head + "\n\n=== user prompt for " + first_alert_id + " ===\n" + first_user_prompt + "\n"
    return head + "\n\n=== user template ===\n" + spec.user_template + "\n\n=== user prompt for " + first_alert_id + " ===\n" + first_user_prompt + "\n"
