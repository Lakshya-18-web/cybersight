"""The response guard: an independent check, outside the model, on the only free text a model can put into a case (the verdict's `evidence` sentence).

Why it exists. The alert reaching the model is already strictly typed (week5.intake), the specialists and memory are deterministic, the verdict must parse as exactly five fields, and the risk policy
(week4.policy) decides routing and containment proposals from the structured verdict. What is left is a model that has been talked into writing something it should not: a secret, its own instructions,
or text addressed to whoever reads the case. This module looks for that, with plain regular expressions and text shingles. It is a tripwire with stated limits, not a classifier: a clever paraphrase can
pass it, which is why it is never the only control and why it can only make the outcome MORE cautious.

What it does:
  * secret_pattern / known_secret / prompt_leak  -> the evidence sentence is WITHHELD (replaced by a fixed notice) before anything is stored, and a `response_withheld` event goes to the audit trail
  * instruction_echo / control_chars             -> the sentence is kept but flagged, and a `policy_violation` event goes to the audit trail
  * any signal                                   -> a case the policy would AUTO-CLOSE is sent to a human instead (needs_review). A guard can raise caution; it can never close, approve or create anything.
Events carry codes and counts, never the offending text.
"""
import re
from collections import namedtuple

Signal = namedtuple("Signal", "code detail")

WITHHOLD_CODES = ("secret_pattern", "known_secret", "prompt_leak")
FLAG_CODES = ("instruction_echo", "control_chars", "untrusted_text")
WITHHELD_TEXT = "[withheld by the response guard: the model's text matched a protection rule]"
GUARD_REASON = "W5-G1: the response guard flagged the model's text (%s); a case is never closed automatically after that"

SECRET_PATTERNS = (
    ("api_key_prefix", re.compile(r"AIza[0-9A-Za-z_\-]{20,}")),
    ("api_key_prefix", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/\-]{16,}", re.I)),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("assignment", re.compile(r"\b(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*\S{6,}", re.I)),
    ("connection_string", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:[^\s@]+@")),
)
INSTRUCTION_PATTERNS = (
    re.compile(r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|rules|messages)", re.I),
    re.compile(r"disregard\s+(the\s+|all\s+)?(previous|prior|above|system)", re.I),
    re.compile(r"\byou\s+are\s+now\b", re.I),
    re.compile(r"\bnew\s+instructions?\s*:", re.I),
    re.compile(r"\b(system|developer)\s+(prompt|message)\b", re.I),
    re.compile(r"</?\s*(system|assistant|tool|instructions?)\s*>", re.I),
    re.compile(r"\bapprove\s+(this|the)\s+action\b", re.I),
    re.compile(r"\bauto[\s_\-]?close\b", re.I),
    re.compile(r"\b(disable|bypass|skip|ignore)\s+(the\s+)?(risk\s+)?(policy|approval)\b", re.I),
    re.compile(r"\bexecute\s+(the\s+)?(action|command|containment)\b", re.I),
)
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u202a-\u202e\u2066-\u2069]")
SHINGLE_WORDS = 6
_shingle_cache = {}


def _words(text):
    return re.findall(r"[a-z0-9_]+", text.lower())


def shingles_of(prompts):
    """The set of SHINGLE_WORDS-word windows of the given prompt texts (cached per tuple of prompts)."""
    key = tuple(prompts)
    if key not in _shingle_cache:
        out = set()
        for p in key:
            w = _words(p)
            for i in range(len(w) - SHINGLE_WORDS + 1):
                out.add(tuple(w[i:i + SHINGLE_WORDS]))
        _shingle_cache[key] = out
    return _shingle_cache[key]


def default_prompts():
    """The two verdict system prompts a model can be asked to reveal. Imported lazily so this module stays light."""
    from agents import verdict_prompt as VP
    from week4.graph import prompt as P2
    return (VP.SYSTEM_PROMPT, P2.SYSTEM_PROMPT)


def scan_text(text, prompts=None, secrets=()):
    """-> [Signal]. Never returns the matched text, only a code and a short non-sensitive detail."""
    if not isinstance(text, str) or text == "":
        return []
    out = []
    seen = set()
    for name, rx in SECRET_PATTERNS:
        if rx.search(text) and ("secret_pattern", name) not in seen:
            seen.add(("secret_pattern", name))
            out.append(Signal("secret_pattern", name))
    for s in secrets:
        if isinstance(s, str) and len(s) >= 8 and s in text:
            out.append(Signal("known_secret", "a configured secret appears in the text"))
            break
    prompts = default_prompts() if prompts is None else prompts
    if prompts:
        shingles = shingles_of(prompts)
        w = _words(text)
        hits = sum(1 for i in range(len(w) - SHINGLE_WORDS + 1) if tuple(w[i:i + SHINGLE_WORDS]) in shingles)
        if hits >= 1:
            out.append(Signal("prompt_leak", "%d prompt phrase(s)" % hits))
    for i, rx in enumerate(INSTRUCTION_PATTERNS):
        if rx.search(text):
            out.append(Signal("instruction_echo", "pattern %d" % i))
            break
    if CONTROL_RE.search(text):
        out.append(Signal("control_chars", "control or bidirectional characters"))
    return out


def model_text(state):
    """The model-authored free text in a finished state: the verdict's evidence sentence (or None)."""
    record = state.get("verdict") if isinstance(state, dict) else None
    verdict = record.get("verdict") if isinstance(record, dict) else None
    text = verdict.get("evidence") if isinstance(verdict, dict) else None
    return text if isinstance(text, str) else None


def apply_to_state(state, prompts=None, secrets=()):
    """-> (state, [Signal]). Returns a copy of the state with the evidence sentence withheld when a WITHHOLD signal fired; the original is never modified."""
    text = model_text(state)
    signals = scan_text(text, prompts, secrets) if text is not None else []
    if not any(s.code in WITHHOLD_CODES for s in signals):
        return state, signals
    import copy
    new = copy.deepcopy(state)
    new["verdict"]["verdict"]["evidence"] = WITHHELD_TEXT
    return new, signals


def adjust_routing(routed, signals):
    """-> routed (a copy). Any signal turns an auto_close into needs_review with an extra reason. Nothing else about the routing changes, and nothing is ever made less cautious."""
    if not signals or routed["routing"]["decision"] != "auto_close":
        return routed
    import copy
    new = copy.deepcopy(routed)
    codes = ", ".join(sorted({s.code for s in signals}))
    new["routing"]["decision"] = "needs_review"
    new["routing"]["reasons"] = list(new["routing"]["reasons"]) + [GUARD_REASON % codes]
    new["actions"] = []
    return new


def event_payload(signals, case_alert_id=None):
    codes = sorted({s.code for s in signals})
    return {"codes": codes, "count": len(signals), "alert_id": case_alert_id}
