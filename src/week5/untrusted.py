"""RR-2: structural safeguards so text from outside the system cannot become an instruction.

Four kinds of text arrive from outside: a sensor's rule name and category, a threat-intelligence provider's answer, an analyst's note or comment, and the alert's own identifiers. The model must never read the
first three, and the fourth is validated and aliased. This module makes that a property of the code, not a hope:

  1. Untrusted(text, origin) is a wrapper that REFUSES to turn into a string by accident. str(), format(), +, % and json.dumps all fail with BoundaryViolation, so a prompt builder that was handed one
     cannot interpolate it. The only ways out are .display() (control and bidirectional characters removed, length capped; for the analyst's screen) and .scan() (a list of signals; for the policy).
  2. assert_model_safe(value) walks everything that is about to reach the model and raises on an Untrusted value or on a string that is not a plain identifier, number, address or timestamp.
     The runner calls it on the alert before every graph run; a failure is a PermanentFailure, not a model call.
  3. scan(origin, text) looks for instruction-shaped content (the response guard's patterns), secrets and control characters in untrusted text and returns signals with the code "untrusted_text". A signal
     blocks auto-close and is audited like any other guard signal. Scanning is a tripwire; the barrier in (1) and (2) is what keeps the text away from the model.
  4. clean_provider_field(kind, value) keeps only values of a known shape from an external provider (a country code, a usage type, a time, a count); anything else becomes None.

Analyst notes, feedback and resolution reasons are stored and shown as text. No code path reads them into a prompt; the tests build a prompt after hostile notes exist and look for them.
"""
import json
import re

from week5.security import guard

CONTROL_RE = guard.CONTROL_RE
DISPLAY_LIMIT = 200
ORIGINS = ("sensor_signature", "sensor_category", "provider_field", "analyst_note", "analyst_feedback", "analyst_resolution")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,200}$")
ADDRESS_RE = re.compile(r"^[0-9A-Fa-f:.]{2,45}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d{1,6})?$")


class BoundaryViolation(Exception):
    """Untrusted text was about to cross into a prompt, a log line or a serialiser."""


class Untrusted:
    __slots__ = ("_text", "origin")

    def __init__(self, text, origin):
        if origin not in ORIGINS:
            raise ValueError("unknown origin")
        object.__setattr__(self, "_text", text if isinstance(text, str) else "")
        object.__setattr__(self, "origin", origin)

    def __setattr__(self, name, value):
        raise AttributeError("Untrusted is read-only")

    def _refuse(self, *a, **k):
        raise BoundaryViolation("untrusted %s text cannot be converted to a string implicitly; use display() or scan()" % self.origin)

    __str__ = __format__ = __add__ = __radd__ = __mod__ = __rmod__ = __bytes__ = __iter__ = __getitem__ = __contains__ = _refuse
    __hash__ = None

    def __repr__(self):
        return "<Untrusted %s, %d characters>" % (self.origin, len(self._text))

    def __len__(self):
        return len(self._text)

    def display(self, limit=DISPLAY_LIMIT):
        """For a human reader: control and bidirectional characters replaced by spaces, whitespace collapsed, length capped."""
        return " ".join(CONTROL_RE.sub(" ", self._text).split())[:limit]

    def scan(self):
        return scan(self.origin, self._text)


def scan(origin, text):
    """-> [guard.Signal] with code 'untrusted_text'. The detail names the origin and the kind of match, never the text."""
    if isinstance(text, Untrusted):
        text = text._text
    if not isinstance(text, str) or not text:
        return []
    out, seen = [], set()
    for s in guard.scan_text(text, prompts=(), secrets=()):
        key = (s.code, s.detail)
        if key not in seen:
            seen.add(key)
            out.append(guard.Signal("untrusted_text", "%s: %s" % (origin, s.code)))
    return out


def _walk(value, path, depth=0):
    if depth > 12:
        raise BoundaryViolation("a structure bound for the model is nested too deeply")
    if isinstance(value, Untrusted):
        raise BoundaryViolation("untrusted %s text is bound for the model at %s" % (value.origin, path))
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise BoundaryViolation("a non-text key is bound for the model at " + path)
            _walk(v, path + "." + k, depth + 1)
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _walk(v, "%s[%d]" % (path, i), depth + 1)
    elif isinstance(value, (bool, int, float)) or value is None:
        return
    elif isinstance(value, str):
        return
    else:
        raise BoundaryViolation("an unsupported value type is bound for the model at " + path)


MODEL_TEXT_FIELDS = {"alert_id": IDENTIFIER_RE, "flow_id": IDENTIFIER_RE, "timestamp": TIMESTAMP_RE, "src_ip": ADDRESS_RE, "dst_ip": ADDRESS_RE}


def assert_model_safe(alert):
    """The alert dict that is about to be given to the model: no Untrusted values anywhere, and every string field is one of the five identifier/address/timestamp fields in its exact shape.
    Raises BoundaryViolation. (week5.intake and week5.eve validate the same things earlier; this is the last line, directly in front of the model.)"""
    _walk(alert, "alert")
    if not isinstance(alert, dict):
        raise BoundaryViolation("the alert must be a dict")
    for name, value in alert.items():
        if isinstance(value, str):
            rx = MODEL_TEXT_FIELDS.get(name)
            if rx is None or not rx.match(value):
                raise BoundaryViolation("field %s holds text that is not an identifier, address or timestamp" % (name if name in MODEL_TEXT_FIELDS or re.fullmatch(r"[A-Za-z /]{1,40}", str(name)) else "?"))
    return alert


def assert_json_safe_for_log(value):
    """Used before logging: an Untrusted value anywhere raises instead of being serialised."""
    try:
        json.dumps(value, default=lambda o: (_ for _ in ()).throw(BoundaryViolation("untrusted text in a log record")) if isinstance(o, Untrusted) else str(o))
    except BoundaryViolation:
        raise
    return value


# ------------------------------------------------------------------ provider fields
COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
USAGE_RE = re.compile(r"^[A-Za-z][A-Za-z /\-]{0,59}$")
PROVIDER_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}([+-]\d{2}:?\d{2}|Z)?$")


def clean_provider_field(kind, value):
    """Keep a provider-supplied value only when it has the expected shape; otherwise None. kind: country | usage_type | time | count | score | flag."""
    if kind == "country":
        return value if isinstance(value, str) and COUNTRY_RE.match(value) else None
    if kind == "usage_type":
        return value if isinstance(value, str) and USAGE_RE.match(value) else None
    if kind == "time":
        return value if isinstance(value, str) and PROVIDER_TIME_RE.match(value) else None
    if kind == "count":
        return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 10 ** 9 else None
    if kind == "score":
        return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100 else None
    if kind == "flag":
        return value if isinstance(value, bool) else None
    raise ValueError("unknown provider field kind")
