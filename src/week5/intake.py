"""Intake: the strict validation every submitted alert passes BEFORE it is stored or queued. This is the first and strongest prompt-injection control.

An alert is a fixed set of 21 fields (the same list the model prompt allows: baseline_prompt.ALERT_FIELDS). Six of them are text (alert_id, flow_id, timestamp, src_ip, dst_ip, protocol is a number);
every text field must match a narrow pattern or parse as the type it claims to be, so free text - and therefore an instruction hidden in a log field - cannot get through. There is no free-text field to
smuggle one in: unknown fields are refused, not ignored. Numbers must be finite. The whole request must fit a byte limit, and nesting is not allowed.

Rejection messages name the FIELD and the RULE, never the submitted value, so a rejected payload cannot be echoed back through an error message, a log line or an audit event.
What is audited for a rejection is the reason code, the field name, the request size and a SHA-256 of the raw body: enough to correlate, nothing to replay.

validate_submission(body) -> Submission(alert, memory)     raises IntakeError(code, field, message)
"""
import datetime
import hashlib
import ipaddress
import json
import math
import re
from collections import namedtuple

# Reason codes (stable: they are written to the audit trail and to the security test report)
BAD_BODY = "bad_body"
UNKNOWN_FIELD = "unknown_field"
MISSING_FIELD = "missing_field"
BAD_TYPE = "bad_type"
BAD_FORMAT = "bad_format"
OUT_OF_RANGE = "out_of_range"
BAD_MEMORY = "bad_memory"
TOO_LARGE = "too_large"
CODES = (BAD_BODY, UNKNOWN_FIELD, MISSING_FIELD, BAD_TYPE, BAD_FORMAT, OUT_OF_RANGE, BAD_MEMORY, TOO_LARGE)

TEXT_FIELDS = ("alert_id", "flow_id", "timestamp", "src_ip", "dst_ip")
INT_FIELDS = {"src_port": (0, 65535), "dst_port": (0, 65535), "protocol": (0, 255)}
SCORE_FIELD = "detector_score"
FEATURE_FIELDS = ("Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Flow Bytes/s", "Flow Packets/s",
                  "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Flow IAT Mean", "SYN Flag Count", "ACK Flag Count")
ALERT_FIELDS = ("alert_id", "timestamp", "flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "detector_score") + FEATURE_FIELDS
NUMBER_LIMIT = 1e15
BODY_KEYS = ("alert", "memory")

ALERT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:\-]{0,63}", re.ASCII)
FLOW_ID_RE = re.compile(r"[A-Za-z0-9._:\-]{1,128}", re.ASCII)
TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d{1,6})?", re.ASCII)
IP_RE = re.compile(r"[0-9A-Fa-f:.]+", re.ASCII)

Submission = namedtuple("Submission", "alert memory")


class IntakeError(ValueError):
    """code: one of CODES. field: the field name (or None). The message never contains submitted content."""

    def __init__(self, code, field, message):
        super().__init__(message)
        self.code, self.field = code, field


def check_against_prompt_fields(baseline_prompt_fields):
    """Raises ValueError if this module's field list is not exactly the model prompt's alert field list. Called by the worker at start-up and by a test."""
    if set(baseline_prompt_fields) != set(ALERT_FIELDS):
        raise ValueError("intake.ALERT_FIELDS differs from baseline_prompt.ALERT_FIELDS: update week5/intake.py")


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _finite(name, value):
    if not _is_number(value):
        raise IntakeError(BAD_TYPE, name, name + " must be a number")
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        raise IntakeError(BAD_FORMAT, name, name + " must be a finite number")
    if abs(value) > NUMBER_LIMIT:
        raise IntakeError(OUT_OF_RANGE, name, name + " is outside the accepted range")
    return value


def _text(name, value, regex=None):
    if not isinstance(value, str):
        raise IntakeError(BAD_TYPE, name, name + " must be text")
    if regex is not None and not regex.fullmatch(value):
        raise IntakeError(BAD_FORMAT, name, name + " does not match the allowed format")
    return value


def _timestamp(value):
    if not isinstance(value, str):
        raise IntakeError(BAD_TYPE, "timestamp", "timestamp must be text")
    if len(value) > 32 or not TIMESTAMP_RE.fullmatch(value):
        raise IntakeError(BAD_FORMAT, "timestamp", "timestamp must look like 2017-07-05 14:30:00 (no time zone)")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("T", " "))
    except ValueError:
        raise IntakeError(BAD_FORMAT, "timestamp", "timestamp is not a real date and time") from None
    if not 2000 <= parsed.year <= 2100:
        raise IntakeError(OUT_OF_RANGE, "timestamp", "timestamp year is outside the accepted range")
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def _ip(name, value):
    if not isinstance(value, str):
        raise IntakeError(BAD_TYPE, name, name + " must be text")
    if len(value) > 45 or not IP_RE.fullmatch(value):
        raise IntakeError(BAD_FORMAT, name, name + " is not a valid IP address")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise IntakeError(BAD_FORMAT, name, name + " is not a valid IP address") from None


def _int(name, value, low, high):
    if isinstance(value, bool) or not isinstance(value, int):
        if isinstance(value, float) and value.is_integer() and not isinstance(value, bool):
            value = int(value)
        else:
            raise IntakeError(BAD_TYPE, name, name + " must be a whole number")
    if not low <= value <= high:
        raise IntakeError(OUT_OF_RANGE, name, "%s must be from %d to %d" % (name, low, high))
    return value


def validate_alert(alert):
    """The cleaned alert (a new dict with exactly ALERT_FIELDS, normalised types). Raises IntakeError."""
    if not isinstance(alert, dict):
        raise IntakeError(BAD_TYPE, "alert", "alert must be a JSON object")
    extra = sorted(str(k) for k in alert if k not in ALERT_FIELDS)
    if extra:
        raise IntakeError(UNKNOWN_FIELD, None, "alert has %d field(s) that are not allowed; the allowed fields are the 21 listed in the API documentation" % len(extra))
    missing = [k for k in ALERT_FIELDS if k not in alert]
    if missing:
        raise IntakeError(MISSING_FIELD, missing[0], "alert is missing: " + ", ".join(missing[:5]) + (" ..." if len(missing) > 5 else ""))
    out = {}
    for name in ALERT_FIELDS:
        value = alert[name]
        if name == "alert_id":
            out[name] = _text(name, value, ALERT_ID_RE)
        elif name == "flow_id":
            out[name] = _text(name, value, FLOW_ID_RE)
        elif name == "timestamp":
            out[name] = _timestamp(value)
        elif name in ("src_ip", "dst_ip"):
            out[name] = _ip(name, value)
        elif name in INT_FIELDS:
            out[name] = _int(name, value, *INT_FIELDS[name])
        elif name == SCORE_FIELD:
            score = _finite(name, value)
            if not 0 <= score <= 1:
                raise IntakeError(OUT_OF_RANGE, name, "detector_score must be from 0 to 1")
            out[name] = float(score)
        else:
            out[name] = _finite(name, value)
    return out


def parse_body(raw, max_bytes):
    """Bytes or text -> parsed JSON object. Raises IntakeError for oversize, invalid JSON, duplicate keys, deep nesting or a non-object."""
    data = raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode("utf-8")
    if len(data) > max_bytes:
        raise IntakeError(TOO_LARGE, None, "the request body is larger than %d bytes" % max_bytes)

    def no_duplicates(pairs):
        seen = {}
        for k, v in pairs:
            if k in seen:
                raise IntakeError(BAD_BODY, None, "the request body repeats a key")
            seen[k] = v
        return seen

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise IntakeError(BAD_BODY, None, "the request body is not valid UTF-8") from None
    try:
        body = json.loads(text, object_pairs_hook=no_duplicates, parse_constant=_reject_constant)
    except IntakeError:
        raise
    except (ValueError, RecursionError):
        raise IntakeError(BAD_BODY, None, "the request body is not valid JSON") from None
    if not isinstance(body, dict):
        raise IntakeError(BAD_BODY, None, "the request body must be a JSON object")
    return body


def _reject_constant(name):
    raise IntakeError(BAD_BODY, None, "the request body contains a non-finite number")


def validate_submission(body, default_memory="off", memory_allowed=True):
    """body: the parsed JSON object {"alert": {...}, "memory": "off"|"on" (optional)}. -> Submission. Raises IntakeError."""
    if not isinstance(body, dict):
        raise IntakeError(BAD_BODY, None, "the request body must be a JSON object")
    extra = sorted(str(k) for k in body if k not in BODY_KEYS)
    if extra:
        raise IntakeError(UNKNOWN_FIELD, None, "the request has %d field(s) that are not allowed; only alert and memory are accepted" % len(extra))
    if "alert" not in body:
        raise IntakeError(MISSING_FIELD, "alert", "the request needs an alert")
    alert = validate_alert(body["alert"])
    memory = body.get("memory", default_memory)
    if memory not in ("off", "on"):
        raise IntakeError(BAD_MEMORY, "memory", "memory must be off or on")
    if memory == "on" and not memory_allowed:
        raise IntakeError(BAD_MEMORY, "memory", "memory is not configured on this server")
    return Submission(alert, memory)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False)


def payload_sha256(alert, memory):
    """The hash that decides whether two submissions are 'the same': the cleaned alert plus the memory mode."""
    return hashlib.sha256(canonical({"alert": alert, "memory": memory}).encode("utf-8")).hexdigest()


def body_sha256(raw):
    data = raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()


def idempotency_key(submitter, client_key, alert, memory):
    """The stored key: submitter + client key (the Idempotency-Key header), or, with no header, a key derived from the content so an identical resubmission is still caught."""
    if client_key:
        base = client_key
    else:
        base = "auto-" + payload_sha256(alert, memory)[:40]
    key = submitter + ":" + base
    if len(key) > 200:
        key = key[:150] + ":" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:40]
    return key
