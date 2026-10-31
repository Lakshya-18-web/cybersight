"""Suricata EVE JSON adapter: the pure part (no database, no network). It turns EVE `alert` and `flow` events into normalised sensor records and into the alert record the analysis graph expects.

What it accepts. One EVE event is a JSON object. Only `event_type` "alert" and "flow" are used; every other type (dns, http, tls, stats, ...) is counted as ignored, not as an error, because a real eve.json is
full of them. Unknown FIELDS inside an alert or flow event are dropped, never stored: the adapter keeps a short fixed list (below). That is deliberate, and different from the strict CIC intake that refuses unknown fields:
an EVE record is a sensor's own, wide format, and the protection is "keep only what is on the list, validated", not "refuse what is not".

What it never does.
  * It never invents a value. A field the sensor did not send is None ("unavailable"), and the alert record says which ones in `unavailable_fields`. The CIC flow features that EVE cannot supply
    (inter-arrival time, SYN and ACK counts) and the detector score (the Week 1 model scores CIC feature vectors, not EVE records) are always unavailable.
  * It never passes sensor free text to the model. The signature name and category are kept only as DISPLAY strings (control characters removed, length capped) for the analyst; the alert record the model sees holds
    numbers, addresses and a timestamp only, so a hostile signature name cannot become an instruction (RR-2). The deterministic evidence policy reads the numeric severity and the signature id instead.
  * It never accepts events with no ports (ICMP and the like): the analysis graph needs ports, and writing 0 would be a made-up value. They are ignored and counted with the reason "no_ports".

Units: Suricata counts bytes on the wire (headers included); the CIC features count payload bytes. The values are copied as the sensor reports them and the difference is stated in docs/WEEK5_SENSOR_INGESTION.md.
Timestamps: EVE writes 2026-10-20T10:15:30.123456+0000; they are converted to UTC. The alert record uses "YYYY-MM-DD HH:MM:SS" (UTC), like every other alert.
"""
import datetime
import hashlib
import ipaddress
import json
import math
import re

from week5 import intake

ADAPTER_VERSION = "eve-adapter-v1"
SUPPORTED_TYPES = ("alert", "flow")
MAX_EVENTS_PER_BATCH = 500
SENSOR_RE = re.compile(r"[A-Za-z0-9_.:\-]{1,64}", re.ASCII)
FLOW_REF_RE = re.compile(r"[0-9]{1,20}", re.ASCII)
APP_PROTO_RE = re.compile(r"[a-z0-9_.\-]{1,24}", re.ASCII)
ENUM_RE = re.compile(r"[a-z_]{1,24}", re.ASCII)
TS_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}(?::?\d{2})?)?", re.ASCII)
PROTOCOL_NUMBERS = {"tcp": 6, "udp": 17, "sctp": 132}
COUNT_LIMIT = 10 ** 13
DISPLAY_MAX = 200
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")

# the CIC feature names an alert record carries (week5.intake.FEATURE_FIELDS); which of them EVE can fill is decided in features_from()
FEATURES_NEVER_AVAILABLE = ("Flow IAT Mean", "SYN Flag Count", "ACK Flag Count")


class EveError(ValueError):
    """code: a short stable reason. The message never contains the offending value."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class Ignored(Exception):
    """An event that is valid JSON but not usable here (other event type, or no ports). Not an error."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


# ------------------------------------------------------------------ field validators
def parse_time(value, field="timestamp"):
    """EVE time text -> aware UTC datetime. Raises EveError."""
    if not isinstance(value, str) or len(value) > 40:
        raise EveError("bad_timestamp", field + " must be a time string")
    m = TS_RE.fullmatch(value.strip())
    if not m:
        raise EveError("bad_timestamp", field + " is not a recognised EVE time")
    year, month, day, hour, minute, second, frac, zone = m.groups()
    try:
        moment = datetime.datetime(int(year), int(month), int(day), int(hour), int(minute), int(second), int((frac or "0").ljust(6, "0")[:6]), tzinfo=datetime.timezone.utc)
    except ValueError:
        raise EveError("bad_timestamp", field + " is not a real date and time") from None
    if zone and zone != "Z":
        digits = zone[1:].replace(":", "")
        offset = datetime.timedelta(hours=int(digits[:2]), minutes=int(digits[2:4] or "0"))
        moment = moment - offset if zone[0] == "+" else moment + offset
    if not 2000 <= moment.year <= 2100:
        raise EveError("bad_timestamp", field + " year is outside the accepted range")
    return moment


def _ip(value, field):
    try:
        return intake._ip(field, value)
    except intake.IntakeError as error:
        raise EveError("bad_ip", str(error)) from None


def _port(value, field):
    if value is None:
        raise Ignored("no_ports")
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
        raise EveError("bad_port", field + " must be a whole number from 0 to 65535")
    return value


def _protocol(value):
    if isinstance(value, bool):
        raise EveError("bad_protocol", "proto must be a protocol name or number")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        key = value.strip().lower()
        if key in PROTOCOL_NUMBERS:
            number = PROTOCOL_NUMBERS[key]
        elif key.isdigit():
            number = int(key)
        else:
            raise Ignored("no_ports")           # icmp, ipv6-icmp, gre ...: no ports to analyse
    else:
        raise EveError("bad_protocol", "proto must be a protocol name or number")
    if not 0 <= number <= 255:
        raise EveError("bad_protocol", "proto is outside 0 to 255")
    if number not in (6, 17, 132):
        raise Ignored("no_ports")
    return number


def _count(value, field):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= COUNT_LIMIT:
        raise EveError("bad_count", field + " must be a whole number from 0 to 10^13")
    return value


def _flow_ref(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise EveError("bad_flow_id", "flow_id must be a whole number")
    text = str(value)
    if not FLOW_REF_RE.fullmatch(text):
        raise EveError("bad_flow_id", "flow_id must be 1 to 20 digits")
    return text


def _enum(value):
    if isinstance(value, str) and ENUM_RE.fullmatch(value):
        return value
    return None


def display_text(value, limit=DISPLAY_MAX):
    """Sensor text kept for DISPLAY only: control and bidirectional characters removed, spaces collapsed, length capped. Never given to the model."""
    if not isinstance(value, str):
        return None
    cleaned = " ".join(CONTROL_RE.sub(" ", value).split())
    return cleaned[:limit] if cleaned else None


def _iso(moment):
    return moment.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "+00:00"


def _alert_time_text(moment):
    return moment.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ------------------------------------------------------------------ normalisation
def check_sensor(sensor):
    if not isinstance(sensor, str) or not SENSOR_RE.fullmatch(sensor):
        raise EveError("bad_sensor", "the sensor name must be 1 to 64 characters from A-Z a-z 0-9 _ . : -")
    return sensor


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False)


def normalise(event, sensor):
    """One EVE event -> a normalised record {event_sha256, event_type, flow_ref, event_time, src_ip, src_port, dst_ip, dst_port, protocol, record}.
    Raises EveError (invalid) or Ignored (valid but not used)."""
    check_sensor(sensor)
    if not isinstance(event, dict):
        raise EveError("bad_event", "an EVE event must be a JSON object")
    kind = event.get("event_type")
    if kind not in SUPPORTED_TYPES:
        raise Ignored("event_type_" + (kind if isinstance(kind, str) and ENUM_RE.fullmatch(kind) else "unknown"))
    moment = parse_time(event.get("timestamp"))
    src_port = _port(event.get("src_port"), "src_port")
    dst_port = _port(event.get("dest_port"), "dest_port")
    protocol = _protocol(event.get("proto"))
    src_ip, dst_ip = _ip(event.get("src_ip"), "src_ip"), _ip(event.get("dest_ip"), "dest_ip")
    flow_ref = _flow_ref(event.get("flow_id"))
    app_proto = event.get("app_proto") if isinstance(event.get("app_proto"), str) and APP_PROTO_RE.fullmatch(event["app_proto"]) else None
    section = event.get("flow") if isinstance(event.get("flow"), dict) else {}
    counts = {"pkts_toserver": _count(section.get("pkts_toserver"), "flow.pkts_toserver"), "pkts_toclient": _count(section.get("pkts_toclient"), "flow.pkts_toclient"),
              "bytes_toserver": _count(section.get("bytes_toserver"), "flow.bytes_toserver"), "bytes_toclient": _count(section.get("bytes_toclient"), "flow.bytes_toclient")}
    start = parse_time(section["start"], "flow.start") if section.get("start") is not None else None
    base = {"event_type": kind, "sensor": sensor, "flow_ref": flow_ref, "src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip, "dst_port": dst_port, "protocol": protocol, "app_proto": app_proto}
    if kind == "flow":
        end = parse_time(section["end"], "flow.end") if section.get("end") is not None else None
        age = section.get("age")
        if age is not None and (isinstance(age, bool) or not isinstance(age, int) or not 0 <= age <= 10 ** 7):
            raise EveError("bad_count", "flow.age must be a whole number of seconds")
        record = dict(base, start=_iso(start or moment), end=_iso(end) if end else None, age_seconds=age, state=_enum(section.get("state")), reason=_enum(section.get("reason")),
                      alerted=bool(section.get("alerted")) if isinstance(section.get("alerted"), bool) else None, **counts)
        identity = {k: record[k] for k in ("event_type", "sensor", "flow_ref", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "start", "end", "age_seconds", "pkts_toserver",
                                           "pkts_toclient", "bytes_toserver", "bytes_toclient")}
        when = start or moment
    else:
        alert = event.get("alert")
        if not isinstance(alert, dict):
            raise EveError("bad_event", "an alert event needs an alert object")
        sid = alert.get("signature_id")
        if isinstance(sid, bool) or not isinstance(sid, int) or not 0 <= sid <= 2 ** 31 - 1:
            raise EveError("bad_signature", "alert.signature_id must be a whole number")
        severity = alert.get("severity")
        if severity is not None and (isinstance(severity, bool) or not isinstance(severity, int) or not 1 <= severity <= 255):
            raise EveError("bad_signature", "alert.severity must be a whole number from 1 to 255")
        action = alert.get("action") if alert.get("action") in ("allowed", "blocked") else None
        gid = alert.get("gid") if isinstance(alert.get("gid"), int) and not isinstance(alert.get("gid"), bool) and 0 <= alert["gid"] <= 2 ** 31 - 1 else None
        rev = alert.get("rev") if isinstance(alert.get("rev"), int) and not isinstance(alert.get("rev"), bool) and 0 <= alert["rev"] <= 2 ** 31 - 1 else None
        identity = dict({k: base[k] for k in ("event_type", "sensor", "flow_ref", "src_ip", "src_port", "dst_ip", "dst_port", "protocol")}, time=_iso(moment), signature_id=sid, gid=gid, rev=rev)
        digest = hashlib.sha256(_canonical(identity).encode("utf-8")).hexdigest()
        record = dict(base, alert_id="EVE-" + digest[:24], timestamp=_iso(moment), flow_start=_iso(start) if start else None, signature_id=sid, gid=gid, rev=rev, severity=severity, action=action,
                      category=display_text(alert.get("category")), signature=display_text(alert.get("signature")), **counts)
        when = moment
    sha = hashlib.sha256(_canonical(identity).encode("utf-8")).hexdigest()
    return {"event_sha256": sha, "event_type": kind, "flow_ref": flow_ref, "event_time": _iso(when), "src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip, "dst_port": dst_port,
            "protocol": protocol, "record": record}


def normalise_batch(events, sensor):
    """-> (records, ignored {reason: n}, rejected [{index, code, message}]). Flow events are ordered before alert events so that an alert can be linked to a flow from the same batch."""
    check_sensor(sensor)
    if not isinstance(events, list):
        raise EveError("bad_batch", "events must be a list")
    if len(events) > MAX_EVENTS_PER_BATCH:
        raise EveError("batch_too_large", "a batch may hold at most %d events" % MAX_EVENTS_PER_BATCH)
    records, ignored, rejected = [], {}, []
    for index, event in enumerate(events):
        try:
            records.append((index, normalise(event, sensor)))
        except Ignored as skip:
            ignored[skip.reason] = ignored.get(skip.reason, 0) + 1
        except EveError as error:
            rejected.append({"index": index, "code": error.code, "message": str(error)})
    records.sort(key=lambda pair: (0 if pair[1]["event_type"] == "flow" else 1, pair[0]))
    return records, ignored, rejected


def parse_ndjson(raw, max_bytes):
    """Bytes of newline-delimited JSON -> list of events. Blank lines are skipped. Raises EveError on a body that is too large or a line that is not JSON (the line NUMBER is reported, never its text)."""
    if len(raw) > max_bytes:
        raise EveError("too_large", "the body is larger than %d bytes" % max_bytes)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise EveError("bad_body", "the body is not UTF-8 text") from None
    events = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except ValueError:
            raise EveError("bad_json", "line %d is not valid JSON" % number) from None
        if len(events) > MAX_EVENTS_PER_BATCH:
            raise EveError("batch_too_large", "a batch may hold at most %d events" % MAX_EVENTS_PER_BATCH)
    return events


# ------------------------------------------------------------------ alert record for the analysis graph
def _rate(total, seconds):
    return None if seconds is None or seconds <= 0 or total is None else round(total / seconds, 6)


def _mean(total, packets):
    return None if total is None or not packets else round(total / packets, 6)


def features_from(counts, duration_seconds):
    """The CIC-named features EVE can support, from forward/backward packet and byte counts and a duration. Everything else is None."""
    fp, bp, fb, bb = counts.get("pkts_toserver"), counts.get("pkts_toclient"), counts.get("bytes_toserver"), counts.get("bytes_toclient")
    have_all = None not in (fp, bp, fb, bb)
    return {
        "Flow Duration": None if duration_seconds is None else round(duration_seconds * 1_000_000, 3),
        "Total Fwd Packets": fp, "Total Backward Packets": bp, "Total Length of Fwd Packets": fb, "Total Length of Bwd Packets": bb,
        "Flow Bytes/s": _rate(fb + bb, duration_seconds) if have_all else None,
        "Flow Packets/s": _rate(fp + bp, duration_seconds) if have_all else None,
        "Fwd Packet Length Mean": _mean(fb, fp), "Bwd Packet Length Mean": _mean(bb, bp),
        "Flow IAT Mean": None, "SYN Flag Count": None, "ACK Flag Count": None,
    }


def build_alert(alert_record, flow_record=None, sensor=None):
    """The 21-field alert dict for one normalised alert record, optionally using the matching flow record's counts and duration.
    -> (alert, unavailable_fields). The dict has exactly the fields the model prompt allows; unavailable ones are None."""
    r = alert_record
    counts = {k: r.get(k) for k in ("pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient")}
    duration, source = None, "alert_event"
    if flow_record is not None:
        counts = {k: flow_record.get(k) for k in counts}
        source = "flow_event"
        if flow_record.get("age_seconds") is not None:
            duration = float(flow_record["age_seconds"])
        elif flow_record.get("end") and flow_record.get("start"):
            duration = max(0.0, (parse_time(flow_record["end"]) - parse_time(flow_record["start"])).total_seconds())
    if duration is None and r.get("flow_start"):
        duration = max(0.0, (parse_time(r["timestamp"]) - parse_time(r["flow_start"])).total_seconds())
    stamp = parse_time(r["timestamp"])
    alert = {"alert_id": r["alert_id"], "timestamp": _alert_time_text(stamp), "flow_id": (sensor or r["sensor"]) + ":" + r["flow_ref"], "src_ip": r["src_ip"], "src_port": r["src_port"],
             "dst_ip": r["dst_ip"], "dst_port": r["dst_port"], "protocol": r["protocol"], "detector_score": None}
    alert.update(features_from(counts, duration))
    unavailable = sorted(k for k, v in alert.items() if v is None)
    return alert, unavailable, source


def validate_alert_record(alert):
    """Re-checks an alert dict built by build_alert with the strict CIC rules for every field that is present. Returns the dict with normalised types; raises intake.IntakeError.
    None is allowed only for the detector score and the 12 features (that is what 'unavailable' means here)."""
    if set(alert) != set(intake.ALERT_FIELDS):
        raise intake.IntakeError(intake.UNKNOWN_FIELD, None, "the alert does not have exactly the allowed fields")
    out = {"alert_id": intake._text("alert_id", alert["alert_id"], intake.ALERT_ID_RE), "flow_id": intake._text("flow_id", alert["flow_id"], intake.FLOW_ID_RE),
           "timestamp": intake._timestamp(alert["timestamp"]), "src_ip": intake._ip("src_ip", alert["src_ip"]), "dst_ip": intake._ip("dst_ip", alert["dst_ip"])}
    for name, (low, high) in intake.INT_FIELDS.items():
        out[name] = intake._int(name, alert[name], low, high)
    optional = (intake.SCORE_FIELD,) + tuple(intake.FEATURE_FIELDS)
    for name in optional:
        value = alert[name]
        if value is None:
            out[name] = None
            continue
        out[name] = intake._finite(name, value)
        if name == intake.SCORE_FIELD and not 0 <= value <= 1:
            raise intake.IntakeError(intake.OUT_OF_RANGE, name, name + " must be from 0 to 1")
    return {k: out[k] for k in intake.ALERT_FIELDS}


def is_finite_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
