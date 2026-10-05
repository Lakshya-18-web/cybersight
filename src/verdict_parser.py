"""Turn raw model text into a validated Verdict, and retry with feedback when it is malformed.

Nothing here calls a model. parse_with_retries() takes a function you give it (call_model: prompt text -> reply text),
so the tests use canned replies and Day 3 plugs in the real call.

Two kinds of repair, and nothing else:
  1. Local, formatting only (recorded in ParseResult.repairs): remove a markdown code fence, ignore prose before
     or after the JSON object, remove trailing commas. The meaning of the reply is never changed: no field is
     renamed, no value is corrected, no missing field is filled in.
  2. A retry: the model is shown its own bad reply and the exact problem, and asked again, up to MAX_RETRIES times.

Every failure gets one error code, so the Day 4 harness can count malformed outputs by kind.
"""
import re
import json
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from pydantic import ValidationError

import llm_config
import verdict_schema
from verdict_schema import Verdict

ERROR_CODES = ["empty_response", "no_json", "invalid_json", "multiple_json_objects", "not_an_object",
               "missing_fields", "extra_fields", "invalid_field", "contradictory"]
PREVIOUS_REPLY_MAX_CHARS = 1500


@dataclass
class ParseResult:
    ok: bool
    verdict: Optional[Verdict] = None
    error_code: Optional[str] = None
    error_detail: str = ""
    repairs: List[str] = field(default_factory=list)


@dataclass
class RetryOutcome:
    verdict: Optional[Verdict]
    attempts: int
    attempt_log: list
    repairs: List[str]

    @property
    def malformed_final(self):
        return self.verdict is None

    @property
    def malformed_first_try(self):
        return len(self.attempt_log) > 0 and self.attempt_log[0]["error_code"] is not None


def _fail(code, detail, repairs):
    return ParseResult(ok=False, error_code=code, error_detail=detail, repairs=repairs)


def _strip_fence(text, repairs):
    match = re.search(r"```[a-zA-Z0-9_-]*\s*\n(.*?)```", text, flags=re.DOTALL)
    if match:
        repairs.append("removed_code_fence")
        return match.group(1)
    return text


def _find_objects(text):
    """Every top-level {...} block, found by counting braces outside of strings."""
    found, depth, start, in_string, escaped = [], 0, None, False, False
    for i, ch in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"' and depth > 0:
            in_string = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0:
                found.append((start, i + 1))
    return found


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    repeated = sorted({k for k in keys if keys.count(k) > 1})
    if repeated:
        raise ValueError("duplicate key " + ", ".join(repeated))
    return dict(pairs)


def _error_summary(error):
    parts = []
    for item in error.errors():
        where = ".".join(str(p) for p in item["loc"]) or "verdict"
        parts.append(where + ": " + item["msg"])
    return "; ".join(parts)


def parse_verdict(text):
    repairs = []
    if text is None or str(text).strip() == "":
        return _fail("empty_response", "the reply was empty", repairs)
    body = _strip_fence(str(text), repairs)
    if body.lstrip().startswith("["):
        return _fail("not_an_object", "the reply is a JSON list; it must be one JSON object", repairs)
    blocks = _find_objects(body)
    if len(blocks) == 0:
        if "{" in body:
            return _fail("invalid_json", "a JSON object was started but never closed (the reply may be cut off)", repairs)
        return _fail("no_json", "the reply contains no JSON object", repairs)
    if len(blocks) > 1:
        return _fail("multiple_json_objects", "the reply contains " + str(len(blocks)) + " JSON objects; it must contain exactly one", repairs)
    start, end = blocks[0]
    if body[:start].strip() != "" or body[end:].strip() != "":
        repairs.append("ignored_text_around_json")
    raw = body[start:end]
    try:
        data = json.loads(raw, object_pairs_hook=_no_duplicates)
    except (ValueError, TypeError) as first_error:
        cleaned = re.sub(r",(\s*[}\]])", r"\1", raw)
        if cleaned != raw:
            try:
                data = json.loads(cleaned, object_pairs_hook=_no_duplicates)
                repairs.append("removed_trailing_comma")
            except (ValueError, TypeError):
                return _fail("invalid_json", str(first_error), repairs)
        else:
            return _fail("invalid_json", str(first_error), repairs)
    if not isinstance(data, dict):
        return _fail("not_an_object", "the JSON value is not an object", repairs)

    try:
        verdict = Verdict.model_validate(data)
    except ValidationError as error:
        kinds = {item["type"] for item in error.errors()}
        detail = _error_summary(error)
        if "missing" in kinds:
            return _fail("missing_fields", detail, repairs)
        if "extra_forbidden" in kinds:
            return _fail("extra_fields", detail, repairs)
        if kinds == {"value_error"} and all(len(item["loc"]) == 0 for item in error.errors()):
            return _fail("contradictory", detail, repairs)
        return _fail("invalid_field", detail, repairs)
    return ParseResult(ok=True, verdict=verdict, repairs=repairs)


def format_reminder():
    """The answer format, repeated in a retry message. This is not the baseline prompt (that is Day 3)."""
    return ("Reply with one JSON object and nothing else, with exactly these keys: "
            "is_malicious (true or false), "
            "attack_type (one of: " + ", ".join(verdict_schema.ATTACK_TYPES) + "), "
            "mitre_technique (like T1046 or T1071.001, or NONE when benign), "
            "severity (one of: " + ", ".join(verdict_schema.SEVERITIES) + "; none only when benign), "
            "evidence (a short text citing the flow facts). "
            "BENIGN goes with is_malicious false, mitre_technique NONE and severity none; an attack class goes with is_malicious true, a technique id and a severity other than none.")


def build_repair_prompt(original_prompt, previous_reply, result):
    previous = str(previous_reply or "")
    if len(previous) > PREVIOUS_REPLY_MAX_CHARS:
        previous = previous[:PREVIOUS_REPLY_MAX_CHARS] + " ...[cut]"
    return (original_prompt.rstrip() + "\n\n"
            "Your previous reply could not be used.\n"
            "Problem (" + str(result.error_code) + "): " + result.error_detail + "\n"
            "Previous reply:\n" + previous + "\n\n"
            "Fix the problem and answer again. " + format_reminder())


def parse_with_retries(call_model: Callable[[str], str], prompt: str, max_retries: Optional[int] = None):
    """Ask, parse, and on failure ask again with feedback. At most 1 + max_retries calls.

    call_model(prompt) must return the reply text. If it raises (network error, quota), the exception is not caught
    here: transport errors and rate limits are the runner's job (Day 3).
    """
    if max_retries is None:
        max_retries = llm_config.MAX_RETRIES
    if max_retries < 0:
        raise ValueError("max_retries must be 0 or more")
    log, current_prompt, repairs = [], prompt, []
    for attempt in range(1, max_retries + 2):
        reply = call_model(current_prompt)
        result = parse_verdict(reply)
        log.append({"attempt": attempt, "error_code": result.error_code, "error_detail": result.error_detail, "repairs": list(result.repairs)})
        if result.ok:
            return RetryOutcome(result.verdict, attempt, log, list(result.repairs))
        current_prompt = build_repair_prompt(prompt, reply, result)
    return RetryOutcome(None, len(log), log, [])
