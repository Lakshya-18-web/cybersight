"""Shared building blocks for the Week 3 tool layer: input validation, the result envelope and the tool description.

Every tool answers with the same envelope, so a graph node can treat all tools alike:

    {"ok": True,  "tool": "<name>", "data": {...},  "error": None}
    {"ok": False, "tool": "<name>", "data": None,   "error": {"code": "<code>", "message": "<text>"}}

Error codes: invalid_input, not_found, unavailable, unknown_tool, internal_error.
A tool never raises to its caller. Bad arguments, a missing record or an unavailable service come back as a result.
Tools are plain infrastructure. They make no LLM call, hold no graph state and never decide a verdict.
"""
import re
import math
import datetime
import ipaddress

CODE_INVALID = "invalid_input"
CODE_NOT_FOUND = "not_found"
CODE_UNAVAILABLE = "unavailable"
CODE_UNKNOWN_TOOL = "unknown_tool"
CODE_INTERNAL = "internal_error"

DEFAULT_MAX_STRING = 200
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ToolFailure(Exception):
    """Raised inside a handler to report an expected failure. It becomes an error envelope."""

    def __init__(self, code, message):
        Exception.__init__(self, message)
        self.code = code
        self.message = message


def P(kind, description, required=False, default=None, minimum=None, maximum=None, enum=None, max_length=None):
    """One parameter of a tool. kind: string, integer, number, boolean, ip, timestamp, enum."""
    return {"type": kind, "description": description, "required": required, "default": default,
            "minimum": minimum, "maximum": maximum, "enum": enum, "max_length": max_length}


def ok_result(tool, data):
    return {"ok": True, "tool": tool, "data": data, "error": None}


def error_result(tool, code, message):
    return {"ok": False, "tool": tool, "data": None, "error": {"code": code, "message": message}}


def plain(value):
    """Turn numpy and pandas values into plain JSON values. NaN and infinity become None."""
    if value is None:
        return None
    if hasattr(value, "item") and not isinstance(value, (str, bytes)):
        try:
            value = value.item()
        except (ValueError, TypeError):
            pass
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        return value
    if isinstance(value, (datetime.datetime,)) or (hasattr(value, "strftime") and hasattr(value, "year")):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, dict):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    return value


def parse_timestamp(text):
    """'YYYY-MM-DD HH:MM[:SS]' or the same with a 'T'. Naive times only (the flow store has no time zone)."""
    cleaned = text.strip().replace("T", " ")
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.datetime.strptime(cleaned, pattern)
        except ValueError:
            continue
    raise ValueError("not a timestamp like 2017-07-05 14:30:00")


def _clean_one(name, spec, value):
    kind = spec["type"]
    if kind == "boolean":
        if not isinstance(value, bool):
            raise ValueError(name + " must be true or false")
        return value
    if kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(name + " must be a whole number")
        result = value
    elif kind == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or (isinstance(value, float) and (math.isnan(value) or math.isinf(value))):
            raise ValueError(name + " must be a finite number")
        result = value
    else:
        if not isinstance(value, str):
            raise ValueError(name + " must be text")
        text = value.strip()
        limit = spec["max_length"] or DEFAULT_MAX_STRING
        if len(text) > limit:
            raise ValueError(name + " is longer than " + str(limit) + " characters")
        if _CONTROL.search(text):
            raise ValueError(name + " contains control characters")
        if kind == "ip":
            try:
                return str(ipaddress.ip_address(text))
            except ValueError:
                raise ValueError(name + " is not a valid IPv4 or IPv6 address")
        if kind == "timestamp":
            try:
                return parse_timestamp(text)
            except ValueError as error:
                raise ValueError(name + ": " + str(error))
        if kind == "enum":
            if text.lower() not in spec["enum"]:
                raise ValueError(name + " must be one of: " + ", ".join(spec["enum"]))
            return text.lower()
        if text == "":
            raise ValueError(name + " is empty")
        return text
    if spec["minimum"] is not None and result < spec["minimum"]:
        raise ValueError(name + " must be at least " + str(spec["minimum"]))
    if spec["maximum"] is not None and result > spec["maximum"]:
        raise ValueError(name + " must be at most " + str(spec["maximum"]))
    return result


def clean_arguments(params, arguments):
    """Validate a tool call. Unknown names are rejected, so an argument can never smuggle in a path or an option."""
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be an object of name/value pairs")
    unknown = sorted(set(arguments) - set(params))
    if unknown:
        raise ValueError("unknown argument(s): " + ", ".join(str(u) for u in unknown))
    cleaned = {}
    for name, spec in params.items():
        value = arguments.get(name)
        if value is None:
            if spec["required"]:
                raise ValueError("missing required argument: " + name)
            cleaned[name] = spec["default"]
        else:
            cleaned[name] = _clean_one(name, spec, value)
    return cleaned


class ToolSpec:
    """A named tool: description, parameters, and a handler that takes the cleaned arguments and returns a data dict."""

    def __init__(self, name, description, params, handler):
        self.name = name
        self.description = description
        self.params = params
        self.handler = handler

    def json_schema(self):
        """The parameter description in JSON-Schema form, for a model's function-calling declaration."""
        properties = {}
        for name, spec in self.params.items():
            kind = spec["type"]
            entry = {"description": spec["description"]}
            if kind in ("integer", "number", "boolean"):
                entry["type"] = kind
                if spec["minimum"] is not None:
                    entry["minimum"] = spec["minimum"]
                if spec["maximum"] is not None:
                    entry["maximum"] = spec["maximum"]
            else:
                entry["type"] = "string"
                if kind == "enum":
                    entry["enum"] = list(spec["enum"])
                if kind == "timestamp":
                    entry["description"] += " Format: YYYY-MM-DD HH:MM:SS."
                if spec["max_length"]:
                    entry["maxLength"] = spec["max_length"]
            if spec["default"] is not None:
                entry["default"] = spec["default"]
            properties[name] = entry
        required = [n for n, s in self.params.items() if s["required"]]
        return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}

    def declaration(self):
        return {"name": self.name, "description": self.description, "parameters": self.json_schema()}

    def run(self, arguments):
        try:
            cleaned = clean_arguments(self.params, arguments)
        except ValueError as error:
            return error_result(self.name, CODE_INVALID, str(error))
        try:
            data = self.handler(cleaned)
        except ToolFailure as failure:
            return error_result(self.name, failure.code, failure.message)
        except Exception as error:  # a bug in a tool must not break the caller; the type is reported, details are not
            return error_result(self.name, CODE_INTERNAL, "the tool failed unexpectedly (" + type(error).__name__ + ")")
        return ok_result(self.name, plain(data))
