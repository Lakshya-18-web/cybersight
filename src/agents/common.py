"""Shared helper for agents that call tools: one safe call, one evidence entry, one error entry. No LLM call, no network.

A tool should never raise and should always answer with the envelope {ok, tool, data, error}. This helper does not trust that:
a registry that raises, an answer that is not a dict, or an "ok" answer whose data is not a dict is recorded as an error and never as evidence of a finding.
"""

CODE_INVALID_RESULT = "invalid_tool_result"
CODE_TOOL_EXCEPTION = "tool_exception"


def call_tool(registry, node, tool, arguments, index):
    """Call one tool. Returns (evidence_entry, error_or_None). The entry has the same shape the traffic analyst uses: index, tool, arguments, ok, error, data."""
    try:
        result = registry.call(tool, arguments)
    except Exception as error:  # only the exception type is kept
        message = "the call raised " + type(error).__name__
        return _entry(index, tool, arguments, False, {"code": CODE_TOOL_EXCEPTION, "message": message}, None), _error(node, tool, CODE_TOOL_EXCEPTION, message)
    if not isinstance(result, dict) or not isinstance(result.get("ok"), bool):
        message = "the tool answer is not a result envelope"
        return _entry(index, tool, arguments, False, {"code": CODE_INVALID_RESULT, "message": message}, None), _error(node, tool, CODE_INVALID_RESULT, message)
    if result["ok"]:
        if not isinstance(result.get("data"), dict):
            message = "the tool reported success but returned no data object"
            return _entry(index, tool, arguments, False, {"code": CODE_INVALID_RESULT, "message": message}, None), _error(node, tool, CODE_INVALID_RESULT, message)
        return _entry(index, tool, arguments, True, None, result["data"]), None
    failure = result.get("error") if isinstance(result.get("error"), dict) else {}
    code, message = str(failure.get("code", "unknown")), str(failure.get("message", ""))
    return _entry(index, tool, arguments, False, {"code": code, "message": message}, None), _error(node, tool, code, message)


def _entry(index, tool, arguments, ok, error, data):
    return {"index": index, "tool": tool, "arguments": arguments, "ok": ok, "error": error, "data": data}


def _error(node, tool, code, message):
    return {"node": node, "tool": tool, "code": code, "message": message}


def agent_status(evidence):
    """ok when every call succeeded, partial when some did, failed when none did (or nothing was called)."""
    ok = sum(1 for e in evidence if e["ok"])
    if ok == 0:
        return "failed"
    return "ok" if ok == len(evidence) else "partial"


def as_number(value):
    """A real number or None. Booleans and non-finite values are not numbers here."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value != value or value in (float("inf"), float("-inf")):
        return None
    return value
