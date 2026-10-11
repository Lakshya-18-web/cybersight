"""The verdict node (Day 5): the one node in the graph that calls a language model. Optional; off unless state["verdict_enabled"] is True.

What it does, in order:
  1. Builds the prompt from the alert and the specialist findings already in the state (verdict_prompt.py). Nothing else is added.
  2. Asks the model through an INJECTED function, call_model(prompt) -> reply text. This module imports no model SDK, no client class, no key
     handling and no network code; the runner (src/run_agent_dev.py) supplies the real call, the tests supply fakes.
  3. Parses and validates the reply with the Week 2 verdict_parser (the five-field verdict_schema), with the Week 2 parse-retry rule:
     at most 1 + max_retries calls, the model is shown its own bad reply and the exact problem on each retry.
  4. Returns state["verdict"], a record in the same shape a Week 2 baseline result has (status, verdict, error_code, error_detail, attempts,
     malformed_first_try, attempt_log, repairs, prompt hash), plus the agent context (prompt version, upstream health).

Failures are recorded, never turned into verdicts:
  ok            the reply parsed and validated; "verdict" holds the five fields.
  parse_failed  every reply was malformed (initial call + retries). "verdict" is None; error_code and error_detail come from the last reply.
  model_error   no usable reply: the call kept failing (code model_unavailable), raised something unexpected (model_exception),
                or the prompt could not be built (prompt_build_failed, no call was made). "verdict" is None.
Every failure also adds an entry to state["errors"]. Nothing is guessed, defaulted or repaired beyond the formatting-only repairs verdict_parser documents.

Two kinds of exception are decided by the runner, not here:
  fatal        exceptions that must stop the whole run (for a real run: a permanent model error such as a bad key). They are re-raised untouched.
  unavailable  exceptions that mean "the model could not be reached after the runner's own transport retries" -> status model_error, code model_unavailable.
Any other exception from call_model becomes model_error / model_exception; only the exception type name is kept.

Nothing in this module reads labels, the answer key, the frozen set or any evaluation file.
"""
import hashlib

import verdict_parser

from . import state as S
from . import verdict_prompt

STATUS_OK = "ok"
STATUS_PARSE_FAILED = "parse_failed"
STATUS_MODEL_ERROR = "model_error"

CODE_UNAVAILABLE = "model_unavailable"
CODE_EXCEPTION = "model_exception"
CODE_PROMPT = "prompt_build_failed"
CODE_NOT_CONFIGURED = "verdict_not_configured"
MODEL_ERROR_CODES = (CODE_UNAVAILABLE, CODE_EXCEPTION)   # failures of the model call itself (the runner counts these toward its stop rule)
DETAIL_MAX_CHARS = 300


def upstream_health(state):
    """What the specialists reported, for the record: {traffic, beacon, enrichment, errors}. A specialist that did not run is "not_run"; one switched off by a Day 6 ablation arm is "disabled"."""
    off = verdict_prompt.disabled_agents(state)

    def status_of(key, agent):
        output = state.get(key)
        if isinstance(output, dict):
            return output.get("status")
        return "disabled" if agent in off else verdict_prompt.NOT_RUN   # "disabled" only in a Day 6 ablation arm; every default run reports "not_run" as before
    return {"traffic": status_of("traffic_findings", S.NODE_TRAFFIC_ANALYST), "beacon": status_of("beacon_findings", S.NODE_C2_BEACON_ANALYST),
            "enrichment": status_of("enrichment_findings", S.NODE_ENRICHMENT_AGENT), "errors": len(state.get("errors", []))}


def _log_from_replies(replies):
    """The attempt log for replies that were received (used when the call sequence ended in an error), same shape as the parser's."""
    log = []
    for i, reply in enumerate(replies):
        result = verdict_parser.parse_verdict(reply)
        log.append({"attempt": i + 1, "error_code": result.error_code, "error_detail": result.error_detail, "repairs": list(result.repairs)})
    return log


def _record(state, spec, prompt_hash, status, verdict=None, error_code=None, error_detail=None, attempt_log=None, repairs=None, calls=0, attempt_prompt_hashes=None):
    attempt_log = attempt_log or []
    return {"status": status, "verdict": verdict, "error_code": error_code, "error_detail": error_detail, "attempts": calls,
            "malformed_first_try": (attempt_log[0]["error_code"] is not None) if attempt_log else None, "attempt_log": attempt_log, "repairs": repairs or [],
            "prompt_version": spec.version, "prompt_sha256": prompt_hash, "attempt_prompt_sha256": list(attempt_prompt_hashes or []),
            "agent_prompt_sha256": spec.sha256, "upstream": upstream_health(state)}


def _failure_update(state, record):
    error = {"node": S.NODE_VERDICT, "code": record["error_code"], "message": "the verdict step ended as " + record["status"] + (": " + record["error_detail"] if record["error_detail"] else "")}
    return {"verdict": record, "errors": list(state["errors"]) + [error], "trace": list(state["trace"]) + [S.NODE_VERDICT]}


def make_verdict_node(call_model, spec=None, max_retries=None, fatal=(), unavailable=()):
    """Build the graph node. call_model(prompt) -> reply text. fatal and unavailable are tuples of exception classes (see the module note)."""
    if not callable(call_model):
        raise ValueError("call_model must be a function: prompt text -> reply text")
    spec = spec or verdict_prompt.get_prompt()
    fatal, unavailable = tuple(fatal), tuple(unavailable)

    def verdict_node(state):
        try:
            prompt = verdict_prompt.build_user_prompt(state, spec)
        except ValueError as error:
            record = _record(state, spec, None, STATUS_MODEL_ERROR, error_code=CODE_PROMPT, error_detail=str(error)[:DETAIL_MAX_CHARS])
            return _failure_update(state, record)
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        replies = []
        attempt_prompt_hashes = []

        def counted(text):
            if "Your previous reply could not be used." in text:
                text = (
                    text.rstrip()
                    + "\n\n"
                    + "Generate a fresh answer from scratch. Correct the specific error above; do not repeat duplicate keys or include unapproved fields. "
                    + "Start from scratch; do not copy or reproduce the previous reply. "
                    + "Include each of the five permitted keys exactly once. Remove every unapproved field and never repeat a key. "
                    + "Return valid JSON with double-quoted keys and string values, and true/false as JSON booleans."
                )
            # Hash the exact text passed to call_model, after any Week 3 retry guidance is appended.
            attempt_prompt_hashes.append(hashlib.sha256(text.encode("utf-8")).hexdigest())
            reply = call_model(text)
            replies.append(reply)
            return reply

        try:
            outcome = verdict_parser.parse_with_retries(counted, prompt, max_retries)
        except fatal:
            raise
        except unavailable as error:
            record = _record(state, spec, prompt_hash, STATUS_MODEL_ERROR, error_code=CODE_UNAVAILABLE, error_detail=str(error)[:DETAIL_MAX_CHARS],
                             attempt_log=_log_from_replies(replies), calls=len(replies), attempt_prompt_hashes=attempt_prompt_hashes)
            return _failure_update(state, record)
        except Exception as error:   # only the type name is kept
            record = _record(state, spec, prompt_hash, STATUS_MODEL_ERROR, error_code=CODE_EXCEPTION, error_detail="the model call raised " + type(error).__name__,
                             attempt_log=_log_from_replies(replies), calls=len(replies), attempt_prompt_hashes=attempt_prompt_hashes)
            return _failure_update(state, record)
        calls = len(outcome.attempt_log)
        if outcome.verdict is not None:
            record = _record(state, spec, prompt_hash, STATUS_OK, verdict=outcome.verdict.model_dump(), attempt_log=outcome.attempt_log, repairs=outcome.repairs, calls=calls, attempt_prompt_hashes=attempt_prompt_hashes)
            return {"verdict": record, "trace": list(state["trace"]) + [S.NODE_VERDICT]}
        last = outcome.attempt_log[-1]
        record = _record(state, spec, prompt_hash, STATUS_PARSE_FAILED, error_code=last["error_code"], error_detail=last["error_detail"], attempt_log=outcome.attempt_log, calls=calls, attempt_prompt_hashes=attempt_prompt_hashes)
        return _failure_update(state, record)

    return verdict_node


def verdict_not_configured_node(state):
    """Used when a graph is built without a model call. If the state asks for a verdict anyway, the failure is recorded; no verdict is made up."""
    spec = verdict_prompt.get_prompt()
    record = _record(state, spec, None, STATUS_MODEL_ERROR, error_code=CODE_NOT_CONFIGURED, error_detail="the graph was built without a verdict model call")
    return _failure_update(state, record)
