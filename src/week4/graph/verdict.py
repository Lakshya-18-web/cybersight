"""The verdict node for graph v2.

Memory off: the Week 3 node itself (agents.verdict_node.make_verdict_node, prompt agent_v1). Not a copy: the same function, so Week 3 behaviour cannot drift.
Memory on:  the same steps with the agent_v2_memory prompt. The reply handling (parse, retry rule, failure records) uses the same Week 2/3 helpers; only the prompt text differs.
The model call is injected, as in Week 3: this module imports no SDK, no key handling and no network code.
"""
import hashlib

import verdict_parser
from agents import state as S1
from agents import verdict_node as VN

from . import prompt as P2

RETRY_MARKER = "Your previous reply could not be used."
RETRY_GUIDANCE = (
    "Generate a fresh answer from scratch. Correct the specific error above; do not repeat duplicate keys or include unapproved fields. "
    "Start from scratch; do not copy or reproduce the previous reply. "
    "Include each of the five permitted keys exactly once. Remove every unapproved field and never repeat a key. "
    "Return valid JSON with double-quoted keys and string values, and true/false as JSON booleans."
)


def make_verdict_node(call_model, memory_enabled, max_retries=None, fatal=(), unavailable=()):
    if not isinstance(memory_enabled, bool):
        raise ValueError("memory_enabled must be True or False")
    if not callable(call_model):
        raise ValueError("call_model must be a function: prompt text -> reply text")
    if not memory_enabled:
        return VN.make_verdict_node(call_model, max_retries=max_retries, fatal=tuple(fatal), unavailable=tuple(unavailable))
    spec = P2.get_prompt()
    fatal, unavailable = tuple(fatal), tuple(unavailable)

    def verdict_node(state):
        try:
            prompt = P2.build_user_prompt(state, spec)
        except ValueError as error:
            return VN._failure_update(state, VN._record(state, spec, None, VN.STATUS_MODEL_ERROR, error_code=VN.CODE_PROMPT, error_detail=str(error)[:VN.DETAIL_MAX_CHARS]))
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        replies, attempt_hashes = [], []

        def counted(text):
            if RETRY_MARKER in text:
                text = text.rstrip() + "\n\n" + RETRY_GUIDANCE
            attempt_hashes.append(hashlib.sha256(text.encode("utf-8")).hexdigest())
            reply = call_model(text)
            replies.append(reply)
            return reply

        try:
            outcome = verdict_parser.parse_with_retries(counted, prompt, max_retries)
        except fatal:
            raise
        except unavailable as error:
            return VN._failure_update(state, VN._record(state, spec, prompt_hash, VN.STATUS_MODEL_ERROR, error_code=VN.CODE_UNAVAILABLE, error_detail=str(error)[:VN.DETAIL_MAX_CHARS],
                                                        attempt_log=VN._log_from_replies(replies), calls=len(replies), attempt_prompt_hashes=attempt_hashes))
        except Exception as error:   # only the type name is kept
            return VN._failure_update(state, VN._record(state, spec, prompt_hash, VN.STATUS_MODEL_ERROR, error_code=VN.CODE_EXCEPTION,
                                                        error_detail="the model call raised " + type(error).__name__, attempt_log=VN._log_from_replies(replies),
                                                        calls=len(replies), attempt_prompt_hashes=attempt_hashes))
        calls = len(outcome.attempt_log)
        if outcome.verdict is not None:
            record = VN._record(state, spec, prompt_hash, VN.STATUS_OK, verdict=outcome.verdict.model_dump(), attempt_log=outcome.attempt_log, repairs=outcome.repairs, calls=calls,
                                attempt_prompt_hashes=attempt_hashes)
            return {"verdict": record, "trace": list(state["trace"]) + [S1.NODE_VERDICT]}
        last = outcome.attempt_log[-1]
        return VN._failure_update(state, VN._record(state, spec, prompt_hash, VN.STATUS_PARSE_FAILED, error_code=last["error_code"], error_detail=last["error_detail"],
                                                    attempt_log=outcome.attempt_log, calls=calls, attempt_prompt_hashes=attempt_hashes))
    return verdict_node
