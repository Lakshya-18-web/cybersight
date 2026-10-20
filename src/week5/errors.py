"""How a failure inside a job is classified: one place decides whether it is worth another attempt, and what (safe) text is stored.

Rules: the stored detail never contains the exception message of an unknown error (only its type name), never a connection string, key or prompt. Codes are lower-case slugs
(they are checked by a database constraint). Retryable = a later attempt could plausibly succeed (an outage, a timeout, a lost worker); not retryable = the same input would fail again
(an invalid alert, a refused model request, an unusable memory store, a database rule).
"""
from collections import namedtuple

import gemini_client
from week4.db.drivers import DbError
from week4.memory import errors as memory_errors
from week4 import policy as policy_module

Classified = namedtuple("Classified", "code retryable timed_out detail")


class JobTimeout(Exception):
    """The job ran longer than its allowed time."""


class ModelUnavailable(Exception):
    """The model could not be reached after the transport retries (the Week 2/3 meaning)."""


class TransientFailure(Exception):
    def __init__(self, code, detail):
        super().__init__(detail)
        self.code, self.detail = code, detail


class PermanentFailure(Exception):
    def __init__(self, code, detail):
        super().__init__(detail)
        self.code, self.detail = code, detail


def classify(error, timeout_seconds=None):
    """-> Classified(code, retryable, timed_out, detail) for any exception raised while processing a job."""
    name = type(error).__name__
    if isinstance(error, (TransientFailure, PermanentFailure)):
        return Classified(error.code, isinstance(error, TransientFailure), False, str(error.detail)[:300])
    if isinstance(error, JobTimeout) or name in ("SoftTimeLimitExceeded", "TimeLimitExceeded"):
        limit = (" " + str(int(timeout_seconds)) + " s") if timeout_seconds else ""
        return Classified("timeout", True, True, "the job did not finish within its time limit" + limit)
    if isinstance(error, gemini_client.PermanentModelError):
        status = getattr(error, "status", None)
        return Classified("model_rejected", False, False, "the model refused the request" + (" (status %s)" % status if isinstance(status, int) else ""))
    if isinstance(error, (ModelUnavailable, gemini_client.TransientModelError)):
        return Classified("model_unavailable", True, False, "the model could not be reached")
    if isinstance(error, DbError):
        state = getattr(error, "sqlstate", None) or ""
        if state.startswith("23") or state == "22023":
            return Classified("case_rejected_by_database", False, False, "the database refused to store the case (rule " + state + ")")
        return Classified("store_unavailable", True, False, "the case store was not available")
    if isinstance(error, (memory_errors.MemoryStoreError, memory_errors.MemoryIsolationError, memory_errors.MemoryDataError, memory_errors.MemoryQueryError)):
        return Classified("memory_unavailable", False, False, "incident memory is not usable (" + name + ")")
    if isinstance(error, policy_module.PolicyError):
        return Classified("policy_error", False, False, "the risk policy could not be applied, so nothing was routed (fail closed)")
    if isinstance(error, ValueError):
        return Classified("invalid_alert", False, False, "the alert was refused by the graph")
    return Classified("worker_exception", True, False, "the worker raised " + name)
