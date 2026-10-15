"""The memory step: one retrieval, recorded as state["memory"]. It makes no decision and calls no model.

Failures are explicit states, never silent: a missing store, an unusable alert, an isolation violation or any unexpected exception becomes memory.status = "error" with a code, and a
matching entry in state["errors"]. The run continues without memory evidence (the risk policy then refuses to auto-close; see policy.py rule R7). Only our own error text is kept; for an
unexpected exception only its type name.
"""
from week4.memory.errors import MemoryIsolationError, MemoryQueryError, MemoryStoreError

from agents import state as S1

from . import state as S2

DETAIL_MAX = 300


def _failed(state, code, detail):
    memory = {"status": "error", "error_code": code, "error_detail": detail[:DETAIL_MAX]}
    error = {"node": S2.NODE_MEMORY, "code": code, "message": "the memory step failed: " + detail[:DETAIL_MAX]}
    return {"memory": memory, "errors": list(state["errors"]) + [error], "trace": list(state["trace"]) + [S2.NODE_MEMORY]}


def make_memory_node(store, k=5):
    """store: a week4.memory.store.MemoryStore (or anything with retrieve(alert, k))."""
    if store is None or not callable(getattr(store, "retrieve", None)):
        raise ValueError("a memory node needs a store with a retrieve(alert, k) method")

    def node(state):
        try:
            result = store.retrieve(state["alert"], k)
            S2.validate_memory(result)
        except MemoryQueryError as error:
            return _failed(state, "bad_query", str(error))
        except MemoryIsolationError as error:
            return _failed(state, "isolation_violation", str(error))
        except MemoryStoreError as error:
            return _failed(state, "store_error", str(error))
        except ValueError:
            return _failed(state, "invalid_result", "the memory store returned a malformed result")
        except Exception as error:   # only the type name is kept
            return _failed(state, "memory_exception", "the memory lookup raised " + type(error).__name__)
        return {"memory": result, "trace": list(state["trace"]) + [S2.NODE_MEMORY]}
    return node


def memory_not_configured_node(state):
    """Used when memory is switched on for an alert but the graph was built without a store. Recorded as an error; no memory evidence is invented."""
    return _failed(state, "memory_not_configured", "memory is enabled but the graph was built without a memory store")
