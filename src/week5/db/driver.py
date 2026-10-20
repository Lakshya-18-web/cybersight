"""A database driver wrapper for long-running processes (the API and the workers).

Week 4's PsycopgDriver holds ONE connection and never reconnects: after a database restart or a network drop every later call would fail until the process is restarted. This wrapper builds the real driver
lazily and, after a CONNECTION-class failure, discards it so the NEXT call builds a fresh one. The failed call is not retried: a lost reply may mean the statement ran, and the callers (the job store, the
worker) already handle DbError and are written to be safe when it happens (claims are leased, completions are owner-checked, submissions are idempotent).

The psql driver starts a process per call and is already independent between calls; the wrapper adds no lock for it. A psycopg connection is shared by threads, so calls are serialised with a lock.
"""
import threading

from week4.db.drivers import DbError, make_driver

CONNECTION_STATES = ("08", "57P", "53", "58")      # connection exception, operator intervention, insufficient resources, system error


def is_connection_failure(error):
    state = getattr(error, "sqlstate", None)
    return state is None or any(state.startswith(prefix) for prefix in CONNECTION_STATES)


class ResilientDriver:
    def __init__(self, kind, dsn, factory=make_driver):
        self.kind, self.dsn, self.factory = kind, dsn, factory
        self._driver = None
        self._lock = threading.Lock()
        self.reconnects = 0

    def _get(self):
        if self._driver is None:
            self._driver = self.factory(self.kind, self.dsn)
            self.reconnects += 1
        return self._driver

    def _call(self, name, *args):
        if self.kind == "psql":
            return getattr(self._get_unlocked(), name)(*args)
        with self._lock:
            driver = self._get()
            try:
                return getattr(driver, name)(*args)
            except DbError as error:
                if is_connection_failure(error):
                    self._discard()
                raise

    def _get_unlocked(self):
        with self._lock:
            return self._get()

    def _discard(self):
        driver, self._driver = self._driver, None
        try:
            if driver is not None:
                driver.close()
        except Exception:      # closing a broken connection may fail; the object is dropped either way
            pass

    def run_script(self, script):
        return self._call("run_script", script)

    def query(self, sql, params=()):
        return self._call("query", sql, params)

    def query_json(self, sql, params=()):
        return self._call("query_json", sql, params)

    def scalar(self, sql, params=()):
        return self._call("scalar", sql, params)

    def close(self):
        with self._lock:
            self._discard()


def choose_kind():
    try:
        import psycopg  # noqa: F401
        return "psycopg"
    except ImportError:
        return "psql"
