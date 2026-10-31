"""A test double that makes the psql-based test driver behave like the psycopg 3 driver the Docker stack uses, in the ways that have bitten this project.

WHAT IT IS: a wrapper around the psql driver that enforces, on every call, the documented psycopg 3 parameter rules and the native result types.
WHAT IT IS NOT: psycopg. The sandbox that wrote it could not install psycopg, so this is an emulation of rules taken from the psycopg 3 documentation and from the failures seen on the real stack.
It catches the mistakes of the kind found in week5/jobs.py ("Psycopg does not adapt plain Python dicts to PostgreSQL jsonb"); it does not prove the code works on psycopg.

Rules enforced
  * a parameter that is a dict, list, tuple or set is refused (psycopg 3 has no default adapter for dict; pass JSON as text with an explicit ::jsonb cast);
  * with a parameter list present (even an empty one) a literal '%' in the SQL text must be written '%%' (psycopg 3 parses placeholders whenever params is not None);
  * scalar() returns native values: an integer for an integer, a bool for t/f (the psql driver returns text such as "1" and "t");
  * a short allow-list of statements keeps the dict-parameter behaviour because the Week 4 repository (locked) passes the case payload that way and the live stack ingests cases successfully:
    ALLOW_DICT_PARAMS.
"""
import re

from week4.db.drivers import DbError

ALLOW_DICT_PARAMS = ("SELECT * FROM soc.ingest_case(",)
_BAD_PERCENT = re.compile(r"%(?![sb t%(])".replace(" ", ""))


class StrictPsycopgDriver:
    def __init__(self, inner, allow_dict=ALLOW_DICT_PARAMS):
        self.inner, self.allow_dict = inner, tuple(allow_dict)
        self.calls = []

    def _check(self, sql, params):
        self.calls.append(sql)
        params = list(params or [])
        for index, value in enumerate(params):
            if isinstance(value, (dict, list, tuple, set)) and not any(sql.lstrip().startswith(prefix) or ("(" + prefix) in sql for prefix in self.allow_dict):
                raise DbError("cannot adapt type '%s' using placeholder '%%s' (parameter %d)" % (type(value).__name__, index))
        stripped = sql.replace("%%", "")
        if _BAD_PERCENT.search(stripped):
            raise DbError("only '%s', '%b', '%t' are allowed as placeholders, got a stray '%'")
        return params

    @staticmethod
    def _native(value):
        if value is None or not isinstance(value, str):
            return value
        if value in ("t", "f"):
            return value == "t"
        if re.fullmatch(r"-?\d+", value):
            return int(value)
        return value

    def run_script(self, script):
        return self.inner.run_script(script)

    def query(self, sql, params=()):
        return self.inner.query(sql, self._check(sql, params))

    def query_json(self, sql, params=()):
        return self.inner.query_json(sql, self._check(sql, params))

    def scalar(self, sql, params=()):
        return self._native(self.inner.scalar(sql, self._check(sql, params)))

    def close(self):
        return self.inner.close()
