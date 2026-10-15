"""Two ways to talk to PostgreSQL, behind one small interface (query / query_json / run_script).

  PsycopgDriver   the normal driver (psycopg 3, installed from requirements-week4.txt). Use this in the API and in day-to-day operation.
  PsqlDriver      shells out to the `psql` client. It needs no Python package, which makes it handy for a database in a container (`docker compose exec`-style setups with a client on the PATH),
                  for the SQL tests and for migrations. Parameters are escaped with sql_literal(); a statement is always sent on psql's standard input, never on the command line.

Neither driver ever logs or prints a password. Connection strings are redacted by redact_dsn() before they appear in an error message.
Placeholders are %s in both drivers.
"""
import re
import json
import shutil
import subprocess
import datetime
import decimal
import uuid

SEP = "\x1f"


class DbError(Exception):
    """A database command failed. message never contains a password."""
    def __init__(self, message, sqlstate=None):
        super().__init__(message)
        self.sqlstate = sqlstate


def redact_dsn(text):
    """Hide the password in a URL (postgresql://user:pw@host/db) and in a key=value connection string (password=pw)."""
    text = re.sub(r"(postgres(?:ql)?://[^:/@\s]+:)[^@\s]*@", r"\1***@", str(text))
    return re.sub(r"(password\s*=\s*)('[^']*'|\S+)", r"\1***", text, flags=re.I)


def sql_literal(value):
    """A SQL literal for a Python value, for the psql driver (standard_conforming_strings is on). Supports None, bool, int, float, Decimal, str, UUID, datetime, dict/list (as jsonb)."""
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, decimal.Decimal)):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise DbError("a non-finite number cannot be sent to the database")
        return repr(value)
    if isinstance(value, uuid.UUID):
        return "'" + str(value) + "'::uuid"
    if isinstance(value, (datetime.datetime, datetime.date)):
        return "'" + value.isoformat() + "'"
    if isinstance(value, (dict, list)):
        try:
            text = json.dumps(value, sort_keys=True, allow_nan=False)
        except (TypeError, ValueError) as error:
            raise DbError("a JSON parameter cannot be serialised: " + str(error)) from None
        return _quote(text) + "::jsonb"
    if isinstance(value, str):
        return _quote(value)
    raise DbError("unsupported parameter type " + type(value).__name__)


def _quote(text):
    if "\x00" in text:
        raise DbError("a text value contains a NUL character")
    return "'" + text.replace("'", "''") + "'"


def bind(sql, params):
    """Replace %s placeholders with literals (psql driver). %% is a literal percent sign. The number of placeholders must equal the number of params."""
    params = list(params or [])
    parts = re.split(r"(%s|%%)", sql)
    out, used = [], 0
    for part in parts:
        if part == "%s":
            if used >= len(params):
                raise DbError("more placeholders than parameters")
            out.append(sql_literal(params[used]))
            used += 1
        elif part == "%%":
            out.append("%")
        else:
            out.append(part)
    if used != len(params):
        raise DbError("more parameters than placeholders")
    return "".join(out)


class PsqlDriver:
    def __init__(self, conninfo=None, env=None, psql_path=None, timeout=120):
        """conninfo: a libpq connection string or URL, or None to use the PG* environment variables. A password should come from PGPASSWORD or a .pgpass file, not from the string."""
        self.conninfo = conninfo
        self.env = env
        self.psql = psql_path or shutil.which("psql")
        self.timeout = timeout
        if not self.psql:
            raise DbError("the psql client was not found on the PATH")

    def _run(self, script, extra=()):
        cmd = [self.psql, "-X", "-q", "-A", "-t", "-F", SEP, "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose"] + list(extra)
        if self.conninfo:
            cmd.append(self.conninfo)
        try:
            p = subprocess.run(cmd, input=script, capture_output=True, text=True, encoding="utf-8", env=self.env, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            raise DbError("the database command timed out")
        if p.returncode != 0:
            match = re.search(r"ERROR:\s+([0-9A-Z]{5}):\s+(.*)", p.stderr)
            if match:
                raise DbError(redact_dsn(match.group(2).strip()), match.group(1))
            lines = [l for l in p.stderr.strip().splitlines() if l.strip()]
            raise DbError(redact_dsn(lines[-1] if lines else "psql failed"))
        return p.stdout

    def run_script(self, script):
        """Run a multi-statement script as given (the caller supplies BEGIN/COMMIT if it wants one transaction). Stops at the first error."""
        self._run(script)

    def query(self, sql, params=()):
        """Rows as lists of text (NULL is None)."""
        out = self._run(bind(sql, params) + "\n")
        rows = []
        for line in out.splitlines():
            rows.append([None if cell == "" else cell for cell in line.split(SEP)])
        return rows

    def query_json(self, sql, params=()):
        """The first cell of the first row, parsed as JSON (sql should return one json/jsonb value)."""
        out = self._run(bind(sql, params) + "\n").strip()
        if out == "":
            return None
        return json.loads(out)

    def scalar(self, sql, params=()):
        rows = self.query(sql, params)
        return rows[0][0] if rows else None

    def close(self):
        pass


class PsycopgDriver:
    def __init__(self, dsn):
        try:
            import psycopg
        except ImportError as error:
            raise DbError("psycopg is not installed. Install it with: pip install -r requirements-week4.txt") from error
        self._psycopg = psycopg
        self.dsn = dsn
        try:
            self.conn = psycopg.connect(dsn, autocommit=True)
        except Exception as error:
            raise DbError("could not connect: " + redact_dsn(str(error))) from None

    def _wrap(self, error):
        return DbError(redact_dsn(str(error).strip().splitlines()[0] if str(error).strip() else type(error).__name__), getattr(error, "sqlstate", None))

    def run_script(self, script):
        try:
            self.conn.execute(script)
        except self._psycopg.Error as error:
            raise self._wrap(error) from None

    def query(self, sql, params=()):
        try:
            cur = self.conn.execute(sql, list(params or []))
            return [[None if v is None else v for v in row] for row in cur.fetchall()] if cur.description else []
        except self._psycopg.Error as error:
            raise self._wrap(error) from None

    def query_json(self, sql, params=()):
        rows = self.query(sql, params)
        if not rows or rows[0][0] is None:
            return None
        value = rows[0][0]
        return json.loads(value) if isinstance(value, str) else value

    def scalar(self, sql, params=()):
        rows = self.query(sql, params)
        return rows[0][0] if rows else None

    def close(self):
        self.conn.close()


def make_driver(kind, dsn=None):
    if kind == "psql":
        return PsqlDriver(dsn)
    if kind == "psycopg":
        if not dsn:
            raise DbError("the psycopg driver needs a connection string (set WEEK4_DATABASE_URL)")
        return PsycopgDriver(dsn)
    raise DbError("unknown driver " + str(kind) + " (psql or psycopg)")
