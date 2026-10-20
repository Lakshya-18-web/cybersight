"""Clients for the load tester: the same two calls (submit an alert, read a job) in-process and over HTTP."""
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


class InProcessClient:
    mode = "inprocess"

    def __init__(self, backend):
        self.backend = backend
        self.headers = {"Authorization": "Bearer " + backend.token, "Content-Type": "application/json"}

    def submit(self, alert, key=None):
        headers = dict(self.headers)
        if key:
            headers["Idempotency-Key"] = key
        raw = json.dumps({"alert": alert}).encode("utf-8")
        r = self.backend.api.dispatch("submit_alert", headers, None, None, {"alert": alert}, raw)
        return r.status, r.body

    def get_job(self, job_id):
        r = self.backend.api.dispatch("get_job", self.headers, None, {"job_id": job_id})
        return r.status, r.body

    def queue_depth(self):
        stats = self.backend.store.stats()
        return sum(stats.get(s, {}).get("n", 0) for s in ("queued", "running"))


class HttpClient:
    """Talks to a running API with urllib. The token comes from an environment variable (never a command-line value). Non-loopback URLs need allow_remote=True."""
    mode = "http"

    def __init__(self, base_url, token_env="WEEK5_LOADTEST_TOKEN", allow_remote=False, timeout=30.0):
        parts = urllib.parse.urlparse(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("base URL must start with http:// or https://")
        if parts.hostname not in LOOPBACK_HOSTS and not allow_remote:
            raise ValueError("refusing to load-test a non-loopback address without --allow-remote (a load test can overload a shared system)")
        token = os.environ.get(token_env, "")
        if not token:
            raise ValueError("set the environment variable " + token_env + " to an API token of an analyst account")
        self.base, self.timeout = base_url.rstrip("/"), timeout
        self._token = token

    def _call(self, method, path, body=None, key=None):
        headers = {"Authorization": "Bearer " + self._token, "Content-Type": "application/json", "Accept": "application/json"}
        if key:
            headers["Idempotency-Key"] = key
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read().decode("utf-8") or "{}")
            except ValueError:
                return error.code, {}
        except (urllib.error.URLError, OSError, TimeoutError):
            return 0, {"error": {"code": "connection_failed"}}

    def submit(self, alert, key=None):
        return self._call("POST", "/alerts", {"alert": alert}, key)

    def get_job(self, job_id):
        return self._call("GET", "/jobs/" + job_id)

    def queue_depth(self):
        return None
