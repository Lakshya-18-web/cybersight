"""The Week 5 routes. The Week 4 routes (cases, approvals, decisions) are unchanged and still served by week4.api.

Roles: None = public, "read" = any active analyst (viewer and up), "submit" = active analyst, approver or admin (a viewer may read but not submit).
"""
from collections import namedtuple

Route = namedtuple("Route", "method path name role summary query")

ROUTES5 = [
    Route("POST", "/alerts", "submit_alert", "submit",
          'Submit one alert for triage. Body: {"alert": {...21 fields...}, "memory": "off"|"on"}. Returns 202 with a job id; the work is done by a worker. '
          "Send an Idempotency-Key header to make a retry safe; without one, an identical resubmission is recognised by its content.", []),
    Route("GET", "/jobs/{job_id}", "get_job", "read", "Status of one job: queued, running, succeeded, failed or timed_out, with the case id once it has succeeded.", []),
    Route("GET", "/jobs", "list_jobs", "read", "List jobs, newest first.", [("status", "queued | running | succeeded | failed | timed_out"), ("limit", "page size, 1 to 200"), ("offset", "rows to skip")]),
    Route("GET", "/health/live", "health_live", None, "The process is up. Checks nothing else.", []),
    Route("GET", "/health/ready", "health_ready", None, "The API can serve: the database answers (503 otherwise); the broker's state is reported (degraded, still accepting, when it is down).", []),
    Route("GET", "/me", "get_me", "read", "Who the credential belongs to: analyst id, role, and what that role may do. Read-only; lets a client show or hide controls the API would refuse anyway.", []),
]
from . import routes6  # noqa: E402
ROUTES5 = ROUTES5 + routes6.build(Route)
BY_NAME5 = {r.name: r for r in ROUTES5}
