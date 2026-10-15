"""The approval API: list and inspect cases, see pending approvals, approve or reject proposed actions, view history, evidence and memory provenance.

Layers (so the rules can be tested without a web framework):
  auth.py      who is calling (bearer token -> analyst id; or an explicit, loopback-only dev mode). Fail closed: no configuration, no server.
  routes.py    the route table: method, path, handler, and the role each route needs.
  handlers.py  Api.dispatch(): authentication, role check, input validation, calling the repository / approval service, status codes. Pure Python, no framework.
  app.py       a thin FastAPI wrapper that registers the table and turns handler results into HTTP responses.
Nothing here executes a containment action: approving records a decision; the optional simulate-execution route writes a "simulated" row.
"""
