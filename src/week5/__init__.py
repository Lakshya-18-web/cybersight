"""Week 5 backend: asynchronous alert ingestion (durable job table + queue + worker), load testing, prompt-injection testing, deployment files and final-evaluation tooling.

A new package. No Week 1, Week 3 or Week 4 file is edited: everything here wraps or extends them (week4.api.Api is delegated to, never changed; the Week 4 graph is
the graph the worker runs). Nothing here contacts a firewall or executes a containment action, and nothing opens the frozen evaluation set unless the explicit gate
in week5.evalrun.gate is satisfied (see docs/WEEK5_BACKEND.md)."""
VERSION = "week5-v1"
