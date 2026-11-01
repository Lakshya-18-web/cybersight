"""The FastAPI application for Week 5: the Week 4 app (all its routes, unchanged) plus the Week 5 routes.

Thin on purpose, like week4.api.app: every request goes to Api5.dispatch. What this layer adds is only what a framework-free dispatcher cannot do: read the request body with a hard size limit (a
request with a lying or missing Content-Length is cut off at the limit, it is never buffered whole), and run the blocking database work in a thread pool so one slow query cannot stall the server.

FastAPI, uvicorn and httpx are installed with  pip install -r requirements-week5.txt.  This file was written in a sandbox where FastAPI could not be installed, so its framework wiring was NOT run there:
the logic is in Api5 (tested), read_limited() is tested with a stand-in request, and tests/test_week5_api.py runs a FastAPI section automatically when fastapi and httpx are installed.
"""
import re

from week4.api import app as week4_app
from week4.api.handlers import error as http_error

from . import routes5
from .api5 import Api5

VERSION = "week5-v1"


class BodyTooLarge(Exception):
    pass


async def read_limited(request, limit):
    """The request body as bytes, never reading more than limit + 1 bytes. Raises BodyTooLarge. Checks Content-Length first, then the stream (chunked requests have no length)."""
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > limit:
                raise BodyTooLarge()
        except ValueError:
            raise BodyTooLarge() from None
    chunks, total = [], 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise BodyTooLarge()
        chunks.append(chunk)
    return b"".join(chunks)


def create_app5(api):
    try:
        from fastapi import Request
        from fastapi.responses import JSONResponse
        from starlette.concurrency import run_in_threadpool
    except ImportError as error_:
        raise ImportError("FastAPI is not installed. Install it with: pip install -r requirements-week5.txt") from error_
    if not isinstance(api, Api5):
        raise TypeError("create_app5 needs an Api5")
    app = week4_app.create_app(api)
    
    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://cybersight-nine.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
    app.title = "SOC Triage - ingestion and approval API"
    app.version = VERSION
    def endpoint_for(route):
        limit = api.body_limit(route.name)

        async def endpoint(request: Request):
            raw = None
            if route.method == "POST":
                try:
                    raw = await read_limited(request, limit)
                except BodyTooLarge:
                    result = http_error(413, "too_large", "the request body is larger than %d bytes" % limit)
                    return JSONResponse(result.body, status_code=result.status, headers=result.headers)
            result = await run_in_threadpool(api.dispatch, route.name, dict(request.headers), dict(request.query_params), dict(request.path_params), None, raw)
            return JSONResponse(result.body, status_code=result.status, headers=result.headers)
        endpoint.__name__ = route.name
        return endpoint

    for route in routes5.ROUTES5:
        params = [{"name": n, "in": "query", "required": False, "description": d, "schema": {"type": "string"}} for n, d in route.query]
        for part in re.findall(r"{(\w+)}", route.path):
            params.append({"name": part, "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"} if part.endswith("_id") else {"type": "string"}})
        extra = {}
        if route.name == "submit_alert":
            params.append({"name": "Idempotency-Key", "in": "header", "required": False, "schema": {"type": "string", "minLength": 8, "maxLength": 200}})
            extra["requestBody"] = {"required": True, "content": {"application/json": {"schema": {"type": "object", "required": ["alert"], "additionalProperties": False,
                                                                                                    "properties": {"alert": {"type": "object"}, "memory": {"type": "string", "enum": ["off", "on"]}}}}}}
        if params:
            extra["parameters"] = params
        if route.role is not None:
            extra["security"] = [{"bearerAuth": []}]
        app.add_api_route(route.path, endpoint_for(route), methods=[route.method], summary=route.summary, name=route.name, openapi_extra=extra or None, status_code=None)
    app.openapi_schema = None
    return app
