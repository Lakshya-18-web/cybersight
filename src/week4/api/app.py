"""The FastAPI wrapper. Thin on purpose: it registers the route table and hands every request to Api.dispatch(); all decisions are made there.

    uvicorn is started by  python -m week4.api.serve   (see docs/WEEK4_OPERATIONS.md)

FastAPI, uvicorn and (for tests) httpx are installed with:  pip install -r requirements-week4.txt
This file was written without FastAPI being installable in the sandbox that produced it, so it was checked by reading and by the route-table tests, not by running it.
Run tests/test_week4_api.py in your environment: its FastAPI section runs automatically when fastapi and httpx are installed.
"""
import re

from . import routes
from .handlers import Api, error
from .schemas import DecisionRequest, ErrorBody

TITLE = "SOC Triage - approval API"
DESCRIPTION = ("Cases produced by the triage agent, the actions it PROPOSES, and the human decisions on them. Approving records a decision; nothing is executed against any system. "
               "All routes except /health need a bearer token; approval routes need an approver or admin.")


def create_app(api):
    try:
        from fastapi import FastAPI, Request
        from fastapi.exceptions import RequestValidationError
        from fastapi.responses import JSONResponse
    except ImportError as error_:
        raise ImportError("FastAPI is not installed. Install it with: pip install -r requirements-week4.txt") from error_

    if not isinstance(api, Api):
        raise TypeError("create_app needs an Api")
    app = FastAPI(title=TITLE, description=DESCRIPTION, version="week4-v1")

    @app.exception_handler(RequestValidationError)
    async def _validation(request, exc):
        return JSONResponse(error(422, "invalid_input", "the request is not valid")[1], status_code=422)

    def endpoint_for(route):
        async def endpoint(request: Request):
            body = None
            if route.method == "POST":
                try:
                    body = await request.json()
                except Exception:
                    body = None
            result = api.dispatch(route.name, headers=dict(request.headers), query=dict(request.query_params), path_params=dict(request.path_params), body=body)
            return JSONResponse(result.body, status_code=result.status, headers=result.headers)
        endpoint.__name__ = route.name
        return endpoint

    for route in routes.ROUTES:
        extra = {}
        params = [{"name": n, "in": "query", "required": False, "description": d, "schema": {"type": "string"}} for n, d in route.query]
        for part in re.findall(r"{(\w+)}", route.path):
            params.append({"name": part, "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}})
        if route.name == "decide":
            params.append({"name": "Idempotency-Key", "in": "header", "required": True, "schema": {"type": "string", "minLength": 8, "maxLength": 200}})
            extra["requestBody"] = {"required": True, "content": {"application/json": {"schema": DecisionRequest.model_json_schema()}}}
        if params or extra:
            extra["parameters"] = params
        if route.role is not None:
            extra["security"] = [{"bearerAuth": []}]
        app.add_api_route(route.path, endpoint_for(route), methods=[route.method], summary=route.summary, name=route.name, openapi_extra=extra or None,
                          responses={401: {"model": ErrorBody}, 403: {"model": ErrorBody}, 404: {"model": ErrorBody}, 409: {"model": ErrorBody}, 422: {"model": ErrorBody}, 503: {"model": ErrorBody}})

    base_openapi = app.openapi

    def openapi():
        if app.openapi_schema is None:
            schema = base_openapi()
            schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {"type": "http", "scheme": "bearer"}
        return app.openapi_schema
    app.openapi = openapi
    return app
