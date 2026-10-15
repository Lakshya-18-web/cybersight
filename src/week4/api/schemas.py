"""Request and response models. Pydantic is used for validation in the handlers (framework-free) and for the OpenAPI schema in app.py."""
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class DecisionRequest(BaseModel):
    """Approve or reject one proposed action. The decider is the authenticated caller; there is no field for it."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    decision: Literal["approved", "rejected"]
    reason: str = Field(min_length=1, max_length=1000, description="why; kept in the audit trail")


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorBody(BaseModel):
    error: ErrorDetail


class Page(BaseModel):
    items: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int
    next_offset: Optional[int] = None


class DecisionResult(BaseModel):
    outcome: Literal["applied", "replayed"]
    replayed: bool
    action: Dict[str, Any]
    decision: Optional[Dict[str, Any]] = None
    execution: Optional[Dict[str, Any]] = None
