from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel

from sentinelpi.detection.engine import DetectionEngine

router = APIRouter(tags=["rules"])


class RuleOut(BaseModel):
    id: str
    name: str
    enabled: bool
    severity: str
    description: str
    thresholds: dict[str, Any]


class RuleList(BaseModel):
    items: list[RuleOut]
    total: int
    limit: int
    next_cursor: None = None


@router.get("/rules", response_model=RuleList)
def list_rules(request: Request) -> RuleList:
    """Effective rule configuration, read-only (change it in the config file)."""
    engine = DetectionEngine(request.app.state.settings.detection)
    items = [RuleOut(**r.catalog_entry()) for r in engine.rules]
    return RuleList(items=items, total=len(items), limit=len(items))
