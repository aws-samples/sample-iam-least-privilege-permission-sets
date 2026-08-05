"""GET /metrics — 지표 시계열(추이). Dashboard 가 latest+first 로 Before/After 표시."""

from __future__ import annotations

from fastapi import APIRouter

from lp2ps.models import MetricsPoint

from . import get_repos

router = APIRouter(tags=["metrics"])


@router.get("/metrics")
def get_metrics() -> list[MetricsPoint]:
    return get_repos().list_metrics()
