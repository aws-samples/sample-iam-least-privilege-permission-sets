"""GET /iac/{run_id}/download — 전체 Terraform 번들 presigned URL."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..deps import valid_run_id
from . import get_repos

router = APIRouter(tags=["iac"])


@router.get("/iac/{run_id}/download")
def download_iac(run_id: str) -> dict:
    """iac 번들 presigned URL. 현재는 permission_sets.tf 단일 파일(zip 번들 확장은 후속)."""
    if not valid_run_id(run_id):
        raise HTTPException(status_code=400, detail="잘못된 run_id 형식")
    repos = get_repos()
    if not repos.run_artifact_exists(run_id, "iac/permission_sets.tf"):
        raise HTTPException(status_code=404, detail=f"IaC 없음: {run_id}")
    return {"url": repos.presign(run_id, "iac/permission_sets.tf")}
