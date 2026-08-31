"""GET /iac/{run_id}/download — 전체 Terraform 번들 presigned URL."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..deps import valid_run_id
from . import get_repos

router = APIRouter(tags=["iac"])

# 다운로드 후보(우선순위). IdC 를 쓰지 않는 고객의 run 에는 permission_sets.tf 가 **없다**
# (m7_iac_emitter 가 uses_identity_center=false 면 생성하지 않는다) — 그때도 관리형 IAM 정책은
# 항상 있으므로 그것을 내려준다. 고정 키 하나만 보면 그 고객은 항상 404 를 받는다.
IAC_CANDIDATES = ("iac/permission_sets.tf", "iac/iam_policies.tf")


def pick_iac_key(repos, run_id: str) -> str | None:  # noqa: ANN001
    """이 run 에 실제로 존재하는 IaC 산출물 키(우선순위 순). 없으면 None."""
    for key in IAC_CANDIDATES:
        if repos.run_artifact_exists(run_id, key):
            return key
    return None


@router.get("/iac/{run_id}/download")
def download_iac(run_id: str) -> dict:
    """iac 번들 presigned URL. 현재는 permission_sets.tf 단일 파일(zip 번들 확장은 후속)."""
    if not valid_run_id(run_id):
        raise HTTPException(status_code=400, detail="잘못된 run_id 형식")
    repos = get_repos()
    key = pick_iac_key(repos, run_id)
    if key is None:
        raise HTTPException(status_code=404, detail=f"IaC 없음: {run_id}")
    return {"url": repos.presign(run_id, key)}
