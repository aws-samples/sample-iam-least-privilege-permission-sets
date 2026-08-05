"""GET /runs · POST /runs — 실행 이력 + 새 run 트리거(Step Functions)."""

from __future__ import annotations

import boto3
from fastapi import APIRouter, HTTPException

from lp2ps.models import Run

from ..deps import get_settings, valid_run_id
from . import get_repos

router = APIRouter(tags=["runs"])


@router.get("/runs")
def list_runs() -> list[Run]:
    return get_repos().list_runs()


@router.get("/runs/{run_id}/sources")
def run_sources(run_id: str) -> dict:
    """한 run 의 소스별 수집 상태 상세(실행 이력 행 확장용).

    '왜 이 상태인지' 근거: 계정·소스별 ok/degraded/skipped 와 note. manifest 없으면 빈 구조.
    """
    # run_id 형식 검증(형제 endpoint 와 일관 — S3 key injection/path traversal 방지).
    if not valid_run_id(run_id):
        raise HTTPException(status_code=400, detail="잘못된 run_id 형식")
    manifest = get_repos().get_run_manifest(run_id)
    if manifest is None:
        return {"run_id": run_id, "status": "unknown", "status_summary": None, "accounts": []}
    return manifest


@router.post("/runs")
def start_run() -> Run:
    """Step Functions 실행 트리거 + running Run 반환.

    쓰기는 도구 소유 Step Functions 만(멤버계정 무관). **run_id·started_at 을 여기서 생성해 SFN
    입력으로 넘긴다** — 4개 stage(collect→…→report)가 반드시 같은 run_id 로 동작해야 하므로
    (엔진 결정론·산출물 경로 일치). started_at 은 불변식②의 허용된 wall-clock.
    """
    import json

    from lp2ps.runctx import new_run_context

    s = get_settings()
    run = new_run_context(s.customer)  # run_id + started_at 생성
    sfn = boto3.client("stepfunctions", region_name=s.region)
    sfn.start_execution(
        stateMachineArn=s.state_machine_arn,
        input=json.dumps({"run_id": run.run_id, "started_at": run.started_at}),
    )
    return Run(
        run_id=run.run_id,
        customer=s.customer,
        started_at=run.started_at,
        account_scope=_account_scope(),
        status="running",
    )


def _account_scope() -> int:
    """대상 계정 수(표시용 근사, 정확값은 run 완료 후 manifest). config.accounts 길이로.

    단일 계정은 1, 교차계정은 accounts 수. config 는 LP2PS_CONFIG_INLINE env 에서."""
    import json
    import os

    inline = os.environ.get("LP2PS_CONFIG_INLINE")
    if not inline:
        return 1
    accounts = json.loads(inline).get("accounts", [])
    return max(1, len(accounts))
