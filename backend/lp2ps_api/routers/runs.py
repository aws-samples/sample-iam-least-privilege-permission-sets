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
    row = Run(
        run_id=run.run_id,
        customer=s.customer,
        started_at=run.started_at,
        account_scope=_account_scope(),
        status="running",
    )
    _record_running(row)
    return row


def _record_running(row: Run) -> None:
    """진행 중 run 을 runs 테이블에 즉시 기록한다.

    이 레코드가 없으면 시작된 run 은 **완료될 때까지 어디에도 존재하지 않는다** — 파이프라인 마지막
    stage(engine snapshot)가 종료 시점에야 put 하기 때문이다. 그러면 GET /runs 로는 진행 중 run 을
    관측할 수 없어 (1) 대시보드가 완료를 감지할 수 없고 (2) 실행 이력에 아무것도 안 보이며
    (3) 모델에 정의된 status="running" 이 도달 불가 상태가 된다.

    엔진의 종료 상태 기록은 status == "running" 인 레코드를 덮어쓰도록 허용된다
    (engine/lp2ps/snapshot.py `_write_dynamodb`) — 즉 여기 쓴 값은 완료 시 최종 상태로 갱신된다.

    실패해도 예외를 올리지 않는다: 실행은 이미 Step Functions 에 트리거됐고 파일 산출물이 SoT 이므로,
    이력 기록 실패로 트리거 자체를 실패 처리하면 오히려 오해를 부른다. 로그만 남긴다.
    """
    import json
    import logging

    s = get_settings()
    if not s.runs_table:
        return  # 테이블 미주입(로컬/테스트) — 파일 산출물만.
    try:
        boto3.resource("dynamodb", region_name=s.region).Table(s.runs_table).put_item(
            Item=json.loads(row.model_dump_json()),
            ConditionExpression="attribute_not_exists(run_id)",
        )
    except Exception:
        logging.getLogger("lp2ps.api").warning(
            "진행 중 run 레코드 기록 실패(실행은 계속 진행): %s", row.run_id, exc_info=True
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
