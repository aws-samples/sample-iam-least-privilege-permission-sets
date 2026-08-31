"""snapshot — run.json + metrics_timeseries append.

파이프라인 종료 시 이번 run 의 요약(Run)과 지표(MetricsPoint)를 기록한다:
- `run.json` — 이번 run 의 Run 레코드(status, account_scope 등).
- `metrics_timeseries.json` — MetricsPoint 목록에 이번 run 지표 append(추이용).

로컬은 JSON, hosted 배포는 DynamoDB. 여기선 LocalFS 만. 불변식 ②: ts/started_at 은 run.started_at
(유일 허용 wall-clock), 나머지 지표는 결정론 집계.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .models import (
    CatalogEntry,
    MetricsPoint,
    PrincipalRecord,
    RiskDist,
    Run,
    RunStatus,
)

if TYPE_CHECKING:  # pragma: no cover
    from .runctx import RunContext
    from .storage import Storage

RUN_NAME = "run.json"
TIMESERIES_NAME = "metrics_timeseries.json"


def write_snapshot(
    storage: "Storage",
    run: "RunContext",
    account_scope: int,
    status: RunStatus,
) -> MetricsPoint:
    """run.json 기록 + metrics_timeseries append. 반환 = 이번 MetricsPoint."""
    records = storage.read_normalized()
    catalog = _load_catalog(storage)

    run_row = Run(
        run_id=run.run_id,
        customer=run.customer,
        started_at=run.started_at,
        account_scope=account_scope,
        status=status,
    )
    storage.write_json(RUN_NAME, run_row.model_dump())

    point = _metrics(records, catalog, run)
    _append_timeseries(storage, point)

    # hosted 모드: DynamoDB runs/metrics 테이블에도 기록(테이블명이 env 로 주입된 경우에만).
    # 로컬/CLI 는 테이블명이 없어 skip(파일 산출물만) — 결정론 코어와 분리.
    _write_dynamodb(run_row, point)
    return point


def _write_dynamodb(run_row: Run, point: MetricsPoint) -> None:
    """도구 소유 DynamoDB 에 run/metrics 기록(hosted). 실패해도 파이프라인은 완주(파일이 SoT)."""
    import os

    runs_table = os.environ.get("LP2PS_RUNS_TABLE")
    metrics_table = os.environ.get("LP2PS_METRICS_TABLE")
    if not runs_table and not metrics_table:
        return  # 로컬 모드 — DynamoDB 미사용
    import boto3

    import logging

    from botocore.exceptions import ClientError

    ddb = boto3.resource("dynamodb")
    # run_id(및 metrics 는 run_id+ts) 가 이미 있으면 덮어쓰지 않는다(충돌 감지).
    # 재실행 멱등(같은 run_id 재기록)은 정상 흐름이 아니므로 조건 위반은 로그만 남기고 완주(파일이 SoT).
    if runs_table:
        try:
            # 허용되는 두 경우만 쓴다:
            #  (a) 레코드가 없다 — CLI/로컬 트리거처럼 API 를 거치지 않은 run.
            #  (b) 레코드가 있고 status == "running" — API POST /runs 가 시작 시점에 먼저 넣어둔
            #      진행 중 레코드를 이번 종료 상태로 갱신하는, 정상 흐름.
            # 그 외(이미 종료 상태인 run_id 재기록)는 여전히 거부해 멱등 위반을 잡아낸다.
            ddb.Table(runs_table).put_item(
                Item=_to_ddb(run_row.model_dump()),
                ConditionExpression="attribute_not_exists(run_id) OR #s = :running",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":running": "running"},
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                logging.getLogger("lp2ps.engine").warning(
                    "run_id 충돌(runs 테이블에 이미 종료 상태로 존재) — 덮어쓰지 않음: %s", run_row.run_id
                )
            else:
                raise
    if metrics_table:
        try:
            ddb.Table(metrics_table).put_item(
                Item=_to_ddb(point.model_dump()),
                ConditionExpression="attribute_not_exists(run_id) AND attribute_not_exists(ts)",
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                logging.getLogger("lp2ps.engine").warning(
                    "metrics run_id+ts 충돌 — 덮어쓰지 않음: %s", point.run_id
                )
            else:
                raise


def _to_ddb(obj: dict) -> dict:
    """DynamoDB 용 직렬화 — float 를 Decimal 로(DynamoDB 는 float 미지원)."""
    import json
    from decimal import Decimal

    return json.loads(json.dumps(obj), parse_float=Decimal)


def _metrics(
    records: list[PrincipalRecord], catalog: list[CatalogEntry], run: "RunContext"
) -> MetricsPoint:
    """전체(모든 계정 통합) MetricsPoint + 계정별 분해(by_account).

    account_id="" 인 total 에 by_account(계정별 MetricsPoint 목록)를 실어, 대시보드가 특정 계정
    선택 시 해당 분해를 쓴다. 결정론: by_account 는 account_id 오름차순.
    """
    total = _metrics_for(records, catalog, run, account_id="")

    # 계정별 분해 — persona 는 계정 교차라 계정별 persona 수는 "그 계정 principal 이 속한 persona 수"로.
    accounts = sorted({r.account_id for r in records})
    if len(accounts) > 1:
        by_account: list[MetricsPoint] = []
        for acct in accounts:
            acct_records = [r for r in records if r.account_id == acct]
            acct_catalog = _catalog_for_account(catalog, acct)
            by_account.append(_metrics_for(acct_records, acct_catalog, run, account_id=acct))
        total.by_account = by_account
    return total


def _catalog_for_account(catalog: list[CatalogEntry], account_id: str) -> list[CatalogEntry]:
    """그 계정 principal(ARN 에 account_id 포함)이 멤버인 persona 만 — 계정별 persona 수 산출용."""
    return [e for e in catalog if any(f":{account_id}:" in m for m in e.members)]


def _metrics_for(
    records: list[PrincipalRecord], catalog: list[CatalogEntry], run: "RunContext", account_id: str
) -> MetricsPoint:
    unused_permissions = sum(len([f for f in r.unused_findings if ":" in f]) for r in records)
    undetermined_permissions = sum(
        len([f for f in r.undetermined_findings if ":" in f]) for r in records
    )
    # `used_services` 도 비어야 미사용 — action 세부가 없어 used_actions 만 빈 역할을 미사용으로
    # 세면 지표가 부풀고, m6 백로그 건수와도 어긋난다(같은 판정식을 쓴다).
    unused_roles = sum(
        1
        for r in records
        if r.identity_type == "role" and not r.used_actions and not r.used_services and r.granted_actions
    )
    long_lived_keys = sum(1 for r in records if r.access_key_age_days is not None and r.access_key_age_days >= 90)
    # no_mfa: 콘솔 로그인 가능한 user 만(서비스 계정은 MFA 무관 — m4/m6 와 일치).
    no_mfa = sum(1 for r in records if r.identity_type == "user" and r.console_login and not r.mfa)
    over_privileged = sum(1 for r in records if r.risk_level in ("critical", "high"))
    escalation_paths = sum(len(r.escalation_paths) for r in records)
    iam_users = [r for r in records if r.identity_type == "user"]
    sso_ps = [r for r in records if r.identity_type == "sso_ps"]
    # ps_migration_pct = **현재 스냅샷 비율**: 사람 접근(IAM User + PS 기반) 중 PS 기반 비율.
    # "User→PS 전환 삭제 추적"(원천 불가)이 아니라, 지금 사람 접근이 얼마나 PS 로 되어 있는지.
    # IdC 미설정이면 sso_ps=0 → 0%. 사람 접근이 전혀 없으면(분모 0) 0%.
    human_access = len(iam_users) + len(sso_ps)
    ps_migration_pct = round(100 * len(sso_ps) / human_access) if human_access else 0

    dist = RiskDist()
    for r in records:
        setattr(dist, r.risk_level, getattr(dist, r.risk_level) + 1)

    return MetricsPoint(
        run_id=run.run_id,
        ts=run.started_at,
        unused_permissions=unused_permissions,
        undetermined_permissions=undetermined_permissions,
        unused_roles=unused_roles,
        long_lived_keys=long_lived_keys,
        no_mfa=no_mfa,
        over_privileged_principals=over_privileged,
        escalation_paths=escalation_paths,
        personas=len(catalog),
        iam_users_pending_migration=len(iam_users),
        ps_migration_pct=ps_migration_pct,
        risk_dist=dist,
        account_id=account_id,
    )


def _append_timeseries(storage: "Storage", point: MetricsPoint) -> None:
    """추이 시계열은 **customer 레벨**(run 디렉토리 상위)에 누적한다 — run 마다 새 디렉토리라
    run 내부에 두면 항상 1건이 되어 추이(Dashboard Before/After)가 안 된다."""
    existing: list[dict] = []
    if storage.shared_exists(TIMESERIES_NAME):
        raw = storage.read_shared_json(TIMESERIES_NAME)
        if isinstance(raw, list):
            existing = raw
    # 같은 run_id 는 교체(재실행 멱등) — 그 외 유지. run_id 순 정렬(결정론).
    existing = [m for m in existing if m.get("run_id") != point.run_id]
    existing.append(point.model_dump())
    existing.sort(key=lambda m: m.get("run_id", ""))
    storage.write_shared_json(TIMESERIES_NAME, existing)
    # run 디렉토리에도 이번 point 스냅샷을 남긴다(그 run 의 자기완결 산출물).
    storage.write_json(TIMESERIES_NAME, existing)


def _load_catalog(storage: "Storage") -> list[CatalogEntry]:
    if not storage.exists("catalog.json"):
        return []
    raw = storage.read_json("catalog.json")
    return [CatalogEntry.model_validate(e) for e in raw]  # type: ignore[union-attr]
