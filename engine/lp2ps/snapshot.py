"""snapshot — run.json + metrics_timeseries append.

파이프라인 종료 시 이번 run 의 요약(Run)과 지표(MetricsPoint)를 기록한다:
- `run.json` — 이번 run 의 Run 레코드(status, account_scope 등).
- `metrics_timeseries.json` — MetricsPoint 목록에 이번 run 지표 append(추이용).

로컬은 JSON, hosted 배포는 DynamoDB. 여기선 LocalFS 만. 불변식 ②: ts/started_at 은 run.started_at
(유일 허용 wall-clock), 나머지 지표는 결정론 집계.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .config import RiskRules
from .m6_reporter import (
    cleanup_items,
    is_deletion_reviewable,
    is_new_unused_role,
    is_unused_role,
    summarize_exclusions,
    summarize_groups,
)
from .models import (
    ActionGroupMetrics,
    CatalogEntry,
    ExclusionEntry,
    MetricsPoint,
    PrincipalRecord,
    RiskDist,
    Run,
    RunStatus,
    UnusedTierDist,
)

# 이 코드가 계산하는 지표 **정의**의 버전. `unused_role` 이 "사용 근거 전무" → "미사용 N일 이상" 으로
# 바뀌었으므로 이전 run 과 숫자를 직접 비교할 수 없다. UI 가 이 값의 변화 지점에 경계선을 그린다 —
# 없으면 정의 변경으로 숫자가 줄어든 것을 고객이 "정리됐다" 로 읽는다(같은 함정을 '판정 불가' 분리
# 때 한 번 겪었다). 정의를 또 바꾸면 이 숫자를 올린다.
#
# 3 = 미사용 판정이 사용 근거의 **부재**가 아니라 **마지막 활동 시각**을 본다(`is_idle_beyond`).
# 오래 전에 쓰인 뒤 방치된 역할이 이제 미사용에 든다 → 라이브 실측에서 삭제 검토 대상이 84개 늘고
# 같은 수만큼 권한 축소에서 빠졌다. 숫자가 **늘어난** 방향의 정의 변경이라 경계선이 더 필요하다:
# 없으면 고객이 "지난주보다 미사용이 84개 늘었다" 를 실제 악화로 읽는다.
DEFINITION_VERSION = 3

if TYPE_CHECKING:
    from .config import Config  # pragma: no cover
    from .runctx import RunContext
    from .storage import Storage

RUN_NAME = "run.json"
TIMESERIES_NAME = "metrics_timeseries.json"


def write_snapshot(
    storage: "Storage",
    run: "RunContext",
    account_scope: int,
    status: RunStatus,
    risk_rules: "RiskRules | None" = None,
    cfg: "Config | None" = None,
) -> MetricsPoint:
    """run.json 기록 + metrics_timeseries append. 반환 = 이번 MetricsPoint.

    `cfg` 는 3그룹 카드(`action_groups`)·제외 내역(`exclusions`)을 채우기 위해 받는다. 그 숫자는
    **백로그 항목 목록에서** 세야 하고, 항목을 만들려면 config(IdC 사용 여부·임계치)가 필요하다.
    없으면 두 필드를 빈 목록으로 둔다 — 0 세 개를 채우면 "할 일이 없다" 는 거짓을 말하게 된다.
    """
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

    point = _metrics(records, catalog, run, risk_rules or (cfg.risk_rules if cfg else RiskRules()),
                     cfg=cfg)
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
    records: list[PrincipalRecord], catalog: list[CatalogEntry], run: "RunContext",
    risk_rules: "RiskRules", cfg: "Config | None" = None,
) -> MetricsPoint:
    """전체(모든 계정 통합) MetricsPoint + 계정별 분해(by_account).

    account_id="" 인 total 에 by_account(계정별 MetricsPoint 목록)를 실어, 대시보드가 특정 계정
    선택 시 해당 분해를 쓴다. 결정론: by_account 는 account_id 오름차순.
    """
    total = _metrics_for(records, catalog, run, risk_rules, account_id="", cfg=cfg)

    # 계정별 분해 — persona 는 계정 교차라 계정별 persona 수는 "그 계정 principal 이 속한 persona 수"로.
    accounts = sorted({r.account_id for r in records})
    if len(accounts) > 1:
        by_account: list[MetricsPoint] = []
        for acct in accounts:
            acct_records = [r for r in records if r.account_id == acct]
            acct_catalog = _catalog_for_account(catalog, acct)
            by_account.append(
                _metrics_for(acct_records, acct_catalog, run, risk_rules, account_id=acct, cfg=cfg)
            )
        total.by_account = by_account
    return total


def _catalog_for_account(catalog: list[CatalogEntry], account_id: str) -> list[CatalogEntry]:
    """그 계정 principal(ARN 에 account_id 포함)이 멤버인 persona 만 — 계정별 persona 수 산출용."""
    return [e for e in catalog if any(f":{account_id}:" in m for m in e.members)]


def _metrics_for(
    records: list[PrincipalRecord], catalog: list[CatalogEntry], run: "RunContext",
    risk_rules: "RiskRules", account_id: str, cfg: "Config | None" = None,
) -> MetricsPoint:
    unused_permissions = sum(len([f for f in r.unused_findings if ":" in f]) for r in records)
    undetermined_permissions = sum(
        len([f for f in r.undetermined_findings if ":" in f]) for r in records
    )
    # m6 백로그와 **같은 함수**를 쓴다. 예전엔 여기 조건을 따로 적어 뒀고(`granted_actions` 만 봄,
    # managed-only 역할 누락) 주석은 "같은 판정식" 이라고 주장했지만 실제로는 대시보드 40 vs
    # 백로그 59로 어긋났다.
    #
    # 관측 기간이 짧아 판단 근거가 부족한 신규 역할은 여기서 뺀다 — 삭제 권고 대상이 아니므로
    # "미사용 역할" 카운트에 넣으면 조치 가능 건수를 부풀린다(m6 은 new_role_unused 로 분리).
    unused_roles = sum(1 for r in records if is_unused_role(r, risk_rules.unused_role_days))
    new_unused_roles = sum(
        1 for r in records if is_new_unused_role(r, risk_rules.new_principal_days)
    )
    # 위 `unused_roles` 중 **삭제를 권고하지 않는** 몫(트랙③-b). 백로그와 같은 판정식
    # (`is_deletion_reviewable`)을 쓴다 — 이 지표가 백로그 유형과 다른 조건을 갖는 순간
    # 대시보드와 목록이 어긋나고, 그 어긋남은 화면에서 '숫자가 틀렸다' 로만 보인다.
    owner_review_roles = sum(
        1 for r in records
        if is_unused_role(r, risk_rules.unused_role_days) and not is_deletion_reviewable(r)
    )
    # 미사용 등급 분포. `unused_roles`(=cleanup 경계 이상)만 보면 "곧 넘어올 것"(watch/review)이
    # 안 보인다. 등급을 셀 근거가 없는 것은 0 이 아니라 **미측정**(ungraded)으로 따로 센다.
    tier_dist = UnusedTierDist()
    for r in records:
        key = r.unused_tier or "ungraded"
        setattr(tier_dist, key, getattr(tier_dist, key) + 1)
    # 전 권한(`*`) 보유 대상 수(R4). 이들은 미사용 개수가 0 으로 잡혀 `unused_permissions` 에
    # 기여하지 못한다 — 이 지표가 없으면 가장 위험한 대상이 대시보드에서 사라진다.
    wildcard_grant_principals = sum(1 for r in records if r.wildcard_grants)
    # 테넌트 경계 위반 의심(R5). 이 도구가 스스로 찾기 가장 어려운 종류의 문제라 지표로 올린다 —
    # 개수가 0 이 아니면 그 자체로 조사 사유다.
    cross_tenant_trust_roles = sum(1 for r in records if r.trust_scope == "cross_tenant")
    # 트랙②(기계가 쓰는 현역 역할)의 규모. 실측에서 계정 과권한의 가장 큰 덩어리이고, 예전에는
    # persona 단계에서 조용히 사라져 화면에 아예 나오지 않았다.
    service_role_targets = sum(1 for r in records if r.track == "service_role")
    service_role_unused_actions = sum(
        len([f for f in r.unused_findings if ":" in f])
        for r in records if r.track == "service_role"
    )
    # 임계치는 config 에서(불변식 ④). 예전엔 여기에 90 이 박혀 있어 고객이
    # `risk_rules.long_lived_key_days` 를 바꿔도 이 지표만 90 을 계속 썼다 — m4/m6 과 어긋난다.
    long_lived_keys = sum(
        1 for r in records
        if r.access_key_age_days is not None and r.access_key_age_days >= risk_rules.long_lived_key_days
    )
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

    # 3그룹 카드 + 제외 내역. 🔴 **백로그 항목 목록에서** 센다 — 여기서 레코드를 다시 훑어
    # 자기 기준으로 세면 카드 숫자와 그 카드가 여는 목록의 행 수가 어긋난다(실제로 났던 결함:
    # KPI 는 action 41,451 을 세고 목록은 principal 329 행을 셌다).
    action_groups: list[ActionGroupMetrics] = []
    exclusions: list[ExclusionEntry] = []
    if cfg is not None:
        _items = cleanup_items(records, cfg)
        action_groups = summarize_groups(_items, records)
        exclusions = summarize_exclusions(records, cfg)

    return MetricsPoint(
        run_id=run.run_id,
        ts=run.started_at,
        unused_permissions=unused_permissions,
        undetermined_permissions=undetermined_permissions,
        unused_roles=unused_roles,
        new_unused_roles=new_unused_roles,
        owner_review_roles=owner_review_roles,
        long_lived_keys=long_lived_keys,
        no_mfa=no_mfa,
        over_privileged_principals=over_privileged,
        escalation_paths=escalation_paths,
        personas=len(catalog),
        iam_users_pending_migration=len(iam_users),
        ps_migration_pct=ps_migration_pct,
        risk_dist=dist,
        unused_tier_dist=tier_dist,
        wildcard_grant_principals=wildcard_grant_principals,
        cross_tenant_trust_roles=cross_tenant_trust_roles,
        service_role_targets=service_role_targets,
        service_role_unused_actions=service_role_unused_actions,
        definition_version=DEFINITION_VERSION,
        action_groups=action_groups,
        exclusions=exclusions,
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
