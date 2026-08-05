"""M5 Catalog — persona 군집 → catalog.json.

**2축 군집**: persona 는 "어느 영역(도메인)"과 "무엇을 하느냐(접근 성격)"의 조합으로 정의한다.
서비스만으로 묶으면 직군(개발자/운영자/감사자/관리자)이 드러나지 않는다 — 개발자와 운영자는 같은
ec2/lambda 를 쓰지만 동사(Create vs Describe)가 다르기 때문. 그래서 두 축을 조합한다:

  1. **도메인**(축1) — 사용 action 의 지배 서비스 도메인(Compute/Data/Identity/...). Observability·
     Identity 는 거의 모든 role 이 공유하는 부수기능이라 지배도메인 판정에서 디웨이팅한다.
  2. **접근 성격**(축2) — action 동사로: 전부 조회면 ReadOnly(감사자/뷰어), 변경 동사 비중이
     임계 이상이면 Write(개발/운영자), IAM·조직 쓰기 + 광범위면 Admin(관리자).

군집 키 = Admin 이면 `BroadAdmin`(도메인 무시), 아니면 `{도메인}{성격}`(예: ComputeWrite,
DataReadOnly). 결정론 명명 → 사람이 검토·승인(approval_status=draft).

`member_count` = 접근 패턴을 공유하는 principal ARN 수.

불변식 ②(결정론): 동사·도메인 규칙과 정렬만으로 군집, wall-clock/random 없음 → 같은 입력 → 같은 catalog.
불변식 ③: ai_suggested=false (결정론 코어 산출). "이 군집은 Developer 같다" 류의 직군 이름 제안은
AI 하네스(`lp2ps.ai`)에서 순수 가산(결정론 코어는 lp2ps.ai 를 import 하지 않음).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .models import CatalogEntry, PolicyAction, PrincipalRecord, SynthesisSource
from .timeutil import max_ts

if TYPE_CHECKING:  # pragma: no cover
    from .config import CatalogConfig
    from .runctx import RunContext
    from .storage import Storage

CATALOG_NAME = "catalog.json"

# 서비스 네임스페이스 → 기능 도메인. 원시 서비스 집합(수백 종)으로 묶으면 principal 마다 군집이
# 쪼개진다. 도메인으로 묶어 소수의 의미있는 persona 를 만든다.
_SERVICE_DOMAIN = {
    # Data (Database 도 지배도메인 판정에서 Data 로 통합 — 사소한 s3 vs dynamodb 분할 방지)
    "s3": "Data", "glue": "Data", "athena": "Data", "kinesis": "Data", "firehose": "Data",
    "quicksight": "Data", "lakeformation": "Data", "emr": "Data", "airflow": "Data",
    "dynamodb": "Database", "rds": "Database", "elasticache": "Database", "redshift": "Database",
    "docdb": "Database", "neptune": "Database", "memorydb": "Database",
    # Compute / Container / Serverless
    "ec2": "Compute", "autoscaling": "Compute", "ecs": "Container", "ecr": "Container",
    "eks": "Container", "lambda": "Serverless", "batch": "Compute", "amazonmq": "Compute",
    # Networking
    "elasticloadbalancing": "Network", "cloudfront": "Network", "route53": "Network",
    "apigateway": "Network", "vpc": "Network", "globalaccelerator": "Network",
    # Identity / Security
    "iam": "Identity", "sts": "Identity", "sso": "Identity", "identitystore": "Identity",
    "kms": "Security", "secretsmanager": "Security", "acm": "Security", "acm-pca": "Security",
    "access-analyzer": "Security", "guardduty": "Security", "securityhub": "Security",
    "waf": "Security", "wafv2": "Security", "inspector2": "Security",
    # Infra / IaC / Ops
    "cloudformation": "Infra", "ssm": "Ops", "states": "Ops", "events": "Ops",
    "servicecatalog": "Infra", "resource-groups": "Ops", "tag": "Ops", "organizations": "Ops",
    # Observability / Audit
    "logs": "Observability", "cloudwatch": "Observability", "xray": "Observability",
    "cloudtrail": "Audit", "config": "Audit",
    # Cost
    "budgets": "Cost", "ce": "Cost", "cost-optimization-hub": "Cost", "compute-optimizer": "Cost",
}

# 지배도메인 판정 시 부수기능 도메인 디웨이팅. 거의 모든 role 이 로그를 쓰고(logs:PutLogEvents) 자기
# 자격을 조회(sts)하므로, 이들이 지배하면 실제 업무 도메인(Compute/Data)이 가려진다. <1.0 가중.
_AMBIENT_WEIGHT = {"Observability": 0.25, "Identity": 0.4}

# Database → Data 통합(지배도메인 이름).
_DOMAIN_ALIAS = {"Database": "Data"}

# 조회(읽기 전용) 동사 접두 — 이 접두로 시작하지 않는 action 은 '변경(write)'으로 간주한다.
# awsguard 읽기 allowlist 와 개념은 같으나 여기선 persona 성격 판정용(엔진 실행 권한과 무관).
_READ_VERB = re.compile(
    r"^(Get|List|Describe|BatchGet|Simulate|Lookup|Select|Search|Generate|Check|View|Detect"
    r"|Estimate|Discover|Preview|Test|Validate|Query|Scan|Sample|Count|Head|Poll|Read|Resolve"
    r"|Retrieve|Export)"
)

# Admin(관리자) 판정: IAM·조직·SSO 쓰기가 있으면서 서비스 폭이 넓거나, 서비스 폭이 매우 넓은 경우.
_IDENTITY_CONTROL_SERVICES = {"iam", "sso", "organizations"}
_ADMIN_MIN_SERVICES_WITH_IDENTITY = 20  # IAM 쓰기 + 서비스 이만큼 이상 → Admin
_ADMIN_MIN_SERVICES = 50  # IAM 쓰기 없어도 서비스 이만큼 이상 광범위 → Admin
# Write 성격 판정: 변경 동사 비중이 이 이상이면 Write, 미만이면 ReadOnly.
_WRITE_RATIO_THRESHOLD = 0.15


def build_catalog(storage: "Storage", run: "RunContext", cfg: "CatalogConfig") -> list[CatalogEntry]:
    """normalized.parquet → persona 카탈로그(catalog.json). 반환 = CatalogEntry[]."""
    records = storage.read_normalized()

    # 예외/미사용 principal 은 persona 대상에서 제외(사용 실태 기반 최소권한 카탈로그).
    active = [r for r in records if r.used_actions and not r.is_exception]

    # 군집 키(도메인×성격) → principal 목록.
    clusters: dict[str, list[PrincipalRecord]] = {}
    for rec in active:
        key = _cluster_key(rec)
        clusters.setdefault(key, []).append(rec)

    entries: list[CatalogEntry] = []
    small_members: list[PrincipalRecord] = []
    # 군집 키를 정렬해 결정론 순서로 처리.
    for key in sorted(clusters):
        members = clusters[key]
        if len(members) < cfg.min_members_for_persona:
            # 최소 인원 미만 군집은 버리지 않고 'General'(기타)로 합친다 → persona 과다분할 방지.
            small_members.extend(members)
            continue
        entries.append(_entry_for(key, members, cfg))

    if small_members:
        entries.append(_entry_for("General", small_members, cfg))

    # persona 명 정렬(결정론).
    entries.sort(key=lambda e: e.persona)
    _write_catalog(storage, entries)
    return entries


def _domain_of(service: str) -> str:
    """서비스 네임스페이스 → 기능 도메인(미매핑은 'Other')."""
    return _SERVICE_DOMAIN.get(service, "Other")


def _verb_of(action: str) -> str:
    """action → 앞머리 동사(예: 's3:GetObject' → 'Get'). 판정 불가 시 로컬부 그대로."""
    local = action.split(":", 1)[-1]
    m = re.match(r"[A-Z][a-z]+", local)
    return m.group() if m else local


def _is_write(action: str) -> bool:
    """조회 동사로 시작하지 않으면 변경(write) action 으로 간주."""
    return not _READ_VERB.match(_verb_of(action))


def _dominant_domain(rec: PrincipalRecord) -> str:
    """principal 의 used action → 지배 업무 도메인(부수기능 디웨이팅, Other 제외)."""
    weight: dict[str, float] = {}
    for u in rec.used_actions:
        if ":" not in u.action:
            continue
        domain = _domain_of(u.action.split(":", 1)[0])
        if domain == "Other":
            continue  # 미매핑 서비스는 지배도메인 판정에서 제외(Other 오염 방지).
        domain = _DOMAIN_ALIAS.get(domain, domain)
        weight[domain] = weight.get(domain, 0.0) + _AMBIENT_WEIGHT.get(domain, 1.0)
    if not weight:
        return "General"
    # 가중치 desc, 동률은 도메인명 asc(결정론).
    return sorted(weight.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def _access_profile(rec: PrincipalRecord) -> str:
    """principal 의 used action 동사 패턴 → 접근 성격: 'Admin' | 'Write' | 'ReadOnly'."""
    actions = [u.action for u in rec.used_actions if ":" in u.action]
    if not actions:
        return "ReadOnly"
    services = {a.split(":", 1)[0] for a in actions}
    identity_write = any(
        a.split(":", 1)[0] in _IDENTITY_CONTROL_SERVICES and _is_write(a) for a in actions
    )
    if (identity_write and len(services) >= _ADMIN_MIN_SERVICES_WITH_IDENTITY) or (
        len(services) >= _ADMIN_MIN_SERVICES
    ):
        return "Admin"
    write_ratio = sum(1 for a in actions if _is_write(a)) / len(actions)
    return "Write" if write_ratio >= _WRITE_RATIO_THRESHOLD else "ReadOnly"


def _cluster_key(rec: PrincipalRecord) -> str:
    """principal → 군집 키(도메인×성격). Admin 은 도메인 무관하게 'BroadAdmin' 하나로 모은다."""
    profile = _access_profile(rec)
    if profile == "Admin":
        return "BroadAdmin"
    return f"{_dominant_domain(rec)}{profile}"


# 사람이 읽기 쉬운 설명(직군 뉘앙스). AI 직군 이름 제안과 달리 이건 결정론 규칙 기반.
_PROFILE_DESC = {
    "ReadOnly": "읽기 전용(조회·감사 성격)",
    "Write": "변경 권한 포함(개발·운영 성격)",
}


def _entry_for(key: str, members: list[PrincipalRecord], cfg: "CatalogConfig") -> CatalogEntry:
    persona = f"{key}Persona"
    member_arns = sorted(r.principal for r in members)

    # synthesis_source: 멤버 중 하나라도 CloudTrail/analyzer 고신뢰면 access_analyzer, 아니면 fallback.
    high_conf = any("access_advisor" in r.source or "analyzer_unused" in r.source for r in members)
    synthesis_source: SynthesisSource = "access_analyzer" if high_conf else "fallback_used_actions"

    # 이 persona 에 실제 기여한 수집 소스(멤버들의 source 합집합, 결정론 정렬).
    contributing_sources = sorted({s for r in members for s in r.source})

    actions = _merge_actions(members)
    description = _describe(key, len(members))

    return CatalogEntry(
        persona=persona,
        description=description,
        members=member_arns,
        member_count=len(member_arns),
        policy_ref=f"policies/{persona}.json",
        approval_status="draft",
        ai_suggested=False,
        synthesis_source=synthesis_source,
        contributing_sources=contributing_sources,
        actions=actions,
    )


def _describe(key: str, n: int) -> str:
    """군집 키 → 사람이 읽는 설명(도메인 + 접근 성격)."""
    if key == "BroadAdmin":
        return f"광범위한 서비스와 IAM·조직 제어 권한을 실사용하는 관리자 성격 principal {n}개."
    if key == "General":
        return f"소수 군집으로 묶기 어려운 기타 principal {n}개."
    for profile, phrase in _PROFILE_DESC.items():
        if key.endswith(profile):
            domain = key[: -len(profile)]
            return f"{domain} 도메인을 {phrase}으로 실사용하는 principal {n}개의 최소권한 묶음."
    return f"{key} principal {n}개의 최소권한 묶음."


def _merge_actions(members: list[PrincipalRecord]) -> list[PolicyAction]:
    """군집 멤버들의 action → PolicyAction[]. 두 종류를 모두 담아 사람이 검토·판단하게 한다:

    1. **실사용(used)** action: used=True, included=True(기본 포함). last_used·count 병합.
    2. **권한 gap**(granted 이나 미사용, unused_findings): used=False, included=False(기본 제외).
       "정말 필요 없나?" 검토용으로 노출 — 운영자가 enable/disable 로 최종 판단.

    같은 action 이 어떤 멤버엔 used, 다른 멤버엔 unused 면 **used 가 우선**(사용 실적 존재).
    결정론(action 정렬).
    """
    merged: dict[str, PolicyAction] = {}
    # 1) 실사용 action(합집합) — 최근 last_used·count 합산.
    for rec in members:
        for u in rec.used_actions:
            existing = merged.get(u.action)
            if existing is None:
                merged[u.action] = PolicyAction(
                    action=u.action, used=True, included=True,
                    last_used=u.last_used, count_90d=u.count_90d,
                )
            else:
                existing.count_90d += u.count_90d
                # 포맷 혼합 안전 비교(문자열 '>' 금지 — timeutil).
                existing.last_used = max_ts(existing.last_used, u.last_used)

    # 2) 권한 gap(granted 이나 미사용) — used action 에 없는 것만 추가(used 우선).
    for rec in members:
        for finding in rec.unused_findings:
            if ":" not in finding or finding in merged:
                continue  # action 형태만, 이미 used 로 잡힌 건 건너뜀.
            merged[finding] = PolicyAction(
                action=finding, used=False, included=False,
                last_used=None, count_90d=0,
            )
    return sorted(merged.values(), key=lambda a: a.action)


def _write_catalog(storage: "Storage", entries: list[CatalogEntry]) -> None:
    payload = [e.model_dump() for e in entries]
    storage.write_json(CATALOG_NAME, payload)
