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

**여기에 테넌트 그룹이 축으로 하나 더 붙는다**(R8): 군집은 그룹 안에서만 이뤄진다. 여러 고객 계정을
한 배포에서 관리할 때, 축이 없으면 A 고객 정책이 B 고객 사용 실태에서 파생되고 A 에게 주는 산출물에
B 계정 ARN 이 들어간다. 화면 필터로는 해결되지 않는다 — 표시를 걸러도 정책 내용은 합쳐진 상태다.

대상 선별은 이 모듈이 하지 않는다. `m5_tracks` 가 배정한 `track == "persona"` 만 읽는다.

`member_count` = 접근 패턴을 공유하는 principal ARN 수.

불변식 ②(결정론): 동사·도메인 규칙과 정렬만으로 군집, wall-clock/random 없음 → 같은 입력 → 같은 catalog.
불변식 ③: ai_suggested=false (결정론 코어 산출). "이 군집은 Developer 같다" 류의 직군 이름 제안은
AI 하네스(`lp2ps.ai`)에서 순수 가산(결정론 코어는 lp2ps.ai 를 import 하지 않음).
"""

from __future__ import annotations

import re
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING

from .models import CatalogEntry, MemberDetail, PolicyAction, PrincipalRecord, SynthesisSource
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
# 임계치(몇 종부터 '광범위'인가, 변경 비중 몇 %부터 Write 인가)는 config `catalog` 에 있다(불변식 ④).
_IDENTITY_CONTROL_SERVICES = {"iam", "sso", "organizations"}


def build_catalog(storage: "Storage", run: "RunContext", cfg: "CatalogConfig") -> list[CatalogEntry]:
    """normalized.parquet → persona 카탈로그(catalog.json). 반환 = CatalogEntry[]."""
    records = storage.read_normalized()
    active = [r for r in records if _is_persona_member(r, cfg)]

    # 군집 키(**테넌트 그룹** × 도메인 × 성격) → principal 목록. 테넌트 축이 없으면 A 고객 정책이
    # B 고객 사용 실태에서 파생되고 A 에게 주는 산출물에 B 계정 ARN 이 들어간다(R8).
    clusters: dict[tuple[str, str], list[PrincipalRecord]] = {}
    for rec in active:
        clusters.setdefault((rec.tenant_group, _cluster_key(rec, cfg)), []).append(rec)

    entries: list[CatalogEntry] = []
    # 소수 군집을 합치는 'General' 도 **그룹별로** 따로 모은다. 하나로 합치면 격리가 여기서 새고,
    # 그 경로가 가장 눈에 안 띈다(정상 군집은 분리됐는데 기타 묶음만 섞인다).
    small_by_group: dict[str, list[PrincipalRecord]] = {}
    # 군집 키를 정렬해 결정론 순서로 처리.
    for group, key in sorted(clusters):
        members = clusters[(group, key)]
        if len(members) < cfg.min_members_for_persona:
            # 최소 인원 미만 군집은 버리지 않고 'General'(기타)로 합친다 → persona 과다분할 방지.
            small_by_group.setdefault(group, []).extend(members)
            continue
        entries.append(_entry_for(key, members, cfg, group))

    for group in sorted(small_by_group):
        entries.append(_entry_for("General", small_by_group[group], cfg, group))

    # persona 명 정렬(결정론).
    entries.sort(key=lambda e: e.persona)
    _write_catalog(storage, entries)
    return entries


def _is_persona_member(rec: PrincipalRecord, cfg: "CatalogConfig") -> bool:
    """이 principal 이 persona 묶음 대상인가.

    배정이 끝난 레코드(`track` 채워짐)는 **다시 판정하지 않는다** — 트랙은 `m5_tracks` 가 한 곳에서
    정하고(제외 사유까지 함께 남긴다) 여기서 조건을 또 쓰면 화면이 "제외" 라고 말한 대상이 persona
    에 들어 있는 어긋남이 생긴다.

    `track` 이 없을 때만 예전 규칙으로 내려간다. 두 경우가 있다: 이 필드가 없던 시절의
    `normalized.parquet` 을 다시 읽는 경우, 그리고 `assign_tracks` 없이 이 함수를 직접 부르는 경우.
    """
    if rec.track is not None:
        return rec.track == "persona"
    # 예외/실사용 근거 없는 principal 은 대상 아님(사용 실태 기반 최소권한 카탈로그).
    if not rec.used_actions or rec.is_exception:
        return False
    # 서비스 실행 역할 제외(기본 켜짐) — 신뢰정책 근거. `unknown`(Principal.AWS 만)은 남긴다:
    # 신뢰정책만으로 갈릴 수 없으므로 추측으로 버리지 않고 사람이 볼 수 있게 카탈로그에 둔다.
    if cfg.exclude_service_roles and rec.principal_kind == "service":
        return False
    # IaC 배포 전용 역할 제외(이름 패턴). 신뢰정책이 `Principal.AWS` 뿐이라 위 필터를 통과하는
    # CDK/Terraform 배포 역할을 걸러낸다 — 사람이 assume 하는 역할이 아니므로 persona 대상이 아니다.
    return not (
        cfg.exclude_principal_patterns
        and _matches_pattern(rec.principal, cfg.exclude_principal_patterns)
    )


def _matches_pattern(arn: str, patterns: list[str]) -> bool:
    """ARN 이 제외 패턴에 걸리는가. 이름(마지막 세그먼트)과 전체 ARN 둘 다 대조한다.

    `fnmatchcase` 를 쓴다 — `fnmatch` 는 플랫폼 파일시스템 규칙을 따라 macOS 에서 대소문자를 무시하고
    Linux 에서는 구분한다. 그러면 같은 config 가 로컬과 Lambda 에서 다른 결과를 내 불변식 ②(결정론)가
    깨진다. 명시적으로 대소문자를 구분한다.
    """
    name = arn.rsplit("/", 1)[-1]
    return any(fnmatchcase(name, p) or fnmatchcase(arn, p) for p in patterns)


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


def _access_profile(rec: PrincipalRecord, cfg: "CatalogConfig") -> str:
    """principal 의 used action 동사 패턴 → 접근 성격: 'Admin' | 'Write' | 'ReadOnly'."""
    actions = [u.action for u in rec.used_actions if ":" in u.action]
    if not actions:
        return "ReadOnly"
    services = {a.split(":", 1)[0] for a in actions}
    identity_write = any(
        a.split(":", 1)[0] in _IDENTITY_CONTROL_SERVICES and _is_write(a) for a in actions
    )
    if (identity_write and len(services) >= cfg.admin_min_services_with_identity) or (
        len(services) >= cfg.admin_min_services
    ):
        return "Admin"
    write_ratio = sum(1 for a in actions if _is_write(a)) / len(actions)
    return "Write" if write_ratio >= cfg.write_ratio_threshold else "ReadOnly"


def _cluster_key(rec: PrincipalRecord, cfg: "CatalogConfig") -> str:
    """principal → 군집 키(도메인×성격). Admin 은 도메인 무관하게 'BroadAdmin' 하나로 모은다."""
    profile = _access_profile(rec, cfg)
    if profile == "Admin":
        return "BroadAdmin"
    return f"{_dominant_domain(rec)}{profile}"


# 사람이 읽기 쉬운 설명(직군 뉘앙스). AI 직군 이름 제안과 달리 이건 결정론 규칙 기반.
_PROFILE_DESC = {
    "ReadOnly": "읽기 전용(조회·감사 성격)",
    "Write": "변경 권한 포함(개발·운영 성격)",
}


def _persona_name(key: str, tenant_group: str) -> str:
    """군집 키 → persona 명. 기본 그룹은 접두를 **붙이지 않는다**.

    격리를 디렉터리 층위가 아니라 이름으로 하는 이유: `policies/{persona}.json` 경로를 persona
    **이름에서 다시 만드는** 호출부가 셋이다(`m7_iac_emitter` · `m7_policy_synth` ·
    백엔드 repositories). 층위를 넣으면 세 곳이 조용히 엇갈린 경로를 만든다.

    기본 그룹에 접두를 안 붙이는 것은 하위호환이다 — 단일 그룹 배포(문자열 목록 config)는 persona
    명과 정책 경로가 이전과 **바이트 동일**하게 유지되고, 승인 상태·Permission Set 이름이 이름으로
    이어져 있어서 접두가 붙으면 전부 새 persona 로 보인다.
    """
    from .config import DEFAULT_TENANT_GROUP

    if not tenant_group or tenant_group == DEFAULT_TENANT_GROUP:
        return f"{key}Persona"
    return f"{tenant_group}_{key}Persona"


def _entry_for(
    key: str, members: list[PrincipalRecord], cfg: "CatalogConfig", tenant_group: str = ""
) -> CatalogEntry:
    persona = _persona_name(key, tenant_group)
    by_arn = {r.principal: r for r in members}
    member_arns = sorted(by_arn)
    # 판별 근거를 members 와 동일 순서로 실어 보낸다(UI 배지·사람/서비스 필터용). 사람의 분류를
    # 저장하지 않고 매 run 신뢰정책에서 다시 판정하므로 여기서 파생값을 복사하는 것으로 충분하다.
    member_details = [
        MemberDetail(
            principal=arn,
            principal_kind=by_arn[arn].principal_kind,
            trust_principals=list(by_arn[arn].trust_principals),
            tags=dict(by_arn[arn].tags),
            # 실사용 축(R1)과 계정. 이게 유일하게 principal 단위 근거가 화면에 닿는 경로다 —
            # `PrincipalRecord` 는 프론트에서 쓰이지 않는다. 이 세 값이 없으면 배지는 신뢰정책만
            # 보고 사람이 쓰는 역할을 전부 '판별 불가' 로 표시한다.
            usage_subject=by_arn[arn].usage_subject,
            usage_subject_basis=by_arn[arn].usage_subject_basis,
            account_id=by_arn[arn].account_id,
        )
        for arn in member_arns
    ]

    # synthesis_source: 멤버 중 하나라도 **last-accessed 계열 소스**(Access Advisor 서비스별
    # 최종 사용 / IAM Access Analyzer 미사용 발견)를 가지면 고신뢰, 아니면 관측된 used action 뿐인
    # 폴백. CloudTrail 은 여기 판정에 들어가지 않는다 — 과거 주석은 "CloudTrail/analyzer" 라고
    # 적혀 있었지만 코드는 CloudTrail 을 보지 않는다(옛 라벨 'access_analyzer' 도 실제 근거가
    # Access **Advisor** 인 경우까지 IAM Access Analyzer 로 오표기했다).
    high_conf = any("access_advisor" in r.source or "analyzer_unused" in r.source for r in members)
    synthesis_source: SynthesisSource = (
        "last_accessed_evidence" if high_conf else "fallback_used_actions"
    )

    # 이 persona 에 실제 기여한 수집 소스(멤버들의 source 합집합, 결정론 정렬).
    contributing_sources = sorted({s for r in members for s in r.source})

    actions = _merge_actions(members)
    description = _describe(key, len(members))
    # 관측 창은 멤버 중 **가장 좁은** 값으로 보고한다(계정마다 CloudTrail 페이지 상한에 걸린 지점이
    # 달라 창 길이가 다르다). 넓은 쪽을 쓰면 근거가 없는 기간까지 관측한 것처럼 보인다.
    windows = [r.observed_days for r in members if r.observed_days is not None]
    observed_window_days = min(windows) if windows else None

    return CatalogEntry(
        persona=persona,
        tenant_group=tenant_group,
        description=description,
        members=member_arns,
        member_details=member_details,
        member_count=len(member_arns),
        policy_ref=f"policies/{persona}.json",
        approval_status="draft",
        ai_suggested=False,
        synthesis_source=synthesis_source,
        contributing_sources=contributing_sources,
        observed_window_days=observed_window_days,
        count_min_observed_days=cfg.count_min_observed_days,
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
    3. **판정 불가**(undetermined_findings): used=False, included=False, undetermined=True.
       기본 제외는 2 와 같지만 **이유가 다르다** — 안 썼다는 증거가 아니라 증거가 없다는 뜻이다.
       빼면 UI 에서 사라져 사람이 포함시킬 기회를 잃고, 2 에 섞으면 '미사용' 이라 거짓말하게 된다.

    같은 action 이 어떤 멤버엔 used, 다른 멤버엔 unused 면 **used 가 우선**(사용 실적 존재).
    미사용 확정과 판정 불가가 겹치면 **미사용 확정이 우선**(한 멤버에서라도 안 썼다고 확인됐다).
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
                    last_used=u.last_used, count_observed=u.count_observed,
                )
            else:
                existing.count_observed += u.count_observed
                # 포맷 혼합 안전 비교(문자열 '>' 금지 — timeutil).
                existing.last_used = max_ts(existing.last_used, u.last_used)

    # 2) 권한 gap(granted 이나 미사용) — used action 에 없는 것만 추가(used 우선).
    for rec in members:
        for finding in rec.unused_findings:
            if ":" not in finding or finding in merged:
                continue  # action 형태만, 이미 used 로 잡힌 건 건너뜀.
            merged[finding] = PolicyAction(
                action=finding, used=False, included=False,
                last_used=None, count_observed=0,
            )

    # 3) 판정 불가 — used 도 아니고 미사용 확정도 아닌 것만(둘 다 우선).
    for rec in members:
        for finding in rec.undetermined_findings:
            if ":" not in finding or finding in merged:
                continue
            merged[finding] = PolicyAction(
                action=finding, used=False, included=False, undetermined=True,
                last_used=None, count_observed=0,
            )
    return sorted(merged.values(), key=lambda a: a.action)


def _write_catalog(storage: "Storage", entries: list[CatalogEntry]) -> None:
    payload = [e.model_dump() for e in entries]
    storage.write_json(CATALOG_NAME, payload)
