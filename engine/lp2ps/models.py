"""단일 데이터 계약 — 엔진·백엔드·프론트 공유.

`frontend/src/api/types.ts` 와 1:1 대응한다(SSOT). 한쪽을 바꾸면 다른 쪽도 맞춰야 하며,
계약 일치는 mock→real 전환 시 화면이 바뀌지 않기 위한 전제다.

불변식 ②(결정론): 산출물에 wall-clock 금지(`Run.started_at` 제외). 직렬화는 안정 정렬로.
불변식 ③(AI 순수 가산): AI 파생 필드는 `ai_suggested` 등으로 명시 분리.
"""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, BaseModel, Field, field_validator

# ---- 리터럴 타입 (types.ts 와 동일) ----
IdentityType = Literal["role", "user", "service", "sso_ps"]
# 신뢰정책(AssumeRolePolicyDocument) 기반 사용 주체 구분 — persona 대상 여부를 가른다.
#  human   : IAM 사용자, 또는 Federated(SAML/OIDC) 신뢰 역할 → 사람이 로그인해 쓴다.
#  service : Principal.Service 가 있는 역할 → AWS 서비스가 실행 주체(사람이 로그인 불가).
#  unknown : Principal.AWS 만(계정/역할 신뢰) → 신뢰정책만으로는 갈리지 않는다. 다른 근거 필요.
PrincipalKind = Literal["human", "service", "unknown"]
RiskLevel = Literal["critical", "high", "medium", "low"]
ApprovalStatus = Literal["draft", "review", "approved"]
RunStatus = Literal["running", "succeeded", "failed", "degraded"]
# 합성 근거의 신뢰도 등급. `last_accessed_evidence` = Access Advisor(서비스별 최종 사용) 또는
# IAM Access Analyzer 미사용 발견이 기여함. 옛 이름은 `access_analyzer` 였는데, 실제 근거가
# Access **Advisor** 인 경우까지 IAM Access Analyzer 로 오표기했다(Terraform 태그·정책 메타에
# 그대로 새겨졌다) — CatalogEntry 에 구값을 읽어 주는 alias 를 둔다.
SynthesisSource = Literal["last_accessed_evidence", "fallback_used_actions"]
_LEGACY_SYNTHESIS_SOURCE = {"access_analyzer": "last_accessed_evidence"}
CleanupType = Literal[
    "unused_permission", "unused_role", "long_lived_key", "no_mfa", "escalation_path",
    # 생성 직후라 관측 기간 자체가 짧은 역할. unused_role 과 갈라 둔다 — 어제 만든 역할에 사용
    # 기록이 없는 건 당연하고, 그걸 "미사용 역할이니 삭제" 로 권고하면 배포 중인 것을 지우게 한다.
    "new_role_unused",
]
# 조치 진행 상태. 엔진은 항상 "open"(미조치)만 낸다 — 사람이 무엇을 처리했는지는 엔진이 알 수 없다.
# 상태는 API 가 도구 소유 DynamoDB(findings)에 따로 보관하고 조회 시 병합한다(불변식 ②: 코어 산출물은
# 결정론이어야 하므로 사람의 판단을 산출물에 섞지 않는다).
CleanupStatus = Literal["open", "done", "deferred"]


class UsedAction(BaseModel):
    action: str
    last_used: str | None = None  # ISO8601, 미사용이면 None
    # CloudTrail 이 **실제로 훑은 구간** 안의 호출 횟수. 예전 이름은 count_90d 였는데 90일을
    # 측정하는 곳이 어디에도 없었다 — LookupEvents 는 페이지 상한에 걸려 라이브에서 2.5일만 덮었고
    # Access Advisor 는 최대 400일 창이다. 실제 구간은 `PrincipalRecord.observed_days` 가 말한다.
    count_observed: int = Field(
        default=0, validation_alias=AliasChoices("count_observed", "count_90d")
    )


class EscalationPath(BaseModel):
    via: str  # 예: "iam:PassRole -> lambda"
    to: str
    mitre: str  # 예: "TA0004"


class PrincipalRecord(BaseModel):
    account_id: str
    principal: str  # ARN
    identity_type: IdentityType
    # 신뢰정책 기반 구분(M2 가 채운다). 서비스 역할을 persona 군집에서 분리하는 근거.
    principal_kind: PrincipalKind = "unknown"
    # 신뢰정책에 적힌 principal 원문(정렬). UI 배지의 근거를 그대로 노출한다 —
    # 예: ["lambda.amazonaws.com"] → 배지 "Lambda", ["arn:…:root"] → "계정 신뢰".
    trust_principals: list[str] = Field(default_factory=list)
    # role/user 태그(키→값). 소유자 귀속 시도용 표시 정보이며 분류 입력으로는 쓰지 않는다.
    tags: dict[str, str] = Field(default_factory=dict)
    granted_actions: list[str] = Field(default_factory=list)
    used_actions: list[UsedAction] = Field(default_factory=list)
    # Access Advisor 가 "이 principal 이 인증했다"고 확인한 서비스 네임스페이스(정렬).
    # action 세부까지 주지 않는 서비스도 여기엔 남는다 — `used_actions` 가 비어 있어도 이 목록이
    # 비어 있지 않으면 그 principal 은 **쓰이는 중**이다(미사용 판정 금지).
    used_services: list[str] = Field(default_factory=list)
    # granted 인데 실사용 근거가 없고, 그 근거 부재가 "안 썼다"로 확정되는 것들.
    unused_findings: list[str] = Field(default_factory=list)
    # granted 인데 **판정 불가**: 서비스는 인증됐지만 Access Advisor 가 그 action 을 추적하지 않고
    # CloudTrail 에도 안 잡힌 것. 미사용과 섞으면 "안 쓰니 지워도 된다"는 잘못된 권고가 된다.
    undetermined_findings: list[str] = Field(default_factory=list)
    mfa: bool = False
    console_login: bool = False  # 콘솔 로그인 가능 여부(MFA 관련성 판단 — 서비스 계정 오탐 방지)
    has_managed_policies: bool = False  # attached managed 정책 존재(미사용 role 판정 보강)
    access_key_age_days: int | None = None
    # IAM 생성일(ISO8601)과 as_of 기준 경과일. "사용 기록이 없다" 를 "안 쓰니 지워라" 로 읽으려면
    # 관측 가능 기간이 필요하다 — 생성 3일 된 역할에 기록이 없는 건 당연하다.
    create_date: str | None = None
    age_days: int | None = None
    # 이 계정에서 CloudTrail 이 **실제로 훑은** 구간(일수 / 가장 오래된 이벤트 시각).
    # LookupEvents 는 최신순 페이지 상한이 있어 요청한 90일이 아니라 며칠만 덮일 수 있다.
    # None = CloudTrail 근거 없음(Access Advisor 만).
    observed_days: int | None = None
    observed_from: str | None = None
    escalation_paths: list[EscalationPath] = Field(default_factory=list)
    risk_score: int = 0  # 0-100
    risk_level: RiskLevel = "low"
    risk_reasons: list[str] = Field(default_factory=list)
    # NOTE: 여기에 있던 `persona`/`persona_confidence` 는 **어느 모듈도 채우지 않아** 항상
    # null/0.0 으로 나가던 유령 필드였다(persona 귀속은 CatalogEntry.members 가 계약). 계약에
    # 남겨 두면 UI/고객이 "신뢰도 0" 을 실측값으로 읽는다 → 제거. 되살릴 때는 채우는 코드와 함께.
    is_exception: bool = False
    exception_type: str | None = None
    source: list[str] = Field(default_factory=list)  # 어느 수집 소스에서 왔는지
    run_id: str
    ai_suggested: bool = False


class Run(BaseModel):
    run_id: str
    customer: str
    started_at: str  # ISO8601 — 결정론 예외(유일하게 wall-clock 허용)
    account_scope: int  # 계정 수
    status: RunStatus


class RiskDist(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class MetricsPoint(BaseModel):
    run_id: str
    ts: str  # ISO8601
    unused_permissions: int = 0
    # 판정 불가 권한 수. unused_permissions 에서 빠진 몫이라, 이 값을 함께 보지 않으면
    # 근거 배선이 개선될 때 미사용 수가 줄어든 것을 "개선" 으로 오독한다.
    undetermined_permissions: int = 0
    unused_roles: int = 0
    # 생성 직후라 관측 기간이 짧은 역할(삭제 권고 대상 아님). unused_roles 에서 뺀 몫이라, 함께
    # 보여주지 않으면 "미사용 역할이 줄었다" 를 개선으로 오독한다.
    new_unused_roles: int = 0
    long_lived_keys: int = 0
    no_mfa: int = 0
    over_privileged_principals: int = 0
    escalation_paths: int = 0
    personas: int = 0
    iam_users_pending_migration: int = 0
    ps_migration_pct: int = 0
    risk_dist: RiskDist = Field(default_factory=RiskDist)
    # 계정 필터용. account_id="" 이면 전체(모든 계정 통합) 집계. by_account 는 이 run 의 계정별
    # 분해(각 항목 account_id 채워짐, by_account 는 비움) — 대시보드가 특정 계정 선택 시 사용.
    account_id: str = ""
    by_account: list["MetricsPoint"] = Field(default_factory=list)


class PolicyAction(BaseModel):
    """PersonaReview 정책 편집기의 action 체크리스트 항목."""

    action: str
    used: bool = False  # 실사용 여부 (기본 포함)
    included: bool = False  # 최종 정책 포함 여부 (사용자 토글)
    # used=False 의 이유가 "안 썼다"가 아니라 "알 수 없다"인 경우. UI 가 '미사용' 대신
    # '근거 불명' 으로 표시해야 한다 — 근거 없이 제외를 권하면 워크로드를 깨뜨린다.
    undetermined: bool = False
    last_used: str | None = None
    # 관측 구간 내 호출 횟수(구간은 CatalogEntry.observed_window_days). DynamoDB 에 이미 저장된
    # persona override 는 구 키(`count_90d`)로 들어 있어 alias 로 받아야 값이 0 으로 유실되지 않는다.
    count_observed: int = Field(
        default=0, validation_alias=AliasChoices("count_observed", "count_90d")
    )


class MemberDetail(BaseModel):
    """persona 적용 대상 1건의 판별 근거.

    `members`(ARN 문자열 목록)만으로는 "이 대상이 사람이냐 서비스냐, 근거가 뭐냐"에 답할 수 없어
    운영자가 목록을 보고도 판단을 못 한다. 신뢰정책 파생 값(`m2_normalizer` 산출)을 그대로 실어
    UI 가 배지·필터로 보여준다 — 사람의 분류를 저장하지 않고 매 run 소스에서 다시 판정한다.
    """

    principal: str
    principal_kind: PrincipalKind = "unknown"
    trust_principals: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)  # 소유자 귀속 표시용(분류 입력 아님)


class CatalogEntry(BaseModel):
    persona: str
    description: str
    members: list[str] = Field(default_factory=list)  # principal ARN 목록
    # members 와 **같은 순서**(principal asc)의 판별 근거. members 를 지우지 않는 이유: 승인
    # member_hash·Terraform 생성이 이미 이 필드를 계약으로 쓴다.
    member_details: list[MemberDetail] = Field(default_factory=list)
    member_count: int = 0
    policy_ref: str  # s3 key or id
    approval_status: ApprovalStatus = "draft"
    ai_suggested: bool = False
    synthesis_source: SynthesisSource = "last_accessed_evidence"  # 근거 신뢰도 등급(고신뢰/폴백)
    # 이 persona 합성에 **실제로 기여한 수집 소스** 목록(멤버 principal 들의 source 합집합).
    # 예: ["access_advisor", "cloudtrail", "credential_report"]. UI 가 근거 출처를 그대로 노출.
    contributing_sources: list[str] = Field(default_factory=list)
    # 이 persona 멤버들의 CloudTrail 관측 구간 중 **가장 짧은** 값(일). UI 가 "횟수(90d)" 처럼
    # 측정하지 않은 숫자를 쓰지 않도록, 실제로 훑은 구간을 그대로 표시하게 한다.
    # None = CloudTrail 근거 없음(Access Advisor 만으로 합성).
    observed_window_days: int | None = None
    actions: list[PolicyAction] = Field(default_factory=list)

    @field_validator("synthesis_source", mode="before")
    @classmethod
    def _accept_legacy_synthesis_source(cls, v: object) -> object:
        """이전 run 의 catalog.json(`access_analyzer`)도 읽을 수 있게 매핑한다."""
        return _LEGACY_SYNTHESIS_SOURCE.get(v, v) if isinstance(v, str) else v


class CleanupItem(BaseModel):
    id: str
    # 조치 상태를 붙이기 위한 **내용 기반 안정 키**(sha256 hex). `id` 는 정렬 후 부여하는 순번(c1, c2…)
    # 이라 항목이 하나 늘거나 사라지면 뒤의 모든 항목이 밀린다 — 그걸 키로 상태를 저장하면 다음 run
    # 에서 "조치완료" 가 엉뚱한 항목에 붙는다. 산출은 m6_reporter.cleanup_finding_key.
    finding_key: str = ""
    type: CleanupType
    account_id: str
    principal: str
    detail: str
    risk_level: RiskLevel
    recommendation: str
    # 위험도 설명 — 운영자가 "왜 이 레벨인지" 즉시 인지하도록. M4 점수·근거를 그대로 전달.
    risk_score: int = 0  # 0-100(가중치 합)
    risk_reasons: list[str] = Field(default_factory=list)  # 예: "장기 액세스키(612일 ≥ 90)"
    # 유형별 상세 근거(라벨→값). 상세 화면에서 "왜/무엇" 을 더 깊이 보여준다.
    # 예(unused_permission): {"미사용 action 수": "35", "granted 총 action": "50", "대표 미사용": "s3:Delete…"}
    evidence: dict[str, str] = Field(default_factory=dict)
    # ---- 조치 상태(사람이 표시) — 엔진 산출물에는 담지 않는다. API 가 findings 테이블에서 병합. ----
    status: CleanupStatus = "open"
    status_note: str = ""  # 조치완료/보류 사유(예: "IdC 없이 IAM 정책만 다듬어 적용함")
    status_updated_at: str = ""  # ISO8601
    status_updated_by: str = ""  # 표시한 운영자(Cognito email 또는 sub)


class ExecSummary(BaseModel):
    accounts: int
    principals: int
    personas: int
    # 미사용 권한을 가진 **principal 수**. 예전 이름은 unused_permissions_removed 였는데 (a) 이 도구는
    # 읽기 전용이라 아무것도 제거하지 않고, (b) 세는 단위가 principal 인데 대시보드의 "미사용 권한"
    # 은 action 수라 두 화면이 서로 다른 숫자를 같은 이름으로 보여줬다(74 vs 2,271).
    # 옛 exec_summary.json 을 계속 읽을 수 있게 alias 로 받는다.
    unused_permission_principals: int = Field(
        validation_alias=AliasChoices("unused_permission_principals", "unused_permissions_removed")
    )
    # 같은 항목의 action 총계(대시보드 "미사용 권한" 과 같은 단위).
    unused_permission_actions: int = 0
    generated_at: str
    # 계정 필터용. account_id="" 이면 전체. by_account 는 계정별 분해(각 항목 account_id 채움).
    account_id: str = ""
    by_account: list["ExecSummary"] = Field(default_factory=list)


class ReportRef(BaseModel):
    run_id: str
    report_html_url: str
    iac_zip_url: str
    exec_summary: ExecSummary


class Citation(BaseModel):
    principal: str | None = None
    action: str | None = None
    source: str


class AssistantAnswer(BaseModel):
    answer: str
    grounded: bool  # grounding gate 통과 여부
    citations: list[Citation] = Field(default_factory=list)
    ai_suggested: Literal[True] = True


class TerraformArtifact(BaseModel):
    """승인 시 반환되는 persona Permission Set Terraform."""

    persona: str
    permission_set_name: str
    filename: str
    hcl: str


# 승인된 persona 정책을 **무엇으로 반영할지**. IdC 를 쓰지 않는 고객은 permission_set 을 쓸 수 없어
# IAM 산출물이 필요하다(이게 없으면 정책을 다듬어 승인해도 반영할 물건이 없다).
#  policy_json      : 정책 문서 원문(콘솔 붙여넣기·기존 정책 교체용)
#  iam_policy_tf    : 관리형 IAM 정책 1개(attach 는 하지 않음 — 어느 역할에 붙일지는 사람이 정한다)
#  iam_role_tf      : 역할까지 새로 만들 경우(신뢰정책은 LP2PS 가 알 수 없어 변수로 뺀다)
#  permission_set_tf: IdC Permission Set(기존 산출물)
ExportTarget = Literal["policy_json", "iam_policy_tf", "iam_role_tf", "permission_set_tf"]


class PolicyArtifact(BaseModel):
    """승인된 persona 정책의 반영 산출물 1건.

    `TerraformArtifact`(PS 전용)를 대체하지 않고 일반화한다 — PS 는 `permission_set_tf` 타깃이다.
    `notes` 는 **사람이 반드시 읽어야 하는 제약**이며 UI 가 그대로 노출한다(파일 주석과 중복돼도
    괜찮다 — 파일을 열지 않고 다운로드만 하는 경로가 있다).
    """

    persona: str
    target: ExportTarget
    label: str  # UI 탭 제목
    filename: str
    content: str
    language: Literal["json", "hcl"]
    notes: list[str] = Field(default_factory=list)


class ProvisionResult(BaseModel):
    """tooling 계정 IdC 에 PS 정의 생성 결과 (opt-in + 2차 확인 후).

    account assignment 은 하지 않는다 — 사람이 수동. `assignment_skipped=True` 로 명시.
    """

    persona: str
    permission_set_arn: str
    created: bool
    assignment_skipped: Literal[True] = True
    provisioned_at: str
