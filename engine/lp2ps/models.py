"""단일 데이터 계약 — 엔진·백엔드·프론트 공유.

`frontend/src/api/types.ts` 와 1:1 대응한다(SSOT). 한쪽을 바꾸면 다른 쪽도 맞춰야 하며,
계약 일치는 mock→real 전환 시 화면이 바뀌지 않기 위한 전제다.

불변식 ②(결정론): 산출물에 wall-clock 금지(`Run.started_at` 제외). 직렬화는 안정 정렬로.
불변식 ③(AI 순수 가산): AI 파생 필드는 `ai_suggested` 등으로 명시 분리.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# ---- 리터럴 타입 (types.ts 와 동일) ----
IdentityType = Literal["role", "user", "service", "sso_ps"]
RiskLevel = Literal["critical", "high", "medium", "low"]
ApprovalStatus = Literal["draft", "review", "approved"]
RunStatus = Literal["running", "succeeded", "failed", "degraded"]
SynthesisSource = Literal["access_analyzer", "fallback_used_actions"]
CleanupType = Literal[
    "unused_permission", "unused_role", "long_lived_key", "no_mfa", "escalation_path"
]


class UsedAction(BaseModel):
    action: str
    last_used: str | None = None  # ISO8601, 미사용이면 None
    count_90d: int = 0


class EscalationPath(BaseModel):
    via: str  # 예: "iam:PassRole -> lambda"
    to: str
    mitre: str  # 예: "TA0004"


class PrincipalRecord(BaseModel):
    account_id: str
    principal: str  # ARN
    identity_type: IdentityType
    granted_actions: list[str] = Field(default_factory=list)
    used_actions: list[UsedAction] = Field(default_factory=list)
    unused_findings: list[str] = Field(default_factory=list)
    mfa: bool = False
    console_login: bool = False  # 콘솔 로그인 가능 여부(MFA 관련성 판단 — 서비스 계정 오탐 방지)
    has_managed_policies: bool = False  # attached managed 정책 존재(미사용 role 판정 보강)
    access_key_age_days: int | None = None
    escalation_paths: list[EscalationPath] = Field(default_factory=list)
    risk_score: int = 0  # 0-100
    risk_level: RiskLevel = "low"
    risk_reasons: list[str] = Field(default_factory=list)
    persona: str | None = None
    persona_confidence: float = 0.0  # 0-1
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
    unused_roles: int = 0
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
    last_used: str | None = None
    count_90d: int = 0


class CatalogEntry(BaseModel):
    persona: str
    description: str
    members: list[str] = Field(default_factory=list)  # principal ARN 목록
    member_count: int = 0
    policy_ref: str  # s3 key or id
    approval_status: ApprovalStatus = "draft"
    ai_suggested: bool = False
    synthesis_source: SynthesisSource = "access_analyzer"  # 근거 신뢰도 등급(고신뢰/폴백)
    # 이 persona 합성에 **실제로 기여한 수집 소스** 목록(멤버 principal 들의 source 합집합).
    # 예: ["access_advisor", "cloudtrail", "credential_report"]. UI 가 근거 출처를 그대로 노출.
    contributing_sources: list[str] = Field(default_factory=list)
    actions: list[PolicyAction] = Field(default_factory=list)


class CleanupItem(BaseModel):
    id: str
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


class ExecSummary(BaseModel):
    accounts: int
    principals: int
    personas: int
    unused_permissions_removed: int
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


class ProvisionResult(BaseModel):
    """tooling 계정 IdC 에 PS 정의 생성 결과 (opt-in + 2차 확인 후).

    account assignment 은 하지 않는다 — 사람이 수동. `assignment_skipped=True` 로 명시.
    """

    persona: str
    permission_set_arn: str
    created: bool
    assignment_skipped: Literal[True] = True
    provisioned_at: str
