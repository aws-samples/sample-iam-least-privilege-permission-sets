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
# **실사용** 근거로 판정한 사용 주체. `principal_kind`(신뢰정책 = 누가 집을 수 **있나**)와 별개 축이다
# — 이쪽은 CloudTrail 이 관측한 "실제로 누가 집었나". 신뢰정책만 보면 사람이 쓰는 역할이 전부
# unknown 으로 떨어진다(실측: 역할 136개 중 human 0개). 최종 판정은 두 축의 논리합.
#  🔴 양성 근거만 승격한다. **부재는 판정 근거가 아니다** — MFA 표시가 없는 것은 사람이 아니라는
#     근거가 못 된다(IdC 콘솔 세션도 없을 수 있다).
UsageSubject = Literal["human", "machine", "none"]
# 세션 이름의 **분류 라벨**. 열린 문자열이 아니라 닫힌 집합이어야 한다 — 세션 이름 원문은 개인정보
# (SSO 는 이메일을 쓴다)이고, 열린 str 이면 구현 실수 한 번에 원문이 산출물로 새어 나간다.
# 라벨을 늘릴 때는 "이 라벨이 원문을 재구성할 수 있나"를 먼저 답할 것.
#  email_like          : 이메일 형식(SSO 사용자) → 사람
#  account_id_embedded : 계정 ID 가 박힌 자동화 세션 → 기계
#  uuid_suffix         : 임의 접미(자동화) → 기계
#  service_name        : 서비스/워크로드 이름 → 기계
#  other               : 위 어디에도 안 맞음 → 판정 근거로 쓰지 않는다
SessionNameShape = Literal[
    "email_like", "account_id_embedded", "uuid_suffix", "service_name", "other"
]
# 미사용 등급. 경계값은 config(`unused_tier_days`, 기본 30/60/90).
#  new = 생성 후 `new_principal_days` 미만 → 등급 유보(어제 만든 역할에 기록이 없는 건 당연하다).
UnusedTier = Literal["active", "watch", "review", "cleanup", "new"]
# 미사용 일수를 **무엇부터** 셌나. 화면 문구가 갈린다:
#  role_last_used : AWS 가 기록한 사실 → 상한 없이 그대로 쓴다(실측에서 1,076일 전 날짜가 나왔다.
#                   문서상 추적 보장이 400일이라고 400일에서 끊으면 근거를 스스로 깎는다).
#  create_date    : 활동 기록이 없어 생성일부터 셌다 → "AWS 추적 보장 400일" 문구를 함께 붙인다.
UnusedDaysBasis = Literal["role_last_used", "create_date"]
# 신뢰 대상이 우리 테넌트인지. **"외부인가" 가 아니라 "내부라고 확인됐나" 를 판정한다** — 오판의
# 비대칭 때문이다. 벤더가 심어둔 역할을 내부로 오판하면 삭제 권고에 올라가 고객이 연동을 끊는다.
# 반대 방향 오판은 "소유자 확인" 으로 한 단계 밀릴 뿐이다. 모르면 보수적으로.
#  internal     : 신뢰 대상이 **같은 테넌트 그룹** 계정
#  cross_tenant : 수집 대상이지만 **다른 그룹** 계정 → 테넌트 경계 위반 의심(삭제 검토 아님)
#  tooling      : 도구가 사는 관리 계정 → 정상 운영 경로. 라벨만
#  service      : AWS 서비스 신뢰
#  unconfirmed  : 어디에도 없음 → 소유자 확인
TrustScope = Literal["internal", "cross_tenant", "tooling", "service", "unconfirmed"]
# 어느 화면으로 가나. **90일 이상 미사용이면 delete_review/owner_review 가 이긴다** — 지울 대상의
# 정책을 다듬는 것은 낭비다.
Track = Literal["persona", "service_role", "delete_review", "owner_review", "excluded"]
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
    # 🔴 `unused_role` 의 정의가 바뀌었다: "사용 근거가 전무" → **"미사용 90일 이상"**(경계는 config).
    # 근거가 활동 기록이든 생성일이든 무관하다. 이전 정의로 잡히던 것 중 30일 미만은 new_role_unused,
    # 나머지는 등급에 따라 흡수된다. 정의가 바뀌었으므로 이전 run 과 숫자를 직접 비교할 수 없다 →
    # MetricsPoint.definition_version 을 보고 UI 가 추이 그래프에 경계선을 그린다.
    "unused_permission", "unused_role", "long_lived_key", "no_mfa", "escalation_path",
    # 생성 직후라 관측 기간 자체가 짧은 역할. unused_role 과 갈라 둔다 — 어제 만든 역할에 사용
    # 기록이 없는 건 당연하고, 그걸 "미사용 역할이니 삭제" 로 권고하면 배포 중인 것을 지우게 한다.
    "new_role_unused",
    # 다른 테넌트 그룹의 계정을 신뢰하는 역할. 삭제 권고가 아니라 **경계 위반 의심**이다 —
    # 여러 고객의 계정을 한 배포에서 관리할 때 이 도구가 스스로 찾기 가장 어려운 종류의 문제다.
    "cross_tenant_trust",
    # 90일 이상 미사용인데 신뢰 대상이 우리 테넌트로 확인되지 않은 역할(벤더·외부 도구가 심어둔 것).
    # **삭제 권고를 하지 않는다** — 안 쓰이는 게 정상인 역할이고, 삭제 목록에 위험한 것이 하나라도
    # 섞이면 고객이 목록 전체를 안 믿는다. 이 목록의 가치는 개수가 아니라 신뢰다.
    "unconfirmed_trust_role",
    # 전 권한(`*`) 보유. 부여 범위에 상한이 없어 **미사용 개수를 셀 수 없다** → gap 계산에서 빠지고,
    # 그 결과 가장 위험한 대상이 findings 0 으로 가장 깨끗하게 보였다. 보유 사실 자체를 findings 로
    # 승격한다. 권고는 "미사용 N개 제거" 가 아니라 실사용 기반 **재작성**이다.
    "wildcard_grant",
    # 신뢰정책이 `Principal:"*"` 등으로 광범위. 범위 판정 문제가 아니라 그 자체가 보안 결함이다.
    "trust_policy_wildcard",
    # 실사용 근거가 서비스 단위로는 있으나 action 단위로 없어 최소권한 정책을 만들 수 없는 대상.
    # 삭제 권고도 정책 권고도 아닌 **확인** 항목이다. 이 유형이 없던 동안 이 대상들은 트랙 배정에서
    # 제외되고 백로그 유형도 없어 화면에서 통째로 사라졌다(R6 위반).
    "unverified_usage",
]

# 🔴 조치 그룹 — 화면의 3카드. **대상(principal) 하나는 정확히 한 그룹에만 속한다.**
#
# 유형(`CleanupType`)은 "무엇이 문제인가" 이고 그룹은 "무엇을 해야 하는가" 다. 유형을 카드로 세우면
# 7~9개가 나오고, 같은 역할이 '미사용 역할' 카드와 '미사용 권한' 카드에 동시에 등장한다 — 실측에서
# `unused_role` 126건 중 121건이 `unused_permission` 에도 있었고, 그래서 "쓰이지 않으니 지워라" 와
# "실사용 기준으로 정책을 다시 써라" 가 같은 역할에 동시에 붙었다(자기모순). 그룹이 그 중복을 없앤다.
#
#   delete_review      — 쓰이지 않는다 → 지울지 검토(트랙③)
#   reduce_scope       — 쓰이고 있다 → 권한 범위를 좁힌다(트랙① persona · 트랙② 서비스 역할)
#   needs_confirmation — 우리가 판단할 수 없다 → 사람이 확인해야 한다(트랙③-b · 관측 기간 부족 등)
#
# 배정 정본은 `m6_reporter.cleanup_group()` 이며 `m5_tracks` 가 배정한 `track` 을 읽는다(다시 판정하지
# 않는다). R6 제외 대상은 그룹이 없다(= 목록에 올리지 않는다) — 개수는 제외 내역에 남는다.
CleanupGroup = Literal["delete_review", "reduce_scope", "needs_confirmation"]
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
    # 🔴 대입도 검증한다. 이 모델의 필드 대부분은 생성 후 단계별로 채워지므로(M2→M3→M4), 생성 시점
    # 검증만으로는 `session_name_shape` 에 세션 이름 **원문**을 넣는 실수를 쓰기 전에 잡을 수 없다 —
    # 개인정보가 산출물에 들어간 뒤 다음 run 이 읽을 때 터진다. 대입 시점에 fail-closed 로 막는다.
    model_config = {"validate_assignment": True}

    account_id: str
    principal: str  # ARN
    identity_type: IdentityType
    # 신뢰정책 기반 구분(M2 가 채운다). 서비스 역할을 persona 군집에서 분리하는 근거.
    principal_kind: PrincipalKind = "unknown"
    # 신뢰정책에 적힌 principal 원문(정렬). UI 배지의 근거를 그대로 노출한다 —
    # 예: ["lambda.amazonaws.com"] → 배지 "Lambda", ["arn:…:root"] → "계정 신뢰".
    trust_principals: list[str] = Field(default_factory=list)
    # ---- 실사용 기반 사용 주체(M2 가 채운다) ----
    # 기본값 "none" 은 fail-safe 다: 근거가 없으면 사람도 기계도 아니라고 말한다(추정하지 않는다).
    usage_subject: UsageSubject = "none"
    # 어느 규칙이 판정했는지의 키(예: "iam_user" / "mfa_session" / "invoked_by" / "trust_service").
    # 화면은 맨몸 "판별 불가" 배지 대신 이 값으로 근거 문장을 만든다.
    usage_subject_basis: str = ""
    # 🔴 세션 이름의 **분류값만** 담는다(예: "email_like" / "uuid_suffix" / "service_name").
    # 원문 금지 — SSO 는 세션 이름에 **사용자 이메일**을 쓰고 자동화 세션 이름에는 계정 ID 가 박힌다.
    # 사람 판정의 가장 강한 근거가 개인정보라는 뜻이다. 판정에만 쓰고 원문은 산출물에 남기지 않는다.
    session_name_shape: SessionNameShape | None = None
    # ---- 테넌트·신뢰 범위(M2) ----
    # 이 principal 이 속한 테넌트 그룹(config `accounts[].group`). 단일 그룹 배포면 기본 그룹.
    # persona 군집 키의 축이다 — 없으면 여러 고객의 principal 이 한 정책으로 합쳐진다.
    tenant_group: str = ""
    trust_scope: TrustScope = "unconfirmed"  # 기본값이 fail-safe(모르면 소유자 확인)
    trust_wildcard: bool = False  # 신뢰정책이 `Principal:"*"` 등 광범위
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
    # IAM 이 직접 추적하는 역할 활동 시각·리전(`RoleLastUsed`, 전 리전 대상). 콘솔 "Last activity".
    # None = **추적 창 안에 활동 기록이 없다**(부재가 정보다 — 미사용 기간의 하한을 준다).
    role_last_used: str | None = None
    role_last_used_region: str | None = None
    # 미사용 일수. ① role_last_used 가 있으면 그날부터(**상한 없음**) ② 없으면 create_date 부터.
    # 둘 다 없으면 None. 무엇부터 셌는지는 `unused_days_basis` 가 말한다 — 화면 문구가 갈리기 때문에
    # 값만으로는 부족하다(① 은 AWS 가 기록한 사실, ② 는 "AWS 추적 보장 400일" 이라는 한계가 붙는다).
    unused_days: int | None = None
    unused_days_basis: UnusedDaysBasis | None = None
    unused_tier: UnusedTier | None = None  # None = 일수를 셀 근거가 없음
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
    # 보유한 와일드카드 원문(`*`, `s3:*` 등, 정렬). 빈 리스트 = 없음. 이 값이 비어 있지 않으면
    # unused_findings 의 개수는 **부여 범위의 상한이 없어** 의미가 없다 → UI 는 개수 대신 배너를 낸다.
    wildcard_grants: list[str] = Field(default_factory=list)
    # 트랙 배정 결과(M5). None = 미배정(아직 배정 단계를 지나지 않은 레코드). "excluded" 를 기본값으로
    # 두면 미배정과 제외가 구분되지 않아, 배정 버그가 "정상적으로 제외됨" 으로 보인다.
    track: Track | None = None
    excluded_reason: str | None = None  # track="excluded" 의 사유(화면에 개수와 함께 노출)
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


class UnusedTierDist(BaseModel):
    """미사용 등급 분포. 등급별로 취해야 할 행동이 다르므로 하나의 숫자로 합치지 않는다."""

    active: int = 0
    watch: int = 0
    review: int = 0
    cleanup: int = 0
    new: int = 0
    # 일수를 셀 근거가 아예 없는 것(활동 기록도 생성일도 없음). 0 이 아니라 **미측정**이다.
    ungraded: int = 0


class ActionGroupMetrics(BaseModel):
    """조치 그룹 1개의 대시보드 카드 값. **백로그 항목에서 집계한다**(레코드에서 따로 세지 않는다).

    이 모델이 존재하는 이유: 예전 대시보드는 `unused_permissions`(=action 수)를 큰 숫자로 걸고
    클릭하면 principal 단위 목록(329행)으로 갔다 — 41,451 을 눌러 329행을 보는 화면이었다. 세는 단위가
    다른 것이 원인이고, 단위를 라벨로 고치는 것만으로는 다음 지표에서 같은 일이 반복된다. 그래서
    카드의 큰 숫자(`targets`)를 **그 카드가 여는 목록의 행 수와 같은 값**으로 정의한다.

    심각도 숫자(`unused_actions`·`wildcard_targets`·`escalation_paths`)는 카드를 따로 세우지 않고 이
    안의 보조 줄로 들어간다 — 세 그룹을 가로지르는 신호라서 카드로 세우면 4번째 분류처럼 보인다.
    """

    group: CleanupGroup
    # 카드의 큰 숫자 = 이 그룹에 속하고 **조치 항목이 하나 이상 있는** 대상(principal) 수
    #                = 이 카드를 눌러 열리는 목록의 행 수(어서션으로 강제).
    targets: int = 0
    items: int = 0  # 그 대상들이 가진 항목 총 건수(대상 하나가 여러 건을 가질 수 있다)
    # --- 그룹을 가로지르는 심각도 신호(카드 안의 보조 줄) ---
    unused_actions: int = 0  # 미사용으로 확정된 action 총계
    wildcard_targets: int = 0  # 전 권한(`*`) 보유 대상 수
    escalation_paths: int = 0  # 권한 상승 경로 건수
    long_lived_keys: int = 0  # 장기 액세스키 대상 수


class ExclusionEntry(BaseModel):
    """조치 목록에서 **빼 둔** 대상의 사유별 개수.

    빼는 것 자체는 옳지만(AWS 소유 역할에 "정책을 다시 쓰라" 고 할 수 없다) 조용히 빼면 "왜 우리
    역할이 여기 없지?" 에 답할 수 없다(R6). 그래서 화면에 접힌 한 줄로 남기고, 펼치면 사유별 대상을
    볼 수 있게 한다 — 이름 패턴으로 뺀 것(고객 선언)은 잘못 걸린 역할을 고객만 알아볼 수 있다.
    """

    reason: str  # `m5_tracks.EXCLUSION_LABEL` 의 키
    label: str  # 사람이 읽는 사유(화면 라벨을 엔진이 정본으로 낸다 — 두 벌이 되면 어긋난다)
    # 근거 등급(`m5_tracks.EXCLUSION_BASIS`): aws_owned / customer_declared / judgment.
    # 등급이 다르면 고객이 할 일도 다르다 — `customer_declared` 는 자기 config 패턴이 틀렸는지
    # 봐야 하고, `judgment` 는 우리 판단이라 뒤집힐 수 있다. 한 덩어리로 보여주면 그 구분이 사라진다.
    basis: str = "judgment"
    targets: int = 0
    # 이 사유로 빠진 대상이 원래 받았을 항목 수. 0 이 아니라는 사실이 "빼도 되는 것을 빼고 있다" 의
    # 근거가 된다(실측: 87개 대상에서 164건이 잘못된 권고를 달고 목록에 올라와 있었다).
    suppressed_items: int = 0
    # 제외된 대상의 ARN 목록(정렬). 개수만 내면 `customer_declared` 등급을 화면에서 **검증할 수
    # 없다** — 그 등급의 존재 이유가 "고객이 적은 이름 패턴이 틀리면 조치 대상이 조용히 빠진다"
    # 인데, 무엇이 걸렸는지 볼 수 없으면 틀린 패턴을 발견할 방법이 없다. `judgment` 등급도 같다:
    # 우리 판단이라 뒤집힐 수 있고, 뒤집으려면 대상을 봐야 한다.
    principals: list[str] = Field(default_factory=list)


class MetricsPoint(BaseModel):
    run_id: str
    ts: str  # ISO8601
    # 🔴 지표 **정의** 버전. `unused_role` 정의가 "사용 근거 전무" → "미사용 90일 이상" 으로 바뀌었다.
    # 이 값이 다른 run 끼리는 숫자를 직접 비교할 수 없다 → UI 가 추이 그래프에 경계선을 그린다.
    # 이 표시가 없으면 정의가 바뀌어 숫자가 줄어든 것을 고객이 "정리됐다" 로 읽는다.
    #
    # 기본값이 **1(구 정의)** 인 이유: 이 필드가 없던 시절의 시계열 항목을 다시 읽을 때 기본값이
    # 적용된다. 그때 2 로 채우면 구 정의 숫자가 신 정의라고 주장하게 되고, 경계선이 사라진다
    # (= 이 필드를 만든 목적이 무효화된다). 쓰는 쪽(`snapshot`)이 현재 버전을 명시한다.
    definition_version: int = 1
    unused_permissions: int = 0
    # 판정 불가 권한 수. unused_permissions 에서 빠진 몫이라, 이 값을 함께 보지 않으면
    # 근거 배선이 개선될 때 미사용 수가 줄어든 것을 "개선" 으로 오독한다.
    undetermined_permissions: int = 0
    unused_roles: int = 0
    # 생성 직후라 관측 기간이 짧은 역할(삭제 권고 대상 아님). unused_roles 에서 뺀 몫이라, 함께
    # 보여주지 않으면 "미사용 역할이 줄었다" 를 개선으로 오독한다.
    new_unused_roles: int = 0
    # 🔴 `unused_roles` 중 **삭제를 권고하지 않는** 몫: 신뢰 대상이 우리 테넌트로 확인되지 않은
    # 역할(트랙③-b, 백로그 유형 `unconfirmed_trust_role`). `unused_roles` 는 "미사용 90일 이상"
    # 이라는 사실의 개수이고 정의는 바뀌지 않았다 — 백로그가 두 유형으로 갈리므로 이 값이 없으면
    # 대시보드 "미사용 역할 N" 과 백로그 "미사용 역할" 카드 건수가 어긋난 것으로 보인다
    # (관계: 백로그 unused_role 건수 = unused_roles - owner_review_roles).
    owner_review_roles: int = 0
    long_lived_keys: int = 0
    no_mfa: int = 0
    over_privileged_principals: int = 0
    escalation_paths: int = 0
    personas: int = 0
    iam_users_pending_migration: int = 0
    ps_migration_pct: int = 0
    # 미사용 등급 분포. `unused_roles`(=cleanup 등급)만 보면 "곧 넘어올 것"(watch/review)이 안 보인다.
    unused_tier_dist: UnusedTierDist = Field(default_factory=UnusedTierDist)
    # 전 권한(`*`) 보유 대상 수. 이들은 미사용 개수가 0 으로 잡혀 다른 지표에 기여하지 못한다 —
    # 이 지표가 없으면 가장 위험한 대상이 대시보드에서 사라진다.
    wildcard_grant_principals: int = 0
    # 다른 테넌트 그룹을 신뢰하는 역할 수(경계 위반 의심).
    cross_tenant_trust_roles: int = 0
    # 트랙② 대상(기계가 쓰는 현역 역할) 수와 그 미사용 확정 권한 수.
    service_role_targets: int = 0
    service_role_unused_actions: int = 0
    risk_dist: RiskDist = Field(default_factory=RiskDist)
    # 🔴 대시보드 3카드. 비어 있으면(이 필드가 없던 시절의 시계열 항목) 화면은 이전 KPI 로 그린다 —
    # 여기에 빈 목록 대신 0 채운 3개를 넣으면 "조치할 것이 없다" 는 거짓을 말한다.
    action_groups: list[ActionGroupMetrics] = Field(default_factory=list)
    # 조치 목록에서 빼 둔 대상(R6). 카드가 아니라 접힌 한 줄로 보여준다.
    exclusions: list[ExclusionEntry] = Field(default_factory=list)
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
    # 실사용 근거 판정과 그 근거 키. 화면이 맨몸 "판별 불가" 배지 대신 근거 문장을 만드는 소스다.
    usage_subject: UsageSubject = "none"
    usage_subject_basis: str = ""
    account_id: str = ""  # 어느 계정의 대상인지(멀티계정 배포에서 목록만 보고는 알 수 없다)


class CatalogEntry(BaseModel):
    persona: str
    # 이 persona 가 속한 테넌트 그룹. **군집 키의 축**이다 — 이 축이 없으면 여러 고객의 principal 이
    # 한 persona·한 정책으로 합쳐져 (i) A 고객 정책이 B 고객 사용 실태에서 파생되고 (ii) A 에게 주는
    # 산출물에 B 의 ARN 이 들어가고 (iii) Permission Set 하나가 여러 테넌트에 걸린다.
    # 화면 필터만으로는 해결되지 않는다 — 표시를 걸러도 정책 내용은 합쳐진 상태 그대로다.
    tenant_group: str = ""
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
    # 화면이 호출 횟수를 표기하기 위해 필요한 최소 관측 구간(일). config `catalog.
    # count_min_observed_days` 유래 — 임계치 리터럴을 UI 에 박으면 불변식 ④ 위반이고, 고객마다
    # 이벤트 발생률이 달라 같은 숫자가 맞지도 않다. `observed_window_days` 는 **측정값**,
    # 이 필드는 **기준값**이다(둘을 한 필드로 합칠 수 없다). 구 catalog.json 호환으로 옵셔널.
    count_min_observed_days: int | None = None
    actions: list[PolicyAction] = Field(default_factory=list)

    @field_validator("synthesis_source", mode="before")
    @classmethod
    def _accept_legacy_synthesis_source(cls, v: object) -> object:
        """이전 run 의 catalog.json(`access_analyzer`)도 읽을 수 있게 매핑한다."""
        return _LEGACY_SYNTHESIS_SOURCE.get(v, v) if isinstance(v, str) else v


class ServiceRollup(BaseModel):
    """트랙② 상세 1행 — 한 역할의 부여 권한을 **서비스(namespace) 단위로 접은** 것.

    권한을 하나씩 뿌리면 한 역할에서 3,000줄이 나온다(실측). 그건 안 뿌리는 것과 같다 — 아무도
    읽지 않고 스크롤만 한다. 권한 이름이 `서비스:동작` 구조이므로 앞부분으로 접으면, 실측에서
    미사용 권한 14,732개가 서비스 단위 2,669행이 되고 **사람이 내릴 결정은 332건**이 된다.
    """

    namespace: str
    # **셀 수 있는** 부여 권한 수. 서비스 단위 와일드카드(`acm:Get*`)는 여기서 빠진다 — 부여 범위에
    # 상한이 없어 개수를 셀 수 없기 때문이다(R4, M2 의 갭 계산과 같은 규칙).
    granted_count: int = 0
    used_count: int = 0
    # 이 서비스에 걸린 와일드카드 부여(`acm:Get*` 등). 개수에서 뺀 것을 **버리지 않고** 남긴다:
    # 빼기만 하면 열거 가능한 권한이 전부 미사용 확정인 서비스가 근거 없이 '판정 불가' 로 보이고
    # (실측에서 판정 불가 행의 대부분이 이것이었다), 반대로 개수에 넣으면 R4 를 어긴다.
    # 정리 결정을 실행할 때 **이 와일드카드 문 자체를 고쳐야 한다**는 신호이기도 하다.
    wildcard_grants: list[str] = Field(default_factory=list)
    # 이 서비스를 마지막으로 쓴 날(Access Advisor). 미사용 action 에는 마지막 사용일이 정의상 없으므로
    # 이 값이 **그 서비스에 속한 미사용 권한들의 미사용 일수 하한선**이 된다. 하한선이라 실제로는 더
    # 오래일 수 있지만 이보다 짧을 수는 없다 — 근거를 부풀리지 않는 방향으로만 쓴다.
    last_used: str | None = None
    tier: UnusedTier | None = None
    #  keep         : 이 서비스는 실제로 쓰인다 → 정책에 남긴다
    #  remove       : 이 서비스를 **한 번도 인증한 적이 없다** → 그 안의 어떤 권한도 쓰였을 수 없다
    #  undetermined : 서비스는 썼는데 그 권한들의 근거가 없다 → 손대지 않는다
    verdict: Literal["keep", "remove", "undetermined"] = "undetermined"


class ServiceRoleEntry(BaseModel):
    """트랙② 목록 1행 — 기계가 쓰는 현역 역할 하나.

    persona 처럼 **묶지 않는다**. Lambda 실행 역할 둘을 한 정책으로 묶으면 서로의 권한을 얻는다 —
    최소권한의 반대다. 역할별로 정책 1개다.
    """

    account_id: str
    tenant_group: str = ""
    principal: str
    # 부여 권한 집합이 **동일한** 역할들을 화면에서 한 행으로 접기 위한 키(집합 해시).
    # 실측 84개 역할 → 49그룹. 정책 자체는 여전히 역할별로 따로 낸다(묶는 것은 표시뿐이다).
    group_key: str = ""
    unused_tier: UnusedTier | None = None
    unused_days: int | None = None
    unused_days_basis: UnusedDaysBasis | None = None
    # 이 역할에 대해 CloudTrail 이 **실제로 훑은** 구간(일, 측정값). None = CloudTrail 근거 없음.
    # 🔴 이 값은 **verdict 의 근거가 아니다** — `keep`/`remove` 는 Access Advisor 의 양성 근거로만
    # 정해진다(`_rollups`). CloudTrail 은 호출 횟수·최근 사용 시각의 근거일 뿐이다. 화면에 "90일"
    # 같은 측정하지 않은 숫자를 쓰지 않기 위해 값을 그대로 내려보낸다.
    observed_days: int | None = None
    # 관측 구간을 **숫자로 말해도 되는** 최소 일수(기준값, config `catalog.count_min_observed_days`).
    # 미만이면 화면이 일수를 표기하지 않는다(몇 시간 창을 "0일" 로 쓰면 고객은 화면 결함으로 읽는다).
    # 구 산출물 호환으로 옵셔널.
    count_min_observed_days: int | None = None
    granted_count: int = 0
    unused_count: int = 0
    wildcard_grants: list[str] = Field(default_factory=list)
    service_rollups: list[ServiceRollup] = Field(default_factory=list)
    # 사람이 판단해야 하는 **서비스 수**(= `keep` rollup 수). 화면 라벨 "판단 필요 서비스" 와 단위가
    # 같다. 예전에는 여기에 "일괄 제거" 묶음 1건을 더해 서비스 수와 작업 수가 섞여 있었다(F15-2).
    # 화면 노출 여부를 이 값으로 판단한다 — 정리되지 않은 수천 줄은 안 보여주는 것보다 나쁘다.
    decision_count: int = 0


class CleanupItem(BaseModel):
    id: str
    # 조치 상태를 붙이기 위한 **내용 기반 안정 키**(sha256 hex). `id` 는 정렬 후 부여하는 순번(c1, c2…)
    # 이라 항목이 하나 늘거나 사라지면 뒤의 모든 항목이 밀린다 — 그걸 키로 상태를 저장하면 다음 run
    # 에서 "조치완료" 가 엉뚱한 항목에 붙는다. 산출은 m6_reporter.cleanup_finding_key.
    finding_key: str = ""
    type: CleanupType
    # 화면 카드 배정(3그룹). 한 대상의 모든 항목은 **같은 그룹**을 갖는다 — 그룹은 대상의 트랙에서
    # 나오고 항목 유형에서 나오지 않는다.
    #
    # `None` 은 이 필드가 없던 시절의 `cleanup_backlog.csv` 를 다시 읽는 경우다(고객이 예전 run 을
    # 선택할 수 있다). 그때 임의의 그룹으로 메꾸면 틀린 카드에 얹히므로 비워 두고, 화면이 '미분류'
    # 로 **보이게** 처리한다 — `track=None` 을 기본값으로 둔 것과 같은 이유다(조용히 사라지는 것 금지).
    group: CleanupGroup | None = None
    # 이 대상의 트랙(`m5_tracks` 배정값). group 이 3카드를 정하고, track 은 카드 **안의 갈래**를
    # 정한다 — '권한 축소' 는 사람이 쓰는 역할(persona → Persona 검토)과 서비스가 쓰는 역할
    # (service_role → 서비스 역할 정리)로 갈라 서로 다른 화면으로 보내야 하고, 그 구분은 track
    # 말고는 항목 어디에도 없다. 화면이 ARN·신뢰정책으로 다시 추측하면 트랙 배정과 어긋난다.
    track: Track | None = None
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
