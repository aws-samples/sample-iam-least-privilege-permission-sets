// ============================================================================
// 데이터 계약 (SSOT 초안) — U1에서 확정, M0에서 pydantic models.py 로 승격.
// 프론트↔백엔드↔엔진이 공유하는 단일 계약. 여기 필드는 곧 API 응답 스키마다.
// ============================================================================

export type IdentityType = "role" | "user" | "service" | "sso_ps";
// 신뢰정책 기반 사용 주체 구분(models.py PrincipalKind 와 1:1).
//  human=사람(IAM 사용자·Federated) / service=AWS 서비스 실행 역할 / unknown=Principal.AWS 만(판별 불가)
export type PrincipalKind = "human" | "service" | "unknown";
// **실사용** 근거로 판정한 사용 주체(models.py UsageSubject 와 1:1). principal_kind(신뢰정책 =
// 누가 집을 수 **있나**)와 별개 축이다 — 이쪽은 CloudTrail 이 관측한 "실제로 누가 집었나".
// 신뢰정책만 보면 사람이 쓰는 역할이 전부 unknown 으로 떨어진다. 최종 판정은 두 축의 논리합.
// 🔴 양성 근거만 승격한다. 부재는 판정 근거가 아니다(MFA 표시 없음 ≠ 사람 아님).
export type UsageSubject = "human" | "machine" | "none";
// 세션 이름의 분류 라벨(models.py SessionNameShape 와 1:1). 원문은 계약에 없다 — 개인정보다.
//  email_like=SSO 사용자(사람) / account_id_embedded·uuid_suffix·service_name=자동화(기계)
//  other=어디에도 안 맞음 → 판정 근거로 쓰지 않는다
export type SessionNameShape =
  | "email_like"
  | "account_id_embedded"
  | "uuid_suffix"
  | "service_name"
  | "other";
// 미사용 등급. 경계는 config(risk_rules.unused_tier_days, 기본 30/60/90).
// new = 생성 후 new_principal_days 미만 → 등급 유보(어제 만든 역할에 기록이 없는 건 당연하다).
export type UnusedTier = "active" | "watch" | "review" | "cleanup" | "new";
// 미사용 일수를 **무엇부터** 셌나. 화면 문구가 갈린다:
//  role_last_used : AWS 가 기록한 사실 → 상한 없이 그대로 표시("1,076일 미사용")
//  create_date    : 활동 기록이 없어 생성일부터 셌다 → "AWS 추적 보장 400일" 문구를 함께 붙인다
export type UnusedDaysBasis = "role_last_used" | "create_date";
// 신뢰 대상이 우리 테넌트인지. "외부인가" 가 아니라 **"내부라고 확인됐나"** 를 판정한다 —
// 벤더 역할을 내부로 오판하면 삭제 권고에 올라가 고객이 연동을 끊는다(반대 오판은 확인 한 단계뿐).
export type TrustScope = "internal" | "cross_tenant" | "tooling" | "service" | "unconfirmed";
// 어느 화면으로 가나. 90일 이상 미사용이면 delete_review/owner_review 가 이긴다.
export type Track = "persona" | "service_role" | "delete_review" | "owner_review" | "excluded";
export type RiskLevel = "critical" | "high" | "medium" | "low";
export type ApprovalStatus = "draft" | "review" | "approved";
export type RunStatus = "running" | "succeeded" | "failed" | "degraded";
// 합성 근거 신뢰도 등급. last_accessed_evidence = Access Advisor(서비스별 최종 사용) 또는
// IAM Access Analyzer 미사용 발견이 기여함. 옛 이름 "access_analyzer" 는 근거가 Access
// **Advisor** 인 경우까지 Access Analyzer 로 오표기했다(engine models.py 가 구값을 매핑해 준다).
export type SynthesisSource = "last_accessed_evidence" | "fallback_used_actions";

export interface UsedAction {
  action: string;
  last_used: string | null; // ISO8601, 미사용이면 null
  // CloudTrail 이 **실제로 훑은 구간** 안의 호출 횟수. 옛 이름은 count_90d 였는데 90일을 측정하는
  // 곳이 어디에도 없었다 — 실제 구간은 PrincipalRecord.observed_days 가 말한다.
  count_observed: number;
}

export interface EscalationPath {
  via: string; // 예: "iam:PassRole -> lambda"
  to: string;
  mitre: string; // 예: "TA0004"
}

export interface PrincipalRecord {
  account_id: string;
  principal: string; // ARN
  identity_type: IdentityType;
  principal_kind: PrincipalKind;
  trust_principals: string[]; // 신뢰정책 principal 원문(배지 근거)
  // 실사용 근거 기반 판정과 그 근거 키(예: "iam_user"/"mfa_session"/"invoked_by"/"trust_service").
  // 화면은 맨몸 "판별 불가" 배지 대신 이 값으로 근거 문장을 만든다.
  usage_subject: UsageSubject;
  usage_subject_basis: string;
  // 🔴 세션 이름의 **분류 라벨만**. 원문은 오지 않는다 — SSO 는 세션 이름에 사용자 이메일을 쓰고
  // 자동화 세션 이름에는 계정 ID 가 박힌다(개인정보). 열린 string 이 아니라 닫힌 집합인 이유는
  // 구현 실수 한 번에 원문이 새어 나가는 것을 엔진이 fail-closed 로 막기 때문이다.
  session_name_shape: SessionNameShape | null;
  // 이 principal 이 속한 테넌트 그룹(config accounts[].group). 단일 그룹 배포면 기본 그룹.
  tenant_group: string;
  trust_scope: TrustScope;
  trust_wildcard: boolean; // 신뢰정책이 Principal:"*" 등 광범위
  tags: Record<string, string>;
  granted_actions: string[];
  used_actions: UsedAction[];
  // Access Advisor 가 "이 principal 이 인증했다"고 확인한 서비스(정렬). used_actions 가 비어도
  // 이게 비어 있지 않으면 그 principal 은 쓰이는 중이다 — 미사용 판정 금지의 근거.
  used_services: string[];
  unused_findings: string[]; // 미사용이 확정된 것
  // 판정 불가: 서비스는 인증됐으나 그 action 의 사용 근거가 없는 것. '미사용' 과 섞으면
  // "안 쓰니 지워도 된다"는 잘못된 권고가 된다.
  undetermined_findings: string[];
  mfa: boolean;
  console_login: boolean; // 콘솔 로그인 가능 여부(MFA 관련성 — 서비스 계정 오탐 방지)
  has_managed_policies: boolean; // attached managed 정책 존재(미사용 role 판정 보강)
  access_key_age_days: number | null;
  create_date: string | null; // principal 생성 시각(ISO8601). 미수집이면 null
  age_days: number | null; // 생성 후 경과일. 신규 역할을 '미사용'으로 오판하지 않기 위한 근거
  // IAM 이 직접 추적하는 역할 활동 시각·리전(RoleLastUsed, 전 리전). 콘솔 "Last activity".
  // null = 추적 창(AWS 사양 최대 400일) 안에 활동 기록 없음 → 미사용 기간의 하한을 준다.
  role_last_used: string | null;
  role_last_used_region: string | null;
  // 미사용 일수. ① role_last_used 가 있으면 그날부터(**상한 없음**) ② 없으면 create_date 부터.
  // 둘 다 없으면 null. 값만으로는 부족하다 — 무엇부터 셌는지에 따라 화면 문구가 갈린다.
  unused_days: number | null;
  unused_days_basis: UnusedDaysBasis | null;
  unused_tier: UnusedTier | null; // null = 일수를 셀 근거가 없음
  // 이 계정에서 CloudTrail 이 **실제로 훑은** 구간(일수 / 가장 오래된 이벤트 시각).
  // null = CloudTrail 근거 없음(Access Advisor 만).
  observed_days: number | null;
  observed_from: string | null;
  escalation_paths: EscalationPath[];
  risk_score: number; // 0-100
  risk_level: RiskLevel;
  risk_reasons: string[];
  // 보유한 와일드카드 원문(`*`, `s3:*` 등). 비어 있지 않으면 unused_findings 의 **개수는 의미가 없다**
  // (부여 범위에 상한이 없다) → UI 는 개수 대신 배너를 낸다.
  wildcard_grants: string[];
  // 트랙 배정 결과. null = 미배정(배정 단계를 지나지 않은 레코드) — "excluded" 와 구분해야 한다.
  track: Track | null;
  excluded_reason: string | null; // track="excluded" 의 사유(개수와 함께 화면에 남긴다)
  is_exception: boolean;
  exception_type: string | null;
  source: string[]; // 어느 수집 소스에서 왔는지
  run_id: string;
  ai_suggested: boolean;
}

export interface Run {
  run_id: string;
  customer: string;
  started_at: string; // ISO8601
  account_scope: number; // 계정 수
  status: RunStatus;
}

// 실행 이력 행 확장용 — 한 run 이 왜 그 상태인지(소스별 상태·사유).
export interface RunSourceStatus {
  source: string;
  status: string; // ok | degraded | skipped
  note: string;
}
export interface RunSources {
  run_id: string;
  status: string;
  status_summary: { degraded_sources: string[]; skipped_sources: string[]; has_skipped: boolean } | null;
  accounts: { account_id: string; sources: RunSourceStatus[] }[];
}

export interface RiskDist {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

// 미사용 등급 분포(models.py UnusedTierDist). 등급별 행동이 다르므로 한 숫자로 합치지 않는다.
export interface UnusedTierDist {
  active: number;
  watch: number;
  review: number;
  cleanup: number;
  new: number;
  ungraded: number; // 일수를 셀 근거가 아예 없는 것. 0 이 아니라 **미측정**이다
}

// 3카드 하나의 숫자. 🔴 `targets` 는 **그 카드가 여는 목록의 행 수**로 정의된다 — 엔진이 백로그
// 항목에서 센 값이다. 예전에는 KPI 가 action(41,451)을 세고 눌러서 열린 목록은 principal(329행)을
// 세서, 같은 화면이 서로 다른 것을 세고 있었다. 나머지 필드는 카드 안의 부속 줄이다(분류를 늘리지
// 않고 정보를 잃지 않기 위한 것 — 미사용 action / 와일드카드 / 상승 경로를 카드 밖으로 빼지 않는다).
export interface ActionGroupMetrics {
  group: CleanupGroup;
  targets: number;
  items: number;
  unused_actions: number;
  wildcard_targets: number;
  escalation_paths: number;
  long_lived_keys: number;
}

// 조치 목록에서 **빼 둔** 대상의 사유별 개수. 조용히 빼면 "왜 우리 역할이 여기 없지?" 에 답할 수
// 없다(R6) → 화면에 접힌 한 줄로 남기고 펼치면 사유별로 볼 수 있게 한다.
export interface ExclusionEntry {
  reason: string;
  label: string; // 사람이 읽는 사유. 정본은 엔진(m5_tracks.EXCLUSION_LABEL) — 화면이 사본을 갖지 않는다
  // aws_owned(사실) / customer_declared(고객 config 패턴) / judgment(우리 판단).
  // 등급이 다르면 고객이 할 일도 다르다 — customer_declared 는 자기 패턴이 틀렸는지 봐야 한다.
  basis: string;
  targets: number;
  // 이 사유로 빠진 대상이 원래 받았을 항목 수. 게이트를 넣은 뒤 미사용 action 이 41,451 → 18,532 로
  // 줄었다 — 그 차이를 적지 않으면 "숫자가 반토막 났다" 로 보인다(정리된 게 아니라 애초에 대상이
  // 아니었다는 사실이 사라진 것이다).
  suppressed_items: number;
  // 제외된 대상의 ARN 목록. 개수만으로는 `customer_declared`(고객이 적은 이름 패턴)가 잘못 걸렸는지
  // 화면에서 확인할 방법이 없다 — 그것이 이 등급을 따로 둔 이유다.
  principals?: string[];
}

export interface MetricsPoint {
  run_id: string;
  ts: string; // ISO8601
  // 🔴 지표 **정의** 버전. unused_role 정의가 "사용 근거 전무" → "미사용 90일 이상" 으로 바뀌었다.
  // 이 값이 다른 run 끼리는 숫자를 직접 비교할 수 없다 → 추이 그래프에 경계선을 그린다.
  // 이 표시가 없으면 정의가 바뀌어 숫자가 줄어든 것을 "정리됐다" 로 오독한다.
  definition_version?: number;
  unused_permissions: number;
  // 판정 불가 권한 수. unused_permissions 에서 빠진 몫이라, 함께 보지 않으면 근거 배선이
  // 개선돼 미사용 수가 줄어든 것을 "정리됐다" 로 오독한다.
  undetermined_permissions: number;
  unused_roles: number;
  // 생성 직후라 관측 기간 자체가 짧은 역할(unused_roles 에서 분리). 어제 만든 역할에 사용 기록이
  // 없는 건 당연하므로 '삭제 후보' 로 세면 배포 중인 것을 지우게 한다.
  new_unused_roles: number;
  // unused_roles 중 **삭제 권고를 하지 않는** 몫(신뢰 대상이 우리 테넌트로 확인되지 않음).
  // 백로그 `unused_role` 건수 = unused_roles - owner_review_roles 이고, 나머지는
  // `unconfirmed_trust_role` 로 나간다. 이 값이 없으면 대시보드 숫자와 백로그 건수가 어긋난다
  // (과거에 "대시보드 40 vs 백로그 59" 로 실제로 어긋났다).
  owner_review_roles?: number;
  long_lived_keys: number;
  no_mfa: number;
  over_privileged_principals: number;
  escalation_paths: number;
  personas: number;
  iam_users_pending_migration: number;
  ps_migration_pct: number;
  // 미사용 등급 분포. unused_roles(=cleanup)만 보면 "곧 넘어올 것"(watch/review)이 안 보인다.
  unused_tier_dist?: UnusedTierDist;
  // 전 권한(`*`) 보유 대상 수. 이들은 미사용 개수가 0 으로 잡혀 다른 지표에 기여하지 못한다 —
  // 이 지표가 없으면 가장 위험한 대상이 대시보드에서 사라진다.
  wildcard_grant_principals?: number;
  cross_tenant_trust_roles?: number; // 다른 테넌트 그룹을 신뢰하는 역할 수(경계 위반 의심)
  service_role_targets?: number; // 트랙② 대상(기계가 쓰는 현역 역할) 수
  service_role_unused_actions?: number; // 그 대상들의 미사용 확정 권한 수
  risk_dist: RiskDist;
  // 🔴 대시보드 3카드의 정본. 빈 배열 = 이 필드가 없던 시절의 run → 예전 KPI 를 그린다.
  // 0 세 개를 채워 두면 "할 일이 없다" 는 거짓을 말하게 되므로 엔진도 빈 배열로 낸다.
  action_groups?: ActionGroupMetrics[];
  exclusions?: ExclusionEntry[];
  account_id?: string; // "" 이면 전체 통합. 특정 계정이면 그 계정.
  by_account?: MetricsPoint[]; // 이 run 의 계정별 분해(total 에만 채워짐)
}

// 관리 중인 계정 목록(collection_manifest 유래). 계정 선택기·필터에 사용.
export interface AccountInfo {
  account_id: string;
  status: string; // ok | degraded | skipped 등(수집 상태)
  is_tooling: boolean; // 관제(호출자) 계정 여부
}

// PersonaReview 정책 편집: action 별 포함 여부 토글의 소스
export interface PolicyAction {
  action: string;
  used: boolean; // 실사용 여부 (기본 포함)
  included: boolean; // 최종 정책 포함 여부 (사용자 토글)
  // used=false 의 이유가 "안 썼다"가 아니라 "알 수 없다"인 경우. '미사용' 이 아니라
  // '근거 불명' 으로 표시해야 한다 — 근거 없이 제외를 권하면 워크로드가 깨진다.
  undetermined: boolean;
  last_used: string | null;
  count_observed: number; // 관측 구간 내 호출 횟수(구간은 CatalogEntry.observed_window_days)
}

// persona 적용 대상 1건의 판별 근거(models.py MemberDetail 과 1:1).
// ARN 만으로는 "사람이냐 서비스냐, 근거가 뭐냐"에 답할 수 없어 배지·필터의 소스로 함께 내려온다.
export interface MemberDetail {
  principal: string;
  principal_kind: PrincipalKind;
  trust_principals: string[]; // 신뢰정책 principal 원문
  tags: Record<string, string>; // 소유자 귀속 표시용
  // 실사용 근거 판정과 그 근거 키. 배지가 근거 문장을 만드는 소스다.
  usage_subject?: UsageSubject;
  usage_subject_basis?: string;
  account_id?: string; // 어느 계정의 대상인지(멀티계정 배포에서 목록만 보고는 알 수 없다)
}

export interface CatalogEntry {
  persona: string;
  // 이 persona 가 속한 테넌트 그룹. **군집 키의 축**이다 — 이 축이 없으면 여러 고객의 principal 이
  // 한 persona·한 정책으로 합쳐져 (i) A 고객 정책이 B 고객 사용 실태에서 파생되고 (ii) A 에게 주는
  // 산출물에 B 의 ARN 이 들어가고 (iii) Permission Set 하나가 여러 테넌트에 걸린다.
  // 화면 필터로는 해결되지 않는다 — 표시를 걸러도 정책 내용은 합쳐진 상태 그대로다.
  tenant_group?: string;
  description: string;
  members: string[]; // principal ARN 목록
  member_details: MemberDetail[]; // members 와 동일 순서(principal asc)
  member_count: number;
  policy_ref: string; // s3 key or id
  approval_status: ApprovalStatus;
  ai_suggested: boolean;
  synthesis_source: SynthesisSource; // 근거 신뢰도 등급(고신뢰/폴백)
  contributing_sources?: string[]; // 실제 기여한 수집 소스(access_advisor, cloudtrail 등)
  // 이 persona 멤버들의 CloudTrail 관측 구간 중 **가장 짧은** 값(일). UI 는 "90d" 처럼 측정하지
  // 않은 숫자를 쓰지 말고 이 값을 그대로 표시한다. null = CloudTrail 근거 없음.
  observed_window_days?: number | null;
  // 호출 횟수를 표기하기 위해 필요한 최소 관측 구간(일, config `catalog.count_min_observed_days`).
  // `observed_window_days` 가 이 값 미만이면 횟수를 **아예 표기하지 않는다** — 몇 시간 창의 "3회" 는
  // 총 사용 횟수가 아니고, 총계처럼 보여 주면 고객 신뢰를 깬다(사용자 결정 2026-09-11).
  // 없으면(구 run) `DEFAULT_COUNT_MIN_OBSERVED_DAYS` 를 쓴다 — 감추는 쪽이 안전한 기본값이다.
  count_min_observed_days?: number | null;
  actions: PolicyAction[]; // 정책 편집기의 좌측 체크리스트
}

export type CleanupType =
  | "unused_permission"
  // 🔴 정의가 바뀌었다: "사용 근거가 전무" → **"미사용 90일 이상"**(경계는 config). 근거가 활동
  // 기록이든 생성일이든 무관하다. 정의가 바뀌었으므로 이전 run 과 숫자를 직접 비교할 수 없다 →
  // MetricsPoint.definition_version 을 보고 추이 그래프에 경계선을 그린다.
  | "unused_role"
  // 생성 직후라 관측 기간이 짧은 역할. unused_role 과 갈라 둔다(삭제 권고 아님).
  | "new_role_unused"
  | "long_lived_key"
  | "no_mfa"
  | "escalation_path"
  // 다른 테넌트 그룹의 계정을 신뢰하는 역할. 삭제 권고가 아니라 **경계 위반 의심**이다.
  | "cross_tenant_trust"
  // 90일 이상 미사용인데 신뢰 대상이 우리 테넌트로 확인되지 않은 역할(벤더·외부 도구가 심은 것).
  // 삭제 권고를 하지 않는다 — 목록에 위험한 것이 하나라도 섞이면 고객이 목록 전체를 안 믿는다.
  | "unconfirmed_trust_role"
  // 전 권한(`*`) 보유. 미사용 개수를 셀 수 없어 gap 계산에서 빠지고, 그 결과 가장 위험한 대상이
  // findings 0 으로 가장 깨끗하게 보였다. 권고는 "N개 제거" 가 아니라 실사용 기반 **재작성**이다.
  | "wildcard_grant"
  // 신뢰정책이 Principal:"*" 등으로 광범위. 범위 판정 문제가 아니라 그 자체가 보안 결함이다.
  | "trust_policy_wildcard"
  // 실사용 근거가 서비스 단위로는 있는데 action 단위로 없는 대상. 최소권한 정책을 만들 수 없다 →
  // 삭제도 정책 재작성도 권고하지 않는다. 이 유형이 없던 동안 해당 대상은 백로그에 아무 유형도
  // 없어 화면에서 **통째로 사라졌다**(R6 위반).
  | "unverified_usage";

// 조치 묶음(3카드). type 이 '무엇이 잘못됐나' 라면 group 은 '무엇을 해야 하나' 다.
// 🔴 화면은 type 으로 카드를 묶지 않는다 — 그러면 같은 역할이 '미사용 역할' 과 '미사용 권한'
// 두 카드에 동시에 나온다(실측: unused_role 126건 중 121건). 한 대상은 정확히 한 카드에만 있다.
//   delete_review      쓰이지 않는다 → 지울지 검토
//   reduce_scope       쓰이고 있다 → 권한 범위를 좁힌다(Persona 검토 / 서비스 역할 정리로 라우팅)
//   needs_confirmation 우리가 판단할 수 없다 → 사람이 확인(삭제·정책 변경 권고 아님)
export type CleanupGroup = "delete_review" | "reduce_scope" | "needs_confirmation";

// 트랙② 상세 1행 — 한 역할의 부여 권한을 **서비스(namespace) 단위로 접은** 것.
// 권한을 하나씩 뿌리면 한 역할에서 3,000줄이 나온다(실측). 그건 안 뿌리는 것과 같다.
// 접기 계산은 엔진에서 한다 — UI 가 3,000개를 파싱하지 않는다.
export interface ServiceRollup {
  namespace: string;
  // 🔴 와일드카드는 이 수에서 **빠져 있다**(R4 — `*` 는 gap 계산 대상이 아니다). 그래서
  // `granted_count: 0` 이어도 권한이 없다는 뜻이 아니다. 아래 `wildcard_grants` 를 함께 읽어야 한다.
  granted_count: number;
  // 이 서비스에 걸린 와일드카드 원문(`acm:Get*` 등). 행에서 지우면 전부 부여된 서비스가 화면에서
  // '판정 불가' 로만 보이고, 정작 고쳐야 할 문장(와일드카드 statement)이 어디 있는지 알 수 없다.
  wildcard_grants: string[];
  used_count: number;
  // 이 서비스를 마지막으로 쓴 날. 미사용 action 에는 마지막 사용일이 정의상 없으므로 이 값이
  // 그 서비스에 속한 미사용 권한들의 미사용 일수 **하한선**이다(더 오래일 수는 있어도 짧을 수는 없다).
  last_used: string | null;
  tier: UnusedTier | null;
  //  keep         : 이 서비스는 실제로 쓰인다 → 정책에 남긴다
  //  remove       : 이 서비스를 한 번도 인증한 적이 없다 → 그 안의 어떤 권한도 쓰였을 수 없다
  //  undetermined : 서비스는 썼는데 그 권한들의 근거가 없다 → 손대지 않는다
  verdict: "keep" | "remove" | "undetermined";
}

// 트랙② 목록 1행 — 기계가 쓰는 현역 역할 하나.
// persona 처럼 **묶지 않는다**: Lambda 실행 역할 둘을 한 정책으로 묶으면 서로의 권한을 얻는다.
export interface ServiceRoleEntry {
  account_id: string;
  tenant_group: string;
  principal: string;
  // 부여 권한 집합이 **동일한** 역할들을 화면에서 한 행으로 접기 위한 키(집합 해시).
  // 정책 자체는 여전히 역할별로 따로 낸다 — 묶는 것은 표시뿐이다.
  group_key: string;
  unused_tier: UnusedTier | null;
  unused_days: number | null;
  unused_days_basis: UnusedDaysBasis | null;
  // CloudTrail 이 이 역할에 대해 **실제로 훑은** 구간(일, 측정값). null = CloudTrail 근거 없음.
  // 🔴 verdict 의 근거가 아니다 — `keep`/`remove` 는 Access Advisor 의 양성 근거로만 정해진다.
  // CloudTrail 은 호출 횟수·최근 사용 시각의 근거다. "90일" 처럼 측정하지 않은 숫자를 쓰지 않는다.
  observed_days: number | null;
  // 관측 구간을 **숫자로 말해도 되는** 최소 일수(기준값, config `catalog.count_min_observed_days`).
  // 미만이면 화면이 일수를 아예 표기하지 않는다. 없으면(구 run) UI 폴백을 쓴다.
  count_min_observed_days?: number | null;
  granted_count: number;
  unused_count: number;
  wildcard_grants: string[];
  service_rollups: ServiceRollup[];
  // 사람이 판단해야 하는 **서비스 수**(= `keep` rollup 수, 화면 라벨 "판단 필요 서비스").
  // 화면 노출 여부를 이 값으로 판단한다 — 정리되지 않은 수천 줄을 보여주는 것은 안 보여주는 것보다 나쁘다.
  decision_count: number;
}

// 조치 진행 상태. 엔진 산출물엔 없고 API 가 도구 소유 DynamoDB 에서 병합한다.
export type CleanupStatus = "open" | "done" | "deferred";

export interface CleanupItem {
  id: string;
  // 조치 상태를 붙이는 내용 기반 안정 키(sha256 hex). `id`(c1, c2…)는 run 마다 밀릴 수 있어 쓰지
  // 않는다. 이전 형식 산출물(구 run)에는 없으므로 빈 문자열일 수 있다 → 그때는 상태 표시 불가.
  finding_key: string;
  type: CleanupType;
  // 🔴 null = 이 컬럼이 없던 시절의 cleanup_backlog.csv(고객이 예전 run 을 선택한 경우).
  // 그때는 '미분류' 로 **보여준다** — 숨기면 예전 run 을 열었을 때 목록이 조용히 비어 보인다.
  group?: CleanupGroup | null;
  // 카드 **안의 갈래**. '권한 축소' 는 사람이 쓰는 역할(persona → Persona 검토)과 서비스가 쓰는
  // 역할(service_role → 서비스 역할 정리)로 갈라 서로 다른 화면으로 보낸다. 그 구분은 track
  // 말고는 항목 어디에도 없다 — 화면이 ARN·신뢰정책으로 다시 추측하면 트랙 배정과 어긋난다.
  track?: Track | null;
  account_id: string;
  principal: string;
  detail: string;
  risk_level: RiskLevel;
  recommendation: string;
  risk_score: number; // 0-100 (가중치 합)
  risk_reasons: string[]; // 왜 이 레벨인지 — M4 규칙 근거
  evidence?: Record<string, string>; // 유형별 상세 근거(라벨→값)
  status: CleanupStatus;
  status_note: string;
  status_updated_at: string;
  status_updated_by: string;
}

// PUT /cleanup-backlog/{finding_key}/status 응답.
export interface CleanupStatusRecord {
  finding_key: string;
  status: CleanupStatus;
  note: string;
  updated_at: string;
  updated_by: string;
}

// 위험도 산정 기준(왜 critical/high 인지 설명용). config risk_rules 유래.
export interface RiskRuleInfo {
  key: string;
  label: string;
  weight: number;
  detail: string;
}
export interface RiskCriteria {
  level_critical: number;
  level_high: number;
  level_medium: number;
  rules: RiskRuleInfo[];
  // 미사용 등급 경계(config risk_rules.unused_tier_days). 등급 라벨이 숫자를 말하는 문장이라
  // 필요하다. 구 API 응답에는 없을 수 있어 옵셔널 — 없으면 lib/tierLabel.ts 의 기본값을 쓴다.
  unused_tier_days?: number[];
}

export interface ExecSummary {
  accounts: number;
  principals: number;
  personas: number;
  // 옛 이름은 unused_permissions_removed 였다 — 아무것도 "제거" 하지 않는데(읽기 전용 도구)
  // 제거된 수처럼 읽혔고, 값도 action 수가 아니라 principal 수였다. 둘로 나눈다.
  unused_permission_principals: number;
  unused_permission_actions: number;
  generated_at: string;
  account_id?: string; // "" 이면 전체
  by_account?: ExecSummary[]; // 계정별 분해(전체에만)
}

export interface ReportRef {
  run_id: string;
  report_html_url: string; // presigned (mock: data url)
  iac_zip_url: string;
  exec_summary: ExecSummary;
}

// Assistant grounded Q&A
export interface AssistantAnswer {
  answer: string;
  grounded: boolean; // grounding gate 통과 여부
  citations: { principal?: string; action?: string; source: string }[];
  ai_suggested: true;
}

export interface AssistantMessage {
  role: "user" | "assistant";
  text: string;
  answer?: AssistantAnswer; // assistant 메시지일 때
}

// 승인 시 반환되는 persona Permission Set Terraform
export interface TerraformArtifact {
  persona: string;
  permission_set_name: string;
  filename: string; // 예: DataEngineer.tf
  hcl: string; // 실제 .tf 내용
}

// 승인된 persona 정책을 **무엇으로 반영할지**. IdC 를 쓰지 않는 고객은 permission_set 을 쓸 수 없어
// IAM 산출물이 필요하다(engine/lp2ps/models.py ExportTarget 과 1:1).
//  policy_json       : 정책 문서 원문(콘솔 붙여넣기·기존 정책 교체용)
//  iam_policy_tf     : 관리형 IAM 정책 1개(attach 는 하지 않음)
//  iam_role_tf       : 역할까지 새로 만들 경우(신뢰정책은 Terraform 변수)
//  permission_set_tf : IdC Permission Set. `uses_identity_center=false` 면 목록에 없다.
export type ExportTarget = "policy_json" | "iam_policy_tf" | "iam_role_tf" | "permission_set_tf";

// 승인된 persona 정책의 반영 산출물 1건 (engine/lp2ps/models.py PolicyArtifact 와 1:1)
export interface PolicyArtifact {
  persona: string;
  target: ExportTarget;
  label: string; // UI 탭 제목
  filename: string;
  content: string;
  language: "json" | "hcl";
  // 사람이 반드시 읽어야 하는 제약. 파일 주석에도 있지만 다운로드만 하는 경로가 있어 UI 에도 띄운다.
  notes: string[];
}

// tooling 계정 IdC 에 PS 정의 생성 결과 (opt-in + 2차 확인 후)
export interface ProvisionResult {
  persona: string;
  permission_set_arn: string; // 생성된 PS ARN
  created: boolean;
  // account assignment 은 하지 않음 — 사람이 수동. 이 사실을 UI 에 명시.
  assignment_skipped: true;
  provisioned_at: string;
}

// 주기적 전체 조회 실행 예약(EventBridge). PUT 요청·GET 응답 공통.
export interface ScheduleState {
  enabled: boolean;
  frequency: "daily" | "weekly" | "monthly" | "custom";
  hour_utc: number; // 0-23, daily/weekly/monthly 실행 시각(UTC)
  day_of_week: number; // 1=일 … 7=토 (weekly)
  day_of_month: number; // 1-28 (monthly)
  cron: string; // EventBridge 6필드(괄호 제외). custom 이거나 조회 결과.
}

// AI 개입 기능 런타임 활성 상태(SSM 저장). 대시보드에서 토글.
export interface AiSettings {
  enabled: boolean;
}

// 이 배포의 성격(config 유래, 읽기 전용). IdC 를 쓰지 않는 고객에게는 PS 마이그레이션 지표가
// 구조적으로 달성 불가(분자가 항상 0)라 '해당 없음' 으로 표시한다.
export interface DeploymentSettings {
  uses_identity_center: boolean;
}
