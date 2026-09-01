// ============================================================================
// 데이터 계약 (SSOT 초안) — U1에서 확정, M0에서 pydantic models.py 로 승격.
// 프론트↔백엔드↔엔진이 공유하는 단일 계약. 여기 필드는 곧 API 응답 스키마다.
// ============================================================================

export type IdentityType = "role" | "user" | "service" | "sso_ps";
// 신뢰정책 기반 사용 주체 구분(models.py PrincipalKind 와 1:1).
//  human=사람(IAM 사용자·Federated) / service=AWS 서비스 실행 역할 / unknown=Principal.AWS 만(판별 불가)
export type PrincipalKind = "human" | "service" | "unknown";
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
  unused_days: number | null; // as_of − role_last_used(일). role_last_used 가 없으면 null
  // 이 계정에서 CloudTrail 이 **실제로 훑은** 구간(일수 / 가장 오래된 이벤트 시각).
  // null = CloudTrail 근거 없음(Access Advisor 만).
  observed_days: number | null;
  observed_from: string | null;
  escalation_paths: EscalationPath[];
  risk_score: number; // 0-100
  risk_level: RiskLevel;
  risk_reasons: string[];
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

export interface MetricsPoint {
  run_id: string;
  ts: string; // ISO8601
  unused_permissions: number;
  // 판정 불가 권한 수. unused_permissions 에서 빠진 몫이라, 함께 보지 않으면 근거 배선이
  // 개선돼 미사용 수가 줄어든 것을 "정리됐다" 로 오독한다.
  undetermined_permissions: number;
  unused_roles: number;
  // 생성 직후라 관측 기간 자체가 짧은 역할(unused_roles 에서 분리). 어제 만든 역할에 사용 기록이
  // 없는 건 당연하므로 '삭제 후보' 로 세면 배포 중인 것을 지우게 한다.
  new_unused_roles: number;
  long_lived_keys: number;
  no_mfa: number;
  over_privileged_principals: number;
  escalation_paths: number;
  personas: number;
  iam_users_pending_migration: number;
  ps_migration_pct: number;
  risk_dist: RiskDist;
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
}

export interface CatalogEntry {
  persona: string;
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
  actions: PolicyAction[]; // 정책 편집기의 좌측 체크리스트
}

export type CleanupType =
  | "unused_permission"
  | "unused_role"
  // 생성 직후라 관측 기간이 짧은 역할. unused_role 과 갈라 둔다(삭제 권고 아님).
  | "new_role_unused"
  | "long_lived_key"
  | "no_mfa"
  | "escalation_path";

// 조치 진행 상태. 엔진 산출물엔 없고 API 가 도구 소유 DynamoDB 에서 병합한다.
export type CleanupStatus = "open" | "done" | "deferred";

export interface CleanupItem {
  id: string;
  // 조치 상태를 붙이는 내용 기반 안정 키(sha256 hex). `id`(c1, c2…)는 run 마다 밀릴 수 있어 쓰지
  // 않는다. 이전 형식 산출물(구 run)에는 없으므로 빈 문자열일 수 있다 → 그때는 상태 표시 불가.
  finding_key: string;
  type: CleanupType;
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
