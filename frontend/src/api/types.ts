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
export type SynthesisSource = "access_analyzer" | "fallback_used_actions";

export interface UsedAction {
  action: string;
  last_used: string | null; // ISO8601, 미사용이면 null
  count_90d: number;
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
  unused_findings: string[];
  mfa: boolean;
  console_login: boolean; // 콘솔 로그인 가능 여부(MFA 관련성 — 서비스 계정 오탐 방지)
  has_managed_policies: boolean; // attached managed 정책 존재(미사용 role 판정 보강)
  access_key_age_days: number | null;
  escalation_paths: EscalationPath[];
  risk_score: number; // 0-100
  risk_level: RiskLevel;
  risk_reasons: string[];
  persona: string | null;
  persona_confidence: number; // 0-1
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
  unused_roles: number;
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
  last_used: string | null;
  count_90d: number;
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
  actions: PolicyAction[]; // 정책 편집기의 좌측 체크리스트
}

export type CleanupType =
  | "unused_permission"
  | "unused_role"
  | "long_lived_key"
  | "no_mfa"
  | "escalation_path";

export interface CleanupItem {
  id: string;
  type: CleanupType;
  account_id: string;
  principal: string;
  detail: string;
  risk_level: RiskLevel;
  recommendation: string;
  risk_score: number; // 0-100 (가중치 합)
  risk_reasons: string[]; // 왜 이 레벨인지 — M4 규칙 근거
  evidence?: Record<string, string>; // 유형별 상세 근거(라벨→값)
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
  unused_permissions_removed: number;
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
