// ============================================================================
// Mock data — sample scenario: 24 accounts · 1,284 principals · Run1→Run5 trend.
// This shape is the API response contract (types.ts). The goal is no UI change when switching
// from mock to real.
// ============================================================================
import type {
  CatalogEntry,
  CleanupItem,
  CleanupStatus,
  MetricsPoint,
  PolicyAction,
  ReportRef,
  Run,
  ServiceRoleEntry,
  ServiceRollup,
} from "@/api/types";

export const CUSTOMER = "example-corp";

// ---- Runs (Run1 → Run5, 미사용 권한이 점진 감소하는 개선 추이) ----
export const RUNS: Run[] = [
  { run_id: "run-005", customer: CUSTOMER, started_at: "2026-07-14T02:00:00Z", account_scope: 24, status: "succeeded" },
  { run_id: "run-004", customer: CUSTOMER, started_at: "2026-06-30T02:00:00Z", account_scope: 24, status: "succeeded" },
  { run_id: "run-003", customer: CUSTOMER, started_at: "2026-06-16T02:00:00Z", account_scope: 24, status: "degraded" },
  { run_id: "run-002", customer: CUSTOMER, started_at: "2026-06-02T02:00:00Z", account_scope: 22, status: "succeeded" },
  { run_id: "run-001", customer: CUSTOMER, started_at: "2026-05-19T02:00:00Z", account_scope: 20, status: "succeeded" },
];

// ---- Metrics 시계열 (Run1=Before → Run5=최신) ----
// 🔴 `definition_version` 은 **두 번** 바뀐다: run-004 에서 1→2, run-005 에서 2→3
// (엔진 `snapshot.DEFINITION_VERSION=3`). 그 지점마다 `unused_roles` 가 **늘어난다** — 정의가
// "사용 근거 전무" → "미사용 90일 이상"(v2) → "마지막 활동 시각 기준"(v3, `is_idle_beyond`)으로
// 넓어졌기 때문이다. 목데이터에서 이 구간을 계속 단조 감소로 두면 경계선 시리즈가 "있어도 없어도
// 화면이 같은" 장식이 되고, 오독을 막는지 검증할 수 없다.
// 🔴 변경 지점이 **두 개**인 것이 의도다(사용자 피드백 2026-09-11 #14-b): 예전 UI 는 첫 경계에서
// 멈춰 두 번째를 안 그렸다. 경계가 하나뿐인 픽스처로는 그 결함이 통과한다 — 어서션이 판별력을
// 가지려면 목데이터에 두 번째 경계가 있어야 한다. 이 값을 되돌려 붙이지 말 것.
export const METRICS: MetricsPoint[] = [
  {
    run_id: "run-001", ts: "2026-05-19T02:00:00Z", definition_version: 1,
    unused_permissions: 1604, undetermined_permissions: 612, unused_roles: 59, new_unused_roles: 7, long_lived_keys: 23, no_mfa: 14,
    over_privileged_principals: 512, escalation_paths: 37, personas: 6,
    iam_users_pending_migration: 148, ps_migration_pct: 12,
    // 정의 v1 은 등급을 세지 않았다 → 등급 분포 없음. UI 가 이를 0 으로 채우지 않는지(=`전부 active`
    // 라고 주장하지 않는지) 확인하려면 목데이터에도 없는 run 이 있어야 한다.
    wildcard_grant_principals: 14, cross_tenant_trust_roles: 3,
    service_role_targets: 96, service_role_unused_actions: 604,
    risk_dist: { critical: 141, high: 288, medium: 402, low: 380 },
  },
  {
    run_id: "run-002", ts: "2026-06-02T02:00:00Z", definition_version: 1,
    unused_permissions: 1498, undetermined_permissions: 588, unused_roles: 55, new_unused_roles: 6, long_lived_keys: 22, no_mfa: 13,
    over_privileged_principals: 471, escalation_paths: 33, personas: 6,
    iam_users_pending_migration: 131, ps_migration_pct: 24,
    wildcard_grant_principals: 13, cross_tenant_trust_roles: 3,
    service_role_targets: 94, service_role_unused_actions: 571,
    risk_dist: { critical: 128, high: 271, medium: 419, low: 421 },
  },
  {
    run_id: "run-003", ts: "2026-06-16T02:00:00Z", definition_version: 1,
    unused_permissions: 1421, undetermined_permissions: 566, unused_roles: 52, new_unused_roles: 6, long_lived_keys: 21, no_mfa: 12,
    over_privileged_principals: 438, escalation_paths: 30, personas: 7,
    iam_users_pending_migration: 118, ps_migration_pct: 38,
    wildcard_grant_principals: 12, cross_tenant_trust_roles: 2,
    service_role_targets: 92, service_role_unused_actions: 540,
    risk_dist: { critical: 119, high: 260, medium: 431, low: 461 },
  },
  {
    run_id: "run-004", ts: "2026-06-30T02:00:00Z", definition_version: 2,
    // 정의가 넓어진 run — 미사용 역할이 52 → 78 로 뛴다(정리가 후퇴한 것이 아니다).
    unused_permissions: 1352, undetermined_permissions: 540, unused_roles: 78, new_unused_roles: 6, long_lived_keys: 19, no_mfa: 10,
    over_privileged_principals: 401, escalation_paths: 27, personas: 7,
    iam_users_pending_migration: 92, ps_migration_pct: 54,
    unused_tier_dist: { active: 402, watch: 118, review: 64, cleanup: 78, new: 6, ungraded: 31 },
    owner_review_roles: 14,
    wildcard_grant_principals: 11, cross_tenant_trust_roles: 2,
    service_role_targets: 90, service_role_unused_actions: 512,
    risk_dist: { critical: 110, high: 251, medium: 439, low: 484 },
  },
  {
    run_id: "run-005", ts: "2026-07-14T02:00:00Z", definition_version: 3,
    // 두 번째 정의 변경(2→3). 여기서는 `unused_roles` 가 78 → 71 로 **줄어든다** — run-004 와
    // 방향이 반대인 것이 의도다: 경계선은 "늘었다=악화" 와 "줄었다=정리됐다" 두 오독을 모두 막아야
    // 하므로 목데이터에 양쪽 방향이 하나씩 있어야 한다.
    unused_permissions: 1284, undetermined_permissions: 521, unused_roles: 71, new_unused_roles: 5, long_lived_keys: 18, no_mfa: 9,
    over_privileged_principals: 368, escalation_paths: 24, personas: 8,
    iam_users_pending_migration: 71, ps_migration_pct: 66,
    unused_tier_dist: { active: 418, watch: 109, review: 58, cleanup: 71, new: 5, ungraded: 27 },
    // 🔴 `unused_roles`(71) 중 삭제 권고를 **하지 않는** 몫. 백로그 `unused_role` 건수 = 71-12 = 59
    // 이고 나머지 12 는 `unconfirmed_trust_role` 로 나간다. run-001~003(정의 v1)에는 이 값이 없다 —
    // 필드가 없을 때 화면이 힌트를 지우는지(0 으로 단정하지 않는지) 확인하려면 없는 run 이 있어야 한다.
    owner_review_roles: 12,
    wildcard_grant_principals: 9, cross_tenant_trust_roles: 2,
    service_role_targets: 88, service_role_unused_actions: 471,
    risk_dist: { critical: 103, high: 244, medium: 437, low: 500 },
  },
];

// ---- 정책 편집기용 action 체크리스트 헬퍼 ----
// granted_unused 의 마지막 1건은 '근거 불명' 으로 만든다 — 실제 배포에선 미사용 판정의 약 28%가
// 판정 불가로 갈리므로, mock 화면도 그 분기를 반드시 렌더해야 UI 검증이 실배포와 어긋나지 않는다.
function mkActions(
  used: [string, string, number][], // [action, last_used, count]
  granted_unused: string[],
): PolicyAction[] {
  return [
    ...used.map(([action, last_used, count_observed]) => ({
      action, used: true, included: true, undetermined: false, last_used, count_observed,
    })),
    ...granted_unused.map((action, i) => ({
      action, used: false, included: false,
      undetermined: granted_unused.length > 1 && i === granted_unused.length - 1,
      last_used: null, count_observed: 0,
    })),
  ];
}

// ---- Persona 카탈로그 ----
export const CATALOG: CatalogEntry[] = [
  {
    persona: "DataEngineer",
    description: "S3/Glue/Athena 데이터 파이프라인 운영. 실사용 기반 read+write 스코프.",
    // 여러 계정에 걸친 persona(전체 뷰에서 계정별 분해 데모).
    members: ["arn:aws:iam::111122223333:role/data-eng-batch", "arn:aws:iam::111122223333:role/glue-job",
              "arn:aws:iam::444455556666:role/data-eng-batch", "arn:aws:iam::444455556666:role/glue-job"],
    // 사용 주체 3종을 모두 담는다 — 배지·필터·CSV 를 목데이터로 실제 확인할 수 있어야 한다.
    // 🔴 첫 행은 **두 축이 엇갈리는** 경우다: 신뢰정책은 계정 root 라 판별 불가(unknown)인데 실사용
    // 관측은 자동화였다. 논리합이 실제로 신뢰 축을 이기는지 이 행이 아니면 확인할 수 없다.
    member_details: [
      { principal: "arn:aws:iam::111122223333:role/data-eng-batch", principal_kind: "unknown",
        usage_subject: "machine", usage_subject_basis: "session_name_automation",
        trust_principals: ["arn:aws:iam::111122223333:root"], tags: { Team: "data", Owner: "data-platform" } },
      { principal: "arn:aws:iam::111122223333:role/glue-job", principal_kind: "service",
        usage_subject: "machine", usage_subject_basis: "invoked_by",
        trust_principals: ["glue.amazonaws.com"], tags: { Team: "data" } },
      { principal: "arn:aws:iam::444455556666:role/data-eng-batch", principal_kind: "human",
        usage_subject: "human", usage_subject_basis: "idc_assignment",
        trust_principals: ["arn:aws:iam::444455556666:saml-provider/Okta"], tags: {} },
      // 실사용 관측이 아예 없는 행 — 근거 문장이 "사용 기록 없음" 으로 떨어지고 배지는 신뢰 축으로
      // 폴백해야 한다. `none` 을 자동화로 승격하면 안 되는 경계다.
      { principal: "arn:aws:iam::444455556666:role/glue-job", principal_kind: "service",
        usage_subject: "none", usage_subject_basis: "no_events",
        trust_principals: ["glue.amazonaws.com"], tags: {} },
    ],
    member_count: 4,
    policy_ref: "policies/DataEngineer.json",
    approval_status: "review",
    ai_suggested: true,
    synthesis_source: "last_accessed_evidence",
    // 🔴 임계치(`count_min_observed_days`) **이상**인 유일한 persona — 횟수 컬럼이 렌더되는 경로다.
    //   나머지는 3일/null 로 두어 미렌더 경로도 함께 돈다. 한쪽만 있으면 어서션 하나는 미측정이다.
    observed_window_days: 45,
    count_min_observed_days: 7,
    contributing_sources: ["access_advisor", "cloudtrail", "credential_report"],
    actions: mkActions(
      [
        ["s3:GetObject", "2026-07-13T18:22:00Z", 8421],
        ["s3:PutObject", "2026-07-13T18:20:00Z", 3120],
        ["glue:StartJobRun", "2026-07-12T09:00:00Z", 210],
        ["athena:StartQueryExecution", "2026-07-13T11:04:00Z", 1890],
        ["athena:GetQueryResults", "2026-07-13T11:05:00Z", 1885],
        // 🔴 군집 일괄 포함/제외(F16)를 실제로 눌러 볼 수 있는 **10개 이상 군집**. 사용자 예시가
        //   "bedrock 에 12개 권한" 이었다. 사용/미사용/근거 불명이 섞여 있어야 일괄 토글의
        //   indeterminate(일부 포함) 상태가 목데이터에서 나온다.
        ["bedrock:InvokeModel", "2026-07-13T12:00:00Z", 4210],
        ["bedrock:InvokeModelWithResponseStream", "2026-07-13T12:01:00Z", 1180],
        ["bedrock:ListFoundationModels", "2026-07-10T08:00:00Z", 42],
      ],
      [
        "iam:PassRole", "s3:DeleteBucket", "glue:DeleteDatabase",
        "bedrock:CreateModelCustomizationJob", "bedrock:DeleteCustomModel",
        "bedrock:GetFoundationModel", "bedrock:ListCustomModels",
        "bedrock:CreateProvisionedModelThroughput", "bedrock:DeleteProvisionedModelThroughput",
        "bedrock:PutModelInvocationLoggingConfiguration",
        "bedrock:TagResource", "bedrock:UntagResource",
        "kms:ScheduleKeyDeletion",
      ],
    ),
  },
  {
    persona: "ReadOnlyAuditor",
    description: "규정 감사용 전역 read-only. 쓰기 action 0.",
    members: ["arn:aws:iam::111122223333:role/auditor"],
    member_details: [
      { principal: "arn:aws:iam::111122223333:role/auditor", principal_kind: "human",
        usage_subject: "human", usage_subject_basis: "mfa_session",
        trust_principals: ["arn:aws:iam::111122223333:saml-provider/Okta"], tags: { Team: "grc" } },
    ],
    member_count: 88,
    policy_ref: "policies/ReadOnlyAuditor.json",
    approval_status: "approved",
    ai_suggested: false,
    synthesis_source: "last_accessed_evidence",
    // 임계치 **미만** — 횟수 컬럼이 사라지고 문구도 일수를 말하지 않아야 한다(측정값은 있다).
    observed_window_days: 3,
    count_min_observed_days: 7,
    contributing_sources: ["access_advisor", "analyzer_unused", "credential_report"],
    actions: mkActions(
      [
        ["cloudtrail:LookupEvents", "2026-07-14T01:00:00Z", 540],
        ["config:GetComplianceDetailsByConfigRule", "2026-07-13T22:00:00Z", 120],
        ["iam:GenerateCredentialReport", "2026-07-14T01:02:00Z", 24],
      ],
      [],
    ),
  },
  {
    persona: "PlatformAdmin",
    description: "플랫폼 인프라 운영. 상승 경로 존재 → 검토 필요.",
    members: ["arn:aws:iam::444455556666:role/platform-admin"],
    member_details: [
      // 이벤트는 있는데 주체 신호가 없는 행 — 배지는 '판별 불가' 로 남지만 근거 문장은 "관측은
      // 있었고 주체를 가릴 신호가 없었다" 를 말해야 한다("아무것도 모른다" 와 다른 상태다).
      { principal: "arn:aws:iam::444455556666:role/platform-admin", principal_kind: "unknown",
        usage_subject: "none", usage_subject_basis: "events_without_subject_signal",
        trust_principals: ["arn:aws:iam::444455556666:root"], tags: {} },
    ],
    member_count: 24,
    policy_ref: "policies/PlatformAdmin.json",
    approval_status: "review",
    ai_suggested: true,
    synthesis_source: "fallback_used_actions",
    // CloudTrail 근거가 없는 persona → 창 길이를 말할 수 없다. UI 가 "90일" 을 박지 않고
    // "관측 구간" 으로 폴백하는지 mock 으로 확인할 수 있게 null 로 둔다.
    observed_window_days: null,
    contributing_sources: ["credential_report"],
    actions: mkActions(
      [
        ["ec2:DescribeInstances", "2026-07-14T00:10:00Z", 990],
        ["ecs:UpdateService", "2026-07-13T14:00:00Z", 66],
        ["cloudformation:UpdateStack", "2026-07-11T10:00:00Z", 18],
      ],
      ["iam:CreateRole", "iam:AttachRolePolicy", "sts:AssumeRole", "organizations:*"],
    ),
  },
  {
    persona: "CICDDeployer",
    description: "배포 파이프라인 역할. 실사용 좁은 write 스코프.",
    members: ["arn:aws:iam::444455556666:role/cicd-deploy"],
    member_details: [
      { principal: "arn:aws:iam::444455556666:role/cicd-deploy", principal_kind: "service",
        usage_subject: "machine", usage_subject_basis: "trust_service",
        trust_principals: ["codebuild.amazonaws.com", "arn:aws:iam::444455556666:root"], tags: { Pipeline: "main" } },
    ],
    member_count: 51,
    policy_ref: "policies/CICDDeployer.json",
    approval_status: "draft",
    ai_suggested: true,
    synthesis_source: "last_accessed_evidence",
    // 🔴 `count_min_observed_days` 를 **의도적으로 비운다** — 구 run 폴백
    //   (`DEFAULT_COUNT_MIN_OBSERVED_DAYS`)이 감추는 쪽으로 동작하는지 여기서 돈다.
    observed_window_days: 3,
    contributing_sources: ["access_advisor", "cloudtrail", "credential_report"],
    actions: mkActions(
      [
        ["ecr:PutImage", "2026-07-13T16:00:00Z", 430],
        ["ecs:RegisterTaskDefinition", "2026-07-13T16:01:00Z", 210],
        ["lambda:UpdateFunctionCode", "2026-07-12T20:00:00Z", 88],
      ],
      ["iam:PassRole", "s3:*"],
    ),
  },
];

// ---- Cleanup 백로그 ----
// 실제 규모(100+)를 반영해 카테고리 그룹→드릴다운 UI 를 검증. seed 로 결정론 생성.
const ACCOUNTS = ["111122223333", "444455556666"];
const RISK_CYCLE: CleanupItem["risk_level"][] = ["critical", "high", "medium", "low", "medium", "high"];

// 유형별 위험 근거(레벨과 함께 조합해 "왜 이 레벨인지" 데모). 백엔드 risk_reasons 형식과 일치.
const TYPE_REASONS: Record<CleanupItem["type"], string[]> = {
  long_lived_key: ["장기 액세스키(612일 ≥ 90)"],
  no_mfa: ["MFA 미설정 콘솔 사용자"],
  escalation_path: ["권한 상승 경로 1건"],
  unused_role: ["미사용 권한/발견 20건"],
  new_role_unused: ["미사용 권한/발견 12건"],
  unused_permission: ["미사용 권한/발견 35건"],
  cross_tenant_trust: ["다른 테넌트 그룹 계정을 신뢰"],
  unconfirmed_trust_role: ["신뢰 대상이 우리 테넌트로 확인되지 않음"],
  wildcard_grant: ["와일드카드 action 부여('*')"],
  trust_policy_wildcard: ["신뢰정책 principal 광범위"],
  unverified_usage: ["실사용 권한이 action 단위로 확인되지 않음"],
};
// 레벨→대표 점수(경계 이상). 데모용.
const LEVEL_SCORE: Record<CleanupItem["risk_level"], number> = { critical: 80, high: 60, medium: 35, low: 15 };

// 유형별 상세 근거(evidence) — 엔진 m6_reporter 형식과 동일.
const TYPE_EVIDENCE: Record<CleanupItem["type"], Record<string, string>> = {
  long_lived_key: { "액세스키 나이": "612일", "임계 기준": "90일 이상", MFA: "미설정", "콘솔 로그인": "가능" },
  no_mfa: { "식별 유형": "user", "콘솔 로그인": "가능", MFA: "미설정", "액세스키 나이": "148일" },
  escalation_path: { "무엇이 가능한가": "역할을 스스로 만들고 그 역할에 관리자급 정책을 붙일 수 있습니다 — 지금 자기 권한 밖의 역할을 만들어 그 역할로 갈아탈 수 있다는 뜻입니다.", "필요한 권한(정책에서 찾을 문자열)": "iam:CreateRole + AttachRolePolicy", "도달 대상": "새로 만든 관리자급 역할 (new-admin-role)", "MITRE ATT&CK": "TA0004 · 권한 상승(Privilege Escalation)", "부여된 action 수": "42" },
  // 🔴 키·문구는 엔진(m6_reporter.py:411)과 **같아야** 한다. 이전 mock 은 "삭제 판단 최소 경과" 같은
  // 옛 키를 들고 있었다 — 화면은 evidence 를 그대로 렌더하므로 mock 이 어긋나면 목데이터 모드의
  // 렌더 검증이 "실 산출물에서는 나오지 않는 화면" 을 통과시킨다.
  unused_role: { "식별 유형": "role", "부여된 action 수": "37", "마지막 활동": "2024-05-02T11:20:00Z", "미사용 기간": "856일", "수집된 사용 흔적": "없음(CloudTrail 3일 + Access Advisor 추적 창(AWS 사양: 최대 400일))", "사용 흔적 서비스": "없음", "역할 생성일": "2024-03-11T04:22:10Z", "생성 후 경과": "856일", "미사용 등급": "90일 이상 미사용", "일수 근거": "IAM 활동 기록(전 리전)", "삭제 검토 임계": "미사용 90일 이상", "판단 보류 기준": "생성 후 14일 미만", "관리형 정책 연결": "예", "수집 소스": "access_advisor, credential_report" },
  new_role_unused: { "식별 유형": "role", "부여된 action 수": "12", "마지막 활동": "없음", "미사용 기간": "판단 보류(생성 후 3일 — 관측 기간 부족)", "수집된 사용 흔적": "없음(CloudTrail 3일 + Access Advisor 추적 창(AWS 사양: 최대 400일))", "사용 흔적 서비스": "없음", "역할 생성일": "2026-07-11T08:01:00Z", "생성 후 경과": "3일", "미사용 등급": "신규 (관측 기간 부족 · 판정 보류)", "일수 근거": "생성일(활동 기록 없음)", "삭제 검토 임계": "미사용 90일 이상", "판단 보류 기준": "생성 후 14일 미만", "관리형 정책 연결": "예", "수집 소스": "access_advisor, credential_report", "판정까지 남은 일수": "11" },
  // `근거 불명 action 수` + `미사용 셈 기준` — 근거 불명을 미사용에 합산하지 않는다는 정의를
  // 카드에 싣는다(결함 D). 50 = 15 실사용 + 35 미사용 이라 여기서는 근거 불명이 0 인 쪽 문구다.
  unused_permission: { "부여된 action 수": "50", "실사용 action 수": "15", "미사용 action 수": "35", "근거 불명 action 수": "0", "미사용 셈 기준": "부여 action 전부에 사용 근거 판정이 있음", "대표 미사용": "s3:DeleteBucket, s3:PutBucketPolicy, iam:PassRole", "수집 소스": "access_advisor, cloudtrail" },
  // 🔴 와일드카드 2종에는 "미사용 action 수" 가 없다 — 부여 범위에 상한이 없어 **셀 수 없다**.
  // 여기에 0 을 적으면 화면이 "미사용 0건" 이라고 말하게 되고, 그것이 R4 가 막으려는 오독이다.
  wildcard_grant: { "식별 유형": "role", "보유 와일드카드": "s3:*", "와일드카드 수": "1", "부여된 action 수": "1", "실사용 action 수": "6", "미사용 개수 산정": "불가(부여 범위에 상한이 없음)", "관측 창": "CloudTrail 3일 + Access Advisor 추적 창(AWS 사양: 최대 400일)", "수집 소스": "access_advisor, cloudtrail" },
  trust_policy_wildcard: { "신뢰 principal": "\"*\" (조건 없음)", "조건(Condition)": "없음", "신뢰 범위": "external", "권고": "신뢰 대상을 특정 계정·서비스로 좁히거나 조건 부여" },
  // 신뢰 축 2종(P7) — 키·문구를 엔진(m6_reporter.py:401·513)과 같은 형식으로 둔다. 특히
  // `unconfirmed_trust_role` 의 임계 라벨은 "삭제 검토 임계" 가 아니라 **"미사용 판정 임계"** 다:
  // 권고가 "삭제 아님" 인데 증거가 삭제 임계를 말하면 화면이 자기모순이 된다.
  unconfirmed_trust_role: {
    "식별 유형": "role", "신뢰 범위 판정": "확인되지 않음(외부라고 판정한 것이 아니다)",
    "신뢰 대상": "arn:aws:iam::999988887777:root",
    // 계정 ID 만 뽑은 값 — '확인 필요' 화면이 신뢰 계정별로 묶고 정렬하는 데 쓴다(ARN 재파싱 금지).
    "신뢰 계정": "999988887777",
    "소속 테넌트 그룹": "acme", "판정 기준": "config `accounts[].group` 으로 확인된 계정·AWS 서비스만 내부로 본다",
    "부여된 action 수": "18", "마지막 활동": "2025-11-02T09:14:00Z", "미사용 기간": "302일",
    "수집된 사용 흔적": "없음(CloudTrail 3일 + Access Advisor 추적 창(AWS 사양: 최대 400일))",
    "미사용 판정 임계": "미사용 90일 이상", "판단 보류 기준": "생성 후 14일 미만",
    "관리형 정책 연결": "예", "수집 소스": "access_advisor, cloudtrail",
  },
  cross_tenant_trust: {
    "식별 유형": "role", "소속 테넌트 그룹": "acme",
    "신뢰 대상": "arn:aws:iam::444455556666:root",
    "신뢰 범위 판정": "다른 테넌트 그룹(경계 위반 의심)",
    // 🔴 '미사용 등급: active' — 현역인데도 올라온다는 사실을 증거에 남긴다. 이것이 없으면
    // "안 쓰이니 지우면 되겠네" 로 읽힌다.
    "미사용 등급": "30일 이내 사용", "판정 기준": "config `accounts[].group` 이 이 계정과 다른 계정을 신뢰",
    "부여된 action 수": "24", "수집 소스": "access_advisor, cloudtrail",
  },
  // action 단위 실사용 근거가 없어 persona 묶음에서 빠진 대상. 🔴 이 유형이 없던 동안 이런 대상은
  // 화면에서 **통째로 사라졌다**(R6 위반) — '확인 필요' 가 약속한 18건이 17건이 됐다.
  unverified_usage: {
    "식별 유형": "role", "부여된 action 수": "9",
    "실사용 action 수": "0(action 단위 근거 없음)",
    "사용 흔적 서비스": "s3, logs",
    "관측 창": "CloudTrail 3일 + Access Advisor 추적 창(AWS 사양: 최대 400일)",
    "수집 소스": "access_advisor",
  },
};

// 🔴 형식이 엔진과 **같아야** 한다: 문장 끝에 `(+N점)` 이 붙고 목록은 **기여도 내림차순**이다
// (`m4_risk_scorer.py:142-144`, F17-3). 화면은 첫 줄을 "점수를 가장 많이 올린 것" 으로 쓰므로
// (`CleanupBacklog.tsx:1060`) 점수 표기가 없으면 그 요약이 아예 렌더되지 않는다 — 목데이터가 옛
// 형식이면 목 모드 렌더 검증이 F17-2 를 **측정하지 못한다**(측정 못 한 것을 통과로 세지 않는다).
// 기여점수 배분은 데모값이지만 **합 = `risk_score`(LEVEL_SCORE)** 를 지킨다. 안 지키면 화면이
// "80점 중 25점이 이 사실에서" 를 말할 때 나머지 항목의 합이 55 가 아니게 되어 화면이 자기모순이다.
function reasonsFor(type: CleanupItem["type"], level: CleanupItem["risk_level"]): string[] {
  // 높은 레벨엔 가중 요인을 덧붙여 점수가 왜 높은지 설명한다(엔진의 admin_like·wildcard_action).
  const extra: [string, number][] =
    level === "critical" ? [["관리자급 광범위 권한", 25], ["와일드카드 action 부여('*')", 25]]
    : level === "high" ? [["와일드카드 action 부여('*')", 25]]
    : [];
  const total = LEVEL_SCORE[level];
  const extraSum = extra.reduce((n, [, p]) => n + p, 0);
  const bases = TYPE_REASONS[type];
  // 유형 근거가 남은 점수를 나눠 가진다(마지막 항목이 나머지를 흡수해 합이 정확히 total 이 된다).
  const rest = Math.max(1, total - extraSum);
  const per = Math.max(1, Math.floor(rest / bases.length));
  const scored: [string, number][] = [
    ...bases.map((t, i): [string, number] => [t, i === bases.length - 1 ? rest - per * (bases.length - 1) : per]),
    ...extra,
  ];
  // 기여도 내림차순 → 동점은 문장 오름차순(결정론). 엔진의 정렬 규칙과 같은 모양이다.
  scored.sort((a, b) => (b[1] - a[1]) || a[0].localeCompare(b[0]));
  return scored.map(([t, p]) => `${t} (+${p}점)`);
}

// 유형 → (조치 묶음, 트랙). 엔진은 **레코드의 트랙**으로 묶음을 정하지 유형으로 정하지 않는다.
// mock 에는 레코드가 없으므로 유형별로 실측과 같은 자리에 놓는다. `unused_permission` 만 두 묶음에
// 걸치게 하는 이유가 이 개편의 출발점이다 — 실측에서 미사용 권한은 지울 대상(121)과 줄일 대상(118)에
// 거의 반씩 있었고, 그래서 유형으로 카드를 만들면 같은 역할이 '지워라' 와 '다시 써라' 두 카드에
// 동시에 나왔다. mock 이 이 겹침을 재현하지 않으면 3카드 개편이 무엇을 고쳤는지 화면에서 볼 수 없다.
const PLACEMENT: Record<CleanupItem["type"], { group: "delete_review" | "reduce_scope" | "needs_confirmation"; track: "persona" | "service_role" | "delete_review" | "owner_review" | "excluded" }> = {
  unused_role: { group: "delete_review", track: "delete_review" },
  unused_permission: { group: "reduce_scope", track: "service_role" }, // 짝수 인덱스는 아래에서 delete_review 로 옮긴다
  escalation_path: { group: "reduce_scope", track: "service_role" },
  wildcard_grant: { group: "reduce_scope", track: "service_role" },
  trust_policy_wildcard: { group: "reduce_scope", track: "service_role" },
  long_lived_key: { group: "reduce_scope", track: "persona" },
  no_mfa: { group: "reduce_scope", track: "persona" },
  new_role_unused: { group: "needs_confirmation", track: "excluded" },
  unconfirmed_trust_role: { group: "needs_confirmation", track: "owner_review" },
  cross_tenant_trust: { group: "needs_confirmation", track: "owner_review" },
  unverified_usage: { group: "needs_confirmation", track: "excluded" },
};

// 한 대상이 여러 문제를 갖는 경우를 만든다 — 화면의 행은 **대상 1개**이고 펼치면 그 대상의 문제가
// 나오는 구조라서, 전부 1:1 인 mock 으로는 그 구조가 한 번도 그려지지 않는다(실측 275개 대상에
// 694건이었다). 🔴 겹침은 **같은 묶음 안에서만** 만든다 — 묶음을 넘어 겹치면 한 대상이 두 카드에
// 동시에 있게 되고, 그건 이 화면이 없앤 바로 그 자기모순이다.
function sharedTarget(group: string, k: number): { account_id: string; principal: string } {
  const acct = ACCOUNTS[0];
  return { account_id: acct, principal: `arn:aws:iam::${acct}:role/multi-${group}-${k % 3}` };
}

function genCleanup(): CleanupItem[] {
  const seedItems: Omit<CleanupItem, "id" | "finding_key" | "account_id" | "risk_level" | "risk_score"
    | "risk_reasons" | "status" | "status_note" | "status_updated_at" | "status_updated_by">[] = [
    { type: "long_lived_key", principal: "user/legacy-svc", detail: "액세스키 age 612일", recommendation: "액세스키 폐기 후 Identity Center(SSO) 임시 자격증명으로 전환" },
    { type: "no_mfa", principal: "user/ops-break-glass", detail: "MFA 미설정 콘솔 사용자", recommendation: "IAM User 폐기 후 Identity Center(SSO+MFA)로 전환" },
    { type: "escalation_path", principal: "role/platform-admin", detail: "iam:CreateRole → AttachRolePolicy 상승 경로", recommendation: "상승 유발 권한 제거 후 최소권한 Permission Set 로 마이그레이션" },
    { type: "unused_role", principal: "role/old-migration", detail: "미사용 역할(CloudTrail 3일 + Access Advisor 추적 창(AWS 사양: 최대 400일) 근거로 사용 기록 없음)", recommendation: "역할 삭제" },
    { type: "new_role_unused", principal: "role/BuildAccessRole", detail: "생성 후 미사용(생성 3일 경과 — 관측 기간 부족)", recommendation: "용도 확인 후 판단 (삭제 권고 아님)" },
    { type: "unused_permission", principal: "role/data-eng-batch", detail: "granted 이나 미사용: s3:DeleteBucket 외 34건", recommendation: "실사용 기반 최소권한 Permission Set 로 마이그레이션" },
    // R4 — 와일드카드는 **미사용 여부·트랙과 무관하게** 올라온다(m6_reporter.py:380). 권고가
    // "삭제" 가 아니라 "재작성" 인 이유: `*` 는 무엇이 안 쓰였는지 셀 수 없어 뺄 대상을 못 고른다.
    { type: "wildcard_grant", principal: "role/legacy-admin", detail: "전 권한 부여: Action \"*\" (미사용 개수 산정 불가)", recommendation: "실사용 기반 Permission Set 로 재작성 (제거 개수 산정 불가)" },
    { type: "trust_policy_wildcard", principal: "role/vendor-integration", detail: "신뢰정책 principal \"*\" — 조건 없음", recommendation: "신뢰정책 `Principal` 을 특정 계정·역할로 좁히고 조건 추가" },
    // R5 / P7 — 신뢰 축 2종. 권고 문구가 **"삭제" 로 시작하지 않는다**는 것이 이 두 행의 요점이고,
    // 화면(라벨·배너·상세)이 그 차이를 실제로 렌더하는지 검증하려면 mock 에 건수가 있어야 한다.
    { type: "unconfirmed_trust_role", principal: "role/OrgVendorScanRole", detail: "미사용 302일이나 신뢰 대상 미확인 — 외부 연동 의심(2025-11-02T09:14:00Z)", recommendation: "소유자·용도 확인 후 판단 (삭제 권고 아님)" },
    { type: "unverified_usage", principal: "role/opaque-batch", detail: "실사용 권한이 action 단위로 확인되지 않음 — 묶을 대상이 없어 persona 에서 빠졌다", recommendation: "용도 확인 후 판단 (삭제 권고 아님)" },
    { type: "cross_tenant_trust", principal: "role/shared-etl-bridge", detail: "다른 테넌트 그룹 계정을 신뢰: arn:aws:iam::444455556666:root", recommendation: "경계 위반인지 확인 (삭제 권고 아님)" },
  ];
  // 유형별 목표 건수(합계 133) — 미사용 권한이 압도적으로 많은 실제 분포 모사.
  // 와일드카드 2종은 **건수가 적다**(9 + 2). 위험도로 정렬하면 목록 아래로 밀려 사라지므로
  // 화면이 이들을 최상단에 고정하는지·배너를 띄우는지 이 분포가 아니면 검증되지 않는다.
  const counts: Record<CleanupItem["type"], number> = {
    unused_permission: 61, unused_role: 22, new_role_unused: 4, long_lived_key: 18, no_mfa: 9, escalation_path: 8,
    wildcard_grant: 9, trust_policy_wildcard: 2,
    // 신뢰 축 2종(P7). `unconfirmed_trust_role` 12 는 지표의 owner_review_roles(12)와 같은 몫이고,
    // `cross_tenant_trust` 2 는 cross_tenant_trust_roles(2)와 일치시킨다 — 대시보드 숫자와 이 목록의
    // 건수가 어긋나면 화면이 산술을 설명해도 그 설명이 틀린 말이 된다.
    // (`unused_role` 22 는 이 mock 이 백로그를 축소 표본으로 만든 결과이며 지표의 59 와 다르다.)
    cross_tenant_trust: 2, unconfirmed_trust_role: 12, unverified_usage: 2,
  };
  const out: CleanupItem[] = [];
  let n = 0;
  (Object.keys(counts) as CleanupItem["type"][]).forEach((type) => {
    const seed = seedItems.find((s) => s.type === type);
    if (!seed) return; // 건수 0 인 신 유형(seed 없음) — 논리 오류가 아니라 아직 안 낸다는 뜻이다.
    for (let i = 0; i < counts[type]; i++) {
      const acct = ACCOUNTS[n % ACCOUNTS.length];
      const level = RISK_CYCLE[(n + (type === "long_lived_key" ? 0 : 2)) % RISK_CYCLE.length];
      // 조치 상태 mock — 8개마다 조치완료, 13개마다 보류. 화면에서 세 상태·필터·집계가 실제로
      // 렌더되는지 확인하려면 mock 에 세 상태가 다 있어야 한다(전부 미조치면 검증이 불가능하다).
      const marked: CleanupStatus = n % 8 === 3 ? "done" : n % 13 === 5 ? "deferred" : "open";
      // 미사용 권한은 두 묶음에 걸친다(위 PLACEMENT 주석). 짝수 인덱스를 '삭제 검토' 로 보낸다.
      const place = type === "unused_permission" && i % 2 === 0
        ? { group: "delete_review" as const, track: "delete_review" as const }
        : PLACEMENT[type];
      // 5개마다 같은 묶음의 공유 대상으로 몰아 다문제 행을 만든다.
      const target = n % 5 === 4
        ? sharedTarget(place.group, n)
        : { account_id: acct, principal: `arn:aws:iam::${acct}:${seed.principal}${i === 0 ? "" : "-" + i}` };
      out.push({
        id: `c${++n}`,
        // 실제 키는 엔진의 sha256 hex(64자). mock 도 같은 형식으로 만들어 화면 로직이 형식에
        // 의존하지 않는지 함께 확인한다.
        finding_key: n.toString(16).padStart(64, "0"),
        type,
        group: place.group,
        track: place.track,
        ...target,
        detail: seed.detail,
        risk_level: level,
        recommendation: seed.recommendation,
        risk_score: LEVEL_SCORE[level],
        risk_reasons: reasonsFor(type, level),
        evidence: TYPE_EVIDENCE[type],
        status: marked,
        status_note: marked === "done" ? "IdC 없이 IAM 정책만 다듬어 적용함" : marked === "deferred" ? "차기 분기 정리 예정" : "",
        status_updated_at: marked === "open" ? "" : "2026-08-30T05:00:00Z",
        status_updated_by: marked === "open" ? "" : "ops@example.com",
      });
    }
  });

  // ── 결함 #9 의 형태: 3년 전에 마지막으로 쓰인 뒤 방치된 역할 ──────────────────────────
  // 신 미사용 판정(사용 근거의 **유무**가 아니라 마지막 활동 **시각**을 본다) 이후 이런 대상은
  // 삭제 검토에 있고, **오래된 사용 흔적과 미사용 권한·와일드카드를 함께** 들고 있다(라이브 실측:
  // 이 판정으로 넘어온 84개 중 58개). mock 에 이 형태가 없으면 목데이터 렌더 검증이 두 회귀를 모두
  // 통과시킨다: (i) 증거가 "사용 근거: 없음" 이라고 거짓을 말하는 것, (ii) 같은 대상이 "지워라" 와
  // "정책을 다시 써라" 를 동시에 말하는 것. 값은 엔진 실행 결과를 그대로 옮긴 것이다.
  const staleAcct = ACCOUNTS[0];
  const stalePrincipal = `arn:aws:iam::${staleAcct}:role/archived-etl-2023`;
  const staleLast = "2023-08-29T02:11:00Z";
  const staleWindow = "CloudTrail 근거 없음 + Access Advisor 추적 창(AWS 사양: 최대 400일)";
  const stale: Array<Pick<CleanupItem, "type" | "detail" | "recommendation" | "risk_level" | "evidence">> = [
    {
      type: "unused_role",
      detail: `미사용 역할(미사용 1103일 — ${staleLast})`,
      recommendation: "역할 삭제",
      risk_level: "high",
      evidence: {
        "식별 유형": "role", "부여된 action 수": "3", "마지막 활동": staleLast, "미사용 기간": "1103일",
        // 🔴 여기가 요점이다 — 흔적이 있는데 "없음" 이라고 적으면, 고객이 콘솔에서 그 흔적을 보는
        // 순간 목록 전체를 안 믿는다. 흔적을 지우지 않고 **언제였는지**를 적는다.
        // 🔴 라벨은 `사용 근거` 였다(결함 C) — 와일드카드 카드의 같은 이름 줄은 **관측 창**이라
        // 한 라벨이 카드마다 다른 것을 가리켰다. 두 뜻을 다른 이름으로 갈랐다.
        "수집된 사용 흔적": `action 1개, 가장 최근 사용 ${staleLast}(${staleWindow})`,
        "사용 흔적 서비스": "glue, s3",
        "역할 생성일": "미수집", "생성 후 경과": "1400일", "미사용 등급": "90일 이상 미사용",
        "일수 근거": "IAM 활동 기록(전 리전)", "삭제 검토 임계": "미사용 90일 이상",
        "판단 보류 기준": "생성 후 30일 미만", "관리형 정책 연결": "예",
        "수집 소스": "access_advisor, cloudtrail",
      },
    },
    {
      type: "wildcard_grant",
      detail: "와일드카드 권한 보유: s3:*",
      recommendation: "삭제하지 않는다면: 실사용 기반 Permission Set 로 재작성 (제거 개수 산정 불가)",
      risk_level: "critical",
      evidence: {
        "식별 유형": "role", "보유 와일드카드": "s3:*", "와일드카드 수": "1", "부여된 action 수": "3",
        "실사용 action 수": "1", "미사용 개수 산정": "불가(부여 범위에 상한이 없음)",
        "관측 창": staleWindow, "수집 소스": "access_advisor, cloudtrail",
      },
    },
    {
      type: "unused_permission",
      detail: "granted 이나 미사용: s3:DeleteBucket 외 1건",
      recommendation: "삭제하지 않는다면: 실사용 기반 최소권한 Permission Set 로 마이그레이션",
      risk_level: "medium",
      evidence: {
        "부여된 action 수": "3", "실사용 action 수": "1", "미사용 action 수": "2",
        "근거 불명 action 수": "0",
        "미사용 셈 기준": "부여 action 전부에 사용 근거 판정이 있음",
        // 🔴 이 대상은 `s3:*` 도 들고 있다 — 와일드카드 카드는 "산정 불가", 이 카드는 "미사용 2건"
        // 이라 같은 부여를 두고 두 카드가 서로를 반박하는 것으로 읽혔다(결함 B). 범위를 명시한다.
        "와일드카드 보유": "예(s3:*) — 위 개수는 명시 부여분만",
        "대표 미사용": "s3:DeleteBucket, s3:PutBucketPolicy",
        "수집 소스": "access_advisor, cloudtrail", "마지막 활동": staleLast,
      },
    },
  ];
  // ── 결함 A 의 형태 + 상세의 대조군: 발견된 문제가 **하나뿐인** 삭제 검토 대상 ────────────
  // 두 가지를 동시에 재게 한다.
  // (i) `used_actions` 는 비어 있고 **서비스 단위 흔적만** 있는 경로. 예전 판은 여기서 "사용 근거:
  //     없음" 을 냈고, 같은 카드의 `사용 흔적 서비스: ec2` 와 정면으로 부딪쳤다. mock 이 action
  //     흔적 있는 경로만 갖고 있어서 렌더 검증이 이 결함을 통과시켰다.
  // (ii) 상세의 '이 대상이 가진 다른 사실' 절이 **없어야** 하는 대조군. 이것이 없으면 그 절을
  //      무조건 그리는 코드도 검증을 통과한다(실패할 수 없는 어서션 = 미측정).
  stale.push({
    type: "unused_role",
    detail: "미사용 역할(미사용 1287일 — 2022-12-19T05:40:00Z)",
    recommendation: "역할 삭제",
    risk_level: "high",
    evidence: {
      "식별 유형": "role", "부여된 action 수": "4", "마지막 활동": "2022-12-19T05:40:00Z",
      "미사용 기간": "1287일",
      "수집된 사용 흔적": `action 단위 근거 없음 · 서비스 단위 흔적 1개(${staleWindow})`,
      "사용 흔적 서비스": "ec2",
      "역할 생성일": "미수집", "생성 후 경과": "1600일", "미사용 등급": "90일 이상 미사용",
      "일수 근거": "IAM 활동 기록(전 리전)", "삭제 검토 임계": "미사용 90일 이상",
      "판단 보류 기준": "생성 후 30일 미만", "관리형 정책 연결": "아니오",
      "수집 소스": "access_advisor",
    },
  });
  // ── 「고치는 곳」 이동 버튼의 목적지가 **실제로 존재하는** 권한 축소 행 2개 ────────────────
  // 권한 축소 행은 그 대상을 고칠 화면으로 바로 이동한다(`/service-roles?role=`·`/personas?principal=`).
  // 🔴 mock 의 다른 권한 축소 대상들은 서비스 역할 목록·persona 카탈로그에 **없는** ARN 이라, 이 두
  //    행이 없으면 목 렌더 검증이 폴백("이 역할이 현재 범위에 없습니다"·"카탈로그에 없습니다")만 재고
  //    정상 경로는 한 번도 그려지지 않는다(실패할 수 없는 어서션 = 미측정). 맞는 것과 안 맞는 것이
  //    함께 있어야 두 경로를 다 잰다 — 안 맞는 쪽은 이미 많다.
  // 🔴 ARN 은 SERVICE_ROLES ①(`etl-batch-runner`)·CATALOG 의 `DataEngineer` 멤버(`glue-job`)와
  //    **글자까지 같아야** 한다(딥링크는 정확히 일치로 찾는다). `glue-job` 을 고른 이유: 그 persona 는
  //    멤버가 4개(2계정)라 "정책을 고치면 4개 대상에 함께 적용됩니다" 라는 파급 문장과, 계정 선택으로
  //    좁혔을 때의 "2개만 보입니다" 분기가 목데이터로 재진다.
  const linkable: Array<Pick<CleanupItem, "type" | "track" | "principal" | "detail" | "recommendation" | "risk_level">> = [
    {
      type: "unused_permission", track: "service_role",
      principal: `arn:aws:iam::${ACCOUNTS[0]}:role/etl-batch-runner`,
      detail: "granted 이나 미사용: dynamodb:DeleteTable 외 9건",
      recommendation: "실사용 기반 최소권한 Permission Set 로 마이그레이션",
      risk_level: "medium",
    },
    {
      type: "unused_permission", track: "persona",
      principal: `arn:aws:iam::${ACCOUNTS[0]}:role/glue-job`,
      detail: "granted 이나 미사용: s3:PutBucketPolicy 외 5건",
      recommendation: "실사용 기반 최소권한 Permission Set 로 마이그레이션",
      risk_level: "low",
    },
    // ── 🔴 표 폭의 극단값 — **긴 ARN + 배지 3개**를 한 대상에 몰아 둔다 ────────────────────
    // 이것이 없으면 열 폭 검사가 실패할 수 없다(= 미측정). 실제로 그랬다: 배지 열 폭 지정을 빼는
    // mutation 을 걸어도 목에서는 배지 열이 406px 을 받아 접히지 않았다 — 목의 대상 ARN 이 짧아
    // `대상` 열이 좁게 잡히기 때문이다. 라이브의 역할명은 CloudFormation 이 만든 것들이라 훨씬
    // 길고(실측 최장 ARN 762px), 그 폭이 배지 열을 88px 로 밀어낸 것이 원래 결함이었다.
    // 길이는 라이브 최장(`SpringClean-…StackSetExecutionR-…` 계열)에 맞춘다.
    {
      type: "escalation_path", track: "service_role",
      principal: `arn:aws:iam::${ACCOUNTS[0]}:role/StackSetOps-EXAMPLE1-StackSetExecutionRole-EXAMPLE23456`,
      detail: "iam:PassRole → cloudformation:CreateStack 상승 경로",
      recommendation: "상승 유발 권한 제거 후 최소권한 Permission Set 로 마이그레이션",
      risk_level: "high",
    },
    {
      type: "long_lived_key", track: "service_role",
      principal: `arn:aws:iam::${ACCOUNTS[0]}:role/StackSetOps-EXAMPLE1-StackSetExecutionRole-EXAMPLE23456`,
      detail: "액세스키 age 431일",
      recommendation: "액세스키 폐기 후 Identity Center(SSO) 임시 자격증명으로 전환",
      risk_level: "high",
    },
    {
      type: "wildcard_grant", track: "service_role",
      principal: `arn:aws:iam::${ACCOUNTS[0]}:role/StackSetOps-EXAMPLE1-StackSetExecutionRole-EXAMPLE23456`,
      detail: "전 권한 부여: Action \"*\" (미사용 개수 산정 불가)",
      recommendation: "실사용 기반 Permission Set 로 재작성 (제거 개수 산정 불가)",
      risk_level: "critical",
    },
  ];
  linkable.forEach((s) => {
    out.push({
      id: `c${++n}`,
      finding_key: n.toString(16).padStart(64, "0"),
      group: "reduce_scope",
      account_id: ACCOUNTS[0],
      risk_score: LEVEL_SCORE[s.risk_level],
      risk_reasons: reasonsFor(s.type, s.risk_level),
      evidence: TYPE_EVIDENCE[s.type],
      status: "open",
      status_note: "",
      status_updated_at: "",
      status_updated_by: "",
      ...s,
    });
  });

  stale.forEach((s, i) => {
    out.push({
      id: `c${++n}`,
      finding_key: n.toString(16).padStart(64, "0"),
      group: "delete_review",
      track: "delete_review",
      account_id: staleAcct,
      // 마지막 항목만 다른 대상이다 — 위 3건은 한 대상에 함께 걸린 것이고, 이쪽은 항목 1개다.
      principal: i < 3 ? stalePrincipal : `arn:aws:iam::${staleAcct}:role/legacy-ec2-snapshot`,
      risk_score: LEVEL_SCORE[s.risk_level],
      risk_reasons: reasonsFor(s.type, s.risk_level),
      status: "open",
      status_note: "",
      status_updated_at: "",
      status_updated_by: "",
      ...s,
    });
  });
  return out;
}

export const CLEANUP: CleanupItem[] = genCleanup();

// 🔴 최신 run 의 3카드·제외 내역은 CLEANUP 에서 **파생**한다(하드코딩 금지).
//
// 대시보드 카드와 조치 목록이 각자 숫자를 계산하던 것이 이 화면들의 원래 결함이었다 — KPI 는 action
// 41,451 을 세고, 눌러서 열린 목록은 principal 329행을 셌다. 목데이터가 두 숫자를 따로 적으면 렌더
// 검증이 그 어긋남을 통과시킨다. 엔진은 같은 항목 목록에서 두 값을 낸다(m6_reporter.summarize_groups).
//
// 옛 run(001~004)에는 이 필드를 싣지 않는다 — 필드가 없을 때 대시보드가 예전 KPI 로 떨어지는지
// 확인하려면 없는 run 이 있어야 한다(0 세 개를 채우면 "할 일이 없다" 는 거짓을 말한다).
{
  const latest = METRICS[METRICS.length - 1];
  const groups = ["delete_review", "reduce_scope", "needs_confirmation"] as const;
  latest.action_groups = groups.map((group) => {
    const gi = CLEANUP.filter((i) => i.group === group);
    const targets = new Set(gi.map((i) => `${i.account_id}\u001f${i.principal}`));
    const wildcard = new Set(
      gi.filter((i) => i.type === "wildcard_grant" || i.type === "trust_policy_wildcard")
        .map((i) => `${i.account_id}\u001f${i.principal}`),
    );
    return {
      group,
      // 카드의 큰 숫자 = 그 카드가 여는 목록의 행 수(대상 수). 정의를 두 번 적지 않는다.
      targets: targets.size,
      items: gi.length,
      unused_actions: gi.reduce((n, i) => {
        const raw = i.evidence?.["미사용 action 수"] ?? "";
        // 와일드카드는 "산정 불가" 문자열이다 — 숫자로 읽어 0 을 더하면 안 된다(R4).
        return n + (/^\d+$/.test(raw) ? Number(raw) : 0);
      }, 0),
      wildcard_targets: wildcard.size,
      escalation_paths: gi.filter((i) => i.type === "escalation_path").length,
      long_lived_keys: gi.filter((i) => i.type === "long_lived_key").length,
    };
  });
  // 제외 내역 — 세 등급이 다 있어야 화면이 등급별 구획을 실제로 그린다(등급이 다르면 고객이 할 일이
  // 다르다: AWS 소유는 손댈 수 없고, 이름 패턴은 고객 설정이 틀렸는지 봐야 하고, 우리 판단은 뒤집힐 수 있다).
  latest.exclusions = [
    {
      reason: "service_linked", label: "AWS service-linked 역할(AWS 소유 — 정책 수정 불가)",
      basis: "aws_owned", targets: 3, suppressed_items: 5,
      principals: [
        "arn:aws:iam::111122223333:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
        "arn:aws:iam::111122223333:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport",
        "arn:aws:iam::444455556666:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS",
      ],
    },
    {
      reason: "iac_bootstrap_role", label: "배포 도구 부트스트랩 역할(고객이 config 에 선언한 이름 패턴)",
      basis: "customer_declared", targets: 2, suppressed_items: 4,
      principals: [
        "arn:aws:iam::111122223333:role/cdk-hnb659fds-deploy-role",
        "arn:aws:iam::444455556666:role/cdk-hnb659fds-file-publishing-role",
      ],
    },
    {
      reason: "too_new", label: "생성 후 관측 기간 미달 — 미사용도 현역도 주장할 수 없다",
      basis: "judgment", targets: 2, suppressed_items: 3,
      principals: [
        "arn:aws:iam::111122223333:role/fresh-lambda-exec",
        "arn:aws:iam::444455556666:role/fresh-eventbridge-forward",
      ],
    },
  ];
}

// 위험도 산정 기준(mock — 엔진 RiskRules 기본값과 일치).
export const RISK_CRITERIA = {
  level_critical: 75,
  level_high: 50,
  level_medium: 25,
  unused_tier_days: [30, 60, 90],
  rules: [
    { key: "long_lived_key", label: "장기 액세스키", weight: 20, detail: "액세스키 사용연수 ≥ 90일" },
    { key: "no_mfa", label: "MFA 미설정", weight: 15, detail: "콘솔 로그인 가능 IAM User 인데 MFA 없음" },
    { key: "unused_permission", label: "미사용 권한", weight: 1, detail: "미사용 발견 1건당 +1(상한 25)" },
    { key: "escalation_path", label: "권한 상승 경로", weight: 30, detail: "상승 경로 1건당 +30(상한 40)" },
    { key: "wildcard_action", label: "와일드카드 권한", weight: 20, detail: "granted 에 '*' 와일드카드 존재" },
    { key: "admin_like", label: "관리자급 권한", weight: 25, detail: "AdministratorAccess 급 광범위 권한('*' 단독 또는 iam:*)" },
  ],
};

// ---- Reports ----
export const REPORTS: Record<string, ReportRef> = {
  "run-005": {
    run_id: "run-005",
    report_html_url: "about:blank",
    iac_zip_url: "about:blank",
    exec_summary: {
      accounts: 24, principals: 1284, personas: 8,
      unused_permission_principals: 74, unused_permission_actions: 320,
      generated_at: "2026-07-14T02:12:00Z",
    },
  },
};

export const LATEST_RUN_ID = "run-005";

// ---- 트랙② 서비스 역할 (M5 `service_roles.json`) ----
// 실 배포 실측(관제 계정 152 역할)의 **형태**를 축소해 옮긴 것이다. 목적은 화면의 각 분기가
// 실제로 렌더되는지 확인하는 것이며, 특히 다음이 데이터로 성립해야 검증이 의미를 갖는다:
//
//  - 관측 구간 표기의 **두 경로**가 모두 나온다: 기준값 이상(45·61·88·90일 → 일수를 적는다)과
//    기준값 미만/근거 없음(0·null → **아무 일수도 적지 않는다**). 한쪽만 있으면 어서션 하나가
//    미측정이다. 상시 경고는 이제 강도가 고정이다(F14-2: 30일 승격 조건은 도달 불가였다).
//  - 등급 필터를 켠 첫 화면(cleanup)과 끈 화면의 줄 수가 다르다. 등급 미측정(null)도 존재한다 —
//    필터를 끄면 나타나야 하고, 0 이나 active 로 접히면 안 된다.
//  - 부여 권한이 같은 역할 2건(`grp-a1b2c3d4e5f6`)이 있다. 표시상 형제이지만 **정책은 역할별**이며
//    사용 실태가 달라 사용하지 않는 서비스 수도 다르다.
//  - 와일드카드만 부여된 서비스(`granted_count: 0` + `wildcard_grants`)가 있다 — 이 행이 '판정 불가'
//    인 이유가 화면에 남아야 한다(개수를 셀 수 없어서다).
function mkRollup(
  namespace: string,
  verdict: ServiceRollup["verdict"],
  granted_count: number,
  used_count: number,
  last_used: string | null,
  tier: ServiceRollup["tier"],
  wildcard_grants: string[] = [],
): ServiceRollup {
  return { namespace, granted_count, wildcard_grants, used_count, last_used, tier, verdict };
}

// 인증 이력이 전혀 없는 서비스 묶음 — 실측에서 이 덩어리가 결정 **1건**("전부 제거")이 된다.
function mkRemoveBlock(namespaces: string[]): ServiceRollup[] {
  return namespaces.map((ns, i) => mkRollup(ns, "remove", 3 + (i % 5), 0, null, "cleanup"));
}

// `decision_count`(= 화면의 `판단 필요 서비스`)는 엔진(M5)이 정한 규칙 그대로 계산한다:
// **`keep` 서비스 수**. 예전에는 여기에 "제거 덩어리" 1건을 더해 서비스 수와 작업 수를 섞었다(F15-2).
// `undetermined` 는 세지 않는다(결론이 '손대지 않는다' 라 사람이 내릴 결정이 없다).
// `count_min_observed_days` 는 config 기준값 — 엔진이 전 항목에 같은 값을 실어 보낸다.
function mkServiceRole(
  e: Omit<ServiceRoleEntry, "decision_count" | "granted_count" | "unused_count" | "count_min_observed_days">,
): ServiceRoleEntry {
  const keeps = e.service_rollups.filter((r) => r.verdict === "keep").length;
  const removes = e.service_rollups.filter((r) => r.verdict === "remove");
  return {
    ...e,
    count_min_observed_days: 7,
    granted_count: e.service_rollups.reduce((n, r) => n + r.granted_count, 0),
    unused_count: removes.reduce((n, r) => n + r.granted_count, 0),
    decision_count: keeps,
  };
}

export const SERVICE_ROLES: ServiceRoleEntry[] = [
  // ① 관측 구간 90일 · cleanup · 제거 덩어리 큼(317 서비스 역할의 축소판) → 판단 필요 서비스 3개
  //    (사용하지 않는 서비스 10개는 여기 안 든다 — 사람이 고를 것이 없으니 판단 대상이 아니다).
  mkServiceRole({
    account_id: "111122223333", tenant_group: "default",
    principal: "arn:aws:iam::111122223333:role/etl-batch-runner",
    group_key: "grp-9f0e1d2c3b4a", unused_tier: "cleanup", unused_days: 132,
    unused_days_basis: "role_last_used", observed_days: 90,
    wildcard_grants: [],
    service_rollups: [
      mkRollup("s3", "keep", 14, 6, "2026-07-13T18:20:00Z", "active"),
      mkRollup("sqs", "keep", 8, 2, "2026-06-02T09:10:00Z", "watch"),
      mkRollup("logs", "keep", 5, 3, "2026-07-14T01:00:00Z", "active"),
      ...mkRemoveBlock(["dynamodb", "kinesis", "firehose", "glue", "athena", "sns", "ses", "kms", "ecr", "ecs"]),
    ],
  }),
  // ② 부여 권한이 같은 형제 1/2 — 같은 정책을 쓰지만 **사용 실태가 다르다**
  //    (사용하지 않는 서비스 3 vs 1).
  mkServiceRole({
    account_id: "111122223333", tenant_group: "default",
    principal: "arn:aws:iam::111122223333:role/lambda-invoice-exec",
    group_key: "grp-a1b2c3d4e5f6", unused_tier: "cleanup", unused_days: 97,
    unused_days_basis: "role_last_used", observed_days: 45,
    wildcard_grants: [],
    service_rollups: [
      mkRollup("logs", "keep", 5, 4, "2026-07-12T22:41:00Z", "active"),
      ...mkRemoveBlock(["dynamodb", "sns", "secretsmanager"]),
      mkRollup("acm", "undetermined", 0, 0, null, null, ["acm:Get*", "acm:List*"]),
    ],
  }),
  // ③ 형제 2/2 — 같은 `group_key`, 다른 등급·다른 판단. 한 행으로 접어 aggregate 를 만들면
  //    (등급·일수·사용하지 않는 서비스 수 중 어느 것도) 실제 값이 아닌 숫자가 화면에 생긴다.
  mkServiceRole({
    account_id: "111122223333", tenant_group: "default",
    principal: "arn:aws:iam::111122223333:role/lambda-refund-exec",
    group_key: "grp-a1b2c3d4e5f6", unused_tier: "active", unused_days: 3,
    unused_days_basis: "role_last_used", observed_days: 45,
    wildcard_grants: [],
    service_rollups: [
      mkRollup("logs", "keep", 5, 5, "2026-07-14T01:55:00Z", "active"),
      mkRollup("dynamodb", "keep", 9, 4, "2026-07-13T20:02:00Z", "active"),
      mkRollup("sns", "keep", 4, 1, "2026-05-30T11:00:00Z", "watch"),
      ...mkRemoveBlock(["secretsmanager"]),
      mkRollup("acm", "undetermined", 0, 0, null, null, ["acm:Get*", "acm:List*"]),
    ],
  }),
  // ④ 등급 미측정(null) — 일수를 셀 근거가 아예 없다. 등급 필터를 끄면 나타나야 한다.
  mkServiceRole({
    account_id: "111122223333", tenant_group: "default",
    principal: "arn:aws:iam::111122223333:role/config-recorder-helper",
    group_key: "grp-77aa11bb22cc", unused_tier: null, unused_days: null,
    unused_days_basis: null, observed_days: 61,
    wildcard_grants: [],
    service_rollups: [
      mkRollup("config", "keep", 6, 2, "2026-07-09T04:30:00Z", "active"),
      mkRollup("ssm", "undetermined", 11, 0, null, null),
    ],
  }),
  // ⑤ 와일드카드 보유 + 🔴 **관측 구간이 기준값 미만(0)** — 라이브의 실제 모습이다(실측 79/79 가
  //    `observed_days = 0`: CloudTrail LookupEvents 페이지 상한 때문에 창이 몇 시간뿐이다).
  //    이 행에서는 관측 구간 항목이 **아예 표기되지 않아야** 한다("0일" 을 쓰지 않는다).
  //    나머지 행은 기준값 이상이라 표기 경로도 함께 돈다 — 한쪽만 있으면 어서션 하나가 미측정이다.
  //    부여 범위에 상한이 없어 '미사용 개수' 를 셀 수 없다(0 이 아니라 산정 불가).
  mkServiceRole({
    account_id: "444455556666", tenant_group: "default",
    principal: "arn:aws:iam::444455556666:role/legacy-deploy-agent",
    group_key: "grp-deadbeef0001", unused_tier: "cleanup", unused_days: 214,
    unused_days_basis: "role_last_used", observed_days: 0,
    wildcard_grants: ["*"],
    service_rollups: [
      mkRollup("cloudformation", "keep", 12, 3, "2026-06-20T08:00:00Z", "watch"),
      ...mkRemoveBlock(["iam", "ec2", "rds", "elasticloadbalancing"]),
    ],
  }),
  // ⑥ CloudTrail 근거 없음(observed_days=null) — "90일" 같은 측정하지 않은 숫자를 쓰지 않는다.
  //    등급도 미측정이면 화면이 아무 기간도 주장할 수 없다.
  mkServiceRole({
    account_id: "444455556666", tenant_group: "default",
    principal: "arn:aws:iam::444455556666:role/vendor-metrics-pull",
    group_key: "grp-0011223344ff", unused_tier: "review", unused_days: 74,
    unused_days_basis: "create_date", observed_days: null,
    wildcard_grants: ["cloudwatch:Get*"],
    service_rollups: [
      mkRollup("cloudwatch", "undetermined", 0, 0, null, null, ["cloudwatch:Get*"]),
      mkRollup("tag", "undetermined", 3, 0, null, null),
    ],
  }),
  // ⑦ 제거할 것이 없는 현역 역할 — 판단 필요 서비스 2개(둘 다 유지 확인)이고 제거는 0.
  //    KPI 숫자가 **역할 수가 아니라 서비스 수**임을 이 행이 드러낸다(역할 1 : 서비스 2).
  mkServiceRole({
    account_id: "444455556666", tenant_group: "default",
    principal: "arn:aws:iam::444455556666:role/api-gateway-authorizer",
    group_key: "grp-5566778899aa", unused_tier: "active", unused_days: 1,
    unused_days_basis: "role_last_used", observed_days: 88,
    wildcard_grants: [],
    service_rollups: [
      mkRollup("logs", "keep", 4, 4, "2026-07-14T01:58:00Z", "active"),
      mkRollup("dynamodb", "keep", 3, 3, "2026-07-14T01:57:00Z", "active"),
    ],
  }),
];
