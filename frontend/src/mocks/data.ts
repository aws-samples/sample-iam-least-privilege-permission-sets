// ============================================================================
// Mock data — sample scenario: 24 accounts · 1,284 principals · Run1→Run5 trend.
// This shape is the API response contract (types.ts). The goal is no UI change when switching
// from mock to real.
// ============================================================================
import type {
  CatalogEntry,
  CleanupItem,
  MetricsPoint,
  PolicyAction,
  ReportRef,
  Run,
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
export const METRICS: MetricsPoint[] = [
  {
    run_id: "run-001", ts: "2026-05-19T02:00:00Z",
    unused_permissions: 1604, unused_roles: 59, long_lived_keys: 23, no_mfa: 14,
    over_privileged_principals: 512, escalation_paths: 37, personas: 6,
    iam_users_pending_migration: 148, ps_migration_pct: 12,
    risk_dist: { critical: 141, high: 288, medium: 402, low: 380 },
  },
  {
    run_id: "run-002", ts: "2026-06-02T02:00:00Z",
    unused_permissions: 1498, unused_roles: 55, long_lived_keys: 22, no_mfa: 13,
    over_privileged_principals: 471, escalation_paths: 33, personas: 6,
    iam_users_pending_migration: 131, ps_migration_pct: 24,
    risk_dist: { critical: 128, high: 271, medium: 419, low: 421 },
  },
  {
    run_id: "run-003", ts: "2026-06-16T02:00:00Z",
    unused_permissions: 1421, unused_roles: 52, long_lived_keys: 21, no_mfa: 12,
    over_privileged_principals: 438, escalation_paths: 30, personas: 7,
    iam_users_pending_migration: 118, ps_migration_pct: 38,
    risk_dist: { critical: 119, high: 260, medium: 431, low: 461 },
  },
  {
    run_id: "run-004", ts: "2026-06-30T02:00:00Z",
    unused_permissions: 1352, unused_roles: 49, long_lived_keys: 19, no_mfa: 10,
    over_privileged_principals: 401, escalation_paths: 27, personas: 7,
    iam_users_pending_migration: 92, ps_migration_pct: 54,
    risk_dist: { critical: 110, high: 251, medium: 439, low: 484 },
  },
  {
    run_id: "run-005", ts: "2026-07-14T02:00:00Z",
    unused_permissions: 1284, unused_roles: 47, long_lived_keys: 18, no_mfa: 9,
    over_privileged_principals: 368, escalation_paths: 24, personas: 8,
    iam_users_pending_migration: 71, ps_migration_pct: 66,
    risk_dist: { critical: 103, high: 244, medium: 437, low: 500 },
  },
];

// ---- 정책 편집기용 action 체크리스트 헬퍼 ----
function mkActions(
  used: [string, string, number][], // [action, last_used, count]
  granted_unused: string[],
): PolicyAction[] {
  return [
    ...used.map(([action, last_used, count_90d]) => ({
      action, used: true, included: true, last_used, count_90d,
    })),
    ...granted_unused.map((action) => ({
      action, used: false, included: false, last_used: null, count_90d: 0,
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
    member_details: [
      { principal: "arn:aws:iam::111122223333:role/data-eng-batch", principal_kind: "unknown",
        trust_principals: ["arn:aws:iam::111122223333:root"], tags: { Team: "data", Owner: "data-platform" } },
      { principal: "arn:aws:iam::111122223333:role/glue-job", principal_kind: "service",
        trust_principals: ["glue.amazonaws.com"], tags: { Team: "data" } },
      { principal: "arn:aws:iam::444455556666:role/data-eng-batch", principal_kind: "human",
        trust_principals: ["arn:aws:iam::444455556666:saml-provider/Okta"], tags: {} },
      { principal: "arn:aws:iam::444455556666:role/glue-job", principal_kind: "service",
        trust_principals: ["glue.amazonaws.com"], tags: {} },
    ],
    member_count: 4,
    policy_ref: "policies/DataEngineer.json",
    approval_status: "review",
    ai_suggested: true,
    synthesis_source: "access_analyzer",
    contributing_sources: ["access_advisor", "cloudtrail", "credential_report"],
    actions: mkActions(
      [
        ["s3:GetObject", "2026-07-13T18:22:00Z", 8421],
        ["s3:PutObject", "2026-07-13T18:20:00Z", 3120],
        ["glue:StartJobRun", "2026-07-12T09:00:00Z", 210],
        ["athena:StartQueryExecution", "2026-07-13T11:04:00Z", 1890],
        ["athena:GetQueryResults", "2026-07-13T11:05:00Z", 1885],
      ],
      ["iam:PassRole", "s3:DeleteBucket", "glue:DeleteDatabase", "kms:ScheduleKeyDeletion"],
    ),
  },
  {
    persona: "ReadOnlyAuditor",
    description: "규정 감사용 전역 read-only. 쓰기 action 0.",
    members: ["arn:aws:iam::111122223333:role/auditor"],
    member_details: [
      { principal: "arn:aws:iam::111122223333:role/auditor", principal_kind: "human",
        trust_principals: ["arn:aws:iam::111122223333:saml-provider/Okta"], tags: { Team: "grc" } },
    ],
    member_count: 88,
    policy_ref: "policies/ReadOnlyAuditor.json",
    approval_status: "approved",
    ai_suggested: false,
    synthesis_source: "access_analyzer",
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
      { principal: "arn:aws:iam::444455556666:role/platform-admin", principal_kind: "unknown",
        trust_principals: ["arn:aws:iam::444455556666:root"], tags: {} },
    ],
    member_count: 24,
    policy_ref: "policies/PlatformAdmin.json",
    approval_status: "review",
    ai_suggested: true,
    synthesis_source: "fallback_used_actions",
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
        trust_principals: ["codebuild.amazonaws.com", "arn:aws:iam::444455556666:root"], tags: { Pipeline: "main" } },
    ],
    member_count: 51,
    policy_ref: "policies/CICDDeployer.json",
    approval_status: "draft",
    ai_suggested: true,
    synthesis_source: "access_analyzer",
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
  unused_permission: ["미사용 권한/발견 35건"],
};
// 레벨→대표 점수(경계 이상). 데모용.
const LEVEL_SCORE: Record<CleanupItem["risk_level"], number> = { critical: 80, high: 60, medium: 35, low: 15 };

// 유형별 상세 근거(evidence) — 엔진 m6_reporter 형식과 동일.
const TYPE_EVIDENCE: Record<CleanupItem["type"], Record<string, string>> = {
  long_lived_key: { "액세스키 나이": "612일", "임계 기준": "90일 이상", MFA: "미설정", "콘솔 로그인": "가능" },
  no_mfa: { "식별 유형": "user", "콘솔 로그인": "가능", MFA: "미설정", "액세스키 나이": "148일" },
  escalation_path: { "경유(via)": "iam:CreateRole", "도달 대상(to)": "AdministratorAccess", "MITRE ATT&CK": "T1098", "부여된 action 수": "42" },
  unused_role: { "식별 유형": "role", "부여된 action 수": "37", "90일 사용 action": "0", "관리형 정책 연결": "예", "수집 소스": "access_advisor, credential_report" },
  unused_permission: { "부여된 action 수": "50", "실사용 action 수": "15", "미사용 action 수": "35", "대표 미사용": "s3:DeleteBucket, s3:PutBucketPolicy, iam:PassRole", "수집 소스": "access_advisor, cloudtrail" },
};

function reasonsFor(type: CleanupItem["type"], level: CleanupItem["risk_level"]): string[] {
  const base = [...TYPE_REASONS[type]];
  // 높은 레벨엔 가중 요인을 덧붙여 점수가 왜 높은지 설명.
  if (level === "critical") base.push("관리자급 광범위 권한", "와일드카드 action 부여('*')");
  else if (level === "high") base.push("와일드카드 action 부여('*')");
  return base;
}

function genCleanup(): CleanupItem[] {
  const seedItems: Omit<CleanupItem, "id" | "account_id" | "risk_level" | "risk_score" | "risk_reasons">[] = [
    { type: "long_lived_key", principal: "user/legacy-svc", detail: "액세스키 age 612일", recommendation: "키 회전 또는 역할 전환" },
    { type: "no_mfa", principal: "user/ops-break-glass", detail: "MFA 미설정 콘솔 사용자", recommendation: "MFA 강제 또는 SSO 전환" },
    { type: "escalation_path", principal: "role/platform-admin", detail: "iam:CreateRole → AttachRolePolicy 상승 경로", recommendation: "권한 경계(permission boundary) 적용" },
    { type: "unused_role", principal: "role/old-migration", detail: "90일간 미사용", recommendation: "역할 삭제 후보" },
    { type: "unused_permission", principal: "role/data-eng-batch", detail: "granted 이나 미사용: s3:DeleteBucket 외 34건", recommendation: "최소권한 정책으로 교체" },
  ];
  // 유형별 목표 건수(합계 118) — 미사용 권한이 압도적으로 많은 실제 분포 모사.
  const counts: Record<CleanupItem["type"], number> = {
    unused_permission: 61, unused_role: 22, long_lived_key: 18, no_mfa: 9, escalation_path: 8,
  };
  const out: CleanupItem[] = [];
  let n = 0;
  (Object.keys(counts) as CleanupItem["type"][]).forEach((type) => {
    const seed = seedItems.find((s) => s.type === type)!;
    for (let i = 0; i < counts[type]; i++) {
      const acct = ACCOUNTS[n % ACCOUNTS.length];
      const level = RISK_CYCLE[(n + (type === "long_lived_key" ? 0 : 2)) % RISK_CYCLE.length];
      out.push({
        id: `c${++n}`,
        type,
        account_id: acct,
        principal: `arn:aws:iam::${acct}:${seed.principal}${i === 0 ? "" : "-" + i}`,
        detail: seed.detail,
        risk_level: level,
        recommendation: seed.recommendation,
        risk_score: LEVEL_SCORE[level],
        risk_reasons: reasonsFor(type, level),
        evidence: TYPE_EVIDENCE[type],
      });
    }
  });
  return out;
}

export const CLEANUP: CleanupItem[] = genCleanup();

// 위험도 산정 기준(mock — 엔진 RiskRules 기본값과 일치).
export const RISK_CRITERIA = {
  level_critical: 75,
  level_high: 50,
  level_medium: 25,
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
      unused_permissions_removed: 320, generated_at: "2026-07-14T02:12:00Z",
    },
  },
};

export const LATEST_RUN_ID = "run-005";
