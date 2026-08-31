// ============================================================================
// API 클라이언트 어댑터 — mock ↔ real 전환 이음새.
//   VITE_USE_MOCKS=true  → 목데이터 모듈 반환 (U1 기본)
//   VITE_USE_MOCKS=false → 실 fetch (Cognito 토큰 attach)
// 페이지 코드는 이 인터페이스에만 의존 → 플래그만 끄면 실 API (계약 일치 시 화면 무변경).
// ============================================================================
import type {
  AssistantAnswer,
  CatalogEntry,
  CleanupItem,
  CleanupStatus,
  CleanupStatusRecord,
  MetricsPoint,
  AccountInfo,
  AiSettings,
  PolicyArtifact,
  ProvisionResult,
  ReportRef,
  RiskCriteria,
  Run,
  RunSources,
  ScheduleState,
  TerraformArtifact,
} from "./types";
import * as mock from "@/mocks/data";
import { getIdToken } from "@/auth/cognito";

const USE_MOCKS = import.meta.env.VITE_USE_MOCKS !== "false"; // 기본 mock

// mock 응답을 살짝 지연시켜 로딩 상태를 실제처럼 확인 가능하게.
function delay<T>(value: T, ms = 220): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), ms));
}

async function real<T>(path: string, init?: RequestInit): Promise<T> {
  // Cognito ID 토큰을 Authorization 헤더에 attach(API GW Cognito authorizer).
  const base = import.meta.env.VITE_API_BASE ?? "";
  const token = await getIdToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (token) headers.Authorization = token;
  const res = await fetch(`${base}${path}`, { ...init, headers });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export interface Api {
  listRuns(): Promise<Run[]>;
  startRun(): Promise<Run>;
  getRunSources(runId: string): Promise<RunSources>; // 실행 이력 행 확장 상세

  getMetrics(): Promise<MetricsPoint[]>;
  getCatalog(): Promise<CatalogEntry[]>;
  // 승인 시 정책 문서(편집 반영)를 함께 넘겨 반영 산출물을 생성해 반환.
  // artifacts = 이 고객이 실제로 apply 할 수 있는 산출물 전부(IdC 미사용이면 PS 는 빠진다).
  // terraform = PS 단건(기존 계약 유지 — provision-ps 흐름이 참조).
  approvePersona(
    persona: string,
    policyDoc: string,
  ): Promise<{ entry: CatalogEntry; terraform: TerraformArtifact; artifacts: PolicyArtifact[] }>;
  // 승인 후 다시 볼 때(승인 응답을 잃은 뒤) 산출물만 다시 받는 경로.
  getArtifacts(persona: string): Promise<PolicyArtifact[]>;
  // 2차 확인 후: tooling-IdC 에 PS 정의 생성(assignment 제외).
  provisionPermissionSet(persona: string): Promise<ProvisionResult>;
  getCleanup(): Promise<CleanupItem[]>;
  // 조치 상태 표시. 실제 조치는 사람이 AWS 에서 수행하고 여기엔 그 사실만 기록한다.
  // findingKey 가 빈 항목(구 형식 산출물)은 호출하면 안 된다 — 상태를 붙일 대상을 특정할 수 없다.
  setCleanupStatus(findingKey: string, status: CleanupStatus, note: string): Promise<CleanupStatusRecord>;
  getRiskCriteria(): Promise<RiskCriteria>;
  getReport(runId: string): Promise<ReportRef>;
  // null = 아직 볼 수 있는 리포트가 없다(갓 배포한 상태 · 전체 조회 미실행). 오류가 아니다.
  getLatestReport(account?: string): Promise<ReportRef | null>; // account="" 이면 전체
  askAssistant(question: string): Promise<AssistantAnswer>;
  // 주기적 전체 조회 예약 조회/갱신(EventBridge 규칙).
  getSchedule(): Promise<ScheduleState>;
  putSchedule(state: ScheduleState): Promise<ScheduleState>;
  // AI 개입 기능 런타임 on/off(SSM).
  getAiSettings(): Promise<AiSettings>;
  putAiSettings(state: AiSettings): Promise<AiSettings>;
  // 관리 중인 계정 목록(계정 선택기).
  getAccounts(): Promise<AccountInfo[]>;
}

// persona 정책 JSON → Permission Set Terraform(HCL) 생성 (mock; 엔진 m7_iac_emitter 계약).
function toTerraform(persona: string, policyDoc: string): TerraformArtifact {
  const psName = `${persona}-least-privilege`;
  const hcl = `# 자동 생성 — LP2PS. 검토 후 apply 하세요.
resource "aws_ssoadmin_permission_set" "${persona.toLowerCase()}" {
  name             = "${psName}"
  description      = "LP2PS 최소권한 — ${persona}"
  instance_arn     = var.identity_center_instance_arn
  session_duration = "PT1H"
}

resource "aws_ssoadmin_permission_set_inline_policy" "${persona.toLowerCase()}" {
  instance_arn       = var.identity_center_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.${persona.toLowerCase()}.arn
  inline_policy      = <<POLICY
${policyDoc.split("\n").map((l) => "  " + l).join("\n")}
POLICY
}

# account assignment 은 의도적으로 생성하지 않음 — 필요 시 사람이 수동으로 추가.
`;
  return { persona, permission_set_name: psName, filename: `${persona}.tf`, hcl };
}

// ---- mock 반영 산출물 ----
// 정본은 engine/lp2ps/policy_export.py 다. 여기 사본은 **mock 모드에서 화면을 확인하기 위한 것**이며,
// 실 API 는 엔진 산출물을 그대로 내려준다(VITE_USE_MOCKS=false). 그래서 문구가 100% 같지 않아도
// 되지만, 탭 라벨·target·notes 갯수 같은 **계약**은 맞춰야 화면 검증이 의미가 있다.
const MOCK_COMMON_NOTES = [
  '정책의 Resource 는 "*" 입니다 — action 만 최소화했고 리소스 범위는 좁히지 않았습니다. 운영 반영 전에 리소스 조건을 좁히는 것을 권장합니다.',
  "이 정책은 이 persona 멤버 전원의 실사용 action 합집합입니다 — 개별 멤버에게는 필요 이상일 수 있으나 부족하지는 않습니다.",
  "다른 계정에 반영할 때는 계정마다 apply 하세요(provider alias 또는 Terraform workspace). LP2PS 는 계정 간 apply 를 수행하지 않습니다.",
];

// mock 이 IdC 사용 고객을 흉내내는가. `VITE_MOCK_NO_IDC=true` 로 빌드/실행하면 IdC 미사용 고객의
// 화면(PS 탭·IdC 생성 버튼 없음)을 그대로 확인할 수 있다 — 이 기능의 대상이 그 고객이라 화면 검증
// 경로가 필요하다. 실 배포에서는 config `provisioning.uses_identity_center` 가 결정한다.
const MOCK_USES_IDC = import.meta.env.VITE_MOCK_NO_IDC !== "true";

function toArtifacts(persona: string, policyDoc: string): PolicyArtifact[] {
  const res = persona.replace(/[^0-9A-Za-z]/g, "_").replace(/^_+|_+$/g, "").toLowerCase() || "persona";
  const iamName = `${persona}-least-privilege`;
  const body = policyDoc.trim() || '{\n  "Version": "2012-10-17",\n  "Statement": []\n}';
  const compact = body.replace(/\s+/g, " ");
  const header = `# 자동 생성 — LP2PS. 검토 후 apply 하세요.\n#\n# persona: ${persona}\n# 주의: Statement 의 Resource 는 "*" 입니다 — action 만 최소화했습니다.\n`;

  const artifacts: PolicyArtifact[] = [
    {
      persona,
      target: "iam_policy_tf",
      label: "IAM 정책 (.tf)",
      filename: `${persona}.iam-policy.tf`,
      content: `${header}\nresource "aws_iam_policy" "${res}" {\n  name        = "${iamName}"\n  description = "LP2PS 최소권한 — ${persona}"\n  policy      = jsonencode(${compact})\n}\n\noutput "${res}_policy_arn" {\n  value       = aws_iam_policy.${res}.arn\n  description = "생성된 관리형 정책 ARN — 기존 역할에 attach 할 때 사용하세요."\n}\n`,
      language: "hcl",
      notes: [...MOCK_COMMON_NOTES],
    },
    {
      persona,
      target: "policy_json",
      label: "정책 JSON",
      filename: `${persona}.policy.json`,
      content: `${body}\n`,
      language: "json",
      notes: [...MOCK_COMMON_NOTES],
    },
    {
      persona,
      target: "iam_role_tf",
      label: "IAM 역할 (.tf)",
      filename: `${persona}.iam-role.tf`,
      content: `${header}\nvariable "${res}_trusted_principals" {\n  description = "이 역할을 assume 할 주체 ARN 목록. LP2PS 는 이 값을 정하지 않습니다 — 반드시 채우세요."\n  type        = list(string)\n}\n\nresource "aws_iam_role" "${res}" {\n  name = "${iamName}"\n\n  assume_role_policy = jsonencode({\n    "Version" : "2012-10-17",\n    "Statement" : [{\n      "Effect" : "Allow",\n      "Principal" : { "AWS" : var.${res}_trusted_principals },\n      "Action" : "sts:AssumeRole"\n    }]\n  })\n}\n\nresource "aws_iam_role_policy" "${res}" {\n  name   = "${iamName}"\n  role   = aws_iam_role.${res}.id\n  policy = jsonencode(${compact})\n}\n`,
      language: "hcl",
      notes: [
        "역할의 신뢰정책(누가 assume 하는가)은 LP2PS 가 알 수 없어 Terraform 변수로 비워뒀습니다. 채우지 않고 apply 하면 아무도 사용할 수 없는 역할이 생깁니다.",
        ...MOCK_COMMON_NOTES,
      ],
    },
  ];
  if (MOCK_USES_IDC) {
    artifacts.push({
      persona,
      target: "permission_set_tf",
      label: "Permission Set (.tf)",
      filename: `${persona}.permission-set.tf`,
      content: `${header}\nresource "aws_ssoadmin_permission_set" "${res}" {\n  name             = "${iamName}"\n  description      = "LP2PS 최소권한 — ${persona}"\n  instance_arn     = var.identity_center_instance_arn\n  session_duration = "PT8H"\n}\n\nresource "aws_ssoadmin_permission_set_inline_policy" "${res}" {\n  instance_arn       = var.identity_center_instance_arn\n  permission_set_arn = aws_ssoadmin_permission_set.${res}.arn\n  inline_policy      = jsonencode(${compact})\n}\n\n# account assignment 은 의도적으로 생성하지 않음 — 필요 시 사람이 수동으로 추가.\n`,
      language: "hcl",
      notes: [
        "account assignment(멤버계정 권한 부여)은 포함되지 않습니다 — 필요 시 사람이 수동으로 추가하세요.",
        ...MOCK_COMMON_NOTES,
      ],
    });
  }
  return artifacts;
}

// mock 스케줄 상태(모듈 레벨 — PUT 이 GET 에 반영되도록 유지).
let mockSchedule: ScheduleState = {
  enabled: false, frequency: "daily", hour_utc: 2, day_of_week: 2, day_of_month: 1, cron: "0 2 * * ? *",
};

// mock AI 토글 상태(모듈 레벨 — PUT→GET 반영).
let mockAi: AiSettings = { enabled: false };

// mock 에서도 백엔드와 동일하게 프리셋 → cron 변환(UI 미리보기 일치).
function mockToCron(s: ScheduleState): string {
  if (s.frequency === "custom") return s.cron.trim();
  if (s.frequency === "weekly") return `0 ${s.hour_utc} ? * ${s.day_of_week} *`;
  if (s.frequency === "monthly") return `0 ${s.hour_utc} ${s.day_of_month} * ? *`;
  return `0 ${s.hour_utc} * * ? *`; // daily
}

// ---- mock 구현 ----
const mockApi: Api = {
  listRuns: () => delay([...mock.RUNS]),
  startRun: () =>
    delay({
      run_id: `run-${String(mock.RUNS.length + 1).padStart(3, "0")}`,
      customer: mock.CUSTOMER,
      started_at: new Date().toISOString(),
      account_scope: 24,
      status: "running",
    }),
  getRunSources: (runId) =>
    delay({
      run_id: runId,
      status: "succeeded",
      status_summary: { degraded_sources: [], skipped_sources: ["analyzer_unused"], has_skipped: true },
      accounts: [
        {
          account_id: "111122223333",
          sources: [
            { source: "access_advisor", status: "ok", note: "" },
            { source: "analyzer_unused", status: "skipped", note: "unused-access analyzer 미존재 — Access Advisor 로 대체(정상)" },
            { source: "cloudtrail", status: "ok", note: "LookupEvents(90d) 관리 이벤트 기반." },
            { source: "credential_report", status: "ok", note: "" },
            { source: "idc_permission_sets", status: "ok", note: "" },
          ],
        },
      ],
    }),
  getMetrics: () => delay([...mock.METRICS]),
  getCatalog: () => delay(structuredClone(mock.CATALOG)),
  approvePersona: (persona, policyDoc) => {
    const entry = mock.CATALOG.find((c) => c.persona === persona)!;
    return delay({
      entry: { ...structuredClone(entry), approval_status: "approved" as const },
      terraform: toTerraform(persona, policyDoc),
      artifacts: toArtifacts(persona, policyDoc),
    });
  },
  getArtifacts: (persona) => delay(toArtifacts(persona, "")),
  provisionPermissionSet: (persona) =>
    delay(
      {
        persona,
        permission_set_arn: `arn:aws:sso:::permissionSet/ssoins-mock/ps-${persona.toLowerCase()}`,
        created: true,
        assignment_skipped: true as const,
        provisioned_at: new Date().toISOString(),
      },
      900,
    ),
  getCleanup: () => delay(mock.CLEANUP.map((c) => ({ ...c }))),
  // mock 은 모듈 상태를 그 자리에서 갱신한다 — 표시 후 재조회했을 때 값이 유지되는지(=화면이
  // 낙관적 갱신에만 의존하지 않는지)까지 확인할 수 있어야 한다.
  setCleanupStatus: (findingKey, status, note) => {
    const target = mock.CLEANUP.find((c) => c.finding_key === findingKey);
    const rec: CleanupStatusRecord = {
      finding_key: findingKey,
      status,
      note,
      updated_at: new Date().toISOString(),
      updated_by: "mock@example.com",
    };
    if (target) {
      target.status = status;
      target.status_note = note;
      target.status_updated_at = rec.updated_at;
      target.status_updated_by = rec.updated_by;
    }
    return delay(rec);
  },
  getRiskCriteria: () => delay(structuredClone(mock.RISK_CRITERIA)),
  getReport: (runId) => delay(mock.REPORTS[runId] ?? mock.REPORTS[mock.LATEST_RUN_ID]),
  getLatestReport: (_account) => delay(mock.REPORTS[mock.LATEST_RUN_ID]),
  askAssistant: (question) =>
    delay(
      {
        answer:
          `수집된 데이터 기준, "${question}" 에 해당하는 principal 중 위험도 High 이상은 ` +
          `PlatformAdmin(iam:CreateRole 상승 경로) 및 legacy-svc(액세스키 612일)입니다. ` +
          `근거는 최신 run(run-005)의 정규화 데이터입니다.`,
        grounded: true,
        citations: [
          { principal: "arn:aws:iam::444455556666:role/platform-admin", action: "iam:CreateRole", source: "normalized.parquet#run-005" },
          { principal: "arn:aws:iam::111122223333:user/legacy-svc", source: "credential_report#run-005" },
        ],
        ai_suggested: true,
      },
      600,
    ),
  getAiSettings: () => delay(structuredClone(mockAi)),
  putAiSettings: (state) => {
    mockAi = { enabled: state.enabled };
    return delay(structuredClone(mockAi));
  },
  getAccounts: () => delay([
    { account_id: "111122223333", status: "ok", is_tooling: true },
    { account_id: "444455556666", status: "degraded", is_tooling: false },
  ]),
  getSchedule: () => delay(structuredClone(mockSchedule)),
  putSchedule: (state) => {
    mockSchedule = { ...state, cron: mockToCron(state) };
    return delay(structuredClone(mockSchedule));
  },
};

// ---- real 구현 ----
const realApi: Api = {
  listRuns: () => real("/runs"),
  startRun: () => real("/runs", { method: "POST" }),
  getRunSources: (runId) => real(`/runs/${encodeURIComponent(runId)}/sources`),
  getMetrics: () => real("/metrics"),
  getCatalog: () => real("/catalog"),
  approvePersona: (persona, policyDoc) =>
    real(`/catalog/${encodeURIComponent(persona)}/approve`, {
      method: "POST",
      // 백엔드 approve 는 {policy_doc} 를 기대(Body embed). 계약 일치.
      body: JSON.stringify({ policy_doc: policyDoc }),
    }),
  getArtifacts: (persona) => real(`/catalog/${encodeURIComponent(persona)}/artifacts`),
  provisionPermissionSet: (persona) =>
    real(`/catalog/${encodeURIComponent(persona)}/provision-ps`, { method: "POST" }),
  getCleanup: () => real("/cleanup-backlog"),
  setCleanupStatus: (findingKey, status, note) =>
    real(`/cleanup-backlog/${encodeURIComponent(findingKey)}/status`, {
      method: "PUT",
      body: JSON.stringify({ status, note }),
    }),
  getRiskCriteria: () => real("/cleanup-backlog/risk-criteria"),
  getReport: (runId) => real(`/reports/${runId}`),
  getLatestReport: (account) => real(account ? `/reports?account=${encodeURIComponent(account)}` : "/reports"),
  askAssistant: (question) =>
    real("/assistant/ask", { method: "POST", body: JSON.stringify({ question }) }),
  getAiSettings: () => real("/settings/ai"),
  putAiSettings: (state) => real("/settings/ai", { method: "PUT", body: JSON.stringify(state) }),
  getAccounts: () => real("/accounts"),
  getSchedule: () => real("/schedule"),
  putSchedule: (state) => real("/schedule", { method: "PUT", body: JSON.stringify(state) }),
};

export const api: Api = USE_MOCKS ? mockApi : realApi;
export const USING_MOCKS = USE_MOCKS;
