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
  MetricsPoint,
  AccountInfo,
  AiSettings,
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
  // 승인 시 정책 문서(편집 반영)를 함께 넘겨 Terraform 을 생성해 반환.
  approvePersona(persona: string, policyDoc: string): Promise<{ entry: CatalogEntry; terraform: TerraformArtifact }>;
  // 2차 확인 후: tooling-IdC 에 PS 정의 생성(assignment 제외).
  provisionPermissionSet(persona: string): Promise<ProvisionResult>;
  getCleanup(): Promise<CleanupItem[]>;
  getRiskCriteria(): Promise<RiskCriteria>;
  getReport(runId: string): Promise<ReportRef>;
  getLatestReport(account?: string): Promise<ReportRef>; // account="" 이면 전체
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
    });
  },
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
  getCleanup: () => delay([...mock.CLEANUP]),
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
  provisionPermissionSet: (persona) =>
    real(`/catalog/${encodeURIComponent(persona)}/provision-ps`, { method: "POST" }),
  getCleanup: () => real("/cleanup-backlog"),
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
