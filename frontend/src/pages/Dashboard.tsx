import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import Container from "@cloudscape-design/components/container";
import Grid from "@cloudscape-design/components/grid";
import Box from "@cloudscape-design/components/box";
import SpaceBetween from "@cloudscape-design/components/space-between";
import LineChart from "@cloudscape-design/components/line-chart";
import BarChart from "@cloudscape-design/components/bar-chart";
import Spinner from "@cloudscape-design/components/spinner";
import Button from "@cloudscape-design/components/button";
import Flashbar from "@cloudscape-design/components/flashbar";
import Modal from "@cloudscape-design/components/modal";
import FormField from "@cloudscape-design/components/form-field";
import Select from "@cloudscape-design/components/select";
import Toggle from "@cloudscape-design/components/toggle";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import Alert from "@cloudscape-design/components/alert";
import { api } from "@/api/client";
import { useAsync } from "@/api/useAsync";
import { useAccounts } from "@/AccountContext";
import { CHART_SERIES, RISK_COLOR } from "@/theme/tokens";
import { tierLabel, cleanupDays } from "@/lib/tierLabel";
import type {
  ActionGroupMetrics,
  CleanupGroup,
  MetricsPoint,
  ScheduleState,
  AiSettings,
  RunStatus,
  RiskCriteria,
  ServiceRoleEntry,
  UnusedTierDist,
} from "@/api/types";

// "전체 조회 실행" 완료 폴링 파라미터. 실 파이프라인은 계정 수·자원 수에 비례해 수 분 걸린다
// (단일 계정 기준 관측치 약 5분 30초). 타임아웃은 넉넉히 두고, 넘으면 실패로 단정하지 않고
// "아직 진행 중일 수 있다"고 안내한다 — 실행 자체는 Step Functions 에서 계속 돌기 때문이다.
const POLL_INTERVAL_MS = 10_000;
const POLL_TIMEOUT_MS = 30 * 60_000;
const TERMINAL_STATUSES: readonly RunStatus[] = ["succeeded", "degraded", "failed"];

/**
 * 해당 run 이 종료 상태가 될 때까지 GET /runs 를 폴링한다.
 * 반환: 종료 상태 문자열, 또는 타임아웃 시 null.
 * 폴링 중 일시적 조회 실패는 무시한다(다음 주기에 재시도) — 실행은 서버에서 계속 진행되므로
 * 네트워크 순간 오류로 완료를 놓치지 않는다.
 */
async function pollRunStatus(runId: string): Promise<RunStatus | null> {
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    try {
      const runs = await api.listRuns();
      const mine = runs.find((r) => r.run_id === runId);
      if (mine && TERMINAL_STATUSES.includes(mine.status)) return mine.status;
    } catch {
      // 일시적 오류 — 다음 주기에 재시도.
    }
  }
  return null;
}

// run 의 total MetricsPoint 에서 선택 계정 뷰를 뽑는다. 전체("")면 total 그대로,
// 특정 계정이면 by_account 에서 매칭(없으면 0 이 담긴 빈 포인트).
function scopeMetric(m: MetricsPoint, account: string): MetricsPoint {
  if (!account) return m;
  const found = m.by_account?.find((b) => b.account_id === account);
  // 그 계정 분해가 없을 때(단일 계정 run 등)는 **모든 집계를 0 으로 내린다**. `...m` 은 run 메타를
  // 물려받기 위한 것이고, 세는 값이 하나라도 남으면 전체 계정 숫자를 그 계정 것이라고 말하게 된다.
  // `definition_version` 은 run 의 속성이므로 그대로 둔다(0 으로 만들면 경계선 판정이 깨진다).
  return found ?? { ...m, by_account: [], account_id: account,
    unused_permissions: 0, undetermined_permissions: 0, unused_roles: 0, new_unused_roles: 0,
    owner_review_roles: 0, long_lived_keys: 0, no_mfa: 0,
    over_privileged_principals: 0, escalation_paths: 0, iam_users_pending_migration: 0,
    ps_migration_pct: 0, wildcard_grant_principals: 0, cross_tenant_trust_roles: 0,
    service_role_targets: 0, service_role_unused_actions: 0,
    // 3카드·제외 내역도 비운다. 배열은 0 으로 못 만들어서 빼먹기 쉬운데, 남겨 두면 그 계정 카드에
    // **전체 계정 대상 수**가 뜨고 눌러서 열린 목록은 그 계정 것만 나온다(단위 불일치 결함의 재발).
    action_groups: [], exclusions: [],
    unused_tier_dist: { active: 0, watch: 0, review: 0, cleanup: 0, new: 0, ungraded: 0 },
    risk_dist: { critical: 0, high: 0, medium: 0, low: 0 } };
}

// ISO8601(UTC) → KST "MM/DD HH:mm" 짧은 라벨(추이 차트 X축용). Asia/Seoul 로 변환.
function fmtKstShort(iso: string): string {
  try {
    // ko-KR 은 "MM. DD. HH:mm" 형태 → "MM/DD HH:mm" 로 정리(날짜/시각 구분).
    return new Date(iso).toLocaleString("ko-KR", {
      timeZone: "Asia/Seoul", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false,
    }).replace(/^(\d{1,2})\.\s*(\d{1,2})\.\s*/, "$1/$2 ").trim();
  } catch {
    return iso.slice(0, 16);
  }
}

// 빈도 프리셋 옵션 (백엔드 frequency 값과 일치).
// 🔴 `custom`(cron 직접 입력)은 **화면에서 뺀다** — cron 6필드는 사용자에게 생소하고, 애초에 이것이
// 노출된 이유는 고급 기능이 아니라 GET 이 프리셋을 복원하지 못한 왕복 결함이었다(백엔드 `_from_cron`
// 이 고쳤다). API 는 `custom` 을 계속 받는다(손으로 만든 EventBridge 규칙을 **읽기**는 해야 한다).
const FREQ_OPTIONS = [
  { value: "daily", label: "매일" },
  { value: "weekly", label: "매주" },
  { value: "monthly", label: "매월" },
];
const DOW_OPTIONS = [
  { value: "1", label: "일요일" }, { value: "2", label: "월요일" }, { value: "3", label: "화요일" },
  { value: "4", label: "수요일" }, { value: "5", label: "목요일" }, { value: "6", label: "금요일" },
  { value: "7", label: "토요일" },
];
// 시각 옵션은 KST 기준(0~23시). 저장은 UTC 로 변환(EventBridge cron 은 UTC 필수).
const HOUR_OPTIONS = Array.from({ length: 24 }, (_, h) => ({ value: String(h), label: `${String(h).padStart(2, "0")}:00 KST` }));

// KST 는 UTC+9. 예약 필드는 백엔드/EventBridge 호환 위해 UTC(hour_utc·day_of_week[1=일])로 저장하고,
// UI 는 KST 로 보여준다. 시각이 자정을 넘으면 요일/날짜가 하루 밀리므로 함께 보정.

// UTC 저장값 → KST 표시값 { hour, dowShift } (dowShift: 요일 +1 필요 여부).
function utcToKst(hourUtc: number): { hour: number; dayShift: number } {
  const h = hourUtc + 9;
  return { hour: h % 24, dayShift: h >= 24 ? 1 : 0 };
}
// KST 표시값 → UTC 저장값 { hour, dayShift } (dayShift: 요일 -1 필요 여부).
function kstToUtc(hourKst: number): { hour: number; dayShift: number } {
  const h = hourKst - 9;
  return { hour: (h + 24) % 24, dayShift: h < 0 ? -1 : 0 };
}
const wrapDow = (d: number) => ((d - 1 + 7) % 7) + 1;          // 1~7 순환(1=일)
const wrapDom = (d: number) => ((d - 1 + 28) % 28) + 1;        // 1~28 순환

// UTC 로 저장된 ScheduleState → KST 표시용 {hourKst, dowKst, domKst}.
function toKstView(s: ScheduleState) {
  const { hour, dayShift } = utcToKst(s.hour_utc);
  return {
    hourKst: hour,
    dowKst: wrapDow(s.day_of_week + dayShift),
    domKst: wrapDom(s.day_of_month + dayShift),
  };
}
// KST 표시값(draft)을 UTC 저장값으로 되돌린 ScheduleState.
function fromKstView(s: ScheduleState, hourKst: number, dowKst: number, domKst: number): ScheduleState {
  const { hour, dayShift } = kstToUtc(hourKst);
  return {
    ...s,
    hour_utc: hour,
    day_of_week: wrapDow(dowKst + dayShift),
    day_of_month: wrapDom(domKst + dayShift),
  };
}

// 현재 예약을 사람이 읽는 한 줄 요약(KST 기준).
function scheduleSummary(s: ScheduleState): string {
  if (!s.enabled) return "예약 없음";
  const { hourKst, dowKst, domKst } = toKstView(s);
  const at = `${String(hourKst).padStart(2, "0")}:00 KST`;
  if (s.frequency === "daily") return `매일 ${at}`;
  if (s.frequency === "weekly") return `매주 ${DOW_OPTIONS.find((d) => d.value === String(dowKst))?.label ?? ""} ${at}`;
  if (s.frequency === "monthly") return `매월 ${domKst}일 ${at}`;
  // `custom` = 우리 프리셋 형태가 아닌 규칙(손으로 만든 EventBridge 규칙). cron 을 KST 문장으로
  // 옮길 수 없으므로 **번역하지 않고 그런 규칙이라는 사실만** 말한다(cron 원문을 다시 노출하지 않는다).
  return "직접 만든 일정 — 프리셋으로 표현할 수 없음";
}

// 현황 KPI 카드 — 현재 값만 표시. onClick 이 있으면 클릭 가능(조치 필요 항목으로 딥링크).
// hint: 숫자만으로 오해가 생기는 카드의 보조 설명(예: '해당 없음' 인 이유).
function Kpi({ label, value, onClick, hint }: { label: string; value: string; onClick?: () => void; hint?: string }) {
  const inner = (
    <SpaceBetween size="xs">
      <Box variant="awsui-key-label">{label}</Box>
      <Box fontSize={value.length > 6 ? "heading-l" : "display-l"} fontWeight="bold">{value}</Box>
      {hint && <Box fontSize="body-s" color="text-body-secondary">{hint}</Box>}
      {onClick && <Box fontSize="body-s" color="text-status-info">항목 보기 →</Box>}
    </SpaceBetween>
  );
  if (!onClick) return <Container>{inner}</Container>;
  return (
    <div
      className="lp2ps-kpi-clickable"
      role="button"
      tabIndex={0}
      onClick={onClick}
      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onClick(); } }}
      style={{ height: "100%" }}
    >
      {/* 컨테이너 내부 요소까지 손가락 커서 강제(Cloudscape 내부 div 가 커서를 덮어씀 방지) */}
      <style>{`.lp2ps-kpi-clickable, .lp2ps-kpi-clickable * { cursor: pointer; }`}</style>
      <Container>{inner}</Container>
    </div>
  );
}

// 조치 묶음 카드 라벨·설명. 🔴 정본은 조치 화면과 **같은 3분류**다 — 대시보드가 자기 분류를 갖는
// 순간 두 화면이 다른 이름으로 다른 숫자를 말한다(그것이 이 개편 전 상태였다: 대시보드는 '미사용
// 권한/미사용 역할/와일드카드 보유' 로 나누고, 목록은 유형 7개로 나눴다).
const GROUP_VIEW: { key: CleanupGroup; label: string; desc: string }[] = [
  { key: "delete_review", label: "삭제 검토", desc: "오래 쓰지 않았고 신뢰 대상이 확인된 대상 — 조치는 삭제입니다." },
  { key: "reduce_scope", label: "권한 축소", desc: "쓰고 있는 대상 — 지우지 않고 정책을 다시 씁니다." },
  { key: "needs_confirmation", label: "확인 필요", desc: "아직 판단할 수 없는 대상 — 조치 권고가 아닙니다." },
];

/**
 * 조치 묶음 카드 — **큰 숫자의 단위는 '대상(principal)'** 이고, 그 값은 카드를 눌러 열리는 목록의
 * 행 수와 같다.
 *
 * 🔴 이 카드가 고치는 결함: 예전 KPI '미사용 권한' 은 action 을 세어 41,451 을 띄웠고, 눌러서 열린
 * 목록은 principal 329행이었다. 라벨에 단위가 없어서 아무도 그 둘이 다른 것을 세고 있다는 것을
 * 몰랐다. 그래서 단위를 라벨에 쓰고(개 대상), 세부 숫자는 **각자 단위를 달고** 아래 줄로 내린다.
 */
function ActionCard({
  label, desc, targets, lines, onClick,
}: { label: string; desc: string; targets: number; lines: string[]; onClick: () => void }) {
  return (
    <div
      className="lp2ps-kpi-clickable"
      role="button"
      tabIndex={0}
      onClick={onClick}
      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onClick(); } }}
      style={{ height: "100%" }}
    >
      <style>{`.lp2ps-kpi-clickable, .lp2ps-kpi-clickable * { cursor: pointer; }`}</style>
      <Container>
        <SpaceBetween size="xs">
          <Box variant="awsui-key-label">{label}</Box>
          <SpaceBetween direction="horizontal" size="xs" alignItems="end">
            <Box fontSize="display-l" fontWeight="bold">{targets.toLocaleString()}</Box>
            <Box fontSize="body-s" color="text-body-secondary" padding={{ bottom: "xxs" }}>개 대상</Box>
          </SpaceBetween>
          <Box fontSize="body-s" color="text-body-secondary">{desc}</Box>
          {lines.length > 0 && (
            <Box fontSize="body-s" color="text-body-secondary">{lines.join(" · ")}</Box>
          )}
          <Box fontSize="body-s" color="text-status-info">항목 보기 →</Box>
        </SpaceBetween>
      </Container>
    </div>
  );
}

export default function Dashboard() {
  const navigate = useNavigate();
  const { selected } = useAccounts();
  const { data: metrics, loading, reload } = useAsync<MetricsPoint[]>(() => api.getMetrics());
  // 트랙②(기계가 쓰는 현역 역할)의 1층 숫자. **지표에서 계산하지 않는다** — 판단 필요 서비스 수는
  // 서비스 접기의 결과이고 그 규칙은 엔진 M5 한 곳에만 있어야 한다(대시보드가 다시 세면 화면과 산출물이 갈린다).
  // 그래서 목록과 같은 산출물을 읽고 `decision_count` 를 합산만 한다. 실패하면 null → "—" 로 두고
  // 0 이라고 말하지 않는다.
  const { data: svcRoles } = useAsync<ServiceRoleEntry[]>(() => api.getServiceRoles());
  // 등급 라벨이 "N일 이상 미사용" 이라 config 경계값이 필요하다(프런트에 30/60/90 을 박으면
  // 경계를 조정한 고객의 범례가 거짓을 말한다). 실패하면 tierLabel 기본값으로 그린다.
  const { data: riskCriteria } = useAsync<RiskCriteria>(() => api.getRiskCriteria());
  const tierDays = riskCriteria?.unused_tier_days;
  const [running, setRunning] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [runErr, setRunErr] = useState<string | null>(null);

  // 예약(스케줄) 상태 + 편집 모달.
  const [schedule, setSchedule] = useState<ScheduleState | null>(null);
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const [draft, setDraft] = useState<ScheduleState | null>(null);
  const [saving, setSaving] = useState(false);
  const [scheduleErr, setScheduleErr] = useState<string | null>(null);

  // AI 개입 기능 런타임 토글(비용 통제 — 대시보드에서 즉시 on/off).
  const [ai, setAi] = useState<AiSettings | null>(null);
  const [aiSaving, setAiSaving] = useState(false);

  // 배포 성격 — IdC 미사용 고객에게는 PS 마이그레이션 지표가 구조적으로 달성 불가라 감춘다.
  // 조회 실패 시 기존 동작(IdC 사용)으로 폴백: 지표가 사라지는 편보다 남는 편이 오해가 적다.
  const [usesIdc, setUsesIdc] = useState(true);

  useEffect(() => {
    api.getSchedule().then(setSchedule).catch(() => setSchedule(null));
    api.getAiSettings().then(setAi).catch(() => setAi({ enabled: false }));
    api.getDeploymentSettings()
      .then((d) => setUsesIdc(d.uses_identity_center))
      .catch(() => setUsesIdc(true));
  }, []);

  async function toggleAi(enabled: boolean) {
    setAiSaving(true);
    try {
      const saved = await api.putAiSettings({ enabled });
      setAi(saved);
      setNote(saved.enabled ? "AI 개입 기능을 켰습니다 (어시스턴트·persona 제안 활성)." : "AI 개입 기능을 껐습니다.");
    } catch {
      setNote("AI 설정 저장에 실패했습니다.");
    } finally {
      setAiSaving(false);
    }
  }

  function openSchedule() {
    setDraft(schedule ?? { enabled: true, frequency: "daily", hour_utc: 2, day_of_week: 2, day_of_month: 1, cron: "0 2 * * ? *" });
    setScheduleErr(null);
    setScheduleOpen(true);
  }

  async function saveSchedule() {
    if (!draft) return;
    setSaving(true);
    setScheduleErr(null);
    try {
      const saved = await api.putSchedule(draft);
      setSchedule(saved);
      setScheduleOpen(false);
      setNote(saved.enabled ? `예약이 설정되었습니다 — ${scheduleSummary(saved)}` : "예약이 해제되었습니다.");
    } catch (e) {
      setScheduleErr(e instanceof Error ? e.message : "예약 저장에 실패했습니다.");
    } finally {
      setSaving(false);
    }
  }

  // "전체 조회 실행": 파이프라인 run 트리거 → 완료를 폴링한 뒤 지표 갱신.
  // 실 파이프라인은 수 분(계정 수·자원 수에 비례) 걸리므로 고정 대기로는 결과를 받을 수 없다.
  // GET /runs 로 해당 run 의 status 가 종료 상태(succeeded|degraded|failed)가 될 때까지 폴링한다.
  async function runScan() {
    setRunning(true);
    setNote(null);
    setRunErr(null);
    try {
      const started = await api.startRun(); // POST /runs
      const finalStatus = await pollRunStatus(started.run_id);
      reload();
      if (finalStatus === "failed") {
        setRunErr("전체 조회가 실패했습니다. 실행 이력에서 상세 사유를 확인하세요.");
      } else if (finalStatus === "degraded") {
        setNote("전체 조회가 완료되었으나 일부 소스가 부분 수집되었습니다(degraded). 실행 이력에서 사유를 확인하세요.");
      } else if (finalStatus === null) {
        setRunErr(
          `전체 조회가 ${Math.round((POLL_TIMEOUT_MS / 60000))}분 내에 끝나지 않았습니다. 실행은 계속 진행 중일 수 있습니다 — 실행 이력에서 상태를 확인하세요.`,
        );
      } else {
        setNote("전체 조회가 완료되어 대시보드를 갱신했습니다.");
      }
    } catch (e) {
      setRunErr(e instanceof Error ? `전체 조회 실행에 실패했습니다: ${e.message}` : "전체 조회 실행에 실패했습니다.");
    } finally {
      setRunning(false);
    }
  }

  // Header actions are shared by the empty state and the populated dashboard: on a fresh deployment the
  // "전체 조회 실행" button is the only way to produce the first run, so it must stay reachable.
  const headerActions = (
    <SpaceBetween direction="horizontal" size="s" alignItems="center">
      {ai && (
        <Toggle checked={ai.enabled} disabled={aiSaving} onChange={(e) => toggleAi(e.detail.checked)}>
          AI 기능 {ai.enabled ? "ON" : "OFF"}
        </Toggle>
      )}
      <Button iconName="calendar" onClick={openSchedule}>예약 설정</Button>
      <Button variant="primary" iconName="refresh" loading={running} onClick={runScan}>
        {running ? "조회 중…" : "전체 조회 실행"}
      </Button>
    </SpaceBetween>
  );

  if (loading || !metrics) {
    return <Box padding="xxl" textAlign="center"><Spinner size="large" /></Box>;
  }

  // No run yet (a fresh deployment returns an empty metrics list). Guarding only on `!metrics` is not
  // enough -- `![]` is false, so an empty array would reach `scoped[scoped.length - 1]` below and read
  // `risk_dist` off undefined, throwing during render and unmounting the whole app.
  if (metrics.length === 0) {
    return (
      <ContentLayout
        header={
          <Header
            variant="h1"
            description={`아직 실행 이력이 없습니다 · 예약: ${schedule ? scheduleSummary(schedule) : "…"}`}
            actions={headerActions}
          >
            대시보드
          </Header>
        }
      >
        <SpaceBetween size="l">
          {running && (
            <Flashbar items={[{ type: "in-progress", header: "전체 조회 실행 중", content: "대상 계정을 읽기 전용으로 수집·분석하고 있습니다. 계정·자원 수에 따라 수 분 걸립니다 — 완료되면 이 화면이 자동으로 갱신됩니다.", loading: true }]} />
          )}
          {note && (
            <Flashbar items={[{ type: "success", header: "완료", content: note, dismissible: true, onDismiss: () => setNote(null) }]} />
          )}
          {runErr && (
            <Flashbar items={[{ type: "error", header: "전체 조회", content: runErr, dismissible: true, onDismiss: () => setRunErr(null) }]} />
          )}
          <Container>
            <Box padding="xxl" textAlign="center" color="text-body-secondary">
              <SpaceBetween size="s">
                <Box variant="h3" color="inherit">수집된 지표가 없습니다</Box>
                <span>
                  우측 상단의 <b>전체 조회 실행</b> 을 눌러 첫 조회를 시작하세요. 대상 계정을 읽기 전용으로
                  수집·분석하며 수 분이 걸립니다. 완료되면 persona·리포트와 함께 지표가 채워집니다.
                </span>
              </SpaceBetween>
            </Box>
          </Container>
        </SpaceBetween>
      </ContentLayout>
    );
  }

  // 선택 계정으로 각 run 지표를 스코프(전체=그대로, 특정 계정=by_account 뷰).
  const scoped = metrics.map((m) => scopeMetric(m, selected));
  const last = scoped[scoped.length - 1];
  // 트랙② 1층 숫자 — 계정 선택을 그대로 반영한다(목록 화면과 같은 스코프여야 숫자가 맞는다).
  // 아직 못 읽었으면 null: 0 으로 그리면 "정리할 것이 없다" 는 거짓을 말한다.
  const svcScoped = (svcRoles ?? []).filter((e) => !selected || e.account_id === selected);
  const svcDecisions = svcRoles === null ? null : svcScoped.reduce((n, e) => n + e.decision_count, 0);
  const svcTargets = svcScoped.length;

  // 조치 묶음 3카드의 소스. 🔴 **폴백 판정은 run 단위**(스코프 전 total)로 한다 — 계정을 골랐는데
  // 그 계정 분해가 없으면 scopeMetric 이 배열을 비우는데, 그것을 "예전 형식 run" 으로 읽으면 계정을
  // 고르는 순간 화면의 분류가 통째로 바뀐다(같은 run 인데 카드 3개 → 예전 KPI 4개).
  const lastTotal = metrics[metrics.length - 1];
  const hasGroups = (lastTotal.action_groups ?? []).length > 0;
  const groups = last.action_groups ?? [];
  const byGroup: Partial<Record<CleanupGroup, ActionGroupMetrics>> = {};
  for (const g of groups) byGroup[g.group] = g;
  // 카드 안의 부속 줄. 🔴 **각 숫자에 자기 단위를 붙인다** — 이 화면의 원래 결함이 "라벨에 단위가 없어
  // 아무도 action 과 대상을 구분하지 못한 것" 이었다. 0 인 항목은 줄을 만들지 않는다(없는 문제를 적으면
  // 세 카드가 다 같아 보여 카드끼리 무엇이 다른지가 사라진다).
  const cardLines = (key: CleanupGroup): string[] => {
    const m = byGroup[key];
    const out: string[] = [];
    if (!m) return out;
    if (m.items) out.push(`발견 ${m.items.toLocaleString()}건`);
    if (m.unused_actions) out.push(`미사용 action ${m.unused_actions.toLocaleString()}개`);
    if (m.wildcard_targets) out.push(`와일드카드 ${m.wildcard_targets.toLocaleString()}개 대상`);
    if (m.escalation_paths) out.push(`상승 경로 ${m.escalation_paths.toLocaleString()}건`);
    if (m.long_lived_keys) out.push(`장기 액세스키 ${m.long_lived_keys.toLocaleString()}건`);
    if (key === "needs_confirmation") {
      // 예전에 독립 KPI 였던 두 숫자. 카드를 만들면서 지우면 "신규 역할은 어디 갔나" 에 답할 수 없다 —
      // 둘 다 '확인 필요' 안에 있고, 사람이 할 일이 서로 다르다(기다린다 / 소유자에게 묻는다).
      if (last.new_unused_roles) out.push(`신규 역할 ${last.new_unused_roles.toLocaleString()}개(기다리면 판정)`);
      if (last.owner_review_roles) out.push(`소유자 확인 ${last.owner_review_roles.toLocaleString()}개`);
    }
    return out;
  };
  // 제외 집계. null = 이 필드가 없던 run → "0" 이라고 말하지 않는다(미수집과 0 은 다르다).
  const excl = last.exclusions;
  const excludedTargets = excl === undefined ? null : excl.reduce((n, e) => n + e.targets, 0);
  const excludedItems = (excl ?? []).reduce((n, e) => n + e.suppressed_items, 0);
  // 등급별 내역을 힌트에 요약한다. 등급이 다르면 고객이 할 일도 다르다 — `customer_declared` 는
  // 자기가 적은 패턴이 잘못 걸렸는지 봐야 하고, `aws_owned` 는 볼 필요가 없다.
  const exclusionBasisLine = (() => {
    const agg: Record<string, number> = {};
    for (const e of excl ?? []) agg[e.basis] = (agg[e.basis] ?? 0) + e.targets;
    const LABEL: Record<string, string> = {
      aws_owned: "AWS 소유", customer_declared: "고객이 선언한 패턴", judgment: "우리 판단",
    };
    const parts = Object.entries(agg).map(([b, n]) => `${LABEL[b] ?? b} ${n}개`);
    return parts.length ? `내역: ${parts.join(" · ")}.` : "";
  })();

  // 총 principal 수 = 최신 실행 위험등급 분포 합(critical+high+medium+low).
  const totalPrincipals =
    last.risk_dist.critical + last.risk_dist.high + last.risk_dist.medium + last.risk_dist.low;

  // X축: run_id(난수) 대신 실행 시각(KST) 라벨. 같은 분에 여러 run이면 뒤에 순번 붙여 중복 방지.
  const xLabels = (() => {
    const seen = new Map<string, number>();
    return scoped.map((m) => {
      let label = fmtKstShort(m.ts);
      const n = seen.get(label) ?? 0;
      seen.set(label, n + 1);
      return n > 0 ? `${label} (${n + 1})` : label;
    });
  })();
  const xDomain = xLabels;
  const mkSeries = (title: string, key: keyof MetricsPoint, color: string) => ({
    title,
    type: "line" as const,
    color,
    data: scoped.map((m, i) => ({ x: xLabels[i], y: m[key] as number })),
  });

  // 지표 **정의**가 바뀐 지점. 정의가 다른 run 끼리는 숫자를 직접 비교할 수 없다 → 차트 경계선.
  // 필드가 없던 run 은 정의 버전 1 로 읽는다(엔진 모델의 기본값과 같은 규칙) — 없는 것을 최신으로
  // 채우면 구 정의 숫자가 신 정의라고 주장해 경계선이 사라진다.
  // 🔴 **전부** 찾는다(사용자 피드백 2026-09-11). 예전에는 첫 변경에서 `return` 해 버려, 정의가
  //   두 번 바뀐 구간에서는 두 번째 경계가 화면에 없었다 — 경계가 없는 곳은 "비교해도 된다" 는
  //   뜻이므로, 빠진 경계선은 없는 것보다 나쁘다(사용자가 그 구간 숫자를 그대로 비교한다).
  const defBoundaries = (() => {
    const out: { label: string; from: number; to: number }[] = [];
    for (let i = 1; i < scoped.length; i++) {
      const prev = scoped[i - 1].definition_version ?? 1;
      const cur = scoped[i].definition_version ?? 1;
      if (cur !== prev) out.push({ label: xLabels[i], from: prev, to: cur });
    }
    return out;
  })();
  // 경계선 시리즈(추이 차트 공용). 정의 변경이 없으면 빈 배열이라 차트가 그대로다.
  // 🔴 범례에 `v1→v2` 를 쓰지 않는다: 정의 버전은 **우리 내부 번호**라 고객이 해석할 근거가 없다
  //   (사용자 피드백 2026-09-11). 대신 "어느 조회 시점부터 기준이 달라졌는가" 를 말한다 — 경계선은
  //   새 기준이 처음 적용된 조회에 그려지므로 문구와 위치가 같은 사실을 가리킨다.
  const defThreshold = defBoundaries.map((b) => ({
    title: `판정 기준 변경 (${b.label} 조회 시점부터)`,
    type: "threshold" as const,
    x: b.label,
  }));

  // 미사용 등급 분포(최신). `unused_roles`(=cleanup)만 보면 **곧 넘어올 것**(watch·review)이 안 보인다.
  const tierDist = last.unused_tier_dist;
  // 색은 CHART_SERIES 고정 순서로만 배정한다(CVD 안전성이 순서에 의존 — theme/tokens.ts).
  // 등급의 심각도를 색으로 말하려 하지 않는다: 상태색과 시리즈색을 섞지 않는 것이 팔레트 규칙이고,
  // 의미는 legend 라벨이 진다.
  //
  // 라벨 문구는 `lib/tierLabel.ts` 한 곳에서 만든다 — 예전에는 여기와 ServiceRoles 가 각자
  // `cleanup(90일 이상)` 처럼 **영문 계약값**을 범례에 노출했다(고객 어휘가 아니다).
  const TIER_VIEW: { key: keyof UnusedTierDist; label: string; color: string }[] = [
    { key: "active", label: tierLabel("active", tierDays), color: CHART_SERIES[0] },
    { key: "watch", label: tierLabel("watch", tierDays), color: CHART_SERIES[1] },
    { key: "review", label: tierLabel("review", tierDays), color: CHART_SERIES[2] },
    { key: "cleanup", label: tierLabel("cleanup", tierDays), color: CHART_SERIES[3] },
    { key: "new", label: tierLabel("new", tierDays), color: CHART_SERIES[4] },
    // 미측정을 0 이나 active 로 접으면 근거가 가장 없는 대상이 화면에서 사라진다.
    { key: "ungraded", label: tierLabel(null, tierDays), color: CHART_SERIES[5] },
  ];

  const riskData = [
    { level: "Critical", key: "critical" as const },
    { level: "High", key: "high" as const },
    { level: "Medium", key: "medium" as const },
    { level: "Low", key: "low" as const },
  ];

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description={`${selected ? `계정 ${selected}` : "전체 계정"} · 최신 실행 ${last.run_id} · principal ${totalPrincipals.toLocaleString()} · 예약: ${schedule ? scheduleSummary(schedule) : "…"}`}
          actions={headerActions}
        >
          대시보드
        </Header>
      }
    >
      <SpaceBetween size="l">
        {running && (
          <Flashbar items={[{ type: "in-progress", header: "전체 조회 실행 중", content: "대상 계정을 읽기 전용으로 수집·분석하고 있습니다. 계정·자원 수에 따라 수 분 걸립니다 — 완료되면 이 화면이 자동으로 갱신됩니다.", loading: true }]} />
        )}
        {note && (
          <Flashbar items={[{ type: "success", header: "완료", content: note, dismissible: true, onDismiss: () => setNote(null) }]} />
        )}
        {runErr && (
          <Flashbar items={[{ type: "error", header: "전체 조회", content: runErr, dismissible: true, onDismiss: () => setRunErr(null) }]} />
        )}
        {/* 🔴 정의 변경 배너는 **없다**(사용자 피드백 2026-09-11 F1). 대시보드 최상단은 이 도구를
            처음 여는 사람이 보는 자리인데, 배너는 우리 내부 정의 버전 이야기를 첫 문장으로 만들었다.
            같은 사실은 추이 차트의 경계선(`defThreshold`, 전 경계 표시)이 **그 숫자 옆에서** 말한다 —
            비교가 성립하지 않는다는 경고는 비교하는 자리에 있어야 한다. */}
        {/* 🔴 조치 묶음 3카드 — **조치 화면과 같은 분류**다. 예전에는 이 자리에 '미사용 권한 /
            미사용 역할 / 신규 역할 / 와일드카드 보유' 4개가 있었는데, (i) 큰 숫자의 단위가 서로 달랐고
            (미사용 권한=action, 나머지=대상) (ii) 눌러서 열린 목록의 행 수와도 달랐고 (iii) 같은 역할이
            여러 카드에 동시에 세어졌다. 잃은 숫자는 없다 — 카드 안의 부속 줄로 내려왔다.
            action_groups 가 없던 시절의 run 을 고객이 선택하면 예전 KPI 를 그린다(0 을 채워 "할 일이
            없다" 는 거짓을 말하지 않는다). */}
        {hasGroups ? (
          // 🔴 카드 아래의 단위 설명 문단을 없앴다(사용자 피드백 2026-09-11 F2). 그 문단이 막으려던
          //   결함 #6(KPI 는 action 을, 목록은 principal 을 세던 사건)은 **숫자를 대상 수로 통일**해서
          //   이미 닫혀 있고, 단위는 큰 숫자 바로 옆의 `개 대상`(ActionCard, 위)이 진다 — 같은 사실을
          //   두 번 말하지 않는다. 단위 라벨은 지우지 말 것: 그것까지 없애면 #6 이 되돌아온다.
          <Grid gridDefinition={[{ colspan: 4 }, { colspan: 4 }, { colspan: 4 }]}>
            {GROUP_VIEW.map((g) => (
              <ActionCard
                key={g.key}
                label={g.label}
                desc={g.desc}
                targets={byGroup[g.key]?.targets ?? 0}
                lines={cardLines(g.key)}
                onClick={() => navigate(`/cleanup?group=${g.key}`)}
              />
            ))}
          </Grid>
        ) : (
          <Grid gridDefinition={[{ colspan: 4 }, { colspan: 4 }, { colspan: 4 }, { colspan: 4 }]}>
            <Kpi label="미사용 권한" value={last.unused_permissions.toLocaleString()} hint="이 실행에는 조치 묶음 집계가 없어 예전 지표를 표시합니다. 단위는 action 수입니다(대상 수가 아닙니다)." onClick={() => navigate("/cleanup?type=unused_permission")} />
            {/* 🔴 이 숫자와 백로그 `미사용 역할` 건수는 **같지 않다**: 신뢰 대상을 우리 테넌트로 확인할
                수 없는 몫(owner_review_roles)은 삭제 권고를 하지 않고 '외부 연동 의심' 유형으로 빠진다.
                어긋난 이유를 화면에 적지 않으면 "대시보드 40 vs 백로그 59" 를 데이터 결함으로 읽는다
                (이 프로젝트에서 실제로 일어났다). 산술을 KPI 힌트에 그대로 쓴다. */}
            <Kpi
              label="미사용 역할"
              value={String(last.unused_roles)}
              hint={
                (last.owner_review_roles ?? 0) > 0
                  ? `이 중 ${last.owner_review_roles}개는 신뢰 대상을 우리 테넌트로 확인할 수 없어 삭제 권고 대상이 아닙니다 — 조치 항목에서는 '외부 연동 의심' 유형으로 분리되고, '미사용 역할' 목록은 ${last.unused_roles - (last.owner_review_roles ?? 0)}건입니다.`
                  : undefined
              }
              onClick={() => navigate("/cleanup?type=unused_role")}
            />
            <Kpi
              label="신규 역할(판정 보류)"
              value={String(last.new_unused_roles ?? 0)}
              hint="생성 후 경과일이 짧아 '미사용' 으로 판정하지 않은 역할입니다(삭제 후보 아님)"
              onClick={() => navigate("/cleanup?type=new_role_unused")}
            />
            {/* 와일드카드 보유자는 미사용 개수가 0 으로 잡혀 위의 어느 숫자에도 기여하지 못한다 —
                이 카드가 없으면 가장 위험한 대상이 대시보드에서 사라진다(R4). */}
            <Kpi
              label="와일드카드 보유"
              value={String(last.wildcard_grant_principals ?? 0)}
              hint="전 권한(`*`)을 가진 대상 수. 이들은 부여 범위에 상한이 없어 '미사용 권한 개수' 를 셀 수 없습니다 — 0 이 아니라 산정 불가입니다."
              onClick={() => navigate("/cleanup?type=wildcard_grant")}
            />
          </Grid>
        )}
        <Grid gridDefinition={[{ colspan: 4 }, { colspan: 4 }, { colspan: 4 }]}>
          {/* PS 전환율은 IdC 가 있어야 의미가 있다. IdC 미사용 배포에서는 분자(sso_ps)가 구조적으로
              0 이라 항상 0% 로 보이는데, 그건 "전환이 안 되고 있다" 가 아니라 "해당 없음" 이다.
              달성 불가한 목표를 KPI 로 띄우지 않는다. */}
          {/* 🔴 0% 의 중의성을 가른다(F5-1). `ps_migration_pct` = `sso_ps / (user + sso_ps)` 이므로
              분모가 0(사람 접근이 아예 없음)이어도 0% 가 나온다 — "전부 IAM User 다"(할 일 있음)와
              "사람 접근이 없다"(할 일 없음)가 같은 숫자로 보였다. 두 필드로 분모 0 을 판별할 수 있다:
              `iam_users_pending_migration == 0` 이고 0% 라면 `sso_ps` 도 0 이다(sso_ps>0 이면 100%).
              #12 에서 등급의 `미측정`/`0` 을 가른 것과 같은 이유다. */}
          {!usesIdc ? (
            <Kpi label="PS 마이그레이션" value="해당 없음" hint="Identity Center 를 사용하지 않는 배포입니다" />
          ) : last.ps_migration_pct === 0 && (last.iam_users_pending_migration ?? 0) === 0 ? (
            <Kpi label="PS 마이그레이션" value="해당 없음" hint="이 범위에는 IAM User 도 Permission Set 도 없습니다 — 옮길 대상이 없어 0% 가 아닙니다." />
          ) : (
            <Kpi label="PS 마이그레이션" value={`${last.ps_migration_pct}%`} hint="현재 스냅샷 비율입니다(Permission Set ÷ (IAM User + Permission Set)) — 'User 를 지우고 옮긴 이력' 이 아닙니다." />
          )}
          {/* 트랙② 1층 — 숫자 하나(사람이 판단할 **서비스 수**). **권한 수가 아니다**: 기계 역할의
              부여 권한을 하나씩 세면 수만 개가 나오고 그 숫자로는 아무도 아무것도 못 한다(R7).
              '권한 축소' 카드의 하위 목적지이므로 카드 옆이 아니라 아래 줄에 둔다.
              🔴 값은 목록의 `판단 필요 서비스` 합계다(F15-2 로 keep 서비스 수만 센다 — 예전에는
              역할마다 "일괄 제거" 1건이 더해져 서비스 수와 작업 수가 한 숫자에 섞여 있었다). */}
          <Kpi
            label="서비스 역할 판단 필요 서비스"
            value={svcDecisions === null ? "—" : svcDecisions.toLocaleString()}
            hint={
              svcDecisions === null
                ? "트랙② 산출물을 읽지 못했습니다 — 0 이 아니라 미확인입니다."
                : `기계가 쓰는 현역 역할 ${svcTargets.toLocaleString()}개에서 사람이 유지/축소를 판단할 서비스 수입니다(권한 수가 아닙니다).`
            }
            onClick={() => navigate("/service-roles")}
          />
          {/* 제외한 대상도 숫자로 남긴다. 조용히 빼면 "왜 우리 역할이 목록에 없지?" 에 답할 수 없다(R6).
              0 건이어도 카드를 지우지 않는다 — 있다가 없어지면 "제외가 없다" 가 아니라 "이 화면이 제외를
              말하지 않는다" 로 읽힌다. */}
          <Kpi
            label="조치 목록 제외"
            value={excludedTargets === null ? "—" : excludedTargets.toLocaleString()}
            hint={
              excludedTargets === null
                ? "이 실행에는 제외 집계가 없습니다 — 0 이 아니라 미수집입니다."
                : `조치 대상이 아니라고 판단해 목록에 올리지 않은 대상 수입니다(권고 ${excludedItems.toLocaleString()}건 숨김). ${exclusionBasisLine} 조치 항목 화면 맨 아래에서 사유별로 펼쳐 볼 수 있습니다.`
            }
            onClick={() => navigate("/cleanup")}
          />
        </Grid>

        {/* 미사용 등급 분포 — cleanup(=삭제 후보) 하나만 KPI 로 보면 30·60일을 지나 곧 넘어올 것이
            안 보인다. 등급별 행동이 다르므로(관찰/검토/삭제/보류/미측정) 한 숫자로 합치지 않는다. */}
        <Container
          header={
            <Header
              variant="h2"
              description={`역할을 마지막 사용 이후 경과일로 나눈 분포입니다. ${cleanupDays(tierDays)}일 이상 미사용만 삭제 검토 후보이고, 신규는 관측 기간이 짧아 판정을 보류한 것, 미측정은 경과일을 셀 근거 자체가 없는 것입니다(0 이 아닙니다).`}
            >
              미사용 등급 분포 (최신)
            </Header>
          }
        >
          {tierDist ? (
            <BarChart
              series={TIER_VIEW.map((t) => ({
                title: `${t.label} · ${tierDist[t.key].toLocaleString()}`,
                type: "bar" as const,
                color: t.color,
                data: [{ x: "역할", y: tierDist[t.key] }],
              }))}
              xDomain={["역할"]}
              yTitle="역할 수"
              height={180}
              stackedBars
              horizontalBars
              hideFilter
              statusType="finished"
            />
          ) : (
            // 등급을 안 실은 구 run 을 0 으로 그리면 "전부 active" 라고 주장한다.
            <Box color="text-status-inactive" padding={{ vertical: "m" }}>
              이 실행에는 등급 분포가 없습니다(지표를 싣기 전 실행). 다음 전체 조회부터 표시됩니다.
            </Box>
          )}
        </Container>

        <Grid gridDefinition={[{ colspan: 8 }, { colspan: 4 }]}>
          <Container header={<Header variant="h2">미사용 권한 · 상승 경로 추이</Header>}>
            <LineChart
              series={[
                mkSeries("미사용 권한", "unused_permissions", CHART_SERIES[0]),
                // 판정 불가를 같이 그리지 않으면 근거 배선이 좋아져 미사용 수가 줄어든 것을
                // "정리됐다" 로 읽는다(엔진에서 실제로 1,658행이 그 자리에 있었다).
                mkSeries("판정 불가 권한", "undetermined_permissions", CHART_SERIES[2]),
                mkSeries("과다권한 principal", "over_privileged_principals", CHART_SERIES[1]),
                mkSeries("상승 경로", "escalation_paths", CHART_SERIES[4]),
                ...defThreshold,
              ]}
              xScaleType="categorical"
              xDomain={xDomain}
              xTitle="실행"
              yTitle="건수"
              height={240}
              hideFilter
              statusType="finished"
            />
          </Container>

          <Container header={<Header variant="h2">위험 등급 분포 (최신)</Header>}>
            <BarChart
              series={riskData.map((r) => ({
                title: r.level,
                type: "bar" as const,
                color: RISK_COLOR[r.key],
                data: [{ x: "principal", y: last.risk_dist[r.key] }],
              }))}
              xDomain={["principal"]}
              yTitle="principal 수"
              height={240}
              stackedBars
              hideFilter
              statusType="finished"
            />
          </Container>
        </Grid>

        {/* IdC 미사용 배포에서는 'PS 전환율' 시리즈가 항상 0 인 직선이라 차트를 읽는 사람을
            오해시킨다(전환이 정체된 것처럼 보인다). IAM User 수는 그 고객에게도 의미가 있으므로
            (임시 자격증명 전환 대상) 그 시리즈만 남기고 제목을 바꾼다. */}
        <Container
          header={
            <Header
              variant="h2"
              description={usesIdc ? undefined : "Identity Center 를 사용하지 않는 배포이므로 PS 전환율은 표시하지 않습니다. IAM User 는 IAM Role 임시 자격증명으로 전환할 대상입니다."}
            >
              {usesIdc ? "IAM User → Permission Set 마이그레이션" : "IAM User 추이"}
            </Header>
          }
        >
          <LineChart
            series={[
              ...(usesIdc ? [mkSeries("PS 전환율(%)", "ps_migration_pct", CHART_SERIES[3])] : []),
              // 🔴 이름이 판정을 주장하지 않게 했다(사용자 피드백 2026-09-11 F5-2). 이 값은
              //   `identity_type == "user"` 인 principal **전부**이고, 그중에는 서비스 계정처럼
              //   Permission Set 으로 옮길 수 없는 것도 섞여 있다 — "마이그레이션 대기" 는 우리가
              //   하지 않은 판정을 말한다. 세는 것을 그대로 부른다.
              mkSeries("IAM User 수", "iam_users_pending_migration", CHART_SERIES[2]),
              ...defThreshold,
            ]}
            xScaleType="categorical"
            xDomain={xDomain}
            xTitle="실행"
            yTitle="값"
            height={220}
            hideFilter
            statusType="finished"
          />
        </Container>
      </SpaceBetween>

      {/* 예약(스케줄) 설정 모달 */}
      <Modal
        visible={scheduleOpen}
        onDismiss={() => setScheduleOpen(false)}
        header="전체 조회 실행 예약"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setScheduleOpen(false)}>취소</Button>
              <Button variant="primary" loading={saving} onClick={saveSchedule}>저장</Button>
            </SpaceBetween>
          </Box>
        }
      >
        {draft && (() => {
          // draft 는 UTC 로 저장 — 모달은 KST 로 표시/편집하고, 변경 시 UTC 로 되돌려 저장.
          const kst = toKstView(draft);
          return (
          <SpaceBetween size="m">
            <Box color="text-body-secondary">
              대상 계정을 읽기 전용으로 주기 수집·분석합니다. 시각은 <b>KST(한국 시간)</b> 기준입니다.
            </Box>
            <Toggle checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.detail.checked })}>
              예약 활성화
            </Toggle>

            <FormField label="빈도">
              <Select
                selectedOption={FREQ_OPTIONS.find((o) => o.value === draft.frequency) ?? null}
                onChange={(e) => setDraft({ ...draft, frequency: e.detail.selectedOption.value as ScheduleState["frequency"] })}
                options={FREQ_OPTIONS}
                disabled={!draft.enabled}
                // `custom`(직접 만든 규칙)은 옵션에 없으므로 선택값이 비어 있다 → 빈 Select 가 아니라
                // 골라야 한다는 것을 말한다.
                placeholder="빈도 선택"
              />
            </FormField>

            <FormField label="실행 시각(KST)">
              <Select
                selectedOption={HOUR_OPTIONS.find((o) => o.value === String(kst.hourKst)) ?? null}
                onChange={(e) => setDraft(fromKstView(draft, Number(e.detail.selectedOption.value), kst.dowKst, kst.domKst))}
                options={HOUR_OPTIONS}
                disabled={!draft.enabled}
                virtualScroll
              />
            </FormField>

            {draft.frequency === "weekly" && (
              <FormField label="요일(KST)">
                <Select
                  selectedOption={DOW_OPTIONS.find((o) => o.value === String(kst.dowKst)) ?? null}
                  onChange={(e) => setDraft(fromKstView(draft, kst.hourKst, Number(e.detail.selectedOption.value), kst.domKst))}
                  options={DOW_OPTIONS}
                  disabled={!draft.enabled}
                />
              </FormField>
            )}

            {draft.frequency === "monthly" && (
              <FormField label="날짜(KST, 1–28)" description="월말 편차를 피하려고 28일까지만 지원합니다.">
                <Select
                  selectedOption={{ value: String(kst.domKst), label: `${kst.domKst}일` }}
                  onChange={(e) => setDraft(fromKstView(draft, kst.hourKst, kst.dowKst, Number(e.detail.selectedOption.value)))}
                  options={Array.from({ length: 28 }, (_, i) => ({ value: String(i + 1), label: `${i + 1}일` }))}
                  disabled={!draft.enabled}
                  virtualScroll
                />
              </FormField>
            )}

            {/* 손으로 만든 EventBridge 규칙이 이미 있는 경우 — 프리셋으로 되돌릴 수 없다. cron 원문을
                다시 보여 주지 않고, **저장하면 대체된다는 사실**만 알린다(모르고 덮으면 사고다). */}
            {draft.frequency === "custom" && (
              <Alert type="warning" header="직접 만든 일정이 설정돼 있습니다">
                이 예약은 화면의 빈도 프리셋으로 표현할 수 없는 EventBridge 규칙입니다. 위에서 빈도를
                고르고 저장하면 <b>기존 규칙이 대체됩니다.</b> 그대로 두려면 저장하지 말고 닫으세요.
              </Alert>
            )}

            <StatusIndicator type={draft.enabled ? "info" : "stopped"}>
              {draft.enabled ? `예정: ${scheduleSummary({ ...draft, cron: draft.cron })}` : "비활성 — 자동 실행 안 함"}
            </StatusIndicator>
            {scheduleErr && <StatusIndicator type="error">{scheduleErr}</StatusIndicator>}
          </SpaceBetween>
          );
        })()}
      </Modal>
    </ContentLayout>
  );
}
