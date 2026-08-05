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
import { api } from "@/api/client";
import { useAsync } from "@/api/useAsync";
import { useAccounts } from "@/AccountContext";
import { CHART_SERIES, RISK_COLOR } from "@/theme/tokens";
import type { MetricsPoint, ScheduleState, AiSettings } from "@/api/types";

// run 의 total MetricsPoint 에서 선택 계정 뷰를 뽑는다. 전체("")면 total 그대로,
// 특정 계정이면 by_account 에서 매칭(없으면 0 이 담긴 빈 포인트).
function scopeMetric(m: MetricsPoint, account: string): MetricsPoint {
  if (!account) return m;
  const found = m.by_account?.find((b) => b.account_id === account);
  return found ?? { ...m, by_account: [], account_id: account,
    unused_permissions: 0, unused_roles: 0, long_lived_keys: 0, no_mfa: 0,
    over_privileged_principals: 0, escalation_paths: 0, iam_users_pending_migration: 0,
    ps_migration_pct: 0, risk_dist: { critical: 0, high: 0, medium: 0, low: 0 } };
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
const FREQ_OPTIONS = [
  { value: "daily", label: "매일" },
  { value: "weekly", label: "매주" },
  { value: "monthly", label: "매월" },
  { value: "custom", label: "직접 입력(cron)" },
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
  return `cron(${s.cron}) · UTC`;
}

// 현황 KPI 카드 — 현재 값만 표시. onClick 이 있으면 클릭 가능(조치 필요 항목으로 딥링크).
function Kpi({ label, value, onClick }: { label: string; value: string; onClick?: () => void }) {
  const inner = (
    <SpaceBetween size="xs">
      <Box variant="awsui-key-label">{label}</Box>
      <Box fontSize="display-l" fontWeight="bold">{value}</Box>
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

export default function Dashboard() {
  const navigate = useNavigate();
  const { selected } = useAccounts();
  const { data: metrics, loading, reload } = useAsync<MetricsPoint[]>(() => api.getMetrics());
  const [running, setRunning] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  // 예약(스케줄) 상태 + 편집 모달.
  const [schedule, setSchedule] = useState<ScheduleState | null>(null);
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const [draft, setDraft] = useState<ScheduleState | null>(null);
  const [saving, setSaving] = useState(false);
  const [scheduleErr, setScheduleErr] = useState<string | null>(null);

  // AI 개입 기능 런타임 토글(비용 통제 — 대시보드에서 즉시 on/off).
  const [ai, setAi] = useState<AiSettings | null>(null);
  const [aiSaving, setAiSaving] = useState(false);

  useEffect(() => {
    api.getSchedule().then(setSchedule).catch(() => setSchedule(null));
    api.getAiSettings().then(setAi).catch(() => setAi({ enabled: false }));
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

  // "전체 조회 실행": 파이프라인 run 트리거 → 완료 시 지표 갱신.
  async function runScan() {
    setRunning(true);
    setNote(null);
    await api.startRun(); // POST /runs
    // 실제로는 Step Functions 완료를 폴링. mock 은 지연 후 최신 지표 재조회.
    await new Promise((r) => setTimeout(r, 1600));
    reload();
    setRunning(false);
    setNote("전체 조회가 완료되어 대시보드를 갱신했습니다.");
  }

  if (loading || !metrics) {
    return <Box padding="xxl" textAlign="center"><Spinner size="large" /></Box>;
  }

  // 선택 계정으로 각 run 지표를 스코프(전체=그대로, 특정 계정=by_account 뷰).
  const scoped = metrics.map((m) => scopeMetric(m, selected));
  const last = scoped[scoped.length - 1];
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
          actions={
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
          }
        >
          대시보드
        </Header>
      }
    >
      <SpaceBetween size="l">
        {running && (
          <Flashbar items={[{ type: "in-progress", header: "전체 조회 실행 중", content: "대상 계정을 읽기 전용으로 수집·분석하고 있습니다…", loading: true }]} />
        )}
        {note && (
          <Flashbar items={[{ type: "success", header: "완료", content: note, dismissible: true, onDismiss: () => setNote(null) }]} />
        )}
        <Grid gridDefinition={[{ colspan: 3 }, { colspan: 3 }, { colspan: 3 }, { colspan: 3 }]}>
          <Kpi label="미사용 권한" value={last.unused_permissions.toLocaleString()} onClick={() => navigate("/cleanup?type=unused_permission")} />
          <Kpi label="미사용 역할" value={String(last.unused_roles)} onClick={() => navigate("/cleanup?type=unused_role")} />
          <Kpi label="장기 액세스키" value={String(last.long_lived_keys)} onClick={() => navigate("/cleanup?type=long_lived_key")} />
          <Kpi label="PS 마이그레이션" value={`${last.ps_migration_pct}%`} />
        </Grid>

        <Grid gridDefinition={[{ colspan: 8 }, { colspan: 4 }]}>
          <Container header={<Header variant="h2">미사용 권한 · 상승 경로 추이</Header>}>
            <LineChart
              series={[
                mkSeries("미사용 권한", "unused_permissions", CHART_SERIES[0]),
                mkSeries("과다권한 principal", "over_privileged_principals", CHART_SERIES[1]),
                mkSeries("상승 경로", "escalation_paths", CHART_SERIES[4]),
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

        <Container header={<Header variant="h2">IAM User → Permission Set 마이그레이션</Header>}>
          <LineChart
            series={[
              mkSeries("PS 전환율(%)", "ps_migration_pct", CHART_SERIES[3]),
              mkSeries("마이그레이션 대기 IAM User", "iam_users_pending_migration", CHART_SERIES[2]),
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
              />
            </FormField>

            {draft.frequency !== "custom" && (
              <FormField label="실행 시각(KST)">
                <Select
                  selectedOption={HOUR_OPTIONS.find((o) => o.value === String(kst.hourKst)) ?? null}
                  onChange={(e) => setDraft(fromKstView(draft, Number(e.detail.selectedOption.value), kst.dowKst, kst.domKst))}
                  options={HOUR_OPTIONS}
                  disabled={!draft.enabled}
                  virtualScroll
                />
              </FormField>
            )}

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

            {draft.frequency === "custom" && (
              <FormField label="cron 식(6필드)" description="EventBridge 형식: 분 시 일 월 요일 연 (예: 0 2 * * ? *)">
                <input
                  style={{ width: "100%", padding: "6px 8px", fontFamily: "Monaco, Menlo, monospace" }}
                  value={draft.cron}
                  disabled={!draft.enabled}
                  onChange={(e) => setDraft({ ...draft, cron: e.target.value })}
                />
              </FormField>
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
