import { useState } from "react";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import Table from "@cloudscape-design/components/table";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import Spinner from "@cloudscape-design/components/spinner";
import SpaceBetween from "@cloudscape-design/components/space-between";
import ExpandableSection from "@cloudscape-design/components/expandable-section";
import { api } from "@/api/client";
import { useAsync } from "@/api/useAsync";
import type { Run, RunStatus, RunSources } from "@/api/types";

function runStatus(s: RunStatus) {
  const map: Record<RunStatus, { type: "success" | "in-progress" | "error" | "warning"; label: string }> = {
    succeeded: { type: "success", label: "성공" },
    running: { type: "in-progress", label: "실행 중" },
    failed: { type: "error", label: "실패" },
    degraded: { type: "warning", label: "부분 성공(degraded)" },
  };
  const m = map[s];
  return <StatusIndicator type={m.type}>{m.label}</StatusIndicator>;
}

// 소스 수집 상태 배지 — skipped 는 "정상(대체됨)"임을 명확히.
function sourceStatus(s: string) {
  if (s === "ok") return <StatusIndicator type="success">수집됨(ok)</StatusIndicator>;
  if (s === "degraded") return <StatusIndicator type="warning">부분 수집(degraded)</StatusIndicator>;
  if (s === "skipped") return <StatusIndicator type="info">해당 없음(skipped·정상)</StatusIndicator>;
  return <StatusIndicator type="stopped">{s}</StatusIndicator>;
}

// 상태 한 줄 사유 — 왜 이 run 이 이 상태인지.
function statusReason(r: Run, det?: RunSources): string {
  if (r.status === "running") return "실행 중입니다.";
  if (r.status === "failed") return "실행이 실패했습니다.";
  const deg = det?.status_summary?.degraded_sources ?? [];
  const skip = det?.status_summary?.skipped_sources ?? [];
  if (r.status === "degraded") {
    return deg.length
      ? `부분 수집된 소스: ${deg.join(", ")} — 사용 실태가 실제보다 과소평가될 수 있습니다(행을 펼쳐 사유 확인).`
      : "일부 소스가 부분 수집(degraded)되었습니다. 행을 펼쳐 사유를 확인하세요.";
  }
  // succeeded — skipped 가 있으면 "정상(대체됨)" 임을 안내.
  return skip.length
    ? `모든 필수 소스 수집 완료. 선택적 소스(${skip.join(", ")})는 미존재라 건너뜀 — Access Advisor 등으로 대체되어 정상입니다.`
    : "모든 소스가 정상 수집되었습니다.";
}

// 행 확장 내용 — 소스별 상태·사유(계정별).
function RunDetail({ run }: { run: Run }) {
  const { data, loading } = useAsync<RunSources>(() => api.getRunSources(run.run_id));
  if (loading || !data) return <Box padding="s"><Spinner /> 소스 상태 불러오는 중…</Box>;
  return (
    <SpaceBetween size="s">
      <Box variant="p" color="text-body-secondary">{statusReason(run, data)}</Box>
      {data.accounts.map((a) => (
        <ExpandableSection
          key={a.account_id}
          defaultExpanded={data.accounts.length === 1}
          headerText={`계정 ${a.account_id}`}
          variant="footer"
        >
          <Table
            variant="embedded"
            columnDefinitions={[
              { id: "source", header: "데이터 소스", cell: (s) => <Box fontWeight="bold">{s.source}</Box> },
              { id: "status", header: "상태", cell: (s) => sourceStatus(s.status) },
              { id: "note", header: "사유 / 비고", cell: (s) => s.note || "—" },
            ]}
            items={a.sources}
          />
        </ExpandableSection>
      ))}
    </SpaceBetween>
  );
}

export default function Runs() {
  const { data, loading, reload } = useAsync<Run[]>(() => api.listRuns());
  const [starting, setStarting] = useState(false);
  const [extra, setExtra] = useState<Run[]>([]);
  const [expanded, setExpanded] = useState<Run[]>([]);

  async function startRun() {
    setStarting(true);
    const run = await api.startRun();
    setExtra((e) => [run, ...e]);
    setStarting(false);
  }

  const isOpen = (r: Run) => expanded.some((e) => e.run_id === r.run_id);
  const toggle = (r: Run) =>
    setExpanded((prev) => (isOpen(r) ? prev.filter((e) => e.run_id !== r.run_id) : [...prev, r]));

  if (loading || !data) {
    return <Box padding="xxl" textAlign="center"><Spinner size="large" /></Box>;
  }

  const items = [...extra, ...data];

  return (
    <ContentLayout header={<Header variant="h1" description="수집→분석→합성→리포트 파이프라인 실행 이력. 행을 펼치면 소스별 수집 상태·사유가 나옵니다.">실행 이력</Header>}>
      <Table
        variant="container"
        header={
          <Header
            variant="h2"
            counter={`(${items.length})`}
            actions={
              <Button variant="primary" loading={starting} iconName="add-plus" onClick={startRun}>
                새 실행
              </Button>
            }
          >
            실행 목록
          </Header>
        }
        columnDefinitions={[
          { id: "run_id", header: "실행 ID", cell: (r: Run) => <Box fontWeight="bold">{r.run_id}</Box> },
          { id: "started", header: "시작 시각(KST)", cell: (r: Run) => new Date(r.started_at).toLocaleString("ko-KR", { timeZone: "Asia/Seoul" }) },
          { id: "scope", header: "계정 수", cell: (r: Run) => r.account_scope },
          { id: "status", header: "상태", cell: (r: Run) => runStatus(r.status) },
          {
            id: "detail",
            header: "상태 근거",
            cell: (r: Run) =>
              r.status === "running" ? (
                "—"
              ) : (
                <Button
                  variant="inline-link"
                  iconName={isOpen(r) ? "treeview-collapse" : "treeview-expand"}
                  onClick={() => toggle(r)}
                >
                  {isOpen(r) ? "상세 닫기" : "상세 보기"}
                </Button>
              ),
          },
          { id: "action", header: "", cell: () => <Button onClick={reload}>새로고침</Button> },
        ]}
        items={items}
        trackBy="run_id"
      />
      {/* 펼친 run 들의 소스별 수집 상태·사유(왜 이 상태인지의 근거). */}
      {expanded.length > 0 && (
        <SpaceBetween size="l">
          {expanded.map((r) => (
            <ExpandableSection key={r.run_id} defaultExpanded variant="container" headerText={`실행 ${r.run_id} · 소스별 수집 상태`}>
              <RunDetail run={r} />
            </ExpandableSection>
          ))}
        </SpaceBetween>
      )}
    </ContentLayout>
  );
}
