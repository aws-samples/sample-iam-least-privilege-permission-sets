import { useState, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import Cards from "@cloudscape-design/components/cards";
import Table from "@cloudscape-design/components/table";
import Box from "@cloudscape-design/components/box";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Button from "@cloudscape-design/components/button";
import Modal from "@cloudscape-design/components/modal";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import Spinner from "@cloudscape-design/components/spinner";
import Badge from "@cloudscape-design/components/badge";
import Link from "@cloudscape-design/components/link";
import BreadcrumbGroup from "@cloudscape-design/components/breadcrumb-group";
import Popover from "@cloudscape-design/components/popover";
import ExpandableSection from "@cloudscape-design/components/expandable-section";
import Alert from "@cloudscape-design/components/alert";
import Container from "@cloudscape-design/components/container";
import KeyValuePairs from "@cloudscape-design/components/key-value-pairs";
import { api } from "@/api/client";
import { useAsync } from "@/api/useAsync";
import { useAccounts } from "@/AccountContext";
import { RISK_INDICATOR } from "@/theme/tokens";
import type { CleanupItem, CleanupType, RiskCriteria, RiskLevel } from "@/api/types";

// 페이지 제목/메뉴명(구 '정리 백로그').
const PAGE_TITLE = "조치 필요 항목";

const TYPE_LABEL: Record<CleanupType, string> = {
  unused_permission: "미사용 권한",
  unused_role: "미사용 역할",
  long_lived_key: "장기 액세스키",
  no_mfa: "MFA 미설정",
  escalation_path: "상승 경로",
};

const RISK_ORDER: Record<RiskLevel, number> = { critical: 0, high: 1, medium: 2, low: 3 };

// 레벨별 한 줄 의미(기준 패널·팝오버 공통).
const LEVEL_MEANING: Record<RiskLevel, string> = {
  critical: "즉시 조치 — 침해 시 피해가 가장 큼",
  high: "우선 조치 — 유의미한 노출",
  medium: "계획된 정리 대상",
  low: "낮은 우선순위",
};

// 위험도 → 상세 모달 상단 배너 타입(색으로 심각도 즉시 인지).
const LEVEL_ALERT: Record<RiskLevel, "error" | "warning" | "info" | "success"> = {
  critical: "error",
  high: "warning",
  medium: "info",
  low: "success",
};

// 위험도 배지 + "왜 이 레벨인지"(점수·근거) 팝오버. 운영자가 즉시 위험을 인지하도록.
function RiskCell({ item, criteria }: { item: CleanupItem; criteria: RiskCriteria | null }) {
  const indicator = <StatusIndicator type={RISK_INDICATOR[item.risk_level]}>{item.risk_level}</StatusIndicator>;
  const boundary = criteria
    ? item.risk_level === "critical" ? `${criteria.level_critical}점 이상`
      : item.risk_level === "high" ? `${criteria.level_high}~${criteria.level_critical - 1}점`
      : item.risk_level === "medium" ? `${criteria.level_medium}~${criteria.level_high - 1}점`
      : `${criteria.level_medium}점 미만`
    : "";
  return (
    <Popover
      dismissButton={false}
      position="top"
      size="medium"
      triggerType="custom"
      header={`위험도 ${item.risk_level} · ${item.risk_score}점`}
      content={
        <SpaceBetween size="xs">
          <Box>{LEVEL_MEANING[item.risk_level]}{boundary ? ` (${boundary})` : ""}</Box>
          <Box variant="awsui-key-label">근거</Box>
          {item.risk_reasons.length ? (
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {item.risk_reasons.map((r, i) => <li key={i}>{r}</li>)}
            </ul>
          ) : (
            <Box color="text-status-inactive">개별 근거 없음(유형 기본 위험도).</Box>
          )}
        </SpaceBetween>
      }
    >
      <span style={{ cursor: "pointer", borderBottom: "1px dashed currentColor", whiteSpace: "nowrap", display: "inline-block" }}>{indicator}</span>
    </Popover>
  );
}

// 위험도 산정 기준 설명 패널(카테고리 화면 상단). 점수=규칙 가중치 합, 레벨=경계.
function RiskCriteriaPanel({ criteria }: { criteria: RiskCriteria | null }) {
  if (!criteria) return null;
  return (
    <ExpandableSection
      variant="container"
      headerText="위험도 산정 기준"
      headerDescription="점수 = 아래 규칙 중 해당하는 항목의 가중치 합(0–100). 레벨은 점수 구간으로 결정됩니다."
    >
      <SpaceBetween size="m">
        <SpaceBetween direction="horizontal" size="l">
          <Box><StatusIndicator type={RISK_INDICATOR.critical}>critical</StatusIndicator> {criteria.level_critical}점 이상 — {LEVEL_MEANING.critical}</Box>
        </SpaceBetween>
        <SpaceBetween direction="horizontal" size="l">
          <Box><StatusIndicator type={RISK_INDICATOR.high}>high</StatusIndicator> {criteria.level_high}–{criteria.level_critical - 1}점 — {LEVEL_MEANING.high}</Box>
        </SpaceBetween>
        <SpaceBetween direction="horizontal" size="l">
          <Box><StatusIndicator type={RISK_INDICATOR.medium}>medium</StatusIndicator> {criteria.level_medium}–{criteria.level_high - 1}점</Box>
          <Box><StatusIndicator type={RISK_INDICATOR.low}>low</StatusIndicator> {criteria.level_medium}점 미만</Box>
        </SpaceBetween>
        <Table
          variant="embedded"
          contentDensity="compact"
          columnDefinitions={[
            { id: "rule", header: "위험 요인", cell: (r) => r.label },
            { id: "weight", header: "가중치", width: 90, cell: (r) => `+${r.weight}` },
            { id: "detail", header: "판정 기준", cell: (r) => r.detail },
          ]}
          items={criteria.rules}
        />
      </SpaceBetween>
    </ExpandableSection>
  );
}

// CSV formula injection 무력화. 셀 앞글자가 = + - @ tab CR LF 이면 ' 프리픽스로
// 스프레드시트가 수식으로 해석하지 못하게 한다. 엔진 m6_reporter._csv_safe(_CSV_INJECT_RE)와 동일 규칙.
function csvSafe(s: string): string {
  return /^[=+\-@\t\r\n]/.test(s) ? "'" + s : s;
}

function toCsv(items: CleanupItem[]): string {
  const head = ["id", "type", "account_id", "principal", "detail", "risk_level", "risk_score", "risk_reasons", "recommendation"];
  const cell = (i: CleanupItem, k: string) =>
    k === "risk_reasons" ? i.risk_reasons.join("|") : String((i as any)[k]);
  const rows = items.map((i) => head.map((k) => `"${csvSafe(cell(i, k)).replace(/"/g, '""')}"`).join(","));
  return [head.join(","), ...rows].join("\n");
}

function download(items: CleanupItem[], filename: string) {
  const blob = new Blob([toCsv(items)], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

interface Group {
  type: CleanupType;
  items: CleanupItem[];
  count: number;
  worst: RiskLevel;
  dist: Record<RiskLevel, number>;
}

const VALID_TYPES: CleanupType[] = ["unused_permission", "unused_role", "long_lived_key", "no_mfa", "escalation_path"];

export default function CleanupBacklog() {
  const { data, loading } = useAsync<CleanupItem[]>(() => api.getCleanup());
  const { data: criteria } = useAsync<RiskCriteria>(() => api.getRiskCriteria());
  const [searchParams, setSearchParams] = useSearchParams();
  const [detail, setDetail] = useState<CleanupItem | null>(null);

  // 드릴다운 대상은 URL ?type= 로 관리 → 대시보드 KPI 카드에서 딥링크로 진입 가능.
  const typeParam = searchParams.get("type");
  const openType: CleanupType | null =
    typeParam && (VALID_TYPES as string[]).includes(typeParam) ? (typeParam as CleanupType) : null;
  const setOpenType = (t: CleanupType | null) => {
    if (t) setSearchParams({ type: t });
    else setSearchParams({});
  };

  const { selected } = useAccounts();

  const groupsFor = (items: CleanupItem[]): Group[] => {
    const byType = new Map<CleanupType, CleanupItem[]>();
    for (const it of items) {
      if (!byType.has(it.type)) byType.set(it.type, []);
      byType.get(it.type)!.push(it);
    }
    return [...byType.entries()]
      .map(([type, its]) => {
        const dist: Record<RiskLevel, number> = { critical: 0, high: 0, medium: 0, low: 0 };
        its.forEach((i) => dist[i.risk_level]++);
        const worst = (["critical", "high", "medium", "low"] as RiskLevel[]).find((r) => dist[r] > 0)!;
        return { type, items: its, count: its.length, worst, dist };
      })
      .sort((a, b) => RISK_ORDER[a.worst] - RISK_ORDER[b.worst] || b.count - a.count);
  };

  const groups = useMemo<Group[]>(() => {
    if (!data) return [];
    const scoped = selected ? data.filter((i) => i.account_id === selected) : data;
    return groupsFor(scoped);
  }, [data, selected]);

  // 전체 뷰: 계정별 항목 묶음(계정 asc). 계정별 섹션으로 먼저 구분해 보여주기 위함.
  const byAccount = useMemo(() => {
    if (!data || selected) return [];
    const accts = [...new Set(data.map((i) => i.account_id))].sort();
    return accts.map((acct) => ({ account: acct, groups: groupsFor(data.filter((i) => i.account_id === acct)) }));
  }, [data, selected]);

  // 선택 계정 반영 총 건수(헤더 카운터).
  const scopedTotal = groups.reduce((n, g) => n + g.count, 0);

  if (loading || !data) {
    return <Box padding="xxl" textAlign="center"><Spinner size="large" /></Box>;
  }

  const drillItems = openType ? (groups.find((g) => g.type === openType)?.items ?? []) : [];
  const sortedDrill = [...drillItems].sort((a, b) => RISK_ORDER[a.risk_level] - RISK_ORDER[b.risk_level]);

  // 카테고리 카드 묶음 렌더(전체 뷰 계정별 섹션·단일계정 공통 재사용).
  const renderCards = (gs: Group[]) => (
    <Cards
      items={gs}
      trackBy="type"
      cardDefinition={{
        header: (g: Group) => (
          <Link fontSize="heading-m" onFollow={() => setOpenType(g.type)}>{TYPE_LABEL[g.type]}</Link>
        ),
        sections: [
          {
            id: "count",
            content: (g: Group) => (
              <SpaceBetween size="xs">
                <Box fontSize="display-l" fontWeight="bold">{g.count.toLocaleString()}</Box>
                <Box color="text-body-secondary" fontSize="body-s">건</Box>
              </SpaceBetween>
            ),
          },
          {
            id: "dist", header: "위험도 분포",
            content: (g: Group) => (
              <SpaceBetween direction="horizontal" size="s">
                {(["critical", "high", "medium", "low"] as RiskLevel[]).filter((r) => g.dist[r] > 0).map((r) => (
                  <StatusIndicator key={r} type={RISK_INDICATOR[r]}>{r} {g.dist[r]}</StatusIndicator>
                ))}
              </SpaceBetween>
            ),
          },
          {
            id: "action",
            content: (g: Group) => <Button onClick={() => setOpenType(g.type)}>{g.count}건 보기</Button>,
          },
        ],
      }}
      cardsPerRow={[{ cards: 1 }, { minWidth: 600, cards: 2 }, { minWidth: 1000, cards: 3 }]}
    />
  );

  // ---- 카테고리 요약 뷰 ----
  if (!openType) {
    return (
      <ContentLayout header={<Header variant="h1" counter={`(${scopedTotal})`} description={`유형별 조치 후보. ${selected ? `계정 ${selected}` : "전체 계정 — 계정별로 구분"}. 실제 조치는 사람이 수행 (읽기전용 도구).`} actions={<Button iconName="download" onClick={() => download(data, "action_items.csv")}>전체 CSV</Button>}>{PAGE_TITLE}</Header>}>
       <SpaceBetween size="l">
        <RiskCriteriaPanel criteria={criteria ?? null} />
        {selected ? (
          renderCards(groups)
        ) : (
          // 전체 뷰: 계정별 섹션으로 먼저 구분, 각 섹션에 그 계정 카테고리 카드.
          byAccount.map(({ account, groups: g }) => (
            <ExpandableSection key={account} variant="container" defaultExpanded
              headerText={`계정 ${account}`}
              headerCounter={`(${g.reduce((n, x) => n + x.count, 0)}건)`}>
              {renderCards(g)}
            </ExpandableSection>
          ))
        )}
       </SpaceBetween>
      </ContentLayout>
    );
  }

  // ---- 드릴다운 뷰 (특정 카테고리 항목 테이블) ----
  return (
    <ContentLayout
      header={
        <SpaceBetween size="s">
          <BreadcrumbGroup
            items={[
              { text: PAGE_TITLE, href: "#" },
              { text: TYPE_LABEL[openType], href: "#" },
            ]}
            onFollow={(e) => { e.preventDefault(); if (e.detail.text === PAGE_TITLE) setOpenType(null); }}
          />
          <Header
            variant="h1"
            counter={`(${drillItems.length})`}
            actions={
              <SpaceBetween direction="horizontal" size="xs">
                <Button onClick={() => setOpenType(null)}>← 카테고리로</Button>
                <Button iconName="download" onClick={() => download(drillItems, `action_items_${openType}.csv`)}>이 카테고리 CSV</Button>
              </SpaceBetween>
            }
          >
            {TYPE_LABEL[openType]}
          </Header>
        </SpaceBetween>
      }
    >
      <Table
        variant="container"
        contentDensity="compact"
        wrapLines
        columnDefinitions={[
          { id: "risk", header: "위험도", width: 130, minWidth: 130, cell: (i: CleanupItem) => <RiskCell item={i} criteria={criteria ?? null} /> },
          { id: "account", header: "계정", width: 130, cell: (i: CleanupItem) => i.account_id },
          { id: "principal", header: "Principal", cell: (i: CleanupItem) => <Box fontSize="body-s">{i.principal}</Box> },
          { id: "why", header: "위험 근거", cell: (i: CleanupItem) => (
            i.risk_reasons.length
              ? <Box fontSize="body-s">{i.risk_reasons.join(", ")}</Box>
              : <Box color="text-status-inactive" fontSize="body-s">유형 기본</Box>
          ) },
          { id: "action", header: "", width: 90, minWidth: 90, cell: (i: CleanupItem) => <Button variant="inline-link" onClick={() => setDetail(i)}><span style={{ whiteSpace: "nowrap" }}>상세 보기</span></Button> },
        ]}
        items={sortedDrill}
      />

      <Modal
        visible={!!detail}
        onDismiss={() => setDetail(null)}
        size="large"
        header={detail ? <SpaceBetween direction="horizontal" size="xs"><Badge>{TYPE_LABEL[detail.type]}</Badge><Box>{detail.principal.split("/").pop()}</Box></SpaceBetween> : ""}
        footer={<Box float="right"><Button variant="primary" onClick={() => setDetail(null)}>닫기</Button></Box>}
      >
        {detail && (
          <SpaceBetween size="l">
            {/* ① 위험도 배너 — 색으로 심각도를 첫눈에. 무엇을 왜 해야 하는지 한 줄 요약. */}
            <Alert
              type={LEVEL_ALERT[detail.risk_level]}
              header={`위험도 ${detail.risk_level.toUpperCase()} · ${detail.risk_score}점 — ${LEVEL_MEANING[detail.risk_level]}`}
            >
              {detail.detail}
            </Alert>

            {/* ② 대상 — 누구/어디 */}
            <Container header={<Header variant="h3">대상</Header>}>
              <KeyValuePairs
                columns={2}
                items={[
                  { label: "계정", value: detail.account_id },
                  { label: "유형", value: TYPE_LABEL[detail.type] },
                  {
                    label: "Principal (ARN)",
                    value: <Box fontSize="body-s" fontWeight="normal">{detail.principal}</Box>,
                  },
                ]}
              />
            </Container>

            {/* ③ 상세 근거 — 무엇이 문제인지 구체 수치 */}
            {detail.evidence && Object.keys(detail.evidence).length > 0 && (
              <Container header={<Header variant="h3">상세 근거</Header>}>
                <KeyValuePairs
                  columns={3}
                  items={Object.entries(detail.evidence).map(([k, v]) => ({ label: k, value: v }))}
                />
              </Container>
            )}

            {/* ④ 위험 판정 근거 — 왜 이 점수인지 */}
            <Container header={<Header variant="h3">위험 판정 근거 ({detail.risk_score}점)</Header>}>
              {detail.risk_reasons.length ? (
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {detail.risk_reasons.map((r, i) => <li key={i}><Box>{r}</Box></li>)}
                </ul>
              ) : (
                <Box color="text-status-inactive">개별 근거 없음(유형 기본 위험도).</Box>
              )}
            </Container>

            {/* ⑤ 권장 조치 — 어떻게 해결할지, success alert 로 강조 */}
            <Alert type="success" header="권장 조치">
              {detail.recommendation}
            </Alert>
          </SpaceBetween>
        )}
      </Modal>
    </ContentLayout>
  );
}
