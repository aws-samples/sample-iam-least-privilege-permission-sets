import { useState, useMemo, useEffect, useCallback, useRef } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import Container from "@cloudscape-design/components/container";
import Table from "@cloudscape-design/components/table";
import Box from "@cloudscape-design/components/box";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Button from "@cloudscape-design/components/button";
import Badge from "@cloudscape-design/components/badge";
import Link from "@cloudscape-design/components/link";
import Popover from "@cloudscape-design/components/popover";
import Input from "@cloudscape-design/components/input";
import Toggle from "@cloudscape-design/components/toggle";
import Checkbox from "@cloudscape-design/components/checkbox";
import SegmentedControl from "@cloudscape-design/components/segmented-control";
import ExpandableSection from "@cloudscape-design/components/expandable-section";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import Modal from "@cloudscape-design/components/modal";
import Spinner from "@cloudscape-design/components/spinner";
import Alert from "@cloudscape-design/components/alert";
import Textarea from "@cloudscape-design/components/textarea";
import Tabs from "@cloudscape-design/components/tabs";
import { api } from "@/api/client";
import { useAsync } from "@/api/useAsync";
import { useAccounts } from "@/AccountContext";
import { useSplitPanel } from "@/SplitPanelContext";
import type {
  CatalogEntry,
  PolicyAction,
  PolicyArtifact,
  PrincipalKind,
  TerraformArtifact,
  UsageSubject,
} from "@/api/types";

/** 우측 패널 탭. 슬롯이 하나라 두 화면을 탭으로 합친다. */
type PanelTab = "policy" | "targets";

/** Action 의 사용 근거 3분할. 서로 배타적이고 합이 전체다. */
type Evidence = "used" | "unused" | "undetermined";
type EvidenceFilter = "all" | Evidence;

/**
 * 이 action 을 어느 칸에 넣나.
 *
 * `used` 가 이긴다 — 사용 실적이 있으면 다른 판정은 의미가 없다. 나머지에서 `undetermined` 는
 * "안 썼다는 증거가 없다"(Access Advisor 커버리지 없음)이고 `unused` 는 "안 썼다고 확인됐다" 다.
 * 이 둘을 한 칸에 넣으면 근거가 없는 권한까지 제거 대상으로 읽힌다.
 */
function evidenceOf(a: PolicyAction): Evidence {
  if (a.used) return "used";
  return a.undetermined ? "undetermined" : "unused";
}

const EVIDENCE_LABEL: Record<Evidence, string> = {
  used: "실사용",
  unused: "미사용 확정",
  undetermined: "근거 불명",
};

function statusIndicator(s: CatalogEntry["approval_status"]) {
  if (s === "approved") return <StatusIndicator type="success">승인</StatusIndicator>;
  if (s === "review") return <StatusIndicator type="warning">검토중</StatusIndicator>;
  return <StatusIndicator type="pending">초안</StatusIndicator>;
}

// 좌측 체크리스트 → IAM 정책 JSON
function buildPolicy(persona: string, actions: PolicyAction[]): string {
  const included = actions.filter((a) => a.included).map((a) => a.action);
  const doc = {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: `${persona.replace(/[^A-Za-z0-9]/g, "")}LeastPrivilege`,
        Effect: "Allow",
        Action: included,
        Resource: "*",
      },
    ],
  };
  return JSON.stringify(doc, null, 2);
}

// 편집된 JSON → action 목록 추출 (좌측 동기화용). 실패 시 null.
function extractActions(json: string): string[] | null {
  try {
    const doc = JSON.parse(json);
    const stmts = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
    const acts = new Set<string>();
    for (const s of stmts) {
      if (!s || s.Effect !== "Allow") continue;
      const a = s.Action;
      (Array.isArray(a) ? a : [a]).forEach((x: string) => x && acts.add(x));
    }
    return [...acts];
  } catch {
    return null;
  }
}

// ── 권한 카테고리화 ──────────────────────────────────────────────────────
// 서비스 = action 접두(':' 앞). 동작(access) = 동사 접두로 read/write 판정(엔진 m5_catalog 와 동일 개념).
const READ_VERB =
  /^(Get|List|Describe|BatchGet|Simulate|Lookup|Select|Search|Generate|Check|View|Detect|Estimate|Discover|Preview|Test|Validate|Query|Scan|Sample|Count|Head|Poll|Read|Resolve|Retrieve|Export)/;

function serviceOf(action: string): string {
  return action.includes(":") ? action.split(":", 1)[0] : action;
}

function accessKindOf(action: string): "read" | "write" {
  const local = action.includes(":") ? action.slice(action.indexOf(":") + 1) : action;
  return READ_VERB.test(local) ? "read" : "write";
}

const ACCESS_LABEL: Record<string, string> = { read: "읽기 (조회)", write: "쓰기 (변경)" };

// 수집 소스 → 라벨·색·설명(합성 소스 컬럼용). 소스마다 다른 색으로 한눈에 구분.
type SourceMeta = { label: string; color: "blue" | "green" | "grey" | "red" | "severity-high"; desc: string };
const SOURCE_META: Record<string, SourceMeta> = {
  access_advisor: {
    label: "Access Advisor", color: "blue",
    desc: "서비스/액션별 마지막 사용 시점(Service Last Accessed). granted-vs-used 갭의 핵심 소스.",
  },
  cloudtrail: {
    label: "CloudTrail", color: "green",
    desc: "실제 API 호출 이벤트(누가·언제·몇 번). 사용 횟수(count)의 근거.",
  },
  analyzer_unused: {
    label: "Access Analyzer", color: "severity-high",
    desc: "IAM Access Analyzer의 미사용 접근 findings(미사용 role/키/권한).",
  },
  credential_report: {
    label: "Credential Report", color: "grey",
    desc: "IAM 자격증명 보고서 — 모든 User의 MFA·액세스키 나이·마지막 사용. principal 인벤토리 뼈대.",
  },
  idc_permission_sets: {
    label: "Identity Center", color: "red",
    desc: "IdC Permission Set 할당(사람의 PS 기반 접근).",
  },
};
function sourceMeta(s: string): SourceMeta {
  return SOURCE_META[s] ?? { label: s, color: "grey", desc: "" };
}

// 멤버 principal 에서 계정 ID 를 뽑는다. IAM ARN(arn:aws:iam::<account>:...) 의 5번째 필드가 계정이지만
// 그 자리가 12자리 숫자가 아닌 문자열(엔진의 합성 레코드 등)이면 계정으로 쓰면 안 된다 — 그대로 넣으면
// 계정 그룹핑에 존재하지 않는 "계정"이 생긴다. 판별 불가는 "?" 로 모은다.
const ACCOUNT_ID = /^\d{12}$/;

export function accountOf(principal: string): string {
  const parts = principal.split(":");
  const candidate = parts.length > 4 ? parts[4] : "";
  return ACCOUNT_ID.test(candidate) ? candidate : "?";
}

// persona 멤버 → 계정별 멤버 수(계정 asc). 전체 뷰에서 persona 가 어느 계정에 얼마나 걸쳐 있는지 보여준다.
function membersByAccount(members: string[]): { account: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const m of members) {
    const acct = accountOf(m);
    counts.set(acct, (counts.get(acct) ?? 0) + 1);
  }
  return [...counts.entries()].map(([account, count]) => ({ account, count })).sort((a, b) => a.account.localeCompare(b.account));
}

// ---- 멤버 principal 표시 ----
// 개수만 보여주면 "이 persona 정책을 누구에게 적용하나"에 답이 안 된다(IdC 미사용 환경에서는 이 ARN 이
// 곧 적용 대상). ARN 은 100자를 넘어 표에 그대로 넣으면 레이아웃이 깨지므로 이름·계정을 주 표시로,
// ARN 은 복사용으로 둔다(CLI·Terraform 적용에 필요).
export interface MemberRef {
  arn: string;
  name: string;      // ARN 마지막 세그먼트(역할/사용자 이름)
  account: string;
  kind: "user" | "role";
}

export function parseMember(arn: string): MemberRef {
  return {
    arn,
    name: arn.split("/").pop() || arn,
    account: accountOf(arn),
    kind: arn.includes(":user/") ? "user" : "role",
  };
}

// persona 카탈로그 표의 컬럼 정의(전체 뷰·계정별 섹션 공통 재사용). selectedAccount 가 없고 persona 가
// 여러 계정에 걸치면 멤버 컬럼에 계정별 분해를 보여준다.
function catalogColumns(selectedAccount: string, openPanel: (e: CatalogEntry, tab: PanelTab) => void) {
  return [
    {
      id: "persona", header: "Persona", minWidth: 150,
      cell: (e: CatalogEntry) => (
        <SpaceBetween direction="horizontal" size="xs">
          <Box fontWeight="bold">{e.persona}</Box>
          {e.ai_suggested && <Badge color="blue">✦ AI 제안</Badge>}
        </SpaceBetween>
      ),
    },
    // minWidth 없이 두면 멤버 컬럼(260)에 밀려 설명이 한 글자씩 세로로 접힌다.
    { id: "desc", header: "설명", minWidth: 160, cell: (e: CatalogEntry) => e.description },
    {
      id: "members", header: "멤버(principal)", minWidth: 200,
      cell: (e: CatalogEntry) => {
        const byAcct = membersByAccount(e.members);
        // 여러 계정에 걸친 persona 는 계정별 분해를 먼저 보여준 뒤 접이식으로 principal 목록.
        const header = !selectedAccount && byAcct.length > 1
          ? (
            <SpaceBetween size="xxs">
              <Box fontWeight="bold">{e.member_count.toLocaleString()} (전체)</Box>
              {byAcct.map((b) => (
                <Box key={b.account} fontSize="body-s" color="text-body-secondary">{b.account}: {b.count.toLocaleString()}</Box>
              ))}
            </SpaceBetween>
          )
          : <Box fontWeight="bold">{e.member_count.toLocaleString()}</Box>;
        if (e.members.length === 0) return header;
        // 표 안에 목록을 펼치지 않는다 — 멤버가 많으면(실측 47개) 행이 화면을 넘겨 표를 못 쓴다.
        // 우측 패널에서 검색·필터·CSV 로 다룬다.
        return (
          <SpaceBetween size="xxs">
            {header}
            <Button variant="inline-link" onClick={() => openPanel(e, "targets")}>
              적용 대상 {e.member_count.toLocaleString()}개 보기
            </Button>
          </SpaceBetween>
        );
      },
    },
    {
      id: "source", header: "합성 소스", minWidth: 160,
      cell: (e: CatalogEntry) => {
        const srcs = e.contributing_sources ?? [];
        const highConf = e.synthesis_source === "last_accessed_evidence";
        if (srcs.length === 0) {
          return highConf
            ? <StatusIndicator type="success">고신뢰</StatusIndicator>
            : <StatusIndicator type="warning">used 기반(저신뢰)</StatusIndicator>;
        }
        return (
          <SpaceBetween size="xxs">
            <SpaceBetween direction="horizontal" size="xxs">
              {srcs.map((s) => {
                const m = sourceMeta(s);
                return (
                  <Popover key={s} dismissButton={false} position="top" size="small" triggerType="custom" header={m.label} content={m.desc}>
                    <span style={{ cursor: "help" }}><Badge color={m.color}>{m.label}</Badge></span>
                  </Popover>
                );
              })}
            </SpaceBetween>
            {!highConf && <Box fontSize="body-s" color="text-status-warning">used 기반 · 저신뢰(사용 이력 소스 없음)</Box>}
          </SpaceBetween>
        );
      },
    },
    { id: "status", header: "상태", width: 90, minWidth: 90, cell: (e: CatalogEntry) => statusIndicator(e.approval_status) },
    { id: "action", header: "", width: 130, minWidth: 130, cell: (e: CatalogEntry) => <Button onClick={() => openPanel(e, "policy")}><span style={{ whiteSpace: "nowrap" }}>정책 편집</span></Button> },
  ];
}

// action 배열을 그룹 키 → 멤버로 묶는다. 그룹은 이름 asc, 내부 action asc (결정론적 표시).
function groupActions(
  actions: PolicyAction[],
  by: "service" | "access",
): { key: string; label: string; items: PolicyAction[] }[] {
  const groups = new Map<string, PolicyAction[]>();
  for (const a of actions) {
    const key = by === "service" ? serviceOf(a.action) : accessKindOf(a.action);
    (groups.get(key) ?? groups.set(key, []).get(key)!).push(a);
  }
  return [...groups.entries()]
    .map(([key, items]) => ({
      key,
      label: by === "access" ? (ACCESS_LABEL[key] ?? key) : key,
      items: [...items].sort((x, y) => x.action.localeCompare(y.action)),
    }))
    .sort((g1, g2) => {
      // 쓰기 그룹을 먼저(검토 우선순위 높음), 그 외는 이름순.
      if (by === "access") return g1.key === g2.key ? 0 : g1.key === "write" ? -1 : 1;
      return g1.label.localeCompare(g2.label);
    });
}

// last_used ISO → 사람이 읽는 상대 표기(결정론: 오늘 기준 아님, 문자열 그대로 날짜만).
function fmtLastUsed(iso: string | null): string {
  if (!iso) return "기록 없음";
  return iso.slice(0, 10); // YYYY-MM-DD
}

// 관측 구간·횟수 표기 임계치의 폴백. 정본은 config `catalog.count_min_observed_days` 이고
// `CatalogEntry.count_min_observed_days` 로 내려온다(불변식 ④ — UI 에 임계치를 박지 않는다).
// 값이 없는 구 run 에서는 이 값을 쓴다: **감추는 쪽**이 안전한 기본이다(짧은 창의 횟수를 총계처럼
// 보여 주는 것이 이 결함의 내용이므로, 모르면 보여주지 않는다).
export const DEFAULT_COUNT_MIN_OBSERVED_DAYS = 7;

function countMinDays(entry: { count_min_observed_days?: number | null }): number {
  return entry.count_min_observed_days ?? DEFAULT_COUNT_MIN_OBSERVED_DAYS;
}

// 호출 횟수를 표기해도 되는가. 사용자 결정(2026-09-11): *"관측 기간이 몇 시간 이런 식이면 그냥
// 표기를 안 해주는 게 맞다. 오히려 고객의 신뢰를 무너뜨릴 수도 있다."*
// CloudTrail LookupEvents 는 페이지 상한이 있어 이벤트가 많은 계정에서 구간이 몇 시간뿐이다
// (실측: 79/79 역할 전부 `observed_days = 0`). 그 창의 "3회" 는 총 사용 횟수가 아니다.
// 측정값이 없으면(null) 역시 표기하지 않는다 — 창을 모르는데 횟수를 보여줄 근거가 없다.
export function showsCount(entry: {
  observed_window_days?: number | null;
  count_min_observed_days?: number | null;
}): boolean {
  const days = entry.observed_window_days;
  return days != null && days >= countMinDays(entry);
}

// CloudTrail 이 **실제로 훑은** 구간 문구. `observed_window_days` 는 측정값이다 — 요청한 90일이
// 아니다(LookupEvents 는 최신순 페이지 상한이 있어 며칠만 덮이는 경우가 있다). 측정값이 없으면
// 일수를 말하지 않는다: 화면에 "90일" 을 박아 두면 측정하지 않은 숫자를 근거처럼 보여준다.
// 🔴 임계치 미만이면 **일수를 아예 말하지 않는다**(횟수와 같은 규칙). 실측에서 이 값이 `0` 으로
// 나온다 — "최근 0일 사용 기록 없음" 은 문장이 성립하지 않고, "1일 미만" 이라고 정직하게 써 봐도
// 미사용 판정이 3시간 관측에 근거한 것처럼 읽힌다. 실제 판정 근거는 Access Advisor(최대 400일,
// 잘리지 않음)이고 CloudTrail 창은 횟수·최근 시각의 근거일 뿐이다(F14-3).
function windowText(
  entry: { observed_window_days?: number | null; count_min_observed_days?: number | null },
): string {
  const days = entry.observed_window_days;
  if (days == null || days < countMinDays(entry)) return "관측 구간";
  return `최근 ${days.toLocaleString()}일`;
}

// ---- principal → persona 역방향 조회 ----
// 운영자는 "이 역할에 무엇을 적용하나"로 접근한다(persona 목록에서 사람을 찾는 방향이 아니다).
// 한 principal 은 정확히 하나의 persona 에 속한다(m5_catalog 가 배타적으로 군집) → 1:1 로 표시.
export interface ReverseHit {
  member: MemberRef;
  persona: CatalogEntry;
}

export function reverseIndex(catalog: CatalogEntry[], query: string): ReverseHit[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  const hits: ReverseHit[] = [];
  for (const persona of catalog) {
    for (const arn of persona.members) {
      const member = parseMember(arn);
      if (member.arn.toLowerCase().includes(q) || member.name.toLowerCase().includes(q)) {
        hits.push({ member, persona });
      }
    }
  }
  return hits.sort((a, b) => a.member.name.localeCompare(b.member.name));
}

/**
 * principal(ARN) → 그 principal 이 속한 persona. **정확히 일치**로 찾는다.
 *
 * 🔴 위의 `reverseIndex` 는 사람이 타이핑하는 검색용(부분 일치)이라 딥링크에 쓰면 안 된다:
 * `role/etl` 로 들어온 링크가 `role/etl-legacy` 의 persona 를 열 수 있고, 그러면 사람은 **다른
 * 역할의 정책**을 자기 것으로 믿고 고친다.
 */
export function personaOfPrincipal(catalog: CatalogEntry[], principal: string): CatalogEntry | null {
  return catalog.find((e) => e.members.includes(principal)) ?? null;
}

function PrincipalLookup({ catalog, onOpen }: { catalog: CatalogEntry[]; onOpen: (e: CatalogEntry) => void }) {
  const [query, setQuery] = useState("");
  const hits = useMemo(() => reverseIndex(catalog, query), [catalog, query]);
  const searched = query.trim().length > 0;
  return (
    <Container
      header={
        <Header
          variant="h2"
          description="역할·사용자 이름으로 검색해 어떤 persona 정책을 적용할지 찾습니다."
        >
          적용 대상 조회 (principal → persona)
        </Header>
      }
    >
      <SpaceBetween size="s">
        <Input
          value={query}
          onChange={(e) => setQuery(e.detail.value)}
          placeholder="역할 이름 또는 ARN 일부 (예: data-eng)"
          type="search"
        />
        {searched && hits.length === 0 && (
          <Alert type="info" header="이 이름으로 카탈로그에 등록된 principal 이 없습니다">
            persona 카탈로그는 <b>실사용 기록이 관측된 principal</b> 만 담습니다. 검색 결과가 없다면
            추천이 없다는 뜻이 아니라, 대개 다음 중 하나입니다.
            <ul>
              <li><b>미사용</b> — 적용 대상이 아니라 회수 대상입니다. <b>조치 필요 항목</b> 화면에서 확인하세요.</li>
              <li><b>서비스 소유 역할</b> — 서비스 연결 역할·IdC 예약 역할은 사람이 쓰는 신원이 아니라 제외됩니다.</li>
              <li>이름 오타 또는 다른 계정의 principal(계정 선택기 확인)</li>
            </ul>
          </Alert>
        )}
        {hits.length > 0 && (
          <Table
            variant="embedded"
            wrapLines
            items={hits}
            columnDefinitions={[
              {
                id: "principal", header: "Principal", minWidth: 220,
                cell: (h: ReverseHit) => (
                  <SpaceBetween direction="horizontal" size="xxs">
                    <Box fontWeight="bold">{h.member.name}</Box>
                    <Badge color={h.member.kind === "user" ? "red" : "grey"}>
                      {h.member.kind === "user" ? "IAM 사용자" : "역할"}
                    </Badge>
                  </SpaceBetween>
                ),
              },
              { id: "account", header: "계정", cell: (h: ReverseHit) => h.member.account },
              {
                id: "persona", header: "추천 persona", minWidth: 180,
                cell: (h: ReverseHit) => <Box fontWeight="bold">{h.persona.persona}</Box>,
              },
              {
                id: "status", header: "승인 상태",
                cell: (h: ReverseHit) => statusIndicator(h.persona.approval_status),
              },
              {
                id: "act", header: "", minWidth: 110,
                cell: (h: ReverseHit) => (
                  <Button variant="inline-link" onClick={() => onOpen(h.persona)}>정책 보기</Button>
                ),
              },
            ]}
          />
        )}
      </SpaceBetween>
    </Container>
  );
}

/**
 * 딥링크로 들어온 대상의 안내 배너.
 *
 * 🔴 이 배너의 본론은 "찾아 주었다" 가 아니라 **파급 범위**다. persona 는 여러 대상을 하나로 묶은
 * 것이어서, 한 행에서 들어와 정책을 고치면 같은 persona 의 다른 대상에도 함께 적용된다(실측:
 * 10개 대상이 4개 persona 에 묶여 있다). 이 문장이 없으면 사람은 역할 하나만 바꾼 줄 알고 남의
 * 권한을 바꾼다. 기계 역할(서비스 역할 정리)은 1:1 이라 이 문제가 없다 — 두 화면이 갈린 이유다.
 */
function LinkedPrincipalBanner({
  principal,
  narrowed,
  full,
  selectedAccount,
  onBack,
  onOpen,
}: {
  principal: string;
  narrowed: CatalogEntry | null;
  full: CatalogEntry | null;
  selectedAccount: string;
  onBack: (() => void) | null;
  onOpen: () => void;
}) {
  const member = parseMember(principal);
  const back = onBack ? <Button onClick={onBack}>← 조치 필요 항목(권한 축소)</Button> : undefined;

  if (!narrowed || !full) {
    // 목적지에서 대상을 못 찾는 것은 **정상일 수 있다**(카탈로그는 실사용이 관측된 principal 만
    // 담는다). 그러니 오류로 말하지 않고, 어느 경우인지 사람이 가를 수 있게 이유를 적는다.
    return (
      <Alert type="warning" header={`${member.name} 은 persona 카탈로그에 없습니다`} action={back}>
        다음 중 하나입니다.
        <ul>
          <li>
            <b>계정 선택기</b>가 다른 계정을 가리키고 있습니다(이 대상은 계정 {member.account}).
            전체 계정 또는 그 계정으로 바꿔 보십시오.
          </li>
          <li><b>실사용 기록이 관측되지 않았습니다</b> — 묶을 근거가 없어 persona 에서 빠집니다.</li>
          <li>이 대상이 사람이 쓰는 신원이 아닙니다(그렇다면 <b>서비스 역할 정리</b>에서 고칩니다).</li>
        </ul>
      </Alert>
    );
  }

  const total = full.members.length;
  const visible = narrowed.members.length;
  return (
    <Alert
      type="info"
      header={`${member.name} 의 정책은 persona 「${narrowed.persona}」 에서 고칩니다`}
      action={back}
    >
      <SpaceBetween size="xxs">
        <Box>
          이 persona 에는 <b>{total}개 대상</b>이 묶여 있습니다 — 정책을 고치면 <b>그 대상 전부에 함께
          적용됩니다</b>(이 역할 하나만 바뀌는 것이 아닙니다).
          {selectedAccount && visible !== total
            ? ` 계정 ${selectedAccount} 범위에서는 ${visible}개만 보입니다.`
            : ""}
        </Box>
        <Box fontSize="body-s" color="text-body-secondary">
          오른쪽 패널이 이 persona 의 정책 편집으로 열려 있습니다(닫았다면 <Link onFollow={onOpen}>다시 열기</Link>).
          조치 완료 표시는 조치 필요 항목 화면에서 합니다 — 이 화면은 정책만 다룹니다.
        </Box>
      </SpaceBetween>
    </Alert>
  );
}

function useDownload() {
  return (filename: string, content: string, mime = "text/plain") => {
    // charset 을 명시한다. 내용에 한국어(설명·주석)가 섞이는데, 선언이 없으면 열는 쪽이 로컬
    // 인코딩을 가정해 깨질 수 있다.
    const blob = new Blob([content], { type: mime.includes("charset") ? mime : `${mime};charset=utf-8` });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };
}
// ---- 적용 대상 판별 근거 표시 ----
// 엔진(m2_normalizer)이 내려준 값을 그대로 보여준다. 사람의 분류를 저장하지 않으므로 여기엔 어떤
// 상태도 없다 — 매 run 의 소스가 곧 표시다.
//
// 축이 **둘**이다: 신뢰정책(`principal_kind` — 누가 집을 수 있나)과 실사용(`usage_subject` —
// 실제로 누가 집었나). 신뢰정책만 보면 사람이 쓰는 역할이 전부 "판별 불가" 로 떨어진다(실측: persona
// 에 올라온 15개 전부). 그래서 표시는 두 축의 논리합이고, 배지 옆에 **왜 그렇게 판정했는지**를 함께
// 낸다 — 맨몸 "판별 불가" 배지는 사람이 다음에 무엇을 할지 알려주지 못한다.
type SubjectView = "human" | "machine" | "unknown";

const SUBJECT_META: Record<SubjectView, { label: string; color: "green" | "blue" | "grey" }> = {
  human: { label: "사람", color: "green" },
  machine: { label: "자동화", color: "blue" },
  unknown: { label: "판별 불가", color: "grey" },
};

// `usage_subject_basis` → (짧은 라벨, 근거 문장). 엔진 `_usage_subject` 의 basis 코드와 1:1이다.
// 🔴 세션 이름 **원문은 여기 오지 않는다**(SSO 세션 이름은 사용자 이메일이다 — R1-a). 문장도
// "이메일 형식" 까지만 말한다.
const BASIS_META: Record<string, { short: string; desc: string }> = {
  iam_user: {
    short: "IAM 사용자",
    desc: "IAM 사용자입니다 — 정의상 사람이 쓰는 자격입니다(신호를 볼 필요가 없습니다).",
  },
  idc_assignment: {
    short: "IdC 할당",
    desc: "Identity Center 할당(Permission Set)입니다 — 사람이 로그인해 씁니다.",
  },
  mfa_session: {
    short: "MFA 세션",
    desc: "MFA 인증 표시가 있는 세션이 관측됐습니다 — 사람만 통과할 수 있는 관문입니다.",
  },
  assume_caller_human: {
    short: "사람이 assume",
    desc: "이 역할을 집은 호출자가 IAM 사용자·페더레이션·SSO·루트였습니다(다른 계정에서 온 호출도 포함 — 고유 ID 접두로 종류를 가립니다).",
  },
  session_name_email: {
    short: "사람 세션명",
    desc: "이 역할을 집을 때 쓴 세션 이름이 이메일 형식이었습니다 — 자동화는 이메일을 세션명으로 쓰지 않습니다. 원문은 저장하지 않습니다.",
  },
  trust_iam_user: {
    short: "신뢰=IAM 사용자",
    desc: "신뢰정책이 IAM 사용자 ARN 을 직접 가리킵니다(계정 신뢰 `:root` 가 아닙니다).",
  },
  invoked_by: {
    short: "서비스 호출",
    desc: "AWS 서비스가 이 역할로 호출한 이벤트가 관측됐습니다(invokedBy).",
  },
  session_name_automation: {
    short: "자동화 세션명",
    desc: "세션 이름이 자동화 형식(계정 ID 삽입·UUID 접미)입니다. 원문은 저장하지 않습니다.",
  },
  trust_service: {
    short: "신뢰=AWS 서비스",
    desc: "신뢰정책 주체가 AWS 서비스(Lambda·EC2·SSM 등)입니다 — 사람이 로그인할 수 없습니다.",
  },
  no_events: {
    short: "관측 이벤트 없음",
    desc: "관측 구간 안에 이 principal 의 CloudTrail 이벤트가 **없었습니다**. 안 쓴다는 뜻이 아니라 관측 밖이라는 뜻입니다(데이터 이벤트는 기본 미기록).",
  },
  events_without_subject_signal: {
    short: "주체 신호 없음",
    desc: "이벤트는 관측됐지만 주체를 가릴 신호(MFA 표시·호출자 종류·세션 형식)가 없었습니다 — 관측했으나 갈리지 않았습니다.",
  },
};

// 신뢰정책 축 문장(실사용 근거가 없을 때 무엇을 알고 있는지 말해 준다).
const TRUST_AXIS_DESC: Record<PrincipalKind, string> = {
  human: "신뢰정책은 사람(IAM 사용자 또는 SAML/OIDC 연합)을 가리킵니다.",
  service: "신뢰정책 주체는 AWS 서비스입니다 — 기본적으로 persona 대상에서 제외됩니다.",
  unknown: "신뢰정책에는 계정/역할(Principal.AWS)만 있어 이 축만으로는 갈릴 수 없습니다. 아래 신뢰 주체를 보고 소유 팀에 확인하세요.",
};

/** 두 축의 논리합. 실사용 근거가 이긴다(R1 — 양성 근거만 승격, 부재는 판정 근거가 아니다). */
export function subjectView(kind: PrincipalKind, subject: UsageSubject | undefined): SubjectView {
  if (subject === "human") return "human";
  if (subject === "machine") return "machine";
  // 실사용 근거가 없으면 신뢰정책 축으로 내려간다. `service` 를 machine 으로 읽는 것은 같은 사실을
  // 다른 소스로 말하는 것이다(신뢰정책이 서비스 = 사람이 집을 수 없다).
  return kind === "human" ? "human" : kind === "service" ? "machine" : "unknown";
}

/** 배지 옆에 붙는 한 줄 근거 + 팝오버 본문. 근거를 못 만들면 축 이름만이라도 밝힌다. */
export function subjectBasisText(
  kind: PrincipalKind,
  subject: UsageSubject | undefined,
  basis: string | undefined,
): { short: string; desc: string } {
  const meta = basis ? BASIS_META[basis] : undefined;
  const trust = TRUST_AXIS_DESC[kind];
  if (subject === "human" || subject === "machine") {
    // 실사용 근거로 판정된 경우 — 신뢰정책 축을 **함께** 보여준다. 둘이 엇갈리는 것 자체가 정보다
    // (신뢰정책은 서비스인데 사람이 집고 있다 = 공유 역할 의심).
    return {
      short: meta?.short ?? "실사용 근거",
      desc: `${meta?.desc ?? "실사용 근거로 판정했습니다."}\n\n신뢰정책 축: ${trust}`,
    };
  }
  // 실사용 근거 없음 — 왜 없는지(관측 밖 vs 못 갈랐다)를 구분해 말한다.
  const why = meta?.desc ?? "실사용 근거가 없습니다.";
  return { short: meta?.short ?? "실사용 근거 없음", desc: `${why}\n\n신뢰정책 축: ${trust}` };
}

// AWS 서비스 principal → 짧은 표시명. 접미(`.amazonaws.com` / `.aws.internal`)를 떼고 첫 라벨만
// 남긴다. 실측에 `orchestrator.alpo.aws.internal` 처럼 `.amazonaws.com` 이 아닌 것도 있으므로
// 특정 도메인을 가정하지 않는다.
function trustLabel(principal: string): { text: string; color: "red" | "green" | "blue" | "grey" } {
  if (principal === "*") return { text: "모든 주체(*)", color: "red" };
  if (principal.includes(":saml-provider/")) return { text: `SAML: ${principal.split("/").pop()}`, color: "green" };
  if (principal.includes(":oidc-provider/")) return { text: `OIDC: ${principal.split("/").pop()}`, color: "green" };
  if (principal.endsWith(":root")) return { text: `계정 신뢰: ${accountOf(principal)}`, color: "grey" };
  if (principal.includes(":role/")) return { text: `역할 신뢰: ${principal.split("/").pop()}`, color: "grey" };
  if (principal.includes(":user/")) return { text: `사용자 신뢰: ${principal.split("/").pop()}`, color: "grey" };
  if (principal.includes(".")) {
    const first = principal.split(".")[0];
    return { text: first.charAt(0).toUpperCase() + first.slice(1), color: "blue" };
  }
  return { text: principal, color: "grey" };
}

/** 적용 대상 1건(표 행) — ARN 파싱 결과 + 두 축(신뢰정책·실사용)의 근거. */
interface TargetRow extends MemberRef {
  subject: SubjectView;
  subjectMeta: (typeof SUBJECT_META)[SubjectView];
  basis: { short: string; desc: string };
  usageSubject: UsageSubject | null;
  principalKind: PrincipalKind;
  trustPrincipals: string[];
  tags: Record<string, string>;
}

/** members + member_details → 표 행. member_details 가 비어도(구 run 산출물) ARN 정보만으로 동작한다. */
export function targetRows(entry: CatalogEntry): TargetRow[] {
  const byArn = new Map((entry.member_details ?? []).map((d) => [d.principal, d]));
  return entry.members
    .map((arn) => {
      const ref = parseMember(arn);
      const d = byArn.get(arn);
      // IAM 사용자는 신뢰정책이 없다 — 엔진이 identity_type 으로 human 을 준다. detail 이 없으면
      // ARN 형태로 같은 결론을 낸다(추측이 아니라 같은 규칙).
      const kind: PrincipalKind = d?.principal_kind ?? (ref.kind === "user" ? "human" : "unknown");
      // 구 run 산출물에는 `usage_subject` 가 없다 → undefined 로 두고 신뢰정책 축으로 내려간다.
      // 여기서 "none" 을 채워 넣으면 근거 문장이 "주체 신호 없음" 이라고 **관측했다고 주장한다**.
      const subject = d?.usage_subject;
      return {
        ...ref,
        principalKind: kind,
        usageSubject: subject ?? null,
        subject: subjectView(kind, subject),
        subjectMeta: SUBJECT_META[subjectView(kind, subject)],
        basis: subjectBasisText(kind, subject, d?.usage_subject_basis),
        trustPrincipals: d?.trust_principals ?? [],
        tags: d?.tags ?? {},
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}

/** 계정 선택 시 persona 를 그 계정 멤버로 좁힌다. members 와 member_details 를 **함께** 좁혀야 한다. */
export function narrowToAccount(entry: CatalogEntry, account: string): CatalogEntry {
  const members = entry.members.filter((m) => accountOf(m) === account);
  const member_details = (entry.member_details ?? []).filter((d) => accountOf(d.principal) === account);
  return { ...entry, members, member_details, member_count: members.length };
}

export default function PersonaReview() {
  const { data: allCatalog, loading } = useAsync<CatalogEntry[]>(() => api.getCatalog());
  const { selected: selectedAccount } = useAccounts();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  // 🔴 컨텍스트 객체(panel) 자체를 의존성에 넣으면 안 된다 — 패널 state 가 바뀔 때마다 새 객체가 되어
  // 등록 effect 가 재실행되고 무한 루프가 된다(실측: "Maximum update depth exceeded").
  // setter 두 개만 꺼내 쓴다. 둘은 provider 에서 렌더 간 참조가 고정돼 있다.
  const { setPanel, setOpen } = useSplitPanel();

  // 선택 계정으로 persona 필터 — CatalogEntry 에 account_id 가 없어 members ARN 에서 계정 파싱
  // (arn:aws:iam::<account>:...). 전체("")면 그대로.
  const catalog = useMemo(() => {
    if (!allCatalog) return allCatalog;
    if (!selectedAccount) return allCatalog;
    return allCatalog.map((e) => narrowToAccount(e, selectedAccount)).filter((e) => e.members.length > 0);
  }, [allCatalog, selectedAccount]);

  // 우측 패널에 무엇을 띄울지. persona + 최초 탭. 편집기 내부 상태는 PersonaEditorPanel 이 소유한다
  // (여기서 들고 있으면 패널을 재등록하는 useEffect 의 의존성이 폭발해 닫힘·초기화 버그가 난다).
  const [target, setTarget] = useState<{ entry: CatalogEntry; tab: PanelTab } | null>(null);

  const openPanel = useCallback(
    (entry: CatalogEntry, tab: PanelTab) => {
      setTarget({ entry, tab });
      setOpen(true);
    },
    [setOpen],
  );
  const closePanel = useCallback(() => {
    setTarget(null);
    setPanel(null);
  }, [setPanel]);

  // ---- 딥링크: 조치 필요 항목의 '권한 축소' 행에서 "Persona 검토에서 고치기" 로 온 경우 ----
  // 사람이 검색창에 ARN 을 타이핑해 자기 역할이 어느 persona 인지 찾던 일을 주소가 대신한다
  // (같은 역방향 조회를 쓴다). `from=cleanup` 은 돌아갈 길이다 — 조치 완료 표시는 그 화면에서만 한다.
  const principalParam = searchParams.get("principal");
  const fromParam = searchParams.get("from");
  const linked = useMemo(
    () => (principalParam ? personaOfPrincipal(catalog ?? [], principalParam) : null),
    [catalog, principalParam],
  );
  // 🔴 파급 범위는 **계정 선택으로 좁히기 전** 카탈로그에서 센다. persona 정책은 계정별이 아니라
  //    persona 단위로 적용되므로, 좁힌 수를 적으면 실제 영향보다 적게 말한다.
  const linkedAll = useMemo(
    () => (principalParam ? personaOfPrincipal(allCatalog ?? [], principalParam) : null),
    [allCatalog, principalParam],
  );

  // 딥링크는 정책 편집 패널을 **자동으로 연다**. 🔴 처리한 파라미터를 ref 에 적어 한 번만 연다 —
  // 사람이 패널을 닫으면 다시 열리지 않아야 한다(열림 상태를 effect 의 조건에 넣으면 닫는 즉시
  // 재등록돼 루프가 된다. 이 파일 위쪽 주석의 "Maximum update depth exceeded" 와 같은 함정이다).
  const autoOpened = useRef<string | null>(null);
  useEffect(() => {
    if (!principalParam || !linked) return;
    if (autoOpened.current === principalParam) return;
    autoOpened.current = principalParam;
    openPanel(linked, "policy");
  }, [principalParam, linked, openPanel]);

  // 패널 등록. 의존성은 target/closePanel/setPanel 뿐 — 편집기 상태가 바뀌거나 패널 state 가
  // 갱신될 때 재등록하지 않는다(재등록하면 편집 중인 내용이 초기화되고 루프가 된다).
  useEffect(() => {
    if (!target) return;
    setPanel({
      header: target.entry.persona,
      content: (
        <PersonaEditorPanel
          key={`${target.entry.persona}:${target.tab}`}
          entry={target.entry}
          defaultTab={target.tab}
          onClose={closePanel}
        />
      ),
    });
  }, [target, closePanel, setPanel]);

  // 🔴 이 화면을 **떠날 때** 패널을 내린다. `SplitPanelProvider` 는 Router 보다 위에 있어서
  //   (App.tsx) 페이지가 언마운트돼도 등록해 둔 내용이 그대로 남는다 — 적용 대상/정책 편집을 열어
  //   둔 채 '조치 필요 항목' 으로 이동하면 아예 다른 기능 위에 persona 패널이 계속 떠 있었다
  //   (사용자 피드백 2026-09-11, 목 렌더로 재현: 이동 후에도 "사용 주체"·persona 명이 DOM 에 남음).
  //   위의 등록 effect 에 cleanup 을 달면 target 이 바뀔 때마다 닫혔다 열려 깜빡이므로
  //   **언마운트 전용** effect 로 분리한다(`setPanel` 은 useCallback([]) 으로 고정된 참조다).
  useEffect(() => () => setPanel(null), [setPanel]);

  if (loading || !catalog) {
    return <Box padding="xxl" textAlign="center"><Spinner size="large" /></Box>;
  }

  const columnDefs = catalogColumns(selectedAccount, openPanel);
  // 전체 뷰: 계정별 ExpandableSection 으로 먼저 구분(각 섹션에 그 계정 persona). 개별 계정: 표 하나.
  let catalogView: React.ReactNode;
  if (selectedAccount) {
    catalogView = (
      <Table variant="container" wrapLines
        header={<Header variant="h2" counter={`(${catalog.length})`}>Persona 카탈로그 · 계정 {selectedAccount}</Header>}
        columnDefinitions={columnDefs} items={catalog} />
    );
  } else {
    // members ARN 으로 계정 추출 → 계정별 persona 묶음(persona 가 여러 계정에 걸치면 각 계정 섹션에 등장).
    const accts = [...new Set(catalog.flatMap((e) => e.members.map(accountOf)))].sort();
    catalogView = (
      <SpaceBetween size="s">
        <Box variant="h2">Persona 카탈로그 · 전체 계정 ({accts.length}개 계정)</Box>
        {accts.map((acct) => {
          const rows = catalog
            .filter((e) => e.members.some((m) => accountOf(m) === acct))
            .map((e) => narrowToAccount(e, acct));
          return (
            <ExpandableSection key={acct} variant="container" defaultExpanded
              headerText={`계정 ${acct}`} headerCounter={`(${rows.length} personas)`}>
              <Table variant="embedded" wrapLines columnDefinitions={columnDefs} items={rows} />
            </ExpandableSection>
          );
        })}
      </SpaceBetween>
    );
  }

  return (
    <ContentLayout header={<Header variant="h1" description={`실사용 기반 bottom-up persona 카탈로그. ${selectedAccount ? `계정 ${selectedAccount}` : "전체 계정 — 계정별로 구분"}`}>Persona 검토</Header>}>
      <SpaceBetween size="l">
        {principalParam && <LinkedPrincipalBanner
          principal={principalParam}
          narrowed={linked}
          full={linkedAll}
          selectedAccount={selectedAccount}
          onBack={fromParam === "cleanup" ? () => navigate("/cleanup?group=reduce_scope") : null}
          onOpen={() => linked && openPanel(linked, "policy")}
        />}
        <PrincipalLookup catalog={catalog} onOpen={(e) => openPanel(e, "policy")} />
        {catalogView}
      </SpaceBetween>
    </ContentLayout>
  );
}

// ---- 우측 패널: 정책 편집 + 적용 대상 ----
// AppLayout 의 SplitPanel 슬롯은 하나뿐이라 두 화면을 각각 띄울 수 없다 → 한 패널 안 Tabs.
// 편집기 상태 전부를 이 컴포넌트가 소유한다(부모가 들고 있으면 패널 재등록마다 초기화된다).
function PersonaEditorPanel({
  entry,
  defaultTab,
  onClose,
}: {
  entry: CatalogEntry;
  defaultTab: PanelTab;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<PanelTab>(defaultTab);
  const [editActions, setEditActions] = useState<PolicyAction[]>(() => entry.actions.map((a) => ({ ...a })));

  // 권한 표시: 그룹 기준(서비스/동작) + **근거 3분할** 필터.
  // 예전에는 "미사용·불명 숨기기" 토글 하나였다 — 두 종류를 한 스위치로 묶으면 "근거 불명만 따로
  // 보고 담당자에게 물어볼" 방법이 없다. 미사용 확정과 근거 불명은 **다른 사실**이고(안 썼다 vs
  // 알 수 없다) 사람이 할 다음 행동도 다르다(제거 vs 확인).
  const [groupBy, setGroupBy] = useState<"service" | "access">("service");
  const [evidence, setEvidence] = useState<EvidenceFilter>("all");

  // 정책 JSON: 편집 모드 여부 + 편집 중 텍스트
  const [jsonEditing, setJsonEditing] = useState(false);
  const [jsonDraft, setJsonDraft] = useState("");
  const [jsonError, setJsonError] = useState<string | null>(null);

  // 승인 플로우 상태머신: idle → confirmApprove → artifacts → confirmProvision → provisioning → done
  const [flow, setFlow] = useState<"idle" | "confirmApprove" | "artifacts" | "confirmProvision" | "provisioning" | "provisioned">("idle");
  const [terraform, setTerraform] = useState<TerraformArtifact | null>(null);
  // 반영 산출물. IdC 를 쓰지 않는 고객은 여기에 Permission Set 이 **없다** — 대신 IAM 정책/역할이
  // 있어서 승인한 정책을 실제로 apply 할 수 있다(예전엔 PS 뿐이라 반영할 물건이 없었다).
  const [artifacts, setArtifacts] = useState<PolicyArtifact[]>([]);
  const [artifactTab, setArtifactTab] = useState<string>("");
  const [provisionArn, setProvisionArn] = useState<string | null>(null);
  const [provisionErr, setProvisionErr] = useState<string | null>(null);
  const [approvedMsg, setApprovedMsg] = useState<string | null>(null);
  const download = useDownload();

  // 좌측 체크리스트에서 생성한 JSON (편집 모드가 아닐 때 표시)
  const generatedJson = useMemo(() => buildPolicy(entry.persona, editActions), [entry.persona, editActions]);
  const effectiveJson = jsonEditing ? jsonDraft : generatedJson;

  // 표시용 그룹: 근거 3분할 필터 적용 후 서비스/동작으로 묶음.
  const visibleGroups = useMemo(() => {
    const base = editActions.filter((a) => evidenceOf(a) === evidence || evidence === "all");
    return groupActions(base, groupBy).filter((g) => g.items.length > 0);
  }, [editActions, groupBy, evidence]);

  // 편집 모드 진입 시 현재 생성 JSON 을 draft 로 복사
  useEffect(() => {
    if (jsonEditing) setJsonDraft(generatedJson);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jsonEditing]);

  function toggle(action: string, included: boolean) {
    setEditActions((prev) => prev.map((a) => (a.action === action ? { ...a, included } : a)));
  }

  /** 군집 일괄 포함/제외(F16). bedrock 13개처럼 한 서비스에 action 이 많으면 하나씩 누르는 것이
   *  사실상 불가능하다(사용자 피드백 2026-09-11).
   *
   *  🔴 **범위는 인자로 받은 action 들뿐**이다 — 호출부는 근거 필터를 통과해 **화면에 보이는 것**만
   *  넘긴다(`visibleGroups` 는 `evidenceOf(a) === evidence` 로 걸러진 목록이다). 군집 전체를 서비스
   *  접두로 다시 찾아 끄면, '근거 불명' 만 보고 있는 사람이 실사용 권한까지 조용히 끄게 된다. */
  function toggleActions(actions: string[], included: boolean) {
    const scope = new Set(actions);
    setEditActions((prev) => prev.map((a) => (scope.has(a.action) ? { ...a, included } : a)));
  }

  // 편집된 JSON 을 검증하고 체크리스트에 동기화
  function applyJsonEdits() {
    const acts = extractActions(jsonDraft);
    if (!acts) {
      setJsonError("유효한 JSON 이 아닙니다. IAM 정책 문서 형식을 확인하세요.");
      return;
    }
    setJsonError(null);
    setEditActions((prev) => {
      const known = new Map(prev.map((a) => [a.action, a]));
      // JSON 에 있는 action = 포함. 목록에 없던 action(범위 밖 수동 추가)은 신규 행으로.
      const next: PolicyAction[] = [];
      for (const a of prev) next.push({ ...a, included: acts.includes(a.action) });
      for (const act of acts) {
        // 사람이 JSON 에 직접 타이핑한 action = 명시적 포함. 근거를 못 찾은 상태가 아니므로
        // undetermined=false 다(불명 배지를 붙이면 사용자 자신의 입력을 의심하는 화면이 된다).
        if (!known.has(act)) {
          next.push({ action: act, used: false, included: true, undetermined: false, last_used: null, count_observed: 0 });
        }
      }
      return next;
    });
    setJsonEditing(false);
  }

  async function doApprove() {
    const res = await api.approvePersona(entry.persona, effectiveJson);
    setTerraform(res.terraform);
    // 구 백엔드(artifacts 미지원)와도 동작해야 한다 — 없으면 빈 배열이 되고 산출물 탭만 비어 보인다.
    const arts = res.artifacts ?? [];
    setArtifacts(arts);
    setArtifactTab(arts[0]?.target ?? "");
    setApprovedMsg(`${res.entry.persona} 정책이 승인되었습니다.`);
    setFlow("artifacts");
  }

  // 현재 보고 있는 산출물 / PS 산출물(있을 때만 IdC 생성 버튼을 노출).
  const shownArtifact = artifacts.find((a) => a.target === artifactTab) ?? artifacts[0] ?? null;
  const hasPermissionSet = artifacts.some((a) => a.target === "permission_set_tf");

  async function doProvision() {
    if (!terraform) return;
    setProvisionErr(null);
    setFlow("provisioning");
    try {
      const res = await api.provisionPermissionSet(terraform.persona);
      setProvisionArn(res.permission_set_arn);
      setFlow("provisioned");
    } catch (e) {
      // 실패 시 무한 로딩 대신 확인 모달로 되돌리고 오류 표시.
      setProvisionErr(e instanceof Error ? e.message : "IdC Permission Set 생성에 실패했습니다.");
      setFlow("confirmProvision");
    }
  }

  const includedCount = editActions.filter((a) => a.included).length;
  // 근거 3분할 — 미사용 확정과 근거 불명을 **합치지 않는다**(합치면 "안 쓰니 지워도 된다" 는 잘못된
  // 권고가 된다). 실사용 / 미사용 확정 / 근거 불명은 서로 배타적이고 합이 전체다.
  const evidenceCounts = useMemo(() => {
    const c: Record<Evidence, number> = { used: 0, unused: 0, undetermined: 0 };
    for (const a of editActions) c[evidenceOf(a)] += 1;
    return c;
  }, [editActions]);
  const rows = useMemo(() => targetRows(entry), [entry]);

  return (
    <>
      <Tabs
        activeTabId={tab}
        onChange={(e) => setTab(e.detail.activeTabId as PanelTab)}
        tabs={[
          {
            id: "policy",
            label: "정책 편집",
            content: (
              <SpaceBetween size="m">
                {approvedMsg && <Alert type="success" dismissible onDismiss={() => setApprovedMsg(null)}>{approvedMsg}</Alert>}
                <Header
                  variant="h3"
                  // 🔴 예전 문구(`실사용=기본 포함 · 미사용=기본 제외 …`)는 **전제를 빼먹어서**
                  //   서로 배척되는 말로 읽혔다: "실사용이라 들어온 목록인데 왜 미사용이 있나"
                  //   (사용자 피드백 2026-09-11). 빠진 전제는 이 목록의 정체다 — 여기 있는 것은
                  //   실사용 action 이 아니라 **지금 부여돼 있는 권한 전부**이고, 사용 근거는 스위치의
                  //   초기 상태만 정한다. 전제를 첫 문장으로 올린다.
                  description={
                    `이 목록은 지금 부여돼 있는 권한 전부입니다 — 사용 근거는 스위치의 처음 상태만 정합니다. ` +
                    `실사용=켜짐 · ${windowText(entry)} 사용 기록 없음=꺼짐 · ` +
                    `근거 불명(사용 여부를 확인할 수 없음)=꺼짐이나 삭제 전 담당자 확인 필요. ` +
                    `꺼진 권한은 승인하는 정책에서 빠집니다.`
                  }
                  actions={
                    <SpaceBetween direction="horizontal" size="xs">
                      <SegmentedControl
                        selectedId={groupBy}
                        onChange={(e) => setGroupBy(e.detail.selectedId as "service" | "access")}
                        label="그룹 기준"
                        options={[
                          { id: "service", text: "서비스별" },
                          { id: "access", text: "동작별" },
                        ]}
                      />
                      {/* 근거 3분할. 숨김 토글이 아니라 **선택**이다 — 근거 불명만 골라 담당자에게
                          물어보는 것이 이 화면에서 가장 자주 하는 일이고, 숨김 토글로는 그게 안 된다. */}
                      <SegmentedControl
                        selectedId={evidence}
                        onChange={(e) => setEvidence(e.detail.selectedId as EvidenceFilter)}
                        label="사용 근거 필터"
                        options={[
                          { id: "all", text: `전체 (${editActions.length})` },
                          { id: "used", text: `${EVIDENCE_LABEL.used} (${evidenceCounts.used})` },
                          { id: "unused", text: `${EVIDENCE_LABEL.unused} (${evidenceCounts.unused})` },
                          { id: "undetermined", text: `${EVIDENCE_LABEL.undetermined} (${evidenceCounts.undetermined})` },
                        ]}
                      />
                    </SpaceBetween>
                  }
                >
                  Action ({includedCount}/{editActions.length})
                </Header>
                {/* 패널 폭이 좁아 좌/우 2단은 못 쓴다 → 체크리스트를 먼저, JSON 은 접이식으로 아래. */}
                <div style={{ maxHeight: 420, overflow: "auto" }}>
                  <SpaceBetween size="xs">
                    {visibleGroups.map((g) => {
                      const groupIncluded = g.items.filter((a) => a.included).length;
                      const allIn = groupIncluded === g.items.length;
                      return (
                        <ExpandableSection
                          key={g.key}
                          variant="container"
                          headerText={g.label}
                          // 카운터는 **보이는 것 기준**이다(근거 필터가 걸려 있으면 그 부분집합) —
                          // 일괄 스위치의 범위와 같은 수를 보여야 눌렀을 때 결과가 예측된다.
                          headerCounter={`(포함 ${groupIncluded}/${g.items.length})`}
                          // F16 일괄 포함/제외. `indeterminate` 로 "일부만 포함" 을 구분한다 —
                          // 없으면 부분 선택이 '전부 꺼짐' 으로 보여, 한 번 누르면 켜질 것 같은데
                          // 실제로는 전부 꺼지는(또는 그 반대의) 조작이 된다.
                          headerActions={
                            <Checkbox
                              checked={allIn}
                              indeterminate={groupIncluded > 0 && !allIn}
                              onChange={(e) => toggleActions(g.items.map((a) => a.action), e.detail.checked)}
                              ariaLabel={`${g.label} ${g.items.length}개 일괄 포함/제외`}
                            >
                              {/* 라벨은 **상태**를 말한다(체크=전부 포함). 조작 이름("전체 제외")으로
                                  바꿔 쓰면 체크된 상자에 '제외' 가 붙어 무엇이 참인지 알 수 없다. */}
                              전체 포함
                            </Checkbox>
                          }
                        >
                          <Table
                            variant="embedded"
                            columnDefinitions={[
                              {
                                id: "toggle", header: "포함", width: 70,
                                cell: (a: PolicyAction) => <Toggle checked={a.included} onChange={(e) => toggle(a.action, e.detail.checked)} />,
                              },
                              {
                                id: "action", header: "Action", minWidth: 200, cell: (a: PolicyAction) => (
                                  <SpaceBetween direction="horizontal" size="xxs">
                                    <Box fontWeight={a.used ? "normal" : "bold"}>{a.action}</Box>
                                    {!a.used && (
                                      a.undetermined
                                        ? <Badge color="grey">근거 불명 · 검토</Badge>
                                        : <Badge color="blue">미사용 · 검토</Badge>
                                    )}
                                    {groupBy === "service" && (
                                      <Badge color={accessKindOf(a.action) === "write" ? "red" : "grey"}>
                                        {accessKindOf(a.action) === "write" ? "쓰기" : "읽기"}
                                      </Badge>
                                    )}
                                  </SpaceBetween>
                                ),
                              },
                              {
                                // 이 화면의 사용 정본은 **마지막 사용 시각**이다(횟수가 아니다).
                                // Access Advisor 의 action-level `LastAccessedTime` 은 최대 400일까지
                                // 잘리지 않으므로 CloudTrail 창 길이에 좌우되지 않고, 제거/유지 결정에
                                // 필요한 것도 "몇 번" 이 아니라 "언제 마지막으로" 다.
                                id: "usage", header: "최근 사용", cell: (a: PolicyAction) =>
                                  a.used ? (
                                    <StatusIndicator type="success">{fmtLastUsed(a.last_used)}</StatusIndicator>
                                  ) : a.undetermined ? (
                                    // "안 썼다"가 아니라 "알 수 없다". Access Advisor 가 이 action 을
                                    // 추적하지 않고 CloudTrail(단일 리전·관리 이벤트)에도 안 잡혔다.
                                    <StatusIndicator type="pending">사용 여부 확인 불가</StatusIndicator>
                                  ) : (
                                    <StatusIndicator type="stopped">{windowText(entry)} 사용 기록 없음</StatusIndicator>
                                  ),
                              },
                              // 🔴 횟수 컬럼은 **관측 구간이 임계치 이상일 때만** 존재한다.
                              //   "횟수(0일)" 이 실제로 나왔고(사용자 피드백 2026-09-11), 몇 시간
                              //   창의 횟수는 총 사용 횟수가 아니다 → 표기 자체를 없앤다.
                              //   `count_observed` 는 산출물에 그대로 남는다(화면만 조건부).
                              ...(showsCount(entry)
                                ? [{
                                    id: "count",
                                    header: `횟수(${entry.observed_window_days}일)`,
                                    width: 110,
                                    cell: (a: PolicyAction) =>
                                      a.count_observed > 0 ? (
                                        <Box>{a.count_observed.toLocaleString()}회</Box>
                                      ) : a.used ? (
                                        <Box color="text-status-inactive" fontSize="body-s">집계 없음</Box>
                                      ) : (
                                        <Box color="text-status-inactive">—</Box>
                                      ),
                                  }]
                                : []),
                            ]}
                            items={g.items}
                          />
                        </ExpandableSection>
                      );
                    })}
                    {visibleGroups.length === 0 && (
                      // 어느 칸이 비었는지 밝힌다 — "권한이 없다" 로 읽히면 정책이 빈 것으로 오해한다.
                      <Box color="text-status-inactive" padding="s">
                        {evidence === "all"
                          ? "표시할 권한이 없습니다."
                          : `${EVIDENCE_LABEL[evidence]}으로 분류된 권한이 없습니다.`}
                      </Box>
                    )}
                  </SpaceBetween>
                </div>

                <ExpandableSection
                  variant="container"
                  // 🔴 Action 수를 헤더에 적는다. 스위치를 껐는데 JSON 이 안 바뀌는 것처럼 보였다는
                  //   보고가 있었다(사용자 피드백 2026-09-11). 배선은 정상이다(토글 → editActions →
                  //   generatedJson, 목 렌더로 5→4 확인). 안 보인 이유는 **어디가 바뀌었는지 보이지
                  //   않기 때문**이다 — Action 배열이 수백 줄인데 `pre` 는 320px 만 보여 주므로 한 줄이
                  //   사라지는 변화가 화면 밖에서 일어난다. 헤더 숫자는 항상 보이는 자리에서 바뀐다.
                  //   (편집 모드에서는 draft 가 정본이라 토글을 따라가지 않는 것이 맞다 — 그 사실도
                  //   헤더가 "편집 중" 으로 말한다.)
                  headerText={`정책 JSON ${jsonEditing ? "(편집 중 — 위 스위치를 따라가지 않습니다)" : `(실시간 · Action ${includedCount}개)`}`}
                  headerActions={
                    jsonEditing ? (
                      <SpaceBetween direction="horizontal" size="xs">
                        <Button onClick={() => { setJsonEditing(false); setJsonError(null); }}>취소</Button>
                        <Button variant="primary" onClick={applyJsonEdits}>적용</Button>
                      </SpaceBetween>
                    ) : (
                      <Button iconName="edit" onClick={() => setJsonEditing(true)}>JSON 편집</Button>
                    )
                  }
                >
                  <SpaceBetween size="s">
                    {jsonError && <Alert type="error">{jsonError}</Alert>}
                    {jsonEditing ? (
                      <>
                        <Alert type="info">위 목록 범위 밖 권한이 필요하면 여기서 직접 추가하세요. 적용 시 목록에 반영됩니다.</Alert>
                        <Textarea value={jsonDraft} onChange={(e) => setJsonDraft(e.detail.value)} rows={16} spellcheck={false} />
                      </>
                    ) : (
                      <Box variant="code">
                        <pre style={{ margin: 0, whiteSpace: "pre-wrap", fontFamily: "Monaco, Menlo, monospace", fontSize: 12, lineHeight: 1.5, maxHeight: 320, overflow: "auto" }}>
                          {effectiveJson}
                        </pre>
                      </Box>
                    )}
                  </SpaceBetween>
                </ExpandableSection>

                <SpaceBetween direction="horizontal" size="xs">
                  <Button variant="primary" disabled={jsonEditing} onClick={() => setFlow("confirmApprove")}>이 정책으로 승인</Button>
                  <Button onClick={onClose}>닫기</Button>
                </SpaceBetween>
              </SpaceBetween>
            ),
          },
          {
            id: "targets",
            label: `적용 대상 (${rows.length})`,
            content: (
              <TargetsTab
                persona={entry.persona}
                rows={rows}
                download={download}
                observedWindow={entry}
              />
            ),
          },
        ]}
      />

      {/* 1) 승인 확인 */}
      <Modal
        visible={flow === "confirmApprove"}
        onDismiss={() => setFlow("idle")}
        header="정책 승인 확인"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setFlow("idle")}>취소</Button>
              <Button variant="primary" onClick={doApprove}>승인</Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween size="s">
          <Box>
            {entry.persona} 를 {includedCount}개 action 으로 승인합니다. 승인 후 이 정책을 반영할 산출물
            (관리형 IAM 정책·역할 Terraform, 정책 JSON, Identity Center 사용 시 Permission Set)이 생성됩니다.
          </Box>
          {entry.ai_suggested && <Alert type="warning">AI 제안 persona 입니다 — 승인 시 사람 검증(human-in-the-loop)으로 기록됩니다.</Alert>}
        </SpaceBetween>
      </Modal>

      {/* 2) 반영 산출물 팝업 (형태 선택 + 다운로드 + IdC 생성 진입) */}
      <Modal
        visible={flow === "artifacts"}
        onDismiss={() => setFlow("idle")}
        size="large"
        header={`반영 산출물 — ${entry.persona}`}
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button onClick={() => setFlow("idle")}>닫기</Button>
              {shownArtifact && (
                <Button
                  iconName="download"
                  onClick={() =>
                    download(
                      shownArtifact.filename,
                      shownArtifact.content,
                      shownArtifact.language === "json" ? "application/json" : "text/plain",
                    )
                  }
                >
                  {shownArtifact.filename} 다운로드
                </Button>
              )}
              {/* IdC 를 쓰지 않는 고객에게는 이 버튼을 아예 보이지 않는다 — 눌러도 IdC 인스턴스가
                  없어 실패하고, "우리랑 상관없는 기능"을 권하는 화면이 된다. */}
              {hasPermissionSet && (
                <Button variant="primary" onClick={() => setFlow("confirmProvision")}>IdC에 Permission Set 생성…</Button>
              )}
            </SpaceBetween>
          </Box>
        }
      >
        {artifacts.length === 0 ? (
          <Alert type="warning">산출물을 받지 못했습니다. 승인은 저장되었으니 목록에서 다시 열어 보세요.</Alert>
        ) : (
          <SpaceBetween size="s">
            <Box variant="p">
              같은 정책을 <b>어떤 형태로 반영할지</b> 고르세요. 필요한 형태만 내려받아 쓰면 됩니다.
            </Box>
            <Tabs
              activeTabId={shownArtifact?.target ?? ""}
              onChange={(e) => setArtifactTab(e.detail.activeTabId)}
              tabs={artifacts.map((a) => ({
                id: a.target,
                label: a.label,
                content: (
                  <SpaceBetween size="s">
                    {a.notes.map((n, i) => (
                      // 첫 항목만 강조(그 산출물 고유의 주의). 나머지는 공통 제약.
                      <Alert key={i} type={i === 0 ? "warning" : "info"}>{n}</Alert>
                    ))}
                    <Box variant="code">
                      <pre style={{ margin: 0, whiteSpace: "pre-wrap", fontFamily: "Monaco, Menlo, monospace", fontSize: 12, lineHeight: 1.5, maxHeight: 320, overflow: "auto" }}>
                        {a.content}
                      </pre>
                    </Box>
                  </SpaceBetween>
                ),
              }))}
            />
          </SpaceBetween>
        )}
      </Modal>

      {/* 3) PS 생성 2차 확인 (실제 쓰기 게이트) */}
      <Modal
        visible={flow === "confirmProvision" || flow === "provisioning"}
        onDismiss={() => flow !== "provisioning" && setFlow("artifacts")}
        header="tooling 계정 IdC에 Permission Set 생성"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" disabled={flow === "provisioning"} onClick={() => setFlow("artifacts")}>취소</Button>
              <Button variant="primary" loading={flow === "provisioning"} onClick={doProvision}>생성 확인</Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween size="s">
          <Alert type="warning" header="실제 쓰기 작업입니다">
            이 도구는 기본적으로 읽기 전용입니다. 확인 시 <b>tooling 계정의 IAM Identity Center에 Permission Set 정의만</b> 생성됩니다.
            <ul style={{ margin: "8px 0 0", paddingLeft: 18 }}>
              <li>분석 대상(멤버) 계정은 <b>전혀 건드리지 않습니다</b>.</li>
              <li>account assignment(실제 권한 부여)는 <b>수행하지 않습니다</b> — 나중에 사람이 수동으로.</li>
            </ul>
          </Alert>
          {provisionErr && <Alert type="error" header="생성 실패">{provisionErr}</Alert>}
          {terraform && <Box>대상 Permission Set: <b>{terraform.permission_set_name}</b></Box>}
        </SpaceBetween>
      </Modal>

      {/* 4) 생성 완료 */}
      <Modal
        visible={flow === "provisioned"}
        onDismiss={() => setFlow("idle")}
        header="Permission Set 생성 완료"
        footer={<Box float="right"><Button variant="primary" onClick={() => setFlow("idle")}>완료</Button></Box>}
      >
        <SpaceBetween size="s">
          <StatusIndicator type="success">Permission Set 정의가 생성되었습니다.</StatusIndicator>
          {provisionArn && <Box variant="code" fontSize="body-s">{provisionArn}</Box>}
          <Alert type="info">account assignment 은 생성하지 않았습니다. IdC 콘솔에서 필요한 계정·그룹에 수동으로 할당하세요.</Alert>
        </SpaceBetween>
      </Modal>
    </>
  );
}

// ---- 적용 대상 탭 ----
// 고객 피드백: 멤버가 많으면 표 아래 접이식 목록으로는 못 쓴다. 검색·필터·CSV 가 필요하고,
// "이게 사람인가 서비스인가"에 근거와 함께 답해야 한다.
type KindFilter = "all" | SubjectView;

function TargetsTab({
  persona,
  rows,
  download,
  observedWindow,
}: {
  persona: string;
  rows: TargetRow[];
  download: (filename: string, content: string, mime?: string) => void;
  // 측정값(창 길이)과 기준값(표기 임계치)을 **둘 다** 받아야 문구를 결정할 수 있다 — 창 길이만
  // 넘기면 임계치를 여기서 다시 박게 되고(불변식 ④), 그게 F14-2 의 도달 불가 임계치가 생긴 경로다.
  observedWindow: { observed_window_days?: number | null; count_min_observed_days?: number | null };
}) {
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<KindFilter>("all");

  const counts = useMemo(() => {
    const c: Record<SubjectView, number> = { human: 0, machine: 0, unknown: 0 };
    for (const r of rows) c[r.subject] += 1;
    return c;
  }, [rows]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rows.filter(
      (r) =>
        (kind === "all" || r.subject === kind) &&
        (!q || r.name.toLowerCase().includes(q) || r.arn.toLowerCase().includes(q)),
    );
  }, [rows, query, kind]);

  function exportCsv() {
    // 필터된 것만 내보낸다(화면에 보이는 것과 파일이 달라지면 안 된다). ARN·이름에 쉼표가 들어갈 수
    // 있어 전 필드를 인용하고 내부 " 는 "" 로 이스케이프한다.
    const esc = (v: string) => `"${v.replace(/"/g, '""')}"`;
    // 두 축을 **따로** 낸다. 한 칼럼으로 합치면 파일을 받은 사람이 "이게 신뢰정책 판정인지 실사용
    // 판정인지" 를 되물을 수 없다(그 구분이 이 화면의 요점이다).
    const header = [
      "persona", "principal_arn", "name", "account",
      "usage_subject", "usage_subject_basis", "trust_policy_kind", "trust_principals", "tags",
    ];
    const body = filtered.map((r) =>
      [
        persona,
        r.arn,
        r.name,
        r.account,
        r.subjectMeta.label,
        r.basis.short,
        r.principalKind,
        r.trustPrincipals.join(" | "),
        Object.entries(r.tags).map(([k, v]) => `${k}=${v}`).join(" | "),
      ].map(esc).join(","),
    );
    download(`${persona}-적용대상.csv`, [header.map(esc).join(","), ...body].join("\n"), "text/csv");
  }

  return (
    <SpaceBetween size="s">
      <Alert type="info">
        이 목록은 <b>{persona} 정책을 적용할 대상</b>입니다. 각 대상의 <b>{windowText(observedWindow)}</b>{" "}
        관측된 실사용 이력을 합집합으로 모은 것이 이 persona 의 정책이므로, 개별 대상 입장에서는{" "}
        <b>필요 이상일 수 있습니다</b>. 반대로 <b>부족할 수도 있습니다</b> — 관측 구간 밖에서 쓴 action,
        데이터 이벤트(기본 미기록), 추적되지 않는 action 은 합집합에 없습니다. 반영 전 검증하세요.
      </Alert>
      <SegmentedControl
        selectedId={kind}
        onChange={(e) => setKind(e.detail.selectedId as KindFilter)}
        label="사용 주체 필터"
        options={[
          { id: "all", text: `전체 (${rows.length})` },
          { id: "human", text: `사람 (${counts.human})` },
          { id: "machine", text: `자동화 (${counts.machine})` },
          { id: "unknown", text: `판별 불가 (${counts.unknown})` },
        ]}
      />
      <Input
        value={query}
        onChange={(e) => setQuery(e.detail.value)}
        placeholder="이름 또는 ARN 일부로 검색"
        type="search"
      />
      <Table
        variant="embedded"
        wrapLines
        items={filtered}
        empty={<Box color="text-status-inactive" padding="s">조건에 맞는 적용 대상이 없습니다.</Box>}
        header={
          <Header
            counter={`(${filtered.length}/${rows.length})`}
            actions={<Button iconName="download" onClick={exportCsv} disabled={filtered.length === 0}>CSV</Button>}
          >
            적용 대상
          </Header>
        }
        columnDefinitions={[
          {
            id: "name", header: "이름", minWidth: 160,
            cell: (r: TargetRow) => (
              <SpaceBetween size="xxs">
                <Box fontWeight="bold">{r.name}</Box>
                <Popover dismissButton={false} position="top" size="large" triggerType="text"
                  content={<Box fontSize="body-s">{r.arn}</Box>}>
                  <Box fontSize="body-s" color="text-status-info">ARN</Box>
                </Popover>
              </SpaceBetween>
            ),
          },
          {
            id: "kind", header: "사용 주체(근거)", minWidth: 150,
            cell: (r: TargetRow) => (
              // 배지 **아래에 근거를 항상 노출**한다. 팝오버에만 두면 "판별 불가" 배지 15개를 보고도
              // 다음에 무엇을 할지 알 수 없다 — 이 화면을 고치는 이유가 그것이다.
              <Popover dismissButton={false} position="top" size="large" triggerType="custom"
                header={`${r.subjectMeta.label} · ${r.basis.short}`}
                content={<Box variant="p" fontSize="body-s">{r.basis.desc}</Box>}>
                <span style={{ cursor: "help" }}>
                  <SpaceBetween size="xxxs">
                    <Badge color={r.subjectMeta.color}>{r.subjectMeta.label}</Badge>
                    <Box fontSize="body-s" color="text-status-inactive">{r.basis.short}</Box>
                  </SpaceBetween>
                </span>
              </Popover>
            ),
          },
          {
            id: "trust", header: "신뢰 주체(근거)", minWidth: 180,
            cell: (r: TargetRow) => {
              if (r.kind === "user") return <Badge color="green">IAM 사용자</Badge>;
              if (r.trustPrincipals.length === 0) {
                return <Box fontSize="body-s" color="text-status-inactive">신뢰정책 미수집</Box>;
              }
              return (
                <SpaceBetween direction="horizontal" size="xxs">
                  {r.trustPrincipals.map((p) => {
                    const l = trustLabel(p);
                    return (
                      <Popover key={p} dismissButton={false} position="top" size="large" triggerType="custom" content={<Box fontSize="body-s">{p}</Box>}>
                        <span style={{ cursor: "help" }}><Badge color={l.color}>{l.text}</Badge></span>
                      </Popover>
                    );
                  })}
                </SpaceBetween>
              );
            },
          },
          {
            id: "tags", header: "태그(소유자 추정)", minWidth: 140,
            cell: (r: TargetRow) => {
              const entries = Object.entries(r.tags);
              if (entries.length === 0) return <Box fontSize="body-s" color="text-status-inactive">없음</Box>;
              return (
                <SpaceBetween size="xxs">
                  {entries.map(([k, v]) => (
                    <Box key={k} fontSize="body-s">{k}: {v}</Box>
                  ))}
                </SpaceBetween>
              );
            },
          },
          // 🔴 `width` 만 주면 지켜지지 않는다. 우측 패널은 폭이 좁고 앞 컬럼들이 minWidth 를
          //   차지하므로 Cloudscape 가 이 컬럼을 52px 까지 줄였고, 12자리 계정 ID 가 **한 글자씩
          //   세로로** 쌓였다(목 렌더 실측: 폭 52px · 높이 260px). `minWidth` 로 하한을 박고 셀을
          //   nowrap 으로 고정한다 — 줄바꿈 대신 표가 가로로 스크롤되는 쪽이 읽을 수 있다.
          {
            id: "account", header: "계정", width: 140, minWidth: 140,
            cell: (r: TargetRow) => <span style={{ whiteSpace: "nowrap" }}>{r.account}</span>,
          },
        ]}
      />
    </SpaceBetween>
  );
}
