import { useState, useMemo, useEffect, useCallback } from "react";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import Container from "@cloudscape-design/components/container";
import Table from "@cloudscape-design/components/table";
import Box from "@cloudscape-design/components/box";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Button from "@cloudscape-design/components/button";
import Badge from "@cloudscape-design/components/badge";
import Popover from "@cloudscape-design/components/popover";
import Input from "@cloudscape-design/components/input";
import Toggle from "@cloudscape-design/components/toggle";
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
} from "@/api/types";

/** 우측 패널 탭. 슬롯이 하나라 두 화면을 탭으로 합친다. */
type PanelTab = "policy" | "targets";

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
          {e.ai_suggested && <Badge color="blue">✦ AI 제안—검증 필요</Badge>}
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

// CloudTrail 이 **실제로 훑은** 구간 문구. `observed_window_days` 는 측정값이다 — 요청한 90일이
// 아니다(LookupEvents 는 최신순 페이지 상한이 있어 며칠만 덮이는 경우가 있다). 측정값이 없으면
// 일수를 말하지 않는다: 화면에 "90일" 을 박아 두면 측정하지 않은 숫자를 근거처럼 보여준다.
function windowText(days: number | null | undefined): string {
  return days == null ? "관측 구간" : `최근 ${days.toLocaleString()}일`;
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
// 신뢰정책(engine m2_normalizer)이 내려준 값을 그대로 보여준다. 사람의 분류를 저장하지 않으므로
// 여기엔 어떤 상태도 없다 — 매 run 의 소스가 곧 표시다.
const KIND_META: Record<PrincipalKind, { label: string; color: "green" | "blue" | "grey"; desc: string }> = {
  human: {
    label: "사람", color: "green",
    desc: "IAM 사용자이거나 신뢰정책이 SAML/OIDC 연합입니다 — 사람이 로그인해 씁니다. persona 정책 적용 대상.",
  },
  service: {
    label: "서비스", color: "blue",
    desc: "신뢰정책 주체가 AWS 서비스(Lambda·EC2·SSM 등)입니다 — 사람이 로그인할 수 없습니다. 기본적으로 persona 대상에서 제외됩니다.",
  },
  unknown: {
    label: "판별 불가", color: "grey",
    desc: "신뢰정책에 계정/역할(Principal.AWS)만 있어 사람인지 자동화인지 신뢰정책만으로는 갈릴 수 없습니다. 아래 신뢰 주체를 보고 소유 팀에 확인하세요.",
  },
};

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

/** 적용 대상 1건(표 행) — ARN 파싱 결과 + 신뢰정책 근거. */
interface TargetRow extends MemberRef {
  kindMeta: (typeof KIND_META)[PrincipalKind];
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
      return {
        ...ref,
        principalKind: kind,
        kindMeta: KIND_META[kind],
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

  // 권한 표시: 그룹 기준(서비스/동작) + 미사용 숨김(스크롤 감소)
  const [groupBy, setGroupBy] = useState<"service" | "access">("service");
  const [hideUnused, setHideUnused] = useState(false);

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

  // 표시용 그룹: 미사용 숨김 필터 적용 후 서비스/동작으로 묶음.
  const visibleGroups = useMemo(() => {
    const base = hideUnused ? editActions.filter((a) => a.used) : editActions;
    return groupActions(base, groupBy).filter((g) => g.items.length > 0);
  }, [editActions, groupBy, hideUnused]);

  // 편집 모드 진입 시 현재 생성 JSON 을 draft 로 복사
  useEffect(() => {
    if (jsonEditing) setJsonDraft(generatedJson);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jsonEditing]);

  function toggle(action: string, included: boolean) {
    setEditActions((prev) => prev.map((a) => (a.action === action ? { ...a, included } : a)));
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
  const unusedCount = editActions.filter((a) => !a.used).length;
  // 근거 불명 = 사용 기록이 없다는 뜻이 아니라 판정할 근거가 없다는 뜻. 미사용 수에서 떼어 센다.
  const undeterminedCount = editActions.filter((a) => !a.used && a.undetermined).length;
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
                  description={`실사용=기본 포함 · 미사용(${windowText(entry.observed_window_days)} 기록 없음)=기본 제외 · 근거 불명(사용 여부를 확인할 수 없음)=기본 제외이나 삭제 전 담당자 확인 필요`}
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
                      {/* 두 종류를 한 토글로 숨기지만 라벨엔 구분해 적는다 — '미사용 숨기기' 라고만
                          쓰면 근거 불명 항목까지 미사용으로 여기게 된다. */}
                      <Toggle checked={hideUnused} onChange={(e) => setHideUnused(e.detail.checked)}>
                        미사용·불명 숨기기
                        {unusedCount > 0
                          ? ` (미사용 ${unusedCount - undeterminedCount} · 불명 ${undeterminedCount})`
                          : ""}
                      </Toggle>
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
                      return (
                        <ExpandableSection
                          key={g.key}
                          variant="container"
                          headerText={g.label}
                          headerCounter={`(${groupIncluded}/${g.items.length})`}
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
                                id: "usage", header: "최근 사용", cell: (a: PolicyAction) =>
                                  a.used ? (
                                    <StatusIndicator type="success">{fmtLastUsed(a.last_used)}</StatusIndicator>
                                  ) : a.undetermined ? (
                                    // "안 썼다"가 아니라 "알 수 없다". Access Advisor 가 이 action 을
                                    // 추적하지 않고 CloudTrail(단일 리전·관리 이벤트)에도 안 잡혔다.
                                    <StatusIndicator type="pending">사용 여부 확인 불가</StatusIndicator>
                                  ) : (
                                    <StatusIndicator type="stopped">{windowText(entry.observed_window_days)} 사용 기록 없음</StatusIndicator>
                                  ),
                              },
                              {
                                id: "count",
                                header: entry.observed_window_days == null
                                  ? "관측 횟수"
                                  : `횟수(${entry.observed_window_days}일)`,
                                width: 110,
                                cell: (a: PolicyAction) =>
                                  a.count_observed > 0 ? (
                                    <Box>{a.count_observed.toLocaleString()}회</Box>
                                  ) : a.used ? (
                                    <Box color="text-status-inactive" fontSize="body-s">집계 없음</Box>
                                  ) : (
                                    <Box color="text-status-inactive">—</Box>
                                  ),
                              },
                            ]}
                            items={g.items}
                          />
                        </ExpandableSection>
                      );
                    })}
                    {visibleGroups.length === 0 && (
                      <Box color="text-status-inactive" padding="s">표시할 권한이 없습니다.</Box>
                    )}
                  </SpaceBetween>
                </div>

                <ExpandableSection
                  variant="container"
                  headerText={`정책 JSON ${jsonEditing ? "(편집 중)" : "(실시간)"}`}
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
                observedWindowDays={entry.observed_window_days}
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
type KindFilter = "all" | PrincipalKind;

function TargetsTab({
  persona,
  rows,
  download,
  observedWindowDays,
}: {
  persona: string;
  rows: TargetRow[];
  download: (filename: string, content: string, mime?: string) => void;
  observedWindowDays: number | null | undefined;
}) {
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<KindFilter>("all");

  const counts = useMemo(() => {
    const c: Record<PrincipalKind, number> = { human: 0, service: 0, unknown: 0 };
    for (const r of rows) c[r.principalKind] += 1;
    return c;
  }, [rows]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rows.filter(
      (r) =>
        (kind === "all" || r.principalKind === kind) &&
        (!q || r.name.toLowerCase().includes(q) || r.arn.toLowerCase().includes(q)),
    );
  }, [rows, query, kind]);

  function exportCsv() {
    // 필터된 것만 내보낸다(화면에 보이는 것과 파일이 달라지면 안 된다). ARN·이름에 쉼표가 들어갈 수
    // 있어 전 필드를 인용하고 내부 " 는 "" 로 이스케이프한다.
    const esc = (v: string) => `"${v.replace(/"/g, '""')}"`;
    const header = ["persona", "principal_arn", "name", "account", "kind", "trust_principals", "tags"];
    const body = filtered.map((r) =>
      [
        persona,
        r.arn,
        r.name,
        r.account,
        r.kindMeta.label,
        r.trustPrincipals.join(" | "),
        Object.entries(r.tags).map(([k, v]) => `${k}=${v}`).join(" | "),
      ].map(esc).join(","),
    );
    download(`${persona}-적용대상.csv`, [header.map(esc).join(","), ...body].join("\n"), "text/csv");
  }

  return (
    <SpaceBetween size="s">
      <Alert type="info">
        이 목록은 <b>{persona} 정책을 적용할 대상</b>입니다. 각 대상의 <b>{windowText(observedWindowDays)}</b>{" "}
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
          { id: "service", text: `서비스 (${counts.service})` },
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
            id: "kind", header: "사용 주체", minWidth: 120,
            cell: (r: TargetRow) => (
              <Popover dismissButton={false} position="top" size="medium" triggerType="custom"
                header={r.kindMeta.label} content={r.kindMeta.desc}>
                <span style={{ cursor: "help" }}><Badge color={r.kindMeta.color}>{r.kindMeta.label}</Badge></span>
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
          { id: "account", header: "계정", width: 130, cell: (r: TargetRow) => r.account },
        ]}
      />
    </SpaceBetween>
  );
}
