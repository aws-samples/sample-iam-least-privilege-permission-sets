import { useState, useMemo, useEffect } from "react";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import Container from "@cloudscape-design/components/container";
import Table from "@cloudscape-design/components/table";
import Grid from "@cloudscape-design/components/grid";
import Box from "@cloudscape-design/components/box";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Button from "@cloudscape-design/components/button";
import Badge from "@cloudscape-design/components/badge";
import Popover from "@cloudscape-design/components/popover";
import Toggle from "@cloudscape-design/components/toggle";
import SegmentedControl from "@cloudscape-design/components/segmented-control";
import ExpandableSection from "@cloudscape-design/components/expandable-section";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import Modal from "@cloudscape-design/components/modal";
import Spinner from "@cloudscape-design/components/spinner";
import Alert from "@cloudscape-design/components/alert";
import Textarea from "@cloudscape-design/components/textarea";
import { api } from "@/api/client";
import { useAsync } from "@/api/useAsync";
import { useAccounts } from "@/AccountContext";
import type { CatalogEntry, PolicyAction, TerraformArtifact } from "@/api/types";

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

// persona 멤버 ARN(arn:aws:iam::<account>:...) → 계정별 멤버 수(계정 asc). 전체 뷰에서 persona 가
// 어느 계정에 얼마나 걸쳐 있는지 보여준다.
function membersByAccount(members: string[]): { account: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const m of members) {
    const parts = m.split(":");
    const acct = parts.length > 4 ? parts[4] : "?";
    counts.set(acct, (counts.get(acct) ?? 0) + 1);
  }
  return [...counts.entries()].map(([account, count]) => ({ account, count })).sort((a, b) => a.account.localeCompare(b.account));
}

// persona 카탈로그 표의 컬럼 정의(전체 뷰·계정별 섹션 공통 재사용). selectedAccount 가 없고 persona 가
// 여러 계정에 걸치면 멤버 컬럼에 계정별 분해를 보여준다.
function catalogColumns(selectedAccount: string, openEditor: (e: CatalogEntry) => void) {
  return [
    {
      id: "persona", header: "Persona", minWidth: 180,
      cell: (e: CatalogEntry) => (
        <SpaceBetween direction="horizontal" size="xs">
          <Box fontWeight="bold">{e.persona}</Box>
          {e.ai_suggested && <Badge color="blue">✦ AI 제안—검증 필요</Badge>}
        </SpaceBetween>
      ),
    },
    { id: "desc", header: "설명", cell: (e: CatalogEntry) => e.description },
    {
      id: "members", header: "멤버(principal)", minWidth: 160,
      cell: (e: CatalogEntry) => {
        const byAcct = membersByAccount(e.members);
        if (!selectedAccount && byAcct.length > 1) {
          return (
            <SpaceBetween size="xxs">
              <Box fontWeight="bold">{e.member_count.toLocaleString()} (전체)</Box>
              {byAcct.map((b) => (
                <Box key={b.account} fontSize="body-s" color="text-body-secondary">{b.account}: {b.count.toLocaleString()}</Box>
              ))}
            </SpaceBetween>
          );
        }
        return e.member_count.toLocaleString();
      },
    },
    {
      id: "source", header: "합성 소스", minWidth: 200,
      cell: (e: CatalogEntry) => {
        const srcs = e.contributing_sources ?? [];
        const highConf = e.synthesis_source === "access_analyzer";
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
    { id: "status", header: "상태", width: 100, cell: (e: CatalogEntry) => statusIndicator(e.approval_status) },
    { id: "action", header: "", width: 130, minWidth: 130, cell: (e: CatalogEntry) => <Button onClick={() => openEditor(e)}><span style={{ whiteSpace: "nowrap" }}>정책 편집</span></Button> },
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

export default function PersonaReview() {
  const { data: allCatalog, loading } = useAsync<CatalogEntry[]>(() => api.getCatalog());
  const { selected: selectedAccount } = useAccounts();
  // 선택 계정으로 persona 필터 — CatalogEntry 에 account_id 가 없어 members ARN 에서 계정 파싱
  // (arn:aws:iam::<account>:...). 전체("")면 그대로. 특정 계정이면 그 계정 principal 을 멤버로
  // 가진 persona 만(멤버 목록도 해당 계정 것으로 좁힘 — member_count 근사).
  const catalog = useMemo(() => {
    if (!allCatalog) return allCatalog;
    if (!selectedAccount) return allCatalog;
    return allCatalog
      .map((e) => {
        const members = e.members.filter((m) => m.includes(`:${selectedAccount}:`));
        return { ...e, members, member_count: members.length };
      })
      .filter((e) => e.members.length > 0);
  }, [allCatalog, selectedAccount]);
  const [selected, setSelected] = useState<CatalogEntry | null>(null);
  const [editActions, setEditActions] = useState<PolicyAction[]>([]);

  // 권한 표시: 그룹 기준(서비스/동작) + 미사용 숨김(스크롤 감소)
  const [groupBy, setGroupBy] = useState<"service" | "access">("service");
  const [hideUnused, setHideUnused] = useState(false);

  // 정책 JSON: 편집 모드 여부 + 편집 중 텍스트
  const [jsonEditing, setJsonEditing] = useState(false);
  const [jsonDraft, setJsonDraft] = useState("");
  const [jsonError, setJsonError] = useState<string | null>(null);

  // 승인 플로우 상태머신: idle → confirmApprove → terraform → confirmProvision → provisioning → done
  const [flow, setFlow] = useState<"idle" | "confirmApprove" | "terraform" | "confirmProvision" | "provisioning" | "provisioned">("idle");
  const [terraform, setTerraform] = useState<TerraformArtifact | null>(null);
  const [provisionArn, setProvisionArn] = useState<string | null>(null);
  const [provisionErr, setProvisionErr] = useState<string | null>(null);
  const [approvedMsg, setApprovedMsg] = useState<string | null>(null);
  const download = useDownload();

  // 좌측 체크리스트에서 생성한 JSON (편집 모드가 아닐 때 표시)
  const generatedJson = useMemo(
    () => (selected ? buildPolicy(selected.persona, editActions) : ""),
    [selected, editActions],
  );
  const effectiveJson = jsonEditing ? jsonDraft : generatedJson;

  // 표시용 그룹: 미사용 숨김 필터 적용 후 서비스/동작으로 묶음. (early-return 이전에 둬야 hooks 순서 고정)
  const visibleGroups = useMemo(() => {
    const base = hideUnused ? editActions.filter((a) => a.used) : editActions;
    return groupActions(base, groupBy).filter((g) => g.items.length > 0);
  }, [editActions, groupBy, hideUnused]);

  // 편집 모드 진입 시 현재 생성 JSON 을 draft 로 복사
  useEffect(() => {
    if (jsonEditing) setJsonDraft(generatedJson);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jsonEditing]);

  function openEditor(entry: CatalogEntry) {
    setSelected(entry);
    setEditActions(entry.actions.map((a) => ({ ...a })));
    setJsonEditing(false);
    setJsonError(null);
    setApprovedMsg(null);
    setFlow("idle");
  }

  function toggle(action: string, included: boolean) {
    setEditActions((prev) => prev.map((a) => (a.action === action ? { ...a, included } : a)));
  }

  // 편집된 JSON 을 검증하고 좌측 체크리스트에 동기화
  function applyJsonEdits() {
    const acts = extractActions(jsonDraft);
    if (!acts) {
      setJsonError("유효한 JSON 이 아닙니다. IAM 정책 문서 형식을 확인하세요.");
      return;
    }
    setJsonError(null);
    setEditActions((prev) => {
      const known = new Map(prev.map((a) => [a.action, a]));
      // JSON 에 있는 action = 포함. 좌측에 없던 action(범위 밖 수동 추가)은 신규 행으로.
      const next: PolicyAction[] = [];
      for (const a of prev) next.push({ ...a, included: acts.includes(a.action) });
      for (const act of acts) {
        if (!known.has(act)) next.push({ action: act, used: false, included: true, last_used: null, count_90d: 0 });
      }
      return next;
    });
    setJsonEditing(false);
  }

  async function doApprove() {
    if (!selected) return;
    const res = await api.approvePersona(selected.persona, effectiveJson);
    setTerraform(res.terraform);
    setApprovedMsg(`${res.entry.persona} 정책이 승인되었습니다.`);
    setFlow("terraform");
  }

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

  if (loading || !catalog) {
    return <Box padding="xxl" textAlign="center"><Spinner size="large" /></Box>;
  }

  const includedCount = editActions.filter((a) => a.included).length;
  const unusedCount = editActions.filter((a) => !a.used).length;

  const columnDefs = catalogColumns(selectedAccount, openEditor);
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
    const accts = [...new Set(catalog.flatMap((e) => e.members.map((m) => m.split(":")[4] || "?")))].sort();
    catalogView = (
      <SpaceBetween size="s">
        <Box variant="h2">Persona 카탈로그 · 전체 계정 ({accts.length}개 계정)</Box>
        {accts.map((acct) => {
          const rows = catalog
            .filter((e) => e.members.some((m) => m.includes(`:${acct}:`)))
            .map((e) => {
              const members = e.members.filter((m) => m.includes(`:${acct}:`));
              return { ...e, members, member_count: members.length };
            });
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
        {catalogView}

        {selected && (
          <Container header={<Header variant="h2" description="좌측 토글 또는 우측 JSON 직접 편집. 편집 시 좌↔우 동기화됩니다.">정책 편집기 — {selected.persona}</Header>}>
            <SpaceBetween size="m">
              {approvedMsg && <Alert type="success" dismissible onDismiss={() => setApprovedMsg(null)}>{approvedMsg}</Alert>}
              <Grid gridDefinition={[{ colspan: 6 }, { colspan: 6 }]}>
                {/* 좌: action 체크리스트 — 서비스/동작 기준 카테고리화, 미사용 숨김 */}
                <SpaceBetween size="s">
                  <Header
                    variant="h3"
                    description="실사용 권한=기본 포함 · 미사용 권한(부여됐으나 90일 미사용)=기본 제외, 검토 후 판단 · 토글로 최종 포함/제외"
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
                        <Toggle checked={hideUnused} onChange={(e) => setHideUnused(e.detail.checked)}>
                          미사용 권한 숨기기{unusedCount > 0 ? ` (${unusedCount})` : ""}
                        </Toggle>
                      </SpaceBetween>
                    }
                  >
                    Action ({includedCount}/{editActions.length})
                  </Header>
                  <div style={{ maxHeight: 440, overflow: "auto" }}>
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
                                  id: "action", header: "Action", cell: (a: PolicyAction) => (
                                    <SpaceBetween direction="horizontal" size="xxs">
                                      <Box fontWeight={a.used ? "normal" : "bold"}>{a.action}</Box>
                                      {!a.used && <Badge color="blue">미사용 · 검토</Badge>}
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
                                    ) : (
                                      <StatusIndicator type="stopped">90일간 미사용</StatusIndicator>
                                    ),
                                },
                                {
                                  id: "count", header: "횟수(90d)", width: 110, cell: (a: PolicyAction) =>
                                    a.count_90d > 0 ? (
                                      <Box>{a.count_90d.toLocaleString()}회</Box>
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
                </SpaceBetween>
                {/* 우: 정책 JSON (보기/편집 전환) */}
                <SpaceBetween size="s">
                  <Header
                    variant="h3"
                    actions={
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
                    정책 JSON {jsonEditing ? "(편집 중)" : "(실시간)"}
                  </Header>
                  {jsonError && <Alert type="error">{jsonError}</Alert>}
                  {jsonEditing ? (
                    <>
                      <Alert type="info">좌측 action 범위 밖 권한이 필요하면 여기서 직접 추가하세요. 적용 시 좌측 목록에 반영됩니다.</Alert>
                      <Textarea value={jsonDraft} onChange={(e) => setJsonDraft(e.detail.value)} rows={18} spellcheck={false} />
                    </>
                  ) : (
                    <Box variant="code">
                      <pre style={{ margin: 0, whiteSpace: "pre-wrap", fontFamily: "Monaco, Menlo, monospace", fontSize: 12, lineHeight: 1.5, maxHeight: 420, overflow: "auto" }}>
                        {effectiveJson}
                      </pre>
                    </Box>
                  )}
                  <SpaceBetween direction="horizontal" size="xs">
                    <Button variant="primary" disabled={jsonEditing} onClick={() => setFlow("confirmApprove")}>이 정책으로 승인</Button>
                    <Button onClick={() => setSelected(null)}>닫기</Button>
                  </SpaceBetween>
                </SpaceBetween>
              </Grid>
            </SpaceBetween>
          </Container>
        )}
      </SpaceBetween>

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
        {selected && (
          <SpaceBetween size="s">
            <Box>{selected.persona} 를 {includedCount}개 action 으로 승인합니다. 승인 후 Permission Set Terraform 이 생성됩니다.</Box>
            {selected.ai_suggested && <Alert type="warning">AI 제안 persona 입니다 — 승인 시 사람 검증(human-in-the-loop)으로 기록됩니다.</Alert>}
          </SpaceBetween>
        )}
      </Modal>

      {/* 2) Terraform 팝업 (다운로드 + PS 생성 진입) */}
      <Modal
        visible={flow === "terraform"}
        onDismiss={() => setFlow("idle")}
        size="large"
        header={terraform ? `Permission Set Terraform — ${terraform.permission_set_name}` : ""}
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button onClick={() => setFlow("idle")}>닫기</Button>
              {terraform && <Button iconName="download" onClick={() => download(terraform.filename, terraform.hcl)}>.tf 다운로드</Button>}
              <Button variant="primary" onClick={() => setFlow("confirmProvision")}>IdC에 Permission Set 생성…</Button>
            </SpaceBetween>
          </Box>
        }
      >
        {terraform && (
          <SpaceBetween size="s">
            <Alert type="info">account assignment(멤버계정 권한 부여)은 포함되지 않습니다 — 필요 시 사람이 수동으로 추가하세요.</Alert>
            <Box variant="code">
              <pre style={{ margin: 0, whiteSpace: "pre-wrap", fontFamily: "Monaco, Menlo, monospace", fontSize: 12, lineHeight: 1.5, maxHeight: 380, overflow: "auto" }}>
                {terraform.hcl}
              </pre>
            </Box>
          </SpaceBetween>
        )}
      </Modal>

      {/* 3) PS 생성 2차 확인 (실제 쓰기 게이트) */}
      <Modal
        visible={flow === "confirmProvision" || flow === "provisioning"}
        onDismiss={() => flow !== "provisioning" && setFlow("terraform")}
        header="tooling 계정 IdC에 Permission Set 생성"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" disabled={flow === "provisioning"} onClick={() => setFlow("terraform")}>취소</Button>
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
    </ContentLayout>
  );
}
