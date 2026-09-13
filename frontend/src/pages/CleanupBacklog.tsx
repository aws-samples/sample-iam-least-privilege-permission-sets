import { useState, useMemo } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
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
import SegmentedControl from "@cloudscape-design/components/segmented-control";
import Textarea from "@cloudscape-design/components/textarea";
import FormField from "@cloudscape-design/components/form-field";
import { api } from "@/api/client";
import { useAsync } from "@/api/useAsync";
import { useAccounts } from "@/AccountContext";
import { downloadCsv } from "@/lib/csv";
import { RISK_INDICATOR } from "@/theme/tokens";
import type {
  CleanupGroup, CleanupItem, CleanupStatus, CleanupType, ExclusionEntry, MetricsPoint,
  RiskCriteria, RiskLevel,
} from "@/api/types";

// 페이지 제목/메뉴명(구 '정리 백로그').
const PAGE_TITLE = "조치 필요 항목";

/**
 * 🔴 이 화면은 **묶음(group) 3개**로만 나뉜다 — 유형(type)이 아니다.
 *
 * 유형으로 카드를 만들던 시절에는 카드가 7~9개였고, 더 나쁜 것은 **같은 역할이 두 카드에 동시에**
 * 나왔다는 것이다(실측: `unused_role` 126건 중 121건이 `unused_permission` 도 가졌다). 한 화면이
 * 같은 역할에 "지워라" 와 "정책을 다시 써라" 를 동시에 말하면 사람은 어느 쪽도 하지 않는다.
 *
 * 묶음은 "무엇을 해야 하나" 다. 한 대상은 정확히 한 묶음에 있고(엔진이 트랙으로 배정), 유형은
 * 그 안에서 "무엇이 잘못됐나" 를 설명하는 하위 정보로 내려간다.
 */
const GROUP_LABEL: Record<CleanupGroup, string> = {
  delete_review: "삭제 검토",
  reduce_scope: "권한 축소",
  needs_confirmation: "확인 필요",
};

const GROUP_DESC: Record<CleanupGroup, string> = {
  delete_review:
    "오래 쓰지 않았고 신뢰 대상이 우리 계정으로 확인된 대상입니다. 조치는 삭제입니다.",
  reduce_scope:
    "쓰고 있는 대상입니다. 지우지 않고 실사용 기록을 기준으로 정책을 다시 씁니다.",
  needs_confirmation:
    "지금은 판단할 수 없는 대상입니다. 확인하거나 기다린 뒤에 판단합니다 — 조치 권고가 아닙니다.",
};

// 카드 순서는 **고정**이다. 위험도로 정렬하면 run 마다 카드가 자리를 바꿔 화면을 익힐 수 없고,
// 무엇보다 세 묶음은 우선순위가 아니라 분류다(확인 필요가 맨 아래인 것은 위험이 낮아서가 아니라
// 아직 판단할 수 없어서다).
const GROUP_ORDER: CleanupGroup[] = ["delete_review", "reduce_scope", "needs_confirmation"];

// 🔴 group=null 인 항목(이 컬럼이 없던 시절의 산출물)을 담는 자리. 숨기지 않는 이유: 고객이 예전
// run 을 선택하면 목록이 통째로 비어 보이고, 그건 "할 일이 없다" 는 거짓이 된다.
const UNGROUPED = "ungrouped" as const;
type CardKey = CleanupGroup | typeof UNGROUPED;

const CARD_LABEL = (k: CardKey) => (k === UNGROUPED ? "미분류(예전 형식 산출물)" : GROUP_LABEL[k]);

const TYPE_LABEL: Record<CleanupType, string> = {
  unused_permission: "미사용 권한",
  unused_role: "미사용 역할",
  new_role_unused: "신규 역할(관측 기간 부족)",
  long_lived_key: "장기 액세스키",
  no_mfa: "MFA 미설정",
  escalation_path: "상승 경로",
  // 이 맵이 `Record<CleanupType, …>` 인 이유: 유형이 늘면 컴파일이 깨져서, 라벨 없는 유형이 화면에
  // "undefined" 로 뜨는 경로가 원천 차단된다.
  // 아래 3종은 **삭제 권고가 아니다** — 라벨 자체에 그 사실을 넣는다. 표에서 라벨만 보고 목록을
  // 훑는 사람이 '미사용 역할' 과 같은 것으로 읽으면 외부 연동을 지우게 된다(R5).
  cross_tenant_trust: "테넌트 경계 위반 의심",
  unconfirmed_trust_role: "외부 연동 의심(소유자 확인)",
  unverified_usage: "실사용 근거 미확인",
  wildcard_grant: "전 권한 부여",
  trust_policy_wildcard: "신뢰정책 광범위",
};

const RISK_ORDER: Record<RiskLevel, number> = { critical: 0, high: 1, medium: 2, low: 3 };

// 와일드카드 2종 — 배너로 따로 말한다(R4). 둘은 다른 사실이다: granted 와일드카드는 "무엇을 할 수
// 있나", 신뢰정책 와일드카드는 "누가 집을 수 있나".
const WILDCARD_TYPES = new Set<CleanupType>(["wildcard_grant", "trust_policy_wildcard"]);

// 조치 상태 — "실제 조치는 사람이 AWS 에서 수행하고, 여기엔 그 사실을 기록한다" 는 의미가 드러나는 라벨.
const STATUS_LABEL: Record<CleanupStatus, string> = {
  open: "미조치",
  done: "조치완료",
  deferred: "보류",
};
const STATUS_INDICATOR: Record<CleanupStatus, "pending" | "success" | "stopped"> = {
  open: "pending",
  done: "success",
  deferred: "stopped",
};
// 상태별 안내 — 무엇을 뜻하는지(특히 "보류" 가 무시가 아니라는 것).
const STATUS_HINT: Record<CleanupStatus, string> = {
  open: "아직 처리하지 않은 항목입니다.",
  done: "권장 조치 또는 그에 상응하는 방법으로 해결했음을 기록합니다(예: IdC 없이 IAM 정책만 다듬어 적용).",
  deferred: "지금은 처리하지 않기로 판단한 항목입니다. 목록에서 사라지지 않고 보류로 분류됩니다.",
};
const STATUS_ORDER: CleanupStatus[] = ["open", "done", "deferred"];

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

// 제외 근거 등급 — **등급이 다르면 고객이 할 일이 다르다.** 라벨은 엔진이 주고(사유별), 여기서는
// 등급별로 "무엇을 해야 하나" 만 붙인다.
const BASIS_LABEL: Record<string, string> = {
  aws_owned: "AWS 소유 — 정책을 수정할 수 없습니다",
  customer_declared: "설정에 선언한 이름 패턴 — 잘못 걸린 것이 있으면 설정을 고치십시오",
  judgment: "이 도구의 판단(관측 기간·근거 부족) — 일부는 '확인 필요' 로 올렸습니다",
};
const BASIS_ORDER = ["judgment", "customer_declared", "aws_owned"];

// ---- 대상 1행 모델 -------------------------------------------------------------------
//
// 🔴 표의 한 행은 **대상(principal) 하나**다. 항목(finding) 하나가 아니다. 카드의 큰 숫자를 행 수와
// 같게 만드는 유일한 방법이고(단위 불일치가 이 화면의 원래 결함이었다 — KPI 는 action 41,451 을
// 세고 눌러서 열린 목록은 principal 329행을 셌다), 사람이 판단하는 단위도 대상이다: "이 역할을
// 어떻게 할까" 를 정하려면 그 역할의 문제를 **한자리에서** 봐야 한다.

interface TargetRow {
  kind: "target";
  key: string;
  account_id: string;
  principal: string;
  items: CleanupItem[];
  worst: RiskLevel; // 미조치 항목 기준 최고 위험도
  status: CleanupStatus; // 대상 단위 상태(아래 규칙)
  openCount: number;
  typeCounts: Array<[CleanupType, number]>;
  daysLeft: number | null; // '확인 필요' 의 판정까지 남은 일수(없으면 null)
  trustAccounts: string; // '확인 필요' 의 신뢰 계정(없으면 "")
  tracks: Set<string>;
}

interface FindingRow {
  kind: "finding";
  key: string;
  item: CleanupItem;
}

type Row = TargetRow | FindingRow;

/**
 * 대상 단위 상태 = **미조치가 하나라도 있으면 미조치**.
 *
 * 낙관적으로 접으면(하나라도 완료면 완료) 남은 작업이 화면에서 사라진다. 보류가 완료를 이기는
 * 것도 같은 이유다 — 보류는 "지금 안 한다" 는 판단이지 처리된 것이 아니다.
 */
function rowStatus(items: CleanupItem[]): CleanupStatus {
  if (items.some((i) => i.status === "open")) return "open";
  if (items.some((i) => i.status === "deferred")) return "deferred";
  return "done";
}

function toTargetRows(items: CleanupItem[]): TargetRow[] {
  const byTarget = new Map<string, CleanupItem[]>();
  for (const it of items) {
    const key = `${it.account_id}${it.principal}`;
    if (!byTarget.has(key)) byTarget.set(key, []);
    byTarget.get(key)!.push(it);
  }
  return [...byTarget.entries()].map(([key, its]) => {
    const openItems = its.filter((i) => i.status === "open");
    // 최고 위험도는 **미조치 항목만** 본다 — 이미 처리한 critical 이 행을 계속 빨갛게 물들이면
    // 남은 작업의 우선순위를 볼 수 없다. 미조치가 없으면 전체에서 고른다(행이 비어 보이지 않게).
    const basis = openItems.length ? openItems : its;
    const worst = (["critical", "high", "medium", "low"] as RiskLevel[])
      .find((r) => basis.some((i) => i.risk_level === r)) ?? "low";
    const typeCount = new Map<CleanupType, number>();
    for (const i of its) typeCount.set(i.type, (typeCount.get(i.type) ?? 0) + 1);
    const daysRaw = its
      .map((i) => i.evidence?.["판정까지 남은 일수"])
      .find((v) => v !== undefined && /^\d+$/.test(v));
    const trust = its.map((i) => i.evidence?.["신뢰 계정"]).find((v) => v && v !== "미수집");
    return {
      kind: "target" as const,
      key,
      account_id: its[0].account_id,
      principal: its[0].principal,
      items: its,
      worst,
      status: rowStatus(its),
      openCount: openItems.length,
      typeCounts: [...typeCount.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])),
      daysLeft: daysRaw === undefined ? null : Number(daysRaw),
      trustAccounts: trust ?? "",
      tracks: new Set(its.map((i) => i.track ?? "").filter(Boolean)),
    };
  });
}

// ---- 고치는 곳(권한 축소 대상의 목적지) ------------------------------------------------
//
// 권한 축소는 "정책을 다시 쓰라" 는 조치이고, **다시 쓰는 화면이 대상마다 다르다**: 사람이 쓰는
// 역할은 여러 대상을 묶어 persona 정책 하나로, 기계가 쓰는 역할은 역할별 개별 정책으로 만든다.
// 목적지 화면 두 개를 링크로 걸어 두기만 했을 때의 문제(사용자 피드백 2026-09-11): 목록의 한 행이
// **어느 쪽**인지 화면이 말하지 않았고, 목적지에 도착해도 수십·수백 행에서 자기 역할을 눈으로 찾아야
// 했다. 그 정보는 이미 항목의 `track` 에 있다(엔진이 정한다) — 예전에는 합계 두 개 세는 데만 썼다.

export type FixDest = "persona" | "service_role";

/**
 * 이 대상을 어느 화면에서 고치는가. 판정할 수 없으면 `null`.
 *
 * 🔴 두 트랙이 섞인 행은 임의로 한쪽을 고르지 않는다. 사람이 쓰는 역할과 기계가 쓰는 역할은 정책을
 * 만드는 방식이 다르고(묶음 vs 개별), 틀린 쪽으로 보내면 **남의 권한을 바꾸게 된다**. 실측
 * (run-20260911T073513Z)에서는 75개 대상 전부 한 트랙이었지만 그것이 구조적 보장은 아니다 —
 * CloudTrail 관측 창에 따라 `track` 이 흔들린다(열린 결함 #13). null 인 행은 버튼을 감추는 대신
 * 이유를 적는다(R6 — 조용히 사라지는 것을 만들지 않는다).
 */
export function fixDest(tracks: Set<string>): FixDest | null {
  const persona = tracks.has("persona");
  const machine = tracks.has("service_role");
  if (persona === machine) return null; // 둘 다이거나 둘 다 아님
  return persona ? "persona" : "service_role";
}

const DEST_LABEL: Record<FixDest, string> = {
  persona: "Persona 검토",
  service_role: "서비스 역할 정리",
};
const DEST_PATH: Record<FixDest, string> = { persona: "/personas", service_role: "/service-roles" };

interface Card {
  key: CardKey;
  rows: TargetRow[];
  targets: number; // 큰 숫자 = rows.length (어서션: 이 카드가 여는 목록의 행 수와 같다)
  openTargets: number;
  itemCount: number;
  statusDist: Record<CleanupStatus, number>; // 대상 기준
  dist: Record<RiskLevel, number>; // 미조치 대상 기준
  worst: RiskLevel;
  typeCounts: Array<[CleanupType, number]>; // 유형별 **대상** 수
}

function cardsFor(items: CleanupItem[]): Card[] {
  const byGroup = new Map<CardKey, CleanupItem[]>();
  for (const it of items) {
    const key: CardKey = it.group ?? UNGROUPED;
    if (!byGroup.has(key)) byGroup.set(key, []);
    byGroup.get(key)!.push(it);
  }
  const order = (k: CardKey) => (k === UNGROUPED ? 99 : GROUP_ORDER.indexOf(k));
  return [...byGroup.entries()]
    .map(([key, its]) => {
      const rows = toTargetRows(its).sort(sortRows);
      const statusDist: Record<CleanupStatus, number> = { open: 0, done: 0, deferred: 0 };
      rows.forEach((r) => statusDist[r.status]++);
      const dist: Record<RiskLevel, number> = { critical: 0, high: 0, medium: 0, low: 0 };
      rows.filter((r) => r.status === "open").forEach((r) => dist[r.worst]++);
      const worst = (["critical", "high", "medium", "low"] as RiskLevel[]).find((r) => dist[r] > 0) ?? "low";
      // 유형별 **대상** 수(항목 수가 아니다). 큰 숫자와 단위를 맞춘다 — 한 대상이 미사용 권한을
      // 12건 가져도 이 줄에서는 1로 센다. 단위를 섞으면 부속 줄의 합이 큰 숫자를 넘어간다.
      const typeCount = new Map<CleanupType, number>();
      for (const r of rows) for (const [t] of r.typeCounts) typeCount.set(t, (typeCount.get(t) ?? 0) + 1);
      return {
        key, rows, targets: rows.length,
        openTargets: rows.filter((r) => r.status === "open").length,
        itemCount: its.length,
        statusDist, dist, worst,
        typeCounts: [...typeCount.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])),
      };
    })
    .sort((a, b) => order(a.key) - order(b.key));
}

// 행 정렬: 미조치 먼저 → 위험도 → 계정 → ARN. 미조치를 위로 올리는 것이 이 화면의 목적이고,
// ARN 까지 넣는 이유는 결정론이다(같은 데이터에서 순서가 흔들리면 어제 본 행을 다시 찾을 수 없다).
function sortRows(a: TargetRow, b: TargetRow): number {
  const openFirst = (r: TargetRow) => (r.status === "open" ? 0 : 1);
  return openFirst(a) - openFirst(b)
    || RISK_ORDER[a.worst] - RISK_ORDER[b.worst]
    || a.account_id.localeCompare(b.account_id)
    || a.principal.localeCompare(b.principal);
}

// 위험도 배지 + "왜 이 레벨인지"(점수·근거) 팝오버. 운영자가 즉시 위험을 인지하도록.
/** 근거 문장 끝에 붙은 기여 점수(`… (+40점)`)를 뽑는다. 표기가 없으면 null.
 *
 *  🔴 null 은 "이전 형식 산출물" 을 뜻한다. 기여도 내림차순 정렬과 점수 표기는 엔진이 함께 넣으므로
 *  (`m4_risk_scorer.py`), 점수가 없는 문장은 **정렬돼 있다고 가정할 수 없다** — 그런 run 에서는
 *  "점수를 가장 많이 올린 것" 을 주장하지 않는다(첫 원소가 1위라는 근거가 없다). */
export function reasonPoints(reason: string): number | null {
  const m = /\(\+(\d+)점\)$/.exec(reason);
  return m ? Number(m[1]) : null;
}

/** 어느 유형에서나 값이 같아 정보가 없는 증거 라벨 — 형제 한 줄 요약에서는 건너뛴다. */
const GENERIC_EVIDENCE_LABELS = new Set(["식별 유형", "수집 소스", "소속 테넌트 그룹"]);

/** 형제 항목에 붙일 **증거 한 줄**. evidence dict 순서는 결정론이고(`m6_reporter.py`) 유형별 핵심이
 *  앞에 오지만, 첫 키가 `식별 유형` 인 유형이 여럿이라 그것만 집으면 "role" 만 반복된다 → 일반 라벨을
 *  건너뛴 첫 항목을 쓴다. 형제 목록은 사실 문장만 있어 숫자가 없으므로 이 줄이 있어야 근거가 된다.
 *
 *  🔴 이 절은 **사실만** 내는 자리다(하네스가 "재작성·마이그레이션·권장 조치·권고" 를 금지어로
 *  검사한다). 증거 라벨·값에 조치 문구가 섞이면 그 어서션이 잡는다 — 새 증거를 넣을 때 확인할 것. */
export function firstEvidence(item: { evidence?: Record<string, string> }): [string, string] | null {
  const es = item.evidence ? Object.entries(item.evidence) : [];
  return es.find(([k]) => !GENERIC_EVIDENCE_LABELS.has(k)) ?? null;
}

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

/**
 * 와일드카드 배너(R4).
 *
 * 왜 배너인가: `*` 보유자는 미사용 findings 가 0 이다. 갭 계산에서 와일드카드를 빼기 때문이고, 그건
 * 맞다(부여 범위에 상한이 없어 "미사용 N개" 를 셀 수 **없다**). 문제는 그 결과 **전 권한 보유자가
 * 숫자로는 가장 깨끗해 보인다**는 것이다. 그래서 숫자 대신 문장으로 말한다.
 *
 * 권고를 "미사용 N개 제거" 라고 쓰지 않는다 — 그러면 그만큼 지우면 최소권한이 된다는 뜻이 되지만
 * `*` 는 그대로 남는다. 조치는 **실사용 기반 재작성**이다.
 */
function WildcardBanner({ items, onOpen }: { items: CleanupItem[]; onOpen: (k: CardKey, t: CleanupType) => void }) {
  const open = items.filter((i) => WILDCARD_TYPES.has(i.type) && i.status === "open");
  if (open.length === 0) return null;
  const total = new Set(open.map((i) => `${i.account_id}${i.principal}`)).size;
  // 와일드카드는 세 묶음 어디에나 있을 수 있다(현역이어도, 지울 대상이어도 `*` 는 `*` 다).
  // 그래서 묶음별로 링크를 낸다 — 하나로 합치면 눌렀을 때 어디로 가는지 알 수 없다.
  const perCard = new Map<CardKey, Set<string>>();
  for (const i of open) {
    const k: CardKey = i.group ?? UNGROUPED;
    if (!perCard.has(k)) perCard.set(k, new Set());
    perCard.get(k)!.add(`${i.account_id}${i.principal}`);
  }
  return (
    <Alert type="warning" header={`와일드카드 권한 보유 대상 ${total}개 — 개수로는 가장 깨끗해 보입니다`}>
      <SpaceBetween size="xs">
        <Box>
          와일드카드(<code>*</code>)를 가진 대상은 <b>미사용 권한 개수가 0 으로 보입니다</b>.
          부여 범위에 상한이 없어 개수를 <b>셀 수 없기</b> 때문이며, 권한이 깨끗하다는 뜻이 아닙니다.
          조치는 "미사용 N개 제거" 가 아니라 <b>실사용 기록을 기준으로 정책을 다시 쓰는 것</b>입니다.
        </Box>
        <SpaceBetween direction="horizontal" size="s">
          {[...perCard.entries()].map(([k, set]) => (
            <Link key={k} onFollow={() => onOpen(k, "wildcard_grant")}>
              {CARD_LABEL(k)} 안의 {set.size}개 대상 보기
            </Link>
          ))}
        </SpaceBetween>
      </SpaceBetween>
    </Alert>
  );
}

/**
 * 제외 내역 — **접힌 한 줄**이다(카드가 아니다).
 *
 * 카드로 두면 "조치할 것" 과 "손대지 않을 것" 이 같은 무게로 보인다. 그렇다고 빼면 R6 위반이다:
 * 조용히 사라지면 "왜 우리 역할이 여기 없지?" 에 답할 수 없다. 그래서 접어서 남기고, 숨긴 권고
 * 건수까지 적는다 — 게이트를 넣은 뒤 숫자가 줄어든 것이 "정리됐다" 로 읽히면 안 되기 때문이다
 * (처음부터 조치 대상이 아니었다는 사실이 사라진 것이다).
 */
function ExclusionSection({ entries }: { entries: ExclusionEntry[] }) {
  if (!entries.length) return null;
  const targets = entries.reduce((n, e) => n + e.targets, 0);
  const hidden = entries.reduce((n, e) => n + e.suppressed_items, 0);
  const byBasis = BASIS_ORDER
    .map((basis) => ({ basis, list: entries.filter((e) => (e.basis || "judgment") === basis) }))
    .filter((g) => g.list.length);
  // 엔진이 새 등급을 내면 위 목록에 없어서 사라진다 → 남은 것을 그대로 붙인다(조용히 빠지지 않게).
  const known = new Set(BASIS_ORDER);
  const rest = entries.filter((e) => !known.has(e.basis || "judgment"));
  if (rest.length) byBasis.push({ basis: "기타", list: rest });
  return (
    <ExpandableSection
      variant="footer"
      headerText={`제외 ${targets}개 대상 — 조치 목록에 올리지 않았습니다 (권고 ${hidden}건 숨김)`}
      headerDescription="손댈 수 없거나, 고치면 배포가 깨지거나, 아직 판단할 수 없는 대상입니다. 펼쳐서 무엇이 빠졌는지 확인하십시오."
    >
      <SpaceBetween size="m">
        {byBasis.map(({ basis, list }) => (
          <Container
            key={basis}
            header={<Header variant="h3" description={BASIS_LABEL[basis] ?? basis}>{
              basis === "aws_owned" ? "AWS 소유"
                : basis === "customer_declared" ? "고객 설정 선언"
                : basis === "judgment" ? "이 도구의 판단" : basis
            }</Header>}
          >
            <SpaceBetween size="s">
              {list.map((e) => (
                <ExpandableSection
                  key={e.reason}
                  headerText={`${e.label} — ${e.targets}개 대상 (숨긴 권고 ${e.suppressed_items}건)`}
                >
                  {e.principals && e.principals.length ? (
                    <ul style={{ margin: 0, paddingLeft: 18 }}>
                      {e.principals.map((p) => (
                        <li key={p}><Box fontSize="body-s">{p}</Box></li>
                      ))}
                    </ul>
                  ) : (
                    <Box color="text-status-inactive" fontSize="body-s">
                      대상 목록이 없는 형식의 조회 결과입니다. 전체 조회를 한 번 더 실행하면 표시됩니다.
                    </Box>
                  )}
                </ExpandableSection>
              ))}
            </SpaceBetween>
          </Container>
        ))}
      </SpaceBetween>
    </ExpandableSection>
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

// CSV 주입 방어·BOM·인용 규칙은 `lib/csv` 가 담당한다 — 트랙② 화면과 **같은 구현**을 쓴다.
// 두 벌이 되면 한쪽만 고쳐지고, CSV 는 화면에서 검증되지 않는 산출물이라 그 사실을 아무도 모른다.
// group·track 을 싣는 이유: CSV 로 내려받아 나누는 사람이 화면과 **같은 3분류**를 볼 수 있어야 한다.
const CSV_HEAD = ["id", "group", "track", "type", "account_id", "principal", "detail", "risk_level",
  "risk_score", "risk_reasons", "recommendation", "status", "status_note", "status_updated_at",
  "status_updated_by"];

function download(items: CleanupItem[], filename: string) {
  // 조치 상태도 함께 내린다 — 이 CSV 가 "누가 무엇을 처리했나" 를 외부에 공유하는 수단이다.
  const cell = (i: CleanupItem, k: string) =>
    k === "risk_reasons" ? i.risk_reasons.join("|")
      : k === "status" ? STATUS_LABEL[i.status]
      : k === "group" ? (i.group ? GROUP_LABEL[i.group] : "미분류")
      : k === "type" ? TYPE_LABEL[i.type]
      : String((i as unknown as Record<string, unknown>)[k] ?? "");
  downloadCsv(filename, CSV_HEAD, items.map((i) => CSV_HEAD.map((k) => cell(i, k))));
}

// `?group=` 딥링크로 열 수 있는 값. 손으로 적지 않고 `GROUP_LABEL`(Record<CleanupGroup,…>)에서
// 파생한다 — 목록으로 두면 묶음이 늘어도 컴파일이 깨지지 않고, 새 묶음의 딥링크가 **조용히**
// 요약 화면으로 되돌아간다(대시보드 KPI 링크가 실제로 그렇게 죽어 있었다).
const VALID_CARDS: string[] = [...(Object.keys(GROUP_LABEL) as CleanupGroup[]), UNGROUPED];
const VALID_TYPES: string[] = Object.keys(TYPE_LABEL);

// 유형 배지 열의 폭 — **라이브 실측**(Badge DOM 을 복제해 잰 렌더 폭의 그룹별 최댓값)에 여유를 더한 값.
// 권한 축소 242 / 삭제 검토 307 / 확인 필요 377. `wait`(신규 역할)는 라이브에 사례가 없어 최대치를 쓴다.
const BADGE_W: Record<"default" | "ask" | "wait" | "fix", number> = {
  fix: 250, default: 320, ask: 390, wait: 390,
};

// 목록에서 `arn:aws:iam::<계정>:` 접두를 떼고 `role/이름` 만 남긴다. 접두는 전 행 동일하고,
// 계정은 계정 열·상세 패널이 말한다. 형태가 다른 값(접두가 안 맞는 경우)은 **그대로** 돌려준다.
const shortPrincipal = (arn: string): string => arn.replace(/^arn:aws[a-z-]*:iam::\d+:/, "");

// `?type=` 이 가리키는 유형이 속한 묶음. 예전 딥링크(대시보드·배너·CSV 공유 URL)를 살려 둔다 —
// 유형 카드가 없어졌다고 그 링크를 요약 화면으로 되돌리면 사람은 자기가 무엇을 잘못 눌렀다고 생각한다.
function cardOfType(items: CleanupItem[], type: CleanupType): CardKey | null {
  const hit = items.find((i) => i.type === type);
  return hit ? (hit.group ?? UNGROUPED) : null;
}

export default function CleanupBacklog() {
  const { data, loading, reload } = useAsync<CleanupItem[]>(() => api.getCleanup());
  const { data: criteria } = useAsync<RiskCriteria>(() => api.getRiskCriteria());
  // 제외 내역은 백로그에 **없다**(빠진 것이니까). 엔진이 metrics 에 실어 보낸 것을 읽는다.
  const { data: metrics } = useAsync<MetricsPoint[]>(() => api.getMetrics());
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const [detail, setDetail] = useState<CleanupItem | null>(null);
  // 드릴다운 상태 필터. 기본 '전체' — 행이 대상 단위가 되면서 카드의 큰 숫자가 **전체 대상 수**가
  // 됐다. 기본을 '미조치' 로 두면 카드 128 을 눌렀는데 표가 120행이 되고, 그 어긋남이 이 화면의
  // 원래 결함이었다(정렬로 미조치를 위에 올려 "남은 작업" 은 그대로 먼저 보인다).
  const [statusFilter, setStatusFilter] = useState<CleanupStatus | "all">("all");
  // 고치는 곳 필터('권한 축소' 전용). 대상이 수백 개면 목적지로 한 번 갈라야 연속 처리가 된다 —
  // 사람이 쓰는 역할과 기계가 쓰는 역할은 작업 방식이 달라서 섞어 놓으면 화면을 계속 왕복한다.
  const [destFilter, setDestFilter] = useState<FixDest | "unknown" | "all">("all");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  // 상세 모달의 조치 표시 초안(저장 전). 모달을 열 때 항목의 현재 값으로 채운다.
  const [draftStatus, setDraftStatus] = useState<CleanupStatus>("open");
  const [draftNote, setDraftNote] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  function openDetail(item: CleanupItem) {
    setDetail(item);
    setDraftStatus(item.status);
    setDraftNote(item.status_note);
    setSaveError(null);
  }

  /**
   * 조치 상태 저장. `alsoKeys` 는 **같은 대상의 다른 발견 항목**들이다.
   *
   * 🔴 목록에서 자식 행을 접은 묶음(삭제 검토)에서는 대표 항목 하나에만 상태를 쓰면 안 된다.
   * 대상 행의 상태는 `rowStatus` 가 **모든 항목**을 보고 정하므로(미조치가 하나라도 있으면 미조치),
   * 역할을 실제로 지우고 '조치완료' 로 표시해도 행은 영구히 "미조치 2/3" 에 머문다 — 나머지 항목의
   * 상태를 바꿀 화살표가 화면에 없으니 되돌릴 방법도 없다. 삭제 검토의 판단 단위는 대상 하나이고
   * 조치(삭제)도 하나이므로, 그 대상의 항목 전체에 같은 상태·같은 노트를 쓴다.
   */
  async function saveStatus(item: CleanupItem, alsoKeys: string[] = []) {
    setSaving(true);
    setSaveError(null);
    try {
      for (const key of alsoKeys) await api.setCleanupStatus(key, draftStatus, draftNote);
      await api.setCleanupStatus(item.finding_key, draftStatus, draftNote);
      // 낙관적 갱신을 하지 않고 서버 상태를 다시 읽는다 — 저장된 것만 화면에 보이게(표시했다고
      // 믿었는데 새로고침하면 사라지는 상황을 만들지 않는다). reload 는 Promise 가 아니라
      // 취소 함수를 반환하므로 await 하지 않는다(await 해도 완료를 기다리지 않는다).
      reload();
      setDetail(null);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  const { selected, setSelected } = useAccounts();
  const scoped = useMemo(
    () => (data ? (selected ? data.filter((i) => i.account_id === selected) : data) : []),
    [data, selected],
  );

  const cards = useMemo(() => cardsFor(scoped), [scoped]);

  // 드릴다운 대상은 URL 로 관리 → 대시보드 카드에서 딥링크로 진입 가능.
  const groupParam = searchParams.get("group");
  const typeParam = searchParams.get("type");
  const typeFocus: CleanupType | null =
    typeParam && VALID_TYPES.includes(typeParam) ? (typeParam as CleanupType) : null;
  const openCard: CardKey | null =
    groupParam && VALID_CARDS.includes(groupParam) ? (groupParam as CardKey)
      : typeFocus ? cardOfType(scoped, typeFocus)
      : null;
  const setOpen = (k: CardKey | null, type?: CleanupType) => {
    setExpanded(new Set());
    if (!k) setSearchParams({});
    else setSearchParams(type ? { group: k, type } : { group: k });
  };

  // 선택 계정 반영 총계(헤더 카운터) — 단위는 **대상**이다.
  const totalTargets = cards.reduce((n, c) => n + c.targets, 0);
  const openTargets = cards.reduce((n, c) => n + c.openTargets, 0);

  // 제외 내역은 계정 선택을 따라간다 — run 전체 값을 특정 계정 화면에 그대로 붙이면 그 계정에 없는
  // 대상이 "이 계정에서 빠졌다" 로 읽힌다.
  const point = useMemo<MetricsPoint | null>(() => {
    if (!metrics?.length) return null;
    const sorted = [...metrics].sort((a, b) => a.ts.localeCompare(b.ts));
    const latest = sorted[sorted.length - 1];
    if (!selected) return latest;
    return latest.by_account?.find((p: MetricsPoint) => p.account_id === selected) ?? null;
  }, [metrics, selected]);

  if (loading || !data) {
    return <Box padding="xxl" textAlign="center"><Spinner size="large" /></Box>;
  }

  // ---- 요약 뷰(3카드) ----
  if (!openCard) {
    return (
      <ContentLayout
        header={
          <Header
            variant="h1"
            counter={`(대상 ${totalTargets} · 미조치 ${openTargets})`}
            description={`${selected ? `계정 ${selected}` : "전체 계정"} — 대상 하나는 아래 세 묶음 중 한 곳에만 있습니다. 실제 조치는 사람이 AWS 에서 수행하고, 이 화면에는 처리했다는 사실만 기록합니다 (읽기전용 도구).`}
            actions={<Button iconName="download" onClick={() => download(scoped, "action_items.csv")}>전체 CSV</Button>}
          >
            {PAGE_TITLE}
          </Header>
        }
      >
        <SpaceBetween size="l">
          <WildcardBanner items={scoped} onOpen={(k, t) => setOpen(k, t)} />
          <RiskCriteriaPanel criteria={criteria ?? null} />
          <Cards
            items={cards}
            trackBy="key"
            empty={<Box padding="l" textAlign="center" color="text-status-inactive">조치 후보가 없습니다.</Box>}
            cardDefinition={{
              header: (c: Card) => (
                <Link fontSize="heading-m" onFollow={() => setOpen(c.key)}>{CARD_LABEL(c.key)}</Link>
              ),
              sections: [
                {
                  id: "count",
                  content: (c: Card) => (
                    <SpaceBetween size="xs">
                      {/* 🔴 큰 숫자 = **대상 수** = 이 카드가 여는 목록의 행 수. 정의를 한 곳에 두고
                          엔진 테스트가 못박는다(예전에는 KPI 가 action 을 세고 목록이 principal 을
                          셌다). 미조치는 아래 줄에 따로 적는다 — 단위가 다르지 않아야 한다. */}
                      <Box fontSize="display-l" fontWeight="bold">{c.targets.toLocaleString()}</Box>
                      <Box color="text-body-secondary" fontSize="body-s">
                        개 대상 (미조치 {c.openTargets.toLocaleString()} · 발견 {c.itemCount.toLocaleString()}건)
                      </Box>
                    </SpaceBetween>
                  ),
                },
                {
                  id: "what",
                  content: (c: Card) => (
                    <Box color="text-body-secondary" fontSize="body-s">
                      {c.key === UNGROUPED
                        ? "이 컬럼이 없던 형식의 조회 결과입니다. 전체 조회를 한 번 더 실행하면 분류됩니다."
                        : GROUP_DESC[c.key]}
                    </Box>
                  ),
                },
                {
                  id: "types", header: "포함된 문제 (대상 수)",
                  content: (c: Card) => (
                    <SpaceBetween direction="horizontal" size="xs">
                      {c.typeCounts.map(([t, n]) => (
                        <Link key={t} onFollow={() => setOpen(c.key, t)}>{TYPE_LABEL[t]} {n}</Link>
                      ))}
                    </SpaceBetween>
                  ),
                },
                {
                  id: "status", header: "조치 상태 (대상 수)",
                  content: (c: Card) => (
                    <SpaceBetween direction="horizontal" size="s">
                      {STATUS_ORDER.filter((s) => c.statusDist[s] > 0).map((s) => (
                        <StatusIndicator key={s} type={STATUS_INDICATOR[s]}>{STATUS_LABEL[s]} {c.statusDist[s]}</StatusIndicator>
                      ))}
                    </SpaceBetween>
                  ),
                },
                {
                  id: "dist", header: "위험도 분포 (미조치 대상)",
                  content: (c: Card) => (
                    <SpaceBetween direction="horizontal" size="s">
                      {(["critical", "high", "medium", "low"] as RiskLevel[]).filter((r) => c.dist[r] > 0).map((r) => (
                        <StatusIndicator key={r} type={RISK_INDICATOR[r]}>{r} {c.dist[r]}</StatusIndicator>
                      ))}
                      {c.openTargets === 0 && <Box color="text-status-inactive">미조치 없음</Box>}
                    </SpaceBetween>
                  ),
                },
                {
                  id: "action",
                  content: (c: Card) => <Button onClick={() => setOpen(c.key)}>{c.targets}개 대상 보기</Button>,
                },
              ],
            }}
            cardsPerRow={[{ cards: 1 }, { minWidth: 600, cards: 2 }, { minWidth: 1000, cards: 3 }]}
          />
          <ExclusionSection entries={point?.exclusions ?? []} />
        </SpaceBetween>
      </ContentLayout>
    );
  }

  // ---- 드릴다운 뷰(대상 목록) ----
  const card = cards.find((c) => c.key === openCard);
  const allRows = card?.rows ?? [];
  // 계정 열을 낼지 — 이 목록에 계정이 2개 이상일 때만(단일 계정이면 상수 열이다).
  const multiAccount = new Set(allRows.map((r) => r.account_id)).size > 1;
  const focusRows = typeFocus ? allRows.filter((r) => r.typeCounts.some(([t]) => t === typeFocus)) : allRows;
  // 고치는 곳은 '권한 축소' 에서만 의미가 있다 — 삭제 검토는 할 일이 삭제 하나이고, 확인 필요는
  // 아직 조치 대상이 아니다.
  const isFixCard = openCard === "reduce_scope";
  const destDist: Record<FixDest | "unknown", number> = { persona: 0, service_role: 0, unknown: 0 };
  focusRows.forEach((r) => destDist[fixDest(r.tracks) ?? "unknown"]++);
  const destRows = isFixCard && destFilter !== "all"
    ? focusRows.filter((r) => (fixDest(r.tracks) ?? "unknown") === destFilter)
    : focusRows;
  const rows = statusFilter === "all" ? destRows : destRows.filter((r) => r.status === statusFilter);
  // 상태 분포는 **목적지 필터를 적용한 뒤**의 집합에서 센다. 두 필터가 서로 다른 모집단을 세면
  // 라벨의 건수와 표의 행 수가 어긋나고, 그 어긋남이 이 화면의 원래 결함이었다.
  const statusDist: Record<CleanupStatus, number> = { open: 0, done: 0, deferred: 0 };
  destRows.forEach((r) => statusDist[r.status]++);
  const flatItems = focusRows.flatMap((r) => r.items);

  /**
   * 목적지 화면으로 **그 대상을 열어서** 이동한다. 두 화면 다 주소로 대상을 지정할 수 있으므로
   * (`/service-roles?role=`·`/personas?principal=`) 목록·필터를 거치지 않고 바로 도착한다.
   *
   * 🔴 계정 선택기를 함께 맞춘다. 목적지 화면들은 선택 계정으로 범위를 좁히기 때문에, 다른 계정이
   * 선택된 상태로 보내면 "이 역할이 현재 범위에 없습니다" 로 떨어진다(ServiceRoles 의 그 분기).
   * `from` 은 돌아올 길이다 — 고친 뒤 조치 완료 표시는 이 화면에서만 하므로 왕복이 되어야 한다.
   */
  function goFix(r: TargetRow, dest: FixDest) {
    if (selected && selected !== r.account_id) setSelected(r.account_id);
    const q = new URLSearchParams(
      dest === "service_role"
        ? { role: r.principal, from: "cleanup" }
        : { principal: r.principal, from: "cleanup" },
    );
    navigate(`${DEST_PATH[dest]}?${q.toString()}`);
  }

  // '확인 필요' 는 두 갈래다 — **할 수 있는 일이 다르다**. 하나는 사람에게 물어야 알 수 있고
  // (소유자 확인), 하나는 시간이 지나야 알 수 있다(관측 기간). 한 표에 섞으면 "확인하라" 는 말이
  // 기다리면 되는 것에도 붙어, 할 수 없는 일을 하라고 시키는 셈이 된다.
  const waitRows = rows.filter((r) => r.daysLeft !== null);
  const askRows = rows.filter((r) => r.daysLeft === null);

  // 🔴 '삭제 검토' 는 **대상당 한 행**이다. 할 일이 "삭제" 하나뿐인데 문제를 자식으로 펼치면 조치가
  // 세 개인 것처럼 읽힌다(사용자 지적 — 라이브 205개 중 177개가 항목 2개 이상이었다). 함께 발견된
  // 사실은 없애지 않고(R6) 상세 보기의 '이 대상이 가진 다른 사실' 로 옮긴다. 권한 축소·확인 필요는
  // 항목마다 할 일이 다르고 조치 상태도 항목별로 달아야 하므로 자식 구조를 유지한다.
  const collapseTargets = openCard === "delete_review";

  // 접힌 행에서 '상세 보기' 가 열 대표 항목 — 삭제 검토의 대표는 **판정 근거를 든** `unused_role`
  // 이다(라이브 205/205 에 존재). 없는 경우(구버전 산출물 등)에는 위험도가 가장 높은 항목으로
  // 내려간다. 여기서 잘못 고르면 상세에 미사용 일수·임계가 아예 안 실린다.
  const repItem = (r: TargetRow): CleanupItem =>
    r.items.find((i) => i.type === "unused_role")
    ?? [...r.items].sort((a, b) => RISK_ORDER[a.risk_level] - RISK_ORDER[b.risk_level])[0];

  // 문제가 하나뿐인 대상도 화살표가 떠서, 열면 부모와 같은 내용 한 줄이 나왔다(라이브 301개 중 64개).
  const isCollapsed = (r: TargetRow) => collapseTargets || r.items.length === 1;

  // 자식 행을 없앤 대신 그 사실들을 상세로 옮긴다(R6 — 화면에서 조용히 사라지는 것이 없어야 한다).
  // 삭제 검토 **판정에 들어가는 값은 시간뿐**이다(`is_idle_beyond` 는 unused_days·basis 만 본다).
  // 와일드카드·상승 경로·미사용 권한은 판정 근거가 아니라 risk_score 가중치이므로 "왜 지우나" 가
  // 아니라 "왜 급한가" 를 말한다 — 그래서 별 절로 갈라 **사실만** 싣고 권고문은 싣지 않는다
  // (이 묶음의 할 일은 삭제 하나뿐인데 "정책을 재작성하라" 가 함께 뜨면 조치가 두 개로 읽힌다).
  const detailSiblings = detail
    ? (allRows.find((r) => r.account_id === detail.account_id && r.principal === detail.principal)?.items ?? [])
        .filter((i) => i.id !== detail.id)
        .sort((a, b) => RISK_ORDER[a.risk_level] - RISK_ORDER[b.risk_level] || a.type.localeCompare(b.type))
    : [];

  // 🔴 열 폭은 **실측**으로 정했다(라이브 1680px: 표 컨테이너 가용폭 1278). 이전에는 고정폭 합이
  // 628 이고 `대상` 열이 잔여를 585 먹어, 폭을 안 준 배지 열이 88px 로 짜부라져 있었다 —
  // 그 결과 (i) 표 전체가 64px 가로 오버플로(스크롤), (ii) 배지가 3~4줄로 접혀 행 높이 139px.
  // 배지 조합의 실제 렌더 폭(Badge DOM 복제 측정, 전 그룹 최댓값): 권한 축소 242 · 삭제 검토 307 ·
  // 확인 필요 377. 그래서 배지 열에 **kind 별 실측 폭**을 주고 접기(`+N`)는 넣지 않는다 —
  // 접으면 유형이 화면에서 사라지고, 폭을 주면 전 행이 한 줄로 들어간다.
  const columns = (kind: "default" | "ask" | "wait" | "fix") => {
    const base = [
      {
        // 🔴 `(최고)` 를 뗐다(F17-1). 위험도는 **대상 단위** 값이라 한 대상의 항목들은 등급이 전부
        // 같다 — 백로그의 모든 유형이 같은 `rec.risk_level` 을 받는다(`m6_reporter.py` 의 `_item(...,
        // rec.risk_level, ...)` 호출 전부). 그러니 이 라벨은 "최고치" 를 말한 것이 아니라 **항목이
        // 2개 이상인 행**을 표시하고 있었고(`r.items.length > 1`), 읽는 사람에게는 "항목마다 등급이
        // 달라서 그중 최고" 로 읽혔다. 항목 수는 오른쪽 유형 배지(`typeCounts`)가 이미 말한다.
        id: "risk", header: "위험도", width: 120, minWidth: 120,
        cell: (r: Row) => r.kind === "finding"
          ? <RiskCell item={r.item} criteria={criteria ?? null} />
          : <StatusIndicator type={RISK_INDICATOR[r.worst]}>{r.worst}</StatusIndicator>,
      },
      {
        id: "status", header: "조치", width: 132, minWidth: 132,
        cell: (r: Row) => r.kind === "finding"
          ? <StatusIndicator type={STATUS_INDICATOR[r.item.status]}>{STATUS_LABEL[r.item.status]}</StatusIndicator>
          : (
            <StatusIndicator type={STATUS_INDICATOR[r.status]}>
              {STATUS_LABEL[r.status]}{r.items.length > 1 ? ` ${r.openCount}/${r.items.length}` : ""}
            </StatusIndicator>
          ),
      },
      // 계정 열은 **계정이 2개 이상일 때만** 낸다. 단일 계정 run 에서는 전 행이 같은 값이라
      // 130px 을 상수에 쓰는 셈이고, 그 폭이 대상 ARN 과 배지에서 빠진다. 계정은 상세 패널·CSV·
      // 상단 계정 선택기가 말한다(값이 화면에서 사라지지 않는다).
      ...(multiAccount
        ? [{ id: "account", header: "계정", width: 130, minWidth: 130, cell: (r: Row) => r.kind === "target" ? r.account_id : "" }]
        : []),
      {
        id: "principal", header: "대상 / 발견된 문제",
        // `arn:aws:iam::<계정>:` 접두는 전 행 동일한 상수다(계정은 위 열/상세가 말한다). 떼면
        // 실측 최장 폭이 762 → 572 로 줄어 대부분의 행이 한 줄에 들어간다. 전체 ARN 은 title 로 남긴다.
        cell: (r: Row) => r.kind === "target"
          ? <Box fontSize="body-s"><span title={r.principal}>{shortPrincipal(r.principal)}</span></Box>
          : (
            <SpaceBetween size="xxxs">
              <Box fontSize="body-s" fontWeight="bold">{TYPE_LABEL[r.item.type]}</Box>
              <Box fontSize="body-s" color="text-body-secondary">{r.item.detail}</Box>
            </SpaceBetween>
          ),
      },
    ];
    if (kind === "ask") {
      // 신뢰 계정을 **열로** 세운다(정렬 키이기도 하다). 소유자 확인은 역할 하나씩 하는 일이 아니라
      // "저 계정 누구 것이냐" 한 번으로 여러 건이 같이 풀리는 일이다.
      base.push({
        id: "trust", header: "신뢰 계정", width: 150, minWidth: 150,
        cell: (r: Row) => r.kind === "target"
          ? (r.trustAccounts || <Box color="text-status-inactive" fontSize="body-s">해당 없음</Box>)
          : "",
      } as never);
    }
    if (kind === "wait") {
      base.push({
        id: "days", header: "판정까지 남은 일수", width: 150, minWidth: 150,
        cell: (r: Row) => r.kind === "target" && r.daysLeft !== null ? `${r.daysLeft}일` : "",
      } as never);
    }
    if (kind === "fix") {
      // 목적지 이름과 이동 버튼을 **한 칸**에 둔다. 이름만 있으면 도착해서 다시 찾아야 하고, 버튼만
      // 있으면 어디로 가는지 모르고 누른다. 자식(발견 항목) 행은 비운다 — 조치 단위는 대상이다.
      base.push({
        id: "fixat", header: "고치는 곳", width: 150, minWidth: 150,
        cell: (r: Row) => {
          if (r.kind !== "target") return "";
          const dest = fixDest(r.tracks);
          if (!dest) {
            // 🔴 버튼을 그냥 빼면 조용한 실패다(왜 이 행만 버튼이 없는지 알 길이 없다).
            return (
              <Box fontSize="body-s" color="text-status-warning">
                판정 불가 — 상세 확인
              </Box>
            );
          }
          // 라벨에서 "에서 고치기" 를 뗐다 — 열 머리글이 이미 「고치는 곳」이고, 화살표가 이동을
          // 말한다. 실측 228px 이던 내용이 열 폭 150 에 한 줄로 들어간다.
          return (
            <Button variant="inline-link" onClick={() => goFix(r, dest)}>
              <span style={{ whiteSpace: "nowrap" }}>{DEST_LABEL[dest]} →</span>
            </Button>
          );
        },
      } as never);
    }
    base.push({
      id: "problems", header: "", width: BADGE_W[kind], minWidth: BADGE_W[kind],
      cell: (r: Row) => r.kind === "target"
        ? (
          // 배지는 **줄바꿈하지 않는다**. `SpaceBetween` 은 flex-wrap 이 켜져 있어 폭이 모자라면
          // 접혔다(사용자가 본 "상승 경로 ⏎ 전 권한 부여"). 폭은 위 실측대로 주고 여기서 nowrap 을
          // 못 박는다. 만약 다른 고객 데이터가 이 폭을 넘으면 잘리는데, 그때도 title 과 상세가
          // 전건을 말한다(조용히 사라지지 않는다).
          <div
            style={{ display: "flex", gap: 4, flexWrap: "nowrap", overflow: "hidden" }}
            title={r.typeCounts.map(([t, n]) => `${TYPE_LABEL[t]}${n > 1 ? ` ${n}` : ""}`).join(" · ")}
          >
            {/* 🔴 `flexShrink: 0` 이 있어야 폭 부족이 **드러난다**. 없으면 배지가 눌려 텍스트만 잘리고
                부모 `scrollWidth` 는 안 늘어나 — 하네스가 "잘림 0" 으로 통과한다(폭을 88 로 되돌린
                mutation 이 실제로 PASS 했다). 안 눌리게 두면 넘친 만큼 그대로 측정된다. */}
            {r.typeCounts.map(([t, n]) => (
              <span key={t} style={{ whiteSpace: "nowrap", flexShrink: 0 }}>
                <Badge>{TYPE_LABEL[t]}{n > 1 ? ` ${n}` : ""}</Badge>
              </span>
            ))}
          </div>
        )
        : "",
    } as never);
    // 상세 버튼은 **자기 열**로 뺀다. 배지와 같은 칸에 두면 배지 폭 계산에 96px 이 섞여 들어가
    // 접힘의 원인이 된다(원래 88px 칸에 배지 3개와 이 버튼이 같이 있었다).
    base.push({
      id: "detail", header: "", width: 96, minWidth: 96,
      cell: (r: Row) => r.kind === "finding"
        ? <Button variant="inline-link" onClick={() => openDetail(r.item)}><span style={{ whiteSpace: "nowrap" }}>상세 보기</span></Button>
        // 펼칠 수 없는 행에는 부모에 상세 버튼을 둔다 — 없으면 그 대상의 근거를 볼 길이 없다.
        : isCollapsed(r)
          ? <Button variant="inline-link" onClick={() => openDetail(repItem(r))}><span style={{ whiteSpace: "nowrap" }}>상세 보기</span></Button>
          : "",
    } as never);
    return base;
  };

  const expandable = (list: TargetRow[]) => ({
    getItemChildren: (r: Row): Row[] =>
      r.kind === "target"
        ? [...r.items]
            .sort((a, b) => RISK_ORDER[a.risk_level] - RISK_ORDER[b.risk_level] || a.type.localeCompare(b.type))
            .map((it) => ({ kind: "finding" as const, key: `${r.key}${it.id}`, item: it }))
        : [],
    isItemExpandable: (r: Row) => r.kind === "target" && !isCollapsed(r),
    expandedItems: list.filter((r) => expanded.has(r.key)) as Row[],
    onExpandableItemToggle: ({ detail: d }: { detail: { item: Row; expanded: boolean } }) => {
      setExpanded((prev) => {
        const next = new Set(prev);
        if (d.expanded) next.add(d.item.key);
        else next.delete(d.item.key);
        return next;
      });
    },
  });

  const emptyBox = (
    <Box padding="l" textAlign="center" color="text-status-inactive">
      {statusFilter !== "all" ? "이 상태에 해당하는 대상이 없습니다(필터를 바꿔 확인하세요)." : "해당하는 대상이 없습니다."}
    </Box>
  );

  const targetTable = (list: TargetRow[], kind: "default" | "ask" | "wait" | "fix", variant: "container" | "embedded" = "container") => (
    <Table
      empty={emptyBox}
      variant={variant}
      contentDensity="compact"
      wrapLines
      items={list as Row[]}
      trackBy="key"
      columnDefinitions={columns(kind) as never}
      // 삭제 검토는 어느 행도 펼치지 않는다 — 확장 기능 자체를 넘기지 않아 화살표 열이 안 생긴다.
      expandableRows={collapseTargets ? undefined : (expandable(list) as never)}
    />
  );

  return (
    <ContentLayout
      header={
        <SpaceBetween size="s">
          <BreadcrumbGroup
            items={[{ text: PAGE_TITLE, href: "#" }, { text: CARD_LABEL(openCard), href: "#" }]}
            onFollow={(e) => { e.preventDefault(); if (e.detail.text === PAGE_TITLE) setOpen(null); }}
          />
          <Header
            variant="h1"
            counter={`(대상 ${rows.length})`}
            // 🔴 접은 묶음에 "펼치면 문제가 나온다" 를 그대로 두면 화면에 없는 조작을 지시한다.
            description={`${openCard === UNGROUPED ? "" : GROUP_DESC[openCard]} 행 하나가 대상 하나입니다 — ${
              collapseTargets
                ? "할 일이 삭제 하나뿐이라 문제를 따로 펼치지 않습니다. 함께 발견된 사실과 근거는 상세 보기에 있고, 조치 상태는 대상 단위로 기록합니다."
                : "펼치면 그 대상에서 발견된 문제가 나오고, 조치 상태는 문제별로 기록합니다."
            }`}
            actions={
              <SpaceBetween direction="horizontal" size="xs">
                <Button onClick={() => setOpen(null)}>← 묶음으로</Button>
                <Button iconName="download" onClick={() => download(flatItems, `action_items_${openCard}.csv`)}>이 묶음 CSV</Button>
              </SpaceBetween>
            }
          >
            {CARD_LABEL(openCard)}
          </Header>
          {typeFocus && (
            <SpaceBetween direction="horizontal" size="xs">
              <Box>유형 필터: <b>{TYPE_LABEL[typeFocus]}</b> — 이 문제를 가진 대상만 보고 있습니다.</Box>
              <Link onFollow={() => setOpen(openCard)}>필터 해제 (전체 {allRows.length}개 대상)</Link>
            </SpaceBetween>
          )}
          {/* 고치는 곳 필터 — '권한 축소' 전용. 한 목적지로 몰아서 연속 처리하기 위한 것이다. */}
          {isFixCard && (
            <SegmentedControl
              selectedId={destFilter}
              onChange={(e) => setDestFilter(e.detail.selectedId as FixDest | "unknown" | "all")}
              label="고치는 곳 필터"
              options={[
                { id: "all", text: `전체 ${focusRows.length}` },
                { id: "service_role", text: `${DEST_LABEL.service_role} ${destDist.service_role}` },
                { id: "persona", text: `${DEST_LABEL.persona} ${destDist.persona}` },
                // 🔴 '판정 불가' 는 0 이면 내지 않는다. 늘 띄우면 없는 문제를 있는 것처럼 보이고,
                //    생겼을 때는 이 칸이 그것을 셀 수 있는 유일한 자리다.
                ...(destDist.unknown > 0 ? [{ id: "unknown", text: `판정 불가 ${destDist.unknown}` }] : []),
              ]}
            />
          )}
          {/* 상태 필터 — 기본 '전체'(카드 숫자와 행 수가 같아야 한다). 라벨에 건수를 실어
              "조치완료로 옮겨간 것" 이 보이게 한다. */}
          <SegmentedControl
            selectedId={statusFilter}
            onChange={(e) => setStatusFilter(e.detail.selectedId as CleanupStatus | "all")}
            label="조치 상태 필터"
            options={[
              { id: "all", text: `전체 ${focusRows.length}` },
              ...STATUS_ORDER.map((s) => ({ id: s, text: `${STATUS_LABEL[s]} ${statusDist[s]}` })),
            ]}
          />
        </SpaceBetween>
      }
    >
      <SpaceBetween size="l">
        {/* 이 묶음에 와일드카드가 있으면 같은 경고를 다시 낸다 — 딥링크·CSV 로 이 화면에 직접 들어온
            사람은 요약 화면의 배너를 보지 못한다. 표에 "미사용 개수" 칼럼이 없다는 사실 자체가
            설명 없이는 데이터 누락처럼 보인다. */}
        {flatItems.some((i) => WILDCARD_TYPES.has(i.type)) && (
          <Alert type="warning" header="와일드카드 보유 대상은 미사용 권한 개수를 산정하지 않습니다">
            부여 범위에 상한이 없어 개수를 셀 수 없습니다(0 이 아니라 <b>산정 불가</b>입니다).
            권장 조치는 실사용 기록 기준의 정책 재작성이며, 상세 보기의 근거에 같은 문장이 있습니다.
          </Alert>
        )}

        {openCard === "delete_review" && (
          <Alert type="info" header="이 묶음만 삭제를 권고합니다">
            미사용 기간이 임계를 넘었고, 신뢰 대상이 <b>우리 계정으로 확인된</b> 대상입니다. 신뢰 대상을
            확인할 수 없었던 역할은 여기 없습니다 — <Link onFollow={() => setOpen("needs_confirmation")}>확인 필요</Link>로
            갈라 두었습니다(벤더가 심은 연동을 지우게 하지 않기 위해서입니다).
          </Alert>
        )}

        {isFixCard && (
          <Container
            header={
              <Header
                variant="h3"
                description="여기서 할 일은 삭제가 아니라 정책 재작성입니다. 그 작업은 아래 두 화면에서 합니다 — 사람이 쓰는 역할은 여러 대상을 묶어 공통 정책 하나로, 서비스가 쓰는 역할은 역할별 개별 정책으로 만듭니다(묶으면 서로의 권한을 얻습니다)."
              >
                정책을 다시 쓰는 화면
              </Header>
            }
          >
            <SpaceBetween size="m">
              {/* 🔴 이 두 버튼은 목적지 화면을 **그냥 여는** 길이다. 대상 하나를 고치러 갈 때는
                  표의 「고치는 곳」 열에 있는 행별 버튼을 쓴다 — 그 버튼은 그 대상의 상세를 바로
                  열어서, 도착한 화면에서 수십·수백 행을 눈으로 훑지 않게 한다(사용자 피드백). */}
              <Box fontSize="body-s" color="text-body-secondary">
                대상 하나를 고치러 갈 때는 아래 표 <b>「고치는 곳」</b> 열의 버튼을 누르십시오 — 그 대상이
                열린 상태로 도착합니다. 이 두 버튼은 목적지 화면 전체를 열 때 씁니다.
              </Box>
              <SpaceBetween size="xxs">
                <Box>사람이 쓰는 역할 <b>{destDist.persona}개 대상</b></Box>
                {/* 🔴 버튼에 목적지 건수를 적지 않는다. 저쪽 화면의 단위는 **묶음**이라 이
                    숫자와 다르다(여러 대상이 한 persona 로 묶인다). 같은 숫자를 두 화면에
                    다른 단위로 적으면 "숫자가 틀렸다" 로 읽힌다. */}
                <Button onClick={() => navigate("/personas")}>Persona 검토 열기</Button>
              </SpaceBetween>
              <SpaceBetween size="xxs">
                <Box>AWS 서비스가 사용하는 역할 <b>{destDist.service_role}개 대상</b></Box>
                <Button onClick={() => navigate("/service-roles")}>서비스 역할 정리 열기</Button>
              </SpaceBetween>
              {/* 목적지를 정할 수 없는 대상도 개수로 남긴다(R6). 0 이면 이 줄이 아예 없다. */}
              {destDist.unknown > 0 && (
                <Box color="text-status-warning">
                  고치는 곳을 판정할 수 없는 대상 <b>{destDist.unknown}개</b> — 항목의 track 이 비어
                  있거나 사람·기계 두 트랙에 걸쳐 있습니다. 어느 쪽으로 보낼지 사람이 정해야 하므로
                  자동 이동 버튼을 내지 않습니다(상세 보기에서 track 을 확인하십시오).
                </Box>
              )}
            </SpaceBetween>
          </Container>
        )}

        {openCard === "needs_confirmation" ? (
          <>
            <Container
              header={
                <Header variant="h3" counter={`(${askRows.length})`}
                  description="사람에게 물어야 알 수 있습니다. 신뢰 계정 소유자에게 용도를 확인한 뒤 판단하십시오.">
                  확인해야 알 수 있는 것
                </Header>
              }
            >
              <SpaceBetween size="m">
                <Alert type="info" header="여기 있는 대상은 외부라고 판정된 것이 아닙니다">
                  신뢰 대상을 <b>우리 계정으로 확인하지 못한</b> 것입니다(모르면 보수적으로 이쪽으로
                  옵니다). 벤더·외부 도구가 심은 연동일 수 있어, 미사용 기간이 길어도 삭제를 권하지
                  않습니다. 실사용 근거가 action 단위로 확인되지 않은 대상도 같은 이유로 여기 있습니다.
                </Alert>
                {targetTable(
                  [...askRows].sort((a, b) => a.trustAccounts.localeCompare(b.trustAccounts) || sortRows(a, b)),
                  "ask", "embedded",
                )}
              </SpaceBetween>
            </Container>
            <Container
              header={
                <Header variant="h3" counter={`(${waitRows.length})`}
                  description="기다리면 알 수 있습니다. 생성 후 관측 기간이 차면 다음 조회에서 자동으로 판정됩니다 — 지금 할 일은 없습니다.">
                  기다리면 알 수 있는 것
                </Header>
              }
            >
              {targetTable(
                [...waitRows].sort((a, b) => (a.daysLeft ?? 0) - (b.daysLeft ?? 0) || sortRows(a, b)),
                "wait", "embedded",
              )}
            </Container>
          </>
        ) : (
          targetTable(rows, isFixCard ? "fix" : "default")
        )}
      </SpaceBetween>

      <Modal
        visible={!!detail}
        onDismiss={() => setDetail(null)}
        size="large"
        header={detail ? <SpaceBetween direction="horizontal" size="xs"><Badge>{TYPE_LABEL[detail.type]}</Badge><Box>{detail.principal.split("/").pop()}</Box><StatusIndicator type={STATUS_INDICATOR[detail.status]}>{STATUS_LABEL[detail.status]}</StatusIndicator></SpaceBetween> : ""}
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button onClick={() => setDetail(null)} disabled={saving}>닫기</Button>
              {/* finding_key 가 없는 항목(이전 형식 산출물)은 상태를 붙일 대상을 특정할 수 없다 →
                  저장 버튼을 비활성화한다. 눌러도 되게 두면 400 을 받는다. */}
              <Button
                variant="primary"
                loading={saving}
                disabled={!detail?.finding_key || (draftStatus === detail?.status && draftNote === detail?.status_note)}
                onClick={() =>
                  detail && saveStatus(
                    detail,
                    collapseTargets
                      ? detailSiblings.map((s) => s.finding_key).filter(Boolean)
                      : [],
                  )
                }
              >
                조치 상태 저장
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        {detail && (
          <SpaceBetween size="l">
            {/* ① 위험도 배너 — 색으로 심각도를 첫눈에. 무엇을 왜 해야 하는지 한 줄 요약.
                🔴 점수의 단위를 함께 밝힌다: `risk_score` 는 이 발견 하나가 아니라 **대상(역할·사용자)
                단위** 값이다(`m6_reporter.py:769` — 모든 발견이 같은 `rec.risk_score` 를 받는다).
                이걸 안 적으면 "이 발견의 상세 근거만으로는 75점이 설명되지 않는다" 로 읽힌다(F17-2). */}
            <Alert
              type={LEVEL_ALERT[detail.risk_level]}
              header={`위험도 ${detail.risk_level.toUpperCase()} · ${detail.risk_score}점 — ${LEVEL_MEANING[detail.risk_level]}`}
            >
              <SpaceBetween size="xxs">
                <Box>{detail.detail}</Box>
                <Box fontSize="body-s" color="text-body-secondary">
                  {detail.risk_score}점은 이 발견 하나의 점수가 아니라 이 대상에서 발견된 사실 전부를 합산한
                  대상 단위 점수입니다.
                </Box>
              </SpaceBetween>
            </Alert>

            {/* ② 대상 — 누구/어디. 묶음을 함께 적는다: 같은 대상이 두 묶음에 없다는 것이 이 화면의
                계약이므로, 상세에서도 그 하나가 무엇인지 보여야 한다. */}
            <Container header={<Header variant="h3">대상</Header>}>
              <KeyValuePairs
                columns={2}
                items={[
                  { label: "계정", value: detail.account_id },
                  { label: "조치 묶음", value: detail.group ? GROUP_LABEL[detail.group] : "미분류" },
                  { label: "발견 유형", value: TYPE_LABEL[detail.type] },
                  {
                    label: "Principal (ARN)",
                    value: <Box fontSize="body-s" fontWeight="normal">{detail.principal}</Box>,
                  },
                ]}
              />
            </Container>

            {/* ③ 상세 근거 — 무엇이 문제인지 구체 수치. 🔴 **최상단 한 줄**은 점수를 가장 많이 올린
                규칙이다(F17-2: "왜 이 점수인지" 가 화면 어디에도 요약돼 있지 않다는 피드백).
                정렬은 엔진이 기여도 내림차순으로 이미 해두므로 여기서 다시 고르지 않는다 — 첫 원소가
                1위다. 다만 점수 표기가 없는(이전 형식) run 에서는 그 가정이 성립하지 않아 이 줄을
                내지 않는다(`reasonPoints`). 전체 목록은 아래 ④ 에 그대로 있다. */}
            {(detail.risk_reasons.length > 0 || (detail.evidence && Object.keys(detail.evidence).length > 0)) && (
              <Container header={<Header variant="h3">상세 근거</Header>}>
                <SpaceBetween size="m">
                  {detail.risk_reasons.length > 0 && reasonPoints(detail.risk_reasons[0]) !== null && (
                    <SpaceBetween size="xxxs">
                      <Box variant="awsui-key-label">점수를 가장 많이 올린 것</Box>
                      <Box fontWeight="bold">{detail.risk_reasons[0]}</Box>
                      <Box fontSize="body-s" color="text-body-secondary">
                        {detail.risk_reasons.length > 1
                          ? `${detail.risk_score}점 중 ${reasonPoints(detail.risk_reasons[0])}점이 이 사실에서 나왔습니다. 나머지 ${detail.risk_reasons.length - 1}건은 아래 '위험 판정 근거' 에 기여도 순으로 있습니다.`
                          : `${detail.risk_score}점 중 ${reasonPoints(detail.risk_reasons[0])}점이 이 사실에서 나왔습니다.`}
                      </Box>
                    </SpaceBetween>
                  )}
                  {detail.evidence && Object.keys(detail.evidence).length > 0 && (
                    <KeyValuePairs
                      columns={3}
                      items={Object.entries(detail.evidence).map(([k, v]) => ({ label: k, value: v }))}
                    />
                  )}
                </SpaceBetween>
              </Container>
            )}

            {/* ③-b 이 대상이 가진 다른 사실 — 목록에서 자식 행을 접은 묶음(삭제 검토)에서만 낸다.
                다른 묶음은 자식 행이 그대로 있으므로 여기서 다시 내면 같은 내용이 두 번 나온다.
                🔴 사실만 낸다: 유형·위험도·발견 내용까지. `recommendation` 은 의도적으로 뺀다. */}
            {collapseTargets && detailSiblings.length > 0 && (
              <Container
                header={
                  <Header
                    variant="h3"
                    counter={`(${detailSiblings.length})`}
                    description="삭제 여부를 가른 근거는 위의 미사용 기간입니다. 아래는 같은 대상에서 함께 발견된 사실로, 삭제를 서둘러야 하는 이유(위험도 가산)입니다 — 목록의 위험도는 이 사실들을 포함한 최고치입니다. 삭제하지 않기로 판단한다면 이 사실들이 남습니다."
                  >
                    이 대상이 가진 다른 사실
                  </Header>
                }
              >
                <SpaceBetween size="s">
                  {detailSiblings.map((s) => {
                    const ev = firstEvidence(s);
                    return (
                      <SpaceBetween key={s.id} size="xxxs">
                        <SpaceBetween direction="horizontal" size="xs">
                          <StatusIndicator type={RISK_INDICATOR[s.risk_level]}>{s.risk_level}</StatusIndicator>
                          <Badge>{TYPE_LABEL[s.type]}</Badge>
                        </SpaceBetween>
                        <Box fontSize="body-s" color="text-body-secondary">{s.detail}</Box>
                        {/* 사실 문장만으로는 숫자가 없다 — 유형별 핵심 증거 한 줄을 붙인다(F17-2). */}
                        {ev && (
                          <Box fontSize="body-s" color="text-status-inactive">{ev[0]}: {ev[1]}</Box>
                        )}
                      </SpaceBetween>
                    );
                  })}
                </SpaceBetween>
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

            {/* ⑤ 권장 조치 — 어떻게 해결할지. '확인 필요' 묶음은 조치가 아니라 확인이므로 색을 바꾼다
                (초록 '권장 조치' 로 두면 카드 제목과 반대를 말하는 셈이다). */}
            <Alert
              type={detail.group === "needs_confirmation" ? "info" : "success"}
              header={detail.group === "needs_confirmation" ? "먼저 확인할 것" : "권장 조치"}
            >
              {detail.recommendation}
            </Alert>

            {/* ⑥ 조치 상태 표시 — 권장 조치와 다른 방법(예: IdC 없이 IAM 정책만 다듬어 적용)으로
                해결한 경우도 '조치완료' 로 기록할 수 있어야 한다. 메모에 그 방법을 남긴다. */}
            <Container
              header={
                <Header
                  variant="h3"
                  description={`이 표시는 기록일 뿐이며 AWS 자원을 변경하지 않습니다.${
                    collapseTargets && detailSiblings.length > 0
                      ? ` 이 묶음은 조치가 삭제 하나이므로, 표시는 이 대상에서 발견된 ${detailSiblings.length + 1}건 전부에 함께 적용됩니다.`
                      : ""
                  }`}
                >
                  조치 상태
                </Header>
              }
            >
              <SpaceBetween size="m">
                {!detail.finding_key && (
                  <Alert type="info" header="이 항목은 상태를 표시할 수 없습니다">
                    이전 형식의 조회 결과라 항목을 고유하게 식별할 수 없습니다. 전체 조회를 한 번 더 실행하면 표시할 수 있습니다.
                  </Alert>
                )}
                <SegmentedControl
                  selectedId={draftStatus}
                  onChange={(e) => setDraftStatus(e.detail.selectedId as CleanupStatus)}
                  label="조치 상태"
                  options={STATUS_ORDER.map((s) => ({ id: s, text: STATUS_LABEL[s], disabled: !detail.finding_key }))}
                />
                <Box color="text-body-secondary" fontSize="body-s">{STATUS_HINT[draftStatus]}</Box>
                <FormField label="메모 (선택)" description="어떻게 처리했는지 남깁니다. 예: IdC 를 쓰지 않아 최소권한 IAM 정책만 적용함. 최대 500자.">
                  <Textarea
                    value={draftNote}
                    onChange={(e) => setDraftNote(e.detail.value.slice(0, 500))}
                    disabled={!detail.finding_key}
                    placeholder="처리 방법·근거"
                    rows={2}
                  />
                </FormField>
                {detail.status_updated_at && (
                  <Box fontSize="body-s" color="text-body-secondary">
                    최근 표시: {detail.status_updated_at}{detail.status_updated_by ? ` · ${detail.status_updated_by}` : ""}
                  </Box>
                )}
                {saveError && <Alert type="error" header="조치 상태 저장 실패">{saveError}</Alert>}
              </SpaceBetween>
            </Container>
          </SpaceBetween>
        )}
      </Modal>
    </ContentLayout>
  );
}
