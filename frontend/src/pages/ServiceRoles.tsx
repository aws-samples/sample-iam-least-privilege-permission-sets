// ============================================================================
// 트랙② — 기계가 쓰는 현역 역할의 권한 정리 화면 (R7 / P6).
//
// **권한을 세지 말고 결정을 센다.** 부여 권한을 하나씩 뿌리면 한 역할에서 3,000줄이 나오고 그건
// 안 뿌리는 것과 같다. 접기·판단 필요 서비스 계산은 전부 엔진(M5)이 끝냈고, 이 화면은 그 값을
// **그대로** 보여준다 — 여기서 다시 세면 같은 권한이 화면과 산출물에서 다르게 읽힌다.
//
// 3층 구조: 1층 대시보드 숫자 하나(정리 권고 N건) → 2층 목록(역할·등급·일수·사용하지 않는 서비스
// 수) → 3층에서 처음 서비스 접기 화면. **정책 파일 본문은 화면에 렌더하지 않는다** — 목록만 CSV.
//
// persona 처럼 묶지 않는다: Lambda 실행 역할 둘을 한 정책으로 묶으면 서로의 권한을 얻는다.
// `group_key`(부여 권한 집합의 해시)는 **표시용 정보**이며, 이 화면은 그것으로 행을 합치지 않는다 —
// 부여 권한이 같아도 사용 실태가 달라 등급·일수·사용하지 않는 서비스 수가 역할마다 다르기 때문이다
// (합치면 화면에 실제 값이 아닌 숫자가 생긴다).
// ============================================================================
import { useMemo, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import Container from "@cloudscape-design/components/container";
import Table from "@cloudscape-design/components/table";
import Box from "@cloudscape-design/components/box";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Button from "@cloudscape-design/components/button";
import Link from "@cloudscape-design/components/link";
import Badge from "@cloudscape-design/components/badge";
import Alert from "@cloudscape-design/components/alert";
import Spinner from "@cloudscape-design/components/spinner";
import Popover from "@cloudscape-design/components/popover";
import SegmentedControl from "@cloudscape-design/components/segmented-control";
import BreadcrumbGroup from "@cloudscape-design/components/breadcrumb-group";
import ExpandableSection from "@cloudscape-design/components/expandable-section";
import KeyValuePairs from "@cloudscape-design/components/key-value-pairs";
import { api } from "@/api/client";
import { useAsync } from "@/api/useAsync";
import { useAccounts } from "@/AccountContext";
import { downloadCsv } from "@/lib/csv";
import { tierLabel, cleanupDays } from "@/lib/tierLabel";
import type { RiskCriteria, ServiceRoleEntry, ServiceRollup, UnusedTier } from "@/api/types";

export const PAGE_TITLE = "서비스 역할 정리";

// 🔴 예전에 여기 있던 `OBSERVED_MIN_DAYS = 30` 은 **폐기했다**(F14-2). 두 가지가 틀려 있었다:
//   ① 임계치 리터럴이 UI 에 있었다(불변식 ④ — 임계치는 config 뿐).
//   ② 그 값이 `cloudtrail_max_pages = 200` 과 양립하지 않아 **도달 불가능**했다. 200페이지 ×
//      50건 = 10,000건이므로 `observed_days ≥ 30` 이려면 계정 이벤트 발생률이 10,000 ÷ 720시간 =
//      시간당 13.9건 이하여야 한다. 실측 이 계정 2,247건/시간 → 경고는 **항상 error** 로 떴다.
//      항상 빨강인 경고는 경고가 아니라 배경이다(고객은 학습해서 무시한다).
// 관측 구간을 숫자로 말해도 되는 기준은 이제 config 에서 온다
// (`ServiceRoleEntry.count_min_observed_days` ← `catalog.count_min_observed_days`).
const DEFAULT_COUNT_MIN_OBSERVED_DAYS = 7;

// 관측 구간을 숫자로 말해도 되는가. 측정값이 없거나 기준값 미만이면 **표기하지 않는다** —
// 사용자 결정(2026-09-11): *"관측 기간이 장기 일수가 아니라 몇 시간 이런 식으로 보여지는 거라면
// 그냥 표기를 안 해주는 게 맞다. 오히려 고객의 신뢰를 무너뜨릴 수도 있다."*
function showsObserved(e: ServiceRoleEntry): boolean {
  const min = e.count_min_observed_days ?? DEFAULT_COUNT_MIN_OBSERVED_DAYS;
  return e.observed_days !== null && e.observed_days >= min;
}

// 등급 라벨 — 색이 아니라 **문장**이 의미를 진다(팔레트 규칙: 상태색·시리즈색을 섞지 않는다).
// 문구는 `lib/tierLabel.ts` 한 곳에서만 만든다(예전에는 이 파일과 Dashboard 가 각자 만들어
// `cleanup (90일 이상)` 처럼 영문 계약값을 화면에 노출했다). 경계 숫자는 config 에서 온다.
const TIER_ORDER: (UnusedTier | null)[] = ["cleanup", "review", "watch", "new", "active", null];

const VERDICT_LABEL: Record<ServiceRollup["verdict"], string> = {
  keep: "유지",
  remove: "제거 후보",
  undetermined: "판정 불가",
};

// 경계값은 인자로 받는다 — 모듈 전역에 캐시해 두면 값이 도착해도 다시 렌더되지 않아
// 첫 화면이 기본값 문구로 굳는다.
function tierText(t: UnusedTier | null, days?: readonly number[]): string {
  return tierLabel(t, days);
}

// 미사용 일수 문구 — **무엇부터 셌는지**에 따라 갈린다. 근거가 생성일이면 그렇게 말한다.
function unusedText(e: ServiceRoleEntry): string {
  if (e.unused_days === null) return "미측정";
  if (e.unused_days_basis === "create_date") {
    return `${e.unused_days.toLocaleString()}일 (생성일 기준 — 활동 기록 없음)`;
  }
  return `${e.unused_days.toLocaleString()}일`;
}

// 관측 구간 문구. 표기 가능할 때만 부른다(`showsObserved`) — "0일"·"근거 없음" 을 쓰지 않는다.
function observedText(d: number): string {
  return `${d.toLocaleString()}일`;
}

const removeRollups = (e: ServiceRoleEntry) => e.service_rollups.filter((r) => r.verdict === "remove");
const keepRollups = (e: ServiceRoleEntry) => e.service_rollups.filter((r) => r.verdict === "keep");
const undeterminedRollups = (e: ServiceRoleEntry) =>
  e.service_rollups.filter((r) => r.verdict === "undetermined");

const roleName = (arn: string) => arn.split("/").pop() ?? arn;

/**
 * 트랙② 전용 상시 경고 — 화면을 열면 **항상** 보인다(닫히지 않는다).
 *
 * 기계 역할의 권한 축소는 장애로 직결된다. 그것이 이 경고의 이유이고, 강도는 고정이다.
 *
 * 🔴 예전에는 CloudTrail 관측 구간이 짧으면 `error` 로 승격했고 문구도 *"판정 근거인 CloudTrail
 * 관측 구간"* 이라고 말했다. **둘 다 틀렸다**(F14-3):
 *  - verdict 의 근거는 CloudTrail 이 아니다. `_rollups`(`m5_service_roles.py`) 확인 —
 *    `keep` ← 사용 기록 있음 **또는** Access Advisor 서비스 인증, `remove` ← 부여 권한 전부가
 *    `unused_findings`. 그리고 `unused_findings` 는 Advisor 의 **양성 부재 근거만** 인정한다
 *    (`m2_normalizer.py`). CloudTrail 부재는 단독으로 미사용 확정을 만들 수 없다 → 창이 짧아도
 *    잘못된 제거 권고는 생기지 않는다.
 *  - 승격 조건(30일)이 `cloudtrail_max_pages` 와 양립하지 않아 항상 참이었다(F14-2).
 * 그래서 CloudTrail 의 역할을 **호출 횟수·최근 사용 시각의 근거**로 좁혀서 말한다.
 */
function TrackWarning() {
  return (
    <Alert
      type="warning"
      header="기계 역할의 권한 축소는 장애로 직결됩니다 — 적용 전 스테이징에서 검증하세요"
    >
      <SpaceBetween size="xs">
        <Box>
          이 목록의 역할은 <b>사람이 아니라 기계가 씁니다</b>. 권한을 줄이면 그 워크로드가 즉시
          실패할 수 있으므로, 반드시 스테이징에서 검증한 뒤 적용하세요. LP2PS 는 AWS 자원을
          변경하지 않습니다(읽기 전용).
        </Box>
        <Box>
          유지/제거 판정의 근거는 <b>IAM Access Advisor</b>(서비스·action 단위 최종 사용 시각,
          최대 400일까지 잘리지 않음)입니다. Advisor 근거가 없는 서비스는 미사용으로 확정하지 않고{" "}
          <b>판정 불가</b>로 남깁니다. CloudTrail 은 호출 횟수와 최근 사용 시각의 근거일 뿐입니다.
        </Box>
        <Box>
          그래도 <b>부족할 수 있습니다</b> — 데이터 이벤트는 기본 미기록이고, Advisor 가 추적하지
          않는 action 도 있습니다. 월말 배치·분기 작업처럼 드물게 도는 경로를 특히 확인하세요.
        </Box>
      </SpaceBetween>
    </Alert>
  );
}

// 부여 권한 집합이 동일한 형제 역할. 접지 않고 **알려만 준다** — 정책은 역할별로 따로 낸다.
function SiblingCell({ entry, all, tierDays }: { entry: ServiceRoleEntry; all: ServiceRoleEntry[]; tierDays?: readonly number[] }) {
  if (!entry.group_key) return <Box color="text-status-inactive" fontSize="body-s">—</Box>;
  const sibs = all.filter((e) => e.group_key === entry.group_key && e.principal !== entry.principal);
  if (sibs.length === 0) return <Box fontSize="body-s" color="text-status-inactive">단독</Box>;
  return (
    <Popover
      dismissButton={false}
      position="top"
      size="medium"
      triggerType="custom"
      header={`부여 권한이 같은 역할 ${sibs.length + 1}개`}
      content={
        <SpaceBetween size="xs">
          <Box>
            부여된 권한이 같습니다. 그래도 <b>정책은 역할별로 따로</b> 적용해야 합니다 — 한 정책으로
            묶으면 서로의 권한을 얻어 최소권한의 반대가 됩니다. 사용 실태가 달라 사용하지 않는
            서비스 수도 역할마다 다릅니다.
          </Box>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {sibs.map((s) => (
              <li key={s.principal}>
                <Box fontSize="body-s">
                  {roleName(s.principal)} · {tierText(s.unused_tier, tierDays)} · 사용하지 않는 서비스 {removeRollups(s).length}
                </Box>
              </li>
            ))}
          </ul>
        </SpaceBetween>
      }
    >
      <span style={{ cursor: "pointer", borderBottom: "1px dashed currentColor", whiteSpace: "nowrap" }}>
        +{sibs.length}개 동일
      </span>
    </Popover>
  );
}

// `unused_tier` 는 계약값(cleanup 등)이고 `unused_tier_label` 은 화면에서 읽은 문구다. 둘을 함께
// 담는 것은 이 파일의 `verdict`/`verdict_label` 규약과 같다 — 스크립트는 계약값으로 처리하고,
// 사람은 화면과 같은 어휘로 논의한다. 계약값만 내리면 CSV 를 받은 사람이 `cleanup` 을 스스로
// 해석해야 하고, 라벨만 내리면 경계를 바꾼 고객의 CSV 가 다른 컬럼값을 갖게 된다.
const LIST_CSV_HEAD = ["account_id", "principal", "group_key", "unused_tier", "unused_tier_label", "unused_days",
  "unused_days_basis", "observed_days", "granted_count", "unused_count", "decision_count",
  "remove_services", "keep_services", "undetermined_services", "wildcard_grants"];

function listRow(e: ServiceRoleEntry, tierDays?: readonly number[]): string[] {
  return [
    e.account_id, e.principal, e.group_key,
    // null 을 빈 칸으로 내리면 스프레드시트에서 0 처럼 읽힌다. 미측정은 미측정이라고 쓴다.
    e.unused_tier ?? "미측정",
    tierText(e.unused_tier, tierDays),
    e.unused_days === null ? "미측정" : String(e.unused_days),
    e.unused_days_basis ?? "미측정",
    e.observed_days === null ? "근거 없음" : String(e.observed_days),
    String(e.granted_count), String(e.unused_count), String(e.decision_count),
    String(removeRollups(e).length), String(keepRollups(e).length), String(undeterminedRollups(e).length),
    e.wildcard_grants.join("|"),
  ];
}

// `verdict` 는 계약값(keep/remove/undetermined)을 그대로 내리고, 화면에서 읽은 단어(`verdict_label`)를
// 함께 담는다 — CSV 를 받은 사람이 화면과 다른 어휘로 논의하지 않게 한다.
const DETAIL_CSV_HEAD = ["account_id", "principal", "namespace", "verdict", "verdict_label", "tier", "tier_label",
  "granted_count", "used_count", "last_used", "wildcard_grants"];

export default function ServiceRoles() {
  const { data, loading, error } = useAsync<ServiceRoleEntry[]>(() => api.getServiceRoles());
  // 등급 라벨이 "N일 이상 미사용" 이라 경계값이 필요하다. 실패해도 화면은 그려야 하므로
  // 값이 없으면 `lib/tierLabel.ts` 기본값(30/60/90)으로 문구를 만든다.
  const { data: criteria } = useAsync<RiskCriteria>(() => api.getRiskCriteria());
  const tierDays = criteria?.unused_tier_days;
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  // 등급 필터 기본 ON(cleanup 만) — 첫 화면을 수십 줄로 유지한다(R7). 필터는 숨김이 아니라
  // 순서 문제라서, 걸러진 건수를 필터 옆에 항상 적는다.
  //
  // 🔴 단, 기본값을 `cleanup` 으로 **못박지 않는다**. 이 화면은 트랙②("기계가 쓰는 **현역** 역할")
  //    이고 미사용 기계 역할은 삭제 검토 묶음으로 빠진다 → cleanup 등급이 0 인 것이 정상이다
  //    (라이브 실측: 0 / 82). 못박으면 첫 화면이 통째로 빈 목록이 되고, 그건 "정리할 것이 없다"
  //    는 거짓으로 읽힌다. 사람이 고르기 전까지는 데이터를 보고 정한다.
  const [tierPick, setTierPick] = useState<"cleanup" | "all" | null>(null);
  const { selected } = useAccounts();

  const scoped = useMemo(
    () => (data ?? []).filter((e) => !selected || e.account_id === selected),
    [data, selected],
  );

  const openRole = searchParams.get("role");
  // 조치 필요 항목의 '권한 축소' 행에서 온 경우(`from=cleanup`) 돌아갈 길을 낸다. 고친 뒤 **조치 완료
  // 표시는 그 화면에서만** 하므로(이 화면에 상태 토글을 두지 않는다) 왕복이 되어야 한다.
  const from = searchParams.get("from");
  const setOpenRole = (arn: string | null) => {
    // 🔴 `from` 을 함께 남긴다 — 상세에서 목록으로 물러난 뒤에도 돌아갈 버튼이 남아 있어야 한다.
    const next: Record<string, string> = {};
    if (arn) next.role = arn;
    if (from) next.from = from;
    setSearchParams(next);
  };
  const backToCleanup = from === "cleanup" ? (
    <Button onClick={() => navigate("/cleanup?group=reduce_scope")}>← 조치 필요 항목(권한 축소)</Button>
  ) : null;

  if (loading && !data) {
    return <Box padding="xxl" textAlign="center"><Spinner size="large" /></Box>;
  }
  if (error) {
    // 0 과 "못 읽었다" 를 구분한다 — 실패를 빈 목록으로 그리면 "정리할 것이 없다" 는 거짓이 된다.
    return (
      <ContentLayout header={<Header variant="h1">{PAGE_TITLE}</Header>}>
        <Alert type="error" header="트랙② 목록을 읽지 못했습니다">
          {error} — 이 화면은 최신 실행의 <code>service_roles.json</code> 을 읽습니다. 목록이 비어
          보이는 것과 읽기 실패는 다른 상태이므로 0 으로 표시하지 않습니다.
        </Alert>
      </ContentLayout>
    );
  }

  const entry = openRole ? scoped.find((e) => e.principal === openRole) : undefined;

  // ---- 3층: 서비스 접기 상세 ----
  if (openRole) {
    if (!entry) {
      return (
        <ContentLayout header={<Header variant="h1">{PAGE_TITLE}</Header>}>
          <SpaceBetween size="l">
            <Alert type="info" header="이 역할이 현재 범위에 없습니다">
              계정 선택이 바뀌었거나 최신 실행에서 대상이 아닙니다. 상단 계정 선택기를 이 역할의 계정
              (또는 전체 계정)으로 바꾸면 나타납니다.
            </Alert>
            <SpaceBetween direction="horizontal" size="xs">
              <Button onClick={() => setOpenRole(null)}>← 목록으로</Button>
              {backToCleanup}
            </SpaceBetween>
          </SpaceBetween>
        </ContentLayout>
      );
    }
    const removes = removeRollups(entry);
    const keeps = keepRollups(entry);
    const undet = undeterminedRollups(entry);
    return (
      <ContentLayout
        header={
          <SpaceBetween size="s">
            <BreadcrumbGroup
              items={[{ text: PAGE_TITLE, href: "#" }, { text: roleName(entry.principal), href: "#" }]}
              onFollow={(e) => { e.preventDefault(); if (e.detail.text === PAGE_TITLE) setOpenRole(null); }}
            />
            <Header
              variant="h1"
              counter={`(결정 ${entry.decision_count}건)`}
              description={`${entry.account_id} · ${entry.principal}`}
              actions={
                <SpaceBetween direction="horizontal" size="xs">
                  {backToCleanup}
                  <Button onClick={() => setOpenRole(null)}>← 목록으로</Button>
                  <Button
                    iconName="download"
                    onClick={() =>
                      downloadCsv(
                        `service_role_${roleName(entry.principal)}.csv`,
                        DETAIL_CSV_HEAD,
                        entry.service_rollups.map((r) => [
                          entry.account_id, entry.principal, r.namespace, r.verdict,
                          VERDICT_LABEL[r.verdict],
                          r.tier ?? "미측정", tierText(r.tier, tierDays), String(r.granted_count), String(r.used_count),
                          r.last_used ?? "기록 없음", r.wildcard_grants.join("|"),
                        ]),
                      )
                    }
                  >
                    결정 CSV
                  </Button>
                </SpaceBetween>
              }
            >
              {roleName(entry.principal)}
            </Header>
          </SpaceBetween>
        }
      >
        <SpaceBetween size="l">
          <TrackWarning />

          <Container header={<Header variant="h3">이 역할</Header>}>
            <KeyValuePairs
              columns={4}
              items={[
                { label: "미사용 등급", value: tierText(entry.unused_tier, tierDays) },
                { label: "미사용 일수", value: unusedText(entry) },
                // 🔴 관측 구간은 **표기 가능할 때만** 항목을 만든다. 실측에서 이 값이 0 이라
                //   "관측 구간 0일" 이 화면에 떴다(사용자 피드백 2026-09-11). 몇 시간짜리 창을
                //   숫자로 적으면 고객은 화면 결함으로 읽고, 판정이 그 창에 근거한 것으로 오해한다.
                //   verdict 의 근거는 Access Advisor 다(위 경고문) — 이 항목은 없어도 판정이 설명된다.
                ...(showsObserved(entry)
                  ? [{ label: "관측 구간(CloudTrail)", value: observedText(entry.observed_days!) }]
                  : []),
                { label: "판단 필요 서비스", value: `${entry.decision_count.toLocaleString()}개` },
                { label: "부여 권한", value: `${entry.granted_count.toLocaleString()}개` },
                { label: "미사용 확정", value: `${entry.unused_count.toLocaleString()}개` },
                { label: "서비스 행", value: `${entry.service_rollups.length.toLocaleString()}행 (부여 권한을 서비스 단위로 접은 결과)` },
                { label: "테넌트 그룹", value: entry.tenant_group || "default" },
              ]}
            />
          </Container>

          {entry.wildcard_grants.length > 0 && (
            <Alert type="warning" header="와일드카드가 부여돼 있습니다 — 개수로는 정리할 수 없습니다">
              <SpaceBetween size="xs">
                <Box>
                  부여 범위에 상한이 없어 <b>미사용 권한 개수를 셀 수 없습니다</b>(0 이 아니라 산정
                  불가). 조치는 "N개 제거" 가 아니라 <b>실사용 기록을 기준으로 정책을 다시 쓰는 것</b>
                  이며, 고쳐야 하는 문장이 바로 아래 원문입니다.
                </Box>
                <Box>
                  {entry.wildcard_grants.map((w) => <Badge key={w}>{w}</Badge>)}
                </Box>
              </SpaceBetween>
            </Alert>
          )}

          {/* 결정 ①: 인증 이력이 전혀 없는 서비스 = 한 덩어리 = **결정 1건**. 이 묶음이 없으면
              같은 정보가 수백 줄이 되고, 그건 안 보여주는 것과 같다. */}
          <Container
            header={
              <Header
                variant="h2"
                counter={`(서비스 ${removes.length} · 결정 ${removes.length ? 1 : 0}건)`}
                description="Access Advisor 가 '인증 기록 없음' 을 확인한 서비스입니다 — 그 안의 어떤 권한도 쓰였을 수 없습니다. 한 덩어리로 함께 제거하는 결정 1건입니다."
              >
                일괄 제거 후보
              </Header>
            }
          >
            {removes.length === 0 ? (
              <Box color="text-status-inactive">제거 후보 서비스가 없습니다 — 부여된 서비스를 모두 쓰고 있거나, 판정 근거가 없습니다.</Box>
            ) : (
              <SpaceBetween size="s">
                <Box>
                  {removes.map((r) => (
                    <Badge key={r.namespace}>{r.namespace} · {r.granted_count}</Badge>
                  ))}
                </Box>
                <Box fontSize="body-s" color="text-body-secondary">
                  배지의 숫자는 그 서비스에서 부여된(열거 가능한) 권한 수입니다. 합계{" "}
                  {removes.reduce((n, r) => n + r.granted_count, 0).toLocaleString()}개.
                </Box>
              </SpaceBetween>
            )}
          </Container>

          {/* 결정 ②: 유지 서비스 — 서비스별로 사람이 확인할 결정 1건씩. */}
          <Table
            variant="container"
            contentDensity="compact"
            header={
              <Header
                variant="h2"
                counter={`(${keeps.length})`}
                description="실제로 쓰이는 서비스입니다(action 단위 사용 기록 또는 Access Advisor 의 서비스 인증). 정책에 남기고, 서비스별로 남길 범위를 확인합니다."
              >
                유지 — 서비스별 확인
              </Header>
            }
            columnDefinitions={[
              { id: "ns", header: "서비스", cell: (r: ServiceRollup) => r.namespace },
              { id: "granted", header: "부여", width: 100, cell: (r: ServiceRollup) => r.granted_count.toLocaleString() },
              { id: "used", header: "사용", width: 100, cell: (r: ServiceRollup) => r.used_count.toLocaleString() },
              {
                id: "last", header: "마지막 사용", width: 200,
                cell: (r: ServiceRollup) => r.last_used ?? <Box color="text-status-inactive">서비스 인증만(action 기록 없음)</Box>,
              },
              { id: "tier", header: "등급(하한선)", cell: (r: ServiceRollup) => tierText(r.tier, tierDays) },
              {
                id: "wc", header: "와일드카드", cell: (r: ServiceRollup) =>
                  r.wildcard_grants.length ? r.wildcard_grants.join(", ") : <Box color="text-status-inactive">—</Box>,
              },
            ]}
            items={keeps}
            empty={<Box padding="m" color="text-status-inactive">유지로 판정된 서비스가 없습니다.</Box>}
          />

          {/* 결정에 세지 않는 것 — 결론이 '손대지 않는다' 이므로 사람이 내릴 결정이 없다.
              그래도 감추지 않는다: 왜 판정할 수 없었는지가 이 화면의 답이다. */}
          <ExpandableSection
            variant="container"
            headerText="판정 불가 — 손대지 않습니다"
            headerCounter={`(${undet.length})`}
            headerDescription="안 쓴다는 증거가 없는 서비스입니다. 판단 필요 서비스에 세지 않습니다 — 결론이 '그대로 둔다' 라 사람이 내릴 결정이 없습니다."
          >
            {undet.length === 0 ? (
              <Box color="text-status-inactive">판정 불가 서비스가 없습니다.</Box>
            ) : (
              <Table
                variant="embedded"
                contentDensity="compact"
                columnDefinitions={[
                  { id: "ns", header: "서비스", cell: (r: ServiceRollup) => r.namespace },
                  { id: "granted", header: "열거 가능한 부여", width: 160, cell: (r: ServiceRollup) => r.granted_count.toLocaleString() },
                  {
                    id: "why", header: "왜 판정할 수 없나",
                    cell: (r: ServiceRollup) =>
                      r.wildcard_grants.length
                        ? `이 서비스에 와일드카드만 부여돼 있습니다(${r.wildcard_grants.join(", ")}) — 셀 수 있는 권한이 없어 개수로 판정할 수 없습니다.`
                        : "이 서비스의 사용 근거(Access Advisor 인증·action 기록)를 확보하지 못했습니다. 안 썼다는 뜻이 아닙니다.",
                  },
                ]}
                items={undet}
              />
            )}
          </ExpandableSection>

          <Alert type="info" header="정책 본문은 화면에 표시하지 않습니다">
            한 역할에서 정책 본문은 수천 줄이 되고, 화면에 뿌리면 아무도 읽지 않습니다. 위의 결정
            목록을 <b>결정 CSV</b> 로 내려받아 검토하세요. 실제 정책 반영은 사람이 AWS 에서 수행합니다
            — LP2PS 는 대상 계정에 쓰지 않습니다.
          </Alert>
        </SpaceBetween>
      </ContentLayout>
    );
  }

  // ---- 2층: 목록 ----
  const cleanupCount = scoped.filter((e) => e.unused_tier === "cleanup").length;
  const tierFilter: "cleanup" | "all" = tierPick ?? (cleanupCount > 0 ? "cleanup" : "all");
  const rows = tierFilter === "cleanup" ? scoped.filter((e) => e.unused_tier === "cleanup") : scoped;
  const sorted = [...rows].sort(
    (a, b) =>
      TIER_ORDER.indexOf(a.unused_tier) - TIER_ORDER.indexOf(b.unused_tier) ||
      (b.unused_days ?? -1) - (a.unused_days ?? -1) ||
      a.principal.localeCompare(b.principal),
  );
  const hiddenUngraded = scoped.filter((e) => e.unused_tier === null).length;
  const decisions = sorted.reduce((n, e) => n + e.decision_count, 0);

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(역할 ${sorted.length} · 결정 ${decisions.toLocaleString()}건)`}
          description={`기계가 쓰는 현역 역할입니다(트랙②). ${selected ? `계정 ${selected}` : "전체 계정"} · 부여 권한을 서비스 단위로 접어 사람이 내릴 결정만 셉니다. persona 처럼 묶지 않습니다 — 정책은 역할별로 따로 적용합니다.`}
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              {backToCleanup}
              <Button
                iconName="download"
                disabled={sorted.length === 0}
                onClick={() => downloadCsv("service_roles.csv", LIST_CSV_HEAD, sorted.map((e) => listRow(e, tierDays)))}
              >
                표시 중인 목록 CSV
              </Button>
            </SpaceBetween>
          }
        >
          {PAGE_TITLE}
        </Header>
      }
    >
      <SpaceBetween size="l">
        {scoped.length === 0 ? (
          <Alert type="info" header="트랙② 대상이 없습니다">
            이 범위에서 기계가 쓰는 현역 역할이 0건입니다. 오류가 아니라 정상 상태입니다 — 실행이
            성공했고 대상이 없다는 뜻입니다.
          </Alert>
        ) : (
          <>
            <TrackWarning />

            <SpaceBetween size="xs">
              <SegmentedControl
                selectedId={tierFilter}
                onChange={(e) => setTierPick(e.detail.selectedId as "cleanup" | "all")}
                label="미사용 등급 필터"
                options={[
                  { id: "cleanup", text: `${cleanupDays(tierDays)}일 이상 미사용 ${cleanupCount}` },
                  { id: "all", text: `전체 ${scoped.length}` },
                ]}
              />
              <Box fontSize="body-s" color="text-body-secondary">
                {tierFilter === "cleanup" ? (
                  <>
                    {cleanupDays(tierDays)}일 이상 미사용인 역할만 보고 있습니다 — 첫 화면을 읽을 수 있는 크기로 두기
                    위한 기본값입니다. 나머지 {scoped.length - cleanupCount}개
                    {hiddenUngraded > 0 && <>(등급 미측정 {hiddenUngraded}개 포함)</>}는 "전체" 에서
                    볼 수 있습니다.
                  </>
                ) : (
                  <>
                    등급 미측정 {hiddenUngraded}개를 포함한 전부입니다. 미측정은 0 이 아니라 사용
                    일수를 셀 근거 자체가 없다는 뜻입니다.
                  </>
                )}
              </Box>
            </SpaceBetween>

            <Table
              variant="container"
              contentDensity="compact"
              wrapLines
              columnDefinitions={[
                {
                  id: "role", header: "역할",
                  cell: (e: ServiceRoleEntry) => (
                    <SpaceBetween size="xxxs">
                      <Link fontSize="body-m" onFollow={() => setOpenRole(e.principal)}>{roleName(e.principal)}</Link>
                      <Box fontSize="body-s" color="text-body-secondary">{e.account_id}</Box>
                    </SpaceBetween>
                  ),
                },
                { id: "tier", header: "미사용 등급", width: 190, cell: (e: ServiceRoleEntry) => tierText(e.unused_tier, tierDays) },
                { id: "days", header: "미사용 일수", width: 200, cell: (e: ServiceRoleEntry) => unusedText(e) },
                // 🔴 관측 구간 컬럼은 **표시할 값이 있는 대상이 하나라도 있을 때만** 존재한다.
                //   실측 79/79 가 `observed_days = 0` 이었다 → 늘 "0일" 만 늘어선 컬럼이었고,
                //   경고색까지 입혀 전 행이 노랗게 떴다(항상 노란 컬럼은 정보가 아니다).
                ...(sorted.some(showsObserved)
                  ? [{
                      id: "observed", header: "관측 구간", width: 130,
                      cell: (e: ServiceRoleEntry) =>
                        showsObserved(e)
                          ? observedText(e.observed_days!)
                          : <Box color="text-status-inactive">—</Box>,
                    }]
                  : []),
                {
                  // `줄일 서비스` → `사용하지 않는 서비스`(사용자 지시 2026-09-11, F15-1). 값은 불변 —
                  // "줄일" 은 우리가 시키는 조치처럼 읽히지만, 이 숫자가 말하는 것은 관측된 사실이다.
                  id: "remove", header: "사용하지 않는 서비스", width: 170,
                  cell: (e: ServiceRoleEntry) => removeRollups(e).length.toLocaleString(),
                },
                {
                  // `결정 수` → `판단 필요 서비스`. 값도 keep 서비스 수로 바뀌었다(F15-2) — 예전 값은
                  // 여기에 "일괄 제거" 묶음 1건을 더해 서비스 수와 작업 수를 한 칼럼에 섞었다.
                  id: "decisions", header: "판단 필요 서비스", width: 150,
                  cell: (e: ServiceRoleEntry) => e.decision_count.toLocaleString(),
                },
                {
                  id: "wildcard", header: "와일드카드", width: 150,
                  cell: (e: ServiceRoleEntry) =>
                    e.wildcard_grants.length ? (
                      // 와일드카드 보유자는 '미사용 확정' 개수가 0 으로 잡힌다 — 개수를 셀 수 없어서다.
                      // 이 칼럼이 없으면 가장 위험한 역할이 가장 깨끗해 보인다(R4).
                      <Box color="text-status-warning">{e.wildcard_grants.join(", ")}</Box>
                    ) : (
                      <Box color="text-status-inactive">—</Box>
                    ),
                },
                {
                  // `부여 집합` → `부여 권한이 같은 역할`(F15-3). "집합" 은 수학 용어이고, 이 칼럼이
                  // 답하는 질문은 "이 역할과 같은 정책을 쓰는 역할이 또 있나" 다.
                  id: "group", header: "부여 권한이 같은 역할", width: 170,
                  cell: (e: ServiceRoleEntry) => <SiblingCell entry={e} all={scoped} tierDays={tierDays} />,
                },
              ]}
              items={sorted}
              empty={
                <Box padding="l" textAlign="center" color="text-status-inactive">
                  {cleanupDays(tierDays)}일 이상 미사용인 역할이 없습니다 — "전체" 로 바꾸면 나머지 {scoped.length}개를 볼 수 있습니다.
                </Box>
              }
            />
          </>
        )}
      </SpaceBetween>
    </ContentLayout>
  );
}
