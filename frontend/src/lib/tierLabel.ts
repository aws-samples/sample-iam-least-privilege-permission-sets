// 미사용 등급 라벨 — **한 곳에서만 만든다**.
//
// `active`/`watch`/`review`/`cleanup`/`new` 는 엔진과의 계약 값(`models.UnusedTier`)이고 화면
// 문구가 아니다. 예전에는 표·차트·필터가 각자 `cleanup (90일 이상)` 처럼 영문 원값을 그대로
// 노출했다 — 고객은 `cleanup` 을 사전 없이 해석해야 했고, 실제로 "cleanup = 지워도 되는 것" 으로
// 읽혔다. 등급은 **며칠 안 썼는가**만 말한다(삭제 권고는 별도 게이트를 거친다).
//
// 그래서 라벨을 사실 문장으로 쓴다: 라벨이 곧 측정값이면 오독할 여지가 없다.
//
// 🔴 경계 숫자를 박지 않는다 — `risk_rules.unused_tier_days` 는 고객이 바꿀 수 있다(불변식 ④).
// 호출자는 `/cleanup-backlog/risk-criteria` 의 `unused_tier_days` 를 넘긴다. 값을 못 받았을 때만
// 기본값을 쓰고, 그 사실은 화면에 별도로 말하지 않는다(기본값이 곧 대부분의 배포다).
import type { UnusedTier } from "../api/types";

export const DEFAULT_TIER_DAYS: readonly number[] = [30, 60, 90];

// 경계 배열은 [watch, review, cleanup] 3개. 잘못된 길이가 오면 기본값으로 되돌린다 —
// 여기서 undefined 를 문구에 흘리면 "undefined일 이상 미사용" 이 화면에 뜬다.
function bounds(days?: readonly number[]): readonly number[] {
  return days && days.length === 3 ? days : DEFAULT_TIER_DAYS;
}

// 등급 없음(null)은 0 이 아니라 **미측정**이다. 이 구분을 문구에서 잃으면 근거가 가장 없는
// 대상이 '방금 쓰인 것' 으로 읽힌다.
export const TIER_UNGRADED = "미측정 (사용 일수 근거 없음)";

export function tierLabel(tier: UnusedTier | null, days?: readonly number[]): string {
  const [watch, review, cleanup] = bounds(days);
  switch (tier) {
    case "active":
      return `${watch}일 이내 사용`;
    case "watch":
      return `${watch}일 이상 미사용`;
    case "review":
      return `${review}일 이상 미사용`;
    case "cleanup":
      return `${cleanup}일 이상 미사용`;
    case "new":
      return "신규 (관측 기간 부족 · 판정 보류)";
    default:
      return TIER_UNGRADED;
  }
}

// cleanup 등급의 경계값(일). "N일 이상 미사용만 보고 있습니다" 같은 설명문에 쓴다.
export function cleanupDays(days?: readonly number[]): number {
  return bounds(days)[2];
}
