// ============================================================================
// 비주얼 토큰 — 목적: "AI가 만든 티" 제거.
//
// 원칙:
//  - UI 껍데기(표면·텍스트·간격·컴포넌트)는 Cloudscape 기본 다크 토큰을 그대로 쓴다.
//    → 여기에 표면/텍스트 hex 를 두지 않는다. Cloudscape 가 런타임에 자동 적용.
//  - 차트·상태색만 검증된 CVD-safe 팔레트를 명시 지정한다
//    (Cloudscape 기본 차트 팔레트는 색각이상 검증이 약하므로 덮어쓴다).
//  - 시리즈색과 상태색은 절대 섞지 않는다.
//  - 색만으로 의미 전달 금지 → 항상 아이콘/라벨 동반 (컴포넌트 레벨에서 강제).
//
// 근거: dataviz 스킬 references/palette.md (대비·CVD 스크립트 검증) + Radix Colors.
// 세 톤 비교 검토 산출물: docs/palette-preview.html.
// ============================================================================

// 차트 시리즈 — 고정 순서로만 배정(CVD 안전성이 순서에 의존).
export const CHART_SERIES = [
  "#3987e5", // 1 blue
  "#199e70", // 2 aqua
  "#c98500", // 3 yellow
  "#008300", // 4 green
  "#9085e9", // 5 violet
  "#e66767", // 6 red
] as const;

// 순차형(단일 지표 추이 등) — blue 단일 hue 라이트→다크 램프.
export const CHART_SEQUENTIAL_BLUE = [
  "#cfe3fb",
  "#8fbef4",
  "#5c9eec",
  "#3987e5",
  "#1f5fb0",
] as const;

// 상태색 — 위험등급/승인. 시리즈색과 분리.
export const STATUS = {
  good: "#0ca30c", // 승인 / Low
  warning: "#fab219", // 검토중 / Medium
  serious: "#ec835a", // High
  critical: "#d03b3b", // Critical
} as const;

import type { RiskLevel } from "@/api/types";

export const RISK_COLOR: Record<RiskLevel, string> = {
  critical: STATUS.critical,
  high: STATUS.serious,
  medium: STATUS.warning,
  low: STATUS.good,
};

// Cloudscape status-indicator type 매핑 (색만으로 전달 금지 → 아이콘 동반).
export const RISK_INDICATOR: Record<RiskLevel, "error" | "warning" | "success"> = {
  critical: "error",
  high: "warning",
  medium: "warning",
  low: "success",
};
