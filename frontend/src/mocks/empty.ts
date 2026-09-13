/**
 * 목데이터 모듈의 **빈 스텁** — 실 빌드(`VITE_USE_MOCKS !== "true"`)에서 `@/mocks/data` 를 이것으로
 * 치환한다(`vite.config.ts` 의 resolve.alias). 목 바이트가 배포 번들에 섞이지 않게 하는 것이 목적이다.
 *
 * 이 값들이 읽히는 경로는 실 빌드에 없다: `USE_MOCKS` 는 컴파일 타임 상수 false 이고 `mock.*` 참조는
 * 전부 `mockApi` 메서드 **본문 안**(호출 시 평가)에 있어 분기째로 죽는다. 그래서 값은 빈 것으로 둔다.
 *
 * 🔴 이름이 하나라도 빠지면 **빌드가 실패한다**(rollup: "not exported by") — `client.ts` 가 새 목
 * 데이터를 쓰기 시작하면 조용히 undefined 가 되는 대신 빌드가 알려준다.
 *
 * 타입체크는 이 파일을 보지 않는다(`tsconfig` paths 가 실제 `mocks/data` 를 가리킨다) — 계약 검사는
 * 원본 모듈로 유지되고, 이 스텁은 번들링에만 개입한다.
 */
export const RUNS: never[] = [];
export const CUSTOMER = "";
export const LATEST_RUN_ID = "";
export const METRICS: never[] = [];
export const CATALOG: never[] = [];
export const CLEANUP: never[] = [];
export const SERVICE_ROLES: never[] = [];
export const RISK_CRITERIA = {};
export const REPORTS: Record<string, never> = {};
