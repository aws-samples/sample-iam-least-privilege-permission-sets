import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

const src = (p: string): string => fileURLToPath(new URL(`./src/${p}`, import.meta.url));

// VITE_USE_MOCKS 는 api/client.ts 어댑터가 읽는다. **명시적으로 "true" 일 때만** 목데이터다
// (fail-closed — 플래그를 잊은 빌드가 목데이터 + 인증 우회로 뜨면 안 된다).
export default defineConfig(({ mode }) => {
  const useMocks = loadEnv(mode, process.cwd(), "VITE_").VITE_USE_MOCKS === "true";
  return {
    plugins: [react()],
    resolve: {
      alias: [
        // 🔴 목데이터는 실 빌드에 **바이트로도** 들어가면 안 된다. `client.ts` 의 mock 분기는
        // 컴파일 타임 상수로 죽지만 rollup 의 tree-shaking 은 데이터 모듈을 부분적으로만
        // 걷어냈다 — 배포된 번들에서 목 계정 문자열 25건이 실측됐다(2026-09-14). 그래서
        // 모듈 자체를 빈 스텁으로 치환한다. 타입체크는 `tsconfig` paths 로 실제 모듈을 보므로
        // 계약 검사는 그대로 유지된다.
        ...(useMocks ? [] : [{ find: /^@\/mocks\/data$/, replacement: src("mocks/empty.ts") }]),
        { find: "@", replacement: fileURLToPath(new URL("./src", import.meta.url)) },
      ],
    },
    // dev 서버에서 `global is not defined` 로 화면이 백지가 되는 것을 막는다.
    // amazon-cognito-identity-js → buffer 가 Node 전역 `global` 을 참조하는데, 브라우저엔 없다.
    // 프로덕션 빌드(rollup)는 이 참조를 정리해 정상 렌더되지만 dev prebundle(esbuild)은 그대로 남긴다.
    // `optimizeDeps.esbuildOptions` 는 **dev 사전번들에만** 적용되므로 배포 번들은 건드리지 않는다
    // (전역 `define` 을 쓰면 프로덕션 번들까지 바뀐다 — 그래서 여기로 한정).
    optimizeDeps: { esbuildOptions: { define: { global: "globalThis" } } },
    server: { port: 5173, open: true },
  };
});
