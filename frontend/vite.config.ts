import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

// VITE_USE_MOCKS 는 api/client.ts 어댑터가 읽는다. 기본 true(목데이터).
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  // dev 서버에서 `global is not defined` 로 화면이 백지가 되는 것을 막는다.
  // amazon-cognito-identity-js → buffer 가 Node 전역 `global` 을 참조하는데, 브라우저엔 없다.
  // 프로덕션 빌드(rollup)는 이 참조를 정리해 정상 렌더되지만 dev prebundle(esbuild)은 그대로 남긴다.
  // `optimizeDeps.esbuildOptions` 는 **dev 사전번들에만** 적용되므로 배포 번들은 건드리지 않는다
  // (전역 `define` 을 쓰면 프로덕션 번들까지 바뀐다 — 그래서 여기로 한정).
  optimizeDeps: { esbuildOptions: { define: { global: "globalThis" } } },
  server: { port: 5173, open: true },
});
