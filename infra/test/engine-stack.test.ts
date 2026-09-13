/**
 * EngineStack 어설션 테스트 (jest 없이 ts-node 로 실행 — `npm test`).
 *
 * 고정하는 계약은 하나다: **run_id 가 4개 stage 를 통과한다.**
 *
 * 스케줄 트리거는 run_id/started_at 을 null 로 넣는다(엔진이 새 run 을 만들라는 뜻). 그런데 모든
 * stage 가 실행 **입력**의 `$.run_id` 를 읽으므로, collect 가 만든 run_id 를 상태 루트로 승격하지
 * 않으면 stage 마다 서로 다른 run 컨텍스트가 생기고 analyze 가 선행 산출물을 못 찾아
 * StageBarrierError 로 죽는다. 라이브에서 스케줄 실행 2건이 정확히 그렇게 실패했고(2026-09-12·13),
 * API 트리거(run_id 를 직접 주입)만 성공했다 — 트리거 경로에 따라 결과가 갈리던 결함이다.
 *
 * 판별력: `resultSelector` 를 지우거나 `resultPath` 를 `$.collectResult` 로 되돌리면 아래 두
 * 어설션이 FAIL 한다(정의 문자열에서 승격 지점이 사라진다).
 */
import * as cdk from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import { DataStack } from "../lib/data-stack";
import { EngineStack } from "../lib/engine-stack";
import type { Lp2psConfig } from "../lib/config-loader";

const CFG: Lp2psConfig = {
  customer: "test",
  region: "us-west-2",
  cross_account: false,
  accounts: ["self"],
  readonly_role_name: null,
  engine: { runtime: "lambda" },
  schedule: { cron: null },
  ai: { enabled: false, model: "us.anthropic.claude-haiku-4-5-20251001-v1:0" },
  provisioning: {},
};

function assert(cond: boolean, msg: string): void {
  if (!cond) {
    console.error(`✗ FAIL: ${msg}`);
    process.exitCode = 1;
  } else {
    console.log(`✓ ${msg}`);
  }
}

const env = { account: "111122223333", region: "us-west-2" };
const app = new cdk.App();
const data = new DataStack(app, "TestData", { env, cfg: CFG });
const engine = new EngineStack(app, "TestEngine", {
  env,
  cfg: CFG,
  dataBucket: data.dataBucket,
  runsTable: data.runsTable,
  metricsTable: data.metricsTable,
  dataKey: data.dataKey,
});
const t = Template.fromStack(engine);

// 상태머신 정의는 Fn::Join 조각으로 합성된다 → 문자열로 이어붙여 검사한다.
const machines = t.findResources("AWS::StepFunctions::StateMachine");
const defs = Object.values(machines).map((m) => {
  const d = (m as { Properties: { DefinitionString: unknown } }).Properties.DefinitionString;
  const join = (d as { "Fn::Join"?: [string, unknown[]] })["Fn::Join"];
  return join ? join[1].map((p) => (typeof p === "string" ? p : "")).join("") : String(d);
});
assert(defs.length === 1, `상태머신 1개(측정 ${defs.length}개)`);
const def = defs[0] ?? "";

// 1. collect 가 Lambda 응답의 run_id 를 상태 루트로 승격한다(ResultSelector + ResultPath:"$").
const promoted =
  def.includes('"run_id.$":"$.Payload.run_id"') &&
  def.includes('"started_at.$":"$.Payload.started_at"') &&
  /"ResultPath":"\$"/.test(def);
assert(promoted, "collect 결과의 run_id·started_at 이 상태 루트로 승격된다");

// 2. 4개 stage 가 모두 존재하고, 각 stage payload 가 `$.run_id` 를 읽는다(= 승격된 값을 읽는다).
for (const name of ["collect", "analyze", "synth", "report"]) {
  assert(def.includes(`"Stage-${name}"`), `stage 존재: ${name}`);
}
const readers = (def.match(/"run_id\.\$":"\$\.run_id"/g) ?? []).length;
assert(readers === 4, `4개 stage 가 모두 $.run_id 를 읽는다(측정 ${readers})`);

// 3. 스케줄 룰은 run 컨텍스트를 만들지 않는다(엔진이 만든다) — 승격이 유일한 전달 경로임을 고정.
t.hasResourceProperties("AWS::Events::Rule", {
  Targets: [{ Input: '{"run_id":null,"started_at":null}' }],
});
assert(true, "스케줄 룰 입력 = {run_id:null, started_at:null}");
assert(engine.scheduleRule !== undefined, "스케줄 룰이 생성된다");

if (process.exitCode && process.exitCode !== 0) {
  console.error("\n일부 어설션 실패");
} else {
  console.log("\n모든 어설션 통과");
}
