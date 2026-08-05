#!/usr/bin/env node
/**
 * LP2PS CDK 진입점 — 멀티고객 반복 배포.
 *
 * `cdk deploy --all -c config=config/<customer>.yaml` 로 배포. config 를 읽어 customer prefix 로
 * 스택을 만든다(다중 배포 충돌 방지). 코드 변경 0 — config 만 교체.
 *
 * Security: cdk-nag AwsSolutionsChecks 상시 + 모든 리소스에 auto-delete=no 태그(사용자 요청).
 */
import * as cdk from "aws-cdk-lib";
import { Aspects, Tags } from "aws-cdk-lib";
import { AwsSolutionsChecks } from "cdk-nag";
import { loadConfig, stackPrefix } from "../lib/config-loader";
import { DataStack } from "../lib/data-stack";
import { AuthStack } from "../lib/auth-stack";
import { EngineStack } from "../lib/engine-stack";
import { ApiStack } from "../lib/api-stack";
import { WebStack } from "../lib/web-stack";

const app = new cdk.App();

// config 경로: -c config=... (기본 config/self.yaml)
const configPath = (app.node.tryGetContext("config") as string) ?? "../config/self.yaml";
const cfg = loadConfig(configPath);
const prefix = stackPrefix(cfg.customer);

const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: cfg.region,
};

const data = new DataStack(app, `${prefix}-Data`, { env, cfg });
const auth = new AuthStack(app, `${prefix}-Auth`, { env, cfg });
const engine = new EngineStack(app, `${prefix}-Engine`, {
  env,
  cfg,
  dataBucket: data.dataBucket,
  runsTable: data.runsTable,
  metricsTable: data.metricsTable,
  dataKey: data.dataKey, // 로그그룹 CMK 암호화
});
engine.addDependency(data);

const api = new ApiStack(app, `${prefix}-Api`, {
  env,
  cfg,
  userPool: auth.userPool,
  dataBucket: data.dataBucket,
  runsTable: data.runsTable,
  metricsTable: data.metricsTable,
  catalogTable: data.catalogTable,
  stateMachine: engine.stateMachine,
  scheduleRule: engine.scheduleRule,
});
api.addDependency(data);
api.addDependency(auth);
api.addDependency(engine);

// web 스택 — frontend/dist(사전 빌드, build-web.sh) 호스팅. dist 없으면 배포 실패하므로
// 별도로 빌드 후 배포한다. 다른 스택과 독립(dist 는 이미 실 env 로 빌드됨).
const web = new WebStack(app, `${prefix}-Web`, { env, cfg, dataBucket: data.dataBucket });
web.addDependency(data);

// 사용자 요청: 콘솔 리소스에 auto-delete=no 태그(테스트 리소스 자동삭제 방지 표식).
Tags.of(app).add("auto-delete", "no");
Tags.of(app).add("ManagedBy", "lp2ps");
Tags.of(app).add("Customer", cfg.customer);

// cdk-nag 상시 — High/Critical 위반은 synth 시 드러난다.
Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

app.synth();
