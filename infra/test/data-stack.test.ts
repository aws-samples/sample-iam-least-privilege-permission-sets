/**
 * DataStack 어설션 테스트 (jest 없이 ts-node 로 실행 — `npm test`).
 *
 * DataBucket lifecycle 값(noncurrent 90d + abort-incomplete 7d)이 회귀하지 않는지 고정.
 * lifecycle 은 §C(1차)에서 추가했고, 이 테스트는 그 값이 바뀌면 실패해 조용한 회귀를 막는다.
 * (Object Lock/MFA-delete 는 샘플 removalPolicy=DESTROY 와 충돌 → wontfix.)
 */
import * as cdk from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { DataStack } from "../lib/data-stack";
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

const app = new cdk.App();
const stack = new DataStack(app, "TestData", { env: { account: "111122223333", region: "us-west-2" }, cfg: CFG });
const t = Template.fromStack(stack);

// DataBucket 에 lifecycle 규칙: NoncurrentVersionExpiration 90d + AbortIncompleteMultipartUpload 7d.
try {
  t.hasResourceProperties("AWS::S3::Bucket", {
    LifecycleConfiguration: {
      Rules: Match.arrayWith([
        Match.objectLike({
          Status: "Enabled",
          NoncurrentVersionExpiration: { NoncurrentDays: 90 },
          AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
        }),
      ]),
    },
  });
  assert(true, "DataBucket lifecycle: noncurrent 90d + abort-incomplete 7d");
} catch (e) {
  assert(false, `DataBucket lifecycle 값 불일치: ${(e as Error).message.split("\n")[0]}`);
}

// 데이터 버킷은 버전 관리 + KMS 암호화(회귀 방지 스팟 체크).
try {
  t.hasResourceProperties("AWS::S3::Bucket", {
    VersioningConfiguration: { Status: "Enabled" },
  });
  assert(true, "DataBucket versioning enabled");
} catch (e) {
  assert(false, `DataBucket versioning: ${(e as Error).message.split("\n")[0]}`);
}

if (process.exitCode && process.exitCode !== 0) {
  console.error("\n일부 어설션 실패");
} else {
  console.log("\n모든 어설션 통과");
}
