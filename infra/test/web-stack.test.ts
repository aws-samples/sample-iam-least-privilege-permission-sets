/**
 * WebStack assertions (run with ts-node via `npm test`, no jest).
 *
 * Locks the CSP connect-src scope. Report/Terraform downloads fetch a presigned URL into a
 * blob, so the data bucket must be reachable -- but only that one bucket. Two regressions are
 * guarded here: dropping the bucket host (downloads break silently) and widening it back to an
 * S3 host wildcard (every bucket in the region becomes a valid XHR destination).
 */
import * as fs from "fs";
import * as path from "path";
import * as cdk from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import { DataStack } from "../lib/data-stack";
import { WebStack } from "../lib/web-stack";
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

// WebStack stages frontend/dist as an asset, which is a build output (gitignored) and therefore
// absent on a fresh checkout. Synth needs the directory to exist; a placeholder is enough because
// these assertions only inspect the CloudFront response headers policy.
const DIST = path.join(__dirname, "..", "..", "frontend", "dist");
if (!fs.existsSync(DIST)) {
  fs.mkdirSync(DIST, { recursive: true });
  fs.writeFileSync(path.join(DIST, "index.html"), "<!doctype html>\n");
}

const env = { account: "111122223333", region: "us-west-2" };
const app = new cdk.App();
const data = new DataStack(app, "TestData", { env, cfg: CFG });
const web = new WebStack(app, "TestWeb", { env, cfg: CFG, dataBucket: data.dataBucket });
const t = Template.fromStack(web);

// The CSP is assembled from a cross-stack token, so the synthesized value is an Fn::Join whose
// parts mix literals and an Fn::ImportValue. If the token were replaced by a hardcoded host the
// value would collapse to a plain string instead -- handle both shapes so the literal assertions
// below never pass vacuously on an unexpected structure.
const policies = t.findResources("AWS::CloudFront::ResponseHeadersPolicy");
const policy = Object.values(policies)[0] as
  | { Properties?: { ResponseHeadersPolicyConfig?: Record<string, unknown> } }
  | undefined;
const cspNode = (policy?.Properties?.ResponseHeadersPolicyConfig as Record<string, any> | undefined)
  ?.SecurityHeadersConfig?.ContentSecurityPolicy?.ContentSecurityPolicy;
const joinParts: unknown[] =
  typeof cspNode === "string" ? [cspNode] : (cspNode?.["Fn::Join"]?.[1] ?? []);
const literals = joinParts.filter((p): p is string => typeof p === "string").join("");
const imports = joinParts.filter(
  (p): p is { "Fn::ImportValue": string } =>
    typeof p === "object" && p !== null && "Fn::ImportValue" in p,
);

assert(literals.length > 0, "CSP directives were found in the synthesized policy");

// The bucket host must come from the data stack's RegionalDomainName export, not a literal.
assert(
  imports.some((i) => /RegionalDomainName/.test(i["Fn::ImportValue"])),
  "CSP connect-src imports the data bucket RegionalDomainName from the data stack",
);

// No S3 host wildcard: that would allow XHR to every bucket in the region.
assert(
  !/\*\.s3[.-]/.test(literals),
  "CSP connect-src has no S3 host wildcard (scoped to the one bucket)",
);

// The directives that must stay locked down regardless of the connect-src change.
assert(/default-src 'self'/.test(literals), "CSP keeps default-src 'self'");
assert(/object-src 'none'/.test(literals), "CSP keeps object-src 'none'");
assert(/frame-ancestors 'none'/.test(literals), "CSP keeps frame-ancestors 'none'");

if (process.exitCode && process.exitCode !== 0) {
  console.error("\n일부 어설션 실패");
} else {
  console.log("\n모든 어설션 통과");
}
