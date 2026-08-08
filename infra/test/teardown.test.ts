/**
 * Teardown-hygiene assertions (run with ts-node via `npm test`, no jest).
 *
 * Guards what `destroy-all.sh` leaves behind. docs/quick-deploy.md §5 presents teardown as deleting
 * the deployment, and two CDK defaults quietly violated that:
 *
 *   1. `RestApi` gives its account-level CloudWatch role -- and the AWS::ApiGateway::Account
 *      singleton pointing at it -- `RemovalPolicy.RETAIN` by default, so every deploy/destroy cycle
 *      stranded one more IAM role in the customer account. Observed live: two orphaned roles from
 *      two cycles.
 *   2. CDK-vended custom-resource Lambdas (S3 auto-delete, BucketDeployment) get no LoggingConfig,
 *      so the Lambda service creates their log groups implicitly on first invocation. Those groups
 *      belong to no stack and survive teardown with never-expire retention. Observed live: three
 *      orphaned log groups.
 *
 * Neither is visible during a normal deploy -- they only show up by auditing the account after
 * teardown, which is exactly what an assertion should hold down.
 *
 * Why this synthesizes bin/lp2ps.ts instead of constructing stacks directly (as the sibling tests
 * do): both fixes are applied at the App level, so building the stacks here and applying the aspects
 * here would test a copy of the wiring rather than the wiring. A first draft did that and passed
 * happily when `applyProviderLogGroupHygiene(app)` was deleted from the entrypoint -- the exact
 * regression it claimed to guard. Driving the real entrypoint (via CDK_OUTDIR/CDK_CONTEXT_JSON, the
 * same env contract the CLI uses) means "the app forgot to apply it" fails the test.
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as logs from "aws-cdk-lib/aws-logs";

function assert(cond: boolean, msg: string): void {
  if (!cond) {
    console.error(`✗ FAIL: ${msg}`);
    process.exitCode = 1;
  } else {
    console.log(`✓ ${msg}`);
  }
}

// WebStack stages frontend/dist, a build output absent on a fresh checkout (same placeholder trick
// as web-stack.test.ts -- these assertions never read the bundle contents).
const DIST = path.join(__dirname, "..", "..", "frontend", "dist");
if (!fs.existsSync(DIST)) {
  fs.mkdirSync(DIST, { recursive: true });
  fs.writeFileSync(path.join(DIST, "index.html"), "<!-- placeholder for assertions -->");
}

// Synthesize the real app. config/example.yaml is the checked-in template config, so this works on a
// fresh clone and needs no live account. CDK_OUTDIR/CDK_CONTEXT_JSON/CDK_DEFAULT_ACCOUNT are the
// env vars the CDK CLI itself sets when it runs the app.
const outdir = fs.mkdtempSync(path.join(os.tmpdir(), "lp2ps-teardown-test-"));
process.env.CDK_OUTDIR = outdir;
process.env.CDK_CONTEXT_JSON = JSON.stringify({
  config: path.join(__dirname, "..", "..", "config", "example.yaml"),
});
process.env.CDK_DEFAULT_ACCOUNT = process.env.CDK_DEFAULT_ACCOUNT ?? "111122223333";
// eslint-disable-next-line @typescript-eslint/no-require-imports -- must run after the env is set
require("../bin/lp2ps");

type CfnResource = { Type: string; Properties?: Record<string, unknown>; DeletionPolicy?: string };
const TEMPLATES = fs
  .readdirSync(outdir)
  .filter((f) => f.endsWith(".template.json"))
  .map((f) => ({
    name: f.replace(/^Lp2ps-example-|\.template\.json$/g, ""),
    resources: (JSON.parse(fs.readFileSync(path.join(outdir, f), "utf8")) as { Resources?: Record<string, CfnResource> })
      .Resources ?? {},
  }));

// If the synth silently produced nothing, every sweep below would pass over an empty set.
assert(TEMPLATES.length === 5, `synthesized all 5 stacks from bin/lp2ps.ts (got ${TEMPLATES.length})`);

// ---- 1. Nothing is retained past teardown ----
//
// A stray RETAIN is how the API Gateway CloudWatch role survived. Sweeping every resource type
// rather than naming that one role means a future construct with a RETAIN default is caught too.
const retained = TEMPLATES.flatMap(({ name, resources }) =>
  Object.entries(resources)
    .filter(([, r]) => r.DeletionPolicy !== undefined && r.DeletionPolicy !== "Delete")
    .map(([id, r]) => `${name}/${id} (${r.Type}: ${r.DeletionPolicy})`),
);
assert(
  retained.length === 0,
  `no resource survives teardown (DeletionPolicy != Delete)${retained.length ? ` -- found: ${retained.join(", ")}` : ""}`,
);

// ---- 2. Every Lambda log group is stack-owned ----
//
// Without LoggingConfig the Lambda service creates the group implicitly and teardown cannot reach
// it. Covers the CDK-vended providers (S3 auto-delete, BucketDeployment) as well as ours.
const lambdasWithoutLogGroup = TEMPLATES.flatMap(({ name, resources }) =>
  Object.entries(resources)
    .filter(([, r]) => r.Type === "AWS::Lambda::Function")
    .filter(
      ([, r]) =>
        (r.Properties as { LoggingConfig?: { LogGroup?: unknown } } | undefined)?.LoggingConfig?.LogGroup === undefined,
    )
    .map(([id]) => `${name}/${id}`),
);
assert(
  lambdasWithoutLogGroup.length === 0,
  `every Lambda points at an explicit log group${lambdasWithoutLogGroup.length ? ` -- missing: ${lambdasWithoutLogGroup.join(", ")}` : ""}`,
);

// Sanity check on the assertion above: it only means something if the CDK-vended providers are in
// this synth. If a refactor drops autoDeleteObjects/BucketDeployment the check would pass over an
// empty set, so pin that they exist.
const providerLambdas = TEMPLATES.flatMap(({ name, resources }) =>
  Object.keys(resources)
    .filter((id) => resources[id].Type === "AWS::Lambda::Function" && id.startsWith("Custom"))
    .map((id) => `${name}/${id}`),
);
assert(
  providerLambdas.length >= 3,
  `CDK-vended provider Lambdas are present, so the log-group check has something to check (found ${providerLambdas.length})`,
);

// ---- 3. Log groups are retention-bounded ----
//
// An implicitly created group never expires. Every group we own must expire; deletion with the stack
// is already covered by check 1.
const RETENTION = 90; // logs.RetentionDays.THREE_MONTHS
assert(
  (logs.RetentionDays.THREE_MONTHS as number) === RETENTION,
  "THREE_MONTHS is 90 days (retention constant matches the asserted value)",
);
const badGroups = TEMPLATES.flatMap(({ name, resources }) =>
  Object.entries(resources)
    .filter(([, r]) => r.Type === "AWS::Logs::LogGroup")
    .filter(([, r]) => (r.Properties as { RetentionInDays?: number } | undefined)?.RetentionInDays !== RETENTION)
    .map(
      ([id, r]) =>
        `${name}/${id} (${(r.Properties as { RetentionInDays?: number } | undefined)?.RetentionInDays ?? "never expires"})`,
    ),
);
assert(
  badGroups.length === 0,
  `every log group retains for ${RETENTION} days${badGroups.length ? ` -- off: ${badGroups.join(", ")}` : ""}`,
);

// ---- 4. The API Gateway account-level role is explicitly DESTROY ----
//
// Check 1 covers this by sweep, but this role is the one resource where RETAIN is the CDK default
// *and* the consequence is cross-deployment accumulation, so it gets a named assertion: a reader who
// removes `cloudWatchRoleRemovalPolicy` should see a message naming that property.
const apiResources = TEMPLATES.find((t) => t.name === "Api")?.resources ?? {};
const cwRoles = Object.entries(apiResources).filter(
  ([id, r]) => r.Type === "AWS::IAM::Role" && id.includes("CloudWatchRole"),
);
assert(cwRoles.length === 1, `the API stack has exactly one API Gateway CloudWatch role (found ${cwRoles.length})`);
assert(
  cwRoles.every(([, r]) => r.DeletionPolicy === undefined || r.DeletionPolicy === "Delete"),
  "the API Gateway CloudWatch role is deleted with the stack (cloudWatchRoleRemovalPolicy: DESTROY)",
);
const cwAccounts = Object.entries(apiResources).filter(([, r]) => r.Type === "AWS::ApiGateway::Account");
assert(cwAccounts.length === 1, `the API stack declares the ApiGateway::Account singleton (found ${cwAccounts.length})`);
assert(
  cwAccounts.every(([, r]) => r.DeletionPolicy === undefined || r.DeletionPolicy === "Delete"),
  "the AWS::ApiGateway::Account singleton is deleted with the stack",
);

fs.rmSync(outdir, { recursive: true, force: true });

if (process.exitCode && process.exitCode !== 0) {
  console.error("\n일부 어설션 실패");
} else {
  console.log("\n모든 어설션 통과");
}
