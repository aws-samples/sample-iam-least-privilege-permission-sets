/**
 * ApiStack assertions (run with ts-node via `npm test`, no jest).
 *
 * Locks the Bedrock IAM statement. The Converse API is authorized by `bedrock:InvokeModel`, not
 * by an action named after the API, so a policy that looks correct can leave the assistant
 * completely non-functional. That regression already happened once and was invisible in
 * production: the app degrades a Bedrock exception into a generic "unavailable" answer and the AI
 * toggle is off by default, so nothing surfaced until CloudTrail was read (89 days, zero
 * successful Bedrock calls by this role).
 *
 * Two failure modes are guarded:
 *   - `bedrock:InvokeModel` missing  -> assistant is dead
 *   - `bedrock:Converse` present     -> dead action; this is a public sample, so a policy string
 *                                       that does not participate in authorization must not be
 *                                       copied by readers as if it did
 */
import * as cdk from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import { DataStack } from "../lib/data-stack";
import { AuthStack } from "../lib/auth-stack";
import { EngineStack } from "../lib/engine-stack";
import { ApiStack } from "../lib/api-stack";
import type { Lp2psConfig } from "../lib/config-loader";

const MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0";

const CFG: Lp2psConfig = {
  customer: "test",
  region: "us-west-2",
  cross_account: false,
  accounts: ["self"],
  readonly_role_name: null,
  engine: { runtime: "lambda" },
  schedule: { cron: null },
  ai: { enabled: false, model: MODEL },
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
const auth = new AuthStack(app, "TestAuth", { env, cfg: CFG });
const engine = new EngineStack(app, "TestEngine", {
  env,
  cfg: CFG,
  dataBucket: data.dataBucket,
  runsTable: data.runsTable,
  metricsTable: data.metricsTable,
  dataKey: data.dataKey,
});
const api = new ApiStack(app, "TestApi", {
  env,
  cfg: CFG,
  userPool: auth.userPool,
  dataBucket: data.dataBucket,
  runsTable: data.runsTable,
  metricsTable: data.metricsTable,
  catalogTable: data.catalogTable,
  stateMachine: engine.stateMachine,
  scheduleRule: engine.scheduleRule,
});
const t = Template.fromStack(api);

// Collect every statement across the stack's policies, then pick the Bedrock one by sid. Matching
// on the sid rather than on statement order keeps this stable as other statements are added.
type Stmt = { Sid?: string; Action?: string | string[]; Resource?: unknown };
const statements: Stmt[] = Object.values(t.findResources("AWS::IAM::Policy")).flatMap(
  (p: any) => (p?.Properties?.PolicyDocument?.Statement ?? []) as Stmt[],
);
const bedrock = statements.filter((s) => s.Sid === "BedrockInvoke");

assert(bedrock.length === 1, "exactly one BedrockInvoke statement exists");

const actions = bedrock.flatMap((s) => (Array.isArray(s.Action) ? s.Action : [s.Action ?? ""]));

// The load-bearing assertion: Converse is authorized by InvokeModel.
assert(
  actions.includes("bedrock:InvokeModel"),
  "BedrockInvoke grants bedrock:InvokeModel (the action that authorizes Converse)" +
    (actions.includes("bedrock:InvokeModel")
      ? ""
      : " -- without it the assistant returns a generic error for every question, silently: " +
        "the app degrades Bedrock exceptions into a safe non-answer and the AI toggle is off " +
        "by default, so nothing surfaces in the UI or in the logs."),
);

// A dead action must not reappear in a policy that ships as a public sample.
//
// This assertion is deliberately brittle: it asserts the *absence* of a string based on how
// Bedrock authorizes Converse **as measured on 2026-07-30** (CloudTrail: Converse ->
// AccessDenied naming bedrock:InvokeModel). If AWS later makes `bedrock:Converse` participate
// in authorization, reverting this is legitimate -- but re-measure first rather than trusting
// the docs, since the failure mode is a completely dead assistant that looks healthy.
assert(
  !actions.includes("bedrock:Converse"),
  "BedrockInvoke does not grant bedrock:Converse (not used in authorization)" +
    (actions.includes("bedrock:Converse")
      ? " -- Converse was authorized by bedrock:InvokeModel when this was last measured " +
        "(2026-07-30, CloudTrail AccessDenied on eventName=Converse). If you are adding it back " +
        "because that changed, verify with a real call and CloudTrail, not with the IAM policy " +
        "simulator: the simulator does not validate action names (bedrock:NotARealAction123 " +
        "returns the same implicitDeny), so an 'allowed' result proves only a policy-string match."
      : ""),
);

// Resources stay scoped to the configured model -- no bare wildcard on the account's Bedrock.
const resources = JSON.stringify(bedrock.map((s) => s.Resource));
assert(
  resources.includes(`inference-profile/${MODEL}`),
  "BedrockInvoke is scoped to the configured inference profile",
);
assert(
  !/"\*"/.test(resources),
  "BedrockInvoke has no bare '*' resource",
);

// ---- Assistant guardrail ----
//
// The guardrail screens externally-sourced IAM metadata before it reaches the model. Two things
// must hold together, and each is silent on its own:
//   - the guardrail resource exists with a prompt-attack filter, and
//   - the role may actually apply it.
// Attaching guardrailConfig without bedrock:ApplyGuardrail turns every assistant call into an
// AccessDenied, which the app degrades into a generic non-answer -- the exact silent-death mode
// that hid the InvokeModel defect for 89 days.
const guardrails = t.findResources("AWS::Bedrock::Guardrail");
assert(Object.keys(guardrails).length === 1, "exactly one Bedrock guardrail is defined");

const gr: any = Object.values(guardrails)[0];
const filters: any[] = gr?.Properties?.ContentPolicyConfig?.FiltersConfig ?? [];
assert(
  filters.some((f) => f?.Type === "PROMPT_ATTACK"),
  "guardrail enables the PROMPT_ATTACK filter",
);

// Scope is intentionally narrow. A denied-topic policy ("do not recommend granting
// AdministratorAccess or wildcard actions") is deliberately absent: the over-broad-grant threat it
// would target is already closed by the advisory-only ai_* output contract and the grounding
// verifier, whereas a topic definition sits semantically next to questions an operator must be able
// to ask -- "who still holds AdministratorAccess", "which personas have wildcard actions", "grant the
// broadest permissions" -- which is what this tool exists to answer. No topic policy has been
// deployed, so its false-positive behaviour is unmeasured; that is the risk being avoided.
// If you add a topic or PII policy, replay the recorded baseline first and change this assertion
// deliberately. Rationale in lib/api-stack.ts; data in lp2ps-finding2-measurements.md.
assert(
  gr?.Properties?.TopicPolicyConfig === undefined,
  "guardrail defines no denied-topic policy (would overlap legitimate operator questions)",
);

assert(
  Object.keys(t.findResources("AWS::Bedrock::GuardrailVersion")).length === 1,
  "the guardrail is pinned to an explicit version (DRAFT is mutable outside the stack)",
);

const applyStmts = statements.filter((s) => s.Sid === "BedrockApplyGuardrail");
assert(applyStmts.length === 1, "exactly one BedrockApplyGuardrail statement exists");
const applyActions = applyStmts.flatMap((s) =>
  Array.isArray(s.Action) ? s.Action : [s.Action ?? ""],
);
assert(
  applyActions.includes("bedrock:ApplyGuardrail"),
  "the API role may apply the guardrail" +
    (applyActions.includes("bedrock:ApplyGuardrail")
      ? ""
      : " -- without it every assistant call fails AccessDenied once guardrailConfig is attached, " +
        "and the app degrades that into a generic 'unavailable' answer, so it looks healthy."),
);
// Scoped to the guardrail itself, not to '*' or to the model.
const applyResources = JSON.stringify(applyStmts.map((s) => s.Resource));
assert(
  !/"\*"/.test(applyResources) && applyResources.includes("GuardrailArn"),
  "BedrockApplyGuardrail is scoped to the guardrail ARN",
);

// The Lambda must receive both identifier and version: the app sends guardrailConfig only when
// both are non-empty, so a half-wired env silently runs the assistant unguarded.
const fns = t.findResources("AWS::Lambda::Function", {
  Properties: { Handler: "lp2ps_api.app.handler" },
});
const envVars: any = (Object.values(fns)[0] as any)?.Properties?.Environment?.Variables ?? {};
assert(
  envVars.LP2PS_GUARDRAIL_ID !== undefined && envVars.LP2PS_GUARDRAIL_VERSION !== undefined,
  "the API Lambda receives both LP2PS_GUARDRAIL_ID and LP2PS_GUARDRAIL_VERSION",
);

// ---- Runs-table write scope ----
//
// POST /runs records the started run as status="running" so it is observable before the pipeline
// finishes. That needs one write action on the runs table, and the temptation is grantReadWriteData,
// which also hands over UpdateItem and DeleteItem -- i.e. the API could mutate or erase completed
// run history. PutItem alone is sufficient (the engine writes the terminal state, conditionally).
const recordRun = statements.filter((s) => s.Sid === "RecordRunningRun");
assert(recordRun.length === 1, "exactly one RecordRunningRun statement exists");

const recordActions = recordRun.flatMap((s) =>
  Array.isArray(s.Action) ? s.Action : [s.Action ?? ""],
);
assert(
  recordActions.length === 1 && recordActions[0] === "dynamodb:PutItem",
  "RecordRunningRun grants only dynamodb:PutItem (no UpdateItem/DeleteItem on run history)",
);
assert(
  !JSON.stringify(recordRun.map((s) => s.Resource)).includes('"*"'),
  "RecordRunningRun has no bare '*' resource",
);

if (process.exitCode && process.exitCode !== 0) {
  console.error("\n일부 어설션 실패");
} else {
  console.log("\n모든 어설션 통과");
}
