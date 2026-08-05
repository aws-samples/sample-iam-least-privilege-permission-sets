# LP2PS — IAM Least-Privilege → Permission Set Generator

LP2PS is a **read-only** tool that collects and analyzes multi-account AWS IAM usage and produces three outputs:

1. **Per-persona least-privilege catalog** — derived bottom-up from actual usage
2. **IAM Identity Center Permission Set Terraform** — infrastructure-as-code output
3. **Cleanup backlog** — unused permissions, long-lived access keys, missing MFA, and privilege-escalation paths

It is not built for any specific customer — it is a reusable sample you can deploy repeatedly across environments. Reuse = swap `config/<name>.yaml` and deploy; **no application code changes required**.

> ⚠️ **Disclaimer / Safety principles**
> - This is **sample code**, provided AS-IS. Review and adapt it to your environment's security and compliance requirements before any production use.
> - The tool treats analyzed (member) accounts as **read-only**. Actual apply/deletion of IAM policies is performed by a human.
> - The only write exception is creating **IAM Identity Center Permission Set definitions in the tooling account**, gated by a server-side approval check. Even then it performs **no account assignment** and never modifies the analyzed accounts.
> - You are responsible for the AWS costs incurred by deploying and operating this tool (see the Cost section).

## Layout

| Directory | Contents |
|---|---|
| `engine/` | Python engine — collect, normalize, analyze, synthesize policy, emit IaC (read-only) |
| `frontend/` | React + Cloudscape web UI (dashboard, persona review, cleanup backlog, reports, assistant) |
| `backend/` | FastAPI + Mangum API (Cognito auth, read + curate tool-owned resources) |
| `infra/` | TypeScript CDK — deployment stacks (Data / Auth / Engine / Api / Web) |
| `config/` | Configuration (`example.yaml` template) |
| `cfn/` | Cross-account read-only role deployed into member accounts (StackSet) |

## Architecture (overview)

```
config/<name>.yaml
        │
        ▼
  ┌───────────┐   read-only     ┌──────────────┐
  │  Engine   │──── collect ───▶│ target        │
  │ (Lambda)  │  (sts:Assume)   │ accounts      │
  └─────┬─────┘                 │ (untouched)   │
        │ outputs (deterministic)└──────────────┘
        ▼
  Catalog (JSON) · Permission Set Terraform · cleanup backlog (CSV) · reports (HTML)
        │  (S3 + DynamoDB, tool-owned)
        ▼
  API (FastAPI/Cognito) ─▶ Frontend (CloudFront) ─(approval)─▶ create PS definition in tooling IdC
```

- **Engine**: zip-based Lambda orchestrated by Step Functions (collect → analyze → synth → report).
- **Storage**: tool-owned S3 (SSE-KMS) + DynamoDB (CMK). Nothing is stored in the analyzed accounts.
- **Web/API**: CloudFront (HSTS + CSP) + API Gateway (Cognito authorizer) + FastAPI Lambda.

## Data handling / security

- The only data stored is **IAM resource metadata** (role/user names, ARNs, policies, usage facts). No separate PII or customer business data is collected or stored. An IAM username may be a person's name and thus an indirect identifier, but outputs are stored **only in the customer-owned S3/DynamoDB** of the account where the tool is self-deployed.
- Read-only is enforced: sessions against analyzed accounts pass through a botocore before-call hook that allows only allowlisted verbs (anything else is blocked immediately). Cross-account assume uses a read-only inline session policy plus an optional ExternalId.
- For the full threat model, authentication (Cognito), CORS/CSP, and audit logging, see [SECURITY.md](./SECURITY.md).

## Prerequisite data sources

The tool behaves identically **read-only in every environment** — it creates or changes nothing in the account it runs in. Some AWS data sources that improve analysis fidelity must therefore be **enabled in advance by the environment owner** (not by the tool). If a source is absent, the tool does not fail — it records that source as `skipped`/`degraded` and completes using fallback sources (per-source status is written to `collection_manifest.json`).

| Data source | Behavior when absent | Why it helps |
|---|---|---|
| **IAM Access Analyzer — unused-access analyzer** | `skipped`; unused-access is approximated from Access Advisor + access-key age | More accurate detection of unused permissions/roles/keys |
| **CloudTrail** (default `LookupEvents`, free) | Enabled by default — no setup needed | Usage aggregation from management events |
| **Access Advisor** (Service Last Accessed) | Enabled by default | Service/action last-accessed (core signal for unused detection) |

> Sources that incur extra cost (e.g., CloudTrail Lake) are intentionally not used — everything runs on default, free-tier sources.

## Quick start (local validation)

```bash
# Engine (read-only enforcement, normalization, deterministic tests)
cd engine && pip install -e '.[dev]'
pytest

aws sso login && export AWS_REGION=us-west-2
cp config/example.yaml config/myenv.yaml   # edit customer/region/accounts
lp2ps run -c config/myenv.yaml --out ./out  # full collect→analyze→synth→report

# Frontend (mock-data UI)
cd frontend && npm install && npm run dev    # http://localhost:5173
```

## Deployment

A one-click script deploys the five stacks (Data / Auth / Engine / Api / Web) in order.

```bash
# Prereqs: aws sso login; cd infra && npm install; engine venv + pip install
infra/scripts/deploy-all.sh config/myenv.yaml            # redeploy
infra/scripts/deploy-all.sh config/myenv.yaml --bootstrap # first time in an account (includes CDK bootstrap)
```

- After deployment, **create a login user in the Cognito console** and open the CloudFront URL from the stack outputs.
- For multi-account analysis, deploy `cfn/lp2ps-readonly-role.yaml` into each member account and set `cross_account: true` in the config. See the deployment/onboarding guides under `docs/`.
- Step-by-step details (including console click-paths) are in `docs/deployment-guide.md`; the one-click summary is in `docs/quick-deploy.md`.

## Cost

Deployment creates the following AWS resources, which may incur cost (varies by region and usage):

- Lambda (engine + API), Step Functions, API Gateway, CloudFront, S3, DynamoDB (PAY_PER_REQUEST), KMS (CMK), CloudWatch Logs (90-day retention), Cognito.
- Enabling the AI assistant adds Amazon Bedrock model-invocation cost (runtime toggle; off by default).
- Analyzed data sources are designed to be free (default CloudTrail, Access Advisor, Credential Report). Enabling Access Analyzer may incur separate charges for that service.

> Idle cost is generally small (serverless), but estimate your actual cost before deploying with the [AWS Pricing Calculator](https://calculator.aws/).

## Teardown

```bash
infra/scripts/destroy-all.sh config/myenv.yaml
```

- Deletes the five stacks in reverse dependency order. S3/DynamoDB use `removalPolicy: DESTROY`, so **their data is deleted as well** (sample behavior — change the policy before deploying if you need retention).
- The member-account read-only role is removed by deleting the `lp2ps-readonly` stack in each member account.
- To also remove the CDK bootstrap (CDKToolkit), delete it separately with `aws cloudformation delete-stack`.

## License

MIT-0. See [LICENSE](./LICENSE) and third-party licenses in [THIRD-PARTY-LICENSES.md](./THIRD-PARTY-LICENSES.md). For security issues see [SECURITY.md](./SECURITY.md); for contributions see [CONTRIBUTING.md](./CONTRIBUTING.md).
