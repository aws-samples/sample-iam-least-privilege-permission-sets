# LP2PS Deployment Guide (New Customer · Start to Finish)

This document explains **every step in detail** so that even someone **who has not worked much with the AWS console or CLI**
can follow along and deploy and use LP2PS from scratch. Commands can be copied and used as-is, and for console tasks
we describe "which screen to use and what to click."

> **Notation**
> - Gray notes beginning with `←` explain what happens in that step and why.
> - `<...>` marks a placeholder to replace with your own value (e.g., `<customer>`, `<account-id>`).
> - Terminal commands are shown as code blocks; console clicks are shown as numbered lists.
> - The AWS console reflects the latest UI as of 2026. If a menu name differs slightly, type the
>   service name into the search bar at the top to find it.

---

## 0. First, understand — what LP2PS is and what gets deployed

**LP2PS** is a tool that analyzes the IAM usage of an AWS account in **read-only** mode, produces "least-privilege
bundles (personas) that contain only the permissions actually used," and helps convert them into **Permission Sets**
in IAM Identity Center (IdC).

When deployed, the following is provisioned into **a single tooling account** (nothing is deployed to member accounts):

| Stack | What |
|---|---|
| `<prefix>-Data` | S3 bucket (analysis artifacts) + DynamoDB tables (run history, metrics, catalog) |
| `<prefix>-Auth` | Cognito (user pool for web login) |
| `<prefix>-Engine` | Analysis engine Lambda + Step Functions (collect → analyze → synthesize → report) + schedule (EventBridge) |
| `<prefix>-Api` | REST API (FastAPI Lambda) + Cognito authentication |
| `<prefix>-Web` | Web dashboard (CloudFront + S3) |

`<prefix>` is determined by the `customer` value in your config (e.g., `customer: acme` → `Lp2ps-acme-Data`).

**Overall flow at a glance**: install tools → sign in to AWS → write config → `cdk bootstrap` → build assets →
deploy → create web login user → run first analysis → open the web dashboard → (optional) multi-account · Permission Sets.

---

## 1. Install local tools (by OS)

Deploying LP2PS requires four things: **AWS CLI, Node.js (18+), Python (3.11+), git**.
If they are already installed, skip to [Step 2](#2-aws-account--permissions--sign-in). Check whether they are installed with:

```bash
aws --version      # OK if aws-cli/2.x is shown
node --version     # v18 or later
python3 --version  # 3.11 or later
git --version
```

### macOS

Install everything at once with Homebrew (a package manager). If you don't have Homebrew, first:

```bash
# Install Homebrew (skip if already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install tools
brew install awscli node python@3.12 git
```

### Windows

1. **AWS CLI**: In your browser, download `https://awscli.amazonaws.com/AWSCLIV2.msi` → run it → keep clicking Next.
2. **Node.js**: Go to `https://nodejs.org` → click the "LTS" button → run the installer.
3. **Python**: Go to `https://www.python.org/downloads/` → "Download Python 3.12" → during installation,
   **be sure to check the "Add python.exe to PATH" checkbox**.
4. **git**: `https://git-scm.com/download/win` → install.
5. After installing, **open a new PowerShell window** and run the verification commands above.

### Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y unzip curl git python3 python3-pip
# AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o awscliv2.zip
unzip awscliv2.zip && sudo ./aws/install
# Node.js 20 LTS
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

---

## 2. AWS account · permissions · sign-in

### 2-1. What you need

- One **tooling account** — the AWS account where LP2PS will be deployed.
- **Administrator permissions** (AdministratorAccess) on that account. Deployment creates
  resources across many services such as IAM, Lambda, S3, and CloudFront.
- One of two sign-in methods:
  - **Sign in with IAM Identity Center (SSO)** (recommended) — see 2-2 below.
  - **Sign in with IAM access keys** — see 2-3 below.

### 2-2. CLI sign-in with SSO (recommended)

```bash
aws configure sso
```

The prompts ask you the following in order (get the values from your organization's administrator):

1. `SSO session name` → any name (e.g., `lp2ps`)
2. `SSO start URL` → your company's IdC start URL (e.g., `https://d-xxxx.awsapps.com/start`)
3. `SSO region` → the IdC region (e.g., `us-east-1`)
4. `SSO registration scopes` → just press Enter (default)
5. When the browser opens, **sign in and click "Allow"**
6. Select account · role → choose the tooling account + AdministratorAccess
7. `CLI default client Region` → the deployment region (e.g., `us-west-2`)
8. `CLI profile name` → a profile name (e.g., `lp2ps`)

Afterward, whenever the session expires (a few hours by default), sign in again:

```bash
aws sso login --profile lp2ps
```

**Important**: If you use an SSO profile, prefix every subsequent command with `AWS_PROFILE=lp2ps`, or run
`export AWS_PROFILE=lp2ps` once. The commands in this guide assume this profile is active.

### 2-3. Sign in with IAM access keys (if not using SSO)

```bash
aws configure
```
- `AWS Access Key ID` / `AWS Secret Access Key` → the IAM user's access key
- `Default region name` → `us-west-2` (deployment region)
- `Default output format` → `json`

### 2-4. Verify sign-in

```bash
aws sts get-caller-identity
```
Success if `Account` shows the tooling account ID and `Arn` shows your role.
**Be sure to confirm that the Account shown here is the account you intend to deploy to.**

---

## 3. Download the source + install dependencies

```bash
# 1) Clone the source (or move into the extracted folder)
git clone <repository URL> lp2ps
cd lp2ps

# 2) Infrastructure (CDK) dependencies
cd infra && npm install && cd ..

# 3) Engine (Python) dependencies — required for building assets
python3 -m venv engine/.venv
engine/.venv/bin/pip install -e 'engine[dev]'
```

> ← `infra/npm install` prepares the CDK deployment tooling locally, and `engine/.venv` prepares the analysis engine.

---

## 4. Write the config (`config/<customer>.yaml`)

LP2PS deploys to multiple environments **by changing only the config, without modifying code**.
Copy `config/self.yaml` to create a new customer config.

```bash
cp config/self.yaml config/acme.yaml   # acme = customer name (any name you like)
```

Open `config/acme.yaml` in an editor and fill in the following:

```yaml
customer: acme                 # Stack name prefix (Lp2ps-acme-*). Lowercase letters and digits.
region: us-west-2              # Deployment region (where analysis, engine, and web are provisioned)

# false to analyze a single account only; true for multiple accounts.
cross_account: false
accounts:
  - self                       # "self" (the deploying account itself) when cross_account=false
readonly_role_name: null       # specify the member role name only when cross_account=true

engine:
  runtime: lambda

schedule:
  cron: null                   # null if not running on a schedule. Can be set later from the dashboard.

ai:
  enabled: false               # AI assistant off by default (Bedrock cost). Can be turned on from the dashboard.
  model: us.anthropic.claude-haiku-4-5-20251001-v1:0

provisioning:
  idc_region: us-east-1        # The region where IdC (Identity Center) resides. One region per account.

risk_rules:                    # Risk scoring rules (defaults recommended; adjust if needed)
  long_lived_key_days: 90
  unused_action_days: 90
  # (leave the remaining weights and level thresholds at the self.yaml defaults)

catalog:
  min_members_for_persona: 2

permission_sets:
  session_duration: PT8H       # PS session length (1–12 hours, ISO 8601). e.g., PT4H
```

> ← **Multi-account (analyzing multiple accounts)** is covered in [Step 12](#12-optional-multi-account--analyzing-multiple-accounts).
> We recommend starting with `cross_account: false` (analyzing only the deploying account).

Validate that the config is correct:

```bash
engine/.venv/bin/python -m lp2ps.cli validate-config -c config/acme.yaml
```

---

## 5. CDK Bootstrap (prepare the account for deployment — once per account · region)

The first time you deploy with CDK to an account · region, a one-time **bootstrap** (preparing the deployment
S3/IAM, etc.) is required. If you have done it before, you can skip this step (running it again is harmless).

```bash
cd infra
npx cdk bootstrap aws://<account-id>/<region>
# e.g.: npx cdk bootstrap aws://123456789012/us-west-2
cd ..
```

> ← `<account-id>` is the Account value from `aws sts get-caller-identity`, and `<region>` is the region in your config.
> Success when "✅ Environment aws://... bootstrapped" appears.

---

## 6. Build deployment assets (package Lambda code)

Bundle the code/dependencies of the engine and API Lambdas for deployment. **Always re-run this whenever you change code or config.**

```bash
bash infra/scripts/build-engine-assets.sh
```

> ← Stages the Linux Python wheels locally and creates the engine and API packages under `infra/assets/`
> (Docker not required). Success when "Asset build complete" appears.

---

## 7. Deploy the infrastructure (Data · Auth · Engine · Api)

Deploy the four stacks except Web first. Web is built later because it needs to know the API address.

```bash
cd infra
npx cdk deploy Lp2ps-acme-Data Lp2ps-acme-Auth Lp2ps-acme-Engine Lp2ps-acme-Api \
  -c config=../config/acme.yaml --require-approval never
cd ..
```

> ← The `acme` in `Lp2ps-acme-*` is the `customer` value from your config. Replace it with your own value.
> `-c config=...` specifies which config to use. This takes 5–10 minutes.
> At the end of each stack, `✅ Lp2ps-acme-...` appears, and **Outputs** print the API URL and so on.
> (If a permission approval prompt appears, `--require-approval never` passes it automatically.)

If deployment asks you to confirm creation of IAM resources, enter `y` (automatic with the never option).

---

## 8. Create a web login user (Cognito)

The web dashboard requires login. The administrator **invites** users (self sign-up is disabled).

### 8-1. Find the User Pool ID

```bash
aws cloudformation describe-stacks --stack-name Lp2ps-acme-Auth \
  --query "Stacks[0].Outputs[?OutputKey=='UserPoolId'].OutputValue" --output text
```
→ Returns a value in the form `us-west-2_XXXXXXXXX` (used in the next command).

### 8-2. Create the user (console)

1. Type **"Cognito"** into the AWS console search bar at the top → click **Amazon Cognito**
2. In the left menu, **User pools** → click the pool matching the ID above
3. **Users** tab → **Create user** button
4. Enter:
   - **Invitation message**: "Send an email invitation" (or "Don't send")
   - **Username**: the login ID (e.g., `admin@acme.com`)
   - **Email address**: the email
   - **Password**: "Generate a password" or set it yourself (12+ characters, upper/lowercase, digits, special characters)
5. **Create user**

### 8-3. Make the password permanent (required)

A console-created user is left in `FORCE_CHANGE_PASSWORD` state, i.e. it must change the password at first
login. The sign-in screen does not implement that challenge (`frontend/src/auth/cognito.ts`), so signing in
would fail with *"Password reset required (contact your administrator)"*. Promote the password to permanent:

```bash
aws cognito-idp admin-set-user-password \
  --user-pool-id us-west-2_XXXXXXXXX --username admin@acme.com \
  --password '<the same password>' --permanent --region us-west-2

# Verify: expect CONFIRMED
aws cognito-idp admin-get-user --user-pool-id us-west-2_XXXXXXXXX \
  --username admin@acme.com --region us-west-2 --query UserStatus --output text
```

> ← User creation is also possible via the CLI, but for beginners the console is clearer. Confirm in the
> top-right of the console that the region is the deployment region (us-west-2) — the user pool exists only
> in that region, so in any other region **User pools** looks empty and it is easy to start creating a *new*
> pool by mistake. The `<prefix>-Auth` stack already created the pool; only add a user to it.

---

## 9. Build + deploy + access the web

### 9-1. Build the web (inject the real API address)

```bash
AWS_REGION=us-west-2 bash infra/scripts/build-web.sh Lp2ps-acme
```

> ← Automatically reads the API URL and Cognito info from the deployed Api · Auth stacks and injects them into the frontend.
> `Lp2ps-acme` is the stack prefix. Success when "frontend/dist build complete" appears.

### 9-2. Deploy the web stack

```bash
cd infra
npx cdk deploy Lp2ps-acme-Web -c config=../config/acme.yaml --require-approval never
cd ..
```

The **SiteUrl** in the Outputs (`https://xxxxx.cloudfront.net`) is the web dashboard address.

### 9-3. Set the CORS origin (⚠ required — the dashboard won't load without it)

For security, the API accepts browser requests only when an allowed origin is configured (if unset, CORS is closed
= no wildcard allowed). Set the **SiteUrl** you just obtained as the API Lambda's `LP2PS_WEB_ORIGIN` environment variable.

```bash
# Find the API Lambda function name
API_FN=$(aws cloudformation describe-stack-resources --stack-name Lp2ps-acme-Api \
  --query "StackResources[?ResourceType=='AWS::Lambda::Function'].PhysicalResourceId" --output text)

# Inject the SiteUrl (without a trailing slash) as LP2PS_WEB_ORIGIN (merging existing env)
ORIGIN="https://xxxxx.cloudfront.net"   # ← the SiteUrl from 9-2 (remove trailing slash)
CUR=$(aws lambda get-function-configuration --function-name "$API_FN" --query 'Environment.Variables' --output json)
NEW=$(python3 -c "import json,sys; e=json.loads(sys.argv[1]); e['LP2PS_WEB_ORIGIN']=sys.argv[2]; print(json.dumps({'Variables':e}))" "$CUR" "$ORIGIN")
aws lambda update-function-configuration --function-name "$API_FN" --environment "$NEW"
```

> ← If you use the one-click script (`deploy-all.sh`), this step is **automatic**. It is only needed for manual deployment.
> If you skip this step, login works but the dashboard cannot load data (CORS errors in the browser console).

### 9-4. Access

Open the SiteUrl in a browser → log in with the user created in Step 8 → enter the dashboard.
(If you haven't run an analysis yet, the data is empty → go to Steps 10–11.)

---

## 10. Run the first analysis (first run)

Click the **"Run full scan"** button at the top of the dashboard to start the analysis (easiest).
Alternatively, you can run it directly via the CLI:

```bash
# Find the Step Functions ARN
aws cloudformation describe-stacks --stack-name Lp2ps-acme-Engine \
  --query "Stacks[0].Outputs[?OutputKey=='StateMachineArn'].OutputValue" --output text

# Run (use the ARN from above)
RID="run-$(date -u +%Y%m%dT%H%M%SZ)"
aws stepfunctions start-execution \
  --state-machine-arn "<ARN from above>" \
  --name "$RID" \
  --input "{\"run_id\":\"$RID\",\"started_at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
```

> ← Collection (Access Advisor, etc.) takes a few minutes, proportional to the number of principals. When it completes,
> the dashboard is populated with the persona catalog, items needing action, and reports. You can check progress
> (RUNNING → SUCCEEDED) with `aws stepfunctions describe-execution --execution-arn <execution ARN> --query status`.

---

## 11. Data source prerequisites (accuracy · cost)

LP2PS works with its default sources **at no additional cost**. The following are optional items that improve accuracy.
(For the detailed table, see "Data source prerequisites and cost" in `docs/multi-account-onboarding.md`.)

| Source | Cost | If absent |
|---|---|---|
| Access Advisor (last-used timestamp) | Free | — (core, always present) |
| CloudTrail LookupEvents (90 days of management events) | Free | Usage counts not collected (supplemented by Access Advisor) |
| Credential Report (MFA · key age) | Free | Cannot assess credential hygiene |
| IAM Access Analyzer (unused-access) | Charged when the analyzer is active | skipped (replaced by Access Advisor) |
| **CloudTrail Lake** | (paid — **not used**) | — |

> LP2PS does not use the paid CloudTrail Lake. Access Analyzer (unused-access) is used automatically if it is already
> enabled, and skipped if not (this is normal).

---

## 12. (Optional) Multi-account — analyzing multiple accounts

For a single tooling account to analyze multiple member accounts, deploy a **read-only role to each member account**
and change the config to `cross_account: true`. The detailed procedure is in the separate document
**`docs/multi-account-onboarding.md`**. Summary:

1. Find the tooling engine role ARN →
2. Deploy `cfn/lp2ps-readonly-role.yaml` to each member account (specify the engine role ARN as a parameter) →
3. Set the config to `cross_account: true`, `accounts: [<account IDs>]`, `readonly_role_name: lp2ps-readonly` →
4. Redeploy the engine + a new run.

> **⚠ Constraints (important)**: The following is identical to the "Scope of application" section of `docs/multi-account-onboarding.md`.
> - **Collection · analysis · least-privilege catalog · reports** work without IdC and regardless of Organizations.
> - **Generating Permission Set definitions** requires IdC to be enabled in the tooling account, and PSs are
>   created **only in the single tooling IdC** (no write permission needed on member account read-only roles).
> - **Permission Set assignment (actual application)** is only possible when the target account **belongs to the same
>   AWS Organization as the tooling IdC**. For accounts in a different Org / standalone accounts, only analysis and PS
>   definition generation are possible.
> - **Pure IAM User environments without IdC** are limited to analysis and least-privilege output. PS automation
>   presupposes IdC.

---

## 13. (Optional) Create · assign Permission Sets — apply least privilege

When the analysis finishes, you can create actual IdC Permission Sets from **Persona review** in the dashboard.
(IdC must be enabled in the tooling account.)

1. **Persona review** → click **Edit policy** for a persona → review permissions (actually-used ones included; unused ones excluded after review)
2. **Approve with this policy** → confirm approval → Terraform is shown
3. **Create Permission Set in IdC…** → second confirmation ("actual write operation") → **Confirm creation**
   → a PS definition is created in the tooling account's IdC (including the inline least-privilege policy; no account assignment).

To actually use the created PS (operational best practice):

1. IdC console (IdC region, e.g., us-east-1) → **Multi-account permissions → AWS accounts**
2. Select the target account → **Assign users or groups**
3. Select **a person (or group)** + the **Permission Set** you just created → Submit
4. That user logs in to the **AWS access portal** (password + MFA) → accesses with least privilege via the assigned PS (temporary credentials)

> ← The PS is created in the tooling IdC, and "who to grant it to" is assigned by a person (the tool does not assign
> automatically — intentional, for safety). Credentials are not handed out by the administrator; instead, **the user
> self-logs-in with their own IdC account**.

---

## 14. Redeploy for updates (when code/config changes)

- **Engine/API code changes**: `bash infra/scripts/build-engine-assets.sh` → `cd infra && npx cdk
  deploy Lp2ps-acme-Engine Lp2ps-acme-Api -c config=../config/acme.yaml --require-approval never`.
  **Always rebuild assets when you change code** (otherwise the old code is deployed).
- **Frontend changes**: `AWS_REGION=us-west-2 bash infra/scripts/build-web.sh Lp2ps-acme` →
  `cd infra && npx cdk deploy Lp2ps-acme-Web -c config=../config/acme.yaml --require-approval never`.
- **Config-only changes**: redeploy only the affected stack (usually Engine/Api).

---

## 15. Deletion (cleanup)

To completely remove the deployment (stop charges):

```bash
cd infra
npx cdk destroy Lp2ps-acme-Web Lp2ps-acme-Api Lp2ps-acme-Engine Lp2ps-acme-Auth Lp2ps-acme-Data \
  -c config=../config/acme.yaml --force
cd ..
```
If you deployed a role to member accounts, also delete the `lp2ps-readonly` stack in those accounts.

Teardown removes every resource these stacks created, including S3/DynamoDB data, the Cognito user pool (and
therefore its users), and all CloudWatch log groups. It does **not** remove the shared CDK bootstrap stack
(`CDKToolkit`) or the member-account roles.

> ⚠ **Shared account**: API Gateway stores the IAM role used for API logging in an account- and Region-wide
> setting (`AWS::ApiGateway::Account`, one per Region). This deployment sets that role and deletes it on
> teardown, which leaves the setting pointing at a deleted role — any **other** REST API in that Region then
> stops writing CloudWatch logs. That is correct for the dedicated tooling account LP2PS assumes. To deploy
> into a shared account, first change `cloudWatchRoleRemovalPolicy` in `infra/lib/api-stack.ts` to
> `cdk.RemovalPolicy.RETAIN`.

See `docs/quick-deploy.md` §5 for the post-teardown verification commands.

---

## 16. Troubleshooting (common issues)

| Symptom | Cause · resolution |
|---|---|
| `cdk` command not found | Run via `npx cdk ...` after `cd infra` (no global install needed). |
| `not bootstrapped` during deploy | Step 5 `cdk bootstrap` was not run → run it. |
| Permission denied during deploy | The sign-in role is not Admin → recheck Step 2, `aws sts get-caller-identity`. |
| `Password reset required (contact your administrator).` at sign-in | The user is still in `FORCE_CHANGE_PASSWORD` → run the Step 8-3 `admin-set-user-password --permanent` command. |
| **User pools** is empty in the Cognito console | The console region does not match `region:` → switch the region in the top right. Do not create a new pool. |
| Blank screen / infinite loading after web login | (1) **The 9-3 CORS origin setting was skipped** — if you see CORS errors in the browser console (F12), set `LP2PS_WEB_ORIGIN` to the SiteUrl. (2) The web was built **before** the API was deployed → rebuild at 9-1, then redeploy at 9-2. |
| Old screen on the web | Hard-refresh the browser (Cmd+Shift+R / Ctrl+Shift+R). CloudFront is invalidated automatically on deploy. |
| Data is empty after analysis | The run was not executed or is still running → Step 10, confirm SUCCEEDED with `describe-execution`. |
| Run status is `degraded` | Shown only when some sources were actually partially collected. In **Run history**, use "Status rationale → View details" on that run's row to see which source is affected and why. A missing optional source (`skipped`) is normal and shown as `succeeded`. |
| `AccessDenied` (SSO) | Session expired → `aws sso login --profile lp2ps`. |
| 409 when creating a Permission Set | IdC not enabled (IdC must be turned on in the tooling account) or the persona is not approved. |

---

## Appendix A. Deployment order at a glance (checklist)

```
[ ] 1. Install tools (aws-cli, node, python, git)
[ ] 2. aws configure sso  →  confirm the account with aws sts get-caller-identity
[ ] 3. git clone → cd infra && npm install → engine venv + pip install
[ ] 4. Write config/<customer>.yaml → validate-config
[ ] 5. cd infra && npx cdk bootstrap aws://<account>/<region>
[ ] 6. bash infra/scripts/build-engine-assets.sh
[ ] 7. cdk deploy <prefix>-Data <prefix>-Auth <prefix>-Engine <prefix>-Api
[ ] 8. Create a login user in the Cognito console → admin-set-user-password --permanent (status CONFIRMED)
[ ] 9. build-web.sh <prefix> → cdk deploy <prefix>-Web → open SiteUrl
[ ] 10. Dashboard "Run full scan" (first run) → confirm SUCCEEDED
[ ] 11. (Optional) Multi-account role / create · assign Permission Sets
```

## Appendix B. Recommended security hardening for production

- Set Cognito MFA to **REQUIRED** (the sample uses OPTIONAL). Cognito console → the pool → Sign-in →
  Multi-factor authentication → "Require MFA".
- CORS allowed origin: after the Web deploy, `deploy-all.sh` **automatically injects** the CloudFront domain into the
  API Lambda's `LP2PS_WEB_ORIGIN` (if unset, CORS is closed = not a wildcard). For manual deployment, set the API
  Lambda environment variable `LP2PS_WEB_ORIGIN=https://<CloudFront domain>` yourself.
- `LP2PS_AUTH_DISABLED` is for local/testing only and must never be set in a deployment (the code ignores it in Lambda).
- Keep the Permission Set session duration short for sensitive personas (config `permission_sets.session_duration`).
