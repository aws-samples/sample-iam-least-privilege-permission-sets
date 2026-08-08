# LP2PS Quick Deploy Guide (One-Click Script)

This document explains how to **deploy LP2PS all at once using the `deploy-all.sh` script**.
If you would rather deploy step by step and understand each stage, see the detailed guide **`docs/deployment-guide.md`**.
This document focuses on "getting it up fast."

> The script is pure bash. **You do not need Claude Code or any other tool** — a terminal is all you need.

---

## 0. Prerequisites (one time only)

### 0-1. Install local tools
You need `aws-cli(v2), node(18+), python(3.11+), git`. Check:
```bash
aws --version && node --version && python3 --version && git --version
```
If missing, install them (see step 1 of `docs/deployment-guide.md` for OS-specific details):
- **macOS**: `brew install awscli node python@3.12 git`
- **Windows**: awscli.amazonaws.com / nodejs.org(LTS) / python.org (check "Add to PATH" during install) / git-scm.com
- **Linux(Ubuntu)**: `sudo apt install -y python3 python3-pip git` + install AWS CLI v2 and Node 20

### 0-2. Sign in to AWS (control account, admin privileges)
```bash
aws configure sso          # SSO method (recommended). Ask your org admin for the start URL and region.
# or  aws configure       # IAM access key method
aws sts get-caller-identity # Verify the target account ID is correct
```
If you used SSO, activate the profile: `export AWS_PROFILE=<profile-name>`
(When the session expires, re-authenticate with `aws sso login --profile <profile-name>`)

### 0-3. Source + dependencies (one time only)
```bash
git clone https://github.com/aws-samples/sample-iam-least-privilege-permission-sets.git lp2ps && cd lp2ps
cd infra && npm install && cd ..
cd frontend && npm install && cd ..
python3 -m venv engine/.venv && engine/.venv/bin/pip install -e 'engine[dev]'
```

---

## 1. Write the config

Copy `config/self.yaml` to create a customer config and fill in `customer`/`region` and other fields.
```bash
cp config/self.yaml config/<customer-name>.yaml     # e.g. config/acme.yaml
```
Minimum fields to edit:
```yaml
customer: acme          # Stack prefix (Lp2ps-acme-*). Lowercase letters and digits.
region: us-west-2       # Deployment region
cross_account: false    # false for single-account analysis (see step 4 for multi-account)
accounts: [self]
provisioning:
  idc_region: us-east-1 # IdC (Identity Center) region
```
Validate:
```bash
engine/.venv/bin/python -m lp2ps.cli validate-config -c config/acme.yaml
```

---

## 2. One-click deploy

```bash
# First account (add --bootstrap if this is the first time using CDK in this account/region)
infra/scripts/deploy-all.sh config/acme.yaml --bootstrap

# Afterward (already bootstrapped) or for redeploys
infra/scripts/deploy-all.sh config/acme.yaml
```

The script runs the following automatically, in order:
```
[0] cdk bootstrap        (only if --bootstrap is given)
[1] Build engine and API assets
[2] Deploy Data, Auth, Engine, and Api
[3] Build web (API address injected automatically)
[4] Deploy Web
```
When it finishes, it prints this at the end:
```
✅ DEPLOY-ALL complete (Lp2ps-acme)
   Web dashboard : https://xxxxx.cloudfront.net
   API           : https://xxxxx.execute-api...
   Cognito pool  : us-west-2_XXXXXXXXX
```
→ Note down the **web dashboard URL** and the **Cognito pool ID** (needed in the next step).

> This takes 5–10 minutes. After changing code or config, rerun this script and the assets are rebuilt automatically.

---

## 3. Create a web login user + sign in

The web app requires login. Self sign-up is disabled, so an administrator invites the user.

> ⚠ **Set the console region first.** In the top-right region selector, switch to the `region:` you deployed
> to. The user pool only exists in that region — in any other region **User pools** looks empty, and it is easy
> to start creating a *new* pool ("Define your application" → Traditional web application / SPA / …) by mistake.
> **Do not create a new pool.** The `<prefix>-Auth` stack already created it; you are only adding a user to it.

1. Search **"Cognito"** in the AWS console → **Amazon Cognito** → **User pools**
2. Click the pool matching the **Cognito pool ID** from step 2 → **Users** tab → **Create user**
3. Enter Email address and Password (12+ chars, upper/lowercase, digit, symbol) → **Create user**
4. **Make the password permanent** (required). A console-created user lands in `FORCE_CHANGE_PASSWORD`
   state, and the sign-in screen does not implement the "new password required" challenge — it would fail with
   *"Password reset required (contact your administrator)"*. Run:
   ```bash
   aws cognito-idp admin-set-user-password \
     --user-pool-id <Cognito pool ID> --username <email> \
     --password '<the same password>' --permanent --region <region>
   ```
   The user status becomes `CONFIRMED`; verify with
   `aws cognito-idp admin-get-user --user-pool-id <pool> --username <email> --region <region> --query UserStatus`.
5. Open the **web dashboard URL** in a browser → sign in as this user
6. Click **"Run full scan"** at the top of the dashboard → the first analysis starts (a few minutes) → once done, personas and reports are populated

---

## 4. (Optional) Multi-account analysis

To analyze multiple accounts from a single control account, deploy a read-only role to each member account and
change the config to `cross_account: true`. For the detailed procedure and constraints, see **`docs/multi-account-onboarding.md`**.

Summary: deploy `cfn/lp2ps-readonly-role.yaml` to member accounts → set
`cross_account: true`, `accounts: [<account IDs>]`, `readonly_role_name: lp2ps-readonly` in the config →
rerun `infra/scripts/deploy-all.sh config/acme.yaml`.

> ⚠ **Constraint**: Permission Set **assignment (actual application)** is only possible when the target account belongs to the
> **same AWS Organization** as the control IdC. Collection, analysis, and PS definition creation work regardless of Org. (For details, see the
> "Scope of application" section of `docs/multi-account-onboarding.md`.)

---

## 5. Teardown (one-click)

```bash
infra/scripts/destroy-all.sh config/acme.yaml
```
This deletes the 5 stacks in reverse order (including S3/DynamoDB data). For member account roles, delete the
`lp2ps-readonly` stack separately in each member account.

> ⚠ **Shared-account caveat — read this before deploying into an account that runs other API Gateway APIs.**
> API Gateway keeps the IAM role used for API logging in an **account- and Region-wide setting**
> (`AWS::ApiGateway::Account`), of which there can be only one per Region. This deployment sets that role and
> deletes it on teardown, so the account-level setting is left pointing at a role that no longer exists. Any
> **other** REST API in the same Region then stops writing CloudWatch logs until the setting is repointed.
>
> LP2PS assumes a dedicated tooling account, where this is the desired behavior — teardown leaves nothing
> behind. If you must deploy into a shared account, change `cloudWatchRoleRemovalPolicy` in
> `infra/lib/api-stack.ts` to `cdk.RemovalPolicy.RETAIN` before deploying; teardown will then leave the role
> and the account-level setting intact, and you delete the role by hand when no other API needs it.

After teardown, confirm nothing was left behind (all five commands should print nothing):

```bash
REGION=us-east-1   # your config's region:
PREFIX=Lp2ps-acme  # Lp2ps-<customer>
aws cloudformation list-stacks --region "$REGION" \
  --query "StackSummaries[?starts_with(StackName,'$PREFIX') && StackStatus!='DELETE_COMPLETE'].StackName" --output text
aws s3api list-buckets --query "Buckets[?contains(Name,'lp2ps')].Name" --output text
aws dynamodb list-tables --region "$REGION" --query "TableNames[?contains(@,'p2ps')]" --output text
aws iam list-roles --query "Roles[?starts_with(RoleName,'$PREFIX')].RoleName" --output text
aws logs describe-log-groups --region "$REGION" \
  --query "logGroups[?contains(logGroupName,'$PREFIX')].logGroupName" --output text
```

The bootstrap stack (`CDKToolkit`) and its staging bucket are **not** removed — they are shared by every CDK
app in the account. Remove them only if nothing else uses CDK there:
`aws cloudformation delete-stack --stack-name CDKToolkit --region "$REGION"`.

---

## Troubleshooting (common issues)

| Symptom | Fix |
|---|---|
| `aws login required` | Run `aws sso login --profile <profile>`, then retry |
| `not bootstrapped` | Rerun with the `--bootstrap` option |
| `config parse failed` | Check that `customer:` and `region:` are at the leftmost column of the file |
| `Password reset required (contact your administrator).` at sign-in | The user is still in `FORCE_CHANGE_PASSWORD`. Run the `admin-set-user-password --permanent` command in step 3-4 |
| **User pools** is empty in the Cognito console | Wrong region. Switch the console region (top right) to your `region:`. Do not create a new pool |
| Infinite loading after web login | This script guarantees ordering automatically, so this is rare. If it happens, rerun `deploy-all.sh` |
| Old screen in web | Hard-refresh the browser (Cmd+Shift+R / Ctrl+Shift+R) |
| Permission denied | Verify your login role is Admin |

For more detailed step-by-step explanations, console click paths, Permission Set creation, and data source costs,
see **`docs/deployment-guide.md`**.
