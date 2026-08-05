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
git clone <repo URL> lp2ps && cd lp2ps
cd infra && npm install && cd ..
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

The web app requires login. Invite a user from the Cognito console:

1. Search **"Cognito"** in the AWS console → **Amazon Cognito** → **User pools**
2. Click the pool matching the **Cognito pool ID** from step 2 → **Users** tab → **Create user**
3. Enter Username (email) and Password → **Create user**
4. Open the **web dashboard URL** in a browser → sign in as this user
5. Click **"Run full scan"** at the top of the dashboard → the first analysis starts (a few minutes) → once done, personas and reports are populated

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

---

## Troubleshooting (common issues)

| Symptom | Fix |
|---|---|
| `aws login required` | Run `aws sso login --profile <profile>`, then retry |
| `not bootstrapped` | Rerun with the `--bootstrap` option |
| `config parse failed` | Check that `customer:` and `region:` are at the leftmost column of the file |
| Infinite loading after web login | This script guarantees ordering automatically, so this is rare. If it happens, rerun `deploy-all.sh` |
| Old screen in web | Hard-refresh the browser (Cmd+Shift+R / Ctrl+Shift+R) |
| Permission denied | Verify your login role is Admin |

For more detailed step-by-step explanations, console click paths, Permission Set creation, and data source costs,
see **`docs/deployment-guide.md`**.
