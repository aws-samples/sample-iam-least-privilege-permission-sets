# LP2PS Multi-Account Onboarding Guide (cross-account read-only role)

LP2PS runs on a structure of **one tooling account** (which hosts the full engine, data,
and web deployment) plus **N member accounts** (each with only a single read-only role).
The tooling engine assumes each member account's read-only role via `sts:AssumeRole` to
collect IAM usage data in a **read-only** manner. The engine, DB, and web are **not deployed**
to member accounts.

```
tooling account (111122223333)          member account(s)
┌────────────────────┐  sts:AssumeRole  ┌───────────────────────┐
│ Engine Lambda       │ ───────────────▶ │ lp2ps-readonly (role) │
│ (Engine role)      │                  │ read-only IAM/CT/AA    │
└────────────────────┘                  └───────────────────────┘
```

---

## Scope / Prerequisites (regarding Permission Set creation & assignment — must read)

Each LP2PS stage has different requirements. **Collection, analysis, the least-privilege catalog,
and reporting are always available**, while **only PS creation and assignment (automation)** are
subject to the conditions below.

| Stage | Requirement |
|---|---|
| Collection, analysis, persona catalog, action items, reporting | Only the member account read-only role (IdC not required, Org-independent) |
| **Permission Set definition creation** (provision-ps) | Requires **IAM Identity Center (IdC) enabled** in the tooling account. PS is created **only in the management (tooling) IdC** (never in member accounts — member roles stay read-only) |
| **Permission Set assignment (assign)** — actual application | The target account must belong to the **same AWS Organization as the management IdC** to appear as an IdC assignment target |

- **PS is created in the management IdC, not in member accounts** → write permissions on the member read-only role are **unnecessary and are not granted** (invariant ①). PS writes are performed by the tooling API Lambda (sso:CreatePermissionSet).
- **Assign only works for accounts in the same Org**: an IdC manages a single Organization. Member accounts in a different Org (or standalone) **can be collected, analyzed, and have PS definitions created, but that PS cannot be assigned to that account** (it will not appear in the IdC "AWS accounts" list). In this case, a person must separately apply the generated least-privilege policy to that account's IdC/IAM (see the report Terraform).
- **Environments without IdC (IAM roles/users only)**: if no IdC instance exists, provision-ps **rejects with a 409** (it does not crash). Set `provisioning.uses_identity_center: false` — approval then produces a **managed IAM policy `.tf`, an IAM role `.tf`, and the policy JSON** instead of a Permission Set `.tf` you could not apply, and a full run writes `iac/iam_policies.tf` (all personas) rather than the PS files. Applying is still a human action, either (a) attach the generated policy to your existing roles, or (b) adopt IdC and migrate to PS later. In other words, **PS automation presupposes IdC, but producing an applicable least-privilege artifact does not**.

---

## Reference Information (for this deployment)

- **tooling account**: `111122223333` / `us-west-2` (the full tool is already deployed)
- **tooling engine role ARN** (needed in the member role's trust policy):
  ```
  arn:aws:iam::111122223333:role/Lp2ps-<customer>-Engine-EngineRole-XXXXXXXX
  ```
  > Note: redeploying the tooling changes this ARN. To check the current value:
  > ```
  > aws cloudformation describe-stack-resources --stack-name Lp2ps-self-Engine \
  >   --query "StackResources[?contains(LogicalResourceId,'EngineRole')].PhysicalResourceId" --output text
  > ```

---

## STEP 1 — Deploy the read-only role to member accounts (done by you)

Using the credentials of each **member account** (console or CLI), deploy the template below.

Template: `cfn/lp2ps-readonly-role.yaml` (included in this repo)

### Option A — CLI (single member account, recommended for testing)

With member account credentials:
```bash
aws cloudformation deploy \
  --template-file cfn/lp2ps-readonly-role.yaml \
  --stack-name lp2ps-readonly \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-west-2 \
  --parameter-overrides \
    ToolingEngineRoleArn=arn:aws:iam::111122223333:role/Lp2ps-<customer>-Engine-EngineRole-XXXXXXXX \
    ReadOnlyRoleName=lp2ps-readonly
```
- `--capabilities CAPABILITY_NAMED_IAM`: required because a named IAM role is created.
- An IAM role is a global resource, but a CloudFormation stack requires a region (us-west-2 recommended, to match the tooling).

### Option B — Console

1. Member account console → CloudFormation → **Create stack → With new resources**
2. Upload `cfn/lp2ps-readonly-role.yaml`
3. Parameters:
   - `ToolingEngineRoleArn` = the tooling engine role ARN above
   - `ReadOnlyRoleName` = `lp2ps-readonly` (default)
4. Check **"I acknowledge that AWS CloudFormation might create IAM resources with custom names"** → Create

### Option C — StackSet (multiple member accounts, production)

Deploy to multiple member accounts at once via a StackSet from the Organizations management account (not needed for testing).

### Verify the deployment
In the member account:
```bash
aws iam get-role --role-name lp2ps-readonly --query 'Role.Arn' --output text
```
→ Success if it returns `arn:aws:iam::<member account ID>:role/lp2ps-readonly`.
Just let me know this role was created (or the member account ID), and I will wire up the tooling side.

---

## STEP 2 — Redeploy the tooling account with multi-account config (done by me)

Once I have the member account ID, I create `config/<customer>.yaml` like this:
```yaml
customer: <customer name>
region: us-west-2
cross_account: true         # ← multi-account mode
accounts:                   # ← member accounts to analyze
  - "<member account ID>"
readonly_role_name: lp2ps-readonly   # ← must match the role name from STEP 1
# engine/ai/provisioning etc. are the same as in self.yaml
```
Then redeploy the engine stack in the tooling account:
```bash
cd infra && npx cdk deploy Lp2ps-<customer>-Engine -c config=config/<customer>.yaml --require-approval never
```
→ The engine role gains `sts:AssumeRole arn:aws:iam::<member>:role/lp2ps-readonly` permission.

---

## STEP 3 — Verify cross-account collection (done by me)

Run Step Functions → assume the member account and collect → verify the S3/DynamoDB artifacts.
- The member account's IAM/CloudTrail/Access Analyzer are **only read**, and nothing is changed (invariant ①).
- If the member account has no unused-access analyzer, that source alone finishes as `skipped` — this is
  **normal** (an optional source is absent, substituted by Access Advisor), and the run status remains
  `succeeded`. To improve accuracy further, enable the analyzer in the member account beforehand
  (a prerequisite; the tool does not create it). `degraded` is shown only when a source was actually
  partially collected (expand the row in the run history to see the per-source reason).

---

## Data Source Prerequisites and Cost (must read before customer deployment)

LP2PS is **read-only** and **does not create** data sources (invariant ①). It is **designed to avoid
sources that incur additional cost** — it operates entirely on default (free) sources. It imposes no
separate cost on the customer.

| Data source | Used | Cost | Role |
|---|---|---|---|
| **Access Advisor** (Service Last Accessed) | ✅ core | **free** | Last-used time per service/action (last_used). The core of unused determination |
| **CloudTrail** (`LookupEvents`, 90d) | ✅ | **free** | Usage count based on management events (count). `ok` on successful collection |
| **Credential Report** | ✅ | **free** | MFA, access key age, last used |
| **IAM Access Analyzer** (unused-access) | optional | billed when analyzer is active | If present, augments unused findings. If absent, `skipped` (substituted by Access Advisor) |
| **CloudTrail Lake** (Event Data Store) | ❌ **not used** | (not adopted because it is paid) | — |

**Key disclosure statement (for customer communication):**
> LP2PS operates **at no additional cost** using the default CloudTrail (LookupEvents), Access Advisor,
> and Credential Report. It does not use the paid CloudTrail Lake.

- **CloudTrail ≠ CloudTrail Lake**: LP2PS uses only the default CloudTrail `LookupEvents` (free).
  This returns **management events** only and does not include data events (e.g., S3 GetObject), but
  Access Advisor (last_used) compensates for this, so it is sufficient for least-privilege analysis
  (`ok` on successful collection).
- Very high-activity accounts may hit the page cap (200) and miss some older events, but this is
  considered **normal (`ok`)** (LookupEvents is inherently a partial source and Access Advisor
  compensates). Only a note records "page cap reached." This is acceptable because the use case does
  not require real-time accuracy.
- Access Analyzer (unused-access) is used automatically if the customer has already enabled it, and is skipped if absent (the tool does not create it).

---

## Safety / Invariant Summary

- The member account role has **query APIs only** (IAM Get/List, Access Analyzer, CloudTrail read). Zero writes.
- The trust policy allows assume **only from the tooling engine role ARN** (no other principal).
- The client the tooling engine attaches to the member session keeps the **awsguard read-only hook** intact.
- Permission Set definition creation (provision-ps) happens **only in the tooling account IdC**; there is no write of any kind to member accounts.

## Cleanup (after testing)
In the member account:
```bash
aws cloudformation delete-stack --stack-name lp2ps-readonly --region us-west-2
```
