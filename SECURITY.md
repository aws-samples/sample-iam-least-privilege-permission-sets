# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in this project, **do not open a public issue.**
Instead, report it privately to the maintainers. Including the following helps:

- Type of vulnerability and its impact
- Reproduction steps or a proof of concept
- Affected versions/commits

We will respond within a reasonable time and, once fixed, credit the reporter (if desired).

## Security design principles of this tool

Because LP2PS produces IAM policies, the tool itself follows least-privilege and read-only principles.

- **Read-only:** Against analyzed (member) accounts, only allowlisted describe/list APIs are called. A
  botocore `before-call` hook blocks anything else as a `ReadOnlyViolation` (fail-closed).
- **Mitigation exception:** Only the creation of Permission Set **definitions** in the tooling account's
  IdC is allowed, gated by a server-side approval check — the persona must already be in the `approved`
  state or the request is rejected. Account assignment is never performed. Member accounts are never
  modified under any circumstances.
- **No secrets:** Credentials, keys, and tokens are not stored in code or configuration. `.env`, `*.pem`,
  and `cdk.context.json` are covered by `.gitignore`.
- **Least-privilege IAM:** The tool's execution roles avoid wildcards and minimize resource scope.
- **Determinism & audit logs:** Risk scoring and policy synthesis record their rationale in audit logs.

## Web/API security (threat model)

Security decisions for the dashboard (React) and API (FastAPI/Lambda) and their rationale.

- **Authentication:** The API is protected by an **API Gateway Cognito authorizer** (first layer), and the
  Lambda re-verifies the authorizer-provided claims in-process (defense-in-depth, `backend/lp2ps_api/auth.py`).
  - **JWKS signature verification (advanced option):** To minimize dependencies, the in-process layer does
    **not re-verify the token signature** against Cognito JWKS itself; it trusts that the request passed the
    API GW authorizer. Since the authorizer already enforces valid signature, expiry, and audience, this is
    sufficient on the normal path. If you consider paths that bypass the authorizer a threat (e.g.,
    redeploying the API without an authorizer), adding JWKS signature verification in `require_auth` is a
    **recommended hardening step**.
  - **Test bypass guard:** `LP2PS_AUTH_DISABLED=true` is a **local/test-only** bypass. Deployment (CDK) code
    never sets this variable, and the code **ignores the bypass in a Lambda environment** (when
    `AWS_LAMBDA_FUNCTION_NAME` is present) and enforces authentication (fail-closed). So even if the env var
    leaks in by a deployment mistake, authentication is not disabled in production.
- **CORS:** The allowed origin is specified only via `LP2PS_WEB_ORIGIN` (the actual CloudFront domain). **When
  unset, CORS is closed rather than opened with a wildcard (`*`) (fail-safe).** The deployment script
  (`deploy-all.sh`) automatically injects the CloudFront domain into the API Lambda after the web stack is
  deployed.
- **Transport security:** CloudFront enforces HTTPS; S3 uses BLOCK_ALL_PUBLIC + a SecureTransport deny; API GW
  uses TLS.
- **Minimal data exposure:** Stored data is only IAM resource metadata (role/user names, ARNs, policies, usage
  facts). No separate PII (e.g., email) or customer business data is collected or stored. Outputs are stored
  only in the customer-owned S3/DynamoDB (each environment self-deploys — no cross-customer data mixing).

## Known dependency advisories

`npm audit` reports **no findings** in either `frontend/` or `infra/`.

The `brace-expansion` DoS advisory (3.0.0 – 5.0.8), reached through `aws-cdk-lib > minimatch`, was
previously unfixable here: `aws-cdk-lib` **bundles** its own copy under
`node_modules/aws-cdk-lib/node_modules/`, so an npm `overrides` entry does not replace it. It is
cleared by `aws-cdk-lib` 2.266.0, which bundles 5.0.9 — outside the advisory range. Keep
`aws-cdk-lib`/`aws-cdk` at 2.266.0 or later.

## Supported versions

This is an early-stage project. Security fixes are provided only for the latest `main`.
