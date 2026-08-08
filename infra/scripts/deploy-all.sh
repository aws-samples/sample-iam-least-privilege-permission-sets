#!/usr/bin/env bash
# One-click full deploy — build assets -> deploy 4 stacks (Data/Auth/Engine/Api) -> build web -> deploy Web ->
# lock CORS origin (inject the CloudFront domain into the API Lambda's LP2PS_WEB_ORIGIN).
# Enforces the correct order (web must be last since it needs the Api/Auth outputs).
#
# Usage:
#   infra/scripts/deploy-all.sh [config-file] [--bootstrap]
# Examples:
#   infra/scripts/deploy-all.sh config/self.yaml
#   infra/scripts/deploy-all.sh config/acme.yaml --bootstrap   # first time in an account: includes bootstrap
#
# Prereqs: aws sign-in (aws sso login), infra/npm install, engine/.venv + pip install.
# Re-running after code/config changes rebuilds assets automatically (avoids stale artifacts).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG_ARG="${1:-config/self.yaml}"
DO_BOOTSTRAP=""
[[ "${2:-}" == "--bootstrap" ]] && DO_BOOTSTRAP="yes"

# Resolve the config path to an absolute path relative to ROOT.
case "$CONFIG_ARG" in
  /*) CONFIG="$CONFIG_ARG" ;;
  *)  CONFIG="$ROOT/$CONFIG_ARG" ;;
esac
[[ -f "$CONFIG" ]] || { echo "❌ config not found: $CONFIG"; exit 1; }

# Extract customer/region from the config (simple parser via grep — works without the engine).
CUSTOMER="$(grep -E '^customer:' "$CONFIG" | head -1 | sed 's/customer:[[:space:]]*//; s/[[:space:]]*$//')"
REGION="$(grep -E '^region:'   "$CONFIG" | head -1 | sed 's/region:[[:space:]]*//;   s/[[:space:]]*$//')"
[[ -n "$CUSTOMER" && -n "$REGION" ]] || { echo "❌ failed to parse customer/region from config"; exit 1; }
PREFIX="Lp2ps-${CUSTOMER}"
export AWS_REGION="$REGION"

echo "== Deploy target: prefix=$PREFIX region=$REGION config=$CONFIG =="
ACCT="$(aws sts get-caller-identity --query Account --output text)" || { echo "❌ AWS sign-in required (aws sso login)"; exit 1; }
echo "   AWS account: $ACCT"

# 0) Build engine/API assets (always — reflects code changes).
#    Must run before any cdk command: cdk synthesizes bin/lp2ps.ts even for `bootstrap`, and the synth
#    reads infra/assets/* (Lambda layer/code). Bootstrapping first would fail with CannotFindAsset.
echo "== [0/5] Build engine/API assets =="
bash "$ROOT/infra/scripts/build-engine-assets.sh"

# 1) (optional) bootstrap. Pass the config so the synth that bootstrap performs uses this customer's
#    config rather than the default config/self.yaml.
if [[ -n "$DO_BOOTSTRAP" ]]; then
  echo "== [1/5] cdk bootstrap aws://$ACCT/$REGION =="
  ( cd "$ROOT/infra" && npx cdk bootstrap "aws://$ACCT/$REGION" -c "config=$CONFIG" )
fi

# 2) Deploy 4 infra stacks (excluding web — web needs the Api/Auth outputs)
echo "== [2/5] Deploy infra: Data / Auth / Engine / Api =="
( cd "$ROOT/infra" && npx cdk deploy \
    "${PREFIX}-Data" "${PREFIX}-Auth" "${PREFIX}-Engine" "${PREFIX}-Api" \
    -c "config=$CONFIG" --require-approval never )

# 3) Build web (inject the deployed Api/Auth outputs as VITE_*)
echo "== [3/5] Build web (wire real API) =="
bash "$ROOT/infra/scripts/build-web.sh" "$PREFIX"

# 4) Deploy web stack
echo "== [4/5] Deploy web =="
( cd "$ROOT/infra" && npx cdk deploy "${PREFIX}-Web" -c "config=$CONFIG" --require-approval never )

# Completion summary — print key outputs
echo ""
SITE="$(aws cloudformation describe-stacks --stack-name "${PREFIX}-Web" --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='SiteUrl'].OutputValue | [0]" --output text 2>/dev/null || true)"
API="$(aws cloudformation describe-stacks  --stack-name "${PREFIX}-Api" --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue | [0]" --output text 2>/dev/null || true)"
POOL="$(aws cloudformation describe-stacks --stack-name "${PREFIX}-Auth" --region "$REGION" --query "Stacks[0].Outputs[?OutputKey=='UserPoolId'].OutputValue | [0]" --output text 2>/dev/null || true)"

# 5) Lock CORS origin (two-phase deploy) — now that the CloudFront domain is known, redeploy Data/Api with the
#    WebOrigin parameter. API GW preflight, the S3 bucket CORS, and the backend CORSMiddleware
#    (LP2PS_WEB_ORIGIN env) all receive the real origin from this parameter (no wildcard). If unset, CORS is closed.
if [[ -n "$SITE" && "$SITE" != "None" ]]; then
  ORIGIN="${SITE%/}"  # strip trailing slash -> https://xxxx.cloudfront.net
  echo "== [5/5] Lock CORS origin (redeploy): WebOrigin=$ORIGIN =="
  ( cd "$ROOT/infra" && npx cdk deploy "${PREFIX}-Data" "${PREFIX}-Api" \
      -c "config=$CONFIG" --require-approval never \
      --parameters "${PREFIX}-Data:WebOrigin=$ORIGIN" \
      --parameters "${PREFIX}-Api:WebOrigin=$ORIGIN" ) \
    && echo "   ✓ CORS origin locked" \
    || echo "   ⚠ CORS redeploy failed — manually redeploy the Data/Api stacks with WebOrigin=$ORIGIN."

  # Force an API GW stage snapshot refresh — changing only the CfnParameter (WebOrigin) does not create a new
  # Deployment, so the OPTIONS preflight integration response (CORS origin) may not reach the prod stage. Redeploy explicitly.
  API_ID="$(aws cloudformation describe-stack-resources --stack-name "${PREFIX}-Api" --region "$REGION" \
    --query "StackResources[?ResourceType=='AWS::ApiGateway::RestApi'].PhysicalResourceId | [0]" --output text 2>/dev/null || true)"
  if [[ -n "$API_ID" && "$API_ID" != "None" ]]; then
    aws apigateway create-deployment --rest-api-id "$API_ID" --stage-name prod --region "$REGION" \
      --description "publish CORS origin" >/dev/null 2>&1 \
      && echo "   ✓ API GW prod stage CORS applied" \
      || echo "   ⚠ API GW stage redeploy failed — manual: aws apigateway create-deployment --rest-api-id $API_ID --stage-name prod"
  fi
fi

echo ""
echo "✅ DEPLOY-ALL complete ($PREFIX)"
echo "   Web dashboard : $SITE"
echo "   API           : $API"
echo "   Cognito pool  : $POOL  (create a web login user in the Cognito console)"
echo "   Next: open the web app -> sign in -> \"Run full scan\" (first run)"
