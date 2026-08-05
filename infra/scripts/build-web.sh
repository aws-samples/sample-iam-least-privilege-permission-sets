#!/usr/bin/env bash
# Build the frontend with the **real API/Cognito env** -> frontend/dist.
# Reads values from the already-deployed api/auth stack outputs and injects them as VITE_*.
# Must run before deploying the web stack so that dist is wired to the real backend.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REGION="${AWS_REGION:-us-west-2}"
PREFIX="${1:-Lp2ps-self}"  # customer prefix

echo "== Query deployed stack outputs =="
API_URL=$(aws cloudformation describe-stacks --stack-name "${PREFIX}-Api" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue | [0]" --output text)
POOL_ID=$(aws cognito-idp list-user-pools --max-results 20 --region "$REGION" \
  --query "UserPools[?starts_with(Name,'UserPool')].Id | [0]" --output text)
CLIENT_ID=$(aws cognito-idp list-user-pool-clients --user-pool-id "$POOL_ID" --region "$REGION" \
  --query 'UserPoolClients[0].ClientId' --output text)

# API_URL has a trailing slash -> strip it (client.ts appends /runs).
API_BASE="${API_URL%/}"

echo "  API_BASE=$API_BASE"
echo "  POOL_ID=$POOL_ID  CLIENT_ID=$CLIENT_ID"

echo "== Build frontend with real env =="
cd "$ROOT/frontend"
VITE_USE_MOCKS=false \
VITE_API_BASE="$API_BASE" \
VITE_COGNITO_USER_POOL_ID="$POOL_ID" \
VITE_COGNITO_CLIENT_ID="$CLIENT_ID" \
  npm run build

echo "frontend/dist build complete (real API wired): $ROOT/frontend/dist"
