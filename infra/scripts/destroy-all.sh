#!/usr/bin/env bash
# One-click full teardown — delete the 5 stacks in reverse dependency order (Web→Api→Engine→Auth→Data).
# Removes only the LP2PS deployment in the tooling account. The member-account read-only role
# (cfn/lp2ps-readonly-role.yaml) must be deleted separately in each member account (out of scope for this
# script — it is a different account and not accessible from here).
#
# Usage:
#   infra/scripts/destroy-all.sh [config-file]
# Example:
#   infra/scripts/destroy-all.sh config/acme.yaml
#
# Warning: S3 buckets and DynamoDB tables use removalPolicy=DESTROY + autoDelete, so their data is deleted too.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG_ARG="${1:-config/self.yaml}"
case "$CONFIG_ARG" in
  /*) CONFIG="$CONFIG_ARG" ;;
  *)  CONFIG="$ROOT/$CONFIG_ARG" ;;
esac
[[ -f "$CONFIG" ]] || { echo "❌ config not found: $CONFIG"; exit 1; }

CUSTOMER="$(grep -E '^customer:' "$CONFIG" | head -1 | sed 's/customer:[[:space:]]*//; s/[[:space:]]*$//')"
REGION="$(grep -E '^region:'   "$CONFIG" | head -1 | sed 's/region:[[:space:]]*//;   s/[[:space:]]*$//')"
[[ -n "$CUSTOMER" && -n "$REGION" ]] || { echo "❌ failed to parse config"; exit 1; }
PREFIX="Lp2ps-${CUSTOMER}"
export AWS_REGION="$REGION"

ACCT="$(aws sts get-caller-identity --query Account --output text)" || { echo "❌ AWS sign-in required"; exit 1; }
echo "⚠  Delete target: prefix=$PREFIX  region=$REGION  account=$ACCT"
echo "   All 5 stacks (Web/Api/Engine/Auth/Data) and their S3/DynamoDB data will be deleted."

# Delete in reverse dependency order (Web references Api/Auth; Api references Engine/Data).
( cd "$ROOT/infra" && npx cdk destroy \
    "${PREFIX}-Web" "${PREFIX}-Api" "${PREFIX}-Engine" "${PREFIX}-Auth" "${PREFIX}-Data" \
    -c "config=$CONFIG" --force )

echo ""
echo "✅ DESTROY-ALL complete ($PREFIX)"
echo "   Delete the member-account read-only role separately by deleting the 'lp2ps-readonly' stack in each member account."
echo "   To also remove the bootstrap (CDKToolkit): aws cloudformation delete-stack --stack-name CDKToolkit --region $REGION"
