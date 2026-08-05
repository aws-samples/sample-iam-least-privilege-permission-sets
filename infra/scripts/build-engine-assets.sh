#!/usr/bin/env bash
# Build engine Lambda assets (without Docker) — stage Linux wheels locally via pip --platform.
#
# Outputs:
#   infra/assets/engine-layer/python/   -> Lambda Layer (deps: pyarrow, pydantic, jinja2, pyyaml)
#   infra/assets/engine-code/           -> function code (lp2ps package only, excluding boto3/deps)
#
# boto3/botocore are built into the Lambda runtime -> excluded from the layer (size reduction).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ASSETS="$ROOT/infra/assets"
LAYER_PY="$ASSETS/engine-layer/python"
CODE="$ASSETS/engine-code"
PY_VER="3.12"

rm -rf "$ASSETS"
mkdir -p "$LAYER_PY" "$CODE"

echo "== 1) Dependency layer (Linux wheels) =="
python3 -m pip install \
  --platform manylinux2014_x86_64 \
  --python-version "$PY_VER" \
  --only-binary=:all: \
  --target "$LAYER_PY" \
  "pyarrow>=15" pydantic pyyaml jinja2 --quiet

echo "== 2) Size reduction (remove tests / unnecessary files) =="
find "$LAYER_PY" -type d -name "tests" -prune -exec rm -rf {} + 2>/dev/null || true
find "$LAYER_PY" -type d -name "__pycache__" -prune -exec rm -rf {} + 2>/dev/null || true
find "$LAYER_PY" -name "*.pyc" -delete 2>/dev/null || true
# pyarrow native .so files are chain-loaded by __init__, so do not delete them individually (causes ImportError).
# Only remove cpp test binaries safely (not imported at runtime).
find "$LAYER_PY/pyarrow" -name "*_cpp_tests*" -delete 2>/dev/null || true
find "$LAYER_PY/pyarrow" -name "*.pxd" -delete 2>/dev/null || true
find "$LAYER_PY/pyarrow" -name "*.pxi" -delete 2>/dev/null || true
find "$LAYER_PY/pyarrow/include" -type d -prune -exec rm -rf {} + 2>/dev/null || true

echo "== 3) Engine code (lp2ps package) =="
cp -R "$ROOT/engine/lp2ps" "$CODE/lp2ps"
find "$CODE" -type d -name "__pycache__" -prune -exec rm -rf {} + 2>/dev/null || true

# ---- API (backend) assets ----
API_LAYER_PY="$ASSETS/api-layer/python"
API_CODE="$ASSETS/api-code"
mkdir -p "$API_LAYER_PY" "$API_CODE"

echo "== 4) API dependency layer (FastAPI, Mangum, pydantic; Linux wheels) =="
python3 -m pip install \
  --platform manylinux2014_x86_64 \
  --python-version "$PY_VER" \
  --only-binary=:all: \
  --target "$API_LAYER_PY" \
  fastapi mangum pydantic --quiet
find "$API_LAYER_PY" -type d -name "__pycache__" -prune -exec rm -rf {} + 2>/dev/null || true
find "$API_LAYER_PY" -name "*.pyc" -delete 2>/dev/null || true

echo "== 5) API code (lp2ps_api + reuse lp2ps engine contracts) =="
cp -R "$ROOT/backend/lp2ps_api" "$API_CODE/lp2ps_api"
# The API imports lp2ps.models and storage -> bundle the engine package too (reuse the contract SoT).
cp -R "$ROOT/engine/lp2ps" "$API_CODE/lp2ps"
find "$API_CODE" -type d -name "__pycache__" -prune -exec rm -rf {} + 2>/dev/null || true

echo "== Sizes =="
du -sh "$ASSETS/engine-layer" "$CODE" "$ASSETS/api-layer" "$API_CODE"
echo "Asset build complete: $ASSETS"
