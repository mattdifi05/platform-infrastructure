#!/usr/bin/env sh
set -eu

TARGET="${1:-${DAST_TARGET:-https://api.localhost.com}}"
OUT_DIR="${DAST_OUTPUT_DIR:-security/dast}"
IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"

mkdir -p "$OUT_DIR"

docker run --rm \
  -v "$(pwd)/$OUT_DIR:/zap/wrk:rw" \
  "$IMAGE" \
  zap-baseline.py \
  -t "$TARGET" \
  -r zap-baseline.html \
  -J zap-baseline.json \
  -x zap-baseline.xml \
  -I

echo "ZAP baseline completed for $TARGET. Reports written to $OUT_DIR."
