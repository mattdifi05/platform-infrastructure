#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/vps-activation-sink-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

if sh "$SCRIPT_DIR/vps-go-live.sh" --confirmLive --start-stack >"$TMP/out" 2>"$TMP/err"; then
  echo "FAIL: legacy VPS activation sink accepted --start-stack" >&2
  exit 1
fi
grep -F -- '--start-stack is disabled' "$TMP/err" >/dev/null
printf 'PASS\tlegacy-start-stack-is-deny-all\n'

if grep -Eq 'compose-vps\.sh[[:space:]]+up|up -d --build' "$SCRIPT_DIR/vps-go-live.sh"; then
  echo "FAIL: legacy VPS orchestrator still contains a direct Compose activation" >&2
  exit 1
fi
printf 'PASS\tlegacy-orchestrator-has-no-compose-sink\n'

grep -F -- '--verify --status-file "$origin_status" --ssh-port "$EXPECTED_SSH_PORT"' \
  "$SCRIPT_DIR/vps-host-readiness.sh" >/dev/null
printf 'PASS\thost-readiness-binds-origin-check-to-ssh-port\n'

if grep -F -- '--start-stack' "$ROOT_DIR/README.md" "$ROOT_DIR/RUNBOOK.md" | grep -v -E 'rifiutato|rejected' >/dev/null; then
  echo "FAIL: production docs still recommend the disabled activation sink" >&2
  exit 1
fi
if grep -F -- '--ports "80"' "$ROOT_DIR/VPS-PREDEPLOY-CHECKLIST.md" >/dev/null; then
  echo "FAIL: VPS checklist still uses the test-only origin-lock port override" >&2
  exit 1
fi
printf 'PASS\tproduction-docs-route-to-trusted-deploy\n'
printf 'VPS activation sink tests passed 4/4\n'
