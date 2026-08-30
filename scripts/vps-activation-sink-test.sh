#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/vps-activation-sink-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

for command in up start restart build pull create run exec cp down stop kill rm; do
  if COMPOSE_ENV_FILE="$TMP/missing.env" bash "$SCRIPT_DIR/compose-vps.sh" "$command" >"$TMP/out" 2>"$TMP/err"; then
    echo "FAIL: read-only Compose wrapper accepted mutation command $command" >&2
    exit 1
  fi
  grep -F -- "Compose mutation command '$command' is disabled" "$TMP/err" >/dev/null
done
printf 'PASS\tcompose-wrapper-is-read-only\n'

if node "$SCRIPT_DIR/infra-ops.mjs" rollback-release --confirmRollback >"$TMP/out" 2>"$TMP/err"; then
  echo "FAIL: legacy rollback apply sink accepted --confirmRollback" >&2
  exit 1
fi
grep -F -- '--confirmRollback is disabled' "$TMP/err" >/dev/null
printf 'PASS\tlegacy-rollback-apply-is-deny-all\n'

grep -F -- '--verify --ssh-port "$EXPECTED_SSH_PORT"' "$SCRIPT_DIR/vps-host-readiness.sh" >/dev/null
if grep -F -- '--status-file' "$SCRIPT_DIR/vps-host-readiness.sh" >/dev/null; then
  echo "FAIL: host readiness injects a caller-authored UFW status file" >&2
  exit 1
fi
printf 'PASS\thost-readiness-binds-origin-check-to-ssh-port\n'

if grep -F -- '--start-stack' "$ROOT_DIR/README.md" "$ROOT_DIR/RUNBOOK.md" | grep -v -E 'rifiutato|rejected' >/dev/null; then
  echo "FAIL: production docs still recommend the disabled activation sink" >&2
  exit 1
fi
if grep -E 'compose-vps\.sh[[:space:]]+(up|start|restart|build|pull|create|run|exec|down)|rollback-release\.sh.*--confirmRollback|enterprise_prod[[:space:]]+(up|start|restart|build|pull)' \
  "$ROOT_DIR/README.md" "$ROOT_DIR/RUNBOOK.md" "$ROOT_DIR/CURRENT-OPERATING-MODEL.md" \
  "$ROOT_DIR/INFRASTRUCTURE-DEEP-DIVE.md" "$ROOT_DIR/RUNTIME-ISOLATION.md" >/dev/null; then
  echo "FAIL: production documentation contains an alternate mutation sink" >&2
  exit 1
fi
if grep -F -- '--ports "80"' "$ROOT_DIR/VPS-PREDEPLOY-CHECKLIST.md" >/dev/null; then
  echo "FAIL: VPS checklist still uses the test-only origin-lock port override" >&2
  exit 1
fi
grep -F -- 'Fresh-host bootstrap only' "$ROOT_DIR/VPS-PREDEPLOY-CHECKLIST.md" >/dev/null
grep -F -- 'config/v1-local-private-source-lock.json' "$ROOT_DIR/README.md" "$ROOT_DIR/RUNBOOK.md" "$ROOT_DIR/VPS-PREDEPLOY-CHECKLIST.md" >/dev/null
printf 'PASS\tproduction-docs-keep-current-operator-boundary\n'
printf 'VPS activation boundary tests passed 4/4\n'
