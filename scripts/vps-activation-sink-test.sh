#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/vps-activation-sink-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

set +e
sh "$SCRIPT_DIR/vps-go-live.sh" --confirmLive --start-stack >"$TMP/out" 2>"$TMP/err"
status=$?
set -e
[ "$status" -eq 78 ] || {
  echo "FAIL: existing-host --confirmLive did not stop with exit 78 (got $status)" >&2
  exit 1
}
grep -F -- 'V1 brownfield existing-host path is STOP' "$TMP/err" >/dev/null
printf 'PASS\tv1-brownfield-confirm-live-is-terminal-stop\n'

go_live_root="$TMP/go-live-root"
fake_bin="$TMP/fake-bin"
mutation_sentinel="$TMP/live-mutation-called"
mkdir -p "$go_live_root/scripts" "$fake_bin"
cp "$SCRIPT_DIR/vps-go-live.sh" "$go_live_root/scripts/vps-go-live.sh"
: > "$TMP/test.env"
printf '%s\n' '#!/bin/sh' ': > "$VPS_MUTATION_SENTINEL"' 'exit 97' > "$fake_bin/sudo"
chmod 700 "$fake_bin/sudo"

set +e
VPS_MUTATION_SENTINEL="$mutation_sentinel" \
V1_BACKUP_GATE=SATISFIED \
V1_PROVIDER_GATES=SATISFIED \
V1_DEPLOYMENT_ADMISSION=AUTHORIZED \
CONFIRM_MUTATING_VPS=true \
PATH="$fake_bin:/usr/bin:/bin" \
  sh "$go_live_root/scripts/vps-go-live.sh" \
    --confirmLive --env-file "$TMP/test.env" --bootstrap --apply-hardening \
    >"$TMP/out" 2>"$TMP/err"
status=$?
set -e
[ "$status" -eq 78 ] || {
  echo "FAIL: caller flags or local NONAUTHORITATIVE state bypassed V1 STOP (got $status)" >&2
  exit 1
}
[ ! -e "$mutation_sentinel" ] || {
  echo "FAIL: existing-host path reached sudo before V1 backup/provider admission" >&2
  exit 1
}
grep -F -- 'V1 brownfield existing-host path is STOP' "$TMP/err" >/dev/null
printf 'PASS\tcaller-state-cannot-bypass-v1-stop\n'

VPS_MUTATION_SENTINEL="$mutation_sentinel" PATH="$fake_bin:/usr/bin:/bin" \
  sh "$go_live_root/scripts/vps-go-live.sh" \
    --planOnly --env-file "$TMP/test.env" --bootstrap --apply-hardening --no-bundle \
    >"$TMP/out" 2>"$TMP/err"
[ ! -e "$mutation_sentinel" ]
grep -F -- 'Plan only. V1 existing-host live execution remains STOP.' "$TMP/out" >/dev/null
printf 'PASS\tplan-only-remains-non-authoritative\n'

if grep -Eq 'compose-vps\.sh[[:space:]]+up|up -d --build' "$SCRIPT_DIR/vps-go-live.sh"; then
  echo "FAIL: legacy VPS orchestrator still contains a direct Compose activation" >&2
  exit 1
fi
printf 'PASS\tlegacy-orchestrator-has-no-compose-sink\n'

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
grep -F -- 'Existing/brownfield V1: terminal STOP' "$ROOT_DIR/VPS-PREDEPLOY-CHECKLIST.md" >/dev/null
grep -F -- 'EXTERNAL-PENDING' "$ROOT_DIR/VPS-PREDEPLOY-CHECKLIST.md" >/dev/null
for document in "$ROOT_DIR/README.md" "$ROOT_DIR/RUNBOOK.md"; do
  grep -F -- 'V1 brownfield: unconditional STOP 78' "$document" >/dev/null
  grep -F -- 'plan/read-only/local tests remain available' "$document" >/dev/null
  if grep -F -- 'vps-go-live.sh --confirmLive --repo' "$document" >/dev/null; then
    echo "FAIL: $document still presents the V1 existing-host live mode as runnable" >&2
    exit 1
  fi
done
printf 'PASS\tproduction-docs-separate-fresh-from-existing-host\n'
printf 'VPS activation sink tests passed 8/8\n'
