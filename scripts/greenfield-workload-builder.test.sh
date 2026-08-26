#!/bin/sh
# Sandbox test for scripts/greenfield-workload-builder.sh.
# Runs on macOS WITHOUT docker; live image builds are exercised on CI runners.
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILDER_SRC="$ROOT_DIR/scripts/greenfield-workload-builder.sh"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/greenfield-workload-builder-test.XXXXXX")

cleanup() {
  rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

pass() {
  printf 'PASS: %s\n' "$1"
}

[ -f "$BUILDER_SRC" ] || fail "missing builder script: $BUILDER_SRC"

BUILDER="$TMP/greenfield-workload-builder.sh"
cp "$BUILDER_SRC" "$BUILDER"
chmod +x "$BUILDER"
GREENFIELD_WORKLOAD_BUILDER_ROOT="$ROOT_DIR"
export GREENFIELD_WORKLOAD_BUILDER_ROOT

# --- plan -------------------------------------------------------------------
plan_out=$("$BUILDER" plan) || fail "plan exited nonzero"
plan_count=$(printf '%s\n' "$plan_out" | grep -o '"dockerfile"' | wc -l | tr -d ' ')
[ "$plan_count" = "8" ] || fail "plan: expected 8 dockerfiles, got $plan_count"
bad_paths=$(printf '%s\n' "$plan_out" | grep -o '"dockerfile": "[^"]*"' | grep -v '"dockerfile": "docker/' || true)
[ -z "$bad_paths" ] || fail "plan: non docker/ path present: $bad_paths"
pass "plan lists exactly 8 dockerfiles under docker/"

# --- build-context (requires clean repo; CI runs clean) ----------------------
if [ -n "$(git -C "$ROOT_DIR" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)" ]; then
  printf 'SKIP: %s worktree is dirty; greenfield builder tests require a clean checkout (CI runs clean)\n' "$ROOT_DIR"
  exit 0
fi

CTX="$TMP/ctx"
"$BUILDER" build-context HEAD "$CTX" || fail "build-context HEAD failed"
[ -f "$CTX/compose.yaml" ] || fail "build-context: compose.yaml missing from extracted archive"

head_bytes=$(git -C "$ROOT_DIR" archive HEAD compose.yaml | tar -xO | shasum | awk '{print $1}')
extracted_bytes=$(shasum "$CTX/compose.yaml" | awk '{print $1}')
[ "$head_bytes" = "$extracted_bytes" ] || fail "build-context: extracted bytes differ from git archive HEAD bytes"
pass "build-context extracted exact HEAD bytes (compose.yaml hashes match)"

# --- audit-context positive ---------------------------------------------------
if "$BUILDER" audit-context "$CTX" >"$TMP/audit-positive.out" 2>&1; then
  pass "audit-context accepts pristine exact-main context"
else
  rc=$?
  cat "$TMP/audit-positive.out" >&2
  fail "audit-context rejected pristine context (exit $rc)"
fi

# --- audit-context negative injections ----------------------------------------
expect_reject() {
  dir=$1
  needle=$2
  label=$3
  rc=0
  "$BUILDER" audit-context "$dir" >"$TMP/negative.out" 2>&1 || rc=$?
  [ "$rc" = "4" ] || { cat "$TMP/negative.out" >&2; fail "$label: expected exit 4, got $rc"; }
  grep -q "$needle" "$TMP/negative.out" || { cat "$TMP/negative.out" >&2; fail "$label: output missing '$needle'"; }
  pass "audit-context rejects $label"
}

cp -R "$CTX" "$TMP/case-secrets"
mkdir -p "$TMP/case-secrets/secrets"
printf 'evil\n' > "$TMP/case-secrets/secrets/evil.txt"
expect_reject "$TMP/case-secrets" 'secrets/' 'secrets/evil.txt injection'

cp -R "$CTX" "$TMP/case-env"
printf 'INJECTED_SECRET=1\n' > "$TMP/case-env/.env"
expect_reject "$TMP/case-env" '.env' '.env file injection'

cp -R "$CTX" "$TMP/case-symlink"
mkdir -p "$TMP/case-symlink/usr"
ln -s /etc/passwd "$TMP/case-symlink/usr/link"
expect_reject "$TMP/case-symlink" 'symlink' 'symlink entry'

cp -R "$CTX" "$TMP/case-fifo"
mkfifo "$TMP/case-fifo/pipe.fifo"
expect_reject "$TMP/case-fifo" 'fifo' 'fifo entry'

cp -R "$CTX" "$TMP/case-pem"
mkdir -p "$TMP/case-pem/traefik/certs"
printf 'not-a-real-key\n' > "$TMP/case-pem/traefik/certs/fake-key.pem"
expect_reject "$TMP/case-pem" '.pem' 'traefik/certs pem'

# --- build-image without docker ------------------------------------------------
if command -v docker >/dev/null 2>&1; then
  printf 'SKIP: docker is available locally; real builds are exercised on the CI runner\n'
else
  rc=0
  "$BUILDER" build-image "$CTX" "$ROOT_DIR/docker/php-apache.Dockerfile" "platform/greenfield-php-apache:local" >"$TMP/build-image.out" 2>&1 || rc=$?
  [ "$rc" = "78" ] || { cat "$TMP/build-image.out" >&2; fail "build-image without docker: expected exit 78, got $rc"; }
  grep -q "docker unavailable: image build must run on the CI runner" "$TMP/build-image.out" || \
    { cat "$TMP/build-image.out" >&2; fail "build-image without docker: missing fail-closed message"; }
  pass "build-image fails closed with exit 78 when docker is unavailable"
fi

printf 'PASS: greenfield workload builder tests passed\n'
