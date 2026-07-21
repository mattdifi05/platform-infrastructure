#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/deploy-vps-input-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

cat > "$TMP/ssh" <<'SH'
#!/usr/bin/env sh
set -eu
printf '%s\n' "$@" > "$FAKE_SSH_ARGS"
cat > "$FAKE_SSH_STDIN"
SH
chmod 700 "$TMP/ssh"

expect_reject() {
  label=$1
  shift
  if env PATH="$TMP:$PATH" "$@" sh "$SCRIPT_DIR/deploy-vps.sh" >/dev/null 2>&1; then
    echo "FAIL: $label was accepted" >&2
    exit 1
  fi
  printf 'PASS\t%s\n' "$label"
}

expect_reject deploy-user-option env DEPLOY_REMOTE='-oProxyCommand=id'
expect_reject deploy-remote-multiple-at env DEPLOY_REMOTE='deploy@example@internal'
expect_reject remote-dir-metachar env DEPLOY_REMOTE='deploy@example.internal' DEPLOY_REMOTE_DIR='/opt/platform;id'
expect_reject branch-substitution env DEPLOY_REMOTE='deploy@example.internal' DEPLOY_BRANCH='main$(id)'
expect_reject env-traversal env DEPLOY_REMOTE='deploy@example.internal' DEPLOY_ENV_FILE='../secret'
expect_reject project-metachar env DEPLOY_REMOTE='deploy@example.internal' DEPLOY_PROJECT_NAME='prod;id'
expect_reject boolean-metachar env DEPLOY_REMOTE='deploy@example.internal' DEPLOY_RUN_WAF_SMOKE='1;id'
expect_reject repo-metachar env DEPLOY_REMOTE='deploy@example.internal' DEPLOY_REPO='owner/repo;id'

export FAKE_SSH_ARGS="$TMP/ssh-args.txt"
export FAKE_SSH_STDIN="$TMP/ssh-stdin.sh"
printf '%s\n' 'example.internal ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnlyPinnedHostKey' > "$TMP/known_hosts"
PATH="$TMP:$PATH" \
DEPLOY_REMOTE='deploy@example.internal' \
DEPLOY_REMOTE_DIR='/opt/platform-infrastructure' \
DEPLOY_KNOWN_HOSTS_PATH="$TMP/known_hosts" \
DEPLOY_BRANCH='main' \
DEPLOY_ENV_FILE='.env' \
DEPLOY_PROJECT_NAME='platform_infra_vps' \
  sh "$SCRIPT_DIR/deploy-vps.sh"

grep -Fx 'deploy@example.internal' "$FAKE_SSH_ARGS" >/dev/null
grep -Fx 'sh -s' "$FAKE_SSH_ARGS" >/dev/null
grep -Fx 'StrictHostKeyChecking=yes' "$FAKE_SSH_ARGS" >/dev/null
grep -Fx "UserKnownHostsFile=$TMP/known_hosts" "$FAKE_SSH_ARGS" >/dev/null
grep -Fx 'GlobalKnownHostsFile=/dev/null' "$FAKE_SSH_ARGS" >/dev/null
if grep -F 'accept-new' "$FAKE_SSH_ARGS" >/dev/null; then
  echo "FAIL: accept-new remained enabled" >&2
  exit 1
fi
if grep -F '/opt/platform-infrastructure' "$FAKE_SSH_STDIN" >/dev/null; then
  echo "FAIL: raw remote directory leaked into generated shell" >&2
  exit 1
fi
grep -E "^PLATFORM_REMOTE_DIR_B64='[A-Za-z0-9+/=]+'$" "$FAKE_SSH_STDIN" >/dev/null
printf 'PASS\tfixed-command-and-encoded-request\n'
grep -F 'git checkout "$branch"' "$SCRIPT_DIR/deploy-vps-remote.sh" >/dev/null
if grep -F 'git checkout -- "$branch"' "$SCRIPT_DIR/deploy-vps-remote.sh" >/dev/null; then
  echo "FAIL: deploy branch is interpreted as a pathspec" >&2
  exit 1
fi
printf 'PASS\tvalidated-branch-checkout\n'
printf 'deploy VPS input tests passed 14/14\n'
