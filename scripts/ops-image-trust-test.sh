#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/ops-image-trust.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
IMAGE="ghcr.io/owner/platform-ops@sha256:$(printf 'a%.0s' $(seq 1 64))"
IMAGE_ID="sha256:$(printf 'b%.0s' $(seq 1 64))"
RECEIPT="$TMP/receipt.json"

cat > "$TMP/docker" <<'SH'
#!/usr/bin/env sh
set -eu
[ "$1 $2" = "image inspect" ]
printf '[{"Id":"%s","RepoDigests":["%s"]}]\n' "$FAKE_IMAGE_ID" "$FAKE_REPO_DIGEST"
SH
chmod 700 "$TMP/docker"

write_receipt() {
  cat > "$RECEIPT" <<EOF
{"kind":"platform-release-artifact-admission/v1","status":"passed","repository":"owner/repo","commitSha":"$(printf 'c%.0s' $(seq 1 40))","subjects":[{"key":"PLATFORM_OPS_IMAGE","image":"$1"}],"provenance":{"verificationFingerprint":"$(printf 'd%.0s' $(seq 1 64))"}}
EOF
}
receipt_sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$RECEIPT" | awk '{print $1}'; else shasum -a 256 "$RECEIPT" | awk '{print $1}'; fi
}
expect_reject() {
  label=$1
  shift
  if "$@" >/dev/null 2>&1; then echo "FAIL: $label was accepted" >&2; exit 1; fi
  printf 'PASS\t%s\n' "$label"
}

write_receipt "$IMAGE"
SHA=$(receipt_sha)
result=$(PATH="$TMP:$PATH" FAKE_IMAGE_ID="$IMAGE_ID" FAKE_REPO_DIGEST="$IMAGE" sh "$SCRIPT_DIR/ops-image-trust.sh" "$IMAGE" "$RECEIPT" "$SHA")
[ "$result" = "$IMAGE_ID" ]
printf 'PASS\texact-receipt-and-local-repodigest\n'

expect_reject receipt-hash-mismatch env PATH="$TMP:$PATH" FAKE_IMAGE_ID="$IMAGE_ID" FAKE_REPO_DIGEST="$IMAGE" sh "$SCRIPT_DIR/ops-image-trust.sh" "$IMAGE" "$RECEIPT" "$(printf 'e%.0s' $(seq 1 64))"
write_receipt "ghcr.io/owner/other@sha256:$(printf 'a%.0s' $(seq 1 64))"
SHA=$(receipt_sha)
expect_reject wrong-receipt-subject env PATH="$TMP:$PATH" FAKE_IMAGE_ID="$IMAGE_ID" FAKE_REPO_DIGEST="$IMAGE" sh "$SCRIPT_DIR/ops-image-trust.sh" "$IMAGE" "$RECEIPT" "$SHA"
write_receipt "$IMAGE"
SHA=$(receipt_sha)
expect_reject wrong-local-repodigest env PATH="$TMP:$PATH" FAKE_IMAGE_ID="$IMAGE_ID" FAKE_REPO_DIGEST="ghcr.io/owner/other@sha256:$(printf 'a%.0s' $(seq 1 64))" sh "$SCRIPT_DIR/ops-image-trust.sh" "$IMAGE" "$RECEIPT" "$SHA"
expect_reject mutable-image env PATH="$TMP:$PATH" FAKE_IMAGE_ID="$IMAGE_ID" FAKE_REPO_DIGEST="$IMAGE" sh "$SCRIPT_DIR/ops-image-trust.sh" "ghcr.io/owner/platform-ops:latest" "$RECEIPT" "$SHA"

run_lines=$(grep -c 'docker run --rm --pull=never' "$SCRIPT_DIR/prepare-hosted-workloads.sh")
[ "$run_lines" -eq 2 ]
if grep -q 'platform/ops:local' "$SCRIPT_DIR/prepare-hosted-workloads.sh"; then echo "FAIL: local ops fallback remains" >&2; exit 1; fi
printf 'PASS\tboth-runs-use-captured-image-id-and-pull-never\n'
printf 'ops image trust tests passed 6/6\n'
