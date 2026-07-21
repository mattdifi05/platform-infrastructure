#!/usr/bin/env sh
set -eu

IMAGE=${1:-}
RECEIPT=${2:-}
EXPECTED_RECEIPT_SHA256=${3:-}

case "$IMAGE" in
  [a-z0-9]*/*@sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "PLATFORM_OPS_IMAGE must be an exact lowercase digest-pinned image reference." >&2; exit 1 ;;
esac
case "$IMAGE" in *[!a-z0-9._/@:-]*) echo "PLATFORM_OPS_IMAGE contains invalid or uppercase characters." >&2; exit 1 ;; esac
case "${IMAGE##*@sha256:}" in *[!a-f0-9]*|'') echo "PLATFORM_OPS_IMAGE has an invalid SHA256 digest." >&2; exit 1 ;; esac
case "$EXPECTED_RECEIPT_SHA256" in
  *[!a-f0-9]*|'') echo "PLATFORM_OPS_IMAGE_ADMISSION_RECEIPT_SHA256 must be a lowercase SHA256." >&2; exit 1 ;;
esac
[ "${#EXPECTED_RECEIPT_SHA256}" -eq 64 ] || { echo "PLATFORM_OPS_IMAGE_ADMISSION_RECEIPT_SHA256 must be complete." >&2; exit 1; }
[ -f "$RECEIPT" ] && [ -r "$RECEIPT" ] || { echo "Ops image admission receipt is missing or unreadable." >&2; exit 1; }

if command -v sha256sum >/dev/null 2>&1; then
  actual_receipt_sha256=$(sha256sum "$RECEIPT" | awk '{print $1}')
else
  actual_receipt_sha256=$(shasum -a 256 "$RECEIPT" | awk '{print $1}')
fi
[ "$actual_receipt_sha256" = "$EXPECTED_RECEIPT_SHA256" ] || { echo "Ops image admission receipt SHA256 mismatch." >&2; exit 1; }

jq -e --arg image "$IMAGE" '
  .kind == "platform-release-artifact-admission/v1" and
  .status == "passed" and
  (.repository | type == "string" and length > 0) and
  (.commitSha | type == "string" and test("^[a-f0-9]{40}$")) and
  (.provenance.verificationFingerprint | type == "string" and test("^[a-f0-9]{64}$")) and
  ([.subjects[]? | select(.key == "PLATFORM_OPS_IMAGE" and .image == $image)] | length == 1)
' "$RECEIPT" >/dev/null || { echo "Ops image admission receipt does not bind the exact PLATFORM_OPS_IMAGE." >&2; exit 1; }

inspect_json=$(docker image inspect "$IMAGE")
image_id=$(printf '%s' "$inspect_json" | jq -er --arg image "$IMAGE" '
  if length == 1 and
     (.[0].Id | type == "string" and test("^sha256:[a-f0-9]{64}$")) and
     (.[0].RepoDigests | type == "array" and index($image) != null)
  then .[0].Id else error("local image identity is not bound to the requested RepoDigest") end
') || { echo "Local ops image does not expose the exact admitted RepoDigest." >&2; exit 1; }

printf '%s\n' "$image_id"
