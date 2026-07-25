#!/usr/bin/env sh
set -eu
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
POLICY="$ROOT/governance/deployment-admission.json"

ARTIFACT_RECEIPT=${DEPLOY_ARTIFACT_RECEIPT_PATH:-}
ARTIFACT_SHA256=${DEPLOY_ARTIFACT_RECEIPT_SHA256:-}
ADMISSION_RECEIPT=${DEPLOY_ADMISSION_RECEIPT_PATH:-}
ADMISSION_SHA256=${DEPLOY_ADMISSION_RECEIPT_SHA256:-}
PROVIDER_METADATA=${DEPLOY_TRUSTED_PROVIDER_METADATA_PATH:-}
PROVIDER_METADATA_SHA256=${DEPLOY_TRUSTED_PROVIDER_METADATA_SHA256:-}
PROVIDER_RUN_ID=${DEPLOY_TRUSTED_PROVIDER_RUN_ID:-}
PROVIDER_RUN_ATTEMPT=${DEPLOY_TRUSTED_PROVIDER_RUN_ATTEMPT:-}
REPOSITORY=${DEPLOY_REPO:-}
COMMIT_SHA=${DEPLOY_RELEASE_SHA:-}
TREE_SHA=${DEPLOY_RELEASE_TREE:-}

case "$COMMIT_SHA:$TREE_SHA" in
  *[!a-f0-9:]*|::*|:*|*:) echo "EXTERNAL-PENDING: exact release commit and tree SHA values are required." >&2; exit 78 ;;
esac
[ "${#COMMIT_SHA}" -eq 40 ] && [ "${#TREE_SHA}" -eq 40 ] || {
  echo "EXTERNAL-PENDING: release commit and tree SHA values must be complete." >&2
  exit 78
}
actual_commit=$(git -C "$ROOT" rev-parse HEAD)
actual_tree=$(git -C "$ROOT" rev-parse "${COMMIT_SHA}^{tree}")
[ "$actual_commit" = "$COMMIT_SHA" ] && [ "$actual_tree" = "$TREE_SHA" ] || {
  echo "Ops admission does not match the exact local checkout commit/tree." >&2
  exit 1
}
[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ] || {
  echo "Ops admission requires a clean local checkout." >&2
  exit 1
}

case "$ARTIFACT_SHA256:$ADMISSION_SHA256:$PROVIDER_METADATA_SHA256" in
  *[!a-f0-9:]*|::*|:*|*:) echo "EXTERNAL-PENDING: exact trusted receipt and provider metadata SHA256 values are required." >&2; exit 78 ;;
esac
[ "${#ARTIFACT_SHA256}" -eq 64 ] && [ "${#ADMISSION_SHA256}" -eq 64 ] && [ "${#PROVIDER_METADATA_SHA256}" -eq 64 ] || {
  echo "EXTERNAL-PENDING: trusted receipt and provider metadata hashes must be complete." >&2
  exit 78
}
for file in "$POLICY" "$ARTIFACT_RECEIPT" "$ADMISSION_RECEIPT" "$PROVIDER_METADATA"; do
  [ -f "$file" ] && [ -r "$file" ] && [ -s "$file" ] && [ ! -L "$file" ] || {
    echo "EXTERNAL-PENDING: a trusted ops admission input is missing, unreadable, empty, or a symlink." >&2
    exit 78
  }
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/platform-ops-admission.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
stable_policy="$temporary/policy.json"
stable_artifact="$temporary/artifact.json"
stable_admission="$temporary/admission.json"
stable_metadata="$temporary/provider-run.json"
cp "$POLICY" "$stable_policy"
cp "$ARTIFACT_RECEIPT" "$stable_artifact"
cp "$ADMISSION_RECEIPT" "$stable_admission"
cp "$PROVIDER_METADATA" "$stable_metadata"
chmod 600 "$stable_policy" "$stable_artifact" "$stable_admission" "$stable_metadata"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
[ "$(hash_file "$stable_artifact")" = "$ARTIFACT_SHA256" ] || { echo "Ops artifact receipt SHA256 mismatch." >&2; exit 1; }
[ "$(hash_file "$stable_admission")" = "$ADMISSION_SHA256" ] || { echo "Ops admission receipt SHA256 mismatch." >&2; exit 1; }
[ "$(hash_file "$stable_metadata")" = "$PROVIDER_METADATA_SHA256" ] || { echo "Ops provider metadata SHA256 mismatch." >&2; exit 1; }

node "$SCRIPT_DIR/trusted-provider-run-policy.mjs" \
  --policy "$stable_policy" \
  --metadata "$stable_metadata" \
  --metadataSha256 "$PROVIDER_METADATA_SHA256" \
  --deploymentReceipt "$stable_admission" \
  --runId "$PROVIDER_RUN_ID" \
  --runAttempt "$PROVIDER_RUN_ATTEMPT" >/dev/null
node "$SCRIPT_DIR/deployment-receipt-policy.mjs" \
  --policy "$stable_policy" \
  --artifactReceipt "$stable_artifact" \
  --artifactReceiptSha256 "$ARTIFACT_SHA256" \
  --deploymentReceipt "$stable_admission" \
  --deploymentReceiptSha256 "$ADMISSION_SHA256" \
  --repo "$REPOSITORY" \
  --commit "$COMMIT_SHA" \
  --tree "$TREE_SHA" \
  --providerRunId "$PROVIDER_RUN_ID" \
  --providerRunAttempt "$PROVIDER_RUN_ATTEMPT" >/dev/null

IMAGE=$(jq -er '.opsRunner.image' "$stable_admission")
IMAGE_ID=$(jq -er '.opsRunner.imageId' "$stable_admission")
command -v docker >/dev/null 2>&1 || {
  echo "Docker is required to inspect the already-present admitted ops image." >&2
  exit 127
}
inspect_json=$(docker image inspect "$IMAGE")
printf '%s' "$inspect_json" | jq -e --arg image "$IMAGE" --arg image_id "$IMAGE_ID" '
  length == 1 and
  .[0].Id == $image_id and
  (.[0].RepoDigests | type == "array" and index($image) != null)
' >/dev/null || {
  echo "Local ops image ID/RepoDigest differs from the trusted provider admission." >&2
  exit 1
}

printf '%s\n' "$(jq -cn --arg image "$IMAGE" --arg imageId "$IMAGE_ID" '{image:$image,imageId:$imageId}')"
