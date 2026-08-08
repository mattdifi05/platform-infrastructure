#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/release-compose-admission-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

CONTROL_IMAGE="ghcr.io/owner/platform-infrastructure-control-center@sha256:$(printf 'a%.0s' $(seq 1 64))"
ALERT_IMAGE="ghcr.io/owner/platform-infrastructure-alert-dispatcher@sha256:$(printf 'b%.0s' $(seq 1 64))"
ROUTER_IMAGE="ghcr.io/owner/platform-infrastructure-project-router@sha256:$(printf 'c%.0s' $(seq 1 64))"
SCHEDULER_IMAGE="ghcr.io/owner/platform-infrastructure-backup-scheduler@sha256:$(printf '7%.0s' $(seq 1 64))"
SCHEDULER_IMAGE_ID="sha256:$(printf '8%.0s' $(seq 1 64))"
OPS_IMAGE="ghcr.io/owner/platform-infrastructure-ops@sha256:$(printf 'd%.0s' $(seq 1 64))"
OPS_IMAGE_ID="sha256:$(printf 'e%.0s' $(seq 1 64))"

write_receipt() {
  cat > "$TMP/receipt.json" <<EOF
{"subjects":[{"key":"CONTROL_CENTER_IMAGE","image":"$CONTROL_IMAGE"},{"key":"PLATFORM_ALERT_DISPATCHER_IMAGE","image":"$ALERT_IMAGE"},{"key":"PLATFORM_BACKUP_SCHEDULER_IMAGE","image":"$SCHEDULER_IMAGE"},{"key":"PROJECT_ROUTER_IMAGE","image":"$ROUTER_IMAGE"}],"subjectVerificationReceipts":[{"key":"CONTROL_CENTER_IMAGE","image":"$CONTROL_IMAGE","registry":{"platforms":[{"platform":"linux/amd64","digest":"sha256:$(printf '9%.0s' $(seq 1 64))","imageId":"sha256:$(printf '1%.0s' $(seq 1 64))"}]}},{"key":"PLATFORM_ALERT_DISPATCHER_IMAGE","image":"$ALERT_IMAGE","registry":{"platforms":[{"platform":"linux/amd64","digest":"sha256:$(printf 'a%.0s' $(seq 1 64))","imageId":"sha256:$(printf '2%.0s' $(seq 1 64))"}]}},{"key":"PLATFORM_BACKUP_SCHEDULER_IMAGE","image":"$SCHEDULER_IMAGE","registry":{"platforms":[{"platform":"linux/amd64","digest":"sha256:$(printf 'b%.0s' $(seq 1 64))","imageId":"$SCHEDULER_IMAGE_ID"}]}},{"key":"PROJECT_ROUTER_IMAGE","image":"$ROUTER_IMAGE","registry":{"platforms":[{"platform":"linux/amd64","digest":"sha256:$(printf '4%.0s' $(seq 1 64))","imageId":"sha256:$(printf '3%.0s' $(seq 1 64))"}]}}]}
EOF
}

write_deployment() {
  cat > "$TMP/deployment.json" <<EOF
{"opsRunner":{"image":"$OPS_IMAGE","imageId":"$OPS_IMAGE_ID","providerAttested":true},"runtimeIntentSha256":"$(printf 'f%.0s' $(seq 1 64))","runtimeIntent":{"version":2,"kind":"platform-runtime-intent/v2","projectName":"platform_infra_vps","sourceRenderSha256":"$(printf '4%.0s' $(seq 1 64))","combinedComposeSha256":"$(printf '5%.0s' $(seq 1 64))","persistentVolumes":[{"name":"enterprise_local_registry_data","createdAt":"2026-07-21T00:00:00.000Z","driver":"local","scope":"local","options":{},"labels":{"platform.infrastructure.managed":"true","platform.infrastructure.purpose":"local-registry"},"mountpoint":"/var/lib/docker/volumes/enterprise_local_registry_data/_data","owner":{"uid":0,"gid":0,"mode":"0755"}}],"services":[{"service":"backup-scheduler","image":"$SCHEDULER_IMAGE","admission":{"kind":"artifact-subject","subjectKey":"PLATFORM_BACKUP_SCHEDULER_IMAGE"},"expectedLocalImageId":"$SCHEDULER_IMAGE_ID"},{"service":"control-center","image":"$CONTROL_IMAGE","admission":{"kind":"artifact-subject","subjectKey":"CONTROL_CENTER_IMAGE"},"expectedLocalImageId":"sha256:$(printf '1%.0s' $(seq 1 64))"},{"service":"platform-alert-dispatcher","image":"$ALERT_IMAGE","admission":{"kind":"artifact-subject","subjectKey":"PLATFORM_ALERT_DISPATCHER_IMAGE"},"expectedLocalImageId":"sha256:$(printf '2%.0s' $(seq 1 64))"},{"service":"project-router","image":"$ROUTER_IMAGE","admission":{"kind":"artifact-subject","subjectKey":"PROJECT_ROUTER_IMAGE"},"expectedLocalImageId":"sha256:$(printf '3%.0s' $(seq 1 64))"}]}}
EOF
}

write_compose() {
  cat > "$TMP/compose.json" <<EOF
{"services":{"backup-scheduler":{"image":"$SCHEDULER_IMAGE"},"control-center":{"image":"$CONTROL_IMAGE","volumes":[{"type":"volume","source":"database","target":"/data"}]},"platform-alert-dispatcher":{"image":"$ALERT_IMAGE"},"project-router":{"image":"$ROUTER_IMAGE"}},"volumes":{"database":{"name":"platform_database","driver":"local"}}}
EOF
}

reset_fixtures() {
  write_receipt
  write_deployment
  write_compose
}

expect_reject() {
  label=$1
  if sh "$SCRIPT_DIR/release-compose-admission.sh" "$TMP/receipt.json" "$TMP/deployment.json" "$TMP/compose.json" >/dev/null 2>&1; then
    echo "FAIL: $label was accepted" >&2
    exit 1
  fi
  printf 'PASS\t%s\n' "$label"
}

expect_reject_with_previous() {
  label=$1
  if sh "$SCRIPT_DIR/release-compose-admission.sh" "$TMP/receipt.json" "$TMP/deployment.json" "$TMP/compose.json" "$TMP/previous.json" >/dev/null 2>&1; then
    echo "FAIL: $label was accepted" >&2
    exit 1
  fi
  printf 'PASS\t%s\n' "$label"
}

reset_fixtures
sh "$SCRIPT_DIR/release-compose-admission.sh" "$TMP/receipt.json" "$TMP/deployment.json" "$TMP/compose.json"
printf 'PASS\texact-runtime-intent-subject-and-service-set\n'

jq '.services["project-router"].image = "ghcr.io/owner/attacker@sha256:'"$(printf '4%.0s' $(seq 1 64))"'"' "$TMP/compose.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/compose.json"
expect_reject wrong-rendered-digest

reset_fixtures
jq '.subjects = .subjects[1:]' "$TMP/receipt.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/receipt.json"
expect_reject missing-subject

reset_fixtures
jq '.subjects += [{"key":"ATTACKER_IMAGE","image":"ghcr.io/owner/attacker@sha256:'"$(printf '5%.0s' $(seq 1 64))"'"}]' "$TMP/receipt.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/receipt.json"
expect_reject extra-subject

reset_fixtures
jq 'del(.services["control-center"])' "$TMP/compose.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/compose.json"
expect_reject missing-service

reset_fixtures
jq '.services.attacker={"image":"ghcr.io/owner/attacker@sha256:'"$(printf '5%.0s' $(seq 1 64))"'"}' "$TMP/compose.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/compose.json"
expect_reject extra-service

reset_fixtures
jq '.services["control-center"].image = "ghcr.io/owner/platform-infrastructure-control-center:latest"' "$TMP/compose.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/compose.json"
expect_reject mutable-image

reset_fixtures
jq '.services["project-router"].build={"context":"."}' "$TMP/compose.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/compose.json"
expect_reject build-fallback

reset_fixtures
jq '.runtimeIntent.services |= reverse' "$TMP/deployment.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/deployment.json"
expect_reject unordered-runtime-intent

reset_fixtures
jq '.runtimeIntent.services[0].expectedLocalImageId = "invalid"' "$TMP/deployment.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/deployment.json"
expect_reject invalid-scheduler-image-id

reset_fixtures
jq '.runtimeIntent.services[0].expectedLocalImageId = "sha256:'"$(printf '6%.0s' $(seq 1 64))"'"' "$TMP/deployment.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/deployment.json"
expect_reject scheduler-platform-image-id-mismatch

reset_fixtures
jq --arg image "$OPS_IMAGE" --arg imageId "$OPS_IMAGE_ID" '
  .runtimeIntent.services[0].image = $image |
  .runtimeIntent.services[0].expectedLocalImageId = $imageId |
  .runtimeIntent.services[0].admission = {kind:"ops-runner"}
' "$TMP/deployment.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/deployment.json"
jq --arg image "$OPS_IMAGE" '.services["backup-scheduler"].image = $image' "$TMP/compose.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/compose.json"
expect_reject scheduler-reuses-privileged-ops-runner

reset_fixtures
jq '.runtimeIntent.version = 1 | .runtimeIntent.kind = "platform-runtime-intent/v1"' "$TMP/deployment.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/deployment.json"
expect_reject legacy-runtime-intent

reset_fixtures
jq '.runtimeIntent.combinedComposeSha256 = .runtimeIntent.sourceRenderSha256' "$TMP/deployment.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/deployment.json"
expect_reject identical-source-and-final-render

reset_fixtures
jq '.runtimeIntent.persistentVolumes[0].owner.uid = 1000' "$TMP/deployment.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/deployment.json"
expect_reject non-root-persistent-volume

reset_fixtures
cp "$TMP/compose.json" "$TMP/previous.json"
sh "$SCRIPT_DIR/release-compose-admission.sh" "$TMP/receipt.json" "$TMP/deployment.json" "$TMP/compose.json" "$TMP/previous.json"
printf 'PASS\texact-persistent-storage-identity\n'

sed 's/"source":"database"/"source":"replacement_database"/' "$TMP/compose.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/compose.json"
expect_reject_with_previous changed-persistent-storage

reset_fixtures
cp "$TMP/compose.json" "$TMP/previous.json"
jq '.services["control-center"].volumes[0].volume={"subpath":"other"}' "$TMP/compose.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/compose.json"
expect_reject_with_previous changed-volume-subpath

reset_fixtures
cp "$TMP/compose.json" "$TMP/previous.json"
jq '.services["control-center"].networks={"candidate_only":null} | .networks={"candidate_only":{"name":"candidate_only"}}' "$TMP/compose.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/compose.json"
expect_reject_with_previous changed-network-identity

! grep -R -F './project-router:/app' "$ROOT/compose.yaml" "$ROOT/compose.runtime-isolation.yaml"
grep -F 'COPY --chown=node:node project-router/server.mjs /app/server.mjs' "$ROOT/docker/project-router.Dockerfile" >/dev/null
printf 'PASS\tproject-router-code-is-image-baked\n'

[ "$(grep -c 'build: !reset null' "$ROOT/compose.runtime-isolation.yaml")" -eq 5 ]
printf 'PASS\tvps-repository-build-fallbacks-reset\n'

! grep -F 'profiles: !reset []' "$ROOT/compose.runtime.yaml" >/dev/null
grep -A4 '^  local-registry:' "$ROOT/compose.runtime.yaml" | grep -F 'local-runtime-disabled' >/dev/null
printf 'PASS\tlocal-admin-dns-registry-profiles-remain-disabled\n'

for key in CONTROL_CENTER_IMAGE PLATFORM_ALERT_DISPATCHER_IMAGE PLATFORM_BACKUP_SCHEDULER_IMAGE PROJECT_ROUTER_IMAGE; do
  grep -F -- "--image \"$key=" "$ROOT/.github/workflows/release-attestation.yml" >/dev/null
done
! grep -F -- '--image "PHP_APACHE_IMAGE=' "$ROOT/.github/workflows/release-attestation.yml" >/dev/null
printf 'PASS\trelease-subjects-match-active-repository-services\n'

printf 'release Compose admission tests passed 23/23\n'
