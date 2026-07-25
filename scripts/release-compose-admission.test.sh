#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/release-compose-admission-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

CONTROL_IMAGE="ghcr.io/owner/platform-infrastructure-control-center@sha256:$(printf 'a%.0s' $(seq 1 64))"
ALERT_IMAGE="ghcr.io/owner/platform-infrastructure-alert-dispatcher@sha256:$(printf 'b%.0s' $(seq 1 64))"
ROUTER_IMAGE="ghcr.io/owner/platform-infrastructure-project-router@sha256:$(printf 'c%.0s' $(seq 1 64))"
OPS_IMAGE="ghcr.io/owner/platform-infrastructure-ops@sha256:$(printf 'd%.0s' $(seq 1 64))"
OPS_IMAGE_ID="sha256:$(printf 'e%.0s' $(seq 1 64))"

write_receipt() {
  cat > "$TMP/receipt.json" <<EOF
{"subjects":[{"key":"CONTROL_CENTER_IMAGE","image":"$CONTROL_IMAGE"},{"key":"PLATFORM_ALERT_DISPATCHER_IMAGE","image":"$ALERT_IMAGE"},{"key":"PROJECT_ROUTER_IMAGE","image":"$ROUTER_IMAGE"}]}
EOF
}

write_deployment() {
  cat > "$TMP/deployment.json" <<EOF
{"opsRunner":{"image":"$OPS_IMAGE","imageId":"$OPS_IMAGE_ID","providerAttested":true},"runtimeIntentSha256":"$(printf 'f%.0s' $(seq 1 64))","runtimeIntent":{"version":1,"kind":"platform-runtime-intent/v1","projectName":"platform_infra_vps","services":[{"service":"backup-scheduler","image":"$OPS_IMAGE","admission":{"kind":"ops-runner"},"expectedLocalImageId":"$OPS_IMAGE_ID"},{"service":"control-center","image":"$CONTROL_IMAGE","admission":{"kind":"artifact-subject","subjectKey":"CONTROL_CENTER_IMAGE"},"expectedLocalImageId":"sha256:$(printf '1%.0s' $(seq 1 64))"},{"service":"platform-alert-dispatcher","image":"$ALERT_IMAGE","admission":{"kind":"artifact-subject","subjectKey":"PLATFORM_ALERT_DISPATCHER_IMAGE"},"expectedLocalImageId":"sha256:$(printf '2%.0s' $(seq 1 64))"},{"service":"project-router","image":"$ROUTER_IMAGE","admission":{"kind":"artifact-subject","subjectKey":"PROJECT_ROUTER_IMAGE"},"expectedLocalImageId":"sha256:$(printf '3%.0s' $(seq 1 64))"}]}}
EOF
}

write_compose() {
  cat > "$TMP/compose.json" <<EOF
{"services":{"backup-scheduler":{"image":"$OPS_IMAGE"},"control-center":{"image":"$CONTROL_IMAGE","volumes":[{"type":"volume","source":"database","target":"/data"}]},"platform-alert-dispatcher":{"image":"$ALERT_IMAGE"},"project-router":{"image":"$ROUTER_IMAGE"}},"volumes":{"database":{"name":"platform_database","driver":"local"}}}
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
jq '.runtimeIntent.services[0].expectedLocalImageId = "sha256:'"$(printf '6%.0s' $(seq 1 64))"'"' "$TMP/deployment.json" > "$TMP/changed.json"
mv "$TMP/changed.json" "$TMP/deployment.json"
expect_reject wrong-ops-image-id

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

[ "$(grep -c 'build: !reset null' "$ROOT/compose.runtime-isolation.yaml")" -eq 4 ]
printf 'PASS\tvps-repository-build-fallbacks-reset\n'

! grep -F 'profiles: !reset []' "$ROOT/compose.runtime.yaml" >/dev/null
grep -A4 '^  local-registry:' "$ROOT/compose.runtime.yaml" | grep -F 'local-runtime-disabled' >/dev/null
printf 'PASS\tlocal-admin-dns-registry-profiles-remain-disabled\n'

for key in CONTROL_CENTER_IMAGE PLATFORM_ALERT_DISPATCHER_IMAGE PROJECT_ROUTER_IMAGE; do
  grep -F -- "--image \"$key=" "$ROOT/.github/workflows/release-attestation.yml" >/dev/null
done
! grep -F -- '--image "PHP_APACHE_IMAGE=' "$ROOT/.github/workflows/release-attestation.yml" >/dev/null
printf 'PASS\trelease-subjects-match-active-repository-services\n'

printf 'release Compose admission tests passed 18/18\n'
