#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/release-compose-admission-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
IMAGE="ghcr.io/owner/platform-infrastructure-php-apache@sha256:$(printf 'a%.0s' $(seq 1 64))"
OTHER_IMAGE="ghcr.io/owner/platform-infrastructure-php-apache@sha256:$(printf 'b%.0s' $(seq 1 64))"
OPS_IMAGE="ghcr.io/owner/platform-infrastructure-ops@sha256:$(printf 'c%.0s' $(seq 1 64))"
OTHER_OPS_IMAGE="ghcr.io/owner/platform-infrastructure-ops@sha256:$(printf 'd%.0s' $(seq 1 64))"
printf '{"opsRunner":{"image":"%s","imageId":"sha256:%s","providerAttested":true}}\n' \
  "$OPS_IMAGE" "$(printf 'e%.0s' $(seq 1 64))" > "$TMP/deployment.json"

write_receipt() {
  subjects=$1
  printf '{"subjects":%s}\n' "$subjects" > "$TMP/receipt.json"
}

write_compose() {
  image=$1
  ops_image=${2:-$OPS_IMAGE}
  printf '{"services":{"php-apache":{"image":"%s","volumes":[{"type":"volume","source":"database","target":"/data"}]},"backup-scheduler":{"image":"%s"}},"volumes":{"database":{"name":"platform_database","driver":"local"}}}\n' \
    "$image" "$ops_image" > "$TMP/compose.json"
}

expect_reject() {
  label=$1
  if sh "$SCRIPT_DIR/release-compose-admission.sh" "$TMP/receipt.json" "$TMP/deployment.json" "$TMP/compose.json" >/dev/null 2>&1; then
    echo "FAIL: $label was accepted" >&2
    exit 1
  fi
  printf 'PASS\t%s\n' "$label"
}

write_receipt "[{\"key\":\"PHP_APACHE_IMAGE\",\"image\":\"$IMAGE\"}]"
write_compose "$IMAGE"
sh "$SCRIPT_DIR/release-compose-admission.sh" "$TMP/receipt.json" "$TMP/deployment.json" "$TMP/compose.json"
printf 'PASS\texact-release-and-ops-subject-service-digests\n'

write_compose "$OTHER_IMAGE"
expect_reject wrong-rendered-digest

write_receipt '[]'
write_compose "$IMAGE"
expect_reject missing-subject

write_receipt "[{\"key\":\"PHP_APACHE_IMAGE\",\"image\":\"$IMAGE\"},{\"key\":\"EXTRA_IMAGE\",\"image\":\"$OTHER_IMAGE\"}]"
expect_reject extra-subject

write_receipt "[{\"key\":\"PHP_APACHE_IMAGE\",\"image\":\"$IMAGE\"}]"
printf '{"services":{"edge":{"image":"%s"},"backup-scheduler":{"image":"%s"}}}\n' "$IMAGE" "$OPS_IMAGE" > "$TMP/compose.json"
expect_reject missing-service

write_receipt '[{"key":"PHP_APACHE_IMAGE","image":"ghcr.io/owner/platform-infrastructure-php-apache:latest"}]'
write_compose 'ghcr.io/owner/platform-infrastructure-php-apache:latest'
expect_reject mutable-subject

TAGGED_IMAGE="ghcr.io/owner/platform-infrastructure-php-apache:release@sha256:$(printf 'f%.0s' $(seq 1 64))"
write_receipt "[{\"key\":\"PHP_APACHE_IMAGE\",\"image\":\"$TAGGED_IMAGE\"}]"
write_compose "$TAGGED_IMAGE"
expect_reject tag-plus-digest-alias

write_receipt "[{\"key\":\"PHP_APACHE_IMAGE\",\"image\":\"$IMAGE\"}]"
write_compose "$IMAGE" "$OTHER_OPS_IMAGE"
expect_reject wrong-ops-runner-digest

write_compose "$IMAGE"
jq '.services["backup-scheduler"].build={"context":"."}' "$TMP/compose.json" > "$TMP/compose-with-build.json"
mv "$TMP/compose-with-build.json" "$TMP/compose.json"
expect_reject ops-runner-build-fallback

write_receipt "[{\"key\":\"PHP_APACHE_IMAGE\",\"image\":\"$IMAGE\"}]"
write_compose "$IMAGE"
cp "$TMP/compose.json" "$TMP/previous.json"
sh "$SCRIPT_DIR/release-compose-admission.sh" "$TMP/receipt.json" "$TMP/deployment.json" "$TMP/compose.json" "$TMP/previous.json"
printf 'PASS\texact-persistent-storage-identity\n'

sed 's/"source":"database"/"source":"replacement_database"/' "$TMP/compose.json" > "$TMP/changed-storage.json"
if sh "$SCRIPT_DIR/release-compose-admission.sh" "$TMP/receipt.json" "$TMP/deployment.json" "$TMP/changed-storage.json" "$TMP/previous.json" >/dev/null 2>&1; then
  echo "FAIL: changed persistent storage identity was accepted" >&2
  exit 1
fi
printf 'PASS\tchanged-persistent-storage-rejected\n'

jq '.services["php-apache"].volumes[0].volume = {"subpath":"other"}' "$TMP/compose.json" > "$TMP/changed-subpath.json"
if sh "$SCRIPT_DIR/release-compose-admission.sh" "$TMP/receipt.json" "$TMP/deployment.json" "$TMP/changed-subpath.json" "$TMP/previous.json" >/dev/null 2>&1; then
  echo "FAIL: changed volume subpath semantics were accepted" >&2
  exit 1
fi
printf 'PASS\tchanged-volume-subpath-rejected\n'

jq '.services["php-apache"].networks = {"candidate_only":null} | .networks = {"candidate_only":{"name":"candidate_only"}}' "$TMP/compose.json" > "$TMP/changed-network.json"
if sh "$SCRIPT_DIR/release-compose-admission.sh" "$TMP/receipt.json" "$TMP/deployment.json" "$TMP/changed-network.json" "$TMP/previous.json" >/dev/null 2>&1; then
  echo "FAIL: changed network identity was accepted" >&2
  exit 1
fi
printf 'PASS\tchanged-network-identity-rejected\n'

printf 'release Compose admission tests passed 13/13\n'
