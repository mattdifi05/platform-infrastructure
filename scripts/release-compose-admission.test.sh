#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/release-compose-admission-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
IMAGE="ghcr.io/owner/platform-infrastructure-php-apache@sha256:$(printf 'a%.0s' $(seq 1 64))"
OTHER_IMAGE="ghcr.io/owner/platform-infrastructure-php-apache@sha256:$(printf 'b%.0s' $(seq 1 64))"

write_receipt() {
  subjects=$1
  printf '{"subjects":%s}\n' "$subjects" > "$TMP/receipt.json"
}

write_compose() {
  image=$1
  printf '{"services":{"php-apache":{"image":"%s","volumes":[{"type":"volume","source":"database","target":"/data"}]}},"volumes":{"database":{"name":"platform_database","driver":"local"}}}\n' "$image" > "$TMP/compose.json"
}

expect_reject() {
  label=$1
  if sh "$SCRIPT_DIR/release-compose-admission.sh" "$TMP/receipt.json" "$TMP/compose.json" >/dev/null 2>&1; then
    echo "FAIL: $label was accepted" >&2
    exit 1
  fi
  printf 'PASS\t%s\n' "$label"
}

write_receipt "[{\"key\":\"PHP_APACHE_IMAGE\",\"image\":\"$IMAGE\"}]"
write_compose "$IMAGE"
sh "$SCRIPT_DIR/release-compose-admission.sh" "$TMP/receipt.json" "$TMP/compose.json"
printf 'PASS\texact-subject-service-digest\n'

write_compose "$OTHER_IMAGE"
expect_reject wrong-rendered-digest

write_receipt '[]'
write_compose "$IMAGE"
expect_reject missing-subject

write_receipt "[{\"key\":\"PHP_APACHE_IMAGE\",\"image\":\"$IMAGE\"},{\"key\":\"EXTRA_IMAGE\",\"image\":\"$OTHER_IMAGE\"}]"
expect_reject extra-subject

write_receipt "[{\"key\":\"PHP_APACHE_IMAGE\",\"image\":\"$IMAGE\"}]"
printf '{"services":{"edge":{"image":"%s"}}}\n' "$IMAGE" > "$TMP/compose.json"
expect_reject missing-service

write_receipt '[{"key":"PHP_APACHE_IMAGE","image":"ghcr.io/owner/platform-infrastructure-php-apache:latest"}]'
write_compose 'ghcr.io/owner/platform-infrastructure-php-apache:latest'
expect_reject mutable-subject

TAGGED_IMAGE="ghcr.io/owner/platform-infrastructure-php-apache:release@sha256:$(printf 'c%.0s' $(seq 1 64))"
write_receipt "[{\"key\":\"PHP_APACHE_IMAGE\",\"image\":\"$TAGGED_IMAGE\"}]"
write_compose "$TAGGED_IMAGE"
expect_reject tag-plus-digest-alias

printf 'release Compose admission tests passed 7/7\n'
