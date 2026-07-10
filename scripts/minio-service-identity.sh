#!/usr/bin/env sh
set -eu

MODE=${MODE:-plan}
MINIO_ALIAS=${MINIO_ALIAS:-platform-root}
MINIO_ENDPOINT=${MINIO_ENDPOINT:-http://minio:9000}
MINIO_ROOT_USER=${MINIO_ROOT_USER:-minio_admin}
MINIO_ROOT_PASSWORD_FILE=${MINIO_ROOT_PASSWORD_FILE:-/run/secrets/minio_root_password}
MINIO_SERVICE_ACCESS_KEY_FILE=${MINIO_SERVICE_ACCESS_KEY_FILE:-/run/secrets/minio_service_access_key}
MINIO_SERVICE_SECRET_KEY_FILE=${MINIO_SERVICE_SECRET_KEY_FILE:-/run/secrets/minio_service_secret_key}
MINIO_BUCKET=${MINIO_BUCKET:-}
MINIO_PREFIX=${MINIO_PREFIX:-}
MINIO_DENY_TEST_BUCKET=${MINIO_DENY_TEST_BUCKET:-}
MINIO_VERIFY_WRITE=${MINIO_VERIFY_WRITE:-0}
CONFIRM=${CONFIRM:-}

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

case "$MINIO_BUCKET" in
  ''|*[!a-z0-9.-]*) fail "MINIO_BUCKET must be a lowercase S3 bucket name" ;;
esac
case "$MINIO_PREFIX" in
  ''|/*|*'..'*|*[!A-Za-z0-9._/-]*) fail "MINIO_PREFIX must be a non-empty relative object prefix" ;;
esac
MINIO_PREFIX=${MINIO_PREFIX%/}/

if [ "$MODE" = plan ]; then
  printf '%s\n' "Plan: create or update one MinIO service account scoped to ${MINIO_BUCKET}/${MINIO_PREFIX}."
  printf '%s\n' "Root material is used only by this one-shot bootstrap; workloads receive only the scoped access and secret key files."
  exit 0
fi

command -v mc >/dev/null 2>&1 || fail "mc is required"
for file in "$MINIO_ROOT_PASSWORD_FILE" "$MINIO_SERVICE_ACCESS_KEY_FILE" "$MINIO_SERVICE_SECRET_KEY_FILE"; do
  [ -s "$file" ] || fail "Required secret file is missing or empty"
done

work=$(mktemp -d)
chmod 700 "$work"
trap 'rm -rf "$work"' EXIT HUP INT TERM
export MC_CONFIG_DIR="$work/mc"

root_password=$(tr -d '\r\n' < "$MINIO_ROOT_PASSWORD_FILE")
access_key=$(tr -d '\r\n' < "$MINIO_SERVICE_ACCESS_KEY_FILE")
secret_key=$(tr -d '\r\n' < "$MINIO_SERVICE_SECRET_KEY_FILE")
[ -n "$root_password" ] && [ -n "$access_key" ] && [ -n "$secret_key" ] || fail "Secret files must contain one non-empty line"

mc alias set "$MINIO_ALIAS" "$MINIO_ENDPOINT" "$MINIO_ROOT_USER" "$root_password" >/dev/null
mc stat "$MINIO_ALIAS/$MINIO_BUCKET" >/dev/null 2>&1 || fail "Target bucket must exist before identity bootstrap"

policy="$work/policy.json"
cat > "$policy" <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::$MINIO_BUCKET"],"Condition":{"StringLike":{"s3:prefix":["$MINIO_PREFIX*"]}}},{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"],"Resource":["arn:aws:s3:::$MINIO_BUCKET/$MINIO_PREFIX*"]}]}
EOF
chmod 600 "$policy"

case "$MODE" in
  apply)
    [ "$CONFIRM" = APPLY-MINIO-SERVICE-IDENTITY ] || fail "Set CONFIRM=APPLY-MINIO-SERVICE-IDENTITY"
    if mc admin user svcacct info "$MINIO_ALIAS" "$access_key" >/dev/null 2>&1; then
      mc admin user svcacct edit "$MINIO_ALIAS" "$access_key" --secret-key "$secret_key" --policy "$policy" >/dev/null
    else
      mc admin user svcacct add "$MINIO_ALIAS" "$MINIO_ROOT_USER" --access-key "$access_key" --secret-key "$secret_key" --policy "$policy" --name "${MINIO_BUCKET}-${MINIO_PREFIX%/}" >/dev/null
    fi
    printf '%s\n' "Scoped MinIO service identity applied."
    ;;
  verify)
    service_alias=platform-service
    mc alias set "$service_alias" "$MINIO_ENDPOINT" "$access_key" "$secret_key" >/dev/null
    mc ls "$service_alias/$MINIO_BUCKET/$MINIO_PREFIX" >/dev/null
    if [ "$MINIO_VERIFY_WRITE" = 1 ]; then
      printf 'service-identity-probe\n' > "$work/probe.txt"
      mc cp "$work/probe.txt" "$service_alias/$MINIO_BUCKET/${MINIO_PREFIX}__identity_probe__" >/dev/null
      [ "$(mc cat "$service_alias/$MINIO_BUCKET/${MINIO_PREFIX}__identity_probe__")" = 'service-identity-probe' ] || fail "Scoped object round-trip failed"
      mc rm "$service_alias/$MINIO_BUCKET/${MINIO_PREFIX}__identity_probe__" >/dev/null
    fi
    if mc ls "$service_alias/$MINIO_BUCKET/__outside_scope__/" >/dev/null 2>&1; then
      fail "Service identity can list outside its prefix"
    fi
    if [ -n "$MINIO_DENY_TEST_BUCKET" ] && mc ls "$service_alias/$MINIO_DENY_TEST_BUCKET" >/dev/null 2>&1; then
      fail "Service identity can list a cross-bucket target"
    fi
    if mc admin info "$service_alias" >/dev/null 2>&1; then
      fail "Service identity can call an admin API"
    fi
    printf '%s\n' "Scoped MinIO service identity verified."
    ;;
  revoke)
    [ "$CONFIRM" = REVOKE-MINIO-SERVICE-IDENTITY ] || fail "Set CONFIRM=REVOKE-MINIO-SERVICE-IDENTITY"
    mc admin user svcacct rm "$MINIO_ALIAS" "$access_key" >/dev/null
    printf '%s\n' "Scoped MinIO service identity revoked."
    ;;
  *) fail "MODE must be plan, apply, verify or revoke" ;;
esac
