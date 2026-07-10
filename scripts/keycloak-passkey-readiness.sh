#!/usr/bin/env sh
set -eu

CONTAINER=${KEYCLOAK_CONTAINER:-enterprise-keycloak}
REALM=${KEYCLOAK_REALM:-platform}
CLIENT_ID=${CONTROL_CENTER_OIDC_CLIENT_ID:-platform-control-center}
ADMIN_USERS=${CONTROL_CENTER_ADMIN_USERS:-}
MIN_PASSKEYS=${CONTROL_CENTER_MIN_PASSKEYS:-2}

case "$REALM:$CLIENT_ID" in
  *[!a-zA-Z0-9._:-]*)
    echo "Unsafe realm or client identifier." >&2
    exit 2
    ;;
esac
case "$MIN_PASSKEYS" in
  ''|*[!0-9]*) echo "CONTROL_CENTER_MIN_PASSKEYS must be numeric." >&2; exit 2 ;;
esac
if [ "$MIN_PASSKEYS" -lt 2 ]; then
  echo "At least two independent passkeys are required." >&2
  exit 2
fi

docker inspect "$CONTAINER" >/dev/null

docker exec \
  -e PLATFORM_VERIFY_REALM="$REALM" \
  -e PLATFORM_VERIFY_CLIENT="$CLIENT_ID" \
  -e PLATFORM_VERIFY_USERS="$ADMIN_USERS" \
  -e PLATFORM_VERIFY_MIN_PASSKEYS="$MIN_PASSKEYS" \
  "$CONTAINER" sh -ec '
    config=/tmp/platform-passkey-readiness.config
    cleanup() { rm -f "$config"; }
    trap cleanup EXIT
    admin_password=$(cat "$KC_BOOTSTRAP_ADMIN_PASSWORD_FILE")
    /opt/keycloak/bin/kcadm.sh config credentials \
      --config "$config" \
      --server http://127.0.0.1:8080 \
      --realm master \
      --user "$KC_BOOTSTRAP_ADMIN_USERNAME" \
      --password "$admin_password" >/dev/null
    unset admin_password

    realm_json=$(/opt/keycloak/bin/kcadm.sh get "realms/$PLATFORM_VERIFY_REALM" --config "$config")
    printf "%s\n" "$realm_json" | grep -q "\"bruteForceProtected\" : true" || { echo "Realm brute-force protection is not enabled." >&2; exit 1; }
    printf "%s\n" "$realm_json" | grep -q "\"resetPasswordAllowed\" : false" || { echo "Realm password recovery is still enabled." >&2; exit 1; }
    printf "%s\n" "$realm_json" | grep -q "\"browserFlow\" : \"platform-passkey-browser\"" || { echo "Passkey-only browser flow is not bound." >&2; exit 1; }
    printf "%s\n" "$realm_json" | grep -q "\"webAuthnPolicyPasswordlessUserVerificationRequirement\" : \"required\"" || { echo "WebAuthn user verification is not required." >&2; exit 1; }

    client_json=$(/opt/keycloak/bin/kcadm.sh get clients --config "$config" -r "$PLATFORM_VERIFY_REALM" -q "clientId=$PLATFORM_VERIFY_CLIENT")
    client_count=$(printf "%s\n" "$client_json" | grep -c "\"clientId\"" || true)
    [ "$client_count" -eq 1 ] || { echo "Control Center OIDC client is missing or duplicated." >&2; exit 1; }
    printf "%s\n" "$client_json" | grep -q "\"publicClient\" : true"
    printf "%s\n" "$client_json" | grep -q "\"directAccessGrantsEnabled\" : false"
    printf "%s\n" "$client_json" | grep -q "\"pkce.code.challenge.method\" : \"S256\""
    printf "%s\n" "$client_json" | grep -q "\"protocolMapper\" : \"oidc-amr-mapper\""

    executions=$(/opt/keycloak/bin/kcadm.sh get authentication/flows/platform-passkey-browser/executions --config "$config" -r "$PLATFORM_VERIFY_REALM")
    printf "%s\n" "$executions" | grep -q "\"providerId\" : \"webauthn-authenticator-passwordless\""
    printf "%s\n" "$executions" | grep -q "\"requirement\" : \"REQUIRED\""
    if printf "%s\n" "$executions" | grep -Eq "auth-username-password|auth-otp|recovery-authn-code"; then
      echo "Password, OTP or recovery execution is present in the admin browser flow." >&2
      exit 1
    fi

    user_total=0
    old_ifs=$IFS
    IFS=,
    for username in $PLATFORM_VERIFY_USERS; do
      IFS=$old_ifs
      username=$(printf "%s" "$username" | tr -d "[:space:]")
      [ -n "$username" ] || continue
      case "$username" in *[!a-zA-Z0-9@._+-]*) echo "Unsafe admin username." >&2; exit 2 ;; esac
      user_json=$(/opt/keycloak/bin/kcadm.sh get users --config "$config" -r "$PLATFORM_VERIFY_REALM" -q "username=$username" --fields id,username,enabled)
      user_id=$(printf "%s\n" "$user_json" | sed -n "s/.*\"id\" : \"\([^\"]*\)\".*/\1/p" | head -n 1)
      [ -n "$user_id" ] || { echo "Admin user not found: $username" >&2; exit 1; }
      printf "%s\n" "$user_json" | grep -q "\"enabled\" : true"
      credentials=$(/opt/keycloak/bin/kcadm.sh get "users/$user_id/credentials" --config "$config" -r "$PLATFORM_VERIFY_REALM")
      passkey_count=$(printf "%s\n" "$credentials" | grep -c "\"type\" : \"webauthn-passwordless\"" || true)
      [ "$passkey_count" -ge "$PLATFORM_VERIFY_MIN_PASSKEYS" ] || { echo "Insufficient passkeys for $username: $passkey_count" >&2; exit 1; }
      roles=$(/opt/keycloak/bin/kcadm.sh get "users/$user_id/role-mappings/realm" --config "$config" -r "$PLATFORM_VERIFY_REALM")
      printf "%s\n" "$roles" | grep -Eq "\"name\" : \"(owner|admin|viewer)\""
      printf "admin=%s passkeys=%s status=ready\n" "$username" "$passkey_count"
      user_total=$((user_total + 1))
      IFS=,
    done
    IFS=$old_ifs
    [ "$user_total" -gt 0 ] || { echo "CONTROL_CENTER_ADMIN_USERS is empty." >&2; exit 1; }
    printf "realm=%s client=%s admins=%s status=ready\n" "$PLATFORM_VERIFY_REALM" "$PLATFORM_VERIFY_CLIENT" "$user_total"
  '
