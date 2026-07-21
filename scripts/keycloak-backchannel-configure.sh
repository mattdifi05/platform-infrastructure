#!/usr/bin/env sh
set -eu

CONTAINER=${KEYCLOAK_CONTAINER:-enterprise-keycloak}
REALM=${KEYCLOAK_REALM:-platform}
CLIENT_ID=${CONTROL_CENTER_OIDC_CLIENT_ID:-platform-control-center}
PUBLIC_ORIGIN=${CONTROL_CENTER_PUBLIC_ORIGIN:-}
APPLY=${KEYCLOAK_BACKCHANNEL_APPLY:-false}
CONFIRM=${KEYCLOAK_BACKCHANNEL_CONFIRM:-}
VALIDATE_ONLY=${KEYCLOAK_BACKCHANNEL_VALIDATE_ONLY:-false}

case "$CONTAINER" in
  ''|-*|*[!a-zA-Z0-9_.:-]*)
    echo "Unsafe Keycloak container identifier." >&2
    exit 2
    ;;
esac
case "$REALM:$CLIENT_ID" in
  *[!a-zA-Z0-9._:-]*)
    echo "Unsafe realm or client identifier." >&2
    exit 2
    ;;
esac
case "$APPLY:$VALIDATE_ONLY" in
  true:true|true:false|false:true|false:false) ;;
  *) echo "Keycloak action flags must be exactly true or false." >&2; exit 2 ;;
esac

origin_error() {
  echo "CONTROL_CENTER_PUBLIC_ORIGIN must be an origin-only HTTPS URL with a DNS hostname." >&2
  exit 2
}
carriage_return=$(printf '\r')
case "$PUBLIC_ORIGIN" in
  *"$carriage_return"*|*"
"*) origin_error ;;
esac
printf '%s\n' "$PUBLIC_ORIGIN" | LC_ALL=C grep -Eq '^https://[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]{1,5})?/?$' || origin_error
normalized_origin=${PUBLIC_ORIGIN%/}
authority=${normalized_origin#https://}
host=${authority%%:*}
case "$host" in
  .*|*.|-*|*-|*..*|*.-*|*-.*) origin_error ;;
esac
normalized_host=$(printf '%s' "$host" | LC_ALL=C tr '[:upper:]' '[:lower:]')
case "$authority" in
  *:*)
    port=${authority##*:}
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || origin_error
    if [ "$port" = 443 ]; then
      normalized_origin="https://$normalized_host"
    else
      normalized_origin="https://$normalized_host:$port"
    fi
    ;;
  *) normalized_origin="https://$normalized_host" ;;
esac
EXPECTED_BACKCHANNEL_URL="$normalized_origin/auth/backchannel-logout"

if [ "$VALIDATE_ONLY" = true ]; then
  [ "$APPLY" = false ] || { echo "Validate-only mode cannot apply changes." >&2; exit 2; }
  printf 'realm=%s client=%s expected_backchannel=%s status=validated-only\n' \
    "$REALM" "$CLIENT_ID" "$EXPECTED_BACKCHANNEL_URL"
  exit 0
fi

if [ "$APPLY" = true ] && [ "$CONFIRM" != "CONFIGURE-OIDC-BACKCHANNEL-LOGOUT" ]; then
  echo "Apply requires KEYCLOAK_BACKCHANNEL_CONFIRM=CONFIGURE-OIDC-BACKCHANNEL-LOGOUT." >&2
  exit 2
fi

docker inspect -- "$CONTAINER" >/dev/null

docker exec \
  -e "PLATFORM_BACKCHANNEL_REALM=$REALM" \
  -e "PLATFORM_BACKCHANNEL_CLIENT=$CLIENT_ID" \
  -e "PLATFORM_BACKCHANNEL_URL=$EXPECTED_BACKCHANNEL_URL" \
  -e "PLATFORM_BACKCHANNEL_APPLY=$APPLY" \
  "$CONTAINER" sh -ec '
    umask 077
    config_dir=$(mktemp -d /tmp/platform-backchannel-configure.XXXXXX)
    config=$config_dir/kcadm.config
    cleanup() { rm -rf -- "$config_dir"; }
    trap cleanup EXIT
    trap "exit 129" HUP
    trap "exit 130" INT
    trap "exit 143" TERM

    admin_password=$(cat "$KC_BOOTSTRAP_ADMIN_PASSWORD_FILE")
    /opt/keycloak/bin/kcadm.sh config credentials \
      --config "$config" \
      --server http://127.0.0.1:8080 \
      --realm master \
      --user "$KC_BOOTSTRAP_ADMIN_USERNAME" \
      --password "$admin_password" >/dev/null
    unset admin_password

    get_client() {
      /opt/keycloak/bin/kcadm.sh get clients \
        --config "$config" \
        -r "$PLATFORM_BACKCHANNEL_REALM" \
        -q "clientId=$PLATFORM_BACKCHANNEL_CLIENT" \
        --fields id,clientId,attributes
    }

    client_json=$(get_client)
    client_count=$(printf "%s\n" "$client_json" | grep -c "\"clientId\"" || true)
    [ "$client_count" -eq 1 ] || {
      echo "Control Center OIDC client is missing or duplicated; no update performed." >&2
      exit 1
    }
    client_uuid=$(printf "%s\n" "$client_json" | sed -n "s/.*\"id\" : \"\([^\"]*\)\".*/\1/p" | head -n 1)
    [ -n "$client_uuid" ] || { echo "Unable to resolve the OIDC client ID; no update performed." >&2; exit 1; }

    exact_contract() {
      candidate=$1
      printf "%s\n" "$candidate" | grep -Fq "\"backchannel.logout.url\" : \"$PLATFORM_BACKCHANNEL_URL\"" &&
        printf "%s\n" "$candidate" | grep -Fq "\"backchannel.logout.session.required\" : \"true\"" &&
        printf "%s\n" "$candidate" | grep -Fq "\"backchannel.logout.revoke.offline.tokens\" : \"true\""
    }

    if exact_contract "$client_json"; then
      printf "realm=%s client=%s expected_backchannel=%s action=none status=ready\n" \
        "$PLATFORM_BACKCHANNEL_REALM" "$PLATFORM_BACKCHANNEL_CLIENT" "$PLATFORM_BACKCHANNEL_URL"
      exit 0
    fi

    if [ "$PLATFORM_BACKCHANNEL_APPLY" != true ]; then
      printf "realm=%s client=%s expected_backchannel=%s action=update-required status=drift\n" \
        "$PLATFORM_BACKCHANNEL_REALM" "$PLATFORM_BACKCHANNEL_CLIENT" "$PLATFORM_BACKCHANNEL_URL"
      exit 1
    fi

    /opt/keycloak/bin/kcadm.sh update "clients/$client_uuid" \
      --config "$config" \
      -r "$PLATFORM_BACKCHANNEL_REALM" \
      -s "attributes.\"backchannel.logout.url\"=\"$PLATFORM_BACKCHANNEL_URL\"" \
      -s "attributes.\"backchannel.logout.session.required\"=\"true\"" \
      -s "attributes.\"backchannel.logout.revoke.offline.tokens\"=\"true\"" >/dev/null

    client_json=$(get_client)
    exact_contract "$client_json" || {
      echo "Keycloak accepted the update but the exact back-channel contract did not verify." >&2
      exit 1
    }
    printf "realm=%s client=%s expected_backchannel=%s action=updated status=ready\n" \
      "$PLATFORM_BACKCHANNEL_REALM" "$PLATFORM_BACKCHANNEL_CLIENT" "$PLATFORM_BACKCHANNEL_URL"
  '
