#!/usr/bin/env sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 SNAPSHOT_JSON PROVIDER_IPV4 PROVIDER_IPV6" >&2
  exit 2
fi

snapshot=$1
provider_ipv4=$2
provider_ipv6=$3

for required in "$snapshot" "$provider_ipv4" "$provider_ipv6"; do
  if [ ! -f "$required" ] || [ ! -s "$required" ]; then
    echo "Missing or empty trusted-proxy input: $required" >&2
    exit 1
  fi
done

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

snapshot_ranges() {
  family=$1
  awk -v section="\"$family\"" '
    index($0, section) { collecting=1; next }
    collecting && /]/ { exit }
    collecting {
      value=$0
      gsub(/[\t \",]/, "", value)
      if (value != "") print value
    }
  ' "$snapshot"
}

normalize_provider() {
  source_file=$1
  output_file=$2
  awk '
    /^[[:space:]]*$/ { next }
    /^[[:space:]]*#/ { next }
    {
      value=$0
      sub(/[[:space:]]*#.*/, "", value)
      gsub(/[[:space:]]/, "", value)
      if (value != "") print value
    }
  ' "$source_file" | LC_ALL=C sort -u > "$output_file"
}

for family in ipv4 ipv6; do
  case "$family" in
    ipv4) provider_file=$provider_ipv4 ;;
    ipv6) provider_file=$provider_ipv6 ;;
  esac

  normalize_provider "$provider_file" "$tmpdir/provider-$family"
  snapshot_ranges "$family" | LC_ALL=C sort -u > "$tmpdir/pinned-$family"

  if [ ! -s "$tmpdir/provider-$family" ] || [ ! -s "$tmpdir/pinned-$family" ]; then
    echo "Trusted-proxy $family range set is empty" >&2
    exit 1
  fi

  if ! cmp -s "$tmpdir/provider-$family" "$tmpdir/pinned-$family"; then
    echo "Cloudflare $family ranges differ from the rate-limit trusted-proxy snapshot" >&2
    exit 1
  fi
done

echo "Cloudflare trusted-proxy snapshot matches the provider range files."
