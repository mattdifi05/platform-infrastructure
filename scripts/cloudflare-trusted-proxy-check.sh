#!/usr/bin/env sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 SNAPSHOT_JSON PROVIDER_IPV4 PROVIDER_IPV6" >&2
  exit 2
fi

snapshot=$1
provider_ipv4=$2
provider_ipv6=$3
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
canonicalizer="$script_dir/cloudflare-trusted-proxy-cidrs.awk"

for required in "$snapshot" "$provider_ipv4" "$provider_ipv6"; do
  if [ ! -f "$required" ] || [ ! -s "$required" ]; then
    echo "Missing or empty trusted-proxy input: $required" >&2
    exit 1
  fi
done

for command in jq awk; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Trusted-proxy CIDR validation requires $command" >&2
    exit 1
  }
done
[ -f "$canonicalizer" ] && [ -s "$canonicalizer" ] || {
  echo "Trusted-proxy CIDR canonicalizer is missing" >&2
  exit 1
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

snapshot_ranges() {
  family=$1
  jq -er --arg family "$family" '
    .[$family]
    | if type == "array" and length > 0 and all(.[]; type == "string" and length > 0)
      then .[]
      else error("invalid trusted-proxy range array")
      end
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
  ' "$source_file" > "$output_file"
}

canonicalize_ranges() {
  family=$1
  source_file=$2
  output_file=$3
  source_label=$4
  unsorted_file="$output_file.unsorted"
  if ! awk -v family="$family" -v source_label="$source_label" -f "$canonicalizer" "$source_file" > "$unsorted_file"; then
    rm -f "$unsorted_file"
    return 1
  fi
  LC_ALL=C sort "$unsorted_file" > "$output_file"
  rm -f "$unsorted_file"
}

for family in ipv4 ipv6; do
  case "$family" in
    ipv4) provider_file=$provider_ipv4 ;;
    ipv6) provider_file=$provider_ipv6 ;;
  esac

  normalize_provider "$provider_file" "$tmpdir/provider-$family.raw"
  snapshot_ranges "$family" > "$tmpdir/pinned-$family.raw"
  canonicalize_ranges "$family" "$tmpdir/provider-$family.raw" "$tmpdir/provider-$family" provider
  canonicalize_ranges "$family" "$tmpdir/pinned-$family.raw" "$tmpdir/pinned-$family" snapshot

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
