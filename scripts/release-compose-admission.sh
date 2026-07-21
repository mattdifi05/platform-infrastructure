#!/usr/bin/env sh
set -eu

artifact_receipt=${1:-}
candidate_compose=${2:-}
previous_compose=${3:-}

require_private_input() {
  label=$1
  file=$2
  [ -f "$file" ] && [ -r "$file" ] && [ -s "$file" ] && [ ! -L "$file" ] || {
    echo "$label must be a readable, non-empty regular file, not a symlink." >&2
    exit 1
  }
}

require_private_input "Artifact verification receipt" "$artifact_receipt"
require_private_input "Candidate Compose model" "$candidate_compose"

# The release workflow currently authenticates exactly one repository-built
# subject. Keep this mapping explicit: accepting arbitrary *_IMAGE keys would
# reintroduce an attacker-controlled subject-to-service projection.
jq -e -s '
  .[0] as $receipt | .[1] as $compose |
  ($receipt.subjects | type == "array" and length == 1) and
  ($receipt.subjects[0].key == "PHP_APACHE_IMAGE") and
  ($receipt.subjects[0].image | type == "string" and test("^[a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)+@sha256:[a-f0-9]{64}$")) and
  ($compose.services | type == "object") and
  ($compose.services["php-apache"] | type == "object") and
  ($compose.services["php-apache"].image == $receipt.subjects[0].image)
' "$artifact_receipt" "$candidate_compose" >/dev/null || {
  echo "Release subjects do not exactly bind PHP_APACHE_IMAGE to the rendered php-apache service digest." >&2
  exit 1
}

if [ -n "$previous_compose" ]; then
  require_private_input "Previous Compose model" "$previous_compose"
  jq -e -s '
    def storage_mounts:
      [
        .services | to_entries[] as $service |
        ($service.value.volumes // [])[] |
        select(type == "object" and (.type == "volume" or .type == "bind")) |
        {
          service: $service.key,
          type: .type,
          source: .source,
          target: .target,
          read_only: (.read_only // false)
        }
      ] | sort_by(.service, .type, .source, .target);
    def volume_definitions:
      [
        (.volumes // {}) | to_entries[] |
        {
          key: .key,
          name: (.value.name // .key),
          external: (.value.external // false),
          driver: (.value.driver // "local"),
          driver_opts: (.value.driver_opts // {})
        }
      ] | sort_by(.key);
    .[0] as $previous | .[1] as $candidate |
    ($previous | storage_mounts) == ($candidate | storage_mounts) and
    ($previous | volume_definitions) == ($candidate | volume_definitions)
  ' "$previous_compose" "$candidate_compose" >/dev/null || {
    echo "Candidate Compose changes persistent storage identity; deploy requires a separately approved migration." >&2
    exit 1
  }
fi
