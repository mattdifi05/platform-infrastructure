#!/usr/bin/env sh
set -eu

GH_VERSION=2.93.0
GH_ARCHIVE_SHA256=02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0
INSTALL_PATH=/usr/local/bin/gh

[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || {
  echo "The pinned GitHub attestation verifier is available only for Linux x86_64." >&2
  exit 1
}
command -v curl >/dev/null 2>&1
command -v sha256sum >/dev/null 2>&1
command -v tar >/dev/null 2>&1
command -v sudo >/dev/null 2>&1

temporary=$(mktemp -d "${RUNNER_TEMP:-/tmp}/platform-gh-verifier.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
archive="$temporary/gh.tar.gz"
curl --fail --location --silent --show-error \
  "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_amd64.tar.gz" \
  --output "$archive"
printf '%s  %s\n' "$GH_ARCHIVE_SHA256" "$archive" | sha256sum -c -
tar -xzf "$archive" -C "$temporary"
sudo install -o root -g root -m 0755 \
  "$temporary/gh_${GH_VERSION}_linux_amd64/bin/gh" "$INSTALL_PATH"
[ "$(command -v gh)" = "$INSTALL_PATH" ]
"$INSTALL_PATH" --version | grep -F "gh version ${GH_VERSION} " >/dev/null
