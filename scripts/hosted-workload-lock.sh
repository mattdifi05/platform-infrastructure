#!/usr/bin/env sh
set -eu

LOCK=${1:?Usage: hosted-workload-lock.sh <lock-file> [verify|compose-files]}
COMMAND=${2:-verify}

[ -f "$LOCK" ] && [ ! -L "$LOCK" ] || { printf '%s\n' "Hosted workload lock must be a regular non-symlink file." >&2; exit 1; }
mode=$(stat -c '%a' "$LOCK")
case "$mode" in 600|400) ;; *) printf '%s\n' "Hosted workload lock must use mode 0600 or 0400." >&2; exit 1 ;; esac
if [ "${HOSTED_WORKLOAD_ALLOW_RESOLVED:-0}" = 1 ]; then
  jq -e '.version == 2 and .validatorVersion == "hosted-contract-v2" and (.state == "resolved" or .state == "verified") and (.snapshotGeneration | type == "string" and length > 0) and (.snapshotRootIdentity.mode == 448) and (.snapshotGenerationIdentity.mode == 320) and (.workloadContentSha256 | test("^[a-f0-9]{64}$")) and (.files | type == "array" and length > 0) and (.workloads | type == "array")' "$LOCK" >/dev/null
else
  jq -e '.version == 2 and .validatorVersion == "hosted-contract-v2" and .state == "verified" and (.snapshotGeneration | type == "string" and length > 0) and (.snapshotRootIdentity.mode == 448) and (.snapshotGenerationIdentity.mode == 320) and (.workloadContentSha256 | test("^[a-f0-9]{64}$")) and (.files | type == "array" and length > 0) and (.workloads | type == "array")' "$LOCK" >/dev/null
fi

count=$(jq '.files | length' "$LOCK")
index=0
while [ "$index" -lt "$count" ]; do
  file=$(jq -r ".files[$index].path" "$LOCK")
  expected=$(jq -r ".files[$index].sha256" "$LOCK")
  case "$file" in /*) ;; *) printf '%s\n' "Locked path is not absolute." >&2; exit 1 ;; esac
  case "$file" in *[!A-Za-z0-9_./-]*|*//*|*/../*|*/..) printf '%s\n' "Locked path contains unsupported syntax." >&2; exit 1 ;; esac
  case "$expected" in *[!a-f0-9]*|'') printf '%s\n' "Locked SHA256 is invalid." >&2; exit 1 ;; esac
  [ "${#expected}" -eq 64 ] || { printf '%s\n' "Locked SHA256 is incomplete." >&2; exit 1; }
  [ -f "$file" ] && [ ! -L "$file" ] || { printf 'Locked file missing or symlinked: %s\n' "$file" >&2; exit 1; }
  actual=$(sha256sum "$file" | awk '{print $1}')
  [ "$actual" = "$expected" ] || { printf 'Locked file changed: %s\n' "$file" >&2; exit 1; }
  index=$((index + 1))
done

case "$COMMAND" in
  verify) ;;
  compose-files)
    jq -r '.workloads[].composePath' "$LOCK"
    ;;
  env-files)
    jq -r '.workloads[].environmentPath' "$LOCK"
    ;;
  core-env-file)
    jq -r '.coreEnvFile' "$LOCK"
    ;;
  project-name)
    jq -r '.projectName' "$LOCK"
    ;;
  *) printf '%s\n' "Command must be verify, compose-files, env-files, core-env-file or project-name." >&2; exit 2 ;;
esac
