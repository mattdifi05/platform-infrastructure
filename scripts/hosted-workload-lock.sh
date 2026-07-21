#!/usr/bin/env sh
set -eu

LOCK=${1:?Usage: hosted-workload-lock.sh <lock-file> [verify|compose-files]}
COMMAND=${2:-verify}
RAW_POLICY_CONTROLS='["deny-api-socket","deny-device-access","deny-env-file","deny-extends","deny-file-configs","deny-include","deny-lifecycle-hooks","deny-local-volume-options","deny-providers","deny-runtime-overrides","deny-scaling","deny-volumes-from"]'

case "$COMMAND" in
  verify|compose-files|env-files|core-env-file|project-name) ;;
  *) printf '%s\n' "Command must be verify, compose-files, env-files, core-env-file or project-name." >&2; exit 2 ;;
esac

die() {
  printf '%s\n' "$1" >&2
  exit 1
}

stat_fields() {
  target=$1
  if stat -c '%d|%i|%u|%a|%s|%Y|%Z' "$target" >/dev/null 2>&1; then
    stat -c '%d|%i|%u|%a|%s|%Y|%Z' "$target"
  else
    stat -f '%d|%i|%u|%Lp|%z|%m|%c' "$target"
  fi
}

stat_stable_identity() {
  raw=$(stat_fields "$1") || return 1
  old_ifs=$IFS
  IFS='|'
  set -- $raw
  IFS=$old_ifs
  mode_decimal=$((0$4))
  printf '%s|%s|%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$mode_decimal" "$5" "$6" "$7"
}

stat_identity() {
  stable=$(stat_stable_identity "$1") || return 1
  printf '%s\n' "$stable" | awk -F'|' '{ print $1 "|" $2 "|" $3 "|" $4 }'
}

sha256_stream() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{ print $1 }'
  else
    die "A SHA-256 utility is required."
  fi
}

stable_sha256_file() {
  target=$1
  [ -f "$target" ] && [ ! -L "$target" ] || die "Locked file missing or symlinked: $target"
  before=$(stat_stable_identity "$target") || die "Locked file cannot be stated: $target"
  if command -v sha256sum >/dev/null 2>&1; then
    digest=$(sha256sum "$target" | awk '{ print $1 }')
  elif command -v shasum >/dev/null 2>&1; then
    digest=$(shasum -a 256 "$target" | awk '{ print $1 }')
  else
    die "A SHA-256 utility is required."
  fi
  after=$(stat_stable_identity "$target") || die "Locked file cannot be restated: $target"
  [ "$before" = "$after" ] || die "Locked file changed while being read: $target"
  printf '%s\n' "$digest"
}

assert_safe_absolute_path() {
  value=$1
  case "$value" in /*) ;; *) die "Locked path is not absolute." ;; esac
  case "$value" in
    *[!A-Za-z0-9_./-]*|*//*|*/../*|*/..|*/./*|*/.) die "Locked path contains unsupported syntax." ;;
  esac
}

assert_no_symlink_components() {
  value=$1
  assert_safe_absolute_path "$value"
  remainder=${value#/}
  cursor=
  while [ -n "$remainder" ]; do
    case "$remainder" in
      */*) component=${remainder%%/*}; remainder=${remainder#*/} ;;
      *) component=$remainder; remainder= ;;
    esac
    cursor=$cursor/$component
    [ ! -L "$cursor" ] || die "Snapshot path contains a symlink component: $cursor"
    stat_fields "$cursor" >/dev/null 2>&1 || die "Snapshot path component is missing: $cursor"
  done
}

[ -f "$LOCK" ] && [ ! -L "$LOCK" ] || die "Hosted workload lock must be a regular non-symlink file."
lock_before=$(stat_stable_identity "$LOCK") || die "Hosted workload lock cannot be stated."
lock_mode=$(printf '%s\n' "$lock_before" | awk -F'|' '{ print $4 }')
lock_uid=$(printf '%s\n' "$lock_before" | awk -F'|' '{ print $3 }')
case "$lock_mode" in 384|256) ;; *) die "Hosted workload lock must use mode 0600 or 0400." ;; esac
[ "$lock_uid" = "$(id -u)" ] || die "Hosted workload lock must be owned by the deployment identity."

if [ "${HOSTED_WORKLOAD_ALLOW_RESOLVED:-0}" = 1 ]; then
  allow_resolved=true
else
  allow_resolved=false
fi

jq -e --arg lockPath "$LOCK" --argjson allowResolved "$allow_resolved" --argjson controls "$RAW_POLICY_CONTROLS" '
  def record_sort: sort_by([(.workloadId // ""), (.kind // ""), (.sourcePath // ""), (.path // "")]);
  . as $lock
  | ($lock.workloads | map(.id)) as $workload_ids
  | ($lock.files | map(.path)) as $file_paths
  | ($lock.files | map(select(.kind == "catalog" and ((.workloadId // null) == null)))) as $catalog_records
  | ($lock.files | map(select(.kind == "core-environment" and ((.workloadId // null) == null)))) as $core_environment_records
  | ($lock.files | map(select(.kind == "core-compose" and ((.workloadId // null) == null)))) as $core_records
  | $lock.version == 2
    and $lock.validatorVersion == "hosted-contract-v2"
    and (if $allowResolved then ($lock.state == "resolved" or $lock.state == "verified") else $lock.state == "verified" end)
    and ($lock.snapshotRoot | type == "string" and length > 0)
    and ($lock.snapshotGeneration | type == "string" and length > 0)
    and ($lock.activationLockPath | type == "string" and length > 0)
    and (if $lock.state == "verified" then $lock.activationLockPath == $lockPath else true end)
    and ($lock.snapshotParentIdentity.mode == 448)
    and ($lock.snapshotRootIdentity.mode == 448)
    and ($lock.snapshotGenerationIdentity.mode == 320)
    and ($lock.snapshotDurability == {
      version: 1,
      filesFsynced: true,
      generationDirectoryFsynced: true,
      rootDirectoryFsynced: true
    })
    and ($lock.workloadContentSha256 | type == "string" and test("^[a-f0-9]{64}$"))
    and ($lock.files | type == "array" and length > 0)
    and ($lock.workloads | type == "array")
    and ($lock.coreFiles | type == "array")
    and (($file_paths | unique | length) == ($file_paths | length))
    and (($workload_ids | unique | length) == ($workload_ids | length))
    and all($lock.workloads[]; (.id | type == "string" and test("^[a-z][a-z0-9-]{1,62}$")))
    and all($lock.files[];
      (.kind | type == "string" and length > 0)
      and (.path | type == "string" and length > 0)
      and (.sha256 | type == "string" and test("^[a-f0-9]{64}$"))
      and (.sizeBytes | type == "number" and . >= 0))
    and ($catalog_records | length == 1 and .[0].snapshot == true)
    and ($core_environment_records | length == 1 and .[0].snapshot != true and .[0].path == $lock.coreEnvFile)
    and (($core_records | map(.path) | sort) == ($lock.coreFiles | unique | sort))
    and all($lock.workloads[];
      . as $workload
      | ($lock.files | map(select(.workloadId == $workload.id))) as $related
      | ($related | map(select(.kind == "workload-manifest"))) as $manifest
      | ($related | map(select(.kind == "workload-compose"))) as $compose
      | ($related | map(select(.kind == "workload-environment"))) as $environment
      | ($related | map(select(.kind == "project-metadata"))) as $metadata
      | ($manifest | length == 1)
        and ($compose | length == 1)
        and ($environment | length == 1)
        and ($metadata | length <= 1)
        and ($workload.manifestPath == $manifest[0].path)
        and ($workload.manifestSourcePath == $manifest[0].sourcePath)
        and ($workload.composePath == $compose[0].path)
        and ($workload.composeSourcePath == $compose[0].sourcePath)
        and ($workload.environmentPath == $environment[0].path)
        and ($workload.environmentSourcePath == $environment[0].sourcePath)
        and (($workload.projectMetadataPath // null) == ($metadata[0].path // null))
        and (($workload.projectMetadataSourcePath // null) == ($metadata[0].sourcePath // null))
        and all($related[];
          . as $related_record
          | $related_record.snapshot == true
          and (["workload-manifest", "workload-compose", "workload-environment", "project-metadata", "migration"] | index($related_record.kind)) != null)
        and (($workload.files | record_sort) == ($related | record_sort)))
    and all($lock.files[];
      . as $record
      | if $record.kind == "catalog" then (($record.workloadId // null) == null and $record.snapshot == true)
        elif $record.kind == "core-environment" or $record.kind == "core-compose" then (($record.workloadId // null) == null and $record.snapshot != true)
        else (($workload_ids | index($record.workloadId)) != null and $record.snapshot == true)
        end)
    and $lock.rawPolicyVersion == "hosted-raw-v1"
    and $lock.rawPolicyWorkloadContentSha256 == $lock.workloadContentSha256
    and $lock.rawPolicyControls == $controls
    and (($lock.rawPolicySha256 | type) == "string" and ($lock.rawPolicySha256 | test("^[a-f0-9]{64}$")))
    and (($lock.rawPolicyReceipt | keys | sort) == ["controls", "policyVersion", "workloadContentSha256", "workloads"])
    and $lock.rawPolicyReceipt.policyVersion == $lock.rawPolicyVersion
    and $lock.rawPolicyReceipt.controls == $controls
    and $lock.rawPolicyReceipt.workloadContentSha256 == $lock.workloadContentSha256
    and (($lock.rawPolicyReceipt.workloads | map(.workloadId) | sort) == ($workload_ids | sort))
    and all($lock.rawPolicyReceipt.workloads[];
      . as $receipt
      | ($lock.files | map(select(.kind == "workload-compose" and .workloadId == $receipt.workloadId))) as $compose
      | ($lock.workloads | map(select(.id == $receipt.workloadId))[0]) as $workload
      | (($receipt | keys | sort) == ["composeSha256", "serviceNames", "topLevelKeys", "workloadId"])
        and ($receipt.serviceNames | type == "array")
        and ($receipt.topLevelKeys | type == "array")
        and ($receipt.serviceNames == ($receipt.serviceNames | unique | sort))
        and ($receipt.topLevelKeys == ($receipt.topLevelKeys | unique | sort))
        and (($receipt.topLevelKeys | index("services")) != null)
        and ($compose | length == 1 and $receipt.composeSha256 == $compose[0].sha256)
        and (([$workload.services[].name] - $receipt.serviceNames) | length == 0))
' "$LOCK" >/dev/null

snapshot_root=$(jq -r '.snapshotRoot' "$LOCK")
snapshot_generation=$(jq -r '.snapshotGeneration' "$LOCK")
activation_lock_path=$(jq -r '.activationLockPath' "$LOCK")
snapshot_parent=$(dirname -- "$snapshot_root")
lock_directory=$(dirname -- "$LOCK")
assert_no_symlink_components "$lock_directory"
assert_no_symlink_components "$snapshot_parent"
assert_no_symlink_components "$snapshot_root"
assert_no_symlink_components "$snapshot_generation"
[ -d "$lock_directory" ] && [ ! -L "$lock_directory" ] || die "Lock parent must be a real directory."
[ -d "$snapshot_parent" ] && [ ! -L "$snapshot_parent" ] || die "Snapshot parent must be a real directory."
[ -d "$snapshot_root" ] && [ ! -L "$snapshot_root" ] || die "Snapshot root must be a real directory."
[ -d "$snapshot_generation" ] && [ ! -L "$snapshot_generation" ] || die "Snapshot generation must be a real directory."
[ "$(dirname -- "$snapshot_generation")" = "$snapshot_root" ] || die "Snapshot generation is outside the locked snapshot root."
[ "$(dirname -- "$activation_lock_path")" = "$snapshot_parent" ] || die "Activation lock is outside the deployment-private snapshot parent."
if [ "$(jq -r '.state' "$LOCK")" = verified ]; then
  [ "$lock_directory" = "$snapshot_parent" ] || die "Verified lock is outside the deployment-private snapshot parent."
fi

expected_parent_identity=$(jq -r '.snapshotParentIdentity | [.device, .inode, .uid, .mode] | map(tostring) | join("|")' "$LOCK")
expected_root_identity=$(jq -r '.snapshotRootIdentity | [.device, .inode, .uid, .mode] | map(tostring) | join("|")' "$LOCK")
expected_generation_identity=$(jq -r '.snapshotGenerationIdentity | [.device, .inode, .uid, .mode] | map(tostring) | join("|")' "$LOCK")
actual_parent_identity=$(stat_identity "$snapshot_parent") || die "Snapshot parent identity is missing."
actual_root_identity=$(stat_identity "$snapshot_root") || die "Snapshot root identity is missing."
actual_generation_identity=$(stat_identity "$snapshot_generation") || die "Snapshot generation identity is missing."
[ "$actual_parent_identity" = "$expected_parent_identity" ] || die "Snapshot parent identity changed after resolution."
[ "$actual_root_identity" = "$expected_root_identity" ] || die "Snapshot root identity changed after resolution."
[ "$actual_generation_identity" = "$expected_generation_identity" ] || die "Snapshot generation identity changed after resolution."
deployment_uid=$(id -u)
lock_directory_identity=$(stat_identity "$lock_directory") || die "Lock parent identity is missing."
lock_directory_uid=$(printf '%s\n' "$lock_directory_identity" | awk -F'|' '{ print $3 }')
lock_directory_mode=$(printf '%s\n' "$lock_directory_identity" | awk -F'|' '{ print $4 }')
[ "$lock_directory_uid" = "$deployment_uid" ] && [ "$lock_directory_mode" = 448 ] || die "Lock parent must be deployment-owned with mode 0700."
[ "$(jq -r '.snapshotParentIdentity.uid | tostring' "$LOCK")" = "$deployment_uid" ] || die "Snapshot parent must be owned by the deployment identity."
[ "$(jq -r '.snapshotRootIdentity.uid | tostring' "$LOCK")" = "$deployment_uid" ] || die "Snapshot root must be owned by the deployment identity."
[ "$(jq -r '.snapshotGenerationIdentity.uid | tostring' "$LOCK")" = "$deployment_uid" ] || die "Snapshot generation must be owned by the deployment identity."

count=$(jq '.files | length' "$LOCK")
index=0
while [ "$index" -lt "$count" ]; do
  file=$(jq -r ".files[$index].path" "$LOCK")
  expected=$(jq -r ".files[$index].sha256" "$LOCK")
  snapshot=$(jq -r ".files[$index].snapshot == true" "$LOCK")
  assert_safe_absolute_path "$file"
  if [ "$snapshot" = true ]; then
    [ "$(dirname -- "$file")" = "$snapshot_generation" ] || die "Snapshot file is outside the locked generation: $file"
    expected_file_identity=$(jq -r ".files[$index] | [.snapshotDevice, .snapshotInode, .snapshotUid, 256] | map(tostring) | join(\"|\")" "$LOCK")
    actual_file_identity=$(stat_identity "$file") || die "Snapshot file identity is missing: $file"
    [ "$actual_file_identity" = "$expected_file_identity" ] || die "Snapshot file identity, owner, or mode changed: $file"
    [ "$(jq -r ".files[$index].snapshotUid | tostring" "$LOCK")" = "$deployment_uid" ] || die "Snapshot file owner differs from the deployment identity: $file"
  fi
  actual=$(stable_sha256_file "$file")
  [ "$actual" = "$expected" ] || die "Locked file changed: $file"
  index=$((index + 1))
done

content_json=$(jq -cSj '[.files[] | select(.snapshot == true) | {kind, sourcePath, sha256, sizeBytes, workloadId:(.workloadId // null)}] | sort_by(((.workloadId | tostring) + ":" + .kind + ":" + .sourcePath))' "$LOCK")
actual_content_sha256=$(printf '%s' "$content_json" | sha256_stream)
[ "$actual_content_sha256" = "$(jq -r '.workloadContentSha256' "$LOCK")" ] || die "Hosted workload content digest does not match its snapshot records."
receipt_json=$(jq -cSj '.rawPolicyReceipt' "$LOCK")
actual_receipt_sha256=$(printf '%s' "$receipt_json" | sha256_stream)
[ "$actual_receipt_sha256" = "$(jq -r '.rawPolicySha256' "$LOCK")" ] || die "Hosted workload raw policy receipt digest is invalid."

catalog_path=$(jq -r '.files[] | select(.kind == "catalog" and ((.workloadId // null) == null)) | .path' "$LOCK")
jq -e --slurpfile catalog "$catalog_path" '
  def relative_to($root): if startswith($root + "/") then .[($root | length) + 1:] else null end;
  . as $lock
  | ($catalog[0]) as $document
  | ($document.version == 1)
    and (($document.workloads | type) == "array")
    and (($document.workloads | map({manifest, environmentFile}) | sort_by(.manifest))
      == ($lock.workloads | map({
          manifest: (.manifestSourcePath | relative_to($lock.workloadRoot)),
          environmentFile: (.environmentSourcePath | relative_to($lock.workloadRoot))
        }) | sort_by(.manifest)))
' "$LOCK" >/dev/null

jq -r '.workloads[].id' "$LOCK" | while IFS= read -r workload_id; do
  manifest_path=$(jq -r --arg id "$workload_id" '.workloads[] | select(.id == $id) | .manifestPath' "$LOCK")
  jq -e --arg id "$workload_id" --slurpfile manifest "$manifest_path" '
    def unique_preserve: reduce .[] as $item ([]; if index($item) == null then . + [$item] else . end);
    def normalized_manifest:
      {
        version,
        id: (.id | ascii_downcase),
        composeFile,
        projectMetadataFile: (.projectMetadataFile // null),
        services: [.services[] | {
          name: (.name | ascii_downcase),
          role: (.role | ascii_downcase),
          routes: [(.routes // [])[] | {slug: (.slug | ascii_downcase), port: (.port | tonumber)}]
        }],
        secrets: ((.secrets // []) | unique | sort),
        migrationRoots: ((.migrationRoots // []) | unique_preserve)
      };
    .workloads[] | select(.id == $id) as $workload
    | ($manifest[0] | normalized_manifest) == ($workload | {
        version, id, composeFile, projectMetadataFile: (.projectMetadataFile // null),
        services, secrets, migrationRoots
      })
  ' "$LOCK" >/dev/null
done

case "$COMMAND" in
  verify) command_output= ;;
  compose-files) command_output=$(jq -r '.workloads[].composePath' "$LOCK") ;;
  env-files) command_output=$(jq -r '.workloads[].environmentPath' "$LOCK") ;;
  core-env-file) command_output=$(jq -r '.coreEnvFile' "$LOCK") ;;
  project-name) command_output=$(jq -r '.projectName' "$LOCK") ;;
esac

lock_after=$(stat_stable_identity "$LOCK") || die "Hosted workload lock cannot be restated."
[ "$lock_before" = "$lock_after" ] || die "Hosted workload lock changed while being verified."
[ -z "$command_output" ] || printf '%s\n' "$command_output"
