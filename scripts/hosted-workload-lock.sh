#!/usr/bin/env sh
set -eu

LOCK=${1:?Usage: hosted-workload-lock.sh <lock-file> [verify|compose-records|activation-bundle]}
COMMAND=${2:-verify}
RAW_POLICY_CONTROLS='["bind-bounded-dependencies","bind-bounded-local-logging","bind-closed-service-schema","bind-exact-healthcheck","bind-exact-security-opt","bind-exact-ulimits","bind-exact-volume-mounts","bind-firewall-gated-restart","bind-network-identity","bind-network-topology","bind-no-swap-oom-policy","bind-owned-secret-aliases","bind-owned-volume-driver","bind-owned-volumes","bind-platform-extension-records","bind-private-pid-numeric-user","deny-accelerator-environment","deny-api-socket","deny-compose-interpolation","deny-deploy-controls","deny-device-access","deny-env-file","deny-extends","deny-file-configs","deny-generic-resources","deny-gpu-access","deny-include","deny-inline-configs","deny-label-file","deny-lifecycle-hooks","deny-local-volume-options","deny-providers","deny-runtime-identity-labels","deny-runtime-overrides","deny-scaling","deny-stop-grace-overrides","deny-supplemental-groups","deny-volumes-from"]'

case "$COMMAND" in
  verify|compose-records|env-records|core-env-file|project-name|activation-bundle) ;;
  *) printf '%s\n' "Command must be verify, compose-records, env-records, core-env-file, project-name or activation-bundle." >&2; exit 2 ;;
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

umask 077
LOCK_READ_DIRECTORY=$(mktemp -d "${TMPDIR:-/tmp}/hosted-workload-lock.XXXXXX") || die "Could not allocate a private lock read snapshot."
LOCK_READ=$LOCK_READ_DIRECTORY/lock.json
cleanup_lock_read() {
  [ ! -e "$LOCK_READ" ] || /bin/rm -- "$LOCK_READ" >/dev/null 2>&1 || :
  [ ! -d "$LOCK_READ_DIRECTORY" ] || /bin/rmdir -- "$LOCK_READ_DIRECTORY" >/dev/null 2>&1 || :
}
trap cleanup_lock_read 0
exec 3<"$LOCK" || die "Hosted workload lock cannot be opened."
exec 4<"$LOCK" || die "Hosted workload lock cannot be opened for its final digest."
lock_descriptor_identity=$(stat_stable_identity /dev/fd/3) || die "Hosted workload lock descriptor cannot be stated."
lock_digest_descriptor_identity=$(stat_stable_identity /dev/fd/4) || die "Hosted workload lock digest descriptor cannot be stated."
lock_before_read_identity=$(printf '%s\n' "$lock_before" | awk -F'|' '{ print $2 "|" $3 "|" $5 "|" $6 "|" $7 }')
lock_descriptor_read_identity=$(printf '%s\n' "$lock_descriptor_identity" | awk -F'|' '{ print $2 "|" $3 "|" $5 "|" $6 "|" $7 }')
lock_digest_descriptor_read_identity=$(printf '%s\n' "$lock_digest_descriptor_identity" | awk -F'|' '{ print $2 "|" $3 "|" $5 "|" $6 "|" $7 }')
[ "$lock_before_read_identity" = "$lock_descriptor_read_identity" ] \
  && [ "$lock_before_read_identity" = "$lock_digest_descriptor_read_identity" ] \
  || die "Hosted workload lock changed before its read-once snapshot."
set -C
if ! eval 'exec 5>"$LOCK_READ"'; then
  set +C
  die "Could not exclusively create the private lock read snapshot."
fi
set +C
exec 6<"$LOCK_READ" || die "Private lock read snapshot cannot be opened."
lock_snapshot_path_identity=$(stat_stable_identity "$LOCK_READ") || die "Private lock read snapshot cannot be stated."
lock_snapshot_write_identity=$(stat_stable_identity /dev/fd/5) || die "Private lock write descriptor cannot be stated."
lock_snapshot_read_identity=$(stat_stable_identity /dev/fd/6) || die "Private lock read descriptor cannot be stated."
lock_snapshot_path_object=$(printf '%s\n' "$lock_snapshot_path_identity" | awk -F'|' '{ print $2 "|" $3 }')
lock_snapshot_write_object=$(printf '%s\n' "$lock_snapshot_write_identity" | awk -F'|' '{ print $2 "|" $3 }')
lock_snapshot_read_object=$(printf '%s\n' "$lock_snapshot_read_identity" | awk -F'|' '{ print $2 "|" $3 }')
[ "$lock_snapshot_path_object" = "$lock_snapshot_write_object" ] \
  && [ "$lock_snapshot_path_object" = "$lock_snapshot_read_object" ] \
  || die "Private lock snapshot descriptors do not reference one object."
/bin/rm -- "$LOCK_READ" || die "Private lock snapshot could not be unlinked before use."
/bin/rmdir -- "$LOCK_READ_DIRECTORY" || die "Private lock snapshot directory could not be removed before use."
trap - 0
/bin/cat <&3 >&5 || die "Hosted workload lock could not be materialized once."
lock_descriptor_after_copy=$(stat_stable_identity /dev/fd/3) || die "Hosted workload lock descriptor cannot be restated."
[ "$lock_descriptor_identity" = "$lock_descriptor_after_copy" ] || die "Hosted workload lock changed while being snapshotted."
exec 3<&-
exec 5>&-
LOCK_JSON=$(/bin/cat <&6; printf '.')
LOCK_JSON=${LOCK_JSON%.}
exec 6<&-
lock_read_sha256=$(printf '%s' "$LOCK_JSON" | sha256_stream)
lock_source_sha256=$(sha256_stream <&4)
lock_digest_descriptor_after=$(stat_stable_identity /dev/fd/4) || die "Hosted workload lock digest descriptor cannot be restated."
exec 4<&-
[ "$lock_digest_descriptor_identity" = "$lock_digest_descriptor_after" ] || die "Hosted workload lock changed while its snapshot digest was bound."
[ "$lock_read_sha256" = "$lock_source_sha256" ] || die "Hosted workload lock bytes changed during their read-once snapshot."
lock_after_snapshot=$(stat_stable_identity "$LOCK") || die "Hosted workload lock cannot be restated after its read-once snapshot."
[ "$lock_before" = "$lock_after_snapshot" ] || die "Hosted workload lock path changed during its read-once snapshot."

jq_lock() {
  printf '%s' "$LOCK_JSON" | jq "$@"
}

if [ "${HOSTED_WORKLOAD_ALLOW_RESOLVED:-0}" = 1 ]; then
  allow_resolved=true
else
  allow_resolved=false
fi

jq_lock -e --arg lockPath "$LOCK" --argjson allowResolved "$allow_resolved" --argjson controls "$RAW_POLICY_CONTROLS" '
  def record_sort: sort_by([(.workloadId // ""), (.kind // ""), (.sourcePath // ""), (.path // "")]);
  def prefix_disjoint:
    . as $ids
    | all($ids[];
        . as $left
        | all($ids[];
            . as $right
            | $left == $right
              or (((($left | startswith($right + "-")) | not))
                and ((($right | startswith($left + "-")) | not)))));
  def protected_resource_names:
    type == "object"
    and ((keys | sort) == ["configs", "networks", "secrets", "services", "volumes"])
    and all(.[]; type == "array" and . == (unique | sort) and all(.[]; type == "string" and length > 0));
  def hyphen_owner($name; $ids):
    [$ids[] as $id
      | select(($name | type) == "string" and ($name | startswith($id + "-")))
      | $id]
    | if length == 1 then .[0] else null end;
  def volume_owner($name; $ids):
    [$ids[] as $id
      | select(($name | type) == "string" and ($name | startswith($id + "_")))
      | $id]
    | if length == 1 then .[0] else null end;
  def network_owner($name; $ids):
    [$ids[] as $id
      | ["ingress", "postgres", "cache", "bus", "identity", "storage", "observability", "egress"][] as $zone
      | select(($name | type) == "string"
        and $name == (($id | gsub("-"; "_")) + "_" + $zone))
      | $id]
    | if length == 1 then .[0] else null end;
  . as $lock
  | ($lock.workloads | map(.id)) as $workload_ids
  | ($lock.files | map(.path)) as $file_paths
  | ($lock.files | map(select(.kind == "catalog" and ((.workloadId // null) == null)))) as $catalog_records
  | ($lock.files | map(select(.kind == "core-environment" and ((.workloadId // null) == null)))) as $core_environment_records
  | ($lock.files | map(select(.kind == "core-compose" and ((.workloadId // null) == null)))) as $core_records
  | $lock.version == 4
    and $lock.validatorVersion == "hosted-contract-v4"
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
    and ($lock.projectName | type == "string" and test("^[a-z0-9][a-z0-9_-]*$"))
    and (($file_paths | unique | length) == ($file_paths | length))
    and (($workload_ids | unique | length) == ($workload_ids | length))
    and ($workload_ids | prefix_disjoint)
    and all($lock.workloads[]; (.id | type == "string" and test("^[a-z][a-z0-9-]{1,62}$")))
    and all($lock.files[];
      (.kind | type == "string" and length > 0)
      and (.path | type == "string" and length > 0)
      and (.sha256 | type == "string" and test("^[a-f0-9]{64}$"))
      and (.sizeBytes | type == "number" and . >= 0)
      and (if .snapshot == true then true else
        (.device | type == "string" and test("^[0-9]+$"))
        and (.inode | type == "string" and test("^[0-9]+$"))
        and (.uid | type == "string" and test("^[0-9]+$"))
        and (.mode | type == "number" and . >= 0 and . <= 511)
      end))
    and (if $lock.state == "verified" then
      ($lock.coreRenderSha256 | type == "string" and test("^[a-f0-9]{64}$"))
      and ($lock.combinedRenderSha256 | type == "string" and test("^[a-f0-9]{64}$"))
    else true end)
    and ($catalog_records | length == 1 and .[0].snapshot == true)
    and ($core_environment_records | length == 1
      and .[0] as $core_environment_record
      | $core_environment_record.snapshot != true
      and $core_environment_record.path == $lock.coreEnvFile
      and ([256, 384] | index($core_environment_record.mode)) != null)
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
    and $lock.rawPolicyVersion == "hosted-raw-v3"
    and $lock.rawPolicyWorkloadContentSha256 == $lock.workloadContentSha256
    and $lock.rawPolicyControls == $controls
    and (($lock.rawPolicySha256 | type) == "string" and ($lock.rawPolicySha256 | test("^[a-f0-9]{64}$")))
    and (($lock.rawPolicyReceipt | keys | sort) == ["controls", "policyVersion", "protectedNetworkNames", "protectedResourceNames", "workloadContentSha256", "workloads"])
    and $lock.rawPolicyReceipt.policyVersion == $lock.rawPolicyVersion
    and $lock.rawPolicyReceipt.controls == $controls
    and ($lock.rawPolicyReceipt.protectedNetworkNames | type == "array")
    and ($lock.rawPolicyReceipt.protectedNetworkNames == ($lock.rawPolicyReceipt.protectedNetworkNames | unique | sort))
    and all($lock.rawPolicyReceipt.protectedNetworkNames[]; type == "string" and length > 0)
    and ($lock.rawPolicyReceipt.protectedResourceNames | protected_resource_names)
    and ($lock.rawPolicyReceipt.protectedResourceNames.networks == $lock.rawPolicyReceipt.protectedNetworkNames)
    and $lock.rawPolicyReceipt.workloadContentSha256 == $lock.workloadContentSha256
    and (($lock.rawPolicyReceipt.workloads | map(.workloadId) | sort) == ($workload_ids | sort))
    and (([$lock.rawPolicyReceipt.workloads[].serviceNames[]] | length)
      == ([$lock.rawPolicyReceipt.workloads[].serviceNames[]] | unique | length))
    and (([$lock.rawPolicyReceipt.workloads[].secretNames[]] | length)
      == ([$lock.rawPolicyReceipt.workloads[].secretNames[]] | unique | length))
    and (([$lock.rawPolicyReceipt.workloads[].volumeNames[]] | length)
      == ([$lock.rawPolicyReceipt.workloads[].volumeNames[]] | unique | length))
    and (([$lock.rawPolicyReceipt.workloads[].networkNames[]] | length)
      == ([$lock.rawPolicyReceipt.workloads[].networkNames[]] | unique | length))
    and all($lock.rawPolicyReceipt.workloads[];
      . as $receipt
      | ($lock.files | map(select(.kind == "workload-compose" and .workloadId == $receipt.workloadId))) as $compose
      | ($lock.workloads | map(select(.id == $receipt.workloadId))[0]) as $workload
      | (($receipt | keys | sort) == ["composeSha256", "configNames", "networkNames", "platformExtensions", "secretNames", "serviceNames", "topLevelKeys", "volumeNames", "workloadId"])
        and ($receipt.configNames == [])
        and ($receipt.networkNames | type == "array")
        and ($receipt.networkNames == ($receipt.networkNames | unique | sort))
        and (($receipt.networkNames - $lock.rawPolicyReceipt.protectedNetworkNames) == $receipt.networkNames)
        and all($receipt.networkNames[]; network_owner(.; $workload_ids) == $receipt.workloadId)
        and ($receipt.serviceNames | type == "array")
        and ($receipt.secretNames | type == "array")
        and ($receipt.volumeNames | type == "array")
        and ($receipt.topLevelKeys | type == "array")
        and ($receipt.serviceNames == ($receipt.serviceNames | unique | sort))
        and ($receipt.secretNames == ($receipt.secretNames | unique | sort))
        and ($receipt.volumeNames == ($receipt.volumeNames | unique | sort))
        and ($receipt.topLevelKeys == ($receipt.topLevelKeys | unique | sort))
        and all($receipt.serviceNames[]; hyphen_owner(.; $workload_ids) == $receipt.workloadId)
        and all($receipt.secretNames[]; hyphen_owner(.; $workload_ids) == $receipt.workloadId)
        and all($receipt.volumeNames[]; volume_owner(.; $workload_ids) == $receipt.workloadId)
        and (($receipt.topLevelKeys | index("services")) != null)
        and ($compose | length == 1 and $receipt.composeSha256 == $compose[0].sha256)
        and ($receipt.serviceNames == ([$workload.services[].name] | unique | sort))
        and ($receipt.secretNames == ($workload.secrets | unique | sort))
        and (($receipt.secretNames - $lock.rawPolicyReceipt.protectedResourceNames.secrets) == $receipt.secretNames)
        and (($receipt.volumeNames - $lock.rawPolicyReceipt.protectedResourceNames.volumes) == $receipt.volumeNames)
        and (($receipt.serviceNames - $lock.rawPolicyReceipt.protectedResourceNames.services) == $receipt.serviceNames)
        and ($receipt.platformExtensions | type == "array")
        and ($receipt.platformExtensions == ($receipt.platformExtensions | unique_by(.serviceName) | sort_by(.serviceName)))
        and all($receipt.platformExtensions[];
          ((keys | sort) == ["networkNames", "serviceName"])
          and (.serviceName | IN("project-router", "postgres", "redis", "nats", "keycloak", "minio", "prometheus"))
          and (.networkNames | type == "array" and length > 0 and . == (unique | sort))
          and ((.networkNames - $receipt.networkNames) == [])))
' >/dev/null || die "Hosted workload lock schema or canonical ownership is invalid."

snapshot_root=$(jq_lock -r '.snapshotRoot')
snapshot_generation=$(jq_lock -r '.snapshotGeneration')
activation_lock_path=$(jq_lock -r '.activationLockPath')
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
if [ "$(jq_lock -r '.state')" = verified ]; then
  [ "$lock_directory" = "$snapshot_parent" ] || die "Verified lock is outside the deployment-private snapshot parent."
fi

expected_parent_identity=$(jq_lock -r '.snapshotParentIdentity | [.device, .inode, .uid, .mode] | map(tostring) | join("|")')
expected_root_identity=$(jq_lock -r '.snapshotRootIdentity | [.device, .inode, .uid, .mode] | map(tostring) | join("|")')
expected_generation_identity=$(jq_lock -r '.snapshotGenerationIdentity | [.device, .inode, .uid, .mode] | map(tostring) | join("|")')
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
[ "$(jq_lock -r '.snapshotParentIdentity.uid | tostring')" = "$deployment_uid" ] || die "Snapshot parent must be owned by the deployment identity."
[ "$(jq_lock -r '.snapshotRootIdentity.uid | tostring')" = "$deployment_uid" ] || die "Snapshot root must be owned by the deployment identity."
[ "$(jq_lock -r '.snapshotGenerationIdentity.uid | tostring')" = "$deployment_uid" ] || die "Snapshot generation must be owned by the deployment identity."
core_environment_uid=$(jq_lock -r '.files[] | select(.kind == "core-environment" and ((.workloadId // null) == null)) | .uid')
core_environment_mode=$(jq_lock -r '.files[] | select(.kind == "core-environment" and ((.workloadId // null) == null)) | .mode')
[ "$core_environment_uid" = "$deployment_uid" ] \
  && { [ "$core_environment_mode" = 256 ] || [ "$core_environment_mode" = 384 ]; } \
  || die "Core environment must be deployment-owned with mode 0400 or 0600."

count=$(jq_lock '.files | length')
index=0
while [ "$index" -lt "$count" ]; do
  file=$(jq_lock -r ".files[$index].path")
  expected=$(jq_lock -r ".files[$index].sha256")
  snapshot=$(jq_lock -r ".files[$index].snapshot == true")
  assert_safe_absolute_path "$file"
  if [ "$snapshot" = true ]; then
    [ "$(dirname -- "$file")" = "$snapshot_generation" ] || die "Snapshot file is outside the locked generation: $file"
    expected_file_identity=$(jq_lock -r ".files[$index] | [.snapshotDevice, .snapshotInode, .snapshotUid, 256] | map(tostring) | join(\"|\")")
    actual_file_identity=$(stat_identity "$file") || die "Snapshot file identity is missing: $file"
    [ "$actual_file_identity" = "$expected_file_identity" ] || die "Snapshot file identity, owner, or mode changed: $file"
    [ "$(jq_lock -r ".files[$index].snapshotUid | tostring")" = "$deployment_uid" ] || die "Snapshot file owner differs from the deployment identity: $file"
  else
    expected_file_identity=$(jq_lock -r ".files[$index] | [.device, .inode, .uid, .mode] | map(tostring) | join(\"|\")")
    actual_file_identity=$(stat_identity "$file") || die "Locked non-snapshot file identity is missing: $file"
    [ "$actual_file_identity" = "$expected_file_identity" ] || die "Locked non-snapshot file identity, owner, or mode changed: $file"
  fi
  actual=$(stable_sha256_file "$file")
  [ "$actual" = "$expected" ] || die "Locked file changed: $file"
  index=$((index + 1))
done

content_json=$(jq_lock -cSj '[.files[] | select(.snapshot == true) | {kind, sourcePath, sha256, sizeBytes, workloadId:(.workloadId // null)}] | sort_by(((.workloadId | tostring) + ":" + .kind + ":" + .sourcePath))')
actual_content_sha256=$(printf '%s' "$content_json" | sha256_stream)
[ "$actual_content_sha256" = "$(jq_lock -r '.workloadContentSha256')" ] || die "Hosted workload content digest does not match its snapshot records."
receipt_json=$(jq_lock -cSj '.rawPolicyReceipt')
actual_receipt_sha256=$(printf '%s' "$receipt_json" | sha256_stream)
[ "$actual_receipt_sha256" = "$(jq_lock -r '.rawPolicySha256')" ] || die "Hosted workload raw policy receipt digest is invalid."

catalog_path=$(jq_lock -r '.files[] | select(.kind == "catalog" and ((.workloadId // null) == null)) | .path')
jq_lock -e --slurpfile catalog "$catalog_path" '
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
' >/dev/null

jq_lock -r '.workloads[].id' | while IFS= read -r workload_id; do
  manifest_path=$(jq_lock -r --arg id "$workload_id" '.workloads[] | select(.id == $id) | .manifestPath')
  jq_lock -e --arg id "$workload_id" --slurpfile manifest "$manifest_path" '
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
  ' >/dev/null
done

case "$COMMAND" in
  verify) command_output= ;;
  compose-records) command_output=$(jq_lock -r '.workloads[] as $workload | .files[] | select(.kind == "workload-compose" and .workloadId == $workload.id and .path == $workload.composePath) | [.path, .sha256, (.snapshotDevice | tostring), (.snapshotInode | tostring), (.snapshotUid | tostring), "256"] | @tsv') ;;
  env-records) command_output=$(jq_lock -r '.workloads[] as $workload | .files[] | select(.kind == "workload-environment" and .workloadId == $workload.id and .path == $workload.environmentPath) | [.path, .sha256, (.snapshotDevice | tostring), (.snapshotInode | tostring), (.snapshotUid | tostring), "256"] | @tsv') ;;
  core-env-file) command_output=$(jq_lock -r '.coreEnvFile') ;;
  project-name) command_output=$(jq_lock -r '.projectName') ;;
  activation-bundle) command_output=$(jq_lock -c --arg lockSha256 "$lock_read_sha256" '
    . as $lock
    | {
      version: 2,
      lockSha256: $lockSha256,
      coreRenderSha256,
      combinedRenderSha256,
      coreEnvFile,
      coreEnvironmentRecord: (
        .files[]
        | select(.kind == "core-environment" and ((.workloadId // null) == null) and .path == $lock.coreEnvFile)
        | {path, sha256, device, inode, uid, mode}
      ),
      projectName,
      workloadIds: [.workloads[].id] | sort,
      protectedNetworkNames: .rawPolicyReceipt.protectedNetworkNames,
      protectedResourceNames: .rawPolicyReceipt.protectedResourceNames,
      networkRecords: [
        .rawPolicyReceipt.workloads[] as $workload
        | $workload.networkNames[]
        | {workloadId: $workload.workloadId, logicalName: ., physicalName: ($lock.projectName + "_" + .)}
      ] | sort_by(.workloadId, .logicalName),
      serviceRecords: [
        .rawPolicyReceipt.workloads[] as $workload
        | $workload.serviceNames[]
        | {workloadId: $workload.workloadId, serviceName: .}
      ] | sort_by(.workloadId, .serviceName),
      platformExtensionRecords: [
        .rawPolicyReceipt.workloads[] as $workload
        | $workload.platformExtensions[]
        | {workloadId: $workload.workloadId, serviceName, networkNames}
      ] | sort_by(.workloadId, .serviceName),
      routeRecords: [
        (.routes // [])[]
        | {workloadId, slug, serviceName: .service, port, upstream}
      ] | sort_by(.workloadId, .slug),
      environmentRecords: [
        .workloads[] as $workload
        | .files[]
        | select(.kind == "workload-environment" and .workloadId == $workload.id and .path == $workload.environmentPath)
        | {path, sha256, device: (.snapshotDevice | tostring), inode: (.snapshotInode | tostring), uid: (.snapshotUid | tostring), mode: 256}
      ],
      composeRecords: [
        .workloads[] as $workload
        | .files[]
        | select(.kind == "workload-compose" and .workloadId == $workload.id and .path == $workload.composePath)
        | {path, sha256, device: (.snapshotDevice | tostring), inode: (.snapshotInode | tostring), uid: (.snapshotUid | tostring), mode: 256}
      ]
    }
  ') ;;
esac

[ -z "$command_output" ] || printf '%s\n' "$command_output"
