#!/usr/bin/env sh
set -eu

artifact_receipt=${1:-}
deployment_receipt=${2:-}
candidate_compose=${3:-}
previous_compose=${4:-}

require_private_input() {
  label=$1
  file=$2
  [ -f "$file" ] && [ -r "$file" ] && [ -s "$file" ] && [ ! -L "$file" ] || {
    echo "$label must be a readable, non-empty regular file, not a symlink." >&2
    exit 1
  }
}

require_private_input "Artifact verification receipt" "$artifact_receipt"
require_private_input "Trusted deployment receipt" "$deployment_receipt"
require_private_input "Candidate Compose model" "$candidate_compose"

jq -e -s '
  def digest_image:
    type == "string" and test("^[a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)+@sha256:[a-f0-9]{64}$");
  def exact_subject($receipt; $deployment; $compose; $key; $service):
    ([ $receipt.subjects[] | select(.key == $key) ] | length == 1) and
    ([ $receipt.subjects[] | select(.key == $key) ][0].image) as $image |
    ([ $receipt.subjectVerificationReceipts[] | select(.key == $key and .image == $image) ] | length == 1) and
    ([ $receipt.subjectVerificationReceipts[] | select(.key == $key and .image == $image) ][0].registry.platforms) as $platforms |
    ($platforms | type == "array" and length == 1) and
    ($platforms[0].platform == "linux/amd64") and
    ($platforms[0].digest | type == "string" and test("^sha256:[a-f0-9]{64}$")) and
    ($platforms[0].imageId | type == "string" and test("^sha256:[a-f0-9]{64}$")) and
    ($platforms[0].imageId != $platforms[0].digest) and
    ($platforms[0].imageId != ($image | split("@") | .[1])) and
    ($image | digest_image) and
    ([ $receipt.subjects[] | select(.key == $key) ][0].key == $key) and
    ([ $receipt.subjects[] | select(.key == $key) ][0].image == $image) and
    ([ $deployment.runtimeIntent.services[]
       | select(.service == $service and .admission.kind == "artifact-subject" and .admission.subjectKey == $key and .image == $image)
     ] | length == 1) and
    ([ $deployment.runtimeIntent.services[] | select(.service == $service) ][0].expectedLocalImageId == $platforms[0].imageId) and
    ($compose.services[$service].image == $image);
  .[0] as $receipt | .[1] as $deployment | .[2] as $compose |
  ($receipt.subjects | type == "array" and length == 4) and
  (($receipt.subjects | map(.key) | sort) == ["CONTROL_CENTER_IMAGE", "PLATFORM_ALERT_DISPATCHER_IMAGE", "PLATFORM_BACKUP_SCHEDULER_IMAGE", "PROJECT_ROUTER_IMAGE"]) and
  ($receipt.subjectVerificationReceipts | type == "array" and length == 4) and
  (($receipt.subjectVerificationReceipts | map(.key) | sort) == ["CONTROL_CENTER_IMAGE", "PLATFORM_ALERT_DISPATCHER_IMAGE", "PLATFORM_BACKUP_SCHEDULER_IMAGE", "PROJECT_ROUTER_IMAGE"]) and
  ($deployment.opsRunner.image | digest_image) and
  ($deployment.opsRunner.imageId | type == "string" and test("^sha256:[a-f0-9]{64}$")) and
  ($deployment.opsRunner.providerAttested == true) and
  ($deployment.runtimeIntentSha256 | type == "string" and test("^[a-f0-9]{64}$")) and
  ($deployment.runtimeIntent.version == 2) and
  ($deployment.runtimeIntent.kind == "platform-runtime-intent/v2") and
  ($deployment.runtimeIntent.projectName == "platform_infra_vps") and
  ($deployment.runtimeIntent.sourceRenderSha256 | type == "string" and test("^[a-f0-9]{64}$")) and
  ($deployment.runtimeIntent.combinedComposeSha256 | type == "string" and test("^[a-f0-9]{64}$")) and
  ($deployment.runtimeIntent.sourceRenderSha256 != $deployment.runtimeIntent.combinedComposeSha256) and
  ($deployment.runtimeIntent.persistentVolumes | type == "array" and length == 1) and
  ($deployment.runtimeIntent.persistentVolumes[0] as $volume |
    (($volume | keys | sort) == ["createdAt", "driver", "labels", "mountpoint", "name", "options", "owner", "scope"]) and
    ($volume.name == "enterprise_local_registry_data") and
    ($volume.createdAt | type == "string" and test("Z$")) and
    ($volume.driver == "local") and
    ($volume.scope == "local") and
    ($volume.options == {}) and
    ($volume.labels == {
      "platform.infrastructure.managed": "true",
      "platform.infrastructure.purpose": "local-registry"
    }) and
    ($volume.mountpoint | type == "string" and test("/enterprise_local_registry_data/_data$")) and
    (($volume.owner | keys | sort) == ["gid", "mode", "uid"]) and
    ($volume.owner.uid == 0) and
    ($volume.owner.gid == 0) and
    ($volume.owner.mode | type == "string" and test("^0[0-7][0145][0145]$"))
  ) and
  ($deployment.runtimeIntent.services | type == "array" and length > 0) and
  (($deployment.runtimeIntent.services | map(.service)) == ($deployment.runtimeIntent.services | map(.service) | sort)) and
  ($compose.services | type == "object") and
  (($compose.services | keys | sort) == ($deployment.runtimeIntent.services | map(.service) | sort)) and
  (all($deployment.runtimeIntent.services[];
    (.image | digest_image) and
    (.expectedLocalImageId | type == "string" and test("^sha256:[a-f0-9]{64}$")) and
    ($compose.services[.service] | type == "object") and
    ($compose.services[.service].image == .image) and
    ($compose.services[.service] | has("build") | not)
  )) and
  (all($deployment.runtimeIntent.services[]; .admission.kind != "ops-runner" and .image != $deployment.opsRunner.image)) and
  exact_subject($receipt; $deployment; $compose; "PLATFORM_BACKUP_SCHEDULER_IMAGE"; "backup-scheduler") and
  exact_subject($receipt; $deployment; $compose; "CONTROL_CENTER_IMAGE"; "control-center") and
  exact_subject($receipt; $deployment; $compose; "PLATFORM_ALERT_DISPATCHER_IMAGE"; "platform-alert-dispatcher") and
  exact_subject($receipt; $deployment; $compose; "PROJECT_ROUTER_IMAGE"; "project-router")
' "$artifact_receipt" "$deployment_receipt" "$candidate_compose" >/dev/null || {
  echo "Release admission does not exactly bind the complete rendered service set to runtime intent and authenticated image subjects." >&2
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
        {service: $service.key, mount: .}
      ] | sort_by(.service, .mount.type, .mount.source, .mount.target);
    def volume_definitions:
      [
        (.volumes // {}) | to_entries[] |
        {key: .key, definition: .value}
      ] | sort_by(.key);
    def network_attachments:
      [
        .services | to_entries[] as $service |
        ($service.value.networks // {}) | to_entries[] |
        {service: $service.key, network: .key, attachment: .value}
      ] | sort_by(.service, .network);
    def network_definitions:
      [(.networks // {}) | to_entries[] | {key: .key, definition: .value}] | sort_by(.key);
    .[0] as $previous | .[1] as $candidate |
    ($previous | storage_mounts) == ($candidate | storage_mounts) and
    ($previous | volume_definitions) == ($candidate | volume_definitions) and
    ($previous | network_attachments) == ($candidate | network_attachments) and
    ($previous | network_definitions) == ($candidate | network_definitions)
  ' "$previous_compose" "$candidate_compose" >/dev/null || {
    echo "Candidate Compose changes persistent storage or network identity; deploy requires a separately approved migration." >&2
    exit 1
  }
fi
