#!/usr/bin/python3 -I
"""Root-only V1 LOCAL_PRIVATE scheduler recovery export refresh.

Rebinds the frozen scheduler recovery export (OCI docker-save archive) and the
LOCAL_PRIVATE pre-deploy checkpoint to the CURRENT candidate commit as one
atomic pair.  The layer blobs of the predecessor image are copied verbatim;
only the candidate-bound annotation/label set and the digests that reference
them are recomputed.  Every step fails closed and restores the previous pair
unless both the new export and the refreshed checkpoint are proven by
readback.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from typing import Dict, Optional, Tuple

EXPORT_PATH_DEFAULT = "/var/lib/platform-infrastructure/v1/predeploy/current/scheduler-recovery-image.tar"
CHECKPOINT_PATH_DEFAULT = "/var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint.json"
SCHEDULER_CONTAINER = "enterprise-backup-scheduler"
RECOVERY_TAG_PREFIX = "platform/v1-scheduler-recovery:"
LAYER_MEDIA = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}
CHECKPOINT_KEYS = (
    "authoritative", "backupCapturedUnixSeconds", "candidateCommit", "candidateTree", "destructiveMutationPlanned",
    "generatedAtUnixSeconds", "logicalBackupEvidenceSha256", "offHostBackupEvidenceSha256", "restoreEvidenceSha256",
    "restoreVerified", "runtimeInventorySha256", "runtimeRecovered", "schedulerRecoveryImageExportSha256",
    "schedulerRecoveryImageId", "schedulerRunningImageId", "schema", "secretsBackupEvidenceSha256", "sourceArchiveSha256",
)
LABEL_CANDIDATE = "com.platform.v1.local-private.candidate-commit"
LABEL_CONFIG_HASH = "com.platform.v1.local-private.scheduler-config-hash"
LABEL_CONTAINER_ID = "com.platform.v1.local-private.scheduler-container-id"
LABEL_RUNNING_IMAGE = "com.platform.v1.local-private.scheduler-running-image-id"
CHECKPOINT_SCHEMA = "platform.v1-local-private-predeploy-checkpoint/v1"
SHA256 = "^[a-f0-9]{64}$"
ID64 = "^sha256:[a-f0-9]{64}$"
GIT40 = "^[a-f0-9]{40}$"
DOCKER = os.environ.get("PLATFORM_V1_RECOVERY_REFRESH_TEST_DOCKER", "/usr/bin/docker")
MAX_LAYER_BYTES = 4 * 1024 * 1024 * 1024


class Stop(Exception):
    def __init__(self, message: str, code: int = 78):
        super().__init__(message)
        self.code = code


def stop(message: str, code: int = 78) -> None:
    raise Stop(message, code)


def require(condition: object, message: str, code: int = 78) -> None:
    if not condition:
        stop(message, code)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: str) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def read_json_file(path: str, label: str) -> Dict[str, object]:
    require(not os.path.islink(path), f"{label} must not be a symlink.", 65)
    with open(path, "rb") as stream:
        raw = stream.read()
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        stop(f"{label} is not valid JSON: {error}.", 65)
    require(isinstance(value, dict), f"{label} must be one JSON object.", 65)
    return value


def run_docker(arguments: list, label: str) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run([DOCKER, *arguments], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=600, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        stop(f"docker {label} failed: {error}.")
    return result


def parse_tar_pair(export_path: str, checkpoint: Dict[str, object], expected_commit: str) -> Dict[str, object]:
    """Parse the CURRENT export and prove coherence with the CURRENT checkpoint."""
    recovery_image_id = checkpoint["schedulerRecoveryImageId"]
    require(isinstance(recovery_image_id, str) and len(recovery_image_id) == 71 and recovery_image_id.startswith("sha256:"),
            "checkpoint schedulerRecoveryImageId is not one image digest.", 65)
    with tarfile.open(export_path, "r:") as archive:
        members = archive.getmembers()
        by_name: Dict[str, object] = {}
        for member in members:
            name = member.name.rstrip("/")
            require(name and not name.startswith("/") and ".." not in name.split("/"),
                    "export member path is unsafe.", 65)
            require(name not in by_name, "export contains duplicate members.", 65)
            require(member.isfile() or member.isdir(), "export contains a forbidden member type.", 65)
            by_name[name] = member

        def blob(digest: str, maximum: int, label: str) -> bytes:
            require(digest.startswith("sha256:") and len(digest) == 71, f"{label} digest invalid.", 65)
            member = by_name.get(f"blobs/sha256/{digest.split(':', 1)[1]}")
            require(member is not None and member.isfile(), f"{label} blob missing.", 65)
            source = archive.extractfile(member)
            require(source is not None, f"{label} blob unreadable.", 65)
            data = source.read()
            require(hashlib.sha256(data).hexdigest() == digest.split(':', 1)[1], f"{label} blob digest differs.", 65)
            require(len(data) <= maximum, f"{label} blob exceeds boundary.", 65)
            return data

        layout = json.loads(archive.extractfile("oci-layout").read())
        require(layout == {"imageLayoutVersion": "1.0.0"}, "export oci-layout is not canonical 1.0.0.", 65)
        root = json.loads(archive.extractfile("index.json").read())
        require(isinstance(root.get("manifests"), list) and len(root["manifests"]) == 1,
                "export root index must hold exactly one descriptor.", 65)
        descriptor = root["manifests"][0]
        require(sorted(descriptor.keys()) == ["annotations", "digest", "mediaType", "size"],
                "export root descriptor is not closed.", 65)
        require(descriptor["digest"] == recovery_image_id,
                "export root digest differs from the checkpoint recovery image ID.", 65)
        annotations = descriptor["annotations"]
        require(sorted(annotations.keys()) == ["io.containerd.image.name", "org.opencontainers.image.ref.name"],
                "export root annotations are missing.", 65)
        prior_tag = RECOVERY_TAG_PREFIX + expected_commit
        require(annotations["org.opencontainers.image.ref.name"] in (prior_tag, expected_commit)
                and annotations["io.containerd.image.name"] in (prior_tag, f"docker.io/{prior_tag}"),
                "export annotations are not bound to the prior candidate.", 65)
        inner = json.loads(blob(descriptor["digest"], 1024 * 1024, "export inner index"))
        require(inner.get("mediaType") == "application/vnd.oci.image.index.v1+json" and len(inner["manifests"]) == 1,
                "export inner index is invalid.", 65)
        platform_descriptor = inner["manifests"][0]
        platform = platform_descriptor.get("platform")
        require(isinstance(platform, dict) and platform.get("os") == "linux" and platform.get("architecture") == "amd64",
                "export inner index platform is invalid.", 65)
        manifest = json.loads(blob(platform_descriptor["digest"], 16 * 1024 * 1024, "export image manifest"))
        require(manifest.get("mediaType") in {"application/vnd.oci.image.manifest.v1+json",
                                             "application/vnd.docker.distribution.manifest.v2+json"},
                "export image manifest media invalid.", 65)
        layers = manifest["layers"]
        require(isinstance(layers, list) and 1 <= len(layers) <= 1024, "export layer count invalid.", 65)
        layer_paths = []
        for index, layer in enumerate(layers):
            require(layer["mediaType"] in LAYER_MEDIA and isinstance(layer["size"], int) and 0 < layer["size"] <= MAX_LAYER_BYTES,
                    f"export layer {index} descriptor invalid.", 65)
            path = f"blobs/sha256/{layer['digest'].split(':', 1)[1]}"
            member = by_name.get(path)
            require(member is not None and member.isfile() and member.size == layer["size"],
                    f"export layer {index} blob missing.", 65)
            source = archive.extractfile(member)
            require(source is not None, f"export layer {index} unreadable.", 65)
            hasher = hashlib.sha256()
            total = 0
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                total += len(chunk)
                hasher.update(chunk)
            require(total == layer["size"] and hasher.hexdigest() == layer["digest"].split(':', 1)[1],
                    f"export layer {index} digest differs.", 65)
            layer_paths.append(path)
        config = json.loads(blob(manifest["config"]["digest"], 16 * 1024 * 1024, "export image config"))
        require(config.get("architecture") == "amd64" and config.get("os") == "linux",
                "export image config platform invalid.", 65)
        labels = (config.get("config") or {}).get("Labels")
        require(isinstance(labels, dict), "export image config labels missing.", 65)
        docker_manifest = json.loads(archive.extractfile("manifest.json").read())
        require(isinstance(docker_manifest, list) and len(docker_manifest) == 1
                and sorted(docker_manifest[0].keys()) == ["Config", "Layers", "RepoTags"]
                and docker_manifest[0]["Layers"] == layer_paths
                and docker_manifest[0]["RepoTags"] == [prior_tag],
                "export docker manifest.json is not the prior-bound singleton.", 65)
        return {
            "prior_tag": prior_tag,
            "prior_commit": expected_commit,
            "labels": labels,
            "config": config,
            "manifest": manifest,
            "inner": inner,
            "layer_paths": layer_paths,
            "layer_count": len(layers),
            "root_digest": descriptor["digest"],
        }


def rewrite_archive(source_path: str, target_path: str, parsed: Dict[str, object], candidate: str, tag: str) -> Tuple[str, str]:
    """Emit the refreshed archive; returns (new export sha256, new recovery image id)."""
    config = json.loads(json.dumps(parsed["config"]))
    section = config.get("config")
    require(isinstance(section, dict), "export image config section invalid.", 65)
    labels = section["Labels"]
    require(labels.get(LABEL_CANDIDATE) == parsed["prior_commit"],
            "export config candidate label differs from its own annotation binding.", 65)
    labels[LABEL_CANDIDATE] = candidate
    config_bytes = json.dumps(config, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    config_digest = "sha256:" + sha256_hex(config_bytes)
    config_path = f"blobs/sha256/{config_digest.split(':', 1)[1]}"

    manifest = {
        "schemaVersion": 2,
        "mediaType": parsed["manifest"]["mediaType"],
        "config": {"mediaType": parsed["manifest"]["config"]["mediaType"], "digest": config_digest, "size": len(config_bytes)},
        "layers": parsed["manifest"]["layers"],
    }
    manifest_bytes = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest_digest = "sha256:" + sha256_hex(manifest_bytes)
    manifest_path = f"blobs/sha256/{manifest_digest.split(':', 1)[1]}"

    inner = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": manifest["mediaType"], "digest": manifest_digest, "size": len(manifest_bytes),
            "platform": {"architecture": "amd64", "os": "linux"},
        }],
    }
    inner_bytes = json.dumps(inner, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    inner_digest = "sha256:" + sha256_hex(inner_bytes)
    inner_path = f"blobs/sha256/{inner_digest.split(':', 1)[1]}"

    root = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.index.v1+json", "digest": inner_digest, "size": len(inner_bytes),
            "annotations": {
                "io.containerd.image.name": f"docker.io/{tag}",
                "org.opencontainers.image.ref.name": candidate,
            },
        }],
    }
    root_bytes = json.dumps(root, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    docker_manifest = [{
        "Config": config_path,
        "Layers": parsed["layer_paths"],
        "RepoTags": [tag],
    }]
    docker_bytes = json.dumps(docker_manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    with tarfile.open(source_path, "r:") as source:
        blobs = {}
        for member in source.getmembers():
            if member.isfile() and member.name.startswith("blobs/sha256/"):
                handle = source.extractfile(member)
                blobs[member.name] = handle.read() if handle else b""
    new_members: Dict[str, bytes] = {"oci-layout": b'{"imageLayoutVersion":"1.0.0"}'}
    for path in parsed["layer_paths"]:
        new_members[path] = blobs[path]
    new_members[config_path] = config_bytes
    new_members[manifest_path] = manifest_bytes
    new_members[inner_path] = inner_bytes
    new_members["index.json"] = root_bytes
    new_members["manifest.json"] = docker_bytes

    with tarfile.open(target_path, "w:", format=tarfile.PAX_FORMAT) as target:
        for name in sorted(new_members):
            payload = new_members[name]
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o644
            info.mtime = 0
            target.addfile(info, __import__("io").BytesIO(payload))
    return sha256_hex(__import__("io").BytesIO(open(target_path, "rb").read()).getvalue()), inner_digest


def docker_load_and_verify(export_path: str, tag: str, recovery_image_id: str) -> None:
    result = run_docker(["load", "-i", export_path], "load recovery export")
    require(result.returncode == 0, "docker load of the refreshed recovery export failed.", 65)
    inspect = run_docker(["image", "inspect", tag], "inspect refreshed recovery image")
    require(inspect.returncode == 0, "refreshed recovery image is unavailable after load.", 65)
    objects = json.loads(inspect.stdout.decode("utf-8", errors="strict"))
    require(isinstance(objects, list) and len(objects) == 1, "docker inspect returned an unexpected shape.", 65)
    require(objects[0].get("Id") == recovery_image_id,
            "loaded recovery image ID differs from the archive inner-index digest.", 65)
    tags = objects[0].get("RepoTags")
    require(tags == [tag], "loaded recovery image RepoTags differ from the fixed tag.", 65)
    loaded_labels = (objects[0].get("Config") or {}).get("Labels") or {}
    for key in (LABEL_CANDIDATE, LABEL_CONFIG_HASH, LABEL_CONTAINER_ID, LABEL_RUNNING_IMAGE):
        require(loaded_labels.get(key) is not None, f"loaded recovery image misses label {key}.", 65)


def verify_live_scheduler(candidate: str, parsed: Dict[str, object]) -> Dict[str, str]:
    inspect = run_docker(["inspect", SCHEDULER_CONTAINER], "inspect the live scheduler")
    require(inspect.returncode == 0, "the live scheduler container is unavailable.", 65)
    objects = json.loads(inspect.stdout.decode("utf-8", errors="strict"))
    require(isinstance(objects, list) and len(objects) == 1, "scheduler inspect returned an unexpected shape.", 65)
    container = objects[0]
    labels = (container.get("Config") or {}).get("Labels") or {}
    config_hash = labels.get("com.docker.compose.config-hash")
    require(isinstance(config_hash, str) and len(config_hash) == 64, "live scheduler compose config-hash invalid.", 65)
    container_id = container.get("Id")
    require(isinstance(container_id, str) and len(container_id) == 64, "live scheduler container ID invalid.", 65)
    running_image = container.get("Image")
    require(isinstance(running_image, str) and running_image.startswith("sha256:") and len(running_image) == 71,
            "live scheduler running image invalid.", 65)
    prior = parsed["labels"]
    require(prior.get(LABEL_CONFIG_HASH) == config_hash,
            "frozen export scheduler config-hash differs from the live container.", 65)
    require(prior.get(LABEL_CONTAINER_ID) == container_id,
            "frozen export scheduler container-id differs from the live container.", 65)
    require(prior.get(LABEL_RUNNING_IMAGE) == running_image,
            "frozen export scheduler running-image differs from the live container.", 65)
    return {
        LABEL_CANDIDATE: candidate,
        LABEL_CONFIG_HASH: config_hash,
        LABEL_CONTAINER_ID: container_id,
        LABEL_RUNNING_IMAGE: running_image,
    }


def main(argv: list) -> int:
    arguments = dict(zip(argv[0::2], argv[1::2]))
    mode = arguments.get("--mode", "plan")
    candidate = arguments.get("--candidate", "")
    export_path = arguments.get("--export", EXPORT_PATH_DEFAULT)
    checkpoint_path = arguments.get("--checkpoint", CHECKPOINT_PATH_DEFAULT)
    if len(argv) % 2 != 0 or mode not in ("plan", "apply"):
        sys.stderr.write("usage: v1-local-private-recovery-refresh.py --mode plan|apply --candidate COMMIT [--export PATH] [--checkpoint PATH]\n")
        return 64
    require(len(candidate) == 40 and all(character in "0123456789abcdef" for character in candidate),
            "candidate must be one lowercase 40-hex commit.", 64)
    tag = RECOVERY_TAG_PREFIX + candidate

    checkpoint = read_json_file(checkpoint_path, "LOCAL_PRIVATE checkpoint")
    require(sorted(checkpoint.keys()) == sorted(CHECKPOINT_KEYS), "LOCAL_PRIVATE checkpoint key set is not closed.", 65)
    require(checkpoint["schema"] == CHECKPOINT_SCHEMA, "LOCAL_PRIVATE checkpoint schema invalid.", 65)
    require(checkpoint["candidateCommit"] == candidate and checkpoint["candidateTree"] and checkpoint["sourceArchiveSha256"],
            "LOCAL_PRIVATE checkpoint is not bound to the refresh candidate.", 65)
    require(checkpoint["authoritative"] is False and checkpoint["destructiveMutationPlanned"] is False
            and checkpoint["restoreVerified"] is True and checkpoint["runtimeRecovered"] is True,
            "LOCAL_PRIVATE checkpoint flags are invalid.", 65)
    current_export_sha = digest_file(export_path)
    require(checkpoint["schedulerRecoveryImageExportSha256"] == current_export_sha,
            "LOCAL_PRIVATE checkpoint is not bound to this export; refusing refresh.", 65)
    if checkpoint["schedulerRecoveryImageExportSha256"] == current_export_sha:
        try:
            prior_commit = checkpoint["candidateCommit"]
            parsed = parse_tar_pair(export_path, checkpoint, prior_commit)
        except Stop:
            parsed = None
        if parsed is not None:
            print(json.dumps({"status": "ALREADY_BOUND", "exportSha256": current_export_sha,
                              "recoveryImageId": checkpoint["schedulerRecoveryImageId"]}, sort_keys=True))
            return 0

    prior_candidate = arguments.get("--prior-candidate", "")
    if not prior_candidate:
        with tarfile.open(export_path, "r:") as probe:
            root = json.loads(probe.extractfile("index.json").read())
        prior_candidate = root["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"]
        if len(prior_candidate) != 40:
            prior_candidate = root["manifests"][0]["annotations"]["io.containerd.image.name"].rsplit(":", 1)[-1]
    require(len(prior_candidate) == 40 and all(character in "0123456789abcdef" for character in prior_candidate),
            "prior candidate binding is invalid.", 65)
    parsed = parse_tar_pair(export_path, checkpoint, prior_candidate)
    expected_labels = verify_live_scheduler(candidate, parsed)
    for key, value in expected_labels.items():
        if key != LABEL_CANDIDATE:
            require(parsed["labels"].get(key) == value,
                    f"frozen export label {key} differs from the live scheduler.", 65)

    if mode == "plan":
        print(json.dumps({"status": "PLAN", "wouldRebind": {
            "candidate": candidate, "tag": tag, "exportPath": export_path, "checkpointPath": checkpoint_path,
            "currentExportSha256": current_export_sha, "priorCandidate": prior_candidate,
        }}, sort_keys=True))
        return 0

    backup_export = export_path + ".refresh-backup"
    backup_checkpoint = checkpoint_path + ".refresh-backup"
    staged_export = export_path + ".refresh-staged"
    for pathname in (backup_export, backup_checkpoint, staged_export):
        if os.path.lexists(pathname):
            os.remove(pathname)
    shutil.copy2(export_path, backup_export)
    shutil.copy2(checkpoint_path, backup_checkpoint)
    new_export_sha, recovery_image_id = rewrite_archive(export_path, staged_export, parsed, candidate, tag)
    staged_mode = stat.S_IMODE(os.stat(export_path).st_mode)
    os.chmod(staged_export, staged_mode)
    try:
        docker_load_and_verify(staged_export, tag, recovery_image_id)
        refreshed = dict(checkpoint)
        refreshed["schedulerRecoveryImageExportSha256"] = new_export_sha
        refreshed["schedulerRecoveryImageId"] = recovery_image_id
        refreshed["generatedAtUnixSeconds"] = int(time.time())
        checkpoint_bytes = (json.dumps(refreshed, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        with open(checkpoint_path + ".refresh-new", "wb") as stream:
            stream.write(checkpoint_bytes)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(checkpoint_path + ".refresh-new", stat.S_IMODE(os.stat(checkpoint_path).st_mode))
        os.replace(staged_export, export_path)
        os.replace(checkpoint_path + ".refresh-new", checkpoint_path)
    except BaseException:
        shutil.copy2(backup_export, export_path)
        shutil.copy2(backup_checkpoint, checkpoint_path)
        raise
    finally:
        for pathname in (backup_export, backup_checkpoint):
            if os.path.lexists(pathname):
                os.remove(pathname)
        if os.path.lexists(checkpoint_path + ".refresh-new"):
            os.remove(checkpoint_path + ".refresh-new")
        if os.path.lexists(staged_export):
            os.remove(staged_export)

    verified = read_json_file(checkpoint_path, "refreshed LOCAL_PRIVATE checkpoint")
    require(verified["schedulerRecoveryImageExportSha256"] == new_export_sha
            and verified["schedulerRecoveryImageId"] == recovery_image_id,
            "checkpoint readback after refresh differs.", 65)
    require(digest_file(export_path) == new_export_sha, "export readback after refresh differs.", 65)
    print(json.dumps({"status": "REFRESHED", "candidate": candidate, "tag": tag,
                      "exportSha256": new_export_sha, "recoveryImageId": recovery_image_id,
                      "checkpointPath": checkpoint_path}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Stop as error:
        sys.stderr.write(f"v1-local-private-recovery-refresh: STOP: {error}\n")
        raise SystemExit(error.code)
    except BrokenPipeError:
        raise SystemExit(74)
