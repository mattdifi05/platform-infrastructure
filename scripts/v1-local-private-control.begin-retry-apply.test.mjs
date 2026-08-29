import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const controller = path.join(repositoryRoot, "scripts/v1-local-private-control.py");
const python = process.env.CODEX_PYTHON ?? "python3";

function runPython(source) {
  const result = spawnSync(python, ["-c", source], { cwd: repositoryRoot, encoding: "utf8", maxBuffer: 4 * 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("begin → retry → apply: one identical 16-key recovery object across all three gates", () => {
  const output = runPython(String.raw`
import hashlib, importlib.util, json, os, sys, tempfile, time
from importlib.machinery import SourceFileLoader

new_commit = "b" * 40
old_commit = "a" * 40

root = tempfile.mkdtemp()
os.chmod(root, 0o700)
os.makedirs(root + "/run", exist_ok=True)
os.environ["PLATFORM_V1_LOCAL_PRIVATE_TEST_ROOT"] = root
os.environ["PLATFORM_V1_LOCAL_PRIVATE_TEST_DOCKER"] = root + "/docker"
os.environ["PLATFORM_V1_LOCAL_PRIVATE_TEST_SYSTEMCTL"] = root + "/systemctl"
open(root + "/docker", "w").write("#!/bin/sh" + chr(10) + "exit 0" + chr(10)); os.chmod(root + "/docker", 0o700)
open(root + "/systemctl", "w").write("#!/bin/sh" + chr(10) + "exit 0" + chr(10)); os.chmod(root + "/systemctl", 0o700)

loader = SourceFileLoader("ctl", ${JSON.stringify(controller)})
spec = importlib.util.spec_from_loader("ctl", loader)
m = importlib.util.module_from_spec(spec); loader.exec_module(m)
m.TEST_ROOT = root
m.OWNER_UID = os.geteuid(); m.OWNER_GID = os.getegid()

new_tree = "c" * 40
archive = "d" * 64
running_image = "sha256:" + "e" * 64
recovery_index = "sha256:" + "f" * 64
export_sha = hashlib.sha256(b"export-tar-bytes").hexdigest()
config_hash = hashlib.sha256(b"scheduler-compose-config").hexdigest()
container_id = hashlib.sha256(b"scheduler-container").hexdigest()

m.CANDIDATE_COMMIT = new_commit
m.CANDIDATE_TREE = new_tree
m.SOURCE_ARCHIVE_SHA256 = archive
m.RELEASE_ROOT = "/srv/platform-infrastructure/releases/" + new_commit + "-" + archive
m.EXACT_AUTHORITY = {
    "candidateCommit": new_commit, "candidateTree": new_tree, "sourceArchiveSha256": archive,
    "releaseRoot": m.RELEASE_ROOT, "schema": "platform.v1-local-private-exact-release-authority/v1",
    "legacyNetworkAttachments": [{"aliases": ["backend"], "containerName": "enterprise-backend",
                                  "networkName": "platform_infra_vps_routing"}],
    "runtimeIdentity": {"commit": new_commit, "tree": new_tree,
                        "deploymentId": "v1-local-private:" + new_commit,
                        "candidateId": "sha256:" + "a" * 64,
                        "sourceRenderSha256": "sha256:" + "b" * 64,
                        "workloadLockSha256": "sha256:" + "c" * 64},
}
m.EXACT_AUTHORITY["documentId"] = m.digest(m.canonical(m.EXACT_AUTHORITY).encode())
m.EXACT_AUTHORITY_SHA256 = m.digest(m.canonical(m.EXACT_AUTHORITY).encode())
m.SCHEDULER_RECOVERY_TAG = "platform/v1-scheduler-recovery:" + new_commit

installed = m.physical(m.CONTROLLER_PATH)
os.makedirs(os.path.dirname(installed), exist_ok=True)
open(installed, "w").write("#!/usr/bin/python3 -I" + chr(10) + "raise SystemExit(0)" + chr(10)); os.chmod(installed, 0o555)
unit_path = m.physical(m.UNIT_PATH)
os.makedirs(os.path.dirname(unit_path), exist_ok=True)
open(unit_path, "w").write("[Unit]" + chr(10) + "Description=stub"); os.chmod(unit_path, 0o444)
sudoers_path = m.physical("/etc/sudoers.d/platform-v1-local-private-control")
os.makedirs(os.path.dirname(sudoers_path), exist_ok=True)
open(sudoers_path, "w").write("platform_infrastructure ALL=(root) NOPASSWD: /usr/local/libexec/platform-v1-local-private-control activate" + chr(10))
os.chmod(sudoers_path, 0o440)
sys.argv = [installed]
m.initialize()

records = []
for idx, name in enumerate(m.HISTORIC_CONTAINERS):
    network = ([{"aliases": ["backend"], "networkName": "platform_infra_vps_routing"}]
               if name == "enterprise-backend" else [{"aliases": [name], "networkName": "platform_infra_vps_internal"}])
    seed = ("img" + str(idx)).encode()
    if name == "enterprise-backup-scheduler":
        records.append({"name": name, "state": "running", "imageId": running_image,
                        "configHash": config_hash, "containerId": container_id,
                        "exitCode": 0, "health": "none", "service": "backup-scheduler",
                        "networkMembership": network})
    else:
        records.append({"name": name, "state": "running",
                        "imageId": "sha256:" + hashlib.sha256(seed).hexdigest(),
                        "configHash": hashlib.sha256(b"cfg" + seed).hexdigest(),
                        "containerId": hashlib.sha256(b"cid" + seed).hexdigest(),
                        "exitCode": 0, "health": "none", "service": "svc" + str(idx),
                        "networkMembership": network})
observation = {"containers": records,
               "schedulerRecovery": {"configHash": config_hash, "containerId": container_id}}
state_fixture = {
    "schema": m.STATE_SCHEMA, "status": "ACTIVE",
    "candidateCommit": old_commit, "candidateTree": "8" * 40,
    "installReceiptSha256": hashlib.sha256(b"install-receipt").hexdigest(),
    "checkpointSha256": hashlib.sha256(b"checkpoint").hexdigest(),
    "createdAtUnixSeconds": 1756100000, "controller": {"sha256": "c" * 64},
    "releaseRoot": "/srv/platform-infrastructure/releases/" + old_commit + "-" + "8" * 64,
    "sourceArchiveSha256": "8" * 64, "observation": observation,
}
receipt_fixture = {"schema": "platform.v1-local-private-control-receipt/v1", "status": "ACTIVE",
                   "activatedAtUnixSeconds": 1756100000, "candidateCommit": old_commit,
                   "candidateTree": "8" * 40}
receipt_fixture["documentId"] = hashlib.sha256(m.canonical(receipt_fixture).encode()).hexdigest()

checkpoint = {
    "authoritative": False, "backupCapturedUnixSeconds": int(time.time()) - 20,
    "candidateCommit": new_commit, "candidateTree": new_tree,
    "destructiveMutationPlanned": False, "generatedAtUnixSeconds": int(time.time()) - 10,
    "logicalBackupEvidenceSha256": "4" * 64, "offHostBackupEvidenceSha256": "5" * 64,
    "restoreEvidenceSha256": "6" * 64, "restoreVerified": True,
    "runtimeInventorySha256": "7" * 64, "runtimeRecovered": True,
    "schedulerRecoveryImageExportSha256": export_sha,
    "schedulerRecoveryImageId": recovery_index,
    "schedulerRunningImageId": running_image,
    "schema": "platform.v1-local-private-predeploy-checkpoint/v1",
    "secretsBackupEvidenceSha256": "8" * 64, "sourceArchiveSha256": archive,
}
checkpoint_bytes = (m.canonical(checkpoint) + chr(10)).encode()
receipt_bytes = (m.canonical(receipt_fixture) + chr(10)).encode()

real_secure_file = m.secure_file
def staged_secure_file(pathname, label, maximum=1048576, mode=None, uid=None, exact_mode=None, **kwargs):
    if pathname == m.CHECKPOINT:
        return checkpoint_bytes
    if pathname == m.RECEIPT_FILE:
        return receipt_bytes
    return real_secure_file(pathname, label, maximum, mode)
m.secure_file = staged_secure_file
m.stream_snapshot = lambda logical, label: {
    "identity": {"ctimeNs": 1, "device": 1, "gid": 0, "inode": 1, "mode": 0o400,
                 "mtimeNs": 1, "nlink": 1, "size": 2048, "uid": 0},
    "sha256": export_sha, "sizeBytes": 2048,
}
labels = {
    m.RECOVERY_LABELS["candidateCommit"]: new_commit,
    m.RECOVERY_LABELS["configHash"]: config_hash,
    m.RECOVERY_LABELS["containerId"]: container_id,
    m.RECOVERY_LABELS["runningImageId"]: running_image,
}
m.parse_recovery_export = lambda snapshot, image_id, expected_tag=None, expected_commit=None: {
    "archiveFormat": "OCI_DOCKER_SAVE_V1", "configDigest": "sha256:" + "9" * 64,
    "exportLabels": labels, "imageIndexDigest": recovery_index,
    "imageIndexPath": "blobs/sha256/" + "f" * 64, "imageManifestDigest": "sha256:" + "2" * 64,
    "manifestConfig": "blobs/sha256/" + "9" * 64, "recoveryTag": expected_tag or m.SCHEDULER_RECOVERY_TAG,
}
m.validate_fixed_evidence_files = lambda value: {}
m.validate_release_and_install = lambda *a, **k: hashlib.sha256(b"install-receipt").hexdigest()
m.validate_predecessor_controller = lambda *_: None
m.validate_receipt_document = lambda value: receipt_fixture
m.receipt_from_state = lambda state, activated_at: receipt_fixture
m.supervisor_is_enabled_and_active = lambda: True
m.supervisor_is_disabled_and_inactive = lambda: True
m.disable_supervisor = lambda: None
m.stable_runtime_identities = lambda names: [dict(item) for item in records if item["name"] in set(names)]

os.makedirs(m.physical(m.STATE_DIR), exist_ok=True)
os.chmod(m.physical(m.STATE_DIR), 0o700)
os.makedirs(m.physical("/var/lib/platform-infrastructure/v1/predeploy/current"), exist_ok=True)
open(m.physical(m.STATE_FILE), "wb").write((m.canonical(state_fixture) + chr(10)).encode())
open(m.physical(m.RECEIPT_FILE), "wb").write((m.canonical(receipt_fixture) + chr(10)).encode())

first = m.begin_maintenance()
doc_path = m.physical(m.RECONCILIATION_FILE)
doc = json.load(open(doc_path))
assert len(doc["rollbackSchedulerRecovery"]) == 16, json.dumps({"len": len(doc["rollbackSchedulerRecovery"]), "keys": sorted(doc["rollbackSchedulerRecovery"])})
assert doc["rollbackCheckpointSha256"] == m.digest(checkpoint_bytes)

retry = m.begin_maintenance()
assert retry["rollbackSchedulerRecovery"] == first["rollbackSchedulerRecovery"]
assert m.validate_checkpoint()[0] == m.digest(checkpoint_bytes)

m.validate_bound_recovery_export(retry["rollbackSchedulerRecovery"], True)

broken = {k: v for k, v in retry["rollbackSchedulerRecovery"].items()
          if k not in ("configHash", "containerId")}
try:
    m.validate_bound_recovery_export(broken, False)
    raise AssertionError("broken 14-key object was accepted")
except m.Stop:
    pass

print(json.dumps({"first": 16, "retryIdentical": True, "applyGate": "PASS"}))
`);
  assert.deepEqual(output, { first: 16, retryIdentical: true, applyGate: "PASS" });
});
