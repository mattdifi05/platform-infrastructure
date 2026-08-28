#!/usr/bin/env node
import assert from "node:assert/strict";
import child from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const tool = path.join(import.meta.dirname, "v1-local-private-recovery-refresh.py");
const python = "/usr/bin/python3";
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");

const OLD_COMMIT = "a".repeat(40);
const NEW_COMMIT = "b".repeat(40);
const TAG_PREFIX = "platform/v1-scheduler-recovery:";
const LABELS = {
  candidate: "com.platform.v1.local-private.candidate-commit",
  configHash: "com.platform.v1.local-private.scheduler-config-hash",
  containerId: "com.platform.v1.local-private.scheduler-container-id",
  runningImage: "com.platform.v1.local-private.scheduler-running-image-id",
};
const LIVE = {
  configHash: "c".repeat(64),
  containerId: "d".repeat(64),
  runningImage: "sha256:" + "e".repeat(64),
};

function canonical(value) {
  return JSON.stringify(value, Object.keys(value).sort(), 0).replace(/"([A-Za-z0-9_.-]+)":/g, '"$1":');
}

function stable(value) {
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableValue(value[key])}`).join(",")}}`;
}
function stableValue(value) {
  return Array.isArray(value) ? `[${value.map(stableValue).join(",")}]`
    : value && typeof value === "object" ? stable(value) : JSON.stringify(value);
}

function buildOciTar({ commit, layerPayloads }) {
  const root = os.tmpdir();
  const work = fs.realpathSync.native(fs.mkdtempSync(path.join(root, "recovery-fixture-")));
  const blobs = path.join(work, "blobs", "sha256");
  fs.mkdirSync(blobs, { recursive: true });
  const put = (bytes) => {
    const digest = "sha256:" + sha(bytes);
    fs.writeFileSync(path.join(blobs, digest.slice(7)), bytes);
    return { digest, size: bytes.length };
  };
  const layerDescriptors = layerPayloads.map((payload) => {
    const descriptor = put(payload);
    return { mediaType: "application/vnd.oci.image.layer.v1.tar+gzip", digest: descriptor.digest, size: descriptor.size };
  });
  const config = {
    architecture: "amd64", os: "linux",
    config: { Labels: {
      [LABELS.candidate]: commit, [LABELS.configHash]: LIVE.configHash,
      [LABELS.containerId]: LIVE.containerId, [LABELS.runningImage]: LIVE.runningImage,
      "com.docker.compose.project": "platform_infra_vps",
    } },
  };
  const configDescriptor = put(Buffer.from(stable(config)));
  const manifest = {
    schemaVersion: 2, mediaType: "application/vnd.oci.image.manifest.v1+json",
    config: { mediaType: "application/vnd.oci.image.config.v1+json", digest: configDescriptor.digest, size: configDescriptor.size },
    layers: layerDescriptors,
  };
  const manifestDescriptor = put(Buffer.from(stable(manifest)));
  const inner = {
    schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json",
    manifests: [{ mediaType: manifest.mediaType, digest: manifestDescriptor.digest, size: manifestDescriptor.size,
      platform: { architecture: "amd64", os: "linux" } }],
  };
  const innerDescriptor = put(Buffer.from(stable(inner)));
  const tag = TAG_PREFIX + commit;
  const rootIndex = {
    schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json",
    manifests: [{ mediaType: inner.mediaType, digest: innerDescriptor.digest, size: innerDescriptor.size,
      annotations: { "io.containerd.image.name": `docker.io/${tag}`, "org.opencontainers.image.ref.name": commit } }],
  };
  fs.writeFileSync(path.join(work, "index.json"), Buffer.from(stable(rootIndex)));
  fs.writeFileSync(path.join(work, "manifest.json"), Buffer.from(JSON.stringify([
    { Config: `blobs/sha256/${configDescriptor.digest.slice(7)}`, Layers: layerDescriptors.map((l) => `blobs/sha256/${l.digest.slice(7)}`), RepoTags: [tag] },
  ])));
  fs.writeFileSync(path.join(work, "oci-layout"), Buffer.from('{"imageLayoutVersion":"1.0.0"}'));
  const tarPath = path.join(work, "scheduler-recovery-image.tar");
  const result = child.spawnSync("tar", ["-cf", tarPath, "-C", work, "blobs", "index.json", "manifest.json", "oci-layout"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const containerFile = path.join(work, "container.json");
  fs.writeFileSync(containerFile, JSON.stringify([{ Id: LIVE.containerId,
    Image: LIVE.runningImage,
    Config: { Labels: { "com.docker.compose.config-hash": LIVE.configHash } } }]));
  const manifestParsed = JSON.parse(fs.readFileSync(path.join(work, "manifest.json")));
  return {
    work, tarPath, recoveryImageId: innerDescriptor.digest,
    checkpoint: {
      authoritative: false, backupCapturedUnixSeconds: 1756100000, candidateCommit: commit,
      candidateTree: "1".repeat(40), destructiveMutationPlanned: false, generatedAtUnixSeconds: 1756100001,
      logicalBackupEvidenceSha256: "2".repeat(64), offHostBackupEvidenceSha256: "3".repeat(64),
      restoreEvidenceSha256: "4".repeat(64), restoreVerified: true, runtimeInventorySha256: "5".repeat(64),
      runtimeRecovered: true, schedulerRecoveryImageExportSha256: sha(fs.readFileSync(tarPath)),
      schedulerRecoveryImageId: innerDescriptor.digest, schedulerRunningImageId: LIVE.runningImage,
      schema: "platform.v1-local-private-predeploy-checkpoint/v1", secretsBackupEvidenceSha256: "6".repeat(64),
      sourceArchiveSha256: "7".repeat(64),
    },
    manifestParsed, layerPayloads, containerFile, cleanup: () => fs.rmSync(work, { recursive: true, force: true }),
  };
}

function fakeDockerScript(directory, containerInspectFile) {
  const docker = path.join(directory, "docker");
  fs.writeFileSync(docker, `#!/usr/bin/python3
import json, sys, tarfile
state = ${JSON.stringify(path.join(directory, "docker-state.json"))}
args = sys.argv[1:]
if args[:2] == ["load", "-i"]:
    with tarfile.open(args[2]) as archive:
        root = json.loads(archive.extractfile("index.json").read())
        descriptor = root["manifests"][0]
        inner = json.loads(archive.extractfile("blobs/sha256/" + descriptor["digest"].split(":")[1]).read())
        platform_descriptor = inner["manifests"][0]
        manifest = json.loads(archive.extractfile("blobs/sha256/" + platform_descriptor["digest"].split(":")[1]).read())
        config = json.loads(archive.extractfile("blobs/sha256/" + manifest["config"]["digest"].split(":")[1]).read())
        docker_manifest = json.loads(archive.extractfile("manifest.json").read())
    json.dump({"Id": descriptor["digest"], "RepoTags": docker_manifest[0]["RepoTags"],
               "Labels": config["config"]["Labels"]}, open(state, "w"))
    sys.exit(0)
if args[:2] == ["image", "inspect"]:
    state_value = json.load(open(state))
    if state_value["RepoTags"][0] not in args[2:]:
        sys.exit(1)
    print(json.dumps([{"Id": state_value["Id"], "RepoTags": state_value["RepoTags"],
                       "Config": {"Labels": state_value["Labels"]}}]))
    sys.exit(0)
if args[:1] == ["inspect"]:
    print(open(${JSON.stringify(containerInspectFile)}).read())
    sys.exit(0)
sys.exit(1)
`, { mode: 0o700 });
  return docker;
}

function runTool(args) {
  return spawnSync(python, ["-I", tool, ...args], { encoding: "utf8" });
}

test("plan reports the rebind without mutating the pair", () => {
  const fixture = buildOciTar({ commit: OLD_COMMIT, layerPayloads: [Buffer.from("layer-one"), Buffer.from("layer-two")] });
  try {
    const checkpointPath = path.join(fixture.work, "checkpoint.json");
    fs.writeFileSync(checkpointPath, Buffer.from(stable({ ...fixture.checkpoint, candidateCommit: NEW_COMMIT }) + "\n"));
    const docker = fakeDockerScript(fixture.work, fixture.containerFile);
    const result = child.spawnSync(python, ["-I", tool, "--mode", "plan", "--candidate", NEW_COMMIT,
      "--export", fixture.tarPath, "--checkpoint", checkpointPath, "--prior-candidate", OLD_COMMIT],
      { encoding: "utf8", env: { ...process.env, PLATFORM_V1_RECOVERY_REFRESH_TEST_DOCKER: docker } });
    assert.equal(result.status, 0, result.stderr);
    const plan = JSON.parse(result.stdout);
    assert.equal(plan.status, "PLAN");
    assert.equal(plan.wouldRebind.candidate, NEW_COMMIT);
    assert.equal(fs.readFileSync(fixture.tarPath).length, fs.readFileSync(fixture.tarPath).length);
  } finally { fixture.cleanup(); }
});

test("apply rebinds annotations, labels, manifest.json and the checkpoint atomically", () => {
  const fixture = buildOciTar({ commit: OLD_COMMIT, layerPayloads: [Buffer.from("layer-one"), Buffer.from("layer-two")] });
  try {
    const checkpointPath = path.join(fixture.work, "checkpoint.json");
    fs.writeFileSync(checkpointPath, Buffer.from(stable({ ...fixture.checkpoint, candidateCommit: NEW_COMMIT }) + "\n"));
    const inspectPayload = JSON.stringify([{
      Id: "PLACEHOLDER", RepoTags: [TAG_PREFIX + NEW_COMMIT],
      Config: { Labels: { [LABELS.candidate]: NEW_COMMIT, [LABELS.configHash]: LIVE.configHash,
        [LABELS.containerId]: LIVE.containerId, [LABELS.runningImage]: LIVE.runningImage } },
    }]);
    const docker = fakeDockerScript(fixture.work, fixture.containerFile);
    const environment = { ...process.env, PLATFORM_V1_RECOVERY_REFRESH_TEST_DOCKER: docker };
    const apply = child.spawnSync(python, ["-I", tool, "--mode", "apply", "--candidate", NEW_COMMIT,
      "--export", fixture.tarPath, "--checkpoint", checkpointPath, "--prior-candidate", OLD_COMMIT],
      { encoding: "utf8", env: environment });
    void docker;
    assert.equal(apply.status, 0, apply.stderr);
    const verdict = JSON.parse(apply.stdout);
    assert.equal(verdict.status, "REFRESHED");
    assert.notEqual(verdict.recoveryImageId, fixture.recoveryImageId);
    const refreshedTar = child.spawnSync("tar", ["-xOf", fixture.tarPath, "index.json"], { encoding: "utf8" });
    const refreshedRoot = JSON.parse(refreshedTar.stdout);
    assert.equal(refreshedRoot.manifests[0].digest, verdict.recoveryImageId);
    assert.equal(refreshedRoot.manifests[0].annotations["org.opencontainers.image.ref.name"], NEW_COMMIT);
    const tar = child.spawnSync("tar", ["-xOf", fixture.tarPath, "index.json"], { encoding: "utf8" });
    const rootIndex = JSON.parse(tar.stdout);
    assert.equal(rootIndex.manifests[0].annotations["org.opencontainers.image.ref.name"], NEW_COMMIT);
    const manifestJson = JSON.parse(child.spawnSync("tar", ["-xOf", fixture.tarPath, "manifest.json"], { encoding: "utf8" }).stdout);
    assert.deepEqual(manifestJson[0].RepoTags, [TAG_PREFIX + NEW_COMMIT]);
    const refreshed = JSON.parse(fs.readFileSync(checkpointPath, "utf8"));
    assert.equal(refreshed.schedulerRecoveryImageExportSha256, verdict.exportSha256);
    assert.equal(refreshed.schedulerRecoveryImageId, verdict.recoveryImageId);
    assert.equal(refreshed.schedulerRunningImageId, LIVE.runningImage);
  } finally { fixture.cleanup(); }
});

test("apply is idempotent once the pair is already bound", () => {
  const fixture = buildOciTar({ commit: NEW_COMMIT, layerPayloads: [Buffer.from("payload")] });
  try {
    const checkpointPath = path.join(fixture.work, "checkpoint.json");
    fs.writeFileSync(checkpointPath, Buffer.from(stable(fixture.checkpoint) + "\n"));
    const result = runTool(["--mode", "apply", "--candidate", NEW_COMMIT, "--export", fixture.tarPath,
      "--checkpoint", checkpointPath]);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).status, "ALREADY_BOUND");
    assert.equal(fixture.checkpoint.schedulerRecoveryImageExportSha256,
      JSON.parse(fs.readFileSync(checkpointPath, "utf8")).schedulerRecoveryImageExportSha256);
  } finally { fixture.cleanup(); }
});

test("a tampered layer blob fails closed before any mutation", () => {
  const fixture = buildOciTar({ commit: OLD_COMMIT, layerPayloads: [Buffer.from("layer-one")] });
  try {
    const checkpointPath = path.join(fixture.work, "checkpoint.json");
    fs.writeFileSync(checkpointPath, Buffer.from(stable({ ...fixture.checkpoint, candidateCommit: NEW_COMMIT }) + "\n"));
    let bytes = fs.readFileSync(fixture.tarPath);
    const marker = Buffer.from("layer-one");
    const at = bytes.indexOf(marker);
    assert.notEqual(at, -1);
    bytes[at] ^= 0x01;
    fs.writeFileSync(fixture.tarPath, bytes);
    const tamperedCheckpoint = { ...fixture.checkpoint, candidateCommit: NEW_COMMIT,
      schedulerRecoveryImageExportSha256: sha(fs.readFileSync(fixture.tarPath)) };
    fs.writeFileSync(checkpointPath, Buffer.from(stable(tamperedCheckpoint) + "\n"));
    const docker = fakeDockerScript(fixture.work, fixture.containerFile);
    const result = child.spawnSync(python, ["-I", tool, "--mode", "apply", "--candidate", NEW_COMMIT,
      "--export", fixture.tarPath, "--checkpoint", checkpointPath, "--prior-candidate", OLD_COMMIT],
      { encoding: "utf8", env: { ...process.env, PLATFORM_V1_RECOVERY_REFRESH_TEST_DOCKER: docker } });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /digest differs|invalid|missing/);
    assert.equal(JSON.parse(fs.readFileSync(checkpointPath, "utf8")).schedulerRecoveryImageExportSha256,
      sha(fs.readFileSync(fixture.tarPath)));
  } finally { fixture.cleanup(); }
});

test("a checkpoint bound to a different export refuses the refresh", () => {
  const fixture = buildOciTar({ commit: OLD_COMMIT, layerPayloads: [Buffer.from("layer-one")] });
  try {
    const checkpointPath = path.join(fixture.work, "checkpoint.json");
    const drifted = { ...fixture.checkpoint, candidateCommit: NEW_COMMIT, schedulerRecoveryImageExportSha256: "9".repeat(64) };
    fs.writeFileSync(checkpointPath, Buffer.from(stable(drifted) + "\n"));
    const result = runTool(["--mode", "apply", "--candidate", NEW_COMMIT, "--export", fixture.tarPath,
      "--checkpoint", checkpointPath, "--prior-candidate", OLD_COMMIT]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /not bound to this export/);
  } finally { fixture.cleanup(); }
});

test("candidate mismatch between checkpoint and CLI fails closed", () => {
  const fixture = buildOciTar({ commit: OLD_COMMIT, layerPayloads: [Buffer.from("layer-one")] });
  try {
    const checkpointPath = path.join(fixture.work, "checkpoint.json");
    fs.writeFileSync(checkpointPath, Buffer.from(stable({ ...fixture.checkpoint, candidateCommit: "f".repeat(40) }) + "\n"));
    const result = runTool(["--mode", "apply", "--candidate", NEW_COMMIT, "--export", fixture.tarPath,
      "--checkpoint", checkpointPath]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /not bound to the refresh candidate/);
  } finally { fixture.cleanup(); }
});
