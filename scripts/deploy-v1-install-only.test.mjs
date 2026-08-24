#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const productionScript = path.join(import.meta.dirname, "deploy-v1-install-only.sh");
const bundledNode = process.execPath;
const candidateCommit = "a".repeat(40);
const candidateTree = "b".repeat(40);
const sourceArchiveBytes = "fixture-source-archive\n";
const sourceArchiveSha256 = crypto.createHash("sha256").update(sourceArchiveBytes).digest("hex");
const releaseRoot = `/srv/platform-infrastructure/releases/${candidateCommit}-${sourceArchiveSha256}`;
const preservedLegacyNames = Array.from({ length: 19 }, (_, index) => `node-legacy-${String(index + 1).padStart(2, "0")}`);

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function canonicalDocument(value) {
  return { ...value, documentId: sha256(stableJson(value)) };
}

function validSemantic() {
  return {
    capAdd: [], capDrop: ["ALL"], command: [], entrypoint: [],
    environment: [{ name: "PLATFORM_MODE", valueSha256: sha256("LOCAL_PRIVATE") }],
    healthcheck: null, imageId: `sha256:${"c".repeat(64)}`,
    imageReference: `127.0.0.1:5000/platform/managed@sha256:${"d".repeat(64)}`,
    init: true, mounts: [], networkMode: "managed", networks: ["platform_infra_vps_internal"],
    pidsLimit: 128, ports: [], privileged: false, readOnlyRootfs: true,
    restartPolicy: "unless-stopped", securityOpt: ["no-new-privileges:true"], user: "65532:65532",
  };
}

function sshString(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

const keyBlob = Buffer.concat([
  sshString("ssh-ed25519"),
  sshString(Buffer.alloc(32, 7)),
]).toString("base64");

function fixture() {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "deploy-v1-install-only-test-")));
  fs.chmodSync(root, 0o700);
  const bin = path.join(root, "bin");
  const key = path.join(root, "deploy-key");
  const knownHosts = path.join(root, "known-hosts");
  const fakeSsh = path.join(root, "fixed-ssh");
  const fakeGit = path.join(root, "fixed-git");
  const argumentsFile = path.join(root, "ssh-arguments");
  const stdinSizeFile = path.join(root, "ssh-stdin-size");
  const bootstrapFrameFile = path.join(root, "bootstrap-frame.bin");
  const uploadedBridgeFile = path.join(root, "uploaded-bridge.py");
  const bootstrapOutput = path.join(root, "bootstrap-receipt.json");
  const controlOutput = path.join(root, "control-artifact-receipt.json");
  const nodeRuntimeOutput = path.join(root, "node-runtime-prerequisite-receipt.json");
  const prepareOutput = path.join(root, "prepare-receipt.json");
  const authorityOutput = path.join(root, "exact-release-authority.json");
  const fixtureScripts = path.join(root, "scripts");
  const fixtureSudoers = path.join(root, "sudoers");
  const fixtureSystemd = path.join(root, "systemd");
  const fixtureConfig = path.join(root, "config");
  const fixtureScript = path.join(fixtureScripts, "deploy-v1-install-only.sh");
  fs.mkdirSync(bin);
  fs.mkdirSync(fixtureScripts);
  fs.mkdirSync(fixtureSudoers);
  fs.mkdirSync(fixtureSystemd);
  fs.mkdirSync(fixtureConfig);
  const source = fs.readFileSync(productionScript, "utf8");
  const systemProbe = "SYSTEM_NAME=$(/usr/bin/uname -s)";
  assert.equal(source.split(systemProbe).length - 1, 1);
  fs.writeFileSync(fixtureScript, source.replace(systemProbe, "SYSTEM_NAME=Darwin"), { mode: 0o700 });
  for (const dependency of [
    "ssh-known-host-endpoint.sh", "pinned-ssh-host-key.mjs", "v1-brownfield-install-receipt.mjs",
    "compose-vps.sh", "v1-brownfield-bootstrap-bridge.py", "v1-brownfield-install-consumer.py", "v1-local-private-control.py", "v1-local-private-reconcile.py",
    "v1-local-private-evidence-producer.py", "v1-node-runtime-prerequisite.py",
  ]) fs.copyFileSync(path.join(import.meta.dirname, dependency), path.join(fixtureScripts, dependency));
  fs.copyFileSync(path.join(import.meta.dirname, "..", "sudoers", "platform-v1-local-private-control"), path.join(fixtureSudoers, "platform-v1-local-private-control"));
  fs.copyFileSync(path.join(import.meta.dirname, "..", "systemd", "platform-v1-local-private-control.service"), path.join(fixtureSystemd, "platform-v1-local-private-control.service"));
  fs.copyFileSync(path.join(import.meta.dirname, "..", "config", "local-private-recovery-escrow-cert.pem"), path.join(fixtureConfig, "local-private-recovery-escrow-cert.pem"));
  fs.copyFileSync(path.join(import.meta.dirname, "..", "config", "no-hosted-workloads.local-private.lock.json"), path.join(fixtureConfig, "no-hosted-workloads.local-private.lock.json"));
  for (const filename of ["compose-vps.sh", "v1-brownfield-install-consumer.py", "v1-local-private-control.py", "v1-local-private-reconcile.py"]) {
    fs.chmodSync(path.join(fixtureScripts, filename), 0o555);
  }
  fs.chmodSync(path.join(fixtureSystemd, "platform-v1-local-private-control.service"), 0o444);
  fs.chmodSync(path.join(fixtureSudoers, "platform-v1-local-private-control"), 0o440);

  const artifacts = {
    composeWrapper: { path: `${releaseRoot}/scripts/compose-vps.sh`, sha256: sha256(fs.readFileSync(path.join(fixtureScripts, "compose-vps.sh"))) },
    controller: { path: "/usr/local/libexec/platform-v1-local-private-control", sha256: sha256(fs.readFileSync(path.join(fixtureScripts, "v1-local-private-control.py"))) },
    installer: { path: "/usr/local/libexec/platform-v1-brownfield-install-consumer", sha256: sha256(fs.readFileSync(path.join(fixtureScripts, "v1-brownfield-install-consumer.py"))) },
    reconciler: { path: "/usr/local/libexec/platform-v1-local-private-reconcile", sha256: sha256(fs.readFileSync(path.join(fixtureScripts, "v1-local-private-reconcile.py"))) },
    sudoers: { path: "/etc/sudoers.d/platform-v1-local-private-control", sha256: sha256(fs.readFileSync(path.join(fixtureSudoers, "platform-v1-local-private-control"))) },
    unit: { path: "/etc/systemd/system/platform-v1-local-private-control.service", sha256: sha256(fs.readFileSync(path.join(fixtureSystemd, "platform-v1-local-private-control.service"))) },
  };
  const sourceRenderSha256 = sha256("identity-free-source-render");
  const workloadLockSha256 = sha256(fs.readFileSync(path.join(fixtureConfig, "no-hosted-workloads.local-private.lock.json")));
  const candidateId = sha256(stableJson({ candidateCommit, candidateTree, sourceRenderSha256, workloadLockSha256 }));
  const authority = canonicalDocument({
    activeManagedContainerNames: ["enterprise-managed"], artifacts, authorityMode: "LOCAL_PRIVATE", authorizedDataMutations: [],
    backupToolImages: {
      mariadbRestore: { imageId: `sha256:${sha256("mariadb-image")}`, imageReference: `registry.local/mariadb-restore@sha256:${sha256("mariadb-manifest")}` },
      minioRestore: { imageId: `sha256:${sha256("minio-image")}`, imageReference: `registry.local/minio-restore@sha256:${sha256("minio-manifest")}` },
      nodeUtility: { imageId: `sha256:${sha256("node-image")}`, imageReference: `registry.local/node-utility@sha256:${sha256("node-manifest")}` },
      postgresRestore: { imageId: `sha256:${sha256("postgres-image")}`, imageReference: `registry.local/postgres-restore@sha256:${sha256("postgres-manifest")}` },
      resticRclone: { imageId: `sha256:${sha256("restic-image")}`, imageReference: `registry.local/restic-rclone@sha256:${sha256("restic-manifest")}` },
    },
    candidateCommit, candidateTree,
    checkoutProof: {
      clean: true, githubMainCommit: candidateCommit, githubMainRef: "refs/remotes/github/main",
      headCommit: candidateCommit, headTree: candidateTree, producer: "CLEAN_CHECKOUT_GITHUB_MAIN_V1",
      status: "PASS", verifiedAtUnixSeconds: 1_800_000_000,
    },
    controllerVerificationScope: "AUTHORITY_ARCHIVE_RELEASE_RENDER_ONLY_NOT_GITHUB",
    disabledComposeServices: ["backup-scheduler", "docker-action-activation-sidecar", "docker-action-broker"],
    evidenceProducer: {
      executor: "/usr/bin/python3", executorFlags: ["-I"],
      forbiddenResticOperations: ["forget", "prune"], hostingerAllowed: false,
      logicalKeys: ["anniversary", "fiplatform", "matthewdifilippo", "opstudents", "public", "stexor", "stream", "workcalendar", "pg-stexor", "pg-keycloak", "mariadb", "minio", "keycloak-config", "confidential"],
      offsiteRepository: "rclone:platform-onedrive:platform-infrastructure/restic",
      operations: ["pre", "post"], path: releaseRoot + "/scripts/v1-local-private-evidence-producer.py",
      recoveryEscrowPrefix: "platform-onedrive:platform-infrastructure/key-escrow",
      sha256: sha256(fs.readFileSync(path.join(fixtureScripts, "v1-local-private-evidence-producer.py"))),
    },
    expectedContainerNames: ["enterprise-managed", ...preservedLegacyNames].sort(),
    legacyNetworkAttachments: [{ aliases: [preservedLegacyNames[0]], containerName: preservedLegacyNames[0], networkName: "platform_infra_vps_routing" }],
    legacyRouteChecks: [{ containerName: preservedLegacyNames[0], expectedStatus: 200, name: "legacy-edge-route", url: "https://legacy.example.invalid/" }],
    legacyUnmanagedContainers: preservedLegacyNames.map((containerName) => ({ containerName, reason: "NO_HOSTED_WORKLOAD_AUTHORITY", status: "LEGACY_UNMANAGED" })),
    preservedLegacyContainerNames: preservedLegacyNames,
    recoveryEscrowCertificate: {
      path: `${releaseRoot}/config/local-private-recovery-escrow-cert.pem`,
      sha256: sha256(fs.readFileSync(path.join(fixtureConfig, "local-private-recovery-escrow-cert.pem"))),
      sha256Fingerprint: new crypto.X509Certificate(fs.readFileSync(path.join(fixtureConfig, "local-private-recovery-escrow-cert.pem"))).fingerprint256.replaceAll(":", "").toLowerCase(),
    },
    releaseRoot,
    renderEnvironment: { path: "/var/lib/platform-infrastructure/v1/local-private/exact-compose.env", sha256: sha256("exact-compose-env") },
    renderSha256: sha256("exact-compose-render"), schema: "platform.v1-local-private-exact-release-authority/v1",
    runtimeIdentity: {
      candidateId, commit: candidateCommit, deploymentId: `v1-local-private:${candidateId}`,
      sourceRenderSha256, tree: candidateTree, workloadLockSha256,
    },
    serviceTargets: [{ configHash: sha256("managed-config"), containerName: "enterprise-managed", project: "platform_infra_vps", semantic: validSemantic(), service: "managed" }],
    sourceArchiveSha256, status: "AUTHORIZED",
  });
  const authorityBytes = `${stableJson(authority)}\n`;
  const controlArtifacts = [
    ["installer", artifacts.installer, "0555"], ["controller", artifacts.controller, "0555"],
    ["reconciler", artifacts.reconciler, "0555"], ["unit", artifacts.unit, "0444"], ["sudoers", artifacts.sudoers, "0440"],
  ].map(([name, artifact, mode]) => ({ mode, name, ...artifact }));
  const controlReceipt = stableJson({
    artifacts: controlArtifacts, candidateCommit, candidateTree, dataMutation: false, dockerMutation: false, hostControlMutation: true,
    schema: "platform.v1-control-artifact-install-receipt/v1", sourceArchiveSha256, status: "CONTROL_ARTIFACTS_INSTALLED",
  });
  const prepareReceipt = stableJson({
    authorityDocumentId: authority.documentId,
    authorityPath: "/var/lib/platform-infrastructure/v1/local-private/exact-release-authority.json",
    authoritySha256: sha256(authorityBytes), renderSha256: authority.renderSha256,
    sourceArchiveSha256, status: "PREPARED",
  });
  const nodeRuntimeBase = {
    activationAuthorized: false,
    binaryPath: "/usr/bin/node",
    binarySha256: sha256("fixture-node-runtime"),
    candidateCommit,
    candidateTree,
    dataMutation: false,
    dockerMutation: false,
    helperSha256: sha256(fs.readFileSync(path.join(fixtureScripts, "v1-node-runtime-prerequisite.py"))),
    hostControlMutation: true,
    packageArchitecture: "amd64",
    packageName: "nodejs",
    packageSource: "UBUNTU_APT_EXACT_VERSION",
    packageVersion: "22.22.1+dfsg+~cs22.19.15-1ubuntu1",
    receiptPath: "/var/lib/platform-infrastructure/v1/local-private/node-runtime-prerequisite-receipt.json",
    releaseRoot,
    runtimeVersion: "v22.22.1",
    schema: "platform.v1-node-runtime-prerequisite-receipt/v1",
    sourceArchiveSha256,
    status: "NODE_RUNTIME_READY",
    workloadMutation: false,
  };
  const nodeRuntimeReceipt = stableJson({ ...nodeRuntimeBase, documentId: sha256(stableJson(nodeRuntimeBase)) });

  fs.writeFileSync(key, "test-only-private-key\n", { mode: 0o600 });
  fs.writeFileSync(knownHosts, `[example.internal]:2222 ssh-ed25519 ${keyBlob}\n`, { mode: 0o600 });
  fs.symlinkSync(bundledNode, path.join(bin, "node"));
  fs.writeFileSync(fakeSsh, `#!${bundledNode}
const crypto = require("node:crypto");
const fs = require("node:fs");
const args = process.argv.slice(2);
const command = args.at(-1);
const input = fs.readFileSync(0);
const stable = (value) => Array.isArray(value) ? \`[\${value.map(stable).join(",")}]\` : value && typeof value === "object" ? \`{\${Object.keys(value).sort().map((key) => \`\${JSON.stringify(key)}:\${stable(value[key])}\`).join(",")}}\` : JSON.stringify(value);
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
fs.appendFileSync(process.env.PLATFORM_V1_INSTALL_TEST_SSH_ARGUMENTS, \`CALL\\n\${args.join("\\n")}\\n\`);
fs.appendFileSync(process.env.PLATFORM_V1_INSTALL_TEST_SSH_STDIN_SIZE, \`\${input.length}\\n\`);
if (command.startsWith("/usr/bin/python3 -I -c ") && command.includes("tempfile.mkstemp")) {
  fs.writeFileSync(process.env.PLATFORM_V1_INSTALL_TEST_UPLOADED_BRIDGE, input);
} else if (command === "/usr/bin/sudo -n -- /usr/bin/python3 -I /home/platform_infrastructure/.v1-bootstrap-upload/v1-brownfield-bootstrap-bridge.py apply") {
  fs.writeFileSync(process.env.PLATFORM_V1_INSTALL_TEST_BOOTSTRAP_FRAME, input);
  if (process.env.PLATFORM_V1_INSTALL_TEST_RECEIPT_MODE === "invalid-bootstrap") {
    process.stdout.write('{"schema":"attacker"}\\n');
  } else {
    const manifestLength = Number.parseInt(input.subarray(0, 8).toString(), 16);
    const manifest = JSON.parse(input.subarray(8, 8 + manifestLength).toString());
    const control = process.env.PLATFORM_V1_INSTALL_TEST_RECEIPT_MODE === "invalid-control" ? { schema: "attacker" } : ${controlReceipt};
    const nodeRuntime = process.env.PLATFORM_V1_INSTALL_TEST_RECEIPT_MODE === "invalid-node-runtime" ? { schema: "attacker" } : ${nodeRuntimeReceipt};
    const controlBytes = Buffer.from(stable(control) + "\\n");
    const nodeRuntimeBytes = Buffer.from(stable(nodeRuntime) + "\\n");
    const base = {
      bridgeSha256: manifest.bridgeSha256, candidateCommit: manifest.candidateCommit,
      candidateConsumerSha256: manifest.consumerSha256, candidateTree: manifest.candidateTree,
      checkpointAfterSha256: manifest.checkpointSha256, checkpointBeforeSha256: "1".repeat(64),
      controlArtifactReceiptSha256: sha(controlBytes), dataMutation: false, dockerMutation: false,
      gitBundleSha256: manifest.gitBundleSha256, hostControlMutation: true,
      installReceiptSha256: "2".repeat(64),
      legacyBroadSudoersAfterSha256: sha("platform_infrastructure ALL=(ALL) NOPASSWD:ALL\\n"),
      legacyBroadSudoersBeforeSha256: sha("platform_infrastructure ALL=(ALL) NOPASSWD:ALL\\n"),
      legacyConsumerSha256: "9902e8c83f12cee7d16ee97b660cde12444da479acbe85f9efa4c613d82f76a9",
      legacyV1SudoersSha256: sha("Defaults:platform_infrastructure env_reset\\nDefaults:platform_infrastructure secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\\nplatform_infrastructure ALL=(root) NOPASSWD: /usr/local/libexec/platform-v1-local-private-control activate\\n"),
      nodeRuntimeReceiptSha256: process.env.PLATFORM_V1_INSTALL_TEST_RECEIPT_MODE === "invalid-node-binding" ? "0".repeat(64) : sha(nodeRuntimeBytes),
      releaseRoot: \`/srv/platform-infrastructure/releases/\${manifest.candidateCommit}-\${manifest.sourceArchiveSha256}\`,
      schema: "platform.v1-brownfield-bootstrap-bridge-receipt/v1",
      sourceArchiveAfterSha256: manifest.sourceArchiveSha256, sourceArchiveBeforeSha256: "3".repeat(64),
      stagingEnvironmentSha256: "4".repeat(64), stagingMutation: true, status: "BOOTSTRAP_CONTROL_INSTALLED",
    };
    const bootstrap = { ...base, documentId: sha(stable(base)) };
    process.stdout.write(stable({ bootstrap, controlArtifacts: control, nodeRuntime, schema: "platform.v1-brownfield-bootstrap-result/v1" }) + "\\n");
  }
} else if (command === "/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-reconcile prepare") {
  process.stdout.write('${prepareReceipt}\\n');
} else if (command === "/usr/bin/sudo -n -- /usr/bin/cat /var/lib/platform-infrastructure/v1/local-private/exact-release-authority.json") {
  const calls = (fs.readFileSync(process.env.PLATFORM_V1_INSTALL_TEST_SSH_ARGUMENTS, "utf8").match(/^CALL$/gm) || []).length;
  process.stdout.write(process.env.PLATFORM_V1_INSTALL_TEST_RECEIPT_MODE === "drifting-authority" && calls >= 5 ? '{"schema":"attacker"}\\n' : ${JSON.stringify(authorityBytes)});
} else process.exit(94);
`, { mode: 0o700 });
  fs.writeFileSync(fakeGit, `#!/bin/sh
test "$1" = -C || exit 91
repo=$2
shift 2
case "$1:$2" in
  rev-parse:--show-toplevel) printf '%s\\n' "$repo" ;;
  rev-parse:--verify)
    case "$3" in
      'HEAD^{commit}') printf '%s\\n' '${candidateCommit}' ;;
      'HEAD^{tree}') printf '%s\\n' '${candidateTree}' ;;
      refs/remotes/github/main) if [ "\${PLATFORM_V1_INSTALL_TEST_GIT_MODE:-exact}" = wrong-main ]; then printf '%s\\n' '${"d".repeat(40)}'; else printf '%s\\n' '${candidateCommit}'; fi ;;
      *) exit 92 ;;
    esac ;;
  status:--porcelain=v1) if [ "\${PLATFORM_V1_INSTALL_TEST_GIT_MODE:-exact}" = dirty ]; then printf '%s\\n' '?? attacker'; fi ;;
  archive:--format=tar) printf '%s\\n' 'fixture-source-archive' ;;
  bundle:create) printf '%s\\n' 'fixture-git-bundle' > "$3" ;;
  bundle:verify) : ;;
  bundle:list-heads) printf '%s HEAD\\n' '${candidateCommit}' ;;
  *) exit 93 ;;
esac
`, { mode: 0o700 });

  const environment = {
    ...process.env, PATH: `${bin}:/usr/bin:/bin`, HOME: root,
    DEPLOY_REMOTE: "platform_infrastructure@example.internal", DEPLOY_SSH_PORT: "2222",
    DEPLOY_SSH_KEY_PATH: key, DEPLOY_SSH_KNOWN_HOSTS_PATH: knownHosts,
    PLATFORM_V1_INSTALL_TEST_SSH: fakeSsh, PLATFORM_V1_INSTALL_TEST_GIT: fakeGit,
    PLATFORM_V1_INSTALL_TEST_NODE: bundledNode,
    PLATFORM_V1_INSTALL_TEST_SSH_ARGUMENTS: argumentsFile,
    PLATFORM_V1_INSTALL_TEST_SSH_STDIN_SIZE: stdinSizeFile,
    PLATFORM_V1_INSTALL_TEST_BOOTSTRAP_FRAME: bootstrapFrameFile,
    PLATFORM_V1_INSTALL_TEST_UPLOADED_BRIDGE: uploadedBridgeFile,
  };
  return {
    argumentsFile, authorityBytes, authorityOutput, bootstrapFrameFile, bootstrapOutput, controlOutput,
    controlReceipt, environment, fixtureScript, knownHosts, nodeRuntimeOutput, nodeRuntimeReceipt,
    prepareOutput, prepareReceipt, root,
    stdinSizeFile, uploadedBridgeFile,
  };
}

function defaultArguments(current) {
  return [
    "--bootstrapReceiptFile", current.bootstrapOutput,
    "--controlArtifactReceiptFile", current.controlOutput,
    "--nodeRuntimeReceiptFile", current.nodeRuntimeOutput,
    "--prepareReceiptFile", current.prepareOutput,
    "--authorityFile", current.authorityOutput,
  ];
}

function execute(current, args = defaultArguments(current), environment = {}) {
  return spawnSync("/bin/sh", [current.fixtureScript, ...args], { encoding: "utf8", env: { ...current.environment, ...environment } });
}

function cleanup(current) {
  fs.rmSync(current.root, { recursive: true, force: true });
}

function remoteUploadPython(uploadRoot) {
  const source = fs.readFileSync(productionScript, "utf8");
  const assignment = source.match(/^UPLOAD_BRIDGE_REMOTE_COMMAND="(.*)"$/m);
  assert.ok(assignment);
  const command = assignment[1].replaceAll('\\\"', '"');
  const prefix = "/usr/bin/python3 -I -c '";
  assert.ok(command.startsWith(prefix) && command.endsWith("'"));
  return command.slice(prefix.length, -1).replace(
    'd="/home/platform_infrastructure/.v1-bootstrap-upload"',
    `d=${JSON.stringify(uploadRoot)}`,
  );
}

test("remote bridge upload is FIFO-compatible, bounded, atomic, and mode-exact", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "v1-bridge-upload-test-")));
  const target = path.join(root, "v1-brownfield-bootstrap-bridge.py");
  const payload = fs.readFileSync(path.join(import.meta.dirname, "v1-brownfield-bootstrap-bridge.py"));
  try {
    const uploaded = spawnSync("/usr/bin/python3", ["-I", "-c", remoteUploadPython(root)], { input: payload, encoding: null });
    assert.equal(uploaded.status, 0, uploaded.stderr?.toString());
    assert.deepEqual(fs.readFileSync(target), payload);
    assert.equal(fs.statSync(target).mode & 0o777, 0o500);
    assert.deepEqual(fs.readdirSync(root), ["v1-brownfield-bootstrap-bridge.py"]);

    fs.rmSync(target);
    for (const rejected of [Buffer.alloc(0), Buffer.alloc(2 * 1024 * 1024 + 1)]) {
      const result = spawnSync("/usr/bin/python3", ["-I", "-c", remoteUploadPython(root)], { input: rejected, encoding: null });
      assert.equal(result.status, 65, result.stderr?.toString());
      assert.equal(fs.existsSync(target), false);
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("runs the fixed install, release bootstrap, prepare, and double authority read sequence", () => {
  const current = fixture();
  try {
    const result = execute(current);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, fs.readFileSync(current.bootstrapOutput, "utf8"));
    const stdinSizes = fs.readFileSync(current.stdinSizeFile, "utf8").trim().split("\n").map(Number);
    assert.equal(stdinSizes.length, 5);
    assert.ok(stdinSizes[0] > 0);
    assert.ok(stdinSizes[1] > stdinSizes[0]);
    assert.deepEqual(stdinSizes.slice(2), [0, 0, 0]);
    assert.deepEqual(fs.readFileSync(current.uploadedBridgeFile), fs.readFileSync(path.join(path.dirname(current.fixtureScript), "v1-brownfield-bootstrap-bridge.py")));
    const frame = fs.readFileSync(current.bootstrapFrameFile);
    const manifestLength = Number.parseInt(frame.subarray(0, 8).toString(), 16);
    const manifest = JSON.parse(frame.subarray(8, 8 + manifestLength).toString());
    assert.equal(manifest.schema, "platform.v1-brownfield-bootstrap-frame/v1");
    assert.equal(manifest.candidateCommit, candidateCommit);
    assert.equal(manifest.candidateTree, candidateTree);
    assert.equal(manifest.sourceArchiveSha256, sourceArchiveSha256);
    assert.deepEqual(Object.keys(manifest.lengths).sort(), ["bridge", "checkpoint", "consumer", "gitBundle", "sourceArchive"]);
    const bootstrapReceipt = JSON.parse(fs.readFileSync(current.bootstrapOutput, "utf8"));
    assert.equal(bootstrapReceipt.status, "BOOTSTRAP_CONTROL_INSTALLED");
    assert.equal(bootstrapReceipt.dataMutation, false);
    assert.equal(bootstrapReceipt.dockerMutation, false);
    assert.equal(bootstrapReceipt.stagingMutation, true);
    assert.equal(fs.readFileSync(current.controlOutput, "utf8"), `${current.controlReceipt}\n`);
    assert.equal(fs.readFileSync(current.nodeRuntimeOutput, "utf8"), `${current.nodeRuntimeReceipt}\n`);
    assert.equal(fs.readFileSync(current.prepareOutput, "utf8"), `${current.prepareReceipt}\n`);
    assert.equal(fs.readFileSync(current.authorityOutput, "utf8"), current.authorityBytes);
    for (const filename of [current.bootstrapOutput, current.controlOutput, current.nodeRuntimeOutput, current.prepareOutput, current.authorityOutput]) assert.equal(fs.statSync(filename).mode & 0o777, 0o400);
    const calls = fs.readFileSync(current.argumentsFile, "utf8").split(/^CALL$/m).slice(1).map((item) => item.trim().split("\n"));
    assert.equal(calls.length, 5);
    const commands = calls.map((call) => call.at(-1));
    assert.match(commands[0], /^\/usr\/bin\/python3 -I -c /);
    assert.match(commands[0], /tempfile\.mkstemp/);
    assert.doesNotMatch(commands[0], /\/dev\/stdin/);
    assert.deepEqual(commands.slice(1), [
      "/usr/bin/sudo -n -- /usr/bin/python3 -I /home/platform_infrastructure/.v1-bootstrap-upload/v1-brownfield-bootstrap-bridge.py apply",
      "/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-reconcile prepare",
      "/usr/bin/sudo -n -- /usr/bin/cat /var/lib/platform-infrastructure/v1/local-private/exact-release-authority.json",
      "/usr/bin/sudo -n -- /usr/bin/cat /var/lib/platform-infrastructure/v1/local-private/exact-release-authority.json",
    ]);
    for (const call of calls) {
      assert.ok(call.includes("BatchMode=yes"));
      assert.ok(call.includes("StrictHostKeyChecking=yes"));
      assert.ok(call.includes("ClearAllForwardings=yes"));
      assert.equal(call.some((argument) => [current.bootstrapOutput, current.controlOutput, current.nodeRuntimeOutput, current.prepareOutput, current.authorityOutput].includes(argument)), false);
    }
  } finally { cleanup(current); }
});

test("rejects caller argument drift and unsafe output paths before SSH", () => {
  for (const args of [[], ["/tmp/attacker"]]) {
    const current = fixture();
    try {
      const result = execute(current, args);
      assert.equal(result.status, 64);
      assert.match(result.stderr, /Usage/);
      assert.equal(fs.existsSync(current.argumentsFile), false);
    } finally { cleanup(current); }
  }
  const current = fixture();
  try {
    fs.writeFileSync(current.controlOutput, "occupied\n");
    const result = execute(current);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /already exists/);
    assert.equal(fs.existsSync(current.argumentsFile), false);
  } finally { cleanup(current); }
});

test("fails closed at install, control, Node runtime, and authority drift boundaries", () => {
  for (const [mode, calls] of [["invalid-bootstrap", 2], ["invalid-control", 2], ["invalid-node-binding", 2], ["invalid-node-runtime", 2], ["drifting-authority", 5]]) {
    const current = fixture();
    try {
      const result = execute(current, undefined, { PLATFORM_V1_INSTALL_TEST_RECEIPT_MODE: mode });
      assert.notEqual(result.status, 0);
      assert.equal((fs.readFileSync(current.argumentsFile, "utf8").match(/^CALL$/gm) ?? []).length, calls);
      assert.equal(fs.existsSync(current.bootstrapOutput), false);
      assert.equal(fs.existsSync(current.controlOutput), false);
      assert.equal(fs.existsSync(current.nodeRuntimeOutput), false);
      assert.equal(fs.existsSync(current.prepareOutput), false);
      assert.equal(fs.existsSync(current.authorityOutput), false);
    } finally { cleanup(current); }
  }
});

test("rejects missing host trust and dirty or non-github-main checkout before SSH", () => {
  const missing = fixture();
  try {
    fs.rmSync(missing.knownHosts);
    const result = execute(missing);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /known-hosts input/);
    assert.equal(fs.existsSync(missing.argumentsFile), false);
  } finally { cleanup(missing); }
  for (const mode of ["dirty", "wrong-main"]) {
    const current = fixture();
    try {
      const result = execute(current, undefined, { PLATFORM_V1_INSTALL_TEST_GIT_MODE: mode });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /clean checkout|github\/main/);
      assert.equal(fs.existsSync(current.argumentsFile), false);
    } finally { cleanup(current); }
  }
});

test("real Git bundle transport advertises only the exact HEAD commit", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-install-real-bundle-"));
  try {
    const run = (args) => spawnSync("/usr/bin/git", args, {
      cwd: root, encoding: "utf8",
      env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", HOME: "/nonexistent" },
    });
    assert.equal(run(["init", "--quiet"]).status, 0);
    assert.equal(run(["config", "user.name", "V1 Fixture"]).status, 0);
    assert.equal(run(["config", "user.email", "v1@example.invalid"]).status, 0);
    fs.writeFileSync(path.join(root, "payload"), "exact HEAD bundle\n");
    assert.equal(run(["add", "payload"]).status, 0);
    assert.equal(run(["commit", "--quiet", "-m", "fixture"]).status, 0);
    const head = run(["rev-parse", "HEAD"]).stdout.trim();
    const bundle = path.join(root, "candidate.bundle");
    const created = run(["bundle", "create", bundle, "HEAD"]);
    assert.equal(created.status, 0, created.stderr);
    assert.equal(run(["bundle", "verify", bundle]).status, 0);
    assert.equal(run(["bundle", "list-heads", bundle]).stdout.trim(), `${head} HEAD`);
    const rawCommit = run(["bundle", "create", path.join(root, "raw.bundle"), head]);
    assert.notEqual(rawCommit.status, 0);
    assert.match(rawCommit.stderr, /empty bundle/i);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("source derives exact-main identity and exposes only the closed staging sequence", () => {
  const source = fs.readFileSync(productionScript, "utf8");
  for (const value of [
    "rev-parse --verify 'HEAD^{commit}'", "rev-parse --verify 'HEAD^{tree}'", "rev-parse --verify refs/remotes/github/main",
    "status --porcelain=v1 --untracked-files=all", "archive --format=tar HEAD", 'bundle create "$git_bundle" HEAD',
    'bundle verify "$git_bundle"', 'bundle list-heads "$git_bundle"',
    "platform.v1-bootstrap-transport-checkpoint/v1", "platform.v1-brownfield-bootstrap-frame/v1",
    "UPLOAD_BRIDGE_REMOTE_COMMAND=", "BOOTSTRAP_REMOTE_COMMAND='/usr/bin/sudo -n -- /usr/bin/python3 -I /home/platform_infrastructure/.v1-bootstrap-upload/v1-brownfield-bootstrap-bridge.py apply'",
    "PREPARE_REMOTE_COMMAND='/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-reconcile prepare'",
    "READ_AUTHORITY_REMOTE_COMMAND='/usr/bin/sudo -n -- /usr/bin/cat /var/lib/platform-infrastructure/v1/local-private/exact-release-authority.json'",
    "nodeRuntimeReceiptSha256", "verify-node-runtime",
    "verify-bootstrap", "verify-control-artifacts", "verify-authority", "verify-prepare", "SSH=/usr/bin/ssh",
    "/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node",
    'SSH=${PLATFORM_V1_INSTALL_TEST_SSH:-$SSH}', 'GIT=${PLATFORM_V1_INSTALL_TEST_GIT:-$GIT}', 'NODE=${PLATFORM_V1_INSTALL_TEST_NODE:-$NODE}',
  ]) assert.ok(source.includes(value), `install client is missing ${value}`);
  for (const stale of ["832bf2baec47055342af" + "7e7f73425444381b91e0", "91cee2380809cb0691b9" + "ac47cafa2a673d434caa"]) {
    assert.equal(source.includes(stale), false);
  }
  assert.match(source, /UPLOAD_BRIDGE_REMOTE_COMMAND="\/usr\/bin\/python3 -I -c '/);
  assert.match(source, /sys\.stdin\.buffer\.read\(2097153\)/);
  assert.match(source, /tempfile\.mkstemp\(prefix=\\\"\.bridge-upload-\\\",dir=d\)/);
  assert.match(source, /os\.replace\(p,t\)/);
  assert.match(source, /stat\.S_IMODE\(s\.st_mode\)==0o500/);
  assert.doesNotMatch(source, /install -m 0500 \/dev\/stdin/);
  assert.doesNotMatch(source, /git (?:fetch|pull|checkout)|docker |scp |sftp |sh -s|platform-activation-broker/);
  assert.doesNotMatch(source, /sudo -n -- \/usr\/bin\/python3 -I \/srv\/platform-infrastructure\/releases\/.*v1-node-runtime-prerequisite/);
});
