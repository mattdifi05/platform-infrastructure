#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  V1_EXACT_RELEASE_AUTHORITY_PATH,
  V1_INSTALL_READY_BUT_DISABLED,
  verifyV1ControlArtifactReceipt,
  verifyV1ExactReleaseAuthority,
  verifyV1InstallReceipt,
  verifyV1NodeRuntimePrerequisiteReceipt,
  verifyV1PrepareReceipt,
} from "./v1-brownfield-install-receipt.mjs";

const verifier = path.join(import.meta.dirname, "v1-brownfield-install-receipt.mjs");
const candidateCommit = "1".repeat(40);
const candidateTree = "2".repeat(40);
const sourceArchiveSha256 = "3".repeat(64);
const releaseRoot = `/srv/platform-infrastructure/releases/${candidateCommit}-${sourceArchiveSha256}`;
const repositoryRoot = path.resolve(import.meta.dirname, "..");
const preservedLegacyNames = Array.from({ length: 19 }, (_, index) => `node-legacy-${String(index + 1).padStart(2, "0")}`);
const artifactSpecs = [
  ["installer", "scripts/v1-brownfield-install-consumer.py", "/usr/local/libexec/platform-v1-brownfield-install-consumer", "0555"],
  ["controller", "scripts/v1-local-private-control.py", "/usr/local/libexec/platform-v1-local-private-control", "0555"],
  ["reconciler", "scripts/v1-local-private-reconcile.py", "/usr/local/libexec/platform-v1-local-private-reconcile", "0555"],
  ["unit", "systemd/platform-v1-local-private-control.service", "/etc/systemd/system/platform-v1-local-private-control.service", "0444"],
  ["sudoers", "sudoers/platform-v1-local-private-control", "/etc/sudoers.d/platform-v1-local-private-control", "0440"],
];

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

function validReceipt(overrides = {}) {
  const value = {
    activationAuthorized: false,
    authorizationSource: "ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY",
    backupEvidenceAuthoritative: false,
    candidateCommit,
    candidateTree,
    dataMutation: false,
    dockerMutation: false,
    readyButDisabled: [...V1_INSTALL_READY_BUT_DISABLED],
    releaseRoot,
    schema: "platform.v1-brownfield-install-receipt/v1",
    sourceArchiveSha256,
    status: "INSTALL_ONLY_COMPLETE",
    ...overrides,
  };
  if (!Object.hasOwn(overrides, "releaseRoot")) {
    value.releaseRoot = `/srv/platform-infrastructure/releases/${value.candidateCommit}-${value.sourceArchiveSha256}`;
  }
  return value;
}

function withDocumentId(base) {
  return { ...base, documentId: sha256(stableJson(base)) };
}

function validSemantic() {
  return {
    capAdd: [],
    capDrop: ["ALL"],
    command: [],
    entrypoint: [],
    environment: [{ name: "PLATFORM_MODE", valueSha256: sha256("LOCAL_PRIVATE") }],
    healthcheck: null,
    imageId: `sha256:${"b".repeat(64)}`,
    imageReference: `registry.local/managed@sha256:${"c".repeat(64)}`,
    init: true,
    mounts: [],
    networkMode: "managed",
    networks: ["platform_infra_vps_internal"],
    pidsLimit: 128,
    ports: [],
    privileged: false,
    readOnlyRootfs: true,
    restartPolicy: "unless-stopped",
    securityOpt: ["no-new-privileges:true"],
    user: "65532:65532",
  };
}

function validAuthority(overrides = {}) {
  const sourceRenderSha256 = sha256("identity-free-source-render");
  const workloadLockSha256 = sha256(fs.readFileSync(path.join(repositoryRoot, "config/no-hosted-workloads.local-private.lock.json")));
  const candidateId = sha256(stableJson({
    candidateCommit, candidateTree, sourceRenderSha256, workloadLockSha256,
  }));
  const base = {
    activeManagedContainerNames: ["enterprise-managed"],
    artifacts: {
      composeWrapper: { path: `${releaseRoot}/scripts/compose-vps.sh`, sha256: "4".repeat(64) },
      controller: { path: "/usr/local/libexec/platform-v1-local-private-control", sha256: "5".repeat(64) },
      installer: { path: "/usr/local/libexec/platform-v1-brownfield-install-consumer", sha256: "6".repeat(64) },
      reconciler: { path: "/usr/local/libexec/platform-v1-local-private-reconcile", sha256: "7".repeat(64) },
      sudoers: { path: "/etc/sudoers.d/platform-v1-local-private-control", sha256: "9".repeat(64) },
      unit: { path: "/etc/systemd/system/platform-v1-local-private-control.service", sha256: "8".repeat(64) },
    },
    authorityMode: "LOCAL_PRIVATE",
    authorizedDataMutations: [],
    backupToolImages: {
      mariadbRestore: { imageId: `sha256:${sha256("mariadb-image")}`, imageReference: `registry.local/mariadb-restore@sha256:${sha256("mariadb-manifest")}` },
      minioRestore: { imageId: `sha256:${sha256("minio-image")}`, imageReference: `registry.local/minio-restore@sha256:${sha256("minio-manifest")}` },
      nodeUtility: { imageId: `sha256:${sha256("node-image")}`, imageReference: `registry.local/node-utility@sha256:${sha256("node-manifest")}` },
      postgresRestore: { imageId: `sha256:${sha256("postgres-image")}`, imageReference: `registry.local/postgres-restore@sha256:${sha256("postgres-manifest")}` },
      resticRclone: { imageId: `sha256:${sha256("restic-image")}`, imageReference: `registry.local/restic-rclone@sha256:${sha256("restic-manifest")}` },
    },
    candidateCommit,
    candidateTree,
    checkoutProof: {
      clean: true,
      githubMainCommit: candidateCommit,
      githubMainRef: "refs/remotes/github/main",
      headCommit: candidateCommit,
      headTree: candidateTree,
      producer: "CLEAN_CHECKOUT_GITHUB_MAIN_V1",
      status: "PASS",
      verifiedAtUnixSeconds: 1_800_000_000,
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
      sha256: sha256(fs.readFileSync(path.join(repositoryRoot, "scripts/v1-local-private-evidence-producer.py"))),
    },
    expectedContainerNames: ["enterprise-managed", ...preservedLegacyNames].sort(),
    legacyNetworkAttachments: [{ aliases: [preservedLegacyNames[0]], containerName: preservedLegacyNames[0], networkName: "platform_infra_vps_routing" }],
    legacyRouteChecks: [{ containerName: preservedLegacyNames[0], expectedStatus: 200, name: "legacy-edge-route", url: "https://legacy.example.invalid/" }],
    legacyUnmanagedContainers: preservedLegacyNames.map((containerName) => ({ containerName, reason: "NO_HOSTED_WORKLOAD_AUTHORITY", status: "LEGACY_UNMANAGED" })),
    preservedLegacyContainerNames: preservedLegacyNames,
    recoveryEscrowCertificate: {
      path: `${releaseRoot}/config/local-private-recovery-escrow-cert.pem`,
      sha256: sha256(fs.readFileSync(path.join(repositoryRoot, "config/local-private-recovery-escrow-cert.pem"))),
      sha256Fingerprint: new crypto.X509Certificate(fs.readFileSync(path.join(repositoryRoot, "config/local-private-recovery-escrow-cert.pem"))).fingerprint256.replaceAll(":", "").toLowerCase(),
    },
    releaseRoot,
    renderEnvironment: { path: "/var/lib/platform-infrastructure/v1/local-private/exact-compose.env", sha256: "9".repeat(64) },
    renderSha256: "a".repeat(64),
    runtimeIdentity: {
      candidateId, commit: candidateCommit, deploymentId: `v1-local-private:${candidateId}`,
      sourceRenderSha256, tree: candidateTree, workloadLockSha256,
    },
    schema: "platform.v1-local-private-exact-release-authority/v1",
    serviceTargets: [{ configHash: sha256("managed-config"), containerName: "enterprise-managed", project: "platform_infra_vps", semantic: validSemantic(), service: "managed" }],
    sourceArchiveSha256,
    status: "AUTHORIZED",
    ...overrides,
  };
  return withDocumentId(base);
}

function repositoryArtifacts() {
  return artifactSpecs.map(([name, source, target, mode]) => ({
    mode,
    name,
    path: target,
    sha256: sha256(fs.readFileSync(path.join(repositoryRoot, source))),
  }));
}

function validControlArtifactReceipt(overrides = {}) {
  return {
    artifacts: repositoryArtifacts(),
    candidateCommit,
    candidateTree,
    dataMutation: false,
    dockerMutation: false,
    hostControlMutation: true,
    schema: "platform.v1-control-artifact-install-receipt/v1",
    sourceArchiveSha256,
    status: "CONTROL_ARTIFACTS_INSTALLED",
    ...overrides,
  };
}

function validPrepareReceipt(authority) {
  return {
    authorityDocumentId: authority.documentId,
    authorityPath: V1_EXACT_RELEASE_AUTHORITY_PATH,
    authoritySha256: sha256(`${stableJson(authority)}\n`),
    renderSha256: authority.renderSha256,
    sourceArchiveSha256: authority.sourceArchiveSha256,
    status: "PREPARED",
  };
}

function validNodeRuntimeReceipt(overrides = {}) {
  const base = {
    activationAuthorized: false,
    binaryPath: "/usr/bin/node",
    binarySha256: sha256("node-runtime-binary"),
    candidateCommit,
    candidateTree,
    dataMutation: false,
    dockerMutation: false,
    helperSha256: sha256(fs.readFileSync(path.join(repositoryRoot, "scripts/v1-node-runtime-prerequisite.py"))),
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
    ...overrides,
  };
  return withDocumentId(base);
}

function fixture(t, { authority = validAuthority(), receipt = validReceipt(), canonicalReceipt = true } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-install-receipt-test-"));
  t?.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const authorityFile = path.join(root, "authority.json");
  const receiptFile = path.join(root, "receipt.json");
  fs.writeFileSync(authorityFile, `${stableJson(authority)}\n`, { mode: 0o600 });
  fs.writeFileSync(receiptFile, canonicalReceipt ? `${stableJson(receipt)}\n` : `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
  return { authorityFile, receiptFile, root };
}

function explicit(file, overrides = {}) {
  return verifyV1InstallReceipt({ file, candidateCommit, candidateTree, sourceArchiveSha256, ...overrides });
}

test("accepts the exact install-only receipt against dynamic expected candidate values", (t) => {
  const current = fixture(t);
  assert.equal(explicit(current.receiptFile).status, "INSTALL_ONLY_COMPLETE");
});

test("accepts the same V1 receipt against the post-prepare exact release authority", (t) => {
  const current = fixture(t);
  const authority = verifyV1ExactReleaseAuthority({ file: current.authorityFile });
  assert.equal(authority.documentId, validAuthority().documentId);
  assert.equal(authority.binding.releaseRoot, releaseRoot);
  assert.equal(verifyV1InstallReceipt({ file: current.receiptFile, authorityFile: current.authorityFile }).status, "INSTALL_ONLY_COMPLETE");
});

test("accepts an idempotent exact already-installed receipt", (t) => {
  const current = fixture(t, { receipt: validReceipt({ status: "ALREADY_INSTALLED" }) });
  assert.equal(explicit(current.receiptFile).status, "ALREADY_INSTALLED");
});

test("accepts the exact closed five-artifact receipt against exact-main source bytes", (t) => {
  const current = fixture(t, { receipt: validControlArtifactReceipt() });
  const receipt = verifyV1ControlArtifactReceipt({
    file: current.receiptFile,
    candidateCommit,
    candidateTree,
    sourceArchiveSha256,
    repositoryRoot,
  });
  assert.equal(receipt.status, "CONTROL_ARTIFACTS_INSTALLED");
  assert.deepEqual(receipt.artifacts.map(({ name }) => name), ["installer", "controller", "reconciler", "unit", "sudoers"]);
});

test("accepts authority-bound idempotent control artifact receipt", (t) => {
  const authority = validAuthority();
  const artifacts = artifactSpecs.map(([name, , target, mode]) => ({
    mode,
    name,
    path: target,
    sha256: authority.artifacts[name].sha256,
  }));
  const current = fixture(t, {
    authority,
    receipt: validControlArtifactReceipt({ artifacts, hostControlMutation: false, status: "ALREADY_INSTALLED" }),
  });
  assert.equal(verifyV1ControlArtifactReceipt({ file: current.receiptFile, authorityFile: current.authorityFile }).status, "ALREADY_INSTALLED");
});

test("rejects extra, reordered, renamed, rehashed, or mutation-capable control artifacts", (t) => {
  const cases = [
    { artifacts: [...repositoryArtifacts(), repositoryArtifacts()[0]] },
    { artifacts: [...repositoryArtifacts()].reverse() },
    { artifacts: repositoryArtifacts().map((item, index) => index ? item : { ...item, name: "consumer" }) },
    { artifacts: repositoryArtifacts().map((item, index) => index ? item : { ...item, sha256: "f".repeat(64) }) },
    { dockerMutation: true },
    { hostControlMutation: false },
  ];
  for (const overrides of cases) {
    const current = fixture(t, { receipt: validControlArtifactReceipt(overrides) });
    assert.throws(() => verifyV1ControlArtifactReceipt({
      file: current.receiptFile,
      candidateCommit,
      candidateTree,
      sourceArchiveSha256,
      repositoryRoot,
    }), /artifact|mutation/i);
  }
});

test("binds the closed prepare result to the exact immutable authority", (t) => {
  const authority = validAuthority();
  const current = fixture(t, { authority, receipt: validPrepareReceipt(authority) });
  assert.equal(verifyV1PrepareReceipt({ file: current.receiptFile, authorityFile: current.authorityFile }).status, "PREPARED");
  const bad = fixture(t, { authority, receipt: { ...validPrepareReceipt(authority), renderSha256: "f".repeat(64) } });
  assert.throws(() => verifyV1PrepareReceipt({ file: bad.receiptFile, authorityFile: bad.authorityFile }), /differs/);
});

test("binds the exact Ubuntu Node runtime prerequisite and its mutation truth", (t) => {
  let current = fixture(t, { receipt: validNodeRuntimeReceipt() });
  let receipt = verifyV1NodeRuntimePrerequisiteReceipt({
    file: current.receiptFile, candidateCommit, candidateTree, sourceArchiveSha256, repositoryRoot,
  });
  assert.equal(receipt.status, "NODE_RUNTIME_READY");
  assert.equal(receipt.hostControlMutation, true);

  current = fixture(t, { receipt: validNodeRuntimeReceipt({ hostControlMutation: false }) });
  receipt = verifyV1NodeRuntimePrerequisiteReceipt({
    file: current.receiptFile, candidateCommit, candidateTree, sourceArchiveSha256, repositoryRoot,
  });
  assert.equal(receipt.hostControlMutation, false);

  for (const overrides of [
    { packageVersion: "latest" },
    { packageArchitecture: "arm64" },
    { runtimeVersion: "v22.22.0" },
    { binaryPath: "/tmp/node" },
    { dataMutation: true },
    { dockerMutation: true },
    { workloadMutation: true },
    { helperSha256: "f".repeat(64) },
  ]) {
    current = fixture(t, { receipt: validNodeRuntimeReceipt(overrides) });
    assert.throws(() => verifyV1NodeRuntimePrerequisiteReceipt({
      file: current.receiptFile, candidateCommit, candidateTree, sourceArchiveSha256, repositoryRoot,
    }), /Node runtime|mutation|helper/i);
  }
});

for (const [name, override, pattern] of [
  ["wrong candidate commit", { candidateCommit: "c".repeat(40) }, /candidateCommit/],
  ["wrong candidate tree", { candidateTree: "d".repeat(40) }, /candidateTree/],
  ["activation authority", { activationAuthorized: true }, /activationAuthorized/],
  ["caller authorization source", { authorizationSource: "CALLER_ASSERTED" }, /authorization source/],
  ["authoritative backup claim", { backupEvidenceAuthoritative: true }, /non-authoritative/],
  ["Docker mutation", { dockerMutation: true }, /dockerMutation/],
  ["data mutation", { dataMutation: true }, /dataMutation/],
  ["READY_BUT_DISABLED reordering", { readyButDisabled: [...V1_INSTALL_READY_BUT_DISABLED].reverse() }, /READY_BUT_DISABLED/],
  ["release-root mismatch", { releaseRoot: "/srv/platform-infrastructure/releases/attacker" }, /release root/],
  ["invalid archive hash", { sourceArchiveSha256: "A".repeat(64) }, /source archive/],
  ["wrong archive hash", { sourceArchiveSha256: "b".repeat(64) }, /sourceArchiveSha256/],
]) {
  test(`rejects ${name}`, (t) => {
    const current = fixture(t, { receipt: validReceipt(override) });
    assert.throws(() => explicit(current.receiptFile), pattern);
  });
}

test("rejects authority drift in document ID, main proof, artifacts and source binding", (t) => {
  let current = fixture(t, { authority: { ...validAuthority(), documentId: "f".repeat(64) } });
  assert.throws(() => verifyV1InstallReceipt({ file: current.receiptFile, authorityFile: current.authorityFile }), /document ID/);

  const badProofBase = validAuthority();
  delete badProofBase.documentId;
  badProofBase.checkoutProof = { ...badProofBase.checkoutProof, githubMainRef: "refs/heads/attacker" };
  current = fixture(t, { authority: withDocumentId(badProofBase) });
  assert.throws(() => verifyV1ExactReleaseAuthority({ file: current.authorityFile }), /checkout proof/);

  const badArtifactBase = validAuthority();
  delete badArtifactBase.documentId;
  badArtifactBase.artifacts = { ...badArtifactBase.artifacts, installer: { ...badArtifactBase.artifacts.installer, path: "/tmp/installer" } };
  current = fixture(t, { authority: withDocumentId(badArtifactBase) });
  assert.throws(() => verifyV1ExactReleaseAuthority({ file: current.authorityFile }), /installer artifact path/);

  const otherArchive = validAuthority({ sourceArchiveSha256: "b".repeat(64), releaseRoot: `/srv/platform-infrastructure/releases/${candidateCommit}-${"b".repeat(64)}` });
  otherArchive.artifacts.composeWrapper.path = `${otherArchive.releaseRoot}/scripts/compose-vps.sh`;
  otherArchive.recoveryEscrowCertificate.path = `${otherArchive.releaseRoot}/config/local-private-recovery-escrow-cert.pem`;
  otherArchive.evidenceProducer.path = otherArchive.releaseRoot + "/scripts/v1-local-private-evidence-producer.py";
  delete otherArchive.documentId;
  current = fixture(t, { authority: withDocumentId(otherArchive) });
  assert.throws(() => verifyV1InstallReceipt({ file: current.receiptFile, authorityFile: current.authorityFile }), /sourceArchiveSha256/);
});

test("rejects incomplete, reordered, or invalid legacy unmanaged classifications", (t) => {
  const cases = [
    {
      mutate(authority) { authority.legacyUnmanagedContainers.pop(); },
      pattern: /nineteen-container set/,
    },
    {
      mutate(authority) { authority.legacyUnmanagedContainers.reverse(); },
      pattern: /canonically aligned/,
    },
    {
      mutate(authority) { authority.legacyUnmanagedContainers[0].status = "MANAGED"; },
      pattern: /invalid legacy unmanaged container classification/,
    },
    {
      mutate(authority) { authority.legacyUnmanagedContainers[0].reason = "CALLER_ASSERTED"; },
      pattern: /invalid legacy unmanaged container classification/,
    },
    {
      mutate(authority) { authority.legacyUnmanagedContainers[0].unexpected = true; },
      pattern: /missing or unexpected fields/,
    },
  ];
  for (const { mutate, pattern } of cases) {
    const authority = validAuthority();
    delete authority.documentId;
    mutate(authority);
    const current = fixture(t, { authority: withDocumentId(authority) });
    assert.throws(() => verifyV1ExactReleaseAuthority({ file: current.authorityFile }), pattern);
  }
});

test("rejects runtime identity and Compose config-hash drift", (t) => {
  const cases = [
    {
      mutate(authority) { authority.runtimeIdentity.candidateId = "f".repeat(64); },
      pattern: /runtime identity is not derived/,
    },
    {
      mutate(authority) { authority.runtimeIdentity.deploymentId = "v1-local-private:attacker"; },
      pattern: /runtime identity is not derived/,
    },
    {
      mutate(authority) { authority.runtimeIdentity.commit = "f".repeat(40); },
      pattern: /runtime identity is not derived/,
    },
    {
      mutate(authority) { authority.runtimeIdentity.tree = "f".repeat(40); },
      pattern: /runtime identity is not derived/,
    },
    {
      mutate(authority) { authority.runtimeIdentity.sourceRenderSha256 = "0".repeat(64); },
      pattern: /runtime source render/,
    },
    {
      mutate(authority) { authority.runtimeIdentity.workloadLockSha256 = "0".repeat(64); },
      pattern: /runtime workload lock/,
    },
    {
      mutate(authority) { authority.serviceTargets[0].configHash = "0".repeat(64); },
      pattern: /Compose config hash/,
    },
    {
      mutate(authority) { delete authority.serviceTargets[0].configHash; },
      pattern: /missing or unexpected fields/,
    },
  ];
  for (const { mutate, pattern } of cases) {
    const authority = validAuthority();
    delete authority.documentId;
    mutate(authority);
    const current = fixture(t, { authority: withDocumentId(authority) });
    assert.throws(() => verifyV1ExactReleaseAuthority({ file: current.authorityFile }), pattern);
  }

  const workloadDrift = validAuthority();
  delete workloadDrift.documentId;
  workloadDrift.runtimeIdentity.workloadLockSha256 = sha256("different-workload-lock");
  workloadDrift.runtimeIdentity.candidateId = sha256(stableJson({
    candidateCommit: workloadDrift.candidateCommit,
    candidateTree: workloadDrift.candidateTree,
    sourceRenderSha256: workloadDrift.runtimeIdentity.sourceRenderSha256,
    workloadLockSha256: workloadDrift.runtimeIdentity.workloadLockSha256,
  }));
  workloadDrift.runtimeIdentity.deploymentId = `v1-local-private:${workloadDrift.runtimeIdentity.candidateId}`;
  for (const artifact of repositoryArtifacts()) workloadDrift.artifacts[artifact.name].sha256 = artifact.sha256;
  workloadDrift.artifacts.composeWrapper.sha256 = sha256(fs.readFileSync(path.join(repositoryRoot, "scripts/compose-vps.sh")));
  const current = fixture(t, { authority: withDocumentId(workloadDrift) });
  assert.throws(() => verifyV1ExactReleaseAuthority({
    file: current.authorityFile,
    repositoryRoot,
  }), /workload-lock bytes differ/);
});

test("rejects mixed or incomplete expected-authority modes", (t) => {
  const current = fixture(t);
  assert.throws(() => verifyV1InstallReceipt({ file: current.receiptFile, authorityFile: current.authorityFile, candidateCommit }), /mutually exclusive/);
  assert.throws(() => verifyV1InstallReceipt({ file: current.receiptFile, candidateCommit }), /complete explicit/);
});

test("rejects unexpected fields, non-canonical JSON and symlinks", (t) => {
  let current = fixture(t, { receipt: validReceipt({ authorization: "caller-asserted" }) });
  assert.throws(() => explicit(current.receiptFile), /missing or unexpected fields/);
  current = fixture(t, { canonicalReceipt: false });
  assert.throws(() => explicit(current.receiptFile), /not canonical/);
  const link = path.join(current.root, "receipt-link.json");
  fs.symlinkSync(current.receiptFile, link);
  assert.throws(() => explicit(link), /regular non-symlink/);
});

test("CLI exposes both exact authority and explicit dynamic expected modes", (t) => {
  const current = fixture(t);
  let result = spawnSync(process.execPath, [verifier, "verify", "--file", current.receiptFile, "--authorityFile", current.authorityFile], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  result = spawnSync(process.execPath, [
    verifier, "verify", "--file", current.receiptFile,
    "--candidateCommit", candidateCommit, "--candidateTree", candidateTree,
    "--sourceArchiveSha256", sourceArchiveSha256,
  ], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const control = fixture(t, { receipt: validControlArtifactReceipt() });
  result = spawnSync(process.execPath, [
    verifier, "verify-control-artifacts", "--file", control.receiptFile,
    "--candidateCommit", candidateCommit, "--candidateTree", candidateTree,
    "--sourceArchiveSha256", sourceArchiveSha256, "--repositoryRoot", repositoryRoot,
  ], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  result = spawnSync(process.execPath, [verifier, "verify-authority", "--file", current.authorityFile], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const authority = validAuthority();
  const prepared = fixture(t, { authority, receipt: validPrepareReceipt(authority) });
  result = spawnSync(process.execPath, [
    verifier, "verify-prepare", "--file", prepared.receiptFile, "--authorityFile", prepared.authorityFile,
  ], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const nodeRuntime = fixture(t, { receipt: validNodeRuntimeReceipt() });
  result = spawnSync(process.execPath, [
    verifier, "verify-node-runtime", "--file", nodeRuntime.receiptFile,
    "--candidateCommit", candidateCommit, "--candidateTree", candidateTree,
    "--sourceArchiveSha256", sourceArchiveSha256, "--repositoryRoot", repositoryRoot,
  ], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});

test("source has no deploy-capable historical candidate pin and exports the fixed authority origin", () => {
  const source = fs.readFileSync(verifier, "utf8");
  assert.equal(V1_EXACT_RELEASE_AUTHORITY_PATH, "/var/lib/platform-infrastructure/v1/local-private/exact-release-authority.json");
  assert.doesNotMatch(source, /V1_INSTALL_(?:CANDIDATE_COMMIT|CANDIDATE_TREE|SOURCE_ARCHIVE_SHA256)\s*=/);
  assert.match(source, /--authorityFile/);
});
