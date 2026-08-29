#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  V1_LOCAL_PRIVATE_ACTIVE_MANAGED_CONTAINER_NAMES as activeManaged,
  V1_LOCAL_PRIVATE_CANONICAL_CONTAINER_NAMES as canonicalNames,
  V1_LOCAL_PRIVATE_PRESERVED_LEGACY_CONTAINER_NAMES as preservedLegacy,
} from "./v1-local-private-control-receipt.mjs";

const productionScript = path.join(import.meta.dirname, "deploy-v1-local-private.sh");
const bundledNode = process.execPath;
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
const stableJson = (value) => Array.isArray(value)
  ? `[${value.map(stableJson).join(",")}]`
  : value && typeof value === "object"
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`
    : JSON.stringify(value);
const candidateCommit = sha("dynamic-main-commit").slice(0, 40);
const candidateTree = sha("dynamic-main-tree").slice(0, 40);
const sourceArchiveSha256 = sha("dynamic-source-archive");

function canonicalDocument(value) {
  return { ...value, documentId: sha(stableJson(value)) };
}

function writeCanonical(filename, value, mode = 0o400) {
  fs.writeFileSync(filename, `${stableJson(value)}\n`, { mode: 0o600 });
  fs.chmodSync(filename, mode);
}

function rewriteAuthority(filename, mutate) {
  fs.chmodSync(filename, 0o600);
  const authority = JSON.parse(fs.readFileSync(filename, "utf8"));
  delete authority.documentId;
  mutate(authority);
  writeCanonical(filename, canonicalDocument(authority));
}

function sshString(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

const keyBlob = Buffer.concat([
  sshString("ssh-ed25519"),
  sshString(Buffer.alloc(32, 11)),
]).toString("base64");

function authorityFixture({ composeWrapperSha256, controllerSha256, installerSha256, reconcilerSha256, sudoersSha256, unitSha256, workloadLockSha256 }) {
  const releaseRoot = `/srv/platform-infrastructure/releases/${candidateCommit}-${sourceArchiveSha256}`;
  const sourceRenderSha256 = sha("runtime-source-render");
  const candidateId = sha(stableJson({
    candidateCommit,
    candidateTree,
    sourceRenderSha256,
    workloadLockSha256,
  }));
  return canonicalDocument({
    activeManagedContainerNames: activeManaged,
    artifacts: {
      composeWrapper: { path: `${releaseRoot}/scripts/compose-vps.sh`, sha256: composeWrapperSha256 },
      controller: { path: "/usr/local/libexec/platform-v1-local-private-control", sha256: controllerSha256 },
      installer: { path: "/usr/local/libexec/platform-v1-brownfield-install-consumer", sha256: installerSha256 },
      reconciler: { path: "/usr/local/libexec/platform-v1-local-private-reconcile", sha256: reconcilerSha256 },
      sudoers: { path: "/etc/sudoers.d/platform-v1-local-private-control", sha256: sudoersSha256 },
      unit: { path: "/etc/systemd/system/platform-v1-local-private-control.service", sha256: unitSha256 },
    },
    authorityMode: "LOCAL_PRIVATE",
    authorizedDataMutations: [],
    backupToolImages: {
      mariadbRestore: { imageId: `sha256:${sha("mariadb-image")}`, imageReference: `registry.local/mariadb-restore@sha256:${sha("mariadb-manifest")}` },
      minioRestore: { imageId: `sha256:${sha("minio-image")}`, imageReference: `registry.local/minio-restore@sha256:${sha("minio-manifest")}` },
      nodeUtility: { imageId: `sha256:${sha("node-image")}`, imageReference: `registry.local/node-utility@sha256:${sha("node-manifest")}` },
      postgresRestore: { imageId: `sha256:${sha("postgres-image")}`, imageReference: `registry.local/postgres-restore@sha256:${sha("postgres-manifest")}` },
      resticRclone: { imageId: `sha256:${sha("restic-image")}`, imageReference: `registry.local/restic-rclone@sha256:${sha("restic-manifest")}` },
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
      sha256: sha(fs.readFileSync(path.join(import.meta.dirname, "v1-local-private-evidence-producer.py"))),
    },
    expectedContainerNames: canonicalNames,
    legacyNetworkAttachments: [{
      aliases: ["node-account"],
      containerName: "node-account",
      networkName: "platform_infra_vps_enterprise_net",
    }],
    legacyRouteChecks: [{
      containerName: "node-account",
      expectedStatus: 200,
      name: "account-edge-route",
      url: "https://account.platform-infrastructure.com/",
    }],
    legacyUnmanagedContainers: preservedLegacy.map((containerName) => ({
      containerName,
      reason: "NO_HOSTED_WORKLOAD_AUTHORITY",
      status: "LEGACY_UNMANAGED",
    })),
    preservedLegacyContainerNames: preservedLegacy,
    recoveryEscrowCertificate: {
      path: `${releaseRoot}/config/local-private-recovery-escrow-cert.pem`,
      sha256: sha(fs.readFileSync(path.join(import.meta.dirname, "..", "config", "local-private-recovery-escrow-cert.pem"))),
      sha256Fingerprint: new crypto.X509Certificate(fs.readFileSync(path.join(import.meta.dirname, "..", "config", "local-private-recovery-escrow-cert.pem"))).fingerprint256.replaceAll(":", "").toLowerCase(),
    },
    releaseRoot,
    renderEnvironment: {
      path: "/var/lib/platform-infrastructure/v1/local-private/exact-compose.env",
      sha256: sha("PLATFORM_COMPOSE_VARIANT=LOCAL_PRIVATE\n"),
    },
    renderSha256: sha("compose-render"),
    runtimeIdentity: {
      candidateId,
      commit: candidateCommit,
      deploymentId: `v1-local-private:${candidateId}`,
      sourceRenderSha256,
      tree: candidateTree,
      workloadLockSha256,
    },
    schema: "platform.v1-local-private-exact-release-authority/v1",
    serviceTargets: activeManaged.map((containerName) => ({
      configHash: sha(`compose-config:${containerName}`),
      containerName,
      project: "platform_infra_vps",
      semantic: {},
      service: containerName.replace(/^enterprise-/, ""),
    })),
    sourceArchiveSha256,
    status: "AUTHORIZED",
  });
}

function evidenceFixture(authority, phase) {
  const post = phase === "POST";
  const runId = post ? "20260824T120100Z-bbbbbbbb" : "20260824T120000Z-aaaaaaaa";
  const transactionId = post ? sha("transaction") : null;
  const reconciliationSha256 = post ? sha("reconciliation") : null;
  const common = {
    artifactSetSha256: sha(`${phase}-artifact-set`),
    authorityDocumentId: authority.documentId,
    authoritySha256: sha(Buffer.from(`${stableJson(authority)}\n`)),
    backupSetSha256: sha(`${phase}-backup-set`),
    backupToolImages: authority.backupToolImages,
    candidateCommit: authority.candidateCommit,
    candidateTree: authority.candidateTree,
    evidencePhase: phase,
    reconciliationSha256,
    runId,
    sourceArchiveSha256: authority.sourceArchiveSha256,
    transactionId,
  };
  const bootstrap = {
    authorityDocumentId: authority.documentId,
    candidateCommit: authority.candidateCommit,
    candidateTree: authority.candidateTree,
    certificateSha256Fingerprint: authority.recoveryEscrowCertificate.sha256Fingerprint,
    confidentialPassphrase: "c".repeat(64),
    phase,
    reconciliationSha256,
    resticPassword: "r".repeat(64),
    resticRepository: "rclone:platform-onedrive:platform-infrastructure/restic",
    runId,
    schema: "platform.v1-local-private-recovery-bootstrap/v1",
    sourceArchiveSha256: authority.sourceArchiveSha256,
    transactionId,
  };
  const ciphertext = Buffer.from(`${stableJson(bootstrap)}\n`);
  assert.ok(ciphertext.length >= 256);
  const recoveryEscrow = {
    certificateSha256: authority.recoveryEscrowCertificate.sha256,
    certificateSha256Fingerprint: authority.recoveryEscrowCertificate.sha256Fingerprint,
    ciphertextBase64: ciphertext.toString("base64"),
    ciphertextSha256: sha(ciphertext),
    ciphertextSizeBytes: ciphertext.length,
    offHostLocation: `platform-onedrive:platform-infrastructure/key-escrow/v1-local-private-recovery-${runId}.cms`,
    remotePayloadByteExact: true,
    status: "PASS",
  };
  return {
    offhost: {
      ...common,
      hostingerUsed: false,
      noPrune: true,
      recoveryEscrow,
      repository: "rclone:platform-onedrive:platform-infrastructure/restic",
      repositoryProvider: "OneDrive",
      retentionSkipped: true,
      schema: "platform.v1-local-private-offhost-backup-evidence/v1",
      status: "PASS",
    },
    secrets: {
      ...common,
      plaintextTemporaryStateAbsent: true,
      recoveryEscrow,
      schema: "platform.v1-local-private-secrets-backup-evidence/v1",
      secretValuesRecorded: false,
      status: "PASS",
    },
  };
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "deploy-v1-local-private-test-"));
  const bin = path.join(root, "bin");
  const key = path.join(root, "deploy-key");
  const recoveryPrivateKey = path.join(root, "operator-recovery-private.pem");
  const knownHosts = path.join(root, "known-hosts");
  const authorityFile = path.join(root, "exact-release-authority.json");
  const fakeSsh = path.join(root, "fixed-ssh");
  const fakeGit = path.join(root, "fixed-git");
  const argumentsFile = path.join(root, "ssh-arguments");
  const commandsFile = path.join(root, "ssh-commands");
  const stdinSizeFile = path.join(root, "ssh-stdin-size");
  const remoteStateFile = path.join(root, "remote-state");
  const fixtureScripts = path.join(root, "scripts");
  const fixtureSudoers = path.join(root, "sudoers");
  const fixtureSystemd = path.join(root, "systemd");
  const fixtureConfig = path.join(root, "config");
  const fixtureScript = path.join(fixtureScripts, "deploy-v1-local-private.sh");
  const fakeOpenSsl = path.join(root, "fixed-openssl");
  fs.mkdirSync(bin);
  fs.mkdirSync(fixtureScripts);
  fs.mkdirSync(fixtureSudoers);
  fs.mkdirSync(fixtureSystemd);
  fs.mkdirSync(fixtureConfig);
  const source = fs.readFileSync(productionScript, "utf8");
  const systemProbe = "SYSTEM_NAME=$(/usr/bin/uname -s)";
  assert.equal(source.split(systemProbe).length - 1, 1, "production client must contain one exact OS test boundary");
  fs.writeFileSync(fixtureScript, source.replace(systemProbe, "SYSTEM_NAME=Darwin"), { mode: 0o700 });
  for (const dependency of ["ssh-known-host-endpoint.sh", "pinned-ssh-host-key.mjs"]) {
    fs.copyFileSync(path.join(import.meta.dirname, dependency), path.join(fixtureScripts, dependency));
  }
  const composeWrapperSource = path.join(fixtureScripts, "compose-vps.sh");
  const controllerSource = path.join(fixtureScripts, "v1-local-private-control.py");
  const installerSource = path.join(fixtureScripts, "v1-brownfield-install-consumer.py");
  const reconcilerSource = path.join(fixtureScripts, "v1-local-private-reconcile.py");
  const evidenceProducerSource = path.join(fixtureScripts, "v1-local-private-evidence-producer.py");
  const sudoersSource = path.join(fixtureSudoers, "platform-v1-local-private-control");
  const unitSource = path.join(fixtureSystemd, "platform-v1-local-private-control.service");
  const workloadLockSource = path.join(fixtureConfig, "no-hosted-workloads.local-private.lock.json");
  fs.copyFileSync(path.join(import.meta.dirname, "compose-vps.sh"), composeWrapperSource);
  fs.copyFileSync(path.join(import.meta.dirname, "v1-local-private-control.py"), controllerSource);
  fs.copyFileSync(path.join(import.meta.dirname, "v1-brownfield-install-consumer.py"), installerSource);
  fs.copyFileSync(path.join(import.meta.dirname, "v1-local-private-reconcile.py"), reconcilerSource);
  fs.copyFileSync(path.join(import.meta.dirname, "v1-local-private-evidence-producer.py"), evidenceProducerSource);
  fs.copyFileSync(path.join(import.meta.dirname, "..", "sudoers", "platform-v1-local-private-control"), sudoersSource);
  fs.copyFileSync(path.join(import.meta.dirname, "..", "systemd", "platform-v1-local-private-control.service"), unitSource);
  fs.copyFileSync(path.join(import.meta.dirname, "..", "config", "local-private-recovery-escrow-cert.pem"), path.join(fixtureConfig, "local-private-recovery-escrow-cert.pem"));
  fs.copyFileSync(path.join(import.meta.dirname, "..", "config", "no-hosted-workloads.local-private.lock.json"), workloadLockSource);
  const composeWrapperSha256 = sha(fs.readFileSync(composeWrapperSource));
  const controllerSha256 = sha(fs.readFileSync(controllerSource));
  const installerSha256 = sha(fs.readFileSync(installerSource));
  const reconcilerSha256 = sha(fs.readFileSync(reconcilerSource));
  const sudoersSha256 = sha(fs.readFileSync(sudoersSource));
  const unitSha256 = sha(fs.readFileSync(unitSource));
  const workloadLockSha256 = sha(fs.readFileSync(workloadLockSource));
  const authority = authorityFixture({
    composeWrapperSha256,
    controllerSha256,
    installerSha256,
    reconcilerSha256,
    sudoersSha256,
    unitSha256,
    workloadLockSha256,
  });
  writeCanonical(authorityFile, authority);
  const authoritySha256 = sha(fs.readFileSync(authorityFile));
  const preEvidence = evidenceFixture(authority, "PRE");
  const postEvidence = evidenceFixture(authority, "POST");
  const responsePaths = Object.fromEntries([
    "preOffhost", "preSecrets", "postOffhost", "postSecrets", "begin", "apply", "evidence",
    "active", "unboundActive", "abortRecord", "abortActive", "abortFinalized", "abortClean",
  ].map((name) => [name, path.join(root, `${name}.json`)]));
  writeCanonical(responsePaths.preOffhost, preEvidence.offhost);
  writeCanonical(responsePaths.preSecrets, preEvidence.secrets);
  writeCanonical(responsePaths.postOffhost, postEvidence.offhost);
  writeCanonical(responsePaths.postSecrets, postEvidence.secrets);
  writeCanonical(responsePaths.begin, {
    candidateCommit, candidateTree, releaseAuthorityDocumentId: authority.documentId,
    releaseAuthoritySha256: authoritySha256, releaseRoot: authority.releaseRoot,
    schema: "platform.v1-local-private-reconciliation/v1", sourceArchiveSha256, status: "RECONCILING",
  });
  const transactionId = sha("transaction");
  writeCanonical(responsePaths.apply, { authorityDocumentId: authority.documentId, status: "APPLIED", transactionId });
  writeCanonical(responsePaths.evidence, {
    evidencePath: "/var/lib/platform-infrastructure/v1/predeploy/current/runtime-inventory-evidence.json",
    evidenceSha256: sha("runtime-evidence"), status: "PASS",
  });
  const activeReceipt = {
    candidateCommit, candidateTree,
    externalAuthorizedReconciliation: {
      releaseAuthorityDocumentId: authority.documentId,
      releaseAuthoritySha256: authoritySha256,
      status: "SEALED",
    },
    schema: "platform.v1-local-private-control-receipt/v1", status: "ACTIVE",
  };
  writeCanonical(responsePaths.active, activeReceipt);
  writeCanonical(responsePaths.unboundActive, {
    ...activeReceipt,
    externalAuthorizedReconciliation: {
      ...activeReceipt.externalAuthorizedReconciliation,
      releaseAuthoritySha256: sha("foreign-authority"),
    },
  });
  const abortRecordSha256 = sha("abort-record");
  writeCanonical(responsePaths.abortRecord, {
    abortRecordPath: `/var/lib/platform-infrastructure/v1/local-private/aborted-reconciliations/${transactionId}-${abortRecordSha256}.json`,
    abortRecordSha256, authorityDocumentId: authority.documentId,
    status: "ABORTED_NO_DATA_MUTATION", transactionId,
  });
  writeCanonical(responsePaths.abortActive, {
    abortedAuthorizedReconciliation: {
      authorityDocumentId: authority.documentId, authoritySha256,
      recordPath: `/var/lib/platform-infrastructure/v1/local-private/aborted-reconciliations/${transactionId}-${abortRecordSha256}.json`,
      recordSha256: abortRecordSha256, status: "ABORTED_NO_DATA_MUTATION", transactionId,
    },
    candidateCommit, candidateTree,
    schema: "platform.v1-local-private-control-receipt/v1", status: "ACTIVE",
  });
  writeCanonical(responsePaths.abortFinalized, {
    authorityDocumentId: authority.documentId,
    journalArchivePath: `/var/lib/platform-infrastructure/v1/local-private/reconcile-journals/${transactionId}-${sha("journal")}.json`,
    recordArchivePath: `/var/lib/platform-infrastructure/v1/local-private/aborted-reconciliations/${transactionId}-${abortRecordSha256}.json`,
    status: "ABORT_FINALIZED", transactionId,
  });
  writeCanonical(responsePaths.abortClean, {
    authorityDocumentId: authority.documentId, status: "ABORTED", transactionId: null,
  });
  fs.writeFileSync(path.join(fixtureScripts, "v1-local-private-control-receipt.mjs"), `#!/usr/bin/env node
import fs from "node:fs";
const argv = process.argv.slice(2);
const value = (flag) => argv[argv.indexOf(flag) + 1];
if (argv.length !== 5 || argv[0] !== "verify" || argv[1] !== "--file" || argv[3] !== "--authorityFile") {
  throw new Error("invalid verifier invocation");
}
const authority = JSON.parse(fs.readFileSync(value("--authorityFile"), "utf8"));
const receipt = JSON.parse(fs.readFileSync(value("--file"), "utf8"));
if (receipt.schema !== "platform.v1-local-private-control-receipt/v1"
  || receipt.status !== "ACTIVE"
  || receipt.candidateCommit !== authority.candidateCommit) {
  throw new Error("invalid LOCAL_PRIVATE receipt");
}
`, { mode: 0o700 });
  fs.writeFileSync(key, "test-only-private-key\n", { mode: 0o600 });
  fs.writeFileSync(recoveryPrivateKey, "TEST-ONLY-PRIVATE-KEY\n".repeat(20), { mode: 0o600 });
  fs.writeFileSync(knownHosts, `[example.internal]:2222 ssh-ed25519 ${keyBlob}\n`, { mode: 0o600 });
  fs.symlinkSync(bundledNode, path.join(bin, "node"));
  fs.writeFileSync(remoteStateFile, "BASELINE\n", { mode: 0o600 });
  fs.writeFileSync(fakeOpenSsl, `#!/bin/sh
if [ "\${1:-}" = pkey ]; then exit 0; fi
found=0
for argument do [ "$argument" = -decrypt ] && found=1; done
[ "$found" -eq 1 ] || exit 64
/bin/cat
`, { mode: 0o700 });

  fs.writeFileSync(fakeGit, `#!/bin/sh
case "$3" in
  rev-parse)
    case "$5" in
      HEAD\\^{commit\\}) printf '%s\\n' '${candidateCommit}' ;;
      HEAD\\^{tree\\}) printf '%s\\n' '${candidateTree}' ;;
      refs/remotes/github/main) printf '%s\\n' '${candidateCommit}' ;;
      *) exit 64 ;;
    esac
    ;;
  status) : ;;
  *) exit 64 ;;
esac
`, { mode: 0o700 });

  fs.writeFileSync(fakeSsh, `#!/bin/sh
: > "$PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH_ARGUMENTS"
command=
for argument do
  printf '%s\\n' "$argument" >> "$PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH_ARGUMENTS"
  command=$argument
done
printf '%s\\n' "$command" >> "$PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH_COMMANDS"
/usr/bin/wc -c < /dev/stdin | /usr/bin/tr -d '[:space:]' > "$PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH_STDIN_SIZE"
if [ "\${PLATFORM_V1_LOCAL_PRIVATE_TEST_RECEIPT_MODE:-valid}" = oversized ]; then
  /usr/bin/yes x | /usr/bin/head -c 600000
  exit 0
fi
state=$(/bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_REMOTE_STATE")
lost_once() {
  name=$1
  [ "\${PLATFORM_V1_LOCAL_PRIVATE_TEST_LOST_ONCE:-}" = "$name" ] || return 1
  marker="$PLATFORM_V1_LOCAL_PRIVATE_TEST_REMOTE_STATE.lost-$name"
  [ ! -e "$marker" ] || return 1
  : > "$marker"
  return 0
}
case "$command" in
  *"/usr/bin/cat /var/lib/platform-infrastructure/v1/local-private/exact-release-authority.json")
    /bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_AUTHORITY" ;;
  *"/usr/bin/cat /var/lib/platform-infrastructure/v1/predeploy/current/offhost-backup-evidence.json")
    case "$state" in EVIDENCED|ACTIVE) /bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_POST_OFFHOST" ;; *) /bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_PRE_OFFHOST" ;; esac ;;
  *"/usr/bin/cat /var/lib/platform-infrastructure/v1/predeploy/current/secrets-backup-evidence.json")
    case "$state" in EVIDENCED|ACTIVE) /bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_POST_SECRETS" ;; *) /bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_PRE_SECRETS" ;; esac ;;
  *"platform-v1-local-private-control begin-maintenance")
    printf 'RECONCILING\\n' > "$PLATFORM_V1_LOCAL_PRIVATE_TEST_REMOTE_STATE"
    lost_once begin && exit 255
    /bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_BEGIN" ;;
  *"platform-v1-local-private-reconcile apply")
    [ "\${PLATFORM_V1_LOCAL_PRIVATE_TEST_FAIL_STAGE:-}" != apply ] || exit 70
    printf 'APPLIED\\n' > "$PLATFORM_V1_LOCAL_PRIVATE_TEST_REMOTE_STATE"
    lost_once apply && exit 255
    /bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_APPLY" ;;
  *"platform-v1-local-private-reconcile evidence")
    if [ "\${PLATFORM_V1_LOCAL_PRIVATE_TEST_FAIL_STAGE:-}" = evidence ]; then
      printf 'COMMITTING\\n' > "$PLATFORM_V1_LOCAL_PRIVATE_TEST_REMOTE_STATE"
      exit 70
    fi
    printf 'EVIDENCED\\n' > "$PLATFORM_V1_LOCAL_PRIVATE_TEST_REMOTE_STATE"
    lost_once evidence && exit 255
    /bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_EVIDENCE" ;;
  *"platform-v1-local-private-control seal")
    if [ "\${PLATFORM_V1_LOCAL_PRIVATE_TEST_FAIL_STAGE:-}" = seal-first ] && [ ! -e "$PLATFORM_V1_LOCAL_PRIVATE_TEST_REMOTE_STATE.seal-first" ]; then
      : > "$PLATFORM_V1_LOCAL_PRIVATE_TEST_REMOTE_STATE.seal-first"
      exit 70
    fi
    printf 'ACTIVE\\n' > "$PLATFORM_V1_LOCAL_PRIVATE_TEST_REMOTE_STATE"
    lost_once seal && exit 255
    /bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_ACTIVE" ;;
  *"platform-v1-local-private-control abort-maintenance")
    printf 'ABORT_ACTIVE\\n' > "$PLATFORM_V1_LOCAL_PRIVATE_TEST_REMOTE_STATE"
    /bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_ABORT_ACTIVE" ;;
  *"platform-v1-local-private-reconcile abort")
    if [ "$state" = ABORT_ACTIVE ]; then
      printf 'FINALIZED\\n' > "$PLATFORM_V1_LOCAL_PRIVATE_TEST_REMOTE_STATE"
      lost_once abort-finalize && exit 255
      /bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_ABORT_FINALIZED"
    elif [ "$state" = FINALIZED ]; then
      /bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_ABORT_CLEAN"
    else
      printf 'ABORTED\\n' > "$PLATFORM_V1_LOCAL_PRIVATE_TEST_REMOTE_STATE"
      /bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_ABORT_RECORD"
    fi ;;
  *"platform-v1-local-private-control verify")
    case "$state" in
      ACTIVE) [ "\${PLATFORM_V1_LOCAL_PRIVATE_TEST_RECEIPT_MODE:-valid}" = unbound ] && /bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_UNBOUND_ACTIVE" || /bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_ACTIVE" ;;
      ABORT_ACTIVE|FINALIZED) /bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_ABORT_ACTIVE" ;;
      *) /bin/cat "$PLATFORM_V1_LOCAL_PRIVATE_TEST_BEGIN" ;;
    esac ;;
  *) exit 64 ;;
esac
`, { mode: 0o700 });

  const environment = {
    ...process.env,
    PATH: `${bin}:/usr/bin:/bin`,
    HOME: root,
    DEPLOY_REMOTE: "deploy_user@example.internal",
    DEPLOY_SSH_PORT: "2222",
    DEPLOY_SSH_KEY_PATH: key,
    DEPLOY_SSH_KNOWN_HOSTS_PATH: knownHosts,
    DEPLOY_RECOVERY_PRIVATE_KEY_PATH: recoveryPrivateKey,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_GIT: fakeGit,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_NODE: bundledNode,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_OPENSSL: fakeOpenSsl,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH: fakeSsh,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH_ARGUMENTS: argumentsFile,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH_COMMANDS: commandsFile,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH_STDIN_SIZE: stdinSizeFile,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_REMOTE_STATE: remoteStateFile,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_AUTHORITY: authorityFile,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_PRE_OFFHOST: responsePaths.preOffhost,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_PRE_SECRETS: responsePaths.preSecrets,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_POST_OFFHOST: responsePaths.postOffhost,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_POST_SECRETS: responsePaths.postSecrets,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_BEGIN: responsePaths.begin,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_APPLY: responsePaths.apply,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_EVIDENCE: responsePaths.evidence,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_ACTIVE: responsePaths.active,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_UNBOUND_ACTIVE: responsePaths.unboundActive,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_ABORT_RECORD: responsePaths.abortRecord,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_ABORT_ACTIVE: responsePaths.abortActive,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_ABORT_FINALIZED: responsePaths.abortFinalized,
    PLATFORM_V1_LOCAL_PRIVATE_TEST_ABORT_CLEAN: responsePaths.abortClean,
  };
  return {
    root, authorityFile, knownHosts, composeWrapperSource, controllerSource, installerSource,
    reconcilerSource, sudoersSource, unitSource, workloadLockSource, fixtureScript, recoveryPrivateKey,
    argumentsFile, commandsFile, stdinSizeFile, environment,
    receipt: `${stableJson(activeReceipt)}\n`, responsePaths,
  };
}

function execute(testFixture, args = ["--authorityFile", testFixture.authorityFile], environment = {}) {
  return spawnSync("/bin/sh", [testFixture.fixtureScript, ...args], {
    encoding: "utf8",
    env: { ...testFixture.environment, ...environment },
  });
}

function remoteCommands(testFixture) {
  return fs.existsSync(testFixture.commandsFile)
    ? fs.readFileSync(testFixture.commandsFile, "utf8").trim().split("\n").filter(Boolean)
    : [];
}

function mutateCanonicalFile(filename, mutate) {
  fs.chmodSync(filename, 0o600);
  const value = JSON.parse(fs.readFileSync(filename, "utf8"));
  mutate(value);
  writeCanonical(filename, value);
}

test("pins host trust and runs the fixed begin/apply/evidence/seal/verify sequence", () => {
  const current = fixture();
  try {
    const result = execute(current);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, current.receipt);
    assert.equal(fs.readFileSync(current.stdinSizeFile, "utf8"), "0");
    const args = fs.readFileSync(current.argumentsFile, "utf8").trim().split("\n");
    assert.deepEqual(args.slice(-3), [
      "--",
      "deploy_user@example.internal",
      "/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-control verify",
    ]);
    assert.ok(args.includes("BatchMode=yes"));
    assert.ok(args.includes("StrictHostKeyChecking=yes"));
    assert.ok(args.includes("ClearAllForwardings=yes"));
    assert.equal(args.some((argument) => argument.includes(current.authorityFile)), false);
    const commands = fs.readFileSync(current.commandsFile, "utf8").trim().split("\n");
    assert.deepEqual(commands, [
      "/usr/bin/sudo -n -- /usr/bin/cat /var/lib/platform-infrastructure/v1/local-private/exact-release-authority.json",
      "/usr/bin/sudo -n -- /usr/bin/cat /var/lib/platform-infrastructure/v1/local-private/validation-lane.json",
      "/usr/bin/sudo -n -- /usr/bin/cat /var/lib/platform-infrastructure/v1/predeploy/current/offhost-backup-evidence.json",
      "/usr/bin/sudo -n -- /usr/bin/cat /var/lib/platform-infrastructure/v1/predeploy/current/secrets-backup-evidence.json",
      "/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-control begin-maintenance",
      "/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-reconcile apply",
      "/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-reconcile evidence",
      "/usr/bin/sudo -n -- /usr/bin/cat /var/lib/platform-infrastructure/v1/predeploy/current/offhost-backup-evidence.json",
      "/usr/bin/sudo -n -- /usr/bin/cat /var/lib/platform-infrastructure/v1/predeploy/current/secrets-backup-evidence.json",
      "/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-control seal",
      "/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-control verify",
    ]);
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("retries lost stdout idempotently at begin, apply and evidence", () => {
  for (const stage of ["begin", "apply", "evidence"]) {
    const current = fixture();
    try {
      const result = execute(current, undefined, { PLATFORM_V1_LOCAL_PRIVATE_TEST_LOST_ONCE: stage });
      assert.equal(result.status, 0, `${stage}: ${result.stderr}`);
      assert.equal(result.stdout, current.receipt);
      const commands = remoteCommands(current);
      const suffix = stage === "begin"
        ? "platform-v1-local-private-control begin-maintenance"
        : `platform-v1-local-private-reconcile ${stage}`;
      assert.equal(commands.filter((command) => command.endsWith(suffix)).length, 2, stage);
      assert.equal(commands.some((command) => command.endsWith("platform-v1-local-private-reconcile abort")), false);
    } finally {
      fs.rmSync(current.root, { recursive: true, force: true });
    }
  }
});

test("resolves lost seal stdout through verify without replaying a completed seal", () => {
  const current = fixture();
  try {
    const result = execute(current, undefined, { PLATFORM_V1_LOCAL_PRIVATE_TEST_LOST_ONCE: "seal" });
    assert.equal(result.status, 0, result.stderr);
    const commands = remoteCommands(current);
    assert.equal(commands.filter((command) => command.endsWith("platform-v1-local-private-control seal")).length, 1);
    assert.equal(commands.filter((command) => command.endsWith("platform-v1-local-private-control verify")).length, 2);
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("resumes seal only after verify proves RECONCILING", () => {
  const current = fixture();
  try {
    const result = execute(current, undefined, {
      PLATFORM_V1_LOCAL_PRIVATE_TEST_FAIL_STAGE: "seal-first",
      PLATFORM_V1_LOCAL_PRIVATE_TEST_LOST_ONCE: "seal",
    });
    assert.equal(result.status, 0, result.stderr);
    const commands = remoteCommands(current);
    assert.equal(commands.filter((command) => command.endsWith("platform-v1-local-private-control seal")).length, 3);
    assert.equal(commands.filter((command) => command.endsWith("platform-v1-local-private-control verify")).length, 2);
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("apply failure performs record-bound abort, controller abort, verify and second-abort finalization", () => {
  const current = fixture();
  try {
    const result = execute(current, undefined, { PLATFORM_V1_LOCAL_PRIVATE_TEST_FAIL_STAGE: "apply" });
    assert.equal(result.status, 70, result.stderr);
    assert.match(result.stderr, /rolled back and finalized/);
    const commands = remoteCommands(current);
    assert.equal(commands.filter((command) => command.endsWith("platform-v1-local-private-reconcile apply")).length, 3);
    assert.deepEqual(commands.slice(-5), [
      "/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-reconcile abort",
      "/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-control abort-maintenance",
      "/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-control verify",
      "/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-reconcile abort",
      "/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-control verify",
    ]);
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("lost stdout after second-abort cleanup is accepted only through the no-current-transaction proof", () => {
  const current = fixture();
  try {
    const result = execute(current, undefined, {
      PLATFORM_V1_LOCAL_PRIVATE_TEST_FAIL_STAGE: "apply",
      PLATFORM_V1_LOCAL_PRIVATE_TEST_LOST_ONCE: "abort-finalize",
    });
    assert.equal(result.status, 70, result.stderr);
    assert.match(result.stderr, /rolled back and finalized/);
    const commands = remoteCommands(current);
    assert.equal(commands.filter((command) => command.endsWith("platform-v1-local-private-reconcile abort")).length, 3);
    assert.equal(commands.at(-1), "/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-control verify");
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("never aborts after an evidence invocation may have crossed COMMITTING", () => {
  const current = fixture();
  try {
    const result = execute(current, undefined, { PLATFORM_V1_LOCAL_PRIVATE_TEST_FAIL_STAGE: "evidence" });
    assert.equal(result.status, 65, result.stderr);
    assert.match(result.stderr, /abort is closed after possible COMMITTING/);
    const commands = remoteCommands(current);
    assert.equal(commands.filter((command) => command.endsWith("platform-v1-local-private-reconcile evidence")).length, 3);
    assert.equal(commands.some((command) => command.endsWith("platform-v1-local-private-reconcile abort")), false);
    assert.equal(commands.some((command) => command.endsWith("platform-v1-local-private-control seal")), false);
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("requires decryptable authority-bound CMS before begin and again before seal", () => {
  for (const phase of ["pre", "post"]) {
    const current = fixture();
    try {
      const target = current.responsePaths[`${phase}Secrets`];
      mutateCanonicalFile(target, (value) => { value.recoveryEscrow.ciphertextSha256 = sha("substituted-ciphertext"); });
      const result = execute(current);
      assert.equal(result.status, 65, `${phase}: ${result.stderr}`);
      assert.match(result.stderr, new RegExp(`${phase.toUpperCase()} CMS recovery escrow`));
      const commands = remoteCommands(current);
      if (phase === "pre") {
        assert.equal(commands.some((command) => command.endsWith("begin-maintenance")), false);
      } else {
        assert.equal(commands.some((command) => command.endsWith("platform-v1-local-private-reconcile evidence")), true);
        assert.equal(commands.some((command) => command.endsWith("platform-v1-local-private-control seal")), false);
        assert.equal(commands.some((command) => command.endsWith("platform-v1-local-private-reconcile abort")), false);
      }
    } finally {
      fs.rmSync(current.root, { recursive: true, force: true });
    }
  }
});

test("rejects any caller argument shape other than one local authority file", () => {
  const current = fixture();
  try {
    for (const args of [[], ["attacker-plan"], ["--authorityFile", current.authorityFile, "attacker-plan"]]) {
      const result = execute(current, args);
      assert.equal(result.status, 64);
      assert.match(result.stderr, /Usage: deploy-v1-local-private/);
      assert.equal(fs.existsSync(current.argumentsFile), false);
    }
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("rejects an invalid root receipt", () => {
  const current = fixture();
  try {
    fs.chmodSync(current.responsePaths.active, 0o600);
    writeCanonical(current.responsePaths.active, { schema: "attacker", status: "ACTIVE" });
    const result = execute(current);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /neither bound ACTIVE nor bound RECONCILING|not sealed to authority/);
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("rejects a receipt not bound to the exact authority bytes", () => {
  const current = fixture();
  try {
    const result = execute(current, undefined, { PLATFORM_V1_LOCAL_PRIVATE_TEST_RECEIPT_MODE: "unbound" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /not sealed to authority|not ACTIVE/);
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("bounds the authenticated remote response at 128 KiB", () => {
  const current = fixture();
  try {
    const result = execute(current, undefined, { PLATFORM_V1_LOCAL_PRIVATE_TEST_RECEIPT_MODE: "oversized" });
    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, "");
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("rejects missing host trust before SSH", () => {
  const current = fixture();
  try {
    fs.rmSync(current.knownHosts);
    const result = execute(current);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /known-hosts input/);
    assert.equal(fs.existsSync(current.argumentsFile), false);
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("uses an explicit Node runtime and rejects an unsafe recovery private key before SSH", () => {
  {
    const current = fixture();
    try {
      const result = execute(current, undefined, { PLATFORM_V1_LOCAL_PRIVATE_TEST_NODE: path.join(current.root, "missing-node") });
      assert.equal(result.status, 78);
      assert.match(result.stderr, /fixed Node.js runtime is unavailable/);
      assert.equal(fs.existsSync(current.commandsFile), false);
    } finally {
      fs.rmSync(current.root, { recursive: true, force: true });
    }
  }
  {
    const current = fixture();
    try {
      fs.chmodSync(current.recoveryPrivateKey, 0o644);
      const result = execute(current);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /recovery private key identity or permissions are invalid/);
      assert.equal(fs.existsSync(current.commandsFile), false);
    } finally {
      fs.rmSync(current.root, { recursive: true, force: true });
    }
  }
});

test("rejects a missing controller source before SSH", () => {
  const current = fixture();
  try {
    fs.rmSync(current.controllerSource);
    const result = execute(current);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /controller source/);
    assert.equal(fs.existsSync(current.argumentsFile), false);
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("rejects any missing exact-main control artifact source before SSH", () => {
  for (const field of ["composeWrapperSource", "installerSource", "reconcilerSource", "sudoersSource", "unitSource", "workloadLockSource"]) {
    const current = fixture();
    try {
      fs.rmSync(current[field]);
      const result = execute(current);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /source/);
      assert.equal(fs.existsSync(current.argumentsFile), false);
    } finally {
      fs.rmSync(current.root, { recursive: true, force: true });
    }
  }
});

test("rejects a missing sudoers source before SSH", () => {
  const current = fixture();
  try {
    fs.rmSync(current.sudoersSource);
    const result = execute(current);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /sudoers source/);
    assert.equal(fs.existsSync(current.argumentsFile), false);
  } finally {
    fs.rmSync(current.root, { recursive: true, force: true });
  }
});

test("rejects non-canonical, mutable, linked, and checkout-mismatched authority before SSH", () => {
  for (const mutate of [
    (current) => { fs.chmodSync(current.authorityFile, 0o600); },
    (current) => {
      fs.chmodSync(current.authorityFile, 0o600);
      fs.appendFileSync(current.authorityFile, " \n");
      fs.chmodSync(current.authorityFile, 0o400);
    },
    (current) => {
      const linked = `${current.authorityFile}.linked`;
      fs.linkSync(current.authorityFile, linked);
      current.authorityFile = linked;
    },
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      authority.candidateCommit = sha("foreign-commit").slice(0, 40);
      authority.checkoutProof.githubMainCommit = authority.candidateCommit;
      authority.checkoutProof.headCommit = authority.candidateCommit;
      authority.releaseRoot = `/srv/platform-infrastructure/releases/${authority.candidateCommit}-${authority.sourceArchiveSha256}`;
      authority.artifacts.composeWrapper.path = `${authority.releaseRoot}/scripts/compose-vps.sh`;
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      authority.artifacts.controller.sha256 = sha("foreign-controller");
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      authority.artifacts.composeWrapper.sha256 = sha("foreign-compose-wrapper");
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      authority.artifacts.installer.sha256 = sha("foreign-installer");
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      authority.artifacts.reconciler.sha256 = sha("foreign-reconciler");
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      authority.artifacts.sudoers.sha256 = sha("foreign-sudoers");
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      delete authority.legacyUnmanagedContainers;
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      authority.legacyUnmanagedContainers[0].unexpected = true;
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      authority.legacyUnmanagedContainers[0].status = "MANAGED";
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      authority.legacyUnmanagedContainers[0].reason = "UNCLASSIFIED";
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      authority.legacyUnmanagedContainers.reverse();
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      authority.runtimeIdentity.unexpected = true;
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      authority.runtimeIdentity.commit = sha("foreign-runtime-commit").slice(0, 40);
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      authority.runtimeIdentity.candidateId = sha("foreign-runtime-candidate");
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      authority.runtimeIdentity.deploymentId = "v1-local-private:foreign";
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      authority.runtimeIdentity.workloadLockSha256 = sha("foreign-workload-lock");
      authority.runtimeIdentity.candidateId = sha(stableJson({
        candidateCommit: authority.candidateCommit,
        candidateTree: authority.candidateTree,
        sourceRenderSha256: authority.runtimeIdentity.sourceRenderSha256,
        workloadLockSha256: authority.runtimeIdentity.workloadLockSha256,
      }));
      authority.runtimeIdentity.deploymentId = `v1-local-private:${authority.runtimeIdentity.candidateId}`;
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      delete authority.serviceTargets[0].configHash;
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      authority.serviceTargets[0].unexpected = true;
    }),
    (current) => rewriteAuthority(current.authorityFile, (authority) => {
      authority.serviceTargets[0].configHash = "not-a-sha256";
    }),
  ]) {
    const current = fixture();
    try {
      mutate(current);
      const result = execute(current);
      assert.notEqual(result.status, 0);
      assert.equal(fs.existsSync(current.argumentsFile), false);
    } finally {
      fs.rmSync(current.root, { recursive: true, force: true });
    }
  }
});

test("source has no frozen candidate pin and transports no plan or authority input", () => {
  const source = fs.readFileSync(productionScript, "utf8");
  for (const value of [
    "Usage: deploy-v1-local-private.sh --authorityFile FILE",
    "V1 exact release authority changed during stable capture.",
    "The root ACTIVE receipt is not sealed to the exact authority bytes.",
    "REMOTE_COMMAND='/usr/bin/sudo -n -- /usr/local/libexec/platform-v1-local-private-control activate'",
    'exec "$SSH" "$@" -- "$REMOTE" "$REMOTE_COMMAND" < /dev/null',
    'capture_remote 3 "begin-maintenance" "$REMOTE_CONTROLLER begin-maintenance"',
    'capture_remote 3 "reconcile apply" "$REMOTE_RECONCILER apply"',
    'capture_remote 3 "reconcile evidence" "$REMOTE_RECONCILER evidence"',
    'capture_remote 1 "controller seal" "$REMOTE_CONTROLLER seal"',
    'capture_remote 3 "final controller verify" "$REMOTE_CONTROLLER verify"',
    '"$OPENSSL" cms -decrypt -binary -inform DER',
    '"$NODE" "$SCRIPT_ROOT/v1-local-private-control-receipt.mjs" verify',
    '--authorityFile "$authority_snapshot"',
    'COMPOSE_WRAPPER_SOURCE="$REPOSITORY_ROOT/scripts/compose-vps.sh"',
    'CONTROLLER_SOURCE="$REPOSITORY_ROOT/scripts/v1-local-private-control.py"',
    'INSTALLER_SOURCE="$REPOSITORY_ROOT/scripts/v1-brownfield-install-consumer.py"',
    'RECONCILER_SOURCE="$REPOSITORY_ROOT/scripts/v1-local-private-reconcile.py"',
    'EVIDENCE_PRODUCER_SOURCE="$REPOSITORY_ROOT/scripts/v1-local-private-evidence-producer.py"',
    'SUDOERS_SOURCE="$REPOSITORY_ROOT/sudoers/platform-v1-local-private-control"',
    'UNIT_SOURCE="$REPOSITORY_ROOT/systemd/platform-v1-local-private-control.service"',
    'WORKLOAD_LOCK_SOURCE="$REPOSITORY_ROOT/config/no-hosted-workloads.local-private.lock.json"',
    "SSH=/usr/bin/ssh",
    'SSH=${PLATFORM_V1_LOCAL_PRIVATE_TEST_SSH:-$SSH}',
    'NODE="${HOME}/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node"',
  ]) assert.ok(source.includes(value), `LOCAL_PRIVATE client is missing ${value}`);
  assert.doesNotMatch(source, /^CANDIDATE_(?:COMMIT|TREE)=|^SOURCE_ARCHIVE_SHA256=/m);
  assert.doesNotMatch(source, /command -v node|^node(?:\s|$)/m);
  assert.doesNotMatch(source, /git (?:fetch|pull|checkout)|docker (?:compose|run|exec)|(?:scp|sftp) |sh -s|platform-activation-broker|activation-request|provider-activation/);
});
