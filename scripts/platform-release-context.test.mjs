#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { createPlatformReleaseContextTestReader } from "./platform-release-context.mjs";

const script = path.join(import.meta.dirname, "platform-release-context.mjs");
const sha = (character) => character.repeat(64);

function fixture() {
  const root = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "platform-release-context-v3-")),
  );
  const releaseId = `${"1".repeat(40)}-${sha("3")}`;
  const stateId = `${releaseId}-${sha("4")}`;
  const releaseRoot = path.join(root, "releases", releaseId);
  const stateRoot = path.join(root, "release-states", stateId);
  fs.mkdirSync(releaseRoot, { recursive: true });
  fs.mkdirSync(stateRoot, { recursive: true });
  const environmentFile = path.join(stateRoot, "environment.env");
  fs.writeFileSync(environmentFile, "PLATFORM_ENV=production\n");
  const contextPath = path.join(stateRoot, "trusted-release-context.json");
  const document = {
    schema: "platform-trusted-release-context/v3",
    repository: "owner/platform-infrastructure",
    commitSha: "1".repeat(40),
    treeSha: "2".repeat(40),
    sourceArchiveSha256: sha("3"),
    releaseId,
    releaseRoot,
    stateId,
    stateRoot,
    environmentFile,
    environmentSha256: sha("4"),
    projectName: "platform_infra_vps",
    decisionId: "decision:12345678",
    provider: {
      metadataSha256: sha("4"),
      runId: "12345678",
      attempt: 1,
      challenge: sha("5"),
    },
    receipts: {
      artifactSha256: sha("6"),
      deploymentSha256: sha("7"),
      dastProviderSha256: sha("8"),
      dastAuthorizationSha256: sha("9"),
    },
    dastChainSha256: sha("a"),
    runtimeIntentSha256: sha("b"),
    subjects: [
      {
        serviceName: "app",
        imageReference: `ghcr.io/owner/platform-infrastructure-app@sha256:${sha("c")}`,
        imageId: `sha256:${sha("d")}`,
      },
      {
        serviceName: "backup-scheduler",
        imageReference: `ghcr.io/owner/platform-infrastructure-backup-scheduler@sha256:${sha("e")}`,
        imageId: `sha256:${sha("f")}`,
      },
    ],
    hostedLockSha256: null,
    noHosted: true,
    sourceRenderSha256: sha("0"),
    combinedRenderSha256: sha("1"),
    persistentVolumes: [{
      name: "enterprise_local_registry_data",
      createdAt: "2026-07-21T00:00:00.000Z",
      driver: "local",
      scope: "local",
      options: {},
      labels: {
        "platform.infrastructure.managed": "true",
        "platform.infrastructure.purpose": "local-registry",
      },
      mountpoint: "/var/lib/docker/volumes/enterprise_local_registry_data/_data",
      owner: { uid: 0, gid: 0, mode: "0755" },
    }],
  };
  return { root, contextPath, document };
}

function execute(root, contextPath, document, { expectedOwner = process.getuid() } = {}) {
  fs.writeFileSync(contextPath, `${JSON.stringify(document)}\n`, { mode: 0o640 });
  fs.chmodSync(contextPath, 0o640);
  const read = createPlatformReleaseContextTestReader({
    infrastructureRoot: root,
    expectedOwner,
  });
  try {
    return { status: 0, stdout: `${JSON.stringify(read(contextPath))}\n`, stderr: "" };
  } catch (error) {
    return { status: 1, stdout: "", stderr: `${String(error?.message ?? error)}\n` };
  }
}

test("accepts only one exact trusted release context v3", () => {
  const { root, contextPath, document } = fixture();
  try {
    const result = execute(root, contextPath, document);
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.deepEqual(
      Object.keys(output).sort(),
      [...Object.keys(document), "activationCoordinatorRoot"].sort(),
    );
    assert.equal(output.activationCoordinatorRoot, path.join(root, "platform-activation"));
    assert.deepEqual(output.receipts, document.receipts);
    assert.deepEqual(output.persistentVolumes, document.persistentVolumes);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("accepts a hosted v3 context with one exact hosted lock digest", () => {
  const { root, contextPath, document } = fixture();
  try {
    document.noHosted = false;
    document.hostedLockSha256 = sha("a");
    const result = execute(root, contextPath, document);
    assert.equal(result.status, 0, result.stderr);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

const invalidMutants = [
  ["v2 schema", (value) => { value.schema = "platform-trusted-release-context/v2"; }],
  ["open schema", (value) => { value.untrusted = true; }],
  ["legacy DAST receipt", (value) => {
    value.receipts = {
      artifactSha256: sha("6"),
      deploymentSha256: sha("7"),
      dastSha256: sha("8"),
    };
  }],
  ["missing DAST chain", (value) => { delete value.dastChainSha256; }],
  ["no-hosted context with a lock", (value) => { value.hostedLockSha256 = sha("a"); }],
  ["hosted context without a lock", (value) => { value.noHosted = false; }],
  ["unpinned subject", (value) => { value.subjects[0].imageReference = "ghcr.io/owner/app:latest"; }],
  ["unsorted subjects", (value) => { value.subjects.reverse(); }],
  ["missing dedicated scheduler subject", (value) => { value.subjects = [value.subjects[0]]; }],
  ["state path mismatch", (value) => { value.stateId = "state:other123"; }],
  ["release root identity mismatch", (value) => {
    value.releaseRoot = path.join(path.dirname(value.releaseRoot), `other-${value.releaseId}`);
  }],
  ["environment outside the trusted state root", (value) => {
    value.environmentFile = path.join(path.dirname(value.stateRoot), "environment.env");
  }],
  ["identical source and combined renders", (value) => {
    value.combinedRenderSha256 = value.sourceRenderSha256;
  }],
  ["missing persistent volume", (value) => { value.persistentVolumes = []; }],
  ["wrong persistent volume identity", (value) => {
    value.persistentVolumes[0].name = "other";
  }],
  ["open persistent volume options", (value) => {
    value.persistentVolumes[0].options.type = "none";
  }],
  ["wrong persistent volume labels", (value) => {
    value.persistentVolumes[0].labels["platform.infrastructure.managed"] = "false";
  }],
  ["wrong persistent volume mountpoint", (value) => {
    value.persistentVolumes[0].mountpoint = "/var/lib/docker/volumes/other/_data";
  }],
  ["writable persistent volume owner", (value) => {
    value.persistentVolumes[0].owner.mode = "0775";
  }],
  ["non-root persistent volume owner", (value) => {
    value.persistentVolumes[0].owner.uid = 1000;
  }],
];

for (const [name, mutate] of invalidMutants) {
  test(`rejects ${name}`, () => {
    const { root, contextPath, document } = fixture();
    try {
      mutate(document);
      const result = execute(root, contextPath, document);
      assert.notEqual(result.status, 0, result.stdout);
      assert.match(result.stderr, /Trusted release context/);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
}

test("Linux-compatible seam preserves exact ownership enforcement", () => {
  const { root, contextPath, document } = fixture();
  try {
    const wrongOwner = process.getuid() === 0 ? 1 : process.getuid() + 1;
    const result = execute(root, contextPath, document, { expectedOwner: wrongOwner });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /root-owned/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("rejects a state root nested below a writable intermediate directory", () => {
  const { root, document } = fixture();
  const writable = path.join(root, "release-states", "attacker-writable");
  const nestedStateRoot = path.join(writable, document.stateId);
  const contextPath = path.join(nestedStateRoot, "trusted-release-context.json");
  try {
    fs.mkdirSync(nestedStateRoot, { recursive: true });
    fs.chmodSync(writable, 0o777);
    document.stateRoot = nestedStateRoot;
    document.environmentFile = path.join(nestedStateRoot, "environment.env");
    fs.writeFileSync(document.environmentFile, "PLATFORM_ENV=production\n");
    const result = execute(root, contextPath, document);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /path identities|release-state store/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("rejects a release ID and roots coherently rebound away from the admitted commit", () => {
  const { root, document } = fixture();
  const forgedReleaseId = `${"9".repeat(40)}-${document.sourceArchiveSha256}`;
  const forgedStateId = `${forgedReleaseId}-${document.environmentSha256}`;
  const contextPath = path.join(
    root,
    "release-states",
    forgedStateId,
    "trusted-release-context.json",
  );
  try {
    document.releaseId = forgedReleaseId;
    document.releaseRoot = path.join(root, "releases", forgedReleaseId);
    document.stateId = forgedStateId;
    document.stateRoot = path.join(root, "release-states", forgedStateId);
    document.environmentFile = path.join(document.stateRoot, "environment.env");
    fs.mkdirSync(document.releaseRoot, { recursive: true });
    fs.mkdirSync(document.stateRoot, { recursive: true });
    fs.writeFileSync(document.environmentFile, "PLATFORM_ENV=production\n");
    const result = execute(root, contextPath, document);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /path identities/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("rejects a state ID and root coherently rebound away from the environment digest", () => {
  const { root, document } = fixture();
  const forgedStateId = `${document.releaseId}-${sha("c")}`;
  const contextPath = path.join(
    root,
    "release-states",
    forgedStateId,
    "trusted-release-context.json",
  );
  try {
    document.stateId = forgedStateId;
    document.stateRoot = path.join(root, "release-states", forgedStateId);
    document.environmentFile = path.join(document.stateRoot, "environment.env");
    fs.mkdirSync(document.stateRoot, { recursive: true });
    fs.writeFileSync(document.environmentFile, "PLATFORM_ENV=production\n");
    const result = execute(root, contextPath, document);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /path identities/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("production reader has no environment-controlled trust-root override", () => {
  const source = fs.readFileSync(script, "utf8");
  assert.doesNotMatch(source, /process\.env/);
});

test("test dependency seam is closed and cannot select a non-Linux policy", () => {
  assert.throws(() => createPlatformReleaseContextTestReader({
    infrastructureRoot: "/tmp/platform-release-context-test",
    expectedOwner: process.getuid(),
    platform: "darwin",
  }), /exact closed dependency schema/);
});

test("production CLI exposes no trust-root injection flag", () => {
  const result = spawnSync(process.execPath, [
    script,
    "read",
    "/tmp/trusted-release-context.json",
    "--infrastructureRoot",
    "/tmp/platform-infrastructure",
  ], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /^Usage: platform-release-context\.mjs read ABSOLUTE_CONTEXT\n$/);
});
