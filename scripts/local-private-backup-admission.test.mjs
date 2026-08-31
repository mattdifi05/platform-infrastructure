import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  createAdmissionPayload,
  fileSha256,
  signAdmission,
  verifyAdmissionDocument,
} from "./local-private-backup-admission.mjs";

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "local-private-admission-"));
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const files = Object.fromEntries(Object.entries({
    backup: "backup-signing-key-material-that-is-not-the-offline-key\n",
    catalog: "catalog-capability-material-00000000000000000000000000000000\n",
    job: "job-capability-material-000000000000000000000000000000000000\n",
    offsite: "offsite-capability-material-000000000000000000000000000000000\n",
    render: "services:\n  broker:\n    image: exact\n",
  }).map(([name, contents]) => {
    const file = path.join(root, name);
    fs.writeFileSync(file, contents, { mode: 0o600 });
    return [name, file];
  }));
  const now = Date.parse("2026-08-31T12:00:00.000Z");
  const payload = createAdmissionPayload({
    backupSigningKeySha256: fileSha256(files.backup),
    brokerImageId: `sha256:${"1".repeat(64)}`,
    catalogCapabilitySha256: fileSha256(files.catalog),
    combinedRenderSha256: fileSha256(files.render),
    expiresAt: "2026-09-30T12:00:00.000Z",
    issuedAt: "2026-08-31T12:00:00.000Z",
    jobCapabilitySha256: fileSha256(files.job),
    offsiteCapabilitySha256: fileSha256(files.offsite),
    releaseCommitSha1: "a".repeat(40),
    resticImageId: `sha256:${"3".repeat(64)}`,
    schedulerImageId: `sha256:${"2".repeat(64)}`,
    treeSha256: "b".repeat(64),
  });
  return {
    cleanup: () => fs.rmSync(root, { recursive: true, force: true }),
    document: signAdmission(payload, privateKey),
    files,
    now,
    privateKey,
    publicKey,
  };
}

function verify(value, subject) {
  return verifyAdmissionDocument(value.document, {
    backupSigningKeyFile: value.files.backup,
    capabilityFiles: {
      "backup.catalog": value.files.catalog,
      "backup.job.execute": value.files.job,
      "backup.offsite.sync": value.files.offsite,
    },
    now: value.now,
    publicKeyPem: value.publicKey,
    renderFile: value.files.render,
  });
}

test("signed LOCAL_PRIVATE admission binds target, render, images and exactly three backup capabilities", () => {
  const value = fixture();
  try {
    const verified = verify(value);
    assert.equal(verified.payload.targetId, "dell-192-168-1-202");
    assert.deepEqual(verified.payload.allowedActions, ["backup.catalog", "backup.job.execute", "backup.offsite.sync"]);
    assert.match(verified.payload.brokerImageId, /^sha256:[a-f0-9]{64}$/);
    assert.match(verified.payload.schedulerImageId, /^sha256:[a-f0-9]{64}$/);
    assert.match(verified.payload.resources.offsite.resticImageId, /^sha256:[a-f0-9]{64}$/);
  } finally {
    value.cleanup();
  }
});

test("signature, target, action widening, expiry, render and capability substitutions fail closed", () => {
  const value = fixture();
  try {
    const unsignedMutation = structuredClone(value.document);
    unsignedMutation.payload.targetId = "old-192-168-1-164";
    assert.throws(() => verify({ ...value, document: unsignedMutation }), /signature rejected/);

    for (const mutate of [
      (payload) => { payload.targetId = "old-192-168-1-164"; },
      (payload) => { payload.allowedActions.push("backup.prune.apply"); },
      (payload) => { payload.expiresAt = "2026-12-31T12:00:00.000Z"; },
      (payload) => { payload.brokerImageId = `sha256:${"0".repeat(64)}`; },
      (payload) => { payload.resources.offsite.repository = "rclone:other:repository"; },
      (payload) => { payload.resources.offsite.resticImageId = `sha256:${"0".repeat(64)}`; },
    ]) {
      const payload = structuredClone(value.document.payload);
      mutate(payload);
      const signed = signAdmission(payload, value.privateKey);
      assert.throws(() => verify({ ...value, document: signed }));
    }

    fs.appendFileSync(value.files.render, "# substituted\n");
    assert.throws(() => verify(value), /render hash differs/);
    fs.writeFileSync(value.files.render, "services:\n  broker:\n    image: exact\n", { mode: 0o600 });
    fs.appendFileSync(value.files.catalog, "substituted\n");
    assert.throws(() => verify(value), /capability hash differs/);
  } finally {
    value.cleanup();
  }
});

test("repository boundary never contains the offline private admission key", () => {
  const repositoryRoot = path.resolve(import.meta.dirname, "..");
  const compose = fs.readFileSync(path.join(repositoryRoot, "compose.local-private-backup.yaml"), "utf8");
  const dockerfile = fs.readFileSync(path.join(repositoryRoot, "docker", "ops.Dockerfile"), "utf8");
  assert.doesNotMatch(compose, /PRIVATE_KEY|private\/ed25519|BEGIN PRIVATE KEY/);
  assert.doesNotMatch(dockerfile, /PRIVATE_KEY|private\/ed25519|BEGIN PRIVATE KEY/);
  assert.match(dockerfile, /local-private-backup-admission\.pub\.pem/);
});

test("LOCAL_PRIVATE broker dependencies resolve from the immutable release tree without NODE_PATH", () => {
  const repositoryRoot = path.resolve(import.meta.dirname, "..");
  const dockerfile = fs.readFileSync(path.join(repositoryRoot, "docker", "ops.Dockerfile"), "utf8");
  const dockerignore = fs.readFileSync(path.join(repositoryRoot, ".dockerignore"), "utf8");
  const broker = fs.readFileSync(path.join(repositoryRoot, "scripts", "local-private-docker-action-broker.mjs"), "utf8");
  assert.match(
    dockerfile,
    /mv \/tmp\/control-center-dependencies\/node_modules \/opt\/platform-infrastructure\/node_modules/,
  );
  assert.doesNotMatch(dockerfile, /mv \/tmp\/control-center-dependencies\/node_modules \/node_modules/);
  assert.match(dockerignore, /^!vendor\/json-schema\/\*\*$/m);
  assert.match(dockerfile, /COPY vendor\/json-schema\/ \/opt\/platform-infrastructure\/vendor\/json-schema\//);
  assert.match(dockerfile, /createRequire\("\/opt\/platform-infrastructure\/vendor\/json-schema\/package\.json"\)/);
  assert.match(dockerfile, /require\("ajv"\)/);
  assert.match(dockerfile, /require\("ajv-formats"\)/);
  assert.match(broker, /delete childEnvironment\.NODE_PATH;/);
});

test("broker trust, render, state and UDS defaults stay outside shared checkout and state parents", () => {
  const repositoryRoot = path.resolve(import.meta.dirname, "..");
  const environment = Object.fromEntries(
    fs.readFileSync(path.join(repositoryRoot, ".env.example"), "utf8")
      .split(/\r?\n/)
      .filter((line) => /^[A-Z0-9_]+=/.test(line))
      .map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]),
  );
  const releaseRoot = environment.LOCAL_PRIVATE_RELEASE_ROOT;
  const privatePaths = [
    environment.LOCAL_PRIVATE_BACKUP_ADMISSION_FILE,
    environment.LOCAL_PRIVATE_BACKUP_RENDER_FILE,
    environment.LOCAL_PRIVATE_BACKUP_TRUST_DIR,
    environment.LOCAL_PRIVATE_BACKUP_BROKER_STATE_DIR,
    environment.LOCAL_PRIVATE_BACKUP_BROKER_RUNTIME_DIR,
  ];
  const isContainedBy = (parent, candidate) => {
    const relative = path.posix.relative(parent, candidate);
    return relative === "" || (!relative.startsWith("../") && relative !== "..");
  };
  for (const privatePath of privatePaths) {
    assert.equal(path.posix.isAbsolute(privatePath), true, privatePath);
    assert.equal(isContainedBy(releaseRoot, privatePath), false, privatePath);
  }

  const compose = fs.readFileSync(path.join(repositoryRoot, "compose.local-private-backup.yaml"), "utf8");
  assert.doesNotMatch(compose, /\$\{PLATFORM_STATE_DIR[^}]*\}\/docker-action-broker-(?:runtime|state)/);
  assert.match(compose, /\$\{LOCAL_PRIVATE_BACKUP_BROKER_STATE_DIR[^}]*\}:\/var\/lib\/platform-docker-action-broker/);
  assert.match(compose, /\$\{LOCAL_PRIVATE_BACKUP_BROKER_RUNTIME_DIR[^}]*\}:\/run\/platform\/docker-action-broker/);
});
