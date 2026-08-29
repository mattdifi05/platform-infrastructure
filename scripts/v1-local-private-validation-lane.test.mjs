#!/usr/bin/env node
import assert from "node:assert/strict";
import child from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const python = process.env.CODEX_PYTHON ?? "python3";
const reconcile = path.join(repositoryRoot, "scripts/v1-local-private-reconcile.py");
const control = path.join(repositoryRoot, "scripts/v1-local-private-control.py");
const deployScript = path.join(repositoryRoot, "scripts/deploy-v1-local-private.sh");

const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
import crypto from "node:crypto";

const CANDIDATE = "b".repeat(40);
const PRIOR_CAPTURE = 1756100000;

function runWithRoot(source, root) {
  const result = spawnSync(python, ["-c", source], {
    cwd: repositoryRoot, encoding: "utf8", maxBuffer: 8 * 1024 * 1024,
    env: { ...process.env, PLATFORM_V1_RECONCILE_TEST_ROOT: root, PLATFORM_V1_LOCAL_PRIVATE_TEST_ROOT: root },
  });
  return result;
}

function seedLane(root, doc) {
  const lanePath = path.join(root, "var/lib/platform-infrastructure/v1/local-private/validation-lane.json");
  fs.mkdirSync(path.dirname(lanePath), { recursive: true, mode: 0o700 });
  if (fs.existsSync(lanePath)) fs.unlinkSync(lanePath);
  fs.writeFileSync(lanePath, Buffer.from(JSON.stringify(doc, Object.keys(doc).sort(), 0) + "\n"));
  fs.chmodSync(lanePath, 0o400);
  fs.chownSync(lanePath, process.getuid(), process.getgid());
  return lanePath;
}

test("validation lane marker loader: valid, exact closed-set, expired, extra key, wrong candidate", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "lane-loader-")));
  fs.chmodSync(root, 0o700);
  const now = Math.floor(Date.now() / 1000);
  const body = (overrides) => JSON.stringify({
    schema: "platform.v1-local-private-validation-lane/v1", candidateCommit: CANDIDATE,
    createdAtUnixSeconds: now - 60, expiresAtUnixSeconds: now + 3600, reason: "fast validation lane",
    ...overrides,
  }, Object.keys({ schema: 0, candidateCommit: 0, createdAtUnixSeconds: 0, expiresAtUnixSeconds: 0, reason: 0 }).sort(), 0);
  try {
    const base = `
import importlib.util, json, os
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("rec", ${JSON.stringify(reconcile)})
spec = importlib.util.spec_from_loader("rec", loader)
m = importlib.util.module_from_spec(spec); loader.exec_module(m)
m.configure_environment()
candidate = ${JSON.stringify(CANDIDATE)}
def probe():
    lane = m.load_validation_lane(candidate)
    return "ABSENT" if lane is None else "PRESENT"
`;
    seedLane(root, JSON.parse(body({})));
    let r = runWithRoot(base + "\nprint(json.dumps({'present': probe()}))", root);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(JSON.parse(r.stdout).present, "PRESENT");

    seedLane(root, JSON.parse(body({ expiresAtUnixSeconds: now - 10 })));
    r = runWithRoot(base + "\nprint(json.dumps({'present': probe()}))", root);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /expired or future-dated/);

    seedLane(root, { schema: "platform.v1-local-private-validation-lane/v1", candidateCommit: CANDIDATE, createdAtUnixSeconds: now - 60, expiresAtUnixSeconds: now + 3600, reason: "fast validation lane", extra: "key" });
    r = runWithRoot(base + "\nprint(json.dumps({'present': probe()}))", root);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /exact closed object/);

    seedLane(root, JSON.parse(body({ candidateCommit: "c".repeat(40) })));
    r = runWithRoot(base + "\nprint(json.dumps({'present': probe()}))", root);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /fields are invalid/);

    fs.rmSync(path.join(root, "var/lib/platform-infrastructure/v1/local-private/validation-lane.json"));
    r = runWithRoot(base + "\nprint(json.dumps({'present': probe()}))", root);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(JSON.parse(r.stdout).present, "ABSENT");
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("fast prepare validation checkpoint: honest booleans, real provenance, readback, no producer call", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "lane-checkpoint-")));
  fs.chmodSync(root, 0o700);
  const now = Math.floor(Date.now() / 1000);
  try {
    const localPrivate = path.join(root, "var/lib/platform-infrastructure/v1/local-private");
    const predeploy = path.join(root, "var/lib/platform-infrastructure/v1/predeploy/current");
    fs.mkdirSync(localPrivate, { recursive: true, mode: 0o700 });
    fs.mkdirSync(predeploy, { recursive: true, mode: 0o700 });
    const priorCheckpoint = {
      schema: "platform.v1-local-private-predeploy-checkpoint/v1", candidateCommit: "a".repeat(40),
      backupCapturedUnixSeconds: PRIOR_CAPTURE,
      schedulerRecoveryImageExportSha256: sha("export-tar"),
      schedulerRecoveryImageId: "sha256:" + sha("export-index"),
      schedulerRunningImageId: "sha256:" + sha("running-image"),
    };
    fs.writeFileSync(path.join(predeploy, "local-private-checkpoint.json"), Buffer.from(JSON.stringify(priorCheckpoint, Object.keys(priorCheckpoint).sort(), 0) + "\n"));
    const reused = {};
    for (const [field, name] of [
      ["logicalBackupEvidenceSha256", "logical-backup-evidence.json"],
      ["offHostBackupEvidenceSha256", "offhost-backup-evidence.json"],
      ["restoreEvidenceSha256", "restore-evidence.json"],
      ["runtimeInventorySha256", "runtime-inventory-evidence.json"],
      ["secretsBackupEvidenceSha256", "secrets-backup-evidence.json"],
    ]) {
      const bytes = Buffer.from(`{"kind":"${name}","real":true}\n`);
      fs.writeFileSync(path.join(predeploy, name), bytes);
      reused[field] = sha(bytes);
    }
    seedLane(root, { schema: "platform.v1-local-private-validation-lane/v1", candidateCommit: CANDIDATE, createdAtUnixSeconds: now - 30, expiresAtUnixSeconds: now + 3600, reason: "fast validation lane" });

    const source = `
import importlib.util, json, os
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("rec", ${JSON.stringify(reconcile)})
spec = importlib.util.spec_from_loader("rec", loader)
m = importlib.util.module_from_spec(spec); loader.exec_module(m)
m.configure_environment()
called = {"producer": False}
def forbidden(*_a, **_k):
    called["producer"] = True
    raise SystemExit(1)
m.invoke_evidence_producer = forbidden
m.existing_recovery_binding = lambda: {
    "exportSha256": ${JSON.stringify(sha("export-tar"))},
    "recoveryImageId": "sha256:" + ${JSON.stringify(sha("export-index"))},
    "runningImageId": "sha256:" + ${JSON.stringify(sha("running-image"))},
}
authority = {"candidateCommit": ${JSON.stringify(CANDIDATE)}}
binding = {"candidateCommit": authority["candidateCommit"], "candidateTree": "9"*40, "sourceArchiveSha256": "8"*64}
checkpoint = m.write_validation_checkpoint(authority, binding)
raw = open(${JSON.stringify(path.join(root, "var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint-validation.json"))}, "rb").read()
print(json.dumps({"producerCalled": called["producer"], "checkpoint": checkpoint,
  "readback": raw.decode() == json.dumps(checkpoint, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\\n"}))
`;
    const r = runWithRoot(source, root);
    assert.equal(r.status, 0, r.stderr);
    const verdict = JSON.parse(r.stdout);
    assert.equal(verdict.producerCalled, false);
    assert.equal(verdict.readback, true);
    assert.equal(verdict.checkpoint.validation, true);
    assert.equal(verdict.checkpoint.restoreVerified, false);
    assert.equal(verdict.checkpoint.runtimeRecovered, false);
    assert.equal(verdict.checkpoint.backupCapturedUnixSeconds, PRIOR_CAPTURE);
    assert.equal(verdict.checkpoint.logicalBackupEvidenceSha256, reused.logicalBackupEvidenceSha256);
    assert.equal(verdict.checkpoint.schema, "platform.v1-local-private-predeploy-checkpoint-validation/v1");
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("prepare source contract: lane gate precedes the heavy evidence producer", () => {
  const source = fs.readFileSync(reconcile, "utf8");
  const prepareBody = source.slice(source.indexOf("def prepare() ->"), source.indexOf("def apply(", source.indexOf("def prepare() ->")));
  const laneIndex = prepareBody.indexOf("load_validation_lane(commit)");
  const producerIndex = prepareBody.indexOf('invoke_evidence_producer(prepared_authority, "pre")');
  assert.ok(laneIndex >= 0 && producerIndex > laneIndex, "validation gate must precede the producer call");
  assert.match(prepareBody, /status.*PREPARED_VALIDATION/);
});

test("control validation branch: validation checkpoint accepted, evidence digests verified, production untouched", () => {
  const source = fs.readFileSync(control, "utf8");
  const validateBody = source.slice(source.indexOf("def load_validation_lane"), source.indexOf("def command_environment()"));
  assert.match(validateBody, /load_validation_lane\(CANDIDATE_COMMIT\)/);
  assert.match(validateBody, /VALIDATION_CHECKPOINT_SCHEMA/);
  assert.match(validateBody, /validation reused evidence/);
  assert.match(source, /validation lane forbids the production seal/);
  const productionGate = source.slice(source.indexOf('data = secure_file(CHECKPOINT, "fresh PRE-DEPLOY checkpoint")'), source.indexOf('export_metadata = parse_recovery_export'));
  assert.doesNotMatch(productionGate, /validation/i);
});

test("deploy source contract: validation mode skips CMS and seal, distinct evidence protocol, production default intact", () => {
  const source = fs.readFileSync(deployScript, "utf8");
  assert.match(source, /REMOTE_VALIDATION_LANE_CAT=/);
  assert.match(source, /VALIDATION_MODE=0/);
  assert.match(source, /\[ "\$\{VALIDATION_MODE:-0\}" != 1 \] && capture_remote 1 "controller seal"/);
  assert.match(source, /VALIDATION_MODE" != 1 ]; then\n  fetch_and_verify_cms PRE/);
  assert.match(source, /VALIDATION_MODE" != 1 ]; then\n  fetch_and_verify_cms POST/);
  assert.match(source, /evidence-validation/);
  const cmsCount = (source.match(/fetch_and_verify_cms (PRE|POST)/g) ?? []).length;
  assert.equal(cmsCount, 2, "PRE and POST must each keep exactly one guarded invocation");
});
