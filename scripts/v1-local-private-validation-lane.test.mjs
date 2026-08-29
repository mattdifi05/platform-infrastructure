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

test("validation-open is checkpoint-candidate-bound, byte-idempotent, and safely supersedes only closed stale lanes", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "lane-open-")));
  fs.chmodSync(root, 0o700);
  const now = Math.floor(Date.now() / 1000);
  const targetTree = "d".repeat(40);
  const targetArchive = "e".repeat(64);
  const lanePath = path.join(root, "var/lib/platform-infrastructure/v1/local-private/validation-lane.json");
  const targetLane = (overrides = {}) => ({
    candidateCommit: CANDIDATE,
    createdAtUnixSeconds: now - 10,
    expiresAtUnixSeconds: now + 3600,
    reason: "fast validation lane",
    schema: "platform.v1-local-private-validation-lane/v1",
    ...overrides,
  });
  const runOpen = () => runWithRoot(`
import importlib.util, json
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("rec", ${JSON.stringify(reconcile)})
spec = importlib.util.spec_from_loader("rec", loader)
m = importlib.util.module_from_spec(spec); loader.exec_module(m)
m.configure_environment()
m.install_binding = lambda: {
  "candidateCommit": ${JSON.stringify(CANDIDATE)}, "candidateTree": ${JSON.stringify(targetTree)},
  "releaseRoot": "/srv/platform-infrastructure/releases/test", "sourceArchiveSha256": ${JSON.stringify(targetArchive)}
}
print(json.dumps(m.validation_open(), sort_keys=True))
`, root);
  try {
    seedLane(root, targetLane());
    const original = fs.readFileSync(lanePath);
    const originalStat = fs.statSync(lanePath, { bigint: true });
    let result = runOpen();
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(fs.readFileSync(lanePath), original, "same-candidate retry rewrote marker bytes");
    const retryStat = fs.statSync(lanePath, { bigint: true });
    assert.equal(retryStat.ino, originalStat.ino, "same-candidate retry replaced the marker inode");
    assert.equal(retryStat.mtimeNs, originalStat.mtimeNs, "same-candidate retry refreshed marker metadata");
    assert.deepEqual(JSON.parse(result.stdout), {
      candidateCommit: CANDIDATE,
      candidateTree: targetTree,
      schema: "platform.v1-local-private-validation-lane-open-result/v1",
      sourceArchiveSha256: targetArchive,
      status: "VALIDATION_LANE_OPEN",
      validationLaneSha256: sha(original),
    });

    for (const stale of [
      targetLane({ candidateCommit: "c".repeat(40) }),
      targetLane({ createdAtUnixSeconds: now - 7200, expiresAtUnixSeconds: now - 3600 }),
    ]) {
      seedLane(root, stale);
      const staleBytes = fs.readFileSync(lanePath);
      result = runOpen();
      assert.equal(result.status, 0, result.stderr);
      const replacement = fs.readFileSync(lanePath);
      assert.notDeepEqual(replacement, staleBytes);
      assert.equal(fs.statSync(lanePath).mode & 0o777, 0o400);
      const document = JSON.parse(replacement);
      assert.equal(document.candidateCommit, CANDIDATE);
      assert.equal(document.reason, "FAST_VALIDATION_NO_MUTATION");
      assert.equal(replacement.toString(), `${JSON.stringify(document, Object.keys(document).sort())}\n`);
    }

    for (const currentName of ["reconciliation.json", "reconcile-journal.json", "reconciliation-abort-record.json"]) {
      const currentPath = path.join(path.dirname(lanePath), currentName);
      for (const stale of [
        targetLane({ candidateCommit: "c".repeat(40) }),
        targetLane({ createdAtUnixSeconds: now - 7200, expiresAtUnixSeconds: now - 3600 }),
      ]) {
        seedLane(root, stale);
        fs.writeFileSync(currentPath, "{}\n", { mode: 0o600 });
        const before = fs.readFileSync(lanePath);
        result = runOpen();
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /transaction is open/);
        assert.deepEqual(fs.readFileSync(lanePath), before, `${currentName} did not preserve marker bytes`);
        fs.unlinkSync(currentPath);
      }
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("validation-close removes only an ACTIVE receipt-bound archived FAST no-mutation lane and is idempotent", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "lane-close-")));
  fs.chmodSync(root, 0o700);
  const now = Math.floor(Date.now() / 1000);
  const lanePath = seedLane(root, {
    candidateCommit: CANDIDATE,
    createdAtUnixSeconds: now - 60,
    expiresAtUnixSeconds: now + 3600,
    reason: "FAST_VALIDATION_NO_MUTATION",
    schema: "platform.v1-local-private-validation-lane/v1",
  });
  const laneSha = sha(fs.readFileSync(lanePath));
  const authorityBytes = Buffer.from("authority-bytes\n");
  const authoritySha = sha(authorityBytes);
  const authorityId = sha("authority-document");
  const transactionId = sha("validation-transaction");
  const source = (overrides = "") => `
import importlib.util, json
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("rec", ${JSON.stringify(reconcile)})
spec = importlib.util.spec_from_loader("rec", loader)
m = importlib.util.module_from_spec(spec); loader.exec_module(m)
m.configure_environment()
authority = {"candidateCommit": ${JSON.stringify(CANDIDATE)}, "candidateTree": "d"*40,
  "documentId": ${JSON.stringify(authorityId)}, "sourceArchiveSha256": "e"*64}
authority_bytes = ${JSON.stringify(authorityBytes.toString())}.encode()
binding = {"authorityDocumentId": authority["documentId"], "authoritySha256": m.digest(authority_bytes),
  "journalSha256": "f"*64, "residualDataMutations": [],
  "status": "ABORTED_NO_DATA_MUTATION", "transactionId": ${JSON.stringify(transactionId)}}
receipt = {"candidateCommit": authority["candidateCommit"], "candidateTree": authority["candidateTree"],
  "schema": "platform.v1-local-private-control-receipt/v1", "sourceArchiveSha256": authority["sourceArchiveSha256"],
  "status": "ACTIVE"}
journal = {"abortCheckpointSha256": None, "authorityDocumentId": authority["documentId"],
  "authoritySha256": m.digest(authority_bytes), "dataMutationEvidence": [], "dataMutationStatus": {"db": "NEVER_STARTED"},
  "phase": "ABORTED", "schema": m.JOURNAL_SCHEMA, "steps": [], "transactionId": binding["transactionId"],
  "validationLaneSha256": ${JSON.stringify(laneSha)}}
journal_bytes = b"archived-fast-journal\\n"
binding["journalSha256"] = m.digest(journal_bytes)
m.read_authority = lambda: (authority, authority_bytes)
m.validate_authority_material = lambda value: {}
m.preverified_active_receipt = lambda: receipt
m.receipt_bound_abort_archive = lambda required=False: (receipt, binding, journal, journal_bytes)
${overrides}
try:
    value = m.validation_close()
    print(json.dumps({"ok": True, "value": value}, sort_keys=True))
except m.Stop as error:
    print(json.dumps({"error": str(error), "ok": False}, sort_keys=True))
`;
  try {
    let result = runWithRoot(source(), root);
    assert.equal(result.status, 0, result.stderr);
    let verdict = JSON.parse(result.stdout);
    assert.equal(verdict.ok, true);
    assert.equal(fs.existsSync(lanePath), false);
    assert.deepEqual(verdict.value, {
      authorityDocumentId: authorityId,
      authoritySha256: authoritySha,
      candidateCommit: CANDIDATE,
      schema: "platform.v1-local-private-validation-lane-close-result/v1",
      status: "VALIDATION_LANE_CLOSED",
      transactionId,
      validationLaneSha256: laneSha,
    });

    result = runWithRoot(source(), root);
    assert.equal(result.status, 0, result.stderr);
    verdict = JSON.parse(result.stdout);
    assert.equal(verdict.ok, true, "lost-output retry did not accept already absent marker");

    seedLane(root, {
      candidateCommit: CANDIDATE, createdAtUnixSeconds: now - 60, expiresAtUnixSeconds: now + 3600,
      reason: "FAST_VALIDATION_NO_MUTATION", schema: "platform.v1-local-private-validation-lane/v1",
    });
    const before = fs.readFileSync(lanePath);
    result = runWithRoot(source('journal["validationLaneSha256"] = "0"*64'), root);
    verdict = JSON.parse(result.stdout);
    assert.equal(verdict.ok, false);
    assert.deepEqual(fs.readFileSync(lanePath), before, "archive mismatch removed or rewrote the marker");

    const current = path.join(path.dirname(lanePath), "reconcile-journal.json");
    fs.writeFileSync(current, "{}\n", { mode: 0o600 });
    result = runWithRoot(source(), root);
    verdict = JSON.parse(result.stdout);
    assert.equal(verdict.ok, false);
    assert.match(verdict.error, /open reconciliation transaction/);
    assert.deepEqual(fs.readFileSync(lanePath), before, "open transaction changed the marker");
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("validation lane lifecycle verbs are fixed no-argument operations under both reconciler locks", () => {
  const source = fs.readFileSync(reconcile, "utf8");
  const mainBody = source.slice(source.indexOf("def main() ->"));
  assert.match(mainBody, /len\(sys\.argv\) != 2/);
  assert.match(mainBody, /"validation-open", "validation-close"/);
  assert.match(mainBody, /shared_lock_fd = acquire_lock\(SHARED_LOCK/);
  assert.match(mainBody, /local_lock_fd = acquire_lock\(LOCK/);
  assert.ok(mainBody.indexOf("shared_lock_fd = acquire_lock(SHARED_LOCK") < mainBody.indexOf("local_lock_fd = acquire_lock(LOCK"));
  const openBody = source.slice(source.indexOf("def validation_open()"), source.indexOf("def journal_uses_validation_lane"));
  assert.match(openBody, /binding = install_binding\(\)/);
  assert.doesNotMatch(openBody, /sys\.argv|os\.environ/);
  assert.match(openBody, /atomic_json\([\s\S]*VALIDATION_LANE_FILE[\s\S]*0o400/);
  const closeBody = source.slice(source.indexOf("def validation_close()"), source.indexOf("def prepare() ->"));
  assert.match(closeBody, /validation_transaction_files_present\(\)/);
  assert.match(closeBody, /preverified_active_receipt\(\)/);
  assert.match(closeBody, /receipt_bound_abort_archive\(required=True\)/);
  assert.match(closeBody, /os\.unlink\(pathname\)[\s\S]*os\.fsync\(directory_fd\)/);
});

test("fast prepare validation checkpoint: honest booleans, real provenance, readback, no producer call", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "lane-checkpoint-")));
  fs.chmodSync(root, 0o700);
  const now = Math.floor(Date.now() / 1000);
  try {
    const localPrivate = path.join(root, "var/lib/platform-infrastructure/v1/local-private");
    const predeploy = path.join(root, "var/lib/platform-infrastructure/v1/predeploy/current");
    const predecessorAuthorityDocumentId = sha("predecessor-authority-document");
    const predecessorAuthoritySha256 = sha("predecessor-authority-bytes");
    const predecessorCommit = "a".repeat(40);
    const predecessorTree = "7".repeat(40);
    const predecessorArchive = "6".repeat(64);
    fs.mkdirSync(localPrivate, { recursive: true, mode: 0o700 });
    fs.mkdirSync(predeploy, { recursive: true, mode: 0o700 });
    const reused = {};
    for (const [field, name] of [
      ["logicalBackupEvidenceSha256", "logical-backup-evidence.json"],
      ["offHostBackupEvidenceSha256", "offhost-backup-evidence.json"],
      ["restoreEvidenceSha256", "restore-evidence.json"],
      ["runtimeInventorySha256", "runtime-inventory-evidence.json"],
      ["secretsBackupEvidenceSha256", "secrets-backup-evidence.json"],
    ]) {
      const evidenceDocument = {
        authorityDocumentId: predecessorAuthorityDocumentId,
        authoritySha256: predecessorAuthoritySha256,
        candidateCommit: predecessorCommit,
        candidateTree: predecessorTree,
        evidencePhase: "PRE",
        kind: name,
        real: true,
        reconciliationSha256: null,
        sourceArchiveSha256: predecessorArchive,
        transactionId: null,
      };
      const bytes = Buffer.from(JSON.stringify(evidenceDocument, Object.keys(evidenceDocument).sort(), 0) + "\n");
      fs.writeFileSync(path.join(predeploy, name), bytes);
      reused[field] = sha(bytes);
    }
    const priorCheckpoint = {
      authoritative: false,
      backupCapturedUnixSeconds: PRIOR_CAPTURE,
      candidateCommit: predecessorCommit,
      candidateTree: predecessorTree,
      destructiveMutationPlanned: false,
      generatedAtUnixSeconds: PRIOR_CAPTURE,
      ...reused,
      restoreVerified: true,
      runtimeRecovered: true,
      schedulerRecoveryImageExportSha256: sha("export-tar"),
      schedulerRecoveryImageId: "sha256:" + sha("export-index"),
      schedulerRunningImageId: "sha256:" + sha("running-image"),
      schema: "platform.v1-local-private-predeploy-checkpoint/v1",
      sourceArchiveSha256: predecessorArchive,
    };
    const priorCheckpointBytes = Buffer.from(JSON.stringify(priorCheckpoint, Object.keys(priorCheckpoint).sort(), 0) + "\n");
    fs.writeFileSync(path.join(predeploy, "local-private-checkpoint.json"), priorCheckpointBytes);
    const priorCheckpointSha256 = sha(priorCheckpointBytes);
    const predecessorState = {
      candidateCommit: predecessorCommit,
      candidateTree: predecessorTree,
      checkpointSha256: priorCheckpointSha256,
      sourceArchiveSha256: predecessorArchive,
      status: "ACTIVE",
    };
    const predecessorReceipt = {
      candidateCommit: predecessorCommit,
      candidateTree: predecessorTree,
      checkpointSha256: priorCheckpointSha256,
      schema: "platform.v1-local-private-control-receipt/v1",
      sourceArchiveSha256: predecessorArchive,
      status: "ACTIVE",
    };
    fs.writeFileSync(path.join(localPrivate, "state.json"), Buffer.from(JSON.stringify(predecessorState, Object.keys(predecessorState).sort(), 0) + "\n"), { mode: 0o600 });
    fs.writeFileSync(path.join(localPrivate, "active-receipt.json"), Buffer.from(JSON.stringify(predecessorReceipt, Object.keys(predecessorReceipt).sort(), 0) + "\n"), { mode: 0o444 });
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
m.read_archived_authority = lambda document_id, authority_sha: ({
    "candidateCommit": ${JSON.stringify(predecessorCommit)},
    "candidateTree": ${JSON.stringify(predecessorTree)},
    "sourceArchiveSha256": ${JSON.stringify(predecessorArchive)},
}, b"authority") if document_id == ${JSON.stringify(predecessorAuthorityDocumentId)} and authority_sha == ${JSON.stringify(predecessorAuthoritySha256)} else (_ for _ in ()).throw(AssertionError("wrong predecessor authority binding"))
authority = {"candidateCommit": ${JSON.stringify(CANDIDATE)}, "candidateTree": "9"*40, "sourceArchiveSha256": "8"*64}
binding = {"candidateCommit": authority["candidateCommit"], "candidateTree": authority["candidateTree"], "sourceArchiveSha256": authority["sourceArchiveSha256"]}
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
    assert.equal(verdict.checkpoint.predecessorAuthorityDocumentId, predecessorAuthorityDocumentId);
    assert.equal(verdict.checkpoint.predecessorCandidateCommit, predecessorCommit);
    assert.equal(verdict.checkpoint.schema, "platform.v1-local-private-predeploy-checkpoint-validation/v2");
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
  assert.match(source, /VALIDATION_CHECKPOINT_SCHEMA = "platform\.v1-local-private-predeploy-checkpoint-validation\/v2"/);
  assert.match(validateBody, /validation reused evidence/);
  assert.match(validateBody, /recorded == "0" \* 64 or not os\.path\.lexists\(pathname\)/);
  assert.match(validateBody, /any\(predecessor_checkpoint\[key\] != value\[key\] for key in CHECKPOINT_EVIDENCE_PATHS\)/);
  assert.match(validateBody, /predecessor_state\["checkpointSha256"\] != value\["predecessorCheckpointSha256"\]/);
  assert.match(source, /validation lane forbids the production seal/);
  const productionGate = source.slice(source.indexOf('data = secure_file(CHECKPOINT, "fresh PRE-DEPLOY checkpoint")'), source.indexOf('export_metadata = parse_recovery_export'));
  assert.doesNotMatch(productionGate, /validation/i);
});

test("deploy source contract: validation mode skips CMS and seal, distinct evidence protocol, production default intact", () => {
  const source = fs.readFileSync(deployScript, "utf8");
  assert.match(source, /REMOTE_VALIDATION_MODE=.*validation-mode/);
  assert.match(source, /capture_remote 3 "controller validation mode"/);
  assert.match(source, /validation_mode=\$\(validate_protocol_json "\$validation_mode_file" validation-mode\)/);
  assert.doesNotMatch(source, /validation mode.*capture_remote 1/i);
  assert.match(source, /\[ "\$\{VALIDATION_MODE:-0\}" != 1 \] && capture_remote 1 "controller seal"/);
  assert.match(source, /VALIDATION_MODE" != 1 ]; then\n  fetch_and_verify_cms PRE/);
  assert.match(source, /VALIDATION_MODE" != 1 ]; then\n  fetch_and_verify_cms POST/);
  assert.match(source, /apply-validation/);
  assert.match(source, /VALIDATED_NO_MUTATION/);
  assert.match(source, /evidence-validation/);
  assert.match(source, /runtime-inventory-evidence-validation-\$\{value\.transactionId\}\.json/);
  assert.match(source, /value\.transactionId !== peer\.transactionId/);
  assert.match(source, /abort-record-no-data-after-apply/);
  assert.match(source, /abort-record-no-data-unbound/);
  assert.match(source, /validation evidence failed; the exact no-mutation transaction was rolled back and finalized/);
  const validationBranch = source.slice(
    source.indexOf('if [ "$VALIDATION_MODE" = 1 ]; then', source.indexOf("evidence_response=")),
    source.indexOf("seal_response="),
  );
  assert.match(validationBranch, /production seal is forbidden/);
  assert.match(validationBranch, /abort_before_commit abort-record-no-data "\$evidence_response"/);
  assert.match(validationBranch, /validation controller activation/);
  assert.match(validationBranch, /cmp -s "\$receipt" "\$abort_final_verify"/);
  assert.match(validationBranch, /validate_protocol_json "\$receipt" aborted-active "\$abort_record"/);
  assert.match(validationBranch, /REMOTE_ABORTED_RECORD/);
  assert.match(validationBranch, /REMOTE_RUNTIME_AUTHORITY/);
  assert.match(validationBranch, /--predecessorAuthorityFile "\$predecessor_authority"/);
  assert.match(validationBranch, /--abortRecordFile "\$exported_abort_record"/);
  assert.match(validationBranch, /cat "\$receipt"\n  exit 0/);
  assert.doesNotMatch(validationBranch, /controller seal/);
  const cmsCount = (source.match(/fetch_and_verify_cms (PRE|POST)/g) ?? []).length;
  assert.equal(cmsCount, 2, "PRE and POST must each keep exactly one guarded invocation");
});
