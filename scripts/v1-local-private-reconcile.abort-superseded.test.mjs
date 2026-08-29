import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const reconciler = path.join(here, "v1-local-private-reconcile.py");
const source = fs.readFileSync(reconciler, "utf8");
const python = process.env.PLATFORM_TEST_PYTHON || "/usr/bin/python3";

function runPython(body) {
  return execFileSync(python, ["-c", `import json,runpy\nm=runpy.run_path(${JSON.stringify(reconciler)},run_name='v1_reconciler_test')\n${body}`], {
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function jsonPython(body) {
  return JSON.parse(runPython(body));
}

const PROJECTION_FIELDS = ["configHash", "containerId", "exitCode", "health", "imageId", "imageReference", "name", "networkMembership", "runtimeConfigSha256", "semanticSha256", "service", "state"];

function seedRecordedIdentities() {
  return ["enterprise-postgres", "enterprise-redis"].map((name) => {
    const record = {};
    for (const [index, field] of PROJECTION_FIELDS.entries()) record[field] = field === "name" ? name : `value-${index}`;
    record.containerId = "b".repeat(64);
    record.configHash = "b".repeat(64);
    return record;
  });
}

test("controller predecessor identity projection is one explicit closed-set contract", () => {
  const recorded = seedRecordedIdentities()[0];
  const live = { ...recorded, project: "platform_infra" };
  const result = jsonPython(`
import json
recorded = json.loads(${JSON.stringify(JSON.stringify(recorded))})
live = json.loads(${JSON.stringify(JSON.stringify(live))})
print(json.dumps({
  'match': m['controller_predecessor_identity_match'](recorded, live),
  'containerDrift': m['controller_predecessor_identity_match'](dict(recorded, containerId='${"c".repeat(64)}'), live),
  'imageDrift': m['controller_predecessor_identity_match'](dict(recorded, imageId='sha256:' + '${"9".repeat(64)}'), live),
  'networkDrift': m['controller_predecessor_identity_match'](dict(recorded, networkMembership=[]), live),
  'extraLiveKey': m['controller_predecessor_identity_match'](recorded, dict(live, unexpected='x')),
  'recordedWithProject': m['controller_predecessor_identity_match'](dict(recorded, project='platform_infra'), live),
  'missingLiveField': m['controller_predecessor_identity_match'](recorded, {k: v for k, v in live.items() if k != 'semanticSha256'}),
  'nonDictBefore': m['controller_predecessor_identity_match'](None, live),
  'nonDictLive': m['controller_predecessor_identity_match'](recorded, None),
}))`);
  assert.deepEqual(result, {
    match: true,
    containerDrift: false,
    imageDrift: false,
    networkDrift: false,
    extraLiveKey: false,
    recordedWithProject: false,
    missingLiveField: false,
    nonDictBefore: false,
    nonDictLive: false,
  });
});

test("materialize_rollback_spec tolerates only the recorded closed projection", () => {
  const value = jsonPython(`
import json, os, tempfile
root = tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root, 0o700); os.chown(root, os.geteuid(), os.getegid())
g = m['materialize_rollback_spec'].__globals__; g['TEST_ROOT'] = root; g['OWNER_UID'] = os.geteuid(); g['OWNER_GID'] = os.getegid()
fields = ${JSON.stringify(PROJECTION_FIELDS)}
before = {field: f"value-{index}" for index, field in enumerate(fields)}
before["name"] = "enterprise-postgres"
before["containerId"] = "b" * 64
live = dict(before, project="platform_infra")
g['inspect_one'] = lambda name: ({"Id": before["containerId"]}, live)
logical, digest = m['materialize_rollback_spec']('a' * 64, before)
written = json.loads(open(m['physical'](logical)).read())
drifted = dict(live, containerId='c' * 64)
g['inspect_one'] = lambda name: ({"Id": drifted["containerId"]}, drifted)
try:
    m['materialize_rollback_spec']('a' * 64, before)
    drift_stopped = False
except m['Stop']:
    drift_stopped = True
print(json.dumps({'specWritten': written['predecessorIdentity'] == before and written['transactionId'] == 'a' * 64, 'driftStopped': drift_stopped}))`);
  assert.deepEqual(value, { specWritten: true, driftStopped: true });
});

test("stale abort preconditions prove apply never started", () => {
  const value = jsonPython(`
import hashlib, json, os, tempfile, time
root = tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root, 0o700); os.chown(root, os.geteuid(), os.getegid())
g = m['verify_superseded_transport_abort_preconditions'].__globals__; g['TEST_ROOT'] = root; g['OWNER_UID'] = os.geteuid(); g['OWNER_GID'] = os.getegid()
def put(logical, data, mode):
    p = m['physical'](logical); os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    if os.path.exists(p): os.chmod(p, 0o600)
    open(p, 'wb').write(data); os.chmod(p, mode)
identities = ${JSON.stringify(seedRecordedIdentities())}
authority = {'documentId': 'd' * 64, 'authorizedDataMutations': [{'id': 'mutation-one'}]}
state_bytes = b'predecessor-state-bytes'
receipt_bytes = b'predecessor-receipt-bytes'
reconciliation = {
    'previousStateSha256': hashlib.sha256(state_bytes).hexdigest(),
    'previousReceiptSha256': hashlib.sha256(receipt_bytes).hexdigest(),
    'predecessorRuntimeIdentities': identities,
}
put(m['STATE_FILE'], state_bytes, 0o600); put(m['ACTIVE_RECEIPT'], receipt_bytes, 0o444)
live_by_name = {item['name']: dict(item, project='platform_infra') for item in identities}
g['inspect_one'] = lambda name: ({'Id': live_by_name[name]['containerId']}, live_by_name[name])
m['verify_superseded_transport_abort_preconditions'](authority, reconciliation)
drifted = dict(live_by_name['enterprise-redis'], containerId='c' * 64)
g['inspect_one'] = lambda name: ({'Id': drifted['containerId']}, drifted if name == 'enterprise-redis' else live_by_name[name])
try:
    m['verify_superseded_transport_abort_preconditions'](authority, reconciliation)
    drift_stopped = False
except m['Stop']:
    drift_stopped = True
g['inspect_one'] = lambda name: ({'Id': live_by_name[name]['containerId']}, live_by_name[name])
m['verify_superseded_transport_abort_preconditions'](authority, reconciliation)
put(f"{m['MUTATION_EVIDENCE_DIR']}/{authority['documentId']}-mutation-one-{'e' * 64}.json", b'{}', 0o444)
try:
    m['verify_superseded_transport_abort_preconditions'](authority, reconciliation)
    evidence_stopped = False
except m['Stop']:
    evidence_stopped = True
print(json.dumps({'preconditionsPass': True, 'driftStopped': drift_stopped, 'evidenceStopped': evidence_stopped}))`);
  assert.deepEqual(value, { preconditionsPass: true, driftStopped: true, evidenceStopped: true });
});

test("latest transport tooling coherence binds installed artifacts to the receipt chain", () => {
  const value = jsonPython(`
import hashlib, json, os, tempfile
root = tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root, 0o700); os.chown(root, os.geteuid(), os.getegid())
g = m['latest_transport_tooling_coherence'].__globals__; g['TEST_ROOT'] = root; g['OWNER_UID'] = os.geteuid(); g['OWNER_GID'] = os.getegid()
def put(logical, data, mode):
    p = m['physical'](logical); os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    if os.path.exists(p): os.chmod(p, 0o600)
    open(p, 'wb').write(data); os.chmod(p, mode)
def sha(data): return hashlib.sha256(data).hexdigest()
commit = 'a' * 40; tree = 'b' * 40; archive = 'c' * 64
artifacts = {}
for name, logical, mode in (
    ('installer', m['INSTALLER'], 0o555),
    ('controller', m['CONTROLLER'], 0o555),
    ('reconciler', m['RECONCILER'], 0o555),
    ('unit', m['UNIT'], 0o444),
    ('sudoers', m['SUDOERS'], 0o440),
):
    data = f'installed-{name}-bytes'.encode()
    put(logical, data, mode)
    artifacts[name] = {'mode': f'{mode:04o}', 'name': name, 'path': logical, 'sha256': sha(data)}
control = {
    'artifacts': [artifacts[name] for name in m['BOOTSTRAP_CONTROL_RECEIPT_ARTIFACT_NAMES']],
    'candidateCommit': commit, 'candidateTree': tree,
    'dataMutation': False, 'dockerMutation': False, 'hostControlMutation': True,
    'schema': m['BOOTSTRAP_CONTROL_ARTIFACT_RECEIPT_SCHEMA'],
    'sourceArchiveSha256': archive, 'status': 'CONTROL_ARTIFACTS_INSTALLED',
}
control_bytes = m['canonical_bytes'](control)
put(m['BOOTSTRAP_CONTROL_RECEIPT_FILE'], control_bytes, 0o400)
bridge = {
    'bridgeSha256': '1' * 64, 'candidateCommit': commit, 'candidateConsumerSha256': '2' * 64,
    'candidateTree': tree, 'checkpointAfterSha256': '3' * 64, 'checkpointBeforeSha256': None,
    'controlArtifactReceiptSha256': sha(control_bytes), 'dataMutation': False, 'dockerMutation': False,
    'documentId': '4' * 64, 'gitBundleSha256': '5' * 64, 'hostControlMutation': True,
    'installReceiptSha256': '6' * 64, 'legacyBroadSudoersAfterSha256': '7' * 64,
    'legacyBroadSudoersBeforeSha256': '7' * 64, 'legacyConsumerSha256': '8' * 64,
    'legacyV1SudoersSha256': '9' * 64, 'nodeRuntimeReceiptSha256': 'a' * 64,
    'releaseRoot': f'/srv/platform-infrastructure/releases/{commit}-{archive}',
    'schema': m['BOOTSTRAP_BRIDGE_RECEIPT_SCHEMA'], 'sourceArchiveAfterSha256': archive,
    'sourceArchiveBeforeSha256': None, 'stagingEnvironmentSha256': 'c' * 64,
    'stagingMutation': True, 'status': 'BOOTSTRAP_CONTROL_INSTALLED',
}
without = dict(bridge); without.pop('documentId')
bridge['documentId'] = m['digest'](m['canonical'](without).encode())
put(m['BOOTSTRAP_BRIDGE_RECEIPT_FILE'], m['canonical_bytes'](bridge), 0o400)
proven = m['latest_transport_tooling_coherence']()
put(m['RECONCILER'], b'replaced-reconciler-bytes', 0o555)
try:
    m['latest_transport_tooling_coherence']()
    drift_stopped = False
except m['Stop']:
    drift_stopped = True
print(json.dumps({'proven': proven == commit, 'driftStopped': drift_stopped}))`);
  assert.deepEqual(value, { proven: true, driftStopped: true });
});

test("superseded transport abort journal is one zero-step ABORTED transaction", () => {
  const value = jsonPython(`
import hashlib, json, os, tempfile, time
root = tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root, 0o700); os.chown(root, os.geteuid(), os.getegid())
g = m['superseded_transport_abort_journal'].__globals__; g['TEST_ROOT'] = root; g['OWNER_UID'] = os.geteuid(); g['OWNER_GID'] = os.getegid()
def put(logical, data, mode):
    p = m['physical'](logical); os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    if os.path.exists(p): os.chmod(p, 0o600)
    open(p, 'wb').write(data); os.chmod(p, mode)
authority = {'documentId': 'd' * 64, 'authorizedDataMutations': [{'id': 'mutation-one'}]}
authority_bytes = m['canonical_bytes'](authority)
began = int(time.time()) - 3600
marker = {'schema': 'platform.v1-local-private-reconciliation/v1', 'status': 'RECONCILING', 'beganAtUnixSeconds': began}
marker_bytes = m['canonical_bytes'](marker)
put(m['RECONCILIATION'], marker_bytes, 0o600)
put(m['DEPLOYMENT_ENV'], b'deployment-env-preimage-bytes', 0o600)
for index, source in enumerate(m['evidence_preimage_sources']()):
    put(source, f'preimage-{index:02d}'.encode(), 0o400 if index % 2 else 0o600)
reconciliation = {'beganAtUnixSeconds': began}
journal = m['superseded_transport_abort_journal'](authority, authority_bytes, reconciliation)
stored = json.loads(open(m['physical'](m['JOURNAL'])).read())
print(json.dumps({
  'phase': journal['phase'],
  'steps': len(journal['steps']),
  'transactionIdBound': journal['transactionId'] == hashlib.sha256(authority_bytes + marker_bytes).hexdigest(),
  'mutationsPending': journal['dataMutationStatus'] == {'mutation-one': 'PENDING'},
  'storedIdentical': m['canonical_bytes'](journal) == m['canonical_bytes'](stored),
}))`);
  assert.deepEqual(value, { phase: "ABORTED", steps: 0, transactionIdBound: true, mutationsPending: true, storedIdentical: true });
});

test("abort source keeps both closure routes and their exact guards", () => {
  const abortSource = runPython("import inspect; print(inspect.getsource(m['abort']))");
  assert.match(abortSource, /read_authority\(check_artifacts=False, check_source_archive=False\)/);
  assert.match(abortSource, /installed_artifacts_match_authority\(authority\) and installed_source_archive_matches_authority\(authority\)/);
  assert.match(abortSource, /latest_transport_tooling_coherence\(\)/);
  assert.match(abortSource, /coherent_candidate == authority\["candidateCommit"\]/);
  assert.match(abortSource, /authority_candidate_transport_complete\(authority\)/);
  assert.match(abortSource, /verify_superseded_transport_abort_preconditions\(authority, reconciliation\)/);
  assert.match(abortSource, /superseded_transport_abort_journal\(authority, authority_bytes, reconciliation\)/);
  assert.match(abortSource, /read_or_create_journal\(authority, authority_bytes, reconciliation\)/);
  assert.match(abortSource, /finalize_consumed_abort\(authority, authority_bytes\)/);
  assert.match(abortSource, /cleanup_consumed_abort_without_current_journal\(authority, authority_bytes\)/);
  const preconditions = runPython("import inspect; print(inspect.getsource(m['verify_superseded_transport_abort_preconditions']))");
  assert.match(preconditions, /previousStateSha256/);
  assert.match(preconditions, /previousReceiptSha256/);
  assert.match(preconditions, /controller_predecessor_identity_match\(record, source\[1\]\)/);
  assert.match(preconditions, /data-mutation evidence/);
  const projection = runPython("import inspect; print(inspect.getsource(m['controller_predecessor_identity_match']))");
  assert.match(projection, /RECONCILER_COMPARABLE_IDENTITY_FIELDS/);
  assert.match(projection, /set\(before\) != set\(fields\)/);
  assert.match(projection, /set\(fields\) \| \{"project"\}/);
  assert.match(projection, /for key in comparable/);
});

test("existing recovery binding reuses the active receipt binding and verifies the export bytes", () => {
  const value = jsonPython(`
import hashlib, json, os, tempfile
root = tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root, 0o700)
g = m['existing_recovery_binding'].__globals__; g['TEST_ROOT'] = root; g['OWNER_UID'] = os.geteuid(); g['OWNER_GID'] = os.getegid()
def put(logical, data, mode):
    p = m['physical'](logical); os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    if os.path.exists(p): os.chmod(p, 0o600)
    open(p, 'wb').write(data); os.chmod(p, mode); os.chown(p, os.geteuid(), os.getegid())
export_bytes = (b'export-tar-header' + b'x' * 2048)
export_sha = hashlib.sha256(export_bytes).hexdigest()
put(m['SCHEDULER_RECOVERY_EXPORT'], export_bytes, 0o444)
st = os.stat(m['physical'](m['SCHEDULER_RECOVERY_EXPORT']))
binding = {
    'archiveFormat': 'OCI_DOCKER_SAVE_V1',
    'configDigest': 'sha256:' + 'a' * 64,
    'configHash': 'b' * 64,
    'containerId': 'c' * 64,
    'exportLabels': {'com.platform.v1.local-private.candidate-commit': 'a' * 40},
    'exportPath': m['SCHEDULER_RECOVERY_EXPORT'],
    'exportSha256': export_sha,
    'exportSizeBytes': st.st_size,
    'imageIndexDigest': 'sha256:' + 'd' * 64,
    'imageIndexPath': 'blobs/sha256/' + 'd' * 64,
    'imageManifestDigest': 'sha256:' + 'e' * 64,
    'manifestConfig': 'blobs/sha256/' + 'a' * 64,
    'recoveryImageId': 'sha256:' + 'd' * 64,
    'recoveryTag': 'platform/v1-scheduler-recovery:' + 'a' * 40,
    'runningImageId': 'sha256:' + 'f' * 64,
}
trust = {'mode': 'LOCAL_DOCKER_IMMUTABLE_IMAGE_ID', 'schedulerRecovery': binding, 'status': 'PASS'}
receipt = {'localArtifactTrust': trust, 'schema': 'platform.v1-local-private-control-receipt/v1', 'status': 'ACTIVE'}
put(m['ACTIVE_RECEIPT'], m['canonical_bytes'](receipt), 0o444)
recovered = m['existing_recovery_binding']()
put(m['SCHEDULER_RECOVERY_EXPORT'], b'tampered-bytes', 0o444)
try:
    m['existing_recovery_binding']()
    drift_stopped = False
except m['Stop']:
    drift_stopped = True
print(json.dumps({'exportSha': recovered['exportSha256'] == export_sha, 'imageIdsDistinct': recovered['recoveryImageId'] != recovered['runningImageId'], 'driftStopped': drift_stopped}))`);
  assert.deepEqual(value, { exportSha: true, imageIdsDistinct: true, driftStopped: true });
});

test("validate_pre_mutation_checkpoint enforces the production contract and the receipt-bound validation lane", () => {
  const value = jsonPython(`
import copy, hashlib, json, os, tempfile, time
root_base = tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root_base, 0o700)
g = m['validate_pre_mutation_checkpoint'].__globals__; g['OWNER_UID'] = os.geteuid()
def semantic_guard(authority, documents, reconciliation_sha, transaction_id, began_at, now, evidence_phase):
    return None
g['validate_backup_evidence_bundle'] = semantic_guard
def put(logical, value, mode=0o400, raw=False):
    p = m['physical'](logical); os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    if os.path.exists(p): os.chmod(p, 0o600)
    data = value if raw else m['canonical_bytes'](value)
    with open(p, 'wb') as stream: stream.write(data)
    os.chmod(p, mode); os.chown(p, os.geteuid(), os.getegid()); return data
def scenario(kind):
    root = tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root, 0o700)
    g['TEST_ROOT'] = root; g['OWNER_GID'] = os.getegid()
    now = int(time.time()); generated = now - 5
    captured = now - 7200 if kind == 'validation' else now - 20
    commit = '1' * 40; tree = '2' * 40; archive = '3' * 64; doc = '4' * 64
    old_commit = '9' * 40
    tools = {name: {'imageId': 'sha256:' + '5' * 64, 'imageReference': 'registry.invalid/' + name + '@sha256:' + '6' * 64} for name in ('mariadbRestore', 'minioRestore', 'nodeUtility', 'postgresRestore', 'resticRclone')}
    authority = {'backupToolImages': tools, 'candidateCommit': commit, 'candidateTree': tree, 'documentId': doc, 'sourceArchiveSha256': archive}
    authority_bytes = m['canonical_bytes'](authority)
    common = {'artifactSetSha256': '7' * 64, 'authorityDocumentId': doc,
              'authoritySha256': m['digest'](authority_bytes), 'backupSetSha256': '8' * 64, 'backupToolImages': tools,
              'candidateCommit': commit, 'candidateTree': tree, 'evidencePhase': 'PRE', 'reconciliationSha256': None,
              'runId': '20260824T120000Z-abcdef12', 'sourceArchiveSha256': archive, 'transactionId': None}
    rows = [{'logicalKey': key} for key in m['EVIDENCE_LOGICAL_KEYS']]
    logical = {**common, 'artifactCount': 14, 'artifactManifestSha256': '9' * 64, 'artifacts': copy.deepcopy(rows), 'backupCompletedUnixSeconds': captured,
               'capturedAtUnixSeconds': captured, 'checksumVerifiedCount': 14, 'freshArtifactStreamHashCount': 14,
               'generatedAtUnixSeconds': generated, 'hmacVerifiedCount': 14, 'schema': 'platform.v1-local-private-logical-backup-evidence/v1',
               'sourceSummarySha256': 'a' * 64, 'status': 'PASS', 'totalArtifactBytes': 14}
    offhost = {**common, 'artifactCount': 14, 'completedAtUnixSeconds': generated - 1, 'distinctSnapshotCount': 14,
               'exactPayloadReadbackCount': 14, 'freshExactSnapshotCount': 14, 'generatedAtUnixSeconds': generated, 'hostingerUsed': False,
               'noPrune': True, 'offsiteProofSha256': 'b' * 64, 'proofs': copy.deepcopy(rows), 'recoveryEscrow': {},
               'repository': 'rclone:platform-onedrive:platform-infrastructure/restic', 'repositoryProvider': 'OneDrive', 'retentionSkipped': True,
               'schema': 'platform.v1-local-private-offhost-backup-evidence/v1', 'sourceSummarySha256': 'a' * 64, 'status': 'PASS'}
    restore = {**common, 'artifactCount': 14, 'completedAtUnixSeconds': generated - 1, 'expectedRestoreCount': 14,
               'generatedAtUnixSeconds': generated, 'localRestoreResultsSha256': 'c' * 64, 'passedRestoreCount': 14, 'results': copy.deepcopy(rows),
               'schema': 'platform.v1-local-private-restore-evidence/v1', 'sourceSummarySha256': 'a' * 64, 'status': 'PASS'}
    secret = {**common, 'backupCompletedUnixSeconds': captured, 'capturedAtUnixSeconds': captured, 'encryptedArtifact': {},
              'generatedAtUnixSeconds': generated, 'plaintextTemporaryStateAbsent': True, 'recoveryEscrow': {},
              'schema': 'platform.v1-local-private-secrets-backup-evidence/v1', 'secretBindingInventory': {}, 'secretRestore': {},
              'secretValuesRecorded': False, 'sourceSummarySha256': 'a' * 64, 'status': 'PASS'}
    export_data = b'x' * 2048; put(m['SCHEDULER_RECOVERY_EXPORT'], export_data, raw=True)
    export_snapshot = m['stable_recovery_export_snapshot'](); recovery_id = 'sha256:' + 'd' * 64; running_id = 'sha256:' + 'e' * 64
    runtime = {**common, 'capturedAtUnixSeconds': generated, 'containerCount': 36, 'containerIdentitySetSha256': 'f' * 64,
               'generatedAtUnixSeconds': generated, 'recovery': {'exportSha256': export_snapshot['sha256'], 'recoveryImageId': recovery_id,
               'runningImageId': running_id}, 'schema': 'platform.v1-local-private-runtime-inventory-evidence/v1', 'status': 'PASS',
               'volumeCount': 1, 'volumeSetSha256': '1' * 64}
    documents = {'logicalBackupEvidenceSha256': logical, 'offHostBackupEvidenceSha256': offhost,
                 'restoreEvidenceSha256': restore, 'runtimeInventorySha256': runtime, 'secretsBackupEvidenceSha256': secret}
    digests = {key: m['digest'](put(m['CHECKPOINT_EVIDENCE_PATHS'][key], document)) for key, document in documents.items()}
    if kind in ('validation', 'validation_no_receipt'):
        checkpoint = {'authoritative': False, 'backupCapturedUnixSeconds': captured, 'candidateCommit': commit, 'candidateTree': tree,
                      'destructiveMutationPlanned': False, 'generatedAtUnixSeconds': generated, **digests, 'restoreVerified': False, 'runtimeRecovered': False,
                      'schedulerRecoveryImageExportSha256': export_snapshot['sha256'], 'schedulerRecoveryImageId': recovery_id,
                      'schedulerRunningImageId': running_id, 'schema': m['VALIDATION_CHECKPOINT_SCHEMA'], 'sourceArchiveSha256': archive, 'validation': True}
        checkpoint_bytes = put(m['VALIDATION_CHECKPOINT_FILE'], checkpoint)
    else:
        checkpoint = {'authoritative': False, 'backupCapturedUnixSeconds': captured, 'candidateCommit': commit, 'candidateTree': tree,
                      'destructiveMutationPlanned': False, 'generatedAtUnixSeconds': generated, **digests, 'restoreVerified': True, 'runtimeRecovered': True,
                      'schedulerRecoveryImageExportSha256': export_snapshot['sha256'], 'schedulerRecoveryImageId': recovery_id,
                      'schedulerRunningImageId': running_id, 'schema': 'platform.v1-local-private-predeploy-checkpoint/v1', 'sourceArchiveSha256': archive}
        checkpoint_bytes = put(m['LOCAL_CHECKPOINT'], checkpoint)
    tag_candidate = old_commit if kind in ('validation', 'production_old_tag') else commit
    labels = {'com.platform.v1.local-private.candidate-commit': tag_candidate,
              'com.platform.v1.local-private.scheduler-config-hash': '2' * 64,
              'com.platform.v1.local-private.scheduler-container-id': '3' * 64,
              'com.platform.v1.local-private.scheduler-running-image-id': running_id}
    config = 'sha256:' + '4' * 64
    recovery = {'archiveFormat': 'OCI_DOCKER_SAVE_V1', 'configDigest': config, 'configHash': '2' * 64, 'containerId': '3' * 64,
                'exportIdentity': export_snapshot['identity'], 'exportLabels': labels, 'exportPath': m['SCHEDULER_RECOVERY_EXPORT'],
                'exportSha256': export_snapshot['sha256'], 'exportSizeBytes': export_snapshot['sizeBytes'], 'imageIndexDigest': recovery_id,
                'imageIndexPath': 'blobs/sha256/' + recovery_id.removeprefix('sha256:'), 'imageManifestDigest': 'sha256:' + '5' * 64,
                'manifestConfig': 'blobs/sha256/' + config.removeprefix('sha256:'), 'recoveryImageId': recovery_id,
                'recoveryTag': 'platform/v1-scheduler-recovery:' + tag_candidate, 'runningImageId': running_id}
    reconciliation = {'rollbackCheckpointSha256': m['digest'](checkpoint_bytes), 'rollbackSchedulerRecovery': recovery,
                      'rollbackSchedulerRecoverySha256': m['digest'](m['canonical'](recovery).encode())}
    if kind == 'validation':
        receipt = {'localArtifactTrust': {'mode': 'LOCAL_DOCKER_IMMUTABLE_IMAGE_ID', 'status': 'PASS',
                  'schedulerRecovery': dict(recovery, containerName='enterprise-backup-scheduler', status='RECOVERY_IMAGE_EXPORT_BOUND')},
                  'schema': 'platform.v1-local-private-control-receipt/v1', 'status': 'ACTIVE'}
        put(m['ACTIVE_RECEIPT'], receipt, 0o444)
        lane = {'candidateCommit': commit, 'createdAtUnixSeconds': now - 60, 'expiresAtUnixSeconds': now + 72000,
                'reason': 'validation lane fixture', 'schema': m['VALIDATION_LANE_SCHEMA']}
        put(m['VALIDATION_LANE_FILE'], lane, 0o400)
    if kind == 'validation_no_receipt':
        receipt = {'localArtifactTrust': {'mode': 'LOCAL_DOCKER_IMMUTABLE_IMAGE_ID', 'status': 'PASS',
                  'schedulerRecovery': dict(recovery, exportSha256='sha256:' + '8' * 64, recoveryImageId='sha256:' + '8' * 64,
                  recoveryTag='platform/v1-scheduler-recovery:' + old_commit, containerName='enterprise-backup-scheduler', status='RECOVERY_IMAGE_EXPORT_BOUND')},
                  'schema': 'platform.v1-local-private-control-receipt/v1', 'status': 'ACTIVE'}
        put(m['ACTIVE_RECEIPT'], receipt, 0o444)
        lane = {'candidateCommit': commit, 'createdAtUnixSeconds': now - 60, 'expiresAtUnixSeconds': now + 72000,
                'reason': 'validation lane fixture', 'schema': m['VALIDATION_LANE_SCHEMA']}
        put(m['VALIDATION_LANE_FILE'], lane, 0o400)
    try:
        m['validate_pre_mutation_checkpoint'](authority, authority_bytes, reconciliation); return True
    except m['Stop']: return False
results = {kind: scenario(kind) for kind in ('production', 'production_old_tag', 'validation', 'validation_no_receipt')}
print(json.dumps(results))`);
  assert.deepEqual(value, { production: true, production_old_tag: false, validation: true, validation_no_receipt: false });
});
