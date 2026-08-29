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
authority = {'candidateCommit': '1' * 40, 'documentId': 'd' * 64, 'authorizedDataMutations': [{'id': 'mutation-one'}]}
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
historical_live = {
    name: dict(item, runtimeConfigSha256='7' * 64, semanticSha256='8' * 64)
    for name, item in live_by_name.items()
}
g['inspect_one'] = lambda name: ({'Id': historical_live[name]['containerId']}, historical_live[name])
historical_authority = dict(authority, candidateCommit=m['HISTORICAL_CONTROLLER_DIGEST_DIVERGENCE_CANDIDATES'][0])
m['verify_superseded_transport_abort_preconditions'](historical_authority, reconciliation)
try:
    m['verify_superseded_transport_abort_preconditions'](authority, reconciliation)
    unregistered_stopped = False
except m['Stop']:
    unregistered_stopped = True
g['inspect_one'] = lambda name: ({'Id': live_by_name[name]['containerId']}, live_by_name[name])
put(f"{m['MUTATION_EVIDENCE_DIR']}/{authority['documentId']}-mutation-one-{'e' * 64}.json", b'{}', 0o444)
try:
    m['verify_superseded_transport_abort_preconditions'](authority, reconciliation)
    evidence_stopped = False
except m['Stop']:
    evidence_stopped = True
print(json.dumps({'preconditionsPass': True, 'driftStopped': drift_stopped, 'evidenceStopped': evidence_stopped,
 'historicalPass': True, 'unregisteredStopped': unregistered_stopped}))`);
  assert.deepEqual(value, { driftStopped: true, evidenceStopped: true, historicalPass: true, preconditionsPass: true, unregisteredStopped: true });
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
signed = {
    'candidateCommit': commit, 'candidateTree': tree, 'checkpointSha256': bridge['checkpointAfterSha256'],
    'createdAtUnixSeconds': 1800000000,
    'greenfieldPreimagePath': '/home/platform_infrastructure/greenfield-live/render/preimage/greenfield-deployment.env',
    'greenfieldPreimageSha256': bridge['stagingEnvironmentSha256'],
    'greenfieldProvenancePath': '/home/platform_infrastructure/greenfield-live/render/preimage/preimage-provenance.json',
    'greenfieldProvenanceReleaseCommit': 'd' * 40, 'greenfieldProvenanceSha256': 'd' * 64,
    'priorCandidateCommit': 'd' * 40, 'priorCandidateTree': 'e' * 40,
    'priorCheckpointAfterSha256': 'e' * 64, 'priorReceiptDocumentId': 'f' * 64,
    'priorStagingEnvironmentSha256': bridge['stagingEnvironmentSha256'],
    'reasonCode': m['BOOTSTRAP_SUCCESSOR_SANCTION_REASON'],
    'runtimeActiveReceiptSha256': '1' * 64, 'runtimeAuthorityDocumentId': '2' * 64,
    'runtimeAuthoritySha256': '3' * 64, 'runtimeCandidateCommit': 'f' * 40,
    'runtimeCandidateTree': '1' * 40, 'runtimeSourceArchiveSha256': '4' * 64,
    'schema': m['BOOTSTRAP_SUCCESSOR_SANCTION_SCHEMA'],
    'signatureBase64': 'c2ln', 'sourceArchiveSha256': archive,
}
bridge['transportSanction'] = {
    **signed, 'present': True, 'sanctionDigest': sha(m['canonical_bytes'](signed)),
    'signerCertSha256': m['BOOTSTRAP_SANCTION_TRUST_CERT_SHA256'],
}
without = dict(bridge); without.pop('documentId'); bridge['documentId'] = m['digest'](m['canonical'](without).encode())
put(m['BOOTSTRAP_BRIDGE_RECEIPT_FILE'], m['canonical_bytes'](bridge), 0o400)
successor_proven = m['latest_transport_tooling_coherence']()
bridge['transportSanction']['unexpected'] = True
without = dict(bridge); without.pop('documentId'); bridge['documentId'] = m['digest'](m['canonical'](without).encode())
put(m['BOOTSTRAP_BRIDGE_RECEIPT_FILE'], m['canonical_bytes'](bridge), 0o400)
try:
    m['latest_transport_tooling_coherence']()
    successor_extra_stopped = False
except m['Stop']:
    successor_extra_stopped = True
del bridge['transportSanction']['unexpected']
without = dict(bridge); without.pop('documentId'); bridge['documentId'] = m['digest'](m['canonical'](without).encode())
put(m['BOOTSTRAP_BRIDGE_RECEIPT_FILE'], m['canonical_bytes'](bridge), 0o400)
put(m['RECONCILER'], b'replaced-reconciler-bytes', 0o555)
try:
    m['latest_transport_tooling_coherence']()
    drift_stopped = False
except m['Stop']:
    drift_stopped = True
print(json.dumps({'proven': proven == commit, 'successorProven': successor_proven == commit,
 'successorExtraStopped': successor_extra_stopped, 'driftStopped': drift_stopped}))`);
  assert.deepEqual(value, { proven: true, successorProven: true, successorExtraStopped: true, driftStopped: true });
});

test("superseded transport abort journal is one zero-step ABORTED transaction", () => {
  const value = jsonPython(`
import hashlib, json, os, tempfile, time
root = tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root, 0o700); os.chown(root, os.geteuid(), os.getegid())
g = m['superseded_transport_abort_journal'].__globals__; g['TEST_ROOT'] = root; g['OWNER_UID'] = os.geteuid(); g['OWNER_GID'] = os.getegid()
def put(logical, data, mode, raw=False):
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
    put(source, f'preimage-{index:02d}'.encode(), 0o400 if index % 2 else 0o600, raw=True)
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
  const superseded = abortSource.indexOf("superseded_transport_abort_journal(authority, authority_bytes, reconciliation)");
  const restoreDeployment = abortSource.indexOf("restore_deployment_config_preimage(journal)", superseded);
  const restoreEvidence = abortSource.indexOf("restore_evidence_preimages(journal)", restoreDeployment);
  const abortRecord = abortSource.indexOf("materialize_abort_record(authority, authority_bytes, journal)", restoreEvidence);
  assert.ok(superseded >= 0 && superseded < restoreDeployment && restoreDeployment < restoreEvidence && restoreEvidence < abortRecord);
  assert.match(abortSource, /read_or_create_journal\(authority, authority_bytes, reconciliation\)/);
  assert.match(abortSource, /finalize_consumed_abort\(authority, authority_bytes\)/);
  assert.match(abortSource, /cleanup_consumed_abort_without_current_journal\(authority, authority_bytes\)/);
  const preconditions = runPython("import inspect; print(inspect.getsource(m['verify_predecessor_state_receipt_unchanged'])+inspect.getsource(m['verify_superseded_transport_abort_preconditions']))");
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
    old_commit = '9' * 40; old_tree = '8' * 40; old_archive = '7' * 64; old_doc = '6' * 64
    tools = {name: {'imageId': 'sha256:' + '5' * 64, 'imageReference': 'registry.invalid/' + name + '@sha256:' + '6' * 64} for name in ('mariadbRestore', 'minioRestore', 'nodeUtility', 'postgresRestore', 'resticRclone')}
    authority = {'backupToolImages': tools, 'candidateCommit': commit, 'candidateTree': tree, 'documentId': doc, 'sourceArchiveSha256': archive}
    authority_bytes = m['canonical_bytes'](authority)
    validation_kind = kind in ('validation', 'validation_no_receipt')
    old_authority = {'backupToolImages': tools, 'candidateCommit': old_commit, 'candidateTree': old_tree,
                     'documentId': old_doc, 'sourceArchiveSha256': old_archive}
    old_authority_bytes = m['canonical_bytes'](old_authority)
    g['read_archived_authority'] = lambda document_id, expected_sha: (old_authority, old_authority_bytes)
    g['verify_predecessor_state_receipt_unchanged'] = lambda reconciliation: None
    common = {'artifactSetSha256': '7' * 64, 'authorityDocumentId': old_doc if validation_kind else doc,
              'authoritySha256': m['digest'](old_authority_bytes) if validation_kind else m['digest'](authority_bytes),
              'backupSetSha256': '8' * 64, 'backupToolImages': tools,
              'candidateCommit': old_commit if validation_kind else commit,
              'candidateTree': old_tree if validation_kind else tree, 'evidencePhase': 'PRE', 'reconciliationSha256': None,
              'runId': '20260824T120000Z-abcdef12',
              'sourceArchiveSha256': old_archive if validation_kind else archive, 'transactionId': None}
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
        predecessor_checkpoint = {'authoritative': False, 'backupCapturedUnixSeconds': captured,
                      'candidateCommit': old_commit, 'candidateTree': old_tree,
                      'destructiveMutationPlanned': False, 'generatedAtUnixSeconds': generated, **digests,
                      'restoreVerified': True, 'runtimeRecovered': True,
                      'schedulerRecoveryImageExportSha256': export_snapshot['sha256'],
                      'schedulerRecoveryImageId': recovery_id, 'schedulerRunningImageId': running_id,
                      'schema': 'platform.v1-local-private-predeploy-checkpoint/v1',
                      'sourceArchiveSha256': old_archive}
        predecessor_checkpoint_bytes = put(m['LOCAL_CHECKPOINT'], predecessor_checkpoint)
        checkpoint = {'authoritative': False, 'backupCapturedUnixSeconds': captured, 'candidateCommit': commit, 'candidateTree': tree,
                      'destructiveMutationPlanned': False, 'generatedAtUnixSeconds': generated, **digests, 'restoreVerified': False, 'runtimeRecovered': False,
                      'predecessorAuthorityDocumentId': old_doc, 'predecessorAuthoritySha256': m['digest'](old_authority_bytes),
                      'predecessorCandidateCommit': old_commit, 'predecessorCandidateTree': old_tree,
                      'predecessorCheckpointSha256': m['digest'](predecessor_checkpoint_bytes),
                      'predecessorReceiptSha256': 'a' * 64, 'predecessorSourceArchiveSha256': old_archive,
                      'predecessorStateSha256': 'b' * 64,
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
    reconciliation = {'previousReceiptSha256': 'a' * 64, 'previousStateSha256': 'b' * 64,
                      'rollbackCheckpointSha256': m['digest'](checkpoint_bytes), 'rollbackSchedulerRecovery': recovery,
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

test("rollback comparisons separate the controller projection from the SHA-bound native identity", () => {
  const value = jsonPython(`
import json, os, tempfile
root = tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root, 0o700)
g = m['load_rollback_spec'].__globals__; g['TEST_ROOT'] = root; g['OWNER_UID'] = os.geteuid(); g['OWNER_GID'] = os.getegid()
def put(logical, value, mode=0o600, raw=False):
    p = m['physical'](logical); os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    if os.path.exists(p): os.chmod(p, 0o600)
    data = value if raw else m['canonical_bytes'](value)
    with open(p, 'wb') as stream: stream.write(data)
    os.chmod(p, mode); os.chown(p, os.geteuid(), os.getegid()); return data
runtime_labels = {name: value for name, value in zip(sorted(m['RUNTIME_IDENTITY_LABEL_BY_ENV'].values()), ('a', 'b', 'c', 'd', 'e', 'f'))}
config_hash = '7' * 64; identifier = '8' * 64; image = 'sha256:' + '9' * 64; name = 'enterprise-control-center'
inspect = {
 'Id': identifier, 'Image': image, 'Name': '/' + name, 'Mounts': [],
 'Config': {'Cmd': None, 'Entrypoint': None, 'Env': [], 'Healthcheck': None, 'Image': 'registry.invalid/control@' + image,
  'Labels': {**runtime_labels, 'com.docker.compose.config-hash': config_hash, 'com.docker.compose.project': 'platform_infra_vps',
   'traefik.enable': 'false', 'com.docker.compose.service': 'control-center'}, 'User': '', 'WorkingDir': '/app'},
 'HostConfig': {'BlkioWeight': 700, 'CapAdd': None, 'CapDrop': None, 'CpuShares': 1024, 'ExtraHosts': ['auth.local:host-gateway'],
  'GroupAdd': ['100'], 'Init': True, 'Memory': 536870912, 'MemoryReservation': 134217728, 'NanoCpus': 1000000000,
  'LogConfig': {'Type': 'json-file', 'Config': {'max-file': '5', 'max-size': '10m'}},
  'NetworkMode': 'platform_infra_vps_platform_routing', 'PidMode': '', 'PidsLimit': 384, 'PortBindings': {}, 'Privileged': False,
  'ReadonlyRootfs': True, 'RestartPolicy': {'Name': 'always'}, 'SecurityOpt': ['no-new-privileges:true'],
  'Tmpfs': {'/tmp': 'rw,noexec,nosuid,nodev,size=67108864'}, 'Ulimits': [{'Name': 'nofile', 'Soft': 16384, 'Hard': 16384}]},
 'NetworkSettings': {'Networks': {'platform_infra_vps_platform_routing': {'Aliases': [name, identifier[:12]]}}, 'Ports': {}},
 'State': {'ExitCode': 0, 'Health': {'Status': 'healthy'}, 'Status': 'running'},
}
live = m['container_identity'](inspect)
recorded_fields = ("configHash", "containerId", "exitCode", "health", "imageId", "imageReference",
                   "name", "networkMembership", "runtimeConfigSha256", "semanticSha256", "service", "state")
before = {field: live[field] for field in recorded_fields}
# The current controller and reconciler share the full semantic contract.  The
# native rollback baseline still comes from the SHA-bound inspect bytes so the
# reconciler-only project field is never invented from the controller record.
transaction_id = 'a' * 64
spec = {'containerInspect': inspect, 'predecessorIdentity': before, 'schema': m['ROLLBACK_SPEC_SCHEMA'], 'transactionId': transaction_id}
spec_path = m['ROLLBACK_SPEC_DIR'] + '/' + transaction_id + '/enterprise-control-center.json'
put(spec_path, spec)
journal = {'transactionId': transaction_id}
step = {'before': before, 'rollbackSpecPath': spec_path, 'rollbackSpecSha256': m['digest'](m['canonical_bytes'](spec))}
loaded = m['load_rollback_spec'](step, journal)
native = m['rollback_native_identity'](step, journal)
backup = dict(native, name='v1-rollback-' + name, state='exited', health='none')
backup_fields = ('configHash', 'containerId', 'imageId', 'imageReference', 'project',
                 'runtimeConfigSha256', 'semanticSha256', 'service')
def changed(value):
    if isinstance(value, list): return []
    if isinstance(value, int): return value + 1
    return str(value) + '-drift'
backup_drift_stopped = all(
    not m['backup_matches'](dict(backup, **{field: changed(backup[field])}), step, journal)
    for field in backup_fields
)
backup_shape_stopped = (
    not m['backup_matches'](dict(backup, unexpected='x'), step, journal)
    and not m['backup_matches']({key: value for key, value in backup.items() if key != 'project'}, step, journal)
)
recreated = dict(native, containerId='e' * 64)
recreated_drift_stopped = all(
    not m['recreated_identity_matches'](dict(recreated, **{field: changed(recreated[field])}), step, journal)
    for field in native if field != 'containerId'
)
recreated_shape_stopped = (
    not m['recreated_identity_matches'](dict(recreated, unexpected='x'), step, journal)
    and not m['recreated_identity_matches']({key: value for key, value in recreated.items() if key != 'project'}, step, journal)
)
drifted_inspect = dict(inspect); drifted_inspect['Id'] = 'c' * 64
drifted_spec = dict(spec, containerInspect=drifted_inspect)
put(spec_path, drifted_spec)
try:
    m['rollback_native_identity'](step, journal)
    hash_drift_stopped = False
except m['Stop']:
    hash_drift_stopped = True
step['rollbackSpecSha256'] = m['digest'](m['canonical_bytes'](drifted_spec))
try:
    m['load_rollback_spec'](step, journal)
    projection_drift_stopped = False
except m['Stop']:
    projection_drift_stopped = True
put(spec_path, spec)
step['rollbackSpecSha256'] = m['digest'](m['canonical_bytes'](spec))
backup_name = 'v1-rollback-' + name
flow_step = {
    'backupName': backup_name, 'before': before, 'containerName': name,
    'rollbackSpecPath': spec_path, 'rollbackSpecSha256': step['rollbackSpecSha256'],
    'status': 'PENDING',
}
flow = {'renamed': False, 'stopped': False}
def flow_inspect(container_name, missing_ok=False):
    if container_name == name:
        return None if flow['renamed'] else (inspect, native)
    if container_name == backup_name:
        if not flow['renamed']:
            return None
        state = 'exited' if flow['stopped'] else native['state']
        health = 'none' if flow['stopped'] else native['health']
        return inspect, dict(native, name=backup_name, state=state, health=health)
    raise AssertionError(container_name)
commands = []
def flow_run(command, label, **kwargs):
    commands.append(command[1])
    if command[1] == 'rename': flow['renamed'] = True
    if command[1] == 'stop': flow['stopped'] = True
    return b''
g['inspect_one'] = flow_inspect
g['docker_binary'] = lambda: '/usr/bin/docker'
g['run'] = flow_run
g['save_journal'] = lambda value: None
m['backup_source'](flow_step, {'transactionId': transaction_id})
live_drift = dict(live, containerId='e' * 64)
semantic_drift = dict(live, semanticSha256='d' * 64, runtimeConfigSha256='d' * 64, project='other_project')
network_drift = dict(live, networkMembership=[])
print(json.dumps({
  'loaded': loaded['predecessorIdentity'] == before,
  'controllerFieldCount': len(before),
  'nativeFieldCount': len(native),
  'nativeFromBoundInspect': native == live,
  'backupMatches': m['backup_matches'](backup, step, journal),
  'backupDriftStopped': backup_drift_stopped,
  'backupShapeStopped': backup_shape_stopped,
  'recreatedMatches': m['recreated_identity_matches'](recreated, step, journal),
  'recreatedDriftStopped': recreated_drift_stopped,
  'recreatedShapeStopped': recreated_shape_stopped,
  'hashDriftStopped': hash_drift_stopped,
  'projectionDriftStopped': projection_drift_stopped,
  'backupFlowStatus': flow_step['status'],
  'backupFlowCommands': commands,
  'identityProjectionStopsSemanticDrift': not m['identity_matches_predecessor'](semantic_drift, before),
  'identityProjectionStopsRealDrift': not m['identity_matches_predecessor'](live_drift, before),
  'identityProjectionStopsNetworkDrift': not m['identity_matches_predecessor'](network_drift, before),
  'networkChangeRequiresExplicitContext': m['identity_matches_predecessor'](network_drift, before, allow_network_change=True),
}))`);
  assert.deepEqual(value, {
    loaded: true,
    controllerFieldCount: 12,
    nativeFieldCount: 13,
    nativeFromBoundInspect: true,
    backupMatches: true,
    backupDriftStopped: true,
    backupShapeStopped: true,
    recreatedMatches: true,
    recreatedDriftStopped: true,
    recreatedShapeStopped: true,
    hashDriftStopped: true,
    projectionDriftStopped: true,
    backupFlowStatus: "BACKED_UP",
    backupFlowCommands: ["rename", "stop"],
    identityProjectionStopsSemanticDrift: true,
    identityProjectionStopsRealDrift: true,
    identityProjectionStopsNetworkDrift: true,
    networkChangeRequiresExplicitContext: true,
  });
});

test("RETAINED resume reuses the cross-module predecessor predicate", () => {
  const recorded = seedRecordedIdentities()[0];
  const value = jsonPython(`
import json
before = json.loads(${JSON.stringify(JSON.stringify(recorded))})
live = dict(before, project='platform_infra_vps')
g = m['apply_service_step'].__globals__
g['wait_for_target'] = lambda name, target: live
saved = []
g['save_journal'] = lambda journal: saved.append(dict(journal))
step = {'after': None, 'before': before, 'containerName': before['name'], 'status': 'RETAINED'}
journal = {'steps': [step]}
m['apply_service_step'](step, {}, {}, journal)
accepted = step['after'] == live and len(saved) == 1
drifted = dict(live, containerId='c' * 64)
g['wait_for_target'] = lambda name, target: drifted
step = {'after': None, 'before': before, 'containerName': before['name'], 'status': 'RETAINED'}
try:
    m['apply_service_step'](step, {}, {}, {'steps': [step]})
    drift_stopped = False
except m['Stop']:
    drift_stopped = True
print(json.dumps({'accepted': accepted, 'driftStopped': drift_stopped, 'rawShapesDiffer': live != before}))`);
  assert.deepEqual(value, { accepted: true, driftStopped: true, rawShapesDiffer: true });
});

test("abort final inventory routes recreated predecessors through their bound journal step", () => {
  const recorded = seedRecordedIdentities()[0];
  const value = jsonPython(`
import json, os, tempfile
root = tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root, 0o700)
g = m['abort'].__globals__; g['TEST_ROOT'] = root; g['OWNER_UID'] = os.geteuid(); g['OWNER_GID'] = os.stat(root).st_gid
for logical in (m['RECONCILIATION'], m['JOURNAL']):
    pathname = m['physical'](logical); os.makedirs(os.path.dirname(pathname), mode=0o700, exist_ok=True); open(pathname, 'wb').write(b'present')
before = json.loads(${JSON.stringify(JSON.stringify(recorded))})
authority = {'candidateCommit': '1' * 40, 'documentId': 'd' * 64}
authority_bytes = b'authority-bytes'
reconciliation = {'predecessorRuntimeIdentities': [before]}
step = {'before': before, 'kind': 'SERVICE', 'restoredByRecreate': True, 'status': 'ABORTING'}
journal = {'dataMutationStatus': {}, 'phase': 'ABORTING', 'steps': [step], 'transactionId': 'a' * 64}
with open(m['physical'](m['JOURNAL']), 'wb') as stream: stream.write(m['canonical_bytes'](journal))
os.chmod(m['physical'](m['JOURNAL']), 0o600)
g['read_authority'] = lambda **kwargs: (authority, authority_bytes)
g['validate_authority_material'] = lambda value: {}
g['installed_artifacts_match_authority'] = lambda value: True
g['installed_source_archive_matches_authority'] = lambda value: True
g['read_reconciliation'] = lambda value, data: reconciliation
g['configure_secret_identity_readonly'] = lambda: None
g['read_or_create_journal'] = lambda value, data, marker: journal
g['restore_predecessor_step'] = lambda value, transaction: value.update(status='ABORTED')
g['inventory'] = lambda: ([{'name': before['name']}], {})
calls = []
def recreated(actual, bound_step, bound_journal):
    calls.append({'sameStep': bound_step is step, 'sameJournal': bound_journal is journal})
    return True
g['recreated_identity_matches'] = recreated
g['restore_deployment_config_preimage'] = lambda value: None
g['restore_evidence_preimages'] = lambda value: None
g['save_journal'] = lambda value: None
g['materialize_abort_record'] = lambda value, data, transaction: ({'status': 'ABORTED_NO_DATA_MUTATION'}, b'record', '/archive')
result = m['abort']()
print(json.dumps({'calls': calls, 'journalPhase': journal['phase'], 'status': result['status']}))`);
  assert.deepEqual(value, {
    calls: [{ sameStep: true, sameJournal: true }],
    journalPhase: "ABORTED",
    status: "ABORTED_NO_DATA_MUTATION",
  });
});

test("superseding-transport abort verifies an existing journal proves apply never mutated", () => {
  const value = jsonPython(`
import json, os, tempfile
root = tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root, 0o700); os.chown(root, os.geteuid(), os.getegid())
g = m['superseded_transport_abort_journal'].__globals__; g['TEST_ROOT'] = root; g['OWNER_UID'] = os.geteuid(); g['OWNER_GID'] = os.getegid()
def put(logical, value, mode=0o600, raw=False):
    p = m['physical'](logical); os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    if os.path.exists(p): os.chmod(p, 0o600)
    data = value if raw else m['canonical_bytes'](value)
    with open(p, 'wb') as stream: stream.write(data)
    os.chmod(p, mode); os.chown(p, os.geteuid(), os.getegid()); return data
def sha(value): return m['digest'](value.encode())
def identity(name, service):
    return {
      'configHash': sha('config-' + name), 'containerId': sha('container-' + name),
      'exitCode': 0, 'health': 'healthy', 'imageId': 'sha256:' + sha('image-' + name),
      'imageReference': 'fixture/' + name + '@sha256:' + sha('manifest-' + name),
      'name': name, 'networkMembership': [{'aliases': [name], 'networkName': 'enterprise_net'}],
      'runtimeConfigSha256': sha('runtime-' + name), 'semanticSha256': sha('semantic-' + name),
      'service': service, 'state': 'running',
    }
predecessors = [identity(name, m['ACTIVE_SERVICE_BY_CONTAINER'][name]) for name in m['ACTIVE_MANAGED']]
scheduler = identity('enterprise-backup-scheduler', 'backup-scheduler'); predecessors.append(scheduler)
targets = [{
  'configHash': sha('target-config-' + name), 'containerName': name,
  'project': m['PROJECT_BY_NAME'][name],
  'semantic': {'imageId': 'sha256:' + sha('target-image-' + name),
               'imageReference': 'fixture/target-' + name + '@sha256:' + sha('target-manifest-' + name)},
  'service': m['ACTIVE_SERVICE_BY_CONTAINER'][name],
} for name in m['ACTIVE_MANAGED']]
authority = {'documentId': 'd' * 64, 'authorizedDataMutations': [{'id': 'mutation-one'}],
             'legacyNetworkAttachments': [], 'serviceTargets': targets}
authority_bytes = m['canonical_bytes'](authority)
marker = {'schema': 'platform.v1-local-private-reconciliation/v1', 'status': 'RECONCILING', 'beganAtUnixSeconds': 1787000000}
marker_bytes = put(m['RECONCILIATION'], marker)
transaction_id = m['digest'](authority_bytes + marker_bytes)
steps = []
legacy_live = {}
for name in m['ACTIVE_MANAGED']:
    before = next(item for item in predecessors if item['name'] == name)
    rollback_path = f"{m['ROLLBACK_SPEC_DIR']}/{transaction_id}/{name}.json"
    legacy_live[name] = {**before, 'project': m['PROJECT_BY_NAME'][name],
                         'runtimeConfigSha256': sha('legacy-live-runtime-' + name),
                         'semanticSha256': sha('legacy-live-semantic-' + name)}
    rollback = {'containerInspect': {'fixtureName': name}, 'predecessorIdentity': before,
                'schema': m['ROLLBACK_SPEC_SCHEMA'], 'transactionId': transaction_id}
    rollback_bytes = put(rollback_path, rollback)
    steps.append({
      'after': None, 'backupName': f"v1-rollback-{transaction_id[:12]}-{name}", 'before': before,
      'containerName': name, 'kind': 'SERVICE', 'restoredByRecreate': False,
      'rollbackSpecPath': rollback_path,
      'rollbackSpecSha256': m['digest'](rollback_bytes), 'service': before['service'], 'status': 'PENDING',
    })
rollback_path = f"{m['ROLLBACK_SPEC_DIR']}/{transaction_id}/{scheduler['name']}.json"
legacy_live[scheduler['name']] = {**scheduler, 'project': 'platform_infra_vps',
                                  'runtimeConfigSha256': sha('legacy-live-runtime-' + scheduler['name']),
                                  'semanticSha256': sha('legacy-live-semantic-' + scheduler['name'])}
rollback = {'containerInspect': {'fixtureName': scheduler['name']}, 'predecessorIdentity': scheduler,
            'schema': m['ROLLBACK_SPEC_SCHEMA'], 'transactionId': transaction_id}
rollback_bytes = put(rollback_path, rollback)
steps.append({
  'after': None, 'backupName': f"v1-rollback-{transaction_id[:12]}-{scheduler['name']}", 'before': scheduler,
  'containerName': scheduler['name'], 'kind': 'REMOVE', 'restoredByRecreate': False,
  'rollbackSpecPath': rollback_path,
  'rollbackSpecSha256': m['digest'](rollback_bytes), 'service': scheduler['service'], 'status': 'PENDING',
})
put(m['DEPLOYMENT_ENV'], b'deployment-env-preimage-bytes', 0o600, raw=True)
for index, source in enumerate(m['evidence_preimage_sources']()):
    put(source, f'preimage-{index:02d}'.encode(), 0o400 if index % 2 else 0o600, raw=True)
deployment_preimage = m['materialize_deployment_config_preimage'](transaction_id)
evidence_preimages = m['materialize_evidence_preimages'](transaction_id)
executed = {'authorityDocumentId': authority['documentId'], 'authoritySha256': m['digest'](authority_bytes),
  'beganAtUnixSeconds': 1787000000, 'createdAtUnixSeconds': 1787000060, 'dataMutationEvidence': [],
  'dataMutationStatus': {'mutation-one': 'PENDING'}, 'deploymentConfigPreimage': deployment_preimage,
  'evidencePreimages': evidence_preimages,
  'phase': 'APPLYING', 'reconciliationSha256': m['digest'](marker_bytes), 'schema': m['JOURNAL_SCHEMA'],
  'steps': steps,
  'transactionId': transaction_id, 'updatedAtUnixSeconds': 1787000060}
put(m['JOURNAL'], executed)
reconciliation = {'beganAtUnixSeconds': 1787000000, 'plannedLegacyNetworkAttachments': [],
                  'predecessorRuntimeIdentities': predecessors}
g['container_identity'] = lambda raw: legacy_live[raw['fixtureName']]
g['materialize_deployment_config_preimage'] = lambda transaction: (_ for _ in ()).throw(AssertionError('rematerialized deployment preimage'))
g['materialize_evidence_preimages'] = lambda transaction: (_ for _ in ()).throw(AssertionError('rematerialized evidence preimages'))
journal = m['superseded_transport_abort_journal'](authority, authority_bytes, reconciliation)
stored = json.loads(open(m['physical'](m['JOURNAL'])).read())
print(json.dumps({'historicalRollback': all(not m['controller_predecessor_identity_match'](item, legacy_live[item['name']]) and m['historical_cleanup_predecessor_identity_match'](item, legacy_live[item['name']]) for item in predecessors), 'phase': journal['phase'], 'preimagesReused': journal['deploymentConfigPreimage'] == executed['deploymentConfigPreimage'] and journal['evidencePreimages'] == executed['evidencePreimages'], 'stepsReplaced': journal['steps'] == [], 'storedIdentical': m['canonical_bytes'](journal) == m['canonical_bytes'](stored)}))`);
  assert.deepEqual(value, { historicalRollback: true, phase: "ABORTED", preimagesReused: true, stepsReplaced: true, storedIdentical: true });
});
