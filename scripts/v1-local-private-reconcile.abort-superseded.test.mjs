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
    'exportIdentity': {'ctimeNs': st.st_ctime_ns, 'device': st.st_dev, 'gid': st.st_gid, 'inode': st.st_ino,
                        'mode': __import__('stat').S_IMODE(st.st_mode), 'mtimeNs': st.st_mtime_ns,
                        'nlink': st.st_nlink, 'size': st.st_size, 'uid': st.st_uid},
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
