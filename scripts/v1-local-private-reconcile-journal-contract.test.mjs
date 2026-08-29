import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const reconciler = path.join(here, "v1-local-private-reconcile.py");
const python = process.env.PLATFORM_TEST_PYTHON || "/usr/bin/python3";

function jsonPython(body) {
  const output = execFileSync(
    python,
    ["-c", `import json,runpy\nm=runpy.run_path(${JSON.stringify(reconciler)},run_name='v1_journal_contract_test')\n${body}`],
    {
      encoding: "utf8",
      env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
      stdio: ["ignore", "pipe", "pipe"],
    },
  ).trim();
  return JSON.parse(output);
}

const fixture = String.raw`
import copy, hashlib, json, os, tempfile, time
g = m['validate_journal_steps'].__globals__
g['load_rollback_spec'] = lambda step, journal: {'predecessorIdentity': step['before']}

def sha(text): return hashlib.sha256(text.encode()).hexdigest()
def identity(name, service):
    return {
        'configHash': sha('config-' + name),
        'containerId': sha('container-' + name),
        'exitCode': 0,
        'health': 'healthy',
        'imageId': 'sha256:' + sha('image-' + name),
        'imageReference': 'fixture/' + name + '@sha256:' + sha('manifest-' + name),
        'name': name,
        'networkMembership': [{'aliases': [name], 'networkName': 'enterprise_net'}],
        'runtimeConfigSha256': sha('controller-runtime-' + name),
        'semanticSha256': sha('controller-semantic-' + name),
        'service': service,
        'state': 'running',
    }

targets = []
predecessors = []
for name in m['ACTIVE_MANAGED']:
    service = m['ACTIVE_SERVICE_BY_CONTAINER'][name]
    semantic = {
        'imageId': 'sha256:' + sha('target-image-' + name),
        'imageReference': 'fixture/target-' + name + '@sha256:' + sha('target-manifest-' + name),
        'token': name,
    }
    config_hash = sha('target-config-' + name)
    if name != m['BROKER_AUTH_BOOTSTRAP']:
        predecessor = identity(name, service)
        predecessor.update({
            'configHash': config_hash,
            'imageId': semantic['imageId'],
            'imageReference': semantic['imageReference'],
            'runtimeConfigSha256': m['runtime_configuration_digest'](semantic),
            'semanticSha256': m['digest'](m['canonical'](semantic).encode()),
        })
        predecessors.append(predecessor)
    targets.append({
        'configHash': config_hash,
        'containerName': name,
        'project': m['PROJECT_BY_NAME'][name],
        'semantic': semantic,
        'service': service,
    })
scheduler = identity('enterprise-backup-scheduler', 'backup-scheduler')
predecessors.append(scheduler)
attachment = {
    'aliases': ['fixture-alias'],
    'containerName': m['PRESERVED_LEGACY'][0],
    'networkName': 'platform_fixture',
}
authority = {
    'authorizedDataMutations': [{'id': 'mutation-one'}],
    'documentId': sha('authority'),
    'legacyNetworkAttachments': [attachment],
    'serviceTargets': targets,
}
reconciliation = {
    'beganAtUnixSeconds': 1700000000,
    'plannedLegacyNetworkAttachments': [attachment],
    'predecessorRuntimeIdentities': predecessors,
}
previous = {item['name']: item for item in predecessors}
transaction_id = sha('transaction')

def after_for(name):
    target = next(item for item in targets if item['containerName'] == name)
    semantic = target['semantic']
    return {
        'configHash': target['configHash'],
        'containerId': sha('target-container-' + name),
        'exitCode': 0,
        'health': 'healthy',
        'imageId': semantic['imageId'],
        'imageReference': semantic['imageReference'],
        'name': name,
        'networkMembership': [{'aliases': [name], 'networkName': 'platform_fixture'}],
        'project': target['project'],
        'runtimeConfigSha256': m['runtime_configuration_digest'](semantic),
        'semanticSha256': m['digest'](m['canonical'](semantic).encode()),
        'service': target['service'],
        'state': 'running',
    }

def retained_after_for(name):
    target = next(item for item in targets if item['containerName'] == name)
    return dict(previous[name], project=target['project'])

def service_step(name):
    before = previous.get(name)
    return {
        'after': None,
        'backupName': f"v1-rollback-{transaction_id[:12]}-{before['name']}" if before is not None else None,
        'before': before,
        'containerName': name,
        'kind': 'SERVICE',
        'restoredByRecreate': False,
        'rollbackSpecPath': f"{m['ROLLBACK_SPEC_DIR']}/{transaction_id}/{before['name']}.json" if before is not None else None,
        'rollbackSpecSha256': sha('rollback-' + before['name']) if before is not None else None,
        'service': m['ACTIVE_SERVICE_BY_CONTAINER'][name],
        'status': 'PENDING',
    }

def base_steps():
    result = [{
        'kind': 'NETWORK_CREATE',
        'networkId': None,
        'networkName': attachment['networkName'],
        'preexisting': None,
        'status': 'PENDING',
    }]
    result.extend(service_step(name) for name in m['ACTIVE_MANAGED'])
    result.append({
        'after': None,
        'backupName': f"v1-rollback-{transaction_id[:12]}-{scheduler['name']}",
        'before': scheduler,
        'containerName': scheduler['name'],
        'kind': 'REMOVE',
        'restoredByRecreate': False,
        'rollbackSpecPath': f"{m['ROLLBACK_SPEC_DIR']}/{transaction_id}/{scheduler['name']}.json",
        'rollbackSpecSha256': sha('rollback-' + scheduler['name']),
        'service': scheduler['service'],
        'status': 'PENDING',
    })
    result.append({'attachment': attachment, 'kind': 'NETWORK_ATTACH', 'status': 'PENDING'})
    return result

def step_journal(phase='APPLYING', steps=None):
    return {
        'dataMutationStatus': {'mutation-one': 'PENDING'},
        'phase': phase,
        'steps': base_steps() if steps is None else steps,
        'transactionId': transaction_id,
    }

def network_resource(value): return next(step for step in value['steps'] if step['kind'] == 'NETWORK_CREATE')
def attachment_step(value): return next(step for step in value['steps'] if step['kind'] == 'NETWORK_ATTACH')
def service_steps(value): return {step['containerName']: step for step in value['steps'] if step['kind'] == 'SERVICE'}
def first_predecessor_service(value): return next(step for step in value['steps'] if step['kind'] == 'SERVICE' and step['before'] is not None)
def remove_step(value): return next(step for step in value['steps'] if step['kind'] == 'REMOVE')

def complete_resource(value, retained=True):
    step = network_resource(value)
    step.update(networkId=sha('fixture-network'), preexisting=retained, status='RETAINED' if retained else 'CREATED')

def complete_attachment(value):
    attachment_step(value)['status'] = 'CONNECTED'

def complete_data(value):
    value['dataMutationStatus']['mutation-one'] = 'SKIPPED_VERIFIED'

def complete_service(step):
    if step['before'] is None:
        step['status'] = 'APPLIED'; step['after'] = after_for(step['containerName'])
    else:
        step['status'] = 'RETAINED'; step['after'] = retained_after_for(step['containerName'])

def complete_services(value):
    by_name = service_steps(value)
    for name in m['SERVICE_REFRESH_ORDER']: complete_service(by_name[name])

def complete_apply(value):
    complete_resource(value); complete_attachment(value); complete_data(value); complete_services(value)
    remove_step(value)['status'] = 'BACKED_UP'

def validates(value):
    try:
        m['validate_journal_steps'](value['steps'], value, authority, reconciliation)
        m['validate_journal_phase_frontier'](value)
        return True
    except m['Stop']:
        return False
`;

test("journal contract accepts every legitimate crash-resume state and phase frontier", () => {
  const result = jsonPython(`${fixture}
accepted = []
# Network creation intent is durable before mutation and both created/retained
# terminals are reachable.
for status, preexisting, network_id in (
    ('PENDING', None, None), ('CREATING', False, None),
    ('CREATED', False, sha('fixture-network')), ('RETAINED', True, sha('fixture-network')),
):
    value = step_journal(); network_resource(value).update(status=status, preexisting=preexisting, networkId=network_id)
    accepted.append(validates(value))

# Attachments start only after all network resources complete.
for status in sorted(m['JOURNAL_NETWORK_APPLY_STATUSES']):
    value = step_journal(); complete_resource(value); attachment_step(value)['status'] = status
    accepted.append(validates(value))

# The data frontier follows network attachments and admits one RUNNING item.
for status in ('PENDING', 'RUNNING', 'SKIPPED_VERIFIED'):
    value = step_journal(); complete_resource(value); complete_attachment(value)
    value['dataMutationStatus']['mutation-one'] = status
    accepted.append(validates(value))

# Exercise every predecessor service crash state after its fixed-order prefix.
predecessor_name = next(name for name in m['SERVICE_REFRESH_ORDER'] if name != m['BROKER_AUTH_BOOTSTRAP'])
for status in sorted(m['JOURNAL_SERVICE_APPLY_STATUSES']):
    value = step_journal(); complete_resource(value); complete_attachment(value); complete_data(value)
    by_name = service_steps(value)
    for name in m['SERVICE_REFRESH_ORDER']:
        if name == predecessor_name: break
        complete_service(by_name[name])
    step = by_name[predecessor_name]; step['status'] = status
    if status == 'RETAINED': step['after'] = retained_after_for(predecessor_name)
    elif status == 'APPLIED': step['after'] = after_for(predecessor_name)
    accepted.append(validates(value))

# The new one-shot service has the narrower state machine.
new_name = next(name for name in m['SERVICE_REFRESH_ORDER'] if service_steps(step_journal())[name]['before'] is None)
for status in ('PENDING', 'REFRESHING', 'APPLIED'):
    value = step_journal(); complete_resource(value); complete_attachment(value); complete_data(value)
    step = service_steps(value)[new_name]; step['status'] = status
    if status == 'APPLIED': step['after'] = after_for(new_name)
    accepted.append(validates(value))

for status in sorted(m['JOURNAL_REMOVE_APPLY_STATUSES']):
    value = step_journal(); complete_resource(value); complete_attachment(value); complete_data(value); complete_services(value)
    remove_step(value)['status'] = status
    accepted.append(validates(value))

applied = step_journal('APPLIED'); complete_apply(applied); accepted.append(validates(applied))

committing = copy.deepcopy(applied); committing['phase'] = 'COMMITTING'
candidates = [step for step in committing['steps'] if step['kind'] in ('SERVICE', 'REMOVE') and step['backupName']]
candidates[0]['status'] = 'PURGED'; candidates[1]['status'] = 'PURGING'
accepted.append(validates(committing))

evidenced = copy.deepcopy(applied); evidenced['phase'] = 'EVIDENCED'
for step in evidenced['steps']:
    if step['kind'] == 'SERVICE' and step['before'] is not None: step['status'] = 'PURGED'
    elif step['kind'] == 'REMOVE': step['status'] = 'PURGED'
accepted.append(validates(evidenced))

# Abort consumes the physical journal in reverse: ABORTED suffix plus one
# current transient, while remaining apply states stay reachable.
aborting = copy.deepcopy(applied); aborting['phase'] = 'ABORTING'
attachment_step(aborting)['status'] = 'ABORTED'
remove_step(aborting)['status'] = 'ABORTING'
accepted.append(validates(aborting))

aborted = copy.deepcopy(applied); aborted['phase'] = 'ABORTED'
for step in aborted['steps']:
    step['status'] = 'ABORTED'
accepted.append(validates(aborted))
print(json.dumps({'accepted': all(accepted), 'count': len(accepted)}))`);
  assert.equal(result.accepted, true);
  assert.ok(result.count >= 20);
});

test("network creation intent is crash-resumable and abort removes only the transaction-owned ID", () => {
  const result = jsonPython(`${fixture}
g = m['apply_network_resource_step'].__globals__
transaction = sha('network-transaction')
definition = {'driver': 'bridge', 'internal': True, 'labels': {'trust': 'fixture'}}
network = None
def observed(tx=transaction):
    return {
        'Attachable': False, 'Driver': 'bridge', 'EnableIPv6': False,
        'Id': sha('network-id'), 'Internal': True,
        'Labels': {'trust': 'fixture', 'com.platform.reconciliation.transaction-id': tx},
        'Name': 'platform_fixture', 'Options': {},
    }
def inspect(name, missing_ok): return network
def create(name, key, raw, tx):
    global network
    network = observed(tx)
events = []
g['inspect_exact_network'] = inspect
g['create_exact_network'] = create
g['save_journal'] = lambda value: events.append(value['steps'][0]['status'])
g['docker_binary'] = lambda: '/usr/bin/docker'
def run(command, label, **kwargs):
    global network
    events.append('RM:' + command[-1])
    network = None
    return b''
g['run'] = run
step = {'kind': 'NETWORK_CREATE', 'networkId': None, 'networkName': 'platform_fixture', 'preexisting': None, 'status': 'PENDING'}
journal = {'steps': [step], 'transactionId': transaction}
m['apply_network_resource_step'](step, ('platform_fixture', definition), journal)
created = dict(step); apply_events = list(events)
events.clear(); m['apply_network_resource_step'](step, ('platform_fixture', definition), journal)
created_retry_no_write = events == []
events.clear(); m['abort_network_resource_step'](step, ('platform_fixture', definition), journal)
abort_events = list(events); removed = network is None and step['status'] == 'ABORTED'

network = observed('f' * 64)
foreign = {'kind': 'NETWORK_CREATE', 'networkId': None, 'networkName': 'platform_fixture', 'preexisting': False, 'status': 'CREATING'}
try:
    m['abort_network_resource_step'](foreign, ('platform_fixture', definition), {'steps': [foreign], 'transactionId': transaction})
    foreign_stopped = False
except m['Stop']:
    foreign_stopped = network is not None
network = observed(); network['Options'] = {'com.docker.network.bridge.enable_icc': 'false'}
tampered = {'kind': 'NETWORK_CREATE', 'networkId': None, 'networkName': 'platform_fixture', 'preexisting': None, 'status': 'PENDING'}
try:
    m['apply_network_resource_step'](tampered, ('platform_fixture', definition), {'steps': [tampered], 'transactionId': transaction})
    options_stopped = False
except m['Stop']:
    options_stopped = tampered['status'] == 'PENDING'
print(json.dumps({
    'abortEvents': abort_events, 'applyEvents': apply_events,
    'created': created, 'createdRetryNoWrite': created_retry_no_write,
    'foreignStopped': foreign_stopped, 'optionsStopped': options_stopped, 'removed': removed,
}, sort_keys=True))`);
  assert.deepEqual(result.applyEvents, ["CREATING", "CREATED"]);
  assert.deepEqual(result.abortEvents, ["REMOVING", `RM:${result.created.networkId}`, "ABORTED"]);
  assert.equal(result.created.preexisting, false);
  assert.match(result.created.networkId, /^[a-f0-9]{64}$/);
  assert.equal(result.createdRetryNoWrite, true);
  assert.equal(result.foreignStopped, true);
  assert.equal(result.optionsStopped, true);
  assert.equal(result.removed, true);
});

test("journal drift in schema, cardinality, order, identity, rollback, or status fails closed", () => {
  const result = jsonPython(`${fixture}
cases = {}

value = step_journal(); value['steps'][0]['unexpected'] = True
cases['schema'] = not validates(value)
value = step_journal(); value['steps'].pop()
cases['cardinality'] = not validates(value)
value = step_journal(); value['steps'][0], value['steps'][1] = value['steps'][1], value['steps'][0]
cases['order'] = not validates(value)
value = step_journal(); value['steps'][0]['status'] = 'UNKNOWN'
cases['status'] = not validates(value)
value = step_journal(); step = first_predecessor_service(value); step['before'] = dict(step['before'], unexpected='x')
cases['beforeSchema'] = not validates(value)
value = step_journal(); step = first_predecessor_service(value); step['status'] = 'APPLIED'; step['after'] = after_for(step['containerName']); step['after'].pop('project')
cases['afterSchema'] = not validates(value)
value = step_journal(); step = first_predecessor_service(value); step['rollbackSpecPath'] += '.drift'
cases['rollback'] = not validates(value)
value = step_journal(); value['steps'][-1]['attachment'] = dict(value['steps'][-1]['attachment'], unexpected='x')
cases['attachmentSchema'] = not validates(value)
value = step_journal('APPLIED'); complete_apply(value); network_resource(value).update(status='PENDING', preexisting=None, networkId=None)
cases['phaseFrontier'] = not validates(value)
complete_resource(value)
new_step = next(step for step in value['steps'] if step['kind'] == 'SERVICE' and step['before'] is None)
new_step['status'] = 'RETAINED'
cases['newServiceRetained'] = not validates(value)
value = step_journal(); complete_resource(value); attachment_step(value)['status'] = 'CONNECTED'; network_resource(value).update(status='PENDING', preexisting=None, networkId=None)
cases['globalFrontier'] = not validates(value)
value = step_journal(); complete_resource(value); complete_attachment(value); complete_data(value)
ordered = service_steps(value); complete_service(ordered[m['SERVICE_REFRESH_ORDER'][1]])
cases['serviceOrderFrontier'] = not validates(value)
value = step_journal(); complete_resource(value); complete_attachment(value); complete_data(value)
ordered = service_steps(value); complete_service(ordered[m['SERVICE_REFRESH_ORDER'][0]])
retained = ordered[m['SERVICE_REFRESH_ORDER'][1]]; retained['status'] = 'RETAINED'; retained['after'] = retained_after_for(retained['containerName']); retained['after']['containerId'] = sha('retained-drift')
cases['retainedBinding'] = not validates(value)
value = copy.deepcopy(step_journal('ABORTING')); value['steps'][0]['status'] = 'ABORTED'
cases['abortPhysicalFrontier'] = not validates(value)
value = step_journal('COMMITTING'); complete_apply(value)
candidates = [step for step in value['steps'] if step['kind'] in ('SERVICE', 'REMOVE') and step['backupName']]
candidates[1]['status'] = 'PURGED'
cases['commitPhysicalFrontier'] = not validates(value)
print(json.dumps(cases, sort_keys=True))`);
  assert.deepEqual(result, {
    afterSchema: true,
    attachmentSchema: true,
    beforeSchema: true,
    cardinality: true,
    commitPhysicalFrontier: true,
    globalFrontier: true,
    newServiceRetained: true,
    order: true,
    phaseFrontier: true,
    rollback: true,
    retainedBinding: true,
    schema: true,
    serviceOrderFrontier: true,
    status: true,
    abortPhysicalFrontier: true,
  });
});

test("mutation evidence is bound to its exact path, bytes, schema, status, time and details digest", () => {
  const result = jsonPython(`${fixture}
root = tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root, 0o700)
g['TEST_ROOT'] = root; g['OWNER_UID'] = os.geteuid(); g['OWNER_GID'] = os.getegid()
began = int(time.time()) - 5
def publish(document, mode=0o444):
    data = m['canonical_bytes'](document); evidence_sha = m['digest'](data)
    logical = f"{m['MUTATION_EVIDENCE_DIR']}/{authority['documentId']}-mutation-one-{evidence_sha}.json"
    pathname = m['physical'](logical); os.makedirs(os.path.dirname(pathname), mode=0o700, exist_ok=True)
    if os.path.exists(pathname): os.chmod(pathname, 0o600)
    with open(pathname, 'wb') as stream: stream.write(data)
    os.chmod(pathname, mode); os.chown(pathname, os.geteuid(), os.getegid())
    return {'authorityId': 'mutation-one', 'evidencePath': logical, 'evidenceSha256': evidence_sha}
base = {'authorityId': 'mutation-one', 'capturedAtUnixSeconds': began, 'detailsSha256': sha('details'), 'schema': m['MUTATION_EVIDENCE_SCHEMA'], 'status': 'PASS'}
accepted = m['validate_mutation_evidence_entry'](publish(base), authority, began, 'fixture')['authorityId'] == 'mutation-one'
cases = {}
entry = publish(base); entry['evidencePath'] += '.drift'
try: m['validate_mutation_evidence_entry'](entry, authority, began, 'fixture'); cases['path'] = False
except m['Stop']: cases['path'] = True
for field, value in (
    ('authorityId', 'other'), ('capturedAtUnixSeconds', began - 1),
    ('detailsSha256', 'bad'), ('schema', 'other'), ('status', 'FAIL'),
):
    document = dict(base, **{field: value}); entry = publish(document)
    try: m['validate_mutation_evidence_entry'](entry, authority, began, 'fixture'); cases[field] = False
    except m['Stop']: cases[field] = True
entry = publish(base, 0o600)
try: m['validate_mutation_evidence_entry'](entry, authority, began, 'fixture'); cases['mode'] = False
except m['Stop']: cases['mode'] = True
print(json.dumps({'accepted': accepted, 'cases': cases}, sort_keys=True))`);
  assert.equal(result.accepted, true);
  assert.deepEqual(result.cases, {
    authorityId: true,
    capturedAtUnixSeconds: true,
    detailsSha256: true,
    mode: true,
    path: true,
    schema: true,
    status: true,
  });
});

test("ordinary validation rejects zero-step ABORTED while the explicit superseded path admits only never-started state", () => {
  const result = jsonPython(`${fixture}
marker_bytes = m['canonical_bytes']({'beganAtUnixSeconds': reconciliation['beganAtUnixSeconds'], 'status': 'RECONCILING'})
authority_bytes = m['canonical_bytes'](authority)
g['secure_file'] = lambda logical, *args, **kwargs: marker_bytes if logical == m['RECONCILIATION'] else (_ for _ in ()).throw(AssertionError(logical))
g['validate_deployment_config_preimage'] = lambda raw, transaction: raw
g['validate_evidence_preimages'] = lambda raw, transaction: raw
now = int(time.time())
zero = {
    'authorityDocumentId': authority['documentId'],
    'authoritySha256': m['digest'](authority_bytes),
    'beganAtUnixSeconds': reconciliation['beganAtUnixSeconds'],
    'createdAtUnixSeconds': now,
    'dataMutationEvidence': [],
    'dataMutationStatus': {'mutation-one': 'PENDING'},
    'deploymentConfigPreimage': {},
    'evidencePreimages': [],
    'phase': 'ABORTED',
    'reconciliationSha256': m['digest'](marker_bytes),
    'schema': m['JOURNAL_SCHEMA'],
    'steps': [],
    'transactionId': m['digest'](authority_bytes + marker_bytes),
    'updatedAtUnixSeconds': now,
}
try:
    m['validate_journal'](zero, authority, authority_bytes, reconciliation)
    ordinary_rejected = False
except m['Stop']:
    ordinary_rejected = True
explicit_accepted = m['validate_journal'](zero, authority, authority_bytes, reconciliation, allow_superseded_zero_step=True) is zero
drift = copy.deepcopy(zero); drift['dataMutationStatus']['mutation-one'] = 'RUNNING'
try:
    m['validate_journal'](drift, authority, authority_bytes, reconciliation, allow_superseded_zero_step=True)
    drift_rejected = False
except m['Stop']:
    drift_rejected = True
print(json.dumps({'ordinaryRejected': ordinary_rejected, 'explicitAccepted': explicit_accepted, 'driftRejected': drift_rejected}))`);
  assert.deepEqual(result, { ordinaryRejected: true, explicitAccepted: true, driftRejected: true });
});

test("FAST journal admits only the immutable zero-step NEVER_STARTED plan", () => {
  const result = jsonPython(`${fixture}
marker_bytes = m['canonical_bytes']({'beganAtUnixSeconds': reconciliation['beganAtUnixSeconds'], 'status': 'RECONCILING'})
authority_bytes = m['canonical_bytes'](authority); now = int(time.time())
g['secure_file'] = lambda logical, *args, **kwargs: marker_bytes if logical == m['RECONCILIATION'] else (_ for _ in ()).throw(AssertionError(logical))
g['validate_deployment_config_preimage'] = lambda raw, transaction: raw
g['validate_evidence_preimages'] = lambda raw, transaction: raw
base = {
    'authorityDocumentId': authority['documentId'], 'authoritySha256': m['digest'](authority_bytes),
    'beganAtUnixSeconds': reconciliation['beganAtUnixSeconds'], 'createdAtUnixSeconds': now,
    'dataMutationEvidence': [], 'dataMutationStatus': {'mutation-one': 'PENDING'},
    'deploymentConfigPreimage': {}, 'evidencePreimages': [], 'phase': 'APPLYING',
    'reconciliationSha256': m['digest'](marker_bytes), 'schema': m['JOURNAL_SCHEMA'],
    'steps': [], 'transactionId': m['digest'](authority_bytes + marker_bytes), 'updatedAtUnixSeconds': now,
    'validationLaneSha256': 'f' * 64,
}
accepted_applying = m['validate_journal'](copy.deepcopy(base), authority, authority_bytes, reconciliation)['phase'] == 'APPLYING'
validated = copy.deepcopy(base); validated['phase'] = 'VALIDATED_NO_MUTATION'; validated['dataMutationStatus']['mutation-one'] = 'NEVER_STARTED'
accepted_validated = m['validate_journal'](validated, authority, authority_bytes, reconciliation)['phase'] == 'VALIDATED_NO_MUTATION'
cases=[]
for mutate in (
    lambda value: value.update(steps=base_steps()),
    lambda value: value['dataMutationStatus'].update({'mutation-one':'RUNNING'}),
    lambda value: value.update(phase='APPLIED'),
    lambda value: value.update(phase='EVIDENCED'),
):
    candidate=copy.deepcopy(base); mutate(candidate)
    try: m['validate_journal'](candidate, authority, authority_bytes, reconciliation); cases.append(False)
    except m['Stop']: cases.append(True)
production=copy.deepcopy(base); production['validationLaneSha256']=None
try: m['validate_journal'](production, authority, authority_bytes, reconciliation); production_rejected=False
except m['Stop']: production_rejected=True
print(json.dumps({'applying':accepted_applying,'validated':accepted_validated,'allRejected':all(cases),'productionRejected':production_rejected}))`);
  assert.deepEqual(result, { allRejected: true, applying: true, productionRejected: true, validated: true });
});

test("superseded conversion validates the complete old journal before any archive or replacement write", () => {
  const result = jsonPython(`${fixture}
root = tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root, 0o700)
g['TEST_ROOT'] = root; g['OWNER_UID'] = os.geteuid(); g['OWNER_GID'] = os.getegid()
def put(logical, value, mode=0o600):
    pathname = m['physical'](logical); os.makedirs(os.path.dirname(pathname), mode=0o700, exist_ok=True)
    if os.path.exists(pathname): os.chmod(pathname, 0o600)
    with open(pathname, 'wb') as stream: stream.write(m['canonical_bytes'](value))
    os.chmod(pathname, mode); os.chown(pathname, os.geteuid(), os.getegid())
marker = {'beganAtUnixSeconds': reconciliation['beganAtUnixSeconds'], 'status': 'RECONCILING'}
marker_bytes = m['canonical_bytes'](marker)
put(m['RECONCILIATION'], marker)
authority_bytes = m['canonical_bytes'](authority)
tx = m['digest'](authority_bytes + marker_bytes)
transaction_id = tx
base = {
    'authorityDocumentId': authority['documentId'], 'authoritySha256': m['digest'](authority_bytes),
    'beganAtUnixSeconds': reconciliation['beganAtUnixSeconds'], 'createdAtUnixSeconds': 1700000001,
    'dataMutationEvidence': [], 'dataMutationStatus': {'mutation-one': 'PENDING'},
    'deploymentConfigPreimage': {}, 'evidencePreimages': [], 'phase': 'APPLYING',
    'reconciliationSha256': m['digest'](marker_bytes), 'schema': m['JOURNAL_SCHEMA'],
    'steps': base_steps(), 'transactionId': tx, 'updatedAtUnixSeconds': 1700000001,
}
# Rebind deterministic rollback names/paths to the authority+marker transaction.
for step in base['steps']:
    if step['kind'] in ('SERVICE', 'REMOVE') and step['before'] is not None:
        step['backupName'] = f"v1-rollback-{tx[:12]}-{step['before']['name']}"
        step['rollbackSpecPath'] = f"{m['ROLLBACK_SPEC_DIR']}/{tx}/{step['before']['name']}.json"
g['validate_deployment_config_preimage'] = lambda raw, transaction: raw
g['validate_evidence_preimages'] = lambda raw, transaction: raw
g['load_rollback_spec'] = lambda step, journal: {'predecessorIdentity': step['before']}
writes = []
g['preserve_json'] = lambda *args, **kwargs: writes.append('archive') or b''
g['atomic_json'] = lambda *args, **kwargs: writes.append('replace')

def rejected_without_write(value):
    writes.clear(); put(m['JOURNAL'], value)
    try:
        m['superseded_transport_abort_journal'](authority, authority_bytes, reconciliation)
        return False
    except m['Stop']:
        return writes == []

cases = []
value = copy.deepcopy(base); value['steps'][0]['unexpected'] = True; cases.append(rejected_without_write(value))
value = copy.deepcopy(base); value['steps'].pop(); cases.append(rejected_without_write(value))
value = copy.deepcopy(base); value['steps'][0], value['steps'][1] = value['steps'][1], value['steps'][0]; cases.append(rejected_without_write(value))
value = copy.deepcopy(base); value['steps'][0]['status'] = 'UNKNOWN'; cases.append(rejected_without_write(value))
value = copy.deepcopy(base); step = first_predecessor_service(value); step['status'] = 'APPLIED'; step['after'] = after_for(step['containerName']); cases.append(rejected_without_write(value))
print(json.dumps({'allRejectedBeforeWrite': all(cases), 'count': len(cases)}))`);
  assert.deepEqual(result, { allRejectedBeforeWrite: true, count: 5 });
});

test("superseded zero-step replacement is an authority-bound no-write crash retry", () => {
  const result = jsonPython(`${fixture}
root = tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root, 0o700)
g['TEST_ROOT'] = root; g['OWNER_UID'] = os.geteuid(); g['OWNER_GID'] = os.getegid()
def put(logical, value, mode=0o600):
    pathname = m['physical'](logical); os.makedirs(os.path.dirname(pathname), mode=0o700, exist_ok=True)
    if os.path.exists(pathname): os.chmod(pathname, 0o600)
    with open(pathname, 'wb') as stream: stream.write(m['canonical_bytes'](value))
    os.chmod(pathname, mode); os.chown(pathname, os.geteuid(), os.getegid())
marker = {'beganAtUnixSeconds': reconciliation['beganAtUnixSeconds'], 'status': 'RECONCILING'}
marker_bytes = m['canonical_bytes'](marker); put(m['RECONCILIATION'], marker)
authority_bytes = m['canonical_bytes'](authority); tx = m['digest'](authority_bytes + marker_bytes); now = int(time.time())
zero = {
    'authorityDocumentId': authority['documentId'], 'authoritySha256': m['digest'](authority_bytes),
    'beganAtUnixSeconds': reconciliation['beganAtUnixSeconds'], 'createdAtUnixSeconds': now,
    'dataMutationEvidence': [], 'dataMutationStatus': {'mutation-one': 'PENDING'},
    'deploymentConfigPreimage': {}, 'evidencePreimages': [], 'phase': 'ABORTED',
    'reconciliationSha256': m['digest'](marker_bytes), 'schema': m['JOURNAL_SCHEMA'],
    'steps': [], 'transactionId': tx, 'updatedAtUnixSeconds': now,
}
put(m['JOURNAL'], zero)
g['validate_deployment_config_preimage'] = lambda raw, transaction: raw
g['validate_evidence_preimages'] = lambda raw, transaction: raw
writes = []
g['preserve_json'] = lambda *args, **kwargs: writes.append('archive')
g['atomic_json'] = lambda *args, **kwargs: writes.append('replace')
g['materialize_deployment_config_preimage'] = lambda *args, **kwargs: writes.append('deployment-preimage')
g['materialize_evidence_preimages'] = lambda *args, **kwargs: writes.append('evidence-preimages')
result = m['superseded_transport_abort_journal'](authority, authority_bytes, reconciliation)
retry_no_write = result == zero and writes == []
drift = copy.deepcopy(zero); drift['authoritySha256'] = '0' * 64; put(m['JOURNAL'], drift)
try:
    m['superseded_transport_abort_journal'](authority, authority_bytes, reconciliation)
    drift_rejected = False
except m['Stop']:
    drift_rejected = writes == []
print(json.dumps({'retryNoWrite': retry_no_write, 'driftRejected': drift_rejected}))`);
  assert.deepEqual(result, { retryNoWrite: true, driftRejected: true });
});
