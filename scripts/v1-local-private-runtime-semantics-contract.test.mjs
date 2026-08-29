import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const controller = path.join(repositoryRoot, "scripts/v1-local-private-control.py");
const reconciler = path.join(repositoryRoot, "scripts/v1-local-private-reconcile.py");
const python = process.env.PLATFORM_TEST_PYTHON || "/usr/bin/python3";

const expectedFields = [
  "blkioWeight",
  "capAdd",
  "capDrop",
  "command",
  "cpuShares",
  "entrypoint",
  "environment",
  "extraHosts",
  "groupAdd",
  "healthcheck",
  "imageId",
  "imageReference",
  "init",
  "logging",
  "memoryBytes",
  "memoryReservationBytes",
  "mounts",
  "nanoCpus",
  "networkEndpoints",
  "networkMode",
  "networks",
  "pidMode",
  "pidsLimit",
  "ports",
  "privileged",
  "readOnlyRootfs",
  "restartPolicy",
  "routingLabels",
  "runtimeIdentityLabels",
  "securityOpt",
  "tmpfs",
  "ulimits",
  "user",
  "workingDirectory",
].sort();

const pythonPrelude = String.raw`
import copy, json, runpy
c = runpy.run_path(${JSON.stringify(controller)}, run_name='v1_controller_contract_test')
r = runpy.run_path(${JSON.stringify(reconciler)}, run_name='v1_reconciler_contract_test')

def fixtures():
    identifier = '8' * 64
    image_id = 'sha256:' + '9' * 64
    image_reference = 'registry.invalid/control@' + image_id
    name = 'enterprise-control-center'
    service = 'control-center'
    network_name = 'platform_infra_vps_platform_routing'
    labels = {
        'com.platform.runtime.candidate-id': 'a' * 64,
        'com.platform.runtime.commit': 'b' * 40,
        'com.platform.runtime.deployment-id': 'v1-local-private:' + 'a' * 64,
        'com.platform.runtime.source-render-sha256': 'c' * 64,
        'com.platform.runtime.tree': 'd' * 40,
        'com.platform.runtime.workload-lock-sha256': 'e' * 64,
        'traefik.enable': 'false',
    }
    inspect = {
        'Id': identifier,
        'Image': image_id,
        'Name': '/' + name,
        'Mounts': [{
            'Destination': '/etc/platform/config',
            'RW': False,
            'Source': '/srv/platform/config',
            'Type': 'bind',
        }],
        'Config': {
            'Cmd': ['serve', '--http=8080'],
            'Entrypoint': ['/usr/local/bin/control-center'],
            'Env': ['FEATURE_MODE=strict', 'LOG_LEVEL=info'],
            'Healthcheck': {
                'Interval': 30_000_000_000,
                'Retries': 5,
                'StartPeriod': 5_000_000_000,
                'Test': ['CMD-SHELL', 'wget -qO- http://127.0.0.1:8080/health'],
                'Timeout': 10_000_000_000,
            },
            'Image': image_reference,
            'Labels': labels,
            'User': '1000:1000',
            'WorkingDir': '/app',
        },
        'HostConfig': {
            'BlkioWeight': 700,
            'CapAdd': ['CHOWN'],
            'CapDrop': ['ALL'],
            'CpuShares': 1024,
            'ExtraHosts': ['auth.local:host-gateway', 'db.local:10.0.0.10'],
            'GroupAdd': ['100'],
            'Init': True,
            'LogConfig': {'Config': {'max-file': '5', 'max-size': '10m'}, 'Type': 'json-file'},
            'Memory': 536_870_912,
            'MemoryReservation': 134_217_728,
            'NanoCpus': 1_500_000_000,
            'NetworkMode': network_name,
            'PidMode': '',
            'PidsLimit': 384,
            'Privileged': False,
            'ReadonlyRootfs': True,
            'RestartPolicy': {'Name': 'always'},
            'SecurityOpt': ['no-new-privileges:true'],
            'Tmpfs': {'/tmp': 'rw,noexec,nosuid,nodev,size=67108864'},
            'Ulimits': [{'Hard': 16384, 'Name': 'nofile', 'Soft': 16384}],
        },
        'NetworkSettings': {
            'Networks': {network_name: {'Aliases': [identifier[:12], name, service, 'control.internal']}},
            'Ports': {'9000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '19000'}]},
        },
    }
    render = {
        'configs': {},
        'name': 'platform_infra_vps',
        'networks': {'platform_routing': {'name': network_name}},
        'secrets': {},
        'services': {service: {
            'blkio_config': {'weight': 700},
            'cap_add': ['CHOWN'],
            'cap_drop': ['ALL'],
            'command': ['serve', '--http=8080'],
            'container_name': name,
            'cpu_shares': 1024,
            'cpus': '1.5',
            'entrypoint': ['/usr/local/bin/control-center'],
            'environment': ['FEATURE_MODE=strict', 'LOG_LEVEL=info'],
            'extra_hosts': ['auth.local=host-gateway', 'db.local=10.0.0.10'],
            'group_add': ['100'],
            'healthcheck': {
                'interval': '30s',
                'retries': 5,
                'start_period': '5s',
                'test': ['CMD-SHELL', 'wget -qO- http://127.0.0.1:8080/health'],
                'timeout': '10s',
            },
            'image': image_reference,
            'init': True,
            'labels': labels,
            'logging': {'driver': 'json-file', 'options': {'max-file': '5', 'max-size': '10m'}},
            'mem_limit': 536_870_912,
            'mem_reservation': 134_217_728,
            'networks': {'platform_routing': {'aliases': ['control.internal']}},
            'pids_limit': 384,
            'ports': [{'host_ip': '127.0.0.1', 'protocol': 'tcp', 'published': 19000, 'target': 9000}],
            'privileged': False,
            'read_only': True,
            'restart': 'always',
            'security_opt': ['no-new-privileges:true'],
            'tmpfs': ['/tmp:rw,noexec,nosuid,nodev,size=64m'],
            'ulimits': {'nofile': {'hard': 16384, 'soft': 16384}},
            'user': '1000:1000',
            'volumes': [{
                'read_only': True,
                'source': '/srv/platform/config',
                'target': '/etc/platform/config',
                'type': 'bind',
            }],
            'working_dir': '/app',
        }},
        'volumes': {},
    }
    return name, service, image_id, inspect, render

def drift_fixture(raw, field):
    value = copy.deepcopy(raw)
    if field == 'blkioWeight': value['HostConfig']['BlkioWeight'] = 701
    elif field == 'capAdd': value['HostConfig']['CapAdd'].append('NET_BIND_SERVICE')
    elif field == 'capDrop': value['HostConfig']['CapDrop'].append('NET_RAW')
    elif field == 'command': value['Config']['Cmd'].append('--strict')
    elif field == 'cpuShares': value['HostConfig']['CpuShares'] = 2048
    elif field == 'entrypoint': value['Config']['Entrypoint'] = ['/usr/local/bin/control-center-v2']
    elif field == 'environment': value['Config']['Env'].append('FEATURE_FLAG=on')
    elif field == 'extraHosts': value['HostConfig']['ExtraHosts'].append('cache.local:10.0.0.11')
    elif field == 'groupAdd': value['HostConfig']['GroupAdd'].append('200')
    elif field == 'healthcheck': value['Config']['Healthcheck']['Retries'] = 6
    elif field == 'imageId': value['Image'] = 'sha256:' + 'a' * 64
    elif field == 'imageReference': value['Config']['Image'] = 'registry.invalid/control@sha256:' + 'b' * 64
    elif field == 'init': value['HostConfig']['Init'] = False
    elif field == 'logging': value['HostConfig']['LogConfig']['Config']['max-file'] = '6'
    elif field == 'memoryBytes': value['HostConfig']['Memory'] = 805_306_368
    elif field == 'memoryReservationBytes': value['HostConfig']['MemoryReservation'] = 268_435_456
    elif field == 'mounts': value['Mounts'][0]['Source'] = '/srv/platform/config-v2'
    elif field == 'nanoCpus': value['HostConfig']['NanoCpus'] = 2_000_000_000
    elif field == 'networkEndpoints': next(iter(value['NetworkSettings']['Networks'].values()))['Aliases'].append('new.internal')
    elif field == 'networkMode': value['HostConfig']['NetworkMode'] = 'host'
    elif field == 'networks':
        binding = next(iter(value['NetworkSettings']['Networks'].values()))
        value['NetworkSettings']['Networks'] = {'platform_infra_vps_platform_alt': binding}
    elif field == 'pidMode': value['HostConfig']['PidMode'] = 'host'
    elif field == 'pidsLimit': value['HostConfig']['PidsLimit'] = 512
    elif field == 'ports': value['NetworkSettings']['Ports']['9000/tcp'][0]['HostPort'] = '19001'
    elif field == 'privileged': value['HostConfig']['Privileged'] = True
    elif field == 'readOnlyRootfs': value['HostConfig']['ReadonlyRootfs'] = False
    elif field == 'restartPolicy': value['HostConfig']['RestartPolicy']['Name'] = 'unless-stopped'
    elif field == 'routingLabels': value['Config']['Labels']['traefik.enable'] = 'true'
    elif field == 'runtimeIdentityLabels': del value['Config']['Labels']['com.platform.runtime.commit']
    elif field == 'securityOpt': value['HostConfig']['SecurityOpt'].append('seccomp=unconfined')
    elif field == 'tmpfs': value['HostConfig']['Tmpfs']['/tmp'] = 'rw,noexec,nosuid,nodev,size=33554432'
    elif field == 'ulimits': value['HostConfig']['Ulimits'][0].update({'Hard': 32768, 'Soft': 32768})
    elif field == 'user': value['Config']['User'] = '2000:2000'
    elif field == 'workingDirectory': value['Config']['WorkingDir'] = '/workspace'
    else: raise AssertionError('missing drift fixture for ' + field)
    return value
`;

function runPython(body) {
  const result = spawnSync(python, ["-c", `${pythonPrelude}\n${body}`], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: { ...process.env, LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
    maxBuffer: 4 * 1024 * 1024,
  });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("controller, reconciler, and render authority share one closed 34-field runtime contract", () => {
  const result = runPython(String.raw`
name, service, image_id, raw, render = fixtures()
controller = c['inspect_service_semantics'](raw, name)
reconciler = r['inspect_service_semantics'](raw, name)
controller_render = c['render_service_semantics'](render, service, image_id, 'platform_infra_vps')
reconciler_render = r['render_service_semantics'](render, service, image_id, 'platform_infra_vps')
print(json.dumps({
    'allEqual': controller == reconciler == controller_render == reconciler_render,
    'digests': [
        c['runtime_configuration_digest'](controller),
        r['runtime_configuration_digest'](reconciler),
        c['runtime_configuration_digest'](controller_render),
        r['runtime_configuration_digest'](reconciler_render),
    ],
    'fields': sorted(controller),
}, sort_keys=True))
`);
  assert.equal(result.allEqual, true);
  assert.deepEqual(result.fields, expectedFields);
  assert.equal(result.fields.length, 34);
  assert.equal(new Set(result.digests).size, 1);
});

test("every runtime field remains byte-semantically aligned under Docker inspect drift", () => {
  const result = runPython(String.raw`
name, _service, _image_id, raw, _render = fixtures()
baseline = c['inspect_service_semantics'](raw, name)
results = {}
for field in sorted(baseline):
    drift = drift_fixture(raw, field)
    controller = c['inspect_service_semantics'](drift, name)
    reconciler = r['inspect_service_semantics'](drift, name)
    results[field] = {
        'changed': controller[field] != baseline[field],
        'digestsEqual': c['runtime_configuration_digest'](controller) == r['runtime_configuration_digest'](reconciler),
        'semanticsEqual': controller == reconciler,
    }
print(json.dumps(results, sort_keys=True))
`);
  assert.deepEqual(Object.keys(result), expectedFields);
  for (const [field, evidence] of Object.entries(result)) {
    assert.equal(evidence.changed, true, `${field} drift was not represented`);
    assert.equal(evidence.semanticsEqual, true, `${field} drift diverged across modules`);
    assert.equal(evidence.digestsEqual, true, `${field} digest diverged across modules`);
  }
});

test("shared inspect normalizers reject malformed runtime representations in both modules", () => {
  const result = runPython(String.raw`
name, _service, _image_id, raw, _render = fixtures()
invalid = {}
candidate = copy.deepcopy(raw); candidate['Image'] = '9' * 64; invalid['imageId'] = candidate
candidate = copy.deepcopy(raw); candidate['HostConfig']['ExtraHosts'] = ['auth.local=host-gateway']; invalid['extraHosts'] = candidate
candidate = copy.deepcopy(raw); candidate['HostConfig']['LogConfig']['Unexpected'] = {}; invalid['logging'] = candidate
candidate = copy.deepcopy(raw); candidate['HostConfig']['Memory'] = True; invalid['memoryBytes'] = candidate
candidate = copy.deepcopy(raw); candidate['Config']['Labels']['com.platform.runtime.commit'] = ''; invalid['runtimeIdentityLabels'] = candidate
candidate = copy.deepcopy(raw); candidate['HostConfig']['Tmpfs'] = ['/tmp']; invalid['tmpfs'] = candidate
candidate = copy.deepcopy(raw); candidate['HostConfig']['Ulimits'].append(copy.deepcopy(candidate['HostConfig']['Ulimits'][0])); invalid['ulimits'] = candidate
rejected = {}
for label, candidate in invalid.items():
    rejected[label] = []
    for module in (c, r):
        try:
            module['inspect_service_semantics'](candidate, name)
            rejected[label].append(False)
        except module['Stop']:
            rejected[label].append(True)
print(json.dumps(rejected, sort_keys=True))
`);
  for (const [field, rejected] of Object.entries(result)) {
    assert.deepEqual(rejected, [true, true], `${field} malformed input did not fail closed`);
  }
});

test("controller upgrade verifies the registered 19-field predecessor identity before adopting the 34-field contract", () => {
  const result = runPython(String.raw`
name, _service, _image_id, raw, _render = fixtures()
baseline = c['inspect_service_semantics'](raw, name)
drifted = c['inspect_service_semantics'](drift_fixture(raw, 'memoryBytes'), name)
legacy_fields = sorted(c['CONTROLLER_RECORDED_SEMANTIC_FIELDS'])
current_sha = 'f' * 64
g = c['predecessor_controller_identity_projection'].__globals__
g['controller_identity'] = lambda: {'sha256': current_sha}
legacy_sha = next(
    sha for sha, projection in c['CONTROLLER_IDENTITY_PROJECTION_BY_SHA256'].items()
    if projection == c['CONTROLLER_IDENTITY_PROJECTION_LEGACY_19']
)
legacy_state = {'controller': {
    'installedPath': c['CONTROLLER_PATH'],
    'sha256': legacy_sha,
    'sudoersPath': c['SUDOERS_PATH'], 'sudoersSha256': '1' * 64,
    'unitPath': c['UNIT_PATH'], 'unitSha256': '2' * 64,
}}
current_state = copy.deepcopy(legacy_state); current_state['controller']['sha256'] = current_sha
prior_full_state = copy.deepcopy(legacy_state); prior_full_state['controller']['sha256'] = 'd' * 64
c['CONTROLLER_IDENTITY_PROJECTION_BY_SHA256'][prior_full_state['controller']['sha256']] = c['CONTROLLER_IDENTITY_PROJECTION_FULL_34']
unknown_state = copy.deepcopy(legacy_state); unknown_state['controller']['sha256'] = 'e' * 64
try:
    c['predecessor_controller_identity_projection'](unknown_state)
    unknown_rejected = False
except c['Stop']:
    unknown_rejected = True
print(json.dumps({
    'currentProjection': c['predecessor_controller_identity_projection'](current_state),
    'fullDigestDetectsNewField': c['runtime_configuration_digest'](baseline) != c['runtime_configuration_digest'](drifted),
    'legacyDigestStableForNewField': c['controller_recorded_runtime_digest'](baseline) == c['controller_recorded_runtime_digest'](drifted),
    'legacyFieldCount': len(legacy_fields),
    'legacyProjection': c['predecessor_controller_identity_projection'](legacy_state),
    'priorFullProjection': c['predecessor_controller_identity_projection'](prior_full_state),
    'unknownRejected': unknown_rejected,
}, sort_keys=True))
`);
  assert.deepEqual(result, {
    currentProjection: "FULL_34",
    fullDigestDetectsNewField: true,
    legacyDigestStableForNewField: true,
    legacyFieldCount: 19,
    legacyProjection: "LEGACY_19",
    priorFullProjection: "FULL_34",
    unknownRejected: true,
  });
});

test("registered f60 upgrade projection reaches verify, begin, abort, and supervisor call paths", () => {
  const result = runPython(String.raw`
legacy = c['CONTROLLER_IDENTITY_PROJECTION_LEGACY_19']
full = c['CONTROLLER_IDENTITY_PROJECTION_FULL_34']
legacy_sha = next(
    sha for sha, projection in c['CONTROLLER_IDENTITY_PROJECTION_BY_SHA256'].items()
    if projection == legacy
)
current_sha = 'f' * 64
g = c['verify_active'].__globals__
g['controller_identity'] = lambda: {'sha256': current_sha}

def controller_document(sha):
    return {
        'installedPath': c['CONTROLLER_PATH'], 'sha256': sha,
        'sudoersPath': c['SUDOERS_PATH'], 'sudoersSha256': '1' * 64,
        'unitPath': c['UNIT_PATH'], 'unitSha256': '2' * 64,
    }

def observation(tag):
    return {
        'containers': [{'name': name, 'projectionFixture': tag} for name in sorted(c['CANONICAL_EXPECTED_NAMES'])],
        'schedulerRecovery': {'projectionFixture': tag},
    }

legacy_observation = observation('legacy')
full_observation = observation('full')
install_sha = '3' * 64
receipt = {'activatedAtUnixSeconds': 1800000000, 'fixture': 'receipt'}
legacy_state = {
    'checkpointSha256': '6' * 64,
    'controller': controller_document(legacy_sha),
    'externalAuthorizedReconciliation': {'releaseAuthorityDocumentId': '4' * 64},
    'installReceiptSha256': install_sha,
    'observation': legacy_observation,
    'schema': c['STATE_SCHEMA'],
    'status': 'ACTIVE',
}
state_ref = [legacy_state]
g['EXACT_AUTHORITY'] = {'documentId': '5' * 64}
g['read_state'] = lambda *_args, **_kwargs: state_ref[0]
g['validate_release_and_install'] = lambda *_args, **_kwargs: install_sha
g['validate_bound_recovery_export'] = lambda *_args, **_kwargs: None
g['validate_receipt_document'] = lambda _value: receipt
g['parse_json'] = lambda *_args, **_kwargs: receipt
g['secure_file'] = lambda *_args, **_kwargs: b'{}'
g['receipt_from_state'] = lambda *_args, **_kwargs: receipt
g['systemctl'] = lambda arguments, _label: 'enabled' if arguments[0] == 'is-enabled' else 'active'

observed_projections = []
def observe_fixture(_recovery, _names=c['EXPECTED_NAMES'], _enforce=True, projection=full):
    projection = c['validate_controller_identity_projection'](projection)
    observed_projections.append(projection)
    return legacy_observation if projection == legacy else full_observation
g['observe'] = observe_fixture

# verify_active traverses the real profile, projection registry, stable double
# observation, receipt, and supervisor checks.
c['verify_active']()
verify_projections = list(observed_projections)
observed_projections.clear()

# begin_maintenance verifies the legacy ACTIVE state with LEGACY_19, then
# captures the new reconciliation marker with the installed FULL_34 contract.
captured_projections = []
legacy_identities = [{'name': name, 'projectionFixture': 'legacy'} for name in sorted(c['CANONICAL_EXPECTED_NAMES'])]
full_identities = [{'name': name, 'projectionFixture': 'full'} for name in sorted(c['CANONICAL_EXPECTED_NAMES'])]
def capture_fixture(_names, projection=full):
    projection = c['validate_controller_identity_projection'](projection)
    captured_projections.append(projection)
    return legacy_identities if projection == legacy else full_identities
g['capture_runtime_identities'] = capture_fixture
g['ensure_private_directory'] = lambda *_args, **_kwargs: None
g['os'].path.lexists = lambda _path: False
g['validate_predecessor_runtime_snapshot'] = lambda *_args, **_kwargs: None
g['supervisor_is_enabled_and_active'] = lambda: True
g['validate_checkpoint'] = lambda: (
    '6' * 64, b'', {
        'exportLabels': {
            c['RECOVERY_LABELS']['configHash']: '7' * 64,
            c['RECOVERY_LABELS']['containerId']: '8' * 64,
        },
    }, {}, {},
)
marker_ref = [{}]
def reconciliation_document_fixture(_state, _receipt, install, _began, identities, _recovery, _checkpoint):
    marker_ref[0] = {
        'installReceiptSha256': install,
        'predecessorRuntimeIdentities': identities,
        'previousReceiptPath': '/fixture/previous-receipt.json',
        'previousStatePath': '/fixture/previous-state.json',
    }
    return marker_ref[0]
g['reconciliation_document'] = reconciliation_document_fixture
g['preserve_immutable_document'] = lambda *_args, **_kwargs: None
g['atomic_write'] = lambda *_args, **_kwargs: None
g['disable_supervisor'] = lambda: None
c['begin_maintenance']()
begin_projections = list(captured_projections)

# abort_maintenance first compares the FULL_34 marker identity, verifies the
# f60 receipt with LEGACY_19, rebaselines with FULL_34, and verifies the new
# ACTIVE state through verify_active before removing the marker.
captured_projections.clear()
observed_projections.clear()
g['os'].path.lexists = lambda _path: True
g['read_reconciliation'] = lambda: marker_ref[0]
g['consume_current_abort_record'] = lambda _marker: {'fixture': 'consumed-abort'}
g['validate_reconciliation_rollback'] = lambda _marker: (legacy_state, receipt)
g['supervisor_is_disabled_and_inactive'] = lambda: True
g['predecessor_runtime_provenance_document'] = lambda _state: {'controllerIdentityProjection': legacy}
def state_document_fixture(_status, runtime, install, _checkpoint, _created, external, _aborted, _provenance):
    return {
        **legacy_state,
        'controller': controller_document(current_sha),
        'externalAuthorizedReconciliation': external,
        'installReceiptSha256': install,
        'observation': runtime,
    }
g['state_document'] = state_document_fixture
def atomic_write_fixture(pathname, document, *_args, **_kwargs):
    if pathname == c['STATE_FILE']:
        state_ref[0] = document
g['atomic_write'] = atomic_write_fixture
g['ensure_supervisor_active'] = lambda: None
g['remove_exact_document'] = lambda *_args, **_kwargs: None
c['abort_maintenance']()
abort_identity_projections = list(captured_projections)
abort_observation_projections = list(observed_projections)

# supervise traverses its real startup projection selection and bounded
# wait. Stop at the first watchdog-loop sleep after READY.
state_ref[0] = legacy_state
observed_projections.clear()
g['os'].path.lexists = lambda _path: False
g['notify'] = lambda _message: None
class SupervisorLoopReached(Exception):
    pass
g['time'].sleep = lambda _seconds: (_ for _ in ()).throw(SupervisorLoopReached())
try:
    c['supervise']()
except SupervisorLoopReached:
    pass
else:
    raise AssertionError('supervisor did not reach its watchdog loop')

print(json.dumps({
    'abortIdentity': abort_identity_projections,
    'abortObservation': abort_observation_projections,
    'begin': begin_projections,
    'supervise': observed_projections,
    'verify': verify_projections,
}, sort_keys=True))
`);
  assert.deepEqual(result, {
    abortIdentity: ["FULL_34", "FULL_34"],
    abortObservation: ["LEGACY_19", "LEGACY_19", "FULL_34", "FULL_34", "FULL_34", "FULL_34", "FULL_34", "FULL_34"],
    begin: ["LEGACY_19", "LEGACY_19", "FULL_34", "FULL_34"],
    supervise: ["LEGACY_19", "LEGACY_19"],
    verify: ["LEGACY_19", "LEGACY_19"],
  });
});

test("controller requires exact reconciler evidence across aligned semantic domains", () => {
  const result = runPython(String.raw`
name, service, image_id, raw, _render = fixtures()
semantic = c['inspect_service_semantics'](raw, name)
controller = {
    'configHash': '1' * 64, 'containerId': '8' * 64, 'exitCode': 0,
    'health': 'healthy', 'imageAvailability': 'LOCAL_IMAGE_STORE',
    'imageId': image_id, 'imageReference': semantic['imageReference'], 'name': name,
    'networkMembership': c['inspect_network_membership'](raw, name),
    'project': 'platform_infra_vps',
    'runtimeConfigSha256': c['runtime_configuration_digest'](semantic),
    'semanticSha256': c['digest'](c['canonical'](semantic).encode()),
    'service': service, 'state': 'running',
}
native = dict(controller,
    runtimeConfigSha256=r['runtime_configuration_digest'](semantic),
    semanticSha256=r['digest'](r['canonical'](semantic).encode()),
)
accepted = c['validate_cross_implementation_identity_inventory']([native], [controller])[0]
drift_rejected = False
try:
    c['validate_cross_implementation_identity_inventory']([dict(native, containerId='7' * 64)], [controller])
except c['Stop']:
    drift_rejected = True
digest_drift_rejected = False
try:
    c['validate_cross_implementation_identity_inventory']([dict(native, runtimeConfigSha256='6' * 64)], [controller])
except c['Stop']:
    digest_drift_rejected = True
print(json.dumps({
    'digestDriftRejected': digest_drift_rejected,
    'digestsExact': accepted['runtimeConfigSha256'] == controller['runtimeConfigSha256'],
    'driftRejected': drift_rejected,
}, sort_keys=True))
`);
  assert.deepEqual(result, {
    digestDriftRejected: true,
    digestsExact: true,
    driftRejected: true,
  });
});
