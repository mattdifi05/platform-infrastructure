import copy
import datetime
import importlib.util
import hashlib
import hmac
import http.client
import socket
import shutil
import threading
import time
import uuid
import json
import io
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

LIBEXEC = pathlib.Path(__file__).resolve().parents[1] / 'libexec'
sys.path.insert(0, str(LIBEXEC))
spec = importlib.util.spec_from_file_location('runtime_updates_test_module', LIBEXEC / 'platform_runtime_updates.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
OLD_IMAGE, NEW_IMAGE = 'sha256:' + 'a' * 64, 'sha256:' + 'b' * 64
SECRET = 'fixture-password-never-public'


def container(running=True):
    return {'Id': 'old-container', 'Name': '/php-service', 'Image': OLD_IMAGE,
            'Config': {'Image': OLD_IMAGE, 'Env': ['PHP_VERSION=8.5.11', 'DB_PASSWORD=' + SECRET], 'Labels': {'role': 'runtime'}, 'Entrypoint': ['docker-php-entrypoint'], 'Cmd': ['apache2-foreground'], 'WorkingDir': '/var/www/html', 'Volumes': {'/data': {}}},
            'HostConfig': {'RestartPolicy': {'Name': 'unless-stopped', 'MaximumRetryCount': 0}, 'Binds': ['named-data:/data:rw'], 'ReadonlyRootfs': True, 'CapDrop': ['ALL'], 'Memory': 512 * 1024 * 1024},
            'Mounts': [{'Type': 'volume', 'Name': 'named-data', 'Source': '/var/lib/docker/volumes/named-data/_data', 'Destination': '/data', 'RW': True}],
            'NetworkSettings': {'Networks': {'infra': {'IPAMConfig': None, 'Aliases': ['php-service'], 'Links': None, 'DriverOpts': None}}},
            'State': {'Running': running, 'OOMKilled': False, 'ExitCode': 0}}


class DockerFixture:
    def __init__(self, running=True):
        self.old = container(running)
        self.rows = {self.old['Id']: copy.deepcopy(self.old)}
        self.calls = []
        self.fail_create = False
        self.created = 0
        self.images = {}

    def inspect(self, identity):
        for key, row in self.rows.items():
            if identity in (key, row['Name'], row['Name'].lstrip('/')):
                return copy.deepcopy(row)
        return None

    def docker(self, method, endpoint, body=None):
        self.calls.append((method, endpoint, copy.deepcopy(body)))
        if endpoint == '/containers/json?all=true':
            return [{'Id': row['Id'], 'Names': [row['Name']], 'ImageID': row['Image'], 'State': 'running' if row['State']['Running'] else 'exited'} for row in self.rows.values()]
        if endpoint.startswith('/images/'):
            return self.images.get(endpoint[len('/images/'):-len('/json')], {'Id': NEW_IMAGE, 'Config': {'Env': ['PHP_VERSION=8.5.12']}})
        if endpoint.startswith('/containers/create?'):
            if self.fail_create:
                raise m.Rejected('updates_unavailable', 'Simulated Docker failure', 503)
            name = endpoint.split('name=', 1)[1]
            source = next((x for x in self.rows.values() if x['Name'].startswith('/' + name + '-update-')), self.old)
            row = copy.deepcopy(source)
            self.created += 1
            row.update(Id='new-container' if self.created == 1 else 'new-container-' + str(self.created), Name='/' + name, Image=body['Image'])
            row['Config'] = {k: copy.deepcopy(v) for k, v in body.items() if k not in ['HostConfig', 'NetworkingConfig']}
            row['HostConfig'] = copy.deepcopy(body['HostConfig'])
            row['NetworkSettings'] = {'Networks': copy.deepcopy(body['NetworkingConfig']['EndpointsConfig'])}
            row['State']['Running'] = False
            self.rows[row['Id']] = row
            return {'Id': row['Id']}
        if endpoint.startswith('/networks/'):
            network = endpoint.split('/')[2]
            row = self.rows[body['Container']]
            if endpoint.endswith('/disconnect'):
                row['NetworkSettings']['Networks'].pop(network, None)
            else:
                row['NetworkSettings']['Networks'][network] = {'IPAMConfig': None, 'Aliases': None, 'Links': None, 'DriverOpts': None, **copy.deepcopy(body['EndpointConfig'])}
            return None
        identity = endpoint.split('/')[2].split('?')[0]
        if method == 'DELETE':
            self.rows.pop(identity, None)
            return None
        row = self.rows[identity]
        if '/rename?' in endpoint:
            row['Name'] = '/' + endpoint.split('name=', 1)[1]
        elif endpoint.endswith('/update'):
            row['HostConfig'].update(copy.deepcopy(body))
        elif '/stop?' in endpoint:
            row['State']['Running'] = False
        elif endpoint.endswith('/start'):
            row['State']['Running'] = True
        else:
            raise AssertionError((method, endpoint))
        return None


class UpdatesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='runtime-updates-worker-')
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.state = self.root / 'state'
        self.config = {'schema': 'platform-runtime-updates/v1', 'components': [{'id': 'php', 'label': 'PHP', 'category': 'Runtime', 'containers': ['php-service'], 'strategy': 'image', 'versionEnv': 'PHP_VERSION', 'probe': ['php', '-r', 'echo PHP_VERSION;']}]}
        self.config_path = self.root / 'config.json'
        self.config_path.write_text(json.dumps(self.config))
        self.addCleanup(patch.stopall)
        patch.object(m, 'ROOT', self.state).start()
        patch.object(m, 'CONFIG', self.config_path).start()
        # The worker's backup lock must stay inside this isolated fixture.
        real_path = pathlib.Path
        module_paths = types.SimpleNamespace(Path=lambda value: self.root / 'backup-lock' / 'operation.lock' if str(value) == '/var/lib/platform-vps-backup/operation.lock' else real_path(value))
        patch.object(m, 'pathlib', module_paths).start()
        m.initialize()
        self.docker = DockerFixture()
        patch.object(m, 'docker', self.docker.docker).start()
        patch.object(m, 'inspect', self.docker.inspect).start()
        real_run = m.run
        def fixture_run(argv, **kwargs):
            if argv[:2] == ['docker', 'exec'] and len(argv) >= 4:
                row = self.docker.inspect(argv[2])
                if row is not None and argv[3:] == ['php', '-r', 'echo PHP_VERSION;']:
                    environment = dict(value.split('=', 1) for value in row['Config'].get('Env', []) if '=' in value)
                    return environment['PHP_VERSION'] + '\n'
                if row is not None and argv[3:] == ['node', '--version']:
                    environment = dict(value.split('=', 1) for value in row['Config'].get('Env', []) if '=' in value)
                    return 'v' + environment['NODE_VERSION'] + '\n'
            # Keep the actual error-redaction path and other deliberate mocks.
            return real_run(argv, **kwargs)
        patch.object(m, 'run', side_effect=fixture_run).start()
        # Root ancestry is tested separately with synthetic lstat metadata below.
        patch.object(m, 'protected', lambda value: real_path(value)).start()
        self.release = {'version': '8.5.12', 'imageDigest': NEW_IMAGE, 'imageReference': 'docker.io/library/php:8.5.12-apache', 'sourceUrl': 'https://www.php.net/releases/'}
        m.save('cache', 'releases', {'checkedAt': m.stamp(), 'components': {'php': {'candidateRelease': self.release, 'latestStable': self.release}}})

    def plan(self):
        return m.handle({'action': 'plan', 'componentId': 'php', 'revision': m.catalog()['revision']})

    def apply_body(self, plan, key='request-1'):
        return {'action': 'apply', 'componentId': 'php', 'revision': plan['revision'], 'planId': plan['planId'], 'confirmation': 'UPDATE', 'idempotencyKey': key}

    def stored(self):
        plan = self.plan()
        return m.load('plan', plan['planId'])

    def prepare_job(self, key='job-1'):
        m.save('operation', key, {'id': key, 'status': 'queued', 'stage': 'queued', 'completedSteps': 0, 'totalSteps': 5})

    def node_group(self):
        images = [OLD_IMAGE, 'sha256:' + 'c' * 64, OLD_IMAGE]
        self.docker.rows = {}
        for i, (version, image) in enumerate(zip(['24.15.0', '26.12.1', '24.15.0'], images)):
            old = container(running=i != 2)
            old.update(Id='old-node-' + str(i), Name='/node-app-' + str(i), Image=image)
            old['Config'].update(Image=image, Env=['NODE_VERSION=' + version, 'DB_PASSWORD=' + SECRET],
                                 WorkingDir='/app-' + str(i), Entrypoint=['application-entrypoint'], Cmd=['server.js'])
            self.docker.rows[old['Id']] = old
        self.node_before = copy.deepcopy(self.docker.rows)
        row = {'id': 'node', 'label': 'Node.js', 'category': 'Runtime', 'repository': 'library/node',
               'compatibility': 'major', 'containers': ['node-app-' + str(i) for i in range(3)],
               'strategy': 'node-layer', 'versionEnv': 'NODE_VERSION', 'probe': ['node', '--version']}
        self.config['components'] = [row]
        self.config_path.write_text(json.dumps(self.config))
        target = dict(self.release, version='26.12.1', imageReference='docker.io/library/node:26.12.1-alpine')
        m.save('cache', 'releases', {'checkedAt': m.stamp(), 'components': {'node': {
            'candidateRelease': dict(target, version='26.12.2'), 'latestStable': target}}})
        self.node_candidates = {OLD_IMAGE: NEW_IMAGE, images[1]: 'sha256:' + 'd' * 64}
        for image in self.node_candidates.values():
            self.docker.images[image] = {'Id': image, 'Config': {'Env': ['NODE_VERSION=26.12.1']}}
        return row

    def node_stored(self):
        public = m.plan('node', m.catalog()['revision'])
        return m.load('plan', public['planId'])

    def test_mixed_family_is_known_and_aligns_to_one_latest_even_when_maximum_already_current(self):
        row = self.node_group()
        item = m.catalog()['components'][0]
        self.assertIsNone(item['current']['version'])
        self.assertEqual(item['current']['versions'], ['24.15.0', '26.12.1'])
        self.assertIsNone(item['current']['imageDigest'])
        self.assertTrue(item['needsAlignment']); self.assertTrue(item['canUpdate'])
        self.assertEqual(item['status'], 'update-available')
        self.assertEqual(item['candidateRelease']['version'], '26.12.1')
        self.assertEqual(m.observed(row)[1], '26.12.1')
        self.assertEqual(self.node_stored()['public']['affectedServices'], ['node-app-0', 'node-app-1', 'node-app-2'])

    def test_discovery_uses_maximum_and_explicit_equal_policy_only_for_mixed_family(self):
        self.node_group(); self.prepare_job()
        result = {'latestStable': dict(self.release, version='26.12.1'), 'candidateRelease': None}
        with patch.object(m, 'resolve_release', return_value=result) as discovery:
            m.check_job('job-1')
        policy, representative = discovery.call_args.args
        self.assertEqual(representative, '26.12.1'); self.assertTrue(policy['includeCurrent'])
        for old in self.docker.rows.values():
            old['Config']['Env'] = ['NODE_VERSION=26.12.1']
        with patch.object(m, 'resolve_release', return_value=result) as discovery:
            m.check_job('job-1')
        self.assertFalse(discovery.call_args.args[0]['includeCurrent'])
        self.assertFalse(m.catalog()['components'][0]['canUpdate'])

    def test_group_state_change_during_preflight_rejects_before_first_mutation(self):
        self.node_group(); stored = self.node_stored(); self.prepare_job()
        def preflight(*args):
            self.docker.rows['old-node-2']['State']['Running'] = True
        with patch.object(m, 'image_candidate', side_effect=lambda row, target, directory, source: self.node_candidates[source]), patch.object(m, 'node_preflight', side_effect=preflight):
            m.apply_job('job-1', stored)
        self.assertEqual(m.load('operation', 'job-1')['status'], 'failed')
        self.assertFalse(any(method != 'GET' for method, _, _ in self.docker.calls))

    def test_unknown_instance_does_not_masquerade_as_known_mixed_family(self):
        self.node_group()
        self.docker.rows['old-node-2']['Config']['Env'] = []
        item = m.catalog()['components'][0]
        self.assertFalse(item['canUpdate']); self.assertFalse(item['needsAlignment'])
        self.assertEqual(item['current']['versions'], [])
        self.assertIsNone(item['current']['version'])

    def test_all_unique_images_prepare_and_all_abi_checks_pass_before_first_service_mutation(self):
        self.node_group(); stored = self.node_stored(); self.prepare_job()
        prepared, checked = [], []
        def build(row, target, directory, source):
            self.assertFalse(any(method != 'GET' for method, _, _ in self.docker.calls))
            prepared.append(source)
            self.assertEqual(target['version'], '26.12.1')
            return self.node_candidates[source]
        def preflight(old, image, version):
            self.assertEqual(set(prepared), set(self.node_candidates))
            self.assertFalse(any(method != 'GET' for method, _, _ in self.docker.calls))
            self.assertEqual(image, self.node_candidates[old['Image']]); checked.append(old['Id'])
        with patch.object(m, 'image_candidate', side_effect=build), patch.object(m, 'node_preflight', side_effect=preflight), patch.object(m, 'refresh_admission') as admission:
            m.apply_job('job-1', stored)
        self.assertEqual(m.load('operation', 'job-1')['status'], 'succeeded')
        self.assertEqual(len(prepared), 2); self.assertEqual(len(checked), 3)
        admission.assert_called_once()
        for old in self.node_before.values():
            new = self.docker.inspect(old['Name'])
            self.assertEqual(new['Image'], self.node_candidates[old['Image']])
            self.assertEqual(new['State']['Running'], old['State']['Running'])
            self.assertEqual(new['HostConfig'], old['HostConfig'])
            self.assertEqual(new['Mounts'], old['Mounts'])
            self.assertEqual(new['Config']['Entrypoint'], old['Config']['Entrypoint'])
            self.assertIn('DB_PASSWORD=' + SECRET, new['Config']['Env'])
            self.assertIn('NODE_VERSION=26.12.1', new['Config']['Env'])
        self.assertEqual(m.load('desired', 'node')['images'], self.node_candidates)
        self.assertNotIn(SECRET, json.dumps(m.catalog()))

    def test_any_image_preparation_failure_leaves_entire_group_untouched(self):
        self.node_group(); stored = self.node_stored(); self.prepare_job()
        def build(row, target, directory, source):
            if source != OLD_IMAGE:
                raise m.Rejected('unsupported', 'Fixture build failure', 422)
            return self.node_candidates[source]
        with patch.object(m, 'image_candidate', side_effect=build), patch.object(m, 'node_preflight') as abi, patch.object(m, 'refresh_admission') as admission:
            m.apply_job('job-1', stored)
        abi.assert_not_called(); admission.assert_not_called()
        self.assertEqual(self.docker.rows, self.node_before)
        self.assertFalse(any(method != 'GET' for method, _, _ in self.docker.calls))
        self.assertEqual(m.load('operation', 'job-1')['status'], 'failed')

    def test_incompatible_native_binding_blocks_whole_group_before_any_stop(self):
        self.node_group(); stored = self.node_stored(); self.prepare_job()
        with patch.object(m, 'image_candidate', side_effect=lambda row, target, directory, source: self.node_candidates[source]), patch.object(m, 'node_preflight', side_effect=m.Rejected('unsupported', 'Native ABI incompatible', 422)):
            m.apply_job('job-1', stored)
        self.assertEqual(self.docker.rows, self.node_before)
        self.assertFalse(any(method != 'GET' for method, _, _ in self.docker.calls))

    def test_failure_in_later_service_rolls_back_entire_stateless_family_to_original_ids(self):
        self.node_group(); stored = self.node_stored(); self.prepare_job()
        verify = m.verify
        def verify_until_failure(old, identity, row, version):
            if old['Id'] == 'old-node-2':
                raise m.Rejected('updates_unavailable', 'Third service failure', 503)
            return verify(old, identity, row, version)
        with patch.object(m, 'image_candidate', side_effect=lambda row, target, directory, source: self.node_candidates[source]), patch.object(m, 'node_preflight'), patch.object(m, 'verify', side_effect=verify_until_failure), patch.object(m, 'refresh_admission') as admission:
            m.apply_job('job-1', stored)
        admission.assert_not_called()
        self.assertEqual(m.load('operation', 'job-1')['status'], 'rolled-back')
        self.assertEqual(self.docker.rows, self.node_before)
        self.assertIsNone(m.load('desired', 'node'))

    def test_native_preflight_has_no_service_mounts_or_environment_and_rejects_shadowed_dependencies(self):
        old = container(); old['Config']['WorkingDir'] = '/app'
        with patch.object(m, 'run', return_value=json.dumps({'version': '26.12.1', 'nativeModules': 2})) as command:
            m.node_preflight(old, NEW_IMAGE, '26.12.1')
        args = command.call_args.args[0]
        self.assertIn('--read-only', args); self.assertIn('--cap-drop', args)
        self.assertEqual(args[args.index('--network') + 1], 'none')
        self.assertEqual(args[args.index('--entrypoint') + 1], 'node')
        self.assertNotIn(SECRET, json.dumps(args)); self.assertNotIn('--mount', args); self.assertNotIn('-v', args)
        self.assertIn('require(item)', args[args.index('-e') + 1])
        self.docker.images[NEW_IMAGE] = {'Config': {'Volumes': {'/app': {}}}}
        with patch.object(m, 'run') as command, self.assertRaises(m.Rejected):
            m.node_preflight(old, NEW_IMAGE, '26.12.1')
        command.assert_not_called()

    def test_real_preflight_scanner_never_executes_app_scripts_and_fails_on_bad_native_binding_or_engine(self):
        binary = shutil.which('node')
        if not binary:
            self.skipTest('Node is required to execute the isolated scanner fixture')
        version = subprocess.check_output([binary, '-p', 'process.versions.node'], text=True).strip()
        working = self.root / 'fixture-app'; working.mkdir()
        (working / 'node_modules').mkdir()
        sentinel = working / 'must-not-run'
        manifest = {'scripts': {'preinstall': 'touch ' + str(sentinel)}, 'main': 'must-not-run.js'}
        (working / 'package.json').write_text(json.dumps(manifest))
        (working / 'must-not-run.js').write_text('throw new Error("Application JS must never execute");')
        old = container(); old['Config']['WorkingDir'] = str(working)
        captured = []
        bundled_semver = pathlib.Path(binary).resolve().parent.parent / 'lib/node_modules/npm/node_modules/semver'
        def isolated_scanner(argv, **kwargs):
            script = argv[argv.index('-e') + 1]
            captured.append(script)
            if bundled_semver.is_dir():
                script = script.replace('/usr/local/lib/node_modules/npm/node_modules/semver', str(bundled_semver))
            completed = subprocess.run([binary, '-e', script, version], cwd=working, capture_output=True, text=True, timeout=10)
            if completed.returncode:
                raise m.Rejected('unsupported', 'Fixture isolated ABI/engine check failed', 422)
            return completed.stdout
        with patch.object(m, 'run', side_effect=isolated_scanner):
            m.node_preflight(old, NEW_IMAGE, version)
            (working / 'node_modules' / 'broken.node').write_bytes(b'not a compatible native addon')
            with self.assertRaises(m.Rejected):
                m.node_preflight(old, NEW_IMAGE, version)
            (working / 'node_modules' / 'broken.node').unlink()
            if bundled_semver.is_dir():
                manifest['engines'] = {'node': '>=22'}
                (working / 'package.json').write_text(json.dumps(manifest))
                m.node_preflight(old, NEW_IMAGE, version)
                manifest['engines']['node'] = '<1'
                (working / 'package.json').write_text(json.dumps(manifest))
                with self.assertRaises(m.Rejected):
                    m.node_preflight(old, NEW_IMAGE, version)
            # An invalid declaration fails before semver is loaded, on every host.
            manifest['engines'] = {'node': {'invalid': True}}
            (working / 'package.json').write_text(json.dumps(manifest))
            with self.assertRaises(m.Rejected):
                m.node_preflight(old, NEW_IMAGE, version)
        self.assertFalse(sentinel.exists())
        self.assertIn("require('/usr/local/lib/node_modules/npm/node_modules/semver')", captured[0])

    def test_node_layer_preserves_local_base_npm_and_libatomic_for_each_source_image(self):
        self.node_group()
        target = m.catalog()['components'][0]['candidateRelease']
        directory = self.root / 'candidate'; directory.mkdir()
        with patch.object(m, 'run', return_value=NEW_IMAGE) as command:
            candidate = m.image_candidate(self.config['components'][0], target, directory, OLD_IMAGE)
        self.assertEqual(candidate, NEW_IMAGE)
        dockerfile = (directory / 'Dockerfile').read_text()
        self.assertIn('FROM platform/runtime-base:candidate', dockerfile)
        self.assertNotIn('FROM ' + OLD_IMAGE, dockerfile)
        self.assertIn('cp -L /usr/lib/libatomic.so.1', dockerfile)
        self.assertIn('/usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm', dockerfile)
        self.assertIn('ENV NODE_VERSION=26.12.1', dockerfile)
        self.assertIn(unittest.mock.call(['docker', 'image', 'tag', OLD_IMAGE, 'platform/runtime-base:candidate']), command.call_args_list)

    def test_database_mixed_major_requires_migration_but_same_major_can_align(self):
        self.node_group()
        row = self.config['components'][0]
        row.update(id='postgres', label='PostgreSQL', category='Database', strategy='image', recoveryPolicy='offline-snapshot-v1')
        self.config_path.write_text(json.dumps(self.config))
        for identity, version in zip(self.docker.rows, ['17.4', '18.5', '17.4']):
            self.docker.rows[identity]['Config']['Env'] = ['NODE_VERSION=' + version]
        target = dict(self.release, version='18.5')
        m.save('cache', 'releases', {'checkedAt': m.stamp(), 'components': {'postgres': {'candidateRelease': None, 'latestStable': target}}})
        item = m.catalog()['components'][0]
        self.assertTrue(item['needsAlignment']); self.assertFalse(item['canUpdate'])
        self.assertEqual(item['status'], 'unsupported'); self.assertIn('migrazione', item['blockedReason'])
        for identity, version in zip(self.docker.rows, ['18.4', '18.5', '18.4']):
            self.docker.rows[identity]['Config']['Env'] = ['NODE_VERSION=' + version]
        item = m.catalog()['components'][0]
        self.assertTrue(item['canUpdate']); self.assertEqual(item['candidateRelease']['version'], '18.5')

    def traefik_fixture(self, mounted_routes=True):
        old = self.docker.rows['old-container']
        old['Name'] = '/edge-router'
        old['Config'].update(Entrypoint=['traefik'], Cmd=['--configFile=/etc/traefik/traefik.yml'])
        old['Mounts'] = [{'Type': 'bind', 'Source': '/fixture/' + name, 'Destination': destination, 'RW': False}
                         for name, destination in [('static', '/etc/traefik/traefik.yml'), ('middleware', '/etc/traefik/dynamic/middleware.yml')]]
        if mounted_routes:
            old['Mounts'].append({'Type': 'bind', 'Source': '/fixture/routes', 'Destination': '/etc/traefik/dynamic/routes.yml', 'RW': False})
        old['State']['Health'] = {'Status': 'healthy'}
        self.route_docs = {'/etc/traefik/traefik.yml': 'providers:\n  file:\n    directory: /etc/traefik/dynamic\n',
                           '/etc/traefik/dynamic/middleware.yml': 'http:\n  middlewares: {}\n',
                           '/etc/traefik/dynamic/routes.yml': 'http:\n  routers:\n    portal:\n      rule: "Host(`portal.example.test`)"\n'}
        row = {'id': 'traefik', 'label': 'Traefik', 'category': 'Rete', 'repository': 'library/traefik',
               'strategy': 'image', 'containers': ['edge-router'], 'probe': ['traefik', 'version'],
               'routeProbes': [{'host': 'portal.example.test', 'port': 8080, 'path': '/', 'expectedStatuses': [200, 401]}]}
        self.config['components'] = [row]; self.config_path.write_text(json.dumps(self.config))
        target = dict(self.release, version='3.7.16')
        m.save('cache', 'releases', {'checkedAt': m.stamp(), 'components': {'traefik': {'candidateRelease': target, 'latestStable': target}}})
        def commands(argv, **kwargs):
            self.assertEqual(argv[:2], ['docker', 'exec'])
            if argv[3:] == ['traefik', 'version']:
                return 'Version: ' + ('3.7.16' if argv[2].startswith('new-container') else '3.7.5')
            if argv[3] == 'cat':
                return self.route_docs[argv[4]]
            if argv[3:] == ['find', '/etc/traefik/dynamic', '-type', 'l']:
                return ''
            if argv[3:] == ['find', '/etc/traefik/dynamic', '-type', 'f']:
                return '/etc/traefik/dynamic/middleware.yml\n/etc/traefik/dynamic/routes.yml\n'
            raise AssertionError(argv)
        patch.object(m, 'run', side_effect=commands).start()
        self.http_status = 401
        self.http_requests = []
        self.http_calls = []
        def connection(address, port, timeout):
            self.http_requests.append((address, port))
            client = unittest.mock.Mock()
            client.request.side_effect = lambda method, path, headers: self.http_calls.append((method, path, headers))
            client.getresponse.side_effect = lambda: types.SimpleNamespace(status=self.http_status)
            return client
        patch.object(m.http.client, 'HTTPConnection', side_effect=connection).start()
        return row, old

    def test_traefik_writable_layer_routes_block_plan_and_queued_update_before_stop(self):
        row, old = self.traefik_fixture(mounted_routes=False)
        with self.assertRaises(m.Rejected) as refused:
            m.plan('traefik', m.catalog()['revision'])
        self.assertEqual(refused.exception.status, 422)
        stored = {'component': row, 'target': dict(self.release, version='3.7.16'), 'fingerprint': m.fingerprint([old]),
                  'public': {'affectedServices': ['edge-router']}}
        self.prepare_job()
        with patch.object(m, 'image_candidate') as image, patch.object(m, 'refresh_admission') as admission:
            m.apply_job('job-1', stored)
        image.assert_not_called(); admission.assert_not_called()
        self.assertFalse(any(method != 'GET' for method, _, _ in self.docker.calls))
        self.assertEqual(m.load('operation', 'job-1')['status'], 'failed')

    def test_traefik_file_or_directory_readonly_mounts_and_exact_http_route_are_required(self):
        row, old = self.traefik_fixture()
        checks = m.traefik_routing_configuration(old, row)
        self.assertIn('/etc/traefik/dynamic/routes.yml', checks['files'])
        self.assertEqual(self.http_requests[-1], ('127.0.0.1', 8080))
        self.assertEqual(self.http_calls[-1], ('GET', '/', {'Host': 'portal.example.test', 'Connection': 'close'}))
        old['Mounts'] = [{'Type': 'bind', 'Source': '/fixture/whole-config', 'Destination': '/etc/traefik', 'RW': False}]
        self.assertEqual(m.traefik_routing_configuration(old, row), checks)
        for mutation in [lambda: old['Mounts'][0].update(RW=True),
                         lambda: row['routeProbes'][0].update(host='unknown.example.test'),
                         lambda: row['routeProbes'][0].update(expectedStatuses=[404])]:
            row, old = self.traefik_fixture()
            mutation()
            with self.assertRaises(m.Rejected):
                m.traefik_routing_configuration(old, row)

    def test_traefik_dynamic_file_change_after_plan_prevents_image_preparation(self):
        row, old = self.traefik_fixture()
        public = m.plan('traefik', m.catalog()['revision']); stored = m.load('plan', public['planId'])
        self.route_docs['/etc/traefik/dynamic/routes.yml'] += '# external configuration change\n'
        self.prepare_job()
        with patch.object(m, 'image_candidate') as image:
            m.apply_job('job-1', stored)
        image.assert_not_called()
        self.assertFalse(any(method != 'GET' for method, _, _ in self.docker.calls))

    def test_traefik_healthy_ping_with_portal_404_rolls_back_instead_of_claiming_success(self):
        row, old = self.traefik_fixture()
        public = m.plan('traefik', m.catalog()['revision']); stored = m.load('plan', public['planId'])
        self.prepare_job(); verify = m.verify
        def check_router(*args):
            self.http_status = 404
            return verify(*args)
        with patch.object(m, 'image_candidate', return_value=NEW_IMAGE), patch.object(m, 'verify', side_effect=check_router), patch.object(m.time, 'sleep'), patch.object(m, 'refresh_admission') as admission:
            m.apply_job('job-1', stored)
        admission.assert_not_called()
        record = m.load('operation', 'job-1')
        self.assertEqual(record['status'], 'rolled-back')
        self.assertEqual(self.docker.inspect('edge-router')['Id'], 'old-container')
        self.assertTrue(self.docker.inspect('edge-router')['State']['Running'])

    def test_traefik_preserved_routes_and_expected_portal_401_allow_verified_commit(self):
        row, old = self.traefik_fixture()
        public = m.plan('traefik', m.catalog()['revision']); stored = m.load('plan', public['planId'])
        self.prepare_job()
        with patch.object(m, 'image_candidate', return_value=NEW_IMAGE), patch.object(m, 'refresh_admission') as admission:
            m.apply_job('job-1', stored)
        admission.assert_called_once()
        self.assertEqual(m.load('operation', 'job-1')['status'], 'succeeded')
        self.assertNotEqual(self.docker.inspect('edge-router')['Id'], 'old-container')

    def batch_fixture(self):
        self.node_group()
        php = container(); php['Image'] = 'sha256:' + 'e' * 64; php['Config']['Image'] = php['Image']
        self.docker.rows[php['Id']] = php
        self.batch_php_before = copy.deepcopy(php)
        self.config['components'].append({'id': 'php', 'label': 'PHP', 'category': 'Runtime', 'containers': ['php-service'], 'strategy': 'image', 'versionEnv': 'PHP_VERSION', 'probe': ['php', '-r', 'echo PHP_VERSION;']})
        self.config_path.write_text(json.dumps(self.config))
        cached = m.load('cache', 'releases')
        cached['components']['php'] = {'candidateRelease': self.release, 'latestStable': self.release}
        m.save('cache', 'releases', cached)
        self.batch_php_candidate = 'sha256:' + 'f' * 64
        self.docker.images[self.batch_php_candidate] = {'Id': self.batch_php_candidate, 'Config': {'Env': ['PHP_VERSION=8.5.12']}}
        public = m.handle({'action': 'plan', 'componentId': 'all', 'revision': m.catalog()['revision']})
        return m.load('plan', public['planId'])

    def batch_build(self, row, target, directory, source=None):
        return self.node_candidates[source] if row['id'] == 'node' else self.batch_php_candidate

    def test_legacy_intermediate_cache_cannot_override_latest_direct_catalog_target(self):
        self.docker.rows['old-container']['Config']['Env'] = ['PHP_VERSION=8.6.7']
        intermediate = dict(self.release, version='8.6.8')
        latest = dict(self.release, version='8.10.3')
        for candidate in [intermediate, None]:
            with self.subTest(candidate=candidate):
                m.save('cache', 'releases', {'checkedAt': m.stamp(), 'components': {'php': {'candidateRelease': candidate, 'latestStable': latest}}})
                item = m.catalog()['components'][0]
                self.assertTrue(item['canUpdate'])
                self.assertEqual(item['candidateRelease'], latest)
                self.assertEqual(self.stored()['public']['targetVersion'], '8.10.3')
        m.save('cache', 'releases', {'checkedAt': m.stamp(), 'components': {'php': {'candidateRelease': intermediate, 'latestStable': None}}})
        self.assertFalse(m.catalog()['components'][0]['canUpdate'])
        self.assertIsNone(m.catalog()['components'][0]['candidateRelease'])

    def test_cached_database_major_and_dedicated_builds_remain_explicitly_blocked(self):
        self.docker.rows['old-container']['Config']['Env'] = ['PHP_VERSION=8.6.7']
        latest = dict(self.release, version='9.0.0')
        for category, repository in [('Database', 'example/database'), ('Runtime', 'library/redis')]:
            self.config['components'][0].update(category=category, repository=repository, recoveryPolicy='offline-snapshot-v1')
            self.config_path.write_text(json.dumps(self.config))
            for candidate in [None, dict(self.release, version='8.6.8')]:
                m.save('cache', 'releases', {'checkedAt': m.stamp(), 'components': {'php': {'candidateRelease': candidate, 'latestStable': latest}}})
                item = m.catalog()['components'][0]
                self.assertFalse(item['canUpdate']); self.assertIsNone(item['candidateRelease'])
                self.assertEqual(item['status'], 'unsupported'); self.assertIn('migrazione', item['blockedReason'])
        self.config['components'][0].update(category='Runtime', repository='example/dedicated', strategy='observe', blockedReason='Builder dedicato: manutenzione assistita.')
        self.config_path.write_text(json.dumps(self.config))
        item = m.catalog()['components'][0]
        self.assertFalse(item['canUpdate']); self.assertIsNone(item['candidateRelease'])
        self.assertEqual(item['blockedReason'], 'Builder dedicato: manutenzione assistita.')

    def test_batch_plan_binds_all_eligible_families_and_no_arbitrary_selection(self):
        stored = self.batch_fixture(); public = stored['public']
        self.assertEqual(public['componentId'], 'all'); self.assertEqual(public['kind'], 'batch')
        self.assertEqual([x['id'] for x in public['components']], ['node', 'php'])
        self.assertEqual(len(public['affectedServices']), 4)
        self.assertEqual(public['targetDigest'], 'sha256:' + m.digest(public['components']))
        self.assertNotIn(SECRET, json.dumps(public))
        with self.assertRaises(m.Rejected) as invalid:
            m.handle({'action': 'plan', 'componentId': 'all', 'revision': public['revision'], 'components': ['node']})
        self.assertEqual(invalid.exception.status, 400)
        self.docker.rows['old-container']['HostConfig']['Memory'] += 1024
        with patch.object(m.EXECUTOR, 'submit') as executor, self.assertRaises(m.Rejected) as stale:
            m.handle(dict(self.apply_body(public), componentId='all'))
        self.assertEqual(stale.exception.code, 'stale_revision'); executor.assert_not_called()

    def test_batch_no_eligible_updates_rejects_without_a_job(self):
        self.docker.rows['old-container']['Config']['Env'] = ['PHP_VERSION=8.5.12']
        with self.assertRaises(m.Rejected) as result:
            m.handle({'action': 'plan', 'componentId': 'all', 'revision': m.catalog()['revision']})
        self.assertEqual(result.exception.status, 422)
        self.assertEqual(m.records('operation'), [])

    def test_batch_idempotency_and_service_inventory_are_durable_before_scheduling(self):
        stored = self.batch_fixture(); public = stored['public']; seen = []
        def schedule(function, identity, plan):
            record = m.load('operation', identity)
            with m.db() as connection:
                prior = connection.execute('SELECT job FROM idempotency WHERE id=?', ('batch-request',)).fetchone()
            seen.append((record, prior['job']))
        body = dict(self.apply_body(public, 'batch-request'), componentId='all')
        with patch.object(m.EXECUTOR, 'submit', side_effect=schedule) as executor:
            first = m.handle(body); second = m.handle(body)
        self.assertEqual(first, second); executor.assert_called_once()
        record, job = seen[0]
        self.assertEqual(job, first['operationId']); self.assertEqual(record['totalServices'], 4)
        self.assertEqual(record['completedServices'], 0)
        self.assertEqual(len(record['serviceResults']), 4)
        self.assertTrue(all(x['status'] == 'queued' for x in record['serviceResults']))
        self.assertNotIn(SECRET, json.dumps(record))

    def test_batch_prepares_every_family_before_first_stop_and_reports_each_service(self):
        stored = self.batch_fixture(); self.prepare_job()
        builds, checks, updates = [], [], []
        recreate = m.recreate
        def build(*args):
            self.assertFalse(any(method != 'GET' for method, _, _ in self.docker.calls))
            builds.append(args[0]['id'])
            return self.batch_build(*args)
        def preflight(old, *args):
            checks.append(old['Id'])
        def update(*args, **kwargs):
            self.assertEqual(builds, ['node', 'node', 'php']); self.assertEqual(len(checks), 3)
            record = m.load('operation', 'job-1')
            self.assertEqual(record['currentService'], args[0]['Name'].lstrip('/'))
            updates.append(record['currentService'])
            return recreate(*args, **kwargs)
        with patch.object(m, 'image_candidate', side_effect=build), patch.object(m, 'node_preflight', side_effect=preflight), patch.object(m, 'recreate', side_effect=update), patch.object(m, 'refresh_admission') as admission:
            m.apply_job('job-1', stored)
        record = m.load('operation', 'job-1')
        self.assertEqual(record['status'], 'succeeded'); self.assertEqual(admission.call_count, 2)
        self.assertEqual(record['completedServices'], 4); self.assertEqual(record['totalServices'], 4)
        self.assertEqual(record['completedSteps'], 4); self.assertEqual(record['totalSteps'], 4)
        self.assertEqual(len(updates), 4); self.assertIsNone(record['currentService'])
        self.assertTrue(all(x['status'] == 'succeeded' for x in record['serviceResults']))
        self.assertTrue(all(x['status'] == 'succeeded' for x in record['componentResults']))
        self.assertNotIn(SECRET, json.dumps(record))

    def test_batch_detects_later_family_drift_before_building_any_image(self):
        stored = self.batch_fixture(); self.prepare_job()
        self.docker.rows['old-container']['HostConfig']['Memory'] += 1024
        with patch.object(m, 'image_candidate') as build, patch.object(m, 'refresh_admission') as admission:
            m.apply_job('job-1', stored)
        build.assert_not_called(); admission.assert_not_called()
        self.assertFalse(any(method != 'GET' for method, _, _ in self.docker.calls))
        self.assertEqual(m.load('operation', 'job-1')['status'], 'failed')

    def test_signed_unix_http_supports_batch_plan_apply_and_durable_service_readback(self):
        self.batch_fixture(); _, request = self.http_server()
        status, catalog = request({'action': 'catalog'})
        self.assertEqual(status, 200)
        status, public = request({'action': 'plan', 'componentId': 'all', 'revision': catalog['revision']})
        self.assertEqual(status, 200); self.assertEqual(public['kind'], 'batch')
        with patch.object(m.EXECUTOR, 'submit') as executor:
            status, accepted = request(dict(self.apply_body(public, 'http-batch'), componentId='all'))
        self.assertEqual(status, 200); executor.assert_called_once()
        status, record = request({'action': 'operation', 'operationId': accepted['operationId']})
        self.assertEqual(status, 200); self.assertEqual(record['status'], 'queued')
        self.assertEqual(record['totalServices'], 4); self.assertEqual(len(record['serviceResults']), 4)
        self.assertNotIn(SECRET, json.dumps(record))

    def test_later_family_build_failure_prevents_every_service_mutation(self):
        stored = self.batch_fixture(); self.prepare_job()
        def build(*args):
            if args[0]['id'] == 'php':
                raise m.Rejected('unsupported', 'Fixture second family preparation failure', 422)
            return self.batch_build(*args)
        before = copy.deepcopy(self.docker.rows)
        with patch.object(m, 'image_candidate', side_effect=build), patch.object(m, 'node_preflight'), patch.object(m, 'refresh_admission') as admission:
            m.apply_job('job-1', stored)
        self.assertEqual(self.docker.rows, before); admission.assert_not_called()
        self.assertFalse(any(method != 'GET' for method, _, _ in self.docker.calls))
        record = m.load('operation', 'job-1')
        self.assertEqual(record['status'], 'failed'); self.assertEqual(record['completedServices'], 0)
        self.assertTrue(all(x['status'] == 'skipped' for x in record['serviceResults']))

    def test_batch_later_family_failure_keeps_prior_success_and_restores_only_current_family(self):
        stored = self.batch_fixture(); self.prepare_job()
        deferred = copy.deepcopy(stored['families'][-1])
        deferred['component'].update(id='zzz', label='Deferred runtime', containers=['deferred-service'])
        deferred['public'].update(componentId='zzz', affectedServices=['deferred-service'])
        old_deferred = copy.deepcopy(self.batch_php_before)
        old_deferred.update(Id='old-deferred', Name='/deferred-service')
        self.docker.rows['old-deferred'] = copy.deepcopy(old_deferred)
        deferred['fingerprint'] = m.fingerprint([old_deferred])
        stored['families'].append(deferred)
        verify = m.verify
        def verify_services(old, identity, row, version):
            if row['id'] == 'php':
                raise m.Rejected('updates_unavailable', 'Fixture later family failure', 503)
            return verify(old, identity, row, version)
        with patch.object(m, 'image_candidate', side_effect=self.batch_build), patch.object(m, 'node_preflight'), patch.object(m, 'verify', side_effect=verify_services), patch.object(m, 'refresh_admission') as admission:
            m.apply_job('job-1', stored)
        admission.assert_called_once()
        record = m.load('operation', 'job-1')
        self.assertEqual(record['status'], 'failed'); self.assertEqual(record['completedServices'], 3)
        self.assertEqual(record['componentResults'], [{'componentId': 'node', 'status': 'succeeded'}, {'componentId': 'php', 'status': 'failed'}, {'componentId': 'zzz', 'status': 'skipped'}])
        self.assertEqual(record['serviceResults'][-2]['status'], 'rolled-back')
        self.assertEqual(record['serviceResults'][-1]['status'], 'skipped')
        self.assertEqual(self.docker.rows['old-deferred'], old_deferred)
        self.assertEqual(self.docker.rows['old-container'], self.batch_php_before)
        for old in self.node_before.values():
            self.assertNotEqual(self.docker.inspect(old['Name'])['Id'], old['Id'])
        self.assertIsNotNone(m.load('desired', 'node')); self.assertIsNone(m.load('desired', 'php'))

    def test_batch_data_failure_never_downgrades_newly_started_database(self):
        stored = self.batch_fixture(); stored['families'][-1]['component'].update(category='Database', recoveryPolicy='offline-snapshot-v1')
        self.prepare_job(); verify = m.verify
        def verify_services(old, identity, row, version):
            if row['id'] == 'php':
                raise m.Rejected('updates_unavailable', 'Fixture database failure', 503)
            return verify(old, identity, row, version)
        with patch.object(m, 'image_candidate', side_effect=self.batch_build), patch.object(m, 'node_preflight'), patch.object(m, 'snapshot_database'), patch.object(m, 'verify', side_effect=verify_services), patch.object(m, 'refresh_admission'):
            m.apply_job('job-1', stored)
        record = m.load('operation', 'job-1')
        self.assertEqual(record['status'], 'failed'); self.assertTrue(record['recoveryRequired'])
        self.assertEqual(record['completedServices'], 3)
        self.assertFalse(self.docker.rows['old-container']['State']['Running'])
        self.assertNotIn(('POST', '/containers/old-container/start', None), self.docker.calls)
        self.assertTrue(m.recovery_required())

    def test_restart_recovery_finds_batch_family_journal_and_retains_prior_results(self):
        stored = self.batch_fixture(); self.prepare_job(); verify = m.verify
        def crash(old, identity, row, version):
            if row['id'] == 'php':
                raise SystemExit('Fixture worker crash')
            return verify(old, identity, row, version)
        with patch.object(m, 'image_candidate', side_effect=self.batch_build), patch.object(m, 'node_preflight'), patch.object(m, 'verify', side_effect=crash), patch.object(m, 'refresh_admission'), self.assertRaises(SystemExit):
            m.apply_job('job-1', stored)
        self.assertTrue((self.state / 'job-1' / 'rollback.json').exists())
        self.assertTrue((self.state / 'job-1' / 'php' / 'rollback.json').exists())
        m.initialize(); record = m.load('operation', 'job-1')
        self.assertEqual(record['status'], 'interrupted'); self.assertTrue(record['recoveryRequired'])
        self.assertEqual(record['componentResults'][0], {'componentId': 'node', 'status': 'succeeded'})
        self.assertEqual(record['completedServices'], 3)

    def host_fixture(self, reboot=True):
        self.host_inventory = {'bootId': 'fixture-boot-before', 'rebootRequired': reboot, 'rebootPackages': ['fixture-package'], 'maintenanceRunning': False}
        self.host_check_result = {**self.host_inventory, 'checkedAt': int(time.time()),
                                  'packages': [{'name': 'fixture-package', 'currentVersion': '1.0', 'targetVersion': '1.1'}],
                                  'keptBack': ['fixture-held'], 'installedFingerprint': 'a' * 64, 'candidateFingerprint': 'b' * 64}
        m.save('cache', 'host-releases', self.host_check_result)
        self.host = unittest.mock.Mock()
        self.host.worker_status.return_value = None
        self.host.worker_alive.return_value = False
        self.host.HostUpdateError = type('FixtureHostError', (RuntimeError,), {})
        self.host.inventory.side_effect = lambda: copy.deepcopy(self.host_inventory)
        def native_plan(value=None):
            return {'planId': uuid.uuid4().hex, 'expiresAt': int(time.time()) + 300,
                    'bootId': self.host_inventory['bootId'], 'packages': value['packages'] if value else [],
                    'steps': ['Prepare', 'Verify'], 'risks': ['Services restart'], 'confirmationRequired': 'UPDATE' if value else 'REBOOT'}
        self.host.plan.side_effect = native_plan
        self.host.reboot_plan.side_effect = native_plan
        def prepare(value, persist, confirmation):
            self.assertEqual(confirmation, 'REBOOT')
            intent = {'schema': 'platform-host-reboot-intent/v1', 'state': 'queued', 'bootIdBefore': value['bootId'], 'planId': value['planId']}
            persist(intent); return intent
        self.host.prepare_reboot.side_effect = prepare
        self.host.schedule_reboot.side_effect = lambda intent: {**intent, 'state': 'waiting-reboot'}
        def reconcile(intent, health_check=None):
            if self.host_inventory['bootId'] == intent['bootIdBefore']:
                return {**intent, 'state': 'waiting-reboot'}
            healthy = health_check()
            return {**intent, 'bootIdAfter': self.host_inventory['bootId'], 'state': 'succeeded' if healthy else 'verifying-services'}
        self.host.reconcile_reboot.side_effect = reconcile
        patch.object(m, 'host_updates', self.host).start()
        patch.object(m, 'host_os_release', return_value={'id': 'ubuntu', 'name': 'Ubuntu', 'version': '24.04', 'kernel': 'fixture-kernel'}).start()
        return self.host

    def host_public_plan(self, reboot=False):
        return m.handle({'action': 'host-reboot-plan' if reboot else 'host-plan', 'revision': m.host_catalog()['revision']})

    def host_apply_body(self, public, reboot=False):
        return {'action': 'host-reboot-apply' if reboot else 'host-apply', 'revision': public['revision'], 'planId': public['planId'],
                'confirmation': 'REBOOT' if reboot else 'UPDATE', 'idempotencyKey': 'fixture-host-request'}

    def test_host_public_catalog_and_plan_expose_counts_without_package_arrays_or_apt_writes(self):
        host = self.host_fixture(); catalog = m.handle({'action': 'host-catalog'})
        self.assertEqual(catalog['schema'], 'host-updates/v1'); self.assertEqual(catalog['updateCount'], 1)
        self.assertEqual(catalog['keptBackCount'], 1); self.assertTrue(catalog['canApply'])
        public = self.host_public_plan()
        self.assertEqual(public['kind'], 'host-upgrade'); self.assertEqual(public['packageCount'], 1)
        self.assertNotIn('fixture-package', json.dumps(catalog) + json.dumps(public))
        self.assertNotIn('packages', public)
        self.assertEqual(m.load('host-plan', public['planId'])['native']['packages'], self.host_check_result['packages'])
        host.plan.assert_called_once_with(self.host_check_result); host.run_transient.assert_not_called()

    def test_host_catalog_and_runtime_catalog_keep_operation_streams_separate(self):
        self.host_fixture()
        m.save('operation', 'runtime-record', {'id': 'runtime-record', 'kind': 'apply', 'status': 'succeeded'})
        m.save('operation', 'os-record', {'id': 'os-record', 'kind': 'host-check', 'status': 'succeeded'})
        self.assertEqual([item['id'] for item in m.catalog()['operations']], ['runtime-record'])
        self.assertEqual([item['id'] for item in m.host_catalog()['operations']], ['os-record'])

    def test_host_cleanup_only_plan_exposes_counts_and_binds_automatic_package_state(self):
        host = self.host_fixture(reboot=False)
        self.host_check_result.update(packages=[], autoremove=[{'name': 'unused-fixture', 'installedVersion': '1'}],
                                      autoremoveFingerprint='c' * 64, automaticFingerprint='d' * 64, protectedPackageFingerprint='e' * 64)
        m.save('cache', 'host-releases', self.host_check_result)
        original = host.plan.side_effect
        host.plan.side_effect = lambda value: {**original(value), 'autoremove': value['autoremove']}
        catalog = m.host_catalog(); public = self.host_public_plan()
        self.assertEqual(catalog['updateCount'], 0); self.assertEqual(catalog['autoremoveCount'], 1); self.assertTrue(catalog['canApply'])
        self.assertEqual(public['packageCount'], 0); self.assertEqual(public['autoremoveCount'], 1)
        self.assertNotIn('unused-fixture', json.dumps(public) + json.dumps(catalog))
        self.host_check_result['automaticFingerprint'] = 'f' * 64
        m.save('cache', 'host-releases', self.host_check_result)
        self.assertNotEqual(catalog['revision'], m.host_catalog()['revision'])

    def test_host_success_requires_verified_autoremove_and_exact_removed_count(self):
        native = {'planId': 'host-fixture', 'packages': [], 'autoremove': [{'name': 'unused-fixture', 'installedVersion': '1'}]}
        result = {'planId': 'host-fixture', 'state': 'succeeded', 'packages': [], 'packageVersionsVerified': True,
                  'dpkgAuditClean': True, 'marksRestored': True, 'autoremoveVerified': True, 'removedCount': 1}
        self.assertTrue(m.verify_host_result(native, result))
        for changes in [{'autoremoveVerified': False}, {'removedCount': 0}, {'removedCount': True}]:
            self.assertFalse(m.verify_host_result(native, {**result, **changes}))

    def test_host_autoremove_progress_never_recedes_or_claims_completion_before_verification(self):
        self.prepare_job()
        m.host_progress('job-1', 'host-upgrade', {'stage': 'packages', 'percent': 83})
        m.host_progress('job-1', 'host-upgrade', {'stage': 'autoremove', 'percent': 0})
        self.assertEqual(m.load('operation', 'job-1')['completedSteps'], 83)
        self.assertIn('dipendenze', m.load('operation', 'job-1')['stage'])
        m.host_progress('job-1', 'host-upgrade', {'stage': 'verify-autoremove', 'percent': 100})
        self.assertEqual(m.load('operation', 'job-1')['completedSteps'], 99)

    def test_host_apply_is_idempotent_durable_and_uses_one_global_executor(self):
        self.host_fixture(); public = self.host_public_plan(); seen = []
        def scheduled(function, identity, kind, stored):
            with m.db() as connection:
                prior = connection.execute('SELECT job FROM idempotency WHERE id=?', ('fixture-host-request',)).fetchone()
            seen.append((m.load('operation', identity), prior['job'], function, kind))
        with patch.object(m.EXECUTOR, 'submit', side_effect=scheduled) as executor:
            first = m.handle(self.host_apply_body(public)); second = m.handle(self.host_apply_body(public))
        self.assertEqual(first, second); executor.assert_called_once()
        record, binding, function, kind = seen[0]
        self.assertEqual(binding, record['id']); self.assertEqual(function, m.host_job); self.assertEqual(kind, 'host-upgrade')
        with self.assertRaises(m.Rejected) as blocked:
            m.handle({'action': 'check'})
        self.assertEqual(blocked.exception.code, 'operation_conflict')
        self.host.run_transient.assert_not_called()

    def test_host_schema_confirmation_stale_expiry_and_cross_kind_replay_fail_before_scheduling(self):
        self.host_fixture(); public = self.host_public_plan()
        body = self.host_apply_body(public)
        with patch.object(m.EXECUTOR, 'submit') as executor:
            for change in [{'command': 'apt-get upgrade'}, {'confirmation': 'REBOOT'}, {'revision': 'changed'}]:
                with self.subTest(change=change), self.assertRaises(m.Rejected):
                    m.handle({**body, **change})
            executor.assert_not_called()
            stored = m.load('host-plan', public['planId']); stored['native']['expiresAt'] = int(time.time()) - 1
            m.save('host-plan', public['planId'], stored)
            with self.assertRaises(m.Rejected) as expired:
                m.handle(body)
            self.assertEqual(expired.exception.status, 410)

    def test_host_upgrade_dispatches_fixed_transient_worker_and_real_progress_without_docker_apply(self):
        host = self.host_fixture(); public = self.host_public_plan(); stored = m.load('host-plan', public['planId'])
        identity = uuid.uuid4().hex
        m.save('operation', identity, {'id': identity, 'kind': 'host-upgrade', 'status': 'queued', 'stage': 'Queued', 'completedSteps': 0, 'totalSteps': 100})
        host.write_plan_file.return_value = '/fixture/root-only-plan.json'
        def transient(action, **kwargs):
            self.assertEqual(action, 'apply'); self.assertEqual(kwargs['plan_file'], '/fixture/root-only-plan.json')
            kwargs['progress']({'stage': 'upgrade', 'state': 'running'})
            kwargs['progress']({'stage': 'packages', 'percent': 37.5, 'package': 'fixture-package', 'state': 'running'})
            self.assertEqual(m.load('operation', identity)['completedSteps'], 37)
            return {'state': 'succeeded', 'planId': stored['native']['planId'],
                    'packages': [{**item, 'state': 'succeeded'} for item in self.host_check_result['packages']], 'rebootRequired': True,
                    'packageVersionsVerified': True, 'dpkgAuditClean': True, 'marksRestored': True}
        host.run_transient.side_effect = transient
        with patch.object(m, 'apply_job') as docker_apply:
            m.host_job(identity, 'host-upgrade', stored)
        docker_apply.assert_not_called(); host.write_plan_file.assert_called_once_with(stored['native'])
        record = m.load('operation', identity)
        self.assertEqual(record['status'], 'succeeded'); self.assertEqual(record['completedSteps'], 100)
        self.assertTrue(record['rebootRequired']); self.assertNotIn('fixture-package', json.dumps(record))

    def test_failed_host_upgrade_never_claims_docker_rollback_and_requires_apt_recovery(self):
        host = self.host_fixture(); public = self.host_public_plan(); identity = uuid.uuid4().hex
        m.save('operation', identity, {'id': identity, 'kind': 'host-upgrade', 'status': 'queued', 'stage': 'Queued', 'completedSteps': 0, 'totalSteps': 100})
        def failing(action, **kwargs):
            kwargs['progress']({'stage': 'upgrade'})
            raise host.HostUpdateError(SECRET)
        host.run_transient.side_effect = failing
        m.host_job(identity, 'host-upgrade', m.load('host-plan', public['planId']))
        record = m.load('operation', identity)
        self.assertEqual(record['status'], 'failed'); self.assertTrue(record['recoveryRequired'])
        self.assertNotIn(SECRET, json.dumps(record)); self.assertIn('APT', record['stage'])
        self.assertFalse(any(method != 'GET' for method, _, _ in self.docker.calls))

    def test_reboot_intent_persists_before_ack_and_is_scheduled_once_only_after_callback(self):
        host = self.host_fixture(); public = self.host_public_plan(reboot=True); callbacks = []
        with patch.object(m.EXECUTOR, 'submit') as executor:
            accepted = m.handle(self.host_apply_body(public, reboot=True), after_response=callbacks.append)
            private = m.load('host-reboot', accepted['operationId'])
            self.assertFalse(private['acknowledged']); self.assertEqual(private['intent']['state'], 'queued')
            executor.assert_not_called(); host.schedule_reboot.assert_not_called()
            self.assertEqual(len(callbacks), 1)
            callbacks[0](); callbacks[0]()
            executor.assert_called_once_with(m.host_reboot_job, accepted['operationId'])
        self.assertTrue(m.load('host-reboot', accepted['operationId'])['acknowledged'])
        m.host_reboot_job(accepted['operationId'])
        host.schedule_reboot.assert_called_once()
        self.assertEqual(m.load('operation', accepted['operationId'])['status'], 'running')

    def test_reboot_wrong_confirmation_or_upgrade_action_cannot_ack_existing_reboot_intent(self):
        self.host_fixture(); public = self.host_public_plan(reboot=True); callbacks = []
        m.handle(self.host_apply_body(public, reboot=True), after_response=callbacks.append)
        body = self.host_apply_body(public, reboot=True)
        with self.assertRaises(m.Rejected):
            m.handle({**body, 'confirmation': 'UPDATE'}, after_response=callbacks.append)
        with self.assertRaises(m.Rejected):
            m.handle({**body, 'action': 'host-apply', 'confirmation': 'UPDATE'}, after_response=callbacks.append)
        self.assertEqual(len(callbacks), 1)

    def test_reboot_reconciles_only_new_boot_and_all_previous_running_services_healthy(self):
        self.host_fixture(); public = self.host_public_plan(reboot=True); callbacks = []
        accepted = m.handle(self.host_apply_body(public, reboot=True), after_response=callbacks.append)
        with patch.object(m.EXECUTOR, 'submit'):
            callbacks[0]()
        m.initialize(); m.reconcile_host_reboots(force=True)
        self.assertEqual(m.load('operation', accepted['operationId'])['status'], 'running')
        self.host_inventory['bootId'] = 'fixture-boot-after'
        self.docker.rows['old-container']['State']['Running'] = False
        m.reconcile_host_reboots(force=True)
        self.assertEqual(m.load('operation', accepted['operationId'])['completedSteps'], 2)
        self.docker.rows['old-container']['State']['Running'] = True
        m.reconcile_host_reboots(force=True)
        record = m.load('operation', accepted['operationId'])
        self.assertEqual(record['status'], 'succeeded'); self.assertEqual(record['completedSteps'], 3)

    def test_reboot_scheduler_runs_after_http_response_body_flush_and_never_before(self):
        self.host_fixture(); public = self.host_public_plan(reboot=True)
        events, scheduled = [], threading.Event()
        class Handler(m.Handler):
            def do_POST(self):
                stream = self.wfile
                class Writer:
                    def write(self, value):
                        events.append('write'); return stream.write(value)
                    def flush(self):
                        events.append('flush'); return stream.flush()
                    def __getattr__(self, key):
                        return getattr(stream, key)
                self.wfile = Writer()
                return super().do_POST()
        _, request = self.http_server(Handler)
        def schedule(function, identity):
            events.append('schedule')
            self.assertTrue(m.load('host-reboot', identity)['acknowledged'])
            scheduled.set()
        with patch.object(m.EXECUTOR, 'submit', side_effect=schedule):
            status, accepted = request(self.host_apply_body(public, reboot=True))
            self.assertTrue(scheduled.wait(1))
        self.assertEqual(status, 200); self.assertEqual(accepted['status'], 'queued')
        index = events.index('schedule')
        self.assertEqual(events[index - 1], 'flush')
        self.host.schedule_reboot.assert_not_called()

    def test_failed_http_flush_retains_intent_without_scheduling_or_acknowledgment(self):
        self.host_fixture(); public = self.host_public_plan(reboot=True)
        handler = m.Handler.__new__(m.Handler)
        body = self.host_apply_body(public, reboot=True)
        raw = m.encode({'body': body, 'timestamp': int(time.time() * 1000), 'nonce': uuid.uuid4().hex})
        key = b'x' * 32
        handler.connection = unittest.mock.Mock()
        handler.server = types.SimpleNamespace(key=key)
        handler.headers = {'Content-Length': str(len(raw)), 'x-platform-signature': hmac.new(key, raw, hashlib.sha256).hexdigest()}
        handler.path = '/v1/updates'; handler.rfile = io.BytesIO(raw)
        class BrokenWriter(io.BytesIO):
            def flush(self):
                raise BrokenPipeError('fixture response delivery failed')
        handler.wfile = BrokenWriter()
        handler.send_response = handler.send_header = handler.end_headers = unittest.mock.Mock()
        with patch.object(m.EXECUTOR, 'submit') as executor, self.assertRaises(BrokenPipeError):
            handler.do_POST()
        executor.assert_not_called(); self.host.schedule_reboot.assert_not_called()
        record = next(item for item in m.records('operation') if item['kind'] == 'host-reboot')
        self.assertFalse(m.load('host-reboot', record['id'])['acknowledged'])
        m.initialize(); m.reconcile_host_reboots(force=True)
        self.assertEqual(m.load('operation', record['id'])['status'], 'queued')

    def durable_host_upgrade(self):
        self.host_fixture(); public = self.host_public_plan()
        with patch.object(m.EXECUTOR, 'submit'):
            accepted = m.handle(self.host_apply_body(public))
        identity = accepted['operationId']
        m.operation_update(identity, status='running', completedSteps=96, totalSteps=100)
        native = m.load('host-plan', public['planId'])['native']
        execution = m.load('host-execution', identity)
        execution.update(services=m.snapshot_running_services(), dispatched=True)
        m.save('host-execution', identity, execution)
        result = {'state': 'succeeded', 'planId': native['planId'], 'packages': [{**item, 'state': 'succeeded'} for item in native['packages']],
                  'packageVersionsVerified': True, 'dpkgAuditClean': True, 'marksRestored': True, 'rebootRequired': True}
        self.host_spool = {'schema': 'platform-host-worker-status/v1', 'operationId': identity, 'action': 'apply', 'planId': native['planId'],
                           'state': 'running', 'progress': {'stage': 'packages', 'percent': 96}, 'updatedAt': int(time.time()), 'result': result}
        self.host.worker_status.side_effect = lambda value: copy.deepcopy(self.host_spool)
        return identity, public, native

    def test_restart_retains_running_host_upgrade_with_durable_progress_and_never_reissues_apt(self):
        identity, public, native = self.durable_host_upgrade()
        self.host.worker_alive.return_value = True
        m.initialize()
        record = m.load('operation', identity)
        self.assertEqual(record['status'], 'running'); self.assertEqual(record['completedSteps'], 96)
        self.assertFalse(record['recoveryRequired']); self.assertTrue(m.host_catalog()['busy'])
        self.host.run_transient.assert_not_called()
        self.host_spool['progress']['percent'] = 97
        m.operation_update(identity, lastHostReconcileAt=0)
        record = m.handle({'action': 'operation', 'operationId': identity})
        self.assertEqual(record['completedSteps'], 97); self.assertEqual(record['status'], 'running')
        self.host.run_transient.assert_not_called()

    def test_missing_consumer_output_recovers_from_complete_persisted_worker_result(self):
        identity, public, native = self.durable_host_upgrade()
        self.host_spool['state'] = 'succeeded'
        self.host.run_transient.side_effect = self.host.HostUpdateError('consumer disappeared')
        m.host_job(identity, 'host-upgrade', m.load('host-plan', public['planId']))
        record = m.load('operation', identity)
        self.assertEqual(record['status'], 'succeeded'); self.assertEqual(record['completedSteps'], 100)
        self.assertFalse(record['recoveryRequired']); self.assertIsNone(record['error'])
        self.host.run_transient.assert_called_once()
        self.assertFalse(any(method != 'GET' for method, _, _ in self.docker.calls))

    def test_running_worker_survives_consumer_exception_without_false_failed_operation(self):
        identity, public, native = self.durable_host_upgrade()
        self.host.worker_alive.return_value = True
        self.host.run_transient.side_effect = self.host.HostUpdateError('broken pipe')
        m.host_job(identity, 'host-upgrade', m.load('host-plan', public['planId']))
        self.assertEqual(m.load('operation', identity)['status'], 'running')
        self.assertEqual(m.load('operation', identity)['completedSteps'], 96)
        self.host.run_transient.assert_called_once()

    def test_only_exact_all_package_targets_clean_dpkg_and_restored_marks_clear_recovery(self):
        identity, public, native = self.durable_host_upgrade()
        self.host_spool['state'] = 'succeeded'
        good = copy.deepcopy(self.host_spool['result'])
        cases = [{**good, key: False} for key in ['packageVersionsVerified', 'dpkgAuditClean', 'marksRestored']]
        cases += [{**good, 'packages': []}, {**good, 'packages': [{**good['packages'][0], 'targetVersion': 'wrong'}]}, {**good, 'planId': 'wrong-plan'}]
        for result in cases:
            with self.subTest(result=result):
                self.host_spool['result'] = result
                m.operation_update(identity, status='interrupted', recoveryRequired=True, lastHostReconcileAt=0)
                m.reconcile_host_jobs(force=True)
                record = m.load('operation', identity)
                self.assertNotEqual(record['status'], 'succeeded'); self.assertTrue(record['recoveryRequired'])
        self.host_spool['result'] = good
        m.reconcile_host_jobs(force=True)
        self.assertEqual(m.load('operation', identity)['status'], 'succeeded')
        self.assertFalse(m.load('operation', identity)['recoveryRequired'])
        self.host.run_transient.assert_not_called()

    def test_old_bridge_job_recovers_plan_binding_and_live_worker_without_a_new_dispatch(self):
        identity, public, native = self.durable_host_upgrade()
        with m.db() as connection:
            connection.execute('DELETE FROM records WHERE kind=? AND id=?', ('host-execution', identity))
        self.host.worker_alive.return_value = True
        m.initialize()
        self.assertEqual(m.load('operation', identity)['status'], 'running')
        self.host_spool['state'] = 'succeeded'; self.host.worker_alive.return_value = False
        m.reconcile_host_jobs(force=True)
        self.assertEqual(m.load('operation', identity)['status'], 'interrupted')
        self.assertTrue(m.load('operation', identity)['recoveryRequired'])
        self.assertIn('baseline', m.load('operation', identity)['stage'])
        self.host.run_transient.assert_not_called()

    def test_worker_status_wrong_job_or_plan_never_clears_host_recovery(self):
        identity, public, native = self.durable_host_upgrade()
        self.host_spool.update(state='succeeded', planId='wrong-plan')
        m.initialize()
        record = m.load('operation', identity)
        self.assertEqual(record['status'], 'interrupted'); self.assertTrue(record['recoveryRequired'])
        self.host_spool.update(planId=native['planId'], operationId='wrong-job')
        m.reconcile_host_jobs(force=True)
        self.assertTrue(m.load('operation', identity)['recoveryRequired'])
        self.host.run_transient.assert_not_called()

    def test_maintenance_lock_wait_is_queued_bounded_and_plan_expiry_prevents_dispatch(self):
        self.prepare_job()
        calls = 0
        def acquire(*args):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise BlockingIOError('maintenance busy')
            self.assertEqual(m.load('operation', 'job-1')['status'], 'queued')
            self.assertIn('attesa', m.load('operation', 'job-1')['stage'])
        with patch.object(m.fcntl, 'flock', side_effect=acquire), patch.object(m.time, 'sleep') as sleep:
            m.wait_operation_lock(object(), 'job-1', time.time() + 100)
        sleep.assert_called_once_with(1)
        with patch.object(m.fcntl, 'flock', side_effect=BlockingIOError), patch.object(m.time, 'monotonic', side_effect=[0, 1, 61]), patch.object(m.time, 'sleep'), self.assertRaises(m.Rejected) as busy:
            m.wait_operation_lock(object(), 'job-1')
        self.assertEqual(busy.exception.code, 'operation_conflict')
        with patch.object(m.fcntl, 'flock') as acquire, self.assertRaises(m.Rejected) as expired:
            m.wait_operation_lock(object(), 'job-1', time.time() - 1)
        self.assertEqual(expired.exception.code, 'plan_expired'); acquire.assert_not_called()

    def test_lock_collision_and_expired_host_plan_report_truthful_no_dispatch(self):
        self.host_fixture(); public = self.host_public_plan(); stored = m.load('host-plan', public['planId'])
        for code, expected in [('operation_conflict', 'Host occupato'), ('plan_expired', 'Piano OS scaduto')]:
            identity = uuid.uuid4().hex
            m.save('operation', identity, {'id': identity, 'kind': 'host-upgrade', 'status': 'queued', 'stage': 'Queued', 'completedSteps': 0, 'totalSteps': 100})
            with patch.object(m, 'wait_operation_lock', side_effect=m.Rejected(code, expected)):
                m.host_job(identity, 'host-upgrade', stored)
            record = m.load('operation', identity)
            self.assertEqual(record['status'], 'failed'); self.assertIn(expected, record['stage'])
            self.assertFalse(record['recoveryRequired'])
        self.host.run_transient.assert_not_called(); self.host.write_plan_file.assert_not_called()

    def test_finished_busy_or_expired_jobs_are_not_resurrected_by_unrelated_package_activity(self):
        self.host_fixture()
        identity = uuid.uuid4().hex
        m.save('operation', identity, {'id': identity, 'kind': 'host-upgrade', 'status': 'failed', 'stage': 'Host occupato: nessun aggiornamento eseguito', 'completedSteps': 0, 'totalSteps': 100, 'recoveryRequired': False})
        self.host.worker_alive.return_value = True
        m.reconcile_host_jobs(force=True)
        self.assertEqual(m.load('operation', identity)['status'], 'failed')
        self.assertFalse(m.load('operation', identity)['recoveryRequired'])
        self.host.worker_status.assert_not_called(); self.host.worker_alive.assert_not_called()

    def test_verified_host_packages_wait_for_all_baseline_services_and_route_health(self):
        identity, public, native = self.durable_host_upgrade()
        self.host_spool['state'] = 'succeeded'
        m.operation_update(identity, recoveryRequired=True)
        self.docker.rows['old-container']['State']['Running'] = False
        m.reconcile_host_jobs(force=True)
        record = m.load('operation', identity)
        self.assertEqual(record['status'], 'running'); self.assertEqual(record['completedSteps'], 99)
        self.assertIn('servizi', record['stage']); self.assertTrue(record['recoveryRequired'])
        self.assertIn('verifiedResult', m.load('host-execution', identity))
        self.docker.rows['old-container']['State']['Running'] = True
        with patch.object(m, 'reboot_services_healthy', return_value=False) as health:
            m.reconcile_host_jobs(force=True)
        health.assert_called_once(); self.assertEqual(m.load('operation', identity)['status'], 'running')
        m.reconcile_host_jobs(force=True)
        self.assertEqual(m.load('operation', identity)['status'], 'succeeded')
        self.assertFalse(m.load('operation', identity)['recoveryRequired'])
        self.host.run_transient.assert_not_called()

    def test_unhealthy_post_upgrade_services_expire_to_assisted_without_apt_retry(self):
        identity, public, native = self.durable_host_upgrade()
        self.host_spool['state'] = 'succeeded'
        execution = m.load('host-execution', identity)
        execution['serviceVerificationStartedAt'] = time.time() - 61
        m.save('host-execution', identity, execution)
        self.docker.rows['old-container']['State']['Running'] = False
        m.reconcile_host_jobs(force=True)
        record = m.load('operation', identity)
        self.assertEqual(record['status'], 'failed'); self.assertTrue(record['recoveryRequired'])
        self.assertEqual(record['completedSteps'], 99); self.assertIn('servizi', record['stage'])
        self.host.run_transient.assert_not_called()

    def test_unconfirmed_running_worker_remains_pending_and_failclosed(self):
        identity, public, native = self.durable_host_upgrade()
        self.host.worker_alive.return_value = None
        m.initialize()
        record = m.load('operation', identity)
        self.assertEqual(record['status'], 'running'); self.assertTrue(record['recoveryRequired'])
        self.host.run_transient.assert_not_called()

    def test_busy_reboot_wait_never_schedules_or_claims_uncertain_host_mutation(self):
        self.host_fixture(); public = self.host_public_plan(reboot=True)
        accepted = m.handle(self.host_apply_body(public, reboot=True))
        with patch.object(m, 'wait_operation_lock', side_effect=m.Rejected('operation_conflict', 'Host busy')):
            m.host_reboot_job(accepted['operationId'])
        self.host.schedule_reboot.assert_not_called()
        record = m.load('operation', accepted['operationId'])
        self.assertEqual(record['status'], 'failed'); self.assertFalse(record['recoveryRequired'])
        self.assertIn('Host occupato', record['stage'])

    def test_restart_of_host_upgrade_marks_apt_interruption_without_fake_runtime_recovery(self):
        self.host_fixture()
        m.save('operation', 'host-interrupted', {'id': 'host-interrupted', 'kind': 'host-upgrade', 'status': 'running', 'stage': 'Upgrade', 'completedSteps': 40, 'totalSteps': 100})
        m.initialize(); record = m.load('operation', 'host-interrupted')
        self.assertEqual(record['status'], 'interrupted'); self.assertTrue(record['recoveryRequired'])
        self.assertIn('APT', record['stage']); self.assertIn('nessun rollback', record['stage'])
        with patch.object(m.EXECUTOR, 'submit') as executor:
            for body in [{'action': 'host-check'}, {'action': 'host-plan', 'revision': m.host_catalog()['revision']}, {'action': 'plan', 'componentId': 'php', 'revision': m.catalog()['revision']}]:
                with self.subTest(body=body), self.assertRaises(m.Rejected) as blocked:
                    m.handle(body)
                self.assertEqual(blocked.exception.code, 'operation_conflict')
            executor.assert_not_called()
        self.host.run_transient.assert_not_called()

    def test_revision_stale_plan_rejected_without_mutation(self):
        before = m.catalog()['revision']
        self.docker.rows['old-container']['HostConfig']['Memory'] += 1024
        self.assertNotEqual(before, m.catalog()['revision'])
        with self.assertRaises(m.Rejected) as error:
            m.handle({'action': 'plan', 'componentId': 'php', 'revision': before})
        self.assertEqual(error.exception.code, 'stale_revision')
        self.assertEqual(self.docker.calls, [])

    def test_apply_expired_stale_and_wrong_confirmation_do_not_submit(self):
        plan = self.plan()
        with patch.object(m, 'submit') as submit:
            bad = self.apply_body(plan)
            bad['confirmation'] = 'YES'
            with self.assertRaises(m.Rejected):
                m.handle(bad)
            bad = self.apply_body(plan)
            bad['revision'] = '0' * 64
            with self.assertRaises(m.Rejected) as stale:
                m.handle(bad)
            self.assertEqual(stale.exception.code, 'stale_revision')
            stored = m.load('plan', plan['planId'])
            stored['public']['expiresAt'] = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)).isoformat()
            m.save('plan', plan['planId'], stored)
            with self.assertRaises(m.Rejected) as expired:
                m.handle(self.apply_body(plan))
            self.assertEqual(expired.exception.status, 410)
            submit.assert_not_called()

    def test_idempotency_returns_same_operation_once_and_rejects_reuse_for_other_plan(self):
        plan = self.plan()
        # Persist the real job and binding; only scheduling is simulated.
        with patch.object(m.EXECUTOR, 'submit') as submit:
            first = m.handle(self.apply_body(plan))
            second = m.handle(self.apply_body(plan))
            self.assertEqual(first['operationId'], second['operationId'])
            self.assertEqual(submit.call_count, 1)
            wrong = self.apply_body(plan)
            wrong['planId'] = 'another-plan'
            with self.assertRaises(m.Rejected) as conflict:
                m.handle(wrong)
            self.assertEqual(conflict.exception.code, 'idempotency_conflict')

    def test_idempotency_binding_is_durable_before_background_job_is_scheduled(self):
        plan = self.plan()
        seen = []
        def schedule(function, job_id, stored):
            with m.db() as connection:
                prior = connection.execute('SELECT plan,job FROM idempotency WHERE id=?', ('request-1',)).fetchone()
            seen.append(prior is not None and prior['plan'] == plan['planId'] and prior['job'] == job_id)
            self.assertIsNotNone(m.load('operation', job_id))
        with patch.object(m.EXECUTOR, 'submit', side_effect=schedule):
            result = m.handle(self.apply_body(plan))
        self.assertEqual(len(seen), 1)
        self.assertTrue(seen[0], 'A crash after scheduling must not lose the idempotency-to-job binding')
        self.assertEqual(m.load('operation', result['operationId'])['status'], 'queued')

    def test_unresolved_recovery_gate_survives_bounded_operation_history(self):
        self.prepare_job('critical-old-job')
        m.operation_update('critical-old-job', status='interrupted', recoveryRequired=True)
        for i in range(105):
            m.save('operation', 'later-check-' + str(i), {'id': 'later-check-' + str(i), 'status': 'succeeded', 'stage': 'complete', 'completedSteps': 1, 'totalSteps': 1})
        self.assertFalse(m.catalog()['canApply'], 'Read-history limits must never clear an unresolved recovery guard')
        with self.assertRaises(m.Rejected) as error:
            self.plan()
        self.assertEqual(error.exception.status, 409)

    def test_stopped_container_preserved_and_config_secret_remains_root_only(self):
        self.docker = DockerFixture(running=False)
        with patch.object(m, 'docker', self.docker.docker), patch.object(m, 'inspect', self.docker.inspect):
            backups = []
            new_id = m.recreate(self.docker.old, NEW_IMAGE, backups)
            new = m.verify(self.docker.old, new_id, self.config['components'][0], '8.5.12')
            self.assertFalse(new['State']['Running'])
            self.assertFalse(any(endpoint.endswith('/start') for _, endpoint, _ in self.docker.calls))
            self.assertEqual(new['HostConfig'], self.docker.old['HostConfig'])
            self.assertEqual(new['Config']['Env'], ['PHP_VERSION=8.5.12', 'DB_PASSWORD=' + SECRET])
            self.assertNotIn(SECRET, json.dumps(m.catalog()))

    def test_recreation_preserves_security_and_canonicalizes_deprecated_no_new_privileges(self):
        old = self.docker.inspect('php-service')
        old['HostConfig']['SecurityOpt'] = ['no-new-privileges:true', 'apparmor=platform-profile']
        with patch.object(m, 'docker', self.docker.docker):
            new_id = m.recreate(old, NEW_IMAGE, [])
        fresh = self.docker.inspect(new_id)
        self.assertEqual(fresh['HostConfig'], {**old['HostConfig'], 'SecurityOpt': ['no-new-privileges=true', 'apparmor=platform-profile']})
        self.assertEqual(old['HostConfig']['SecurityOpt'][0], 'no-new-privileges:true')

    def test_failed_new_runtime_rolls_back_same_old_container_identity(self):
        stored = self.stored()
        self.prepare_job()
        with patch.object(m, 'image_candidate', return_value=NEW_IMAGE), patch.object(m, 'verify', side_effect=m.Rejected('updates_unavailable', 'Injected verification failure', 503)), patch.object(m, 'refresh_admission') as admission:
            m.apply_job('job-1', stored)
        restored = self.docker.inspect('php-service')
        self.assertEqual(restored['Id'], 'old-container')
        self.assertEqual(restored['Image'], OLD_IMAGE)
        self.assertTrue(restored['State']['Running'])
        self.assertEqual(restored['HostConfig'], self.docker.old['HostConfig'])
        self.assertEqual(restored['Mounts'], self.docker.old['Mounts'])
        self.assertEqual(m.endpoints(restored), m.endpoints(self.docker.old))
        self.assertEqual(m.load('operation', 'job-1')['status'], 'rolled-back')
        self.assertNotIn(SECRET, json.dumps(m.records('operation')))
        admission.assert_not_called()
        self.assertEqual(stat.S_IMODE((self.state / 'job-1' / 'before.json').stat().st_mode), 0o600)

    def test_create_failure_after_rename_restores_old_id_and_original_name(self):
        stored = self.stored()
        self.prepare_job()
        self.docker.fail_create = True
        with patch.object(m, 'image_candidate', return_value=NEW_IMAGE):
            m.apply_job('job-1', stored)
        self.assertEqual(self.docker.inspect('php-service')['Id'], 'old-container')
        self.assertTrue(self.docker.inspect('php-service')['State']['Running'])
        self.assertEqual(m.load('operation', 'job-1')['status'], 'rolled-back')

    def test_fingerprint_drift_before_job_prevents_all_docker_mutations(self):
        stored = self.stored()
        self.prepare_job()
        self.docker.rows['old-container']['Config']['Labels']['changed'] = 'yes'
        with patch.object(m, 'image_candidate') as build:
            m.apply_job('job-1', stored)
        self.assertEqual(m.load('operation', 'job-1')['status'], 'failed')
        build.assert_not_called()
        self.assertEqual(self.docker.calls, [])

    def test_restart_marks_unfinished_jobs_interrupted_without_claiming_success(self):
        self.prepare_job()
        m.operation_update('job-1', status='running')
        m.initialize()
        job = m.load('operation', 'job-1')
        self.assertEqual(job['status'], 'interrupted')
        self.assertIn('finishedAt', job)
        self.assertEqual(self.docker.calls, [])

    def test_operation_lookup_has_exact_request_schema_and_missing_id_404(self):
        self.prepare_job()
        self.assertEqual(m.handle({'action': 'operation', 'operationId': 'job-1'})['id'], 'job-1')
        for body in [{'action': 'operation'}, {'action': 'operation', 'operationId': '../etc'}, {'action': 'operation', 'operationId': 'job-1', 'path': '/etc/shadow'}]:
            with self.assertRaises(m.Rejected) as error:
                m.handle(body)
            self.assertEqual(error.exception.status, 400)
        with self.assertRaises(m.Rejected) as missing:
            m.handle({'action': 'operation', 'operationId': 'missing'})
        self.assertEqual(missing.exception.status, 404)

    def test_stopped_verification_still_rejects_changed_mounts(self):
        old = container(running=False)
        changed = copy.deepcopy(old)
        changed.update(Id='new-container', Image=NEW_IMAGE)
        changed['Mounts'][0]['Name'] = 'wrong-empty-volume'
        with patch.object(m, 'inspect', return_value=changed):
            with self.assertRaises(m.Rejected):
                m.verify(old, 'new-container', self.config['components'][0], '8.5.12')

    def test_drift_during_image_build_does_not_overwrite_changed_runtime(self):
        stored = self.stored()
        self.prepare_job()
        def build(*args):
            self.docker.rows['old-container']['HostConfig']['Memory'] += 1024
            return NEW_IMAGE
        with patch.object(m, 'image_candidate', side_effect=build), patch.object(m, 'recreate') as recreate:
            m.apply_job('job-1', stored)
        recreate.assert_not_called()
        self.assertEqual(m.load('operation', 'job-1')['status'], 'failed')

    def test_database_verification_failure_never_restarts_old_engine_after_new_start(self):
        # Defense in depth for an already admitted plan: a database start can
        # modify the shared data even when subsequent health checks fail.
        stored = self.stored()
        stored['component']['category'] = 'Database'
        self.prepare_job()
        with patch.object(m, 'image_candidate', return_value=NEW_IMAGE), patch.object(m, 'snapshot_database') as snapshot, patch.object(m, 'verify', side_effect=m.Rejected('updates_unavailable', 'DB health failure', 503)), patch.object(m, 'refresh_admission'):
            m.apply_job('job-1', stored)
        snapshot.assert_called_once()
        self.assertTrue(any(endpoint == '/containers/new-container/start' for _, endpoint, _ in self.docker.calls), 'Fixture must reach new DB engine start before injected failure')
        old_starts = [endpoint for method, endpoint, _ in self.docker.calls if method == 'POST' and endpoint == '/containers/old-container/start']
        self.assertEqual(old_starts, [], 'Never downgrade a DB image after the new engine has accessed its data')
        self.assertNotEqual(m.load('operation', 'job-1')['status'], 'rolled-back')

    def test_worker_crash_has_durable_journal_before_first_container_mutation(self):
        stored = self.stored()
        self.prepare_job()
        seen = []
        docker = self.docker.docker
        def observe(method, endpoint, body=None):
            if method in ['POST', 'DELETE']:
                journal = self.state / 'job-1' / 'rollback.json'
                value = json.loads(journal.read_text()) if journal.exists() else None
                seen.append((endpoint, bool(value)))
            return docker(method, endpoint, body)
        with patch.object(m, 'docker', side_effect=observe), patch.object(m, 'image_candidate', return_value=NEW_IMAGE), patch.object(m, 'verify', side_effect=m.Rejected('updates_unavailable', 'fixture', 503)):
            m.apply_job('job-1', stored)
        self.assertTrue(seen, 'Fixture must reach a container mutation')
        self.assertTrue(all(durable for _, durable in seen), 'Docker mutated without durable rollback intent: ' + str([endpoint for endpoint, durable in seen if not durable]))

    def test_restart_blocks_new_mutation_while_partial_rollback_journal_needs_reconciliation(self):
        self.prepare_job()
        directory = self.state / 'job-1'
        directory.mkdir()
        m.atomic(directory / 'rollback.json', m.encode([{'old': self.docker.old, 'backupName': 'php-service-update-fixture', 'newId': 'new-container', 'phase': 'renamed'}]))
        m.operation_update('job-1', status='running')
        m.initialize()
        with self.assertRaises(m.Rejected) as error:
            self.plan()
        self.assertEqual(error.exception.status, 409)

    def http_server(self, handler=None):
        endpoint = self.root / 'u.sock'
        server = m.Server(str(endpoint), handler or m.Handler)
        server.key = b'x' * 32
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.addCleanup(cleanup)
        class Connection(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.settimeout(2)
                self.sock.connect(str(endpoint))
        def request(body, envelope=None, signature=None):
            envelope = envelope or {'body': body, 'timestamp': int(time.time() * 1000), 'nonce': uuid.uuid4().hex}
            raw = m.encode(envelope)
            conn = Connection('localhost', timeout=2)
            headers = {'Content-Type': 'application/json', 'x-platform-signature': signature or hmac.new(server.key, raw, hashlib.sha256).hexdigest()}
            try:
                conn.request('POST', '/v1/updates', raw, headers)
                response = conn.getresponse()
                return response.status, json.loads(response.read())
            finally:
                conn.close()
        return endpoint, request

    def test_server_events_is_a_nofields_hmac_read_without_queued_mutations(self):
        payload = {'schema': 'server-events/v1', 'available': True, 'partial': False, 'checkedAt': m.stamp(),
                   'issues': [], 'events': [], 'sources': [{'id': 'host', 'available': True}]}
        _, request = self.http_server()
        with patch.object(m, 'SERVER_EVENTS_COLLECTOR', return_value=payload) as collector, patch.object(m.EXECUTOR, 'submit') as submit:
            status, value = request({'action': 'server-events'})
            self.assertEqual(status, 200); self.assertEqual(value, payload)
            self.assertEqual(request({'action': 'server-events', 'url': 'https://example.test'})[0], 400)
            self.assertEqual(request({'action': 'server-events'}, signature='0' * 64)[0], 403)
        collector.assert_called_once(); submit.assert_not_called()

    def test_unix_http_signature_replay_and_typed_rejections(self):
        _, request = self.http_server()
        body = {'action': 'catalog'}
        envelope = {'body': body, 'timestamp': int(time.time() * 1000), 'nonce': uuid.uuid4().hex}
        self.assertEqual(request(body, envelope)[0], 200)
        self.assertEqual(request(body, envelope)[0], 403)
        self.assertEqual(request(body, signature='0' * 64)[0], 403)
        for malformed in [{'action': []}, {'action': 'operation', 'operationId': []}, {'action': 'plan', 'componentId': 'php', 'revision': {}}]:
            with self.subTest(body=malformed):
                status, result = request(malformed)
                self.assertEqual(status, 400)
                self.assertNotIn(SECRET, json.dumps(result))

    def test_control_center_replacement_does_not_replace_or_interrupt_worker_socket(self):
        row = self.config['components'][0]
        row.update(id='control-center', label='Control Center', containers=['enterprise-control-center'])
        self.config_path.write_text(json.dumps(self.config))
        self.docker.rows['old-container']['Name'] = '/enterprise-control-center'
        m.save('cache', 'releases', {'checkedAt': m.stamp(), 'components': {'control-center': {'candidateRelease': self.release, 'latestStable': self.release}}})
        endpoint, request = self.http_server()
        socket_identity = endpoint.stat().st_ino
        status, catalog = request({'action': 'catalog'})
        self.assertEqual(status, 200)
        status, plan = request({'action': 'plan', 'componentId': 'control-center', 'revision': catalog['revision']})
        self.assertEqual(status, 200)
        stored = m.load('plan', plan['planId'])
        self.prepare_job()
        with patch.object(m, 'image_candidate', return_value=NEW_IMAGE), patch.object(m, 'verify', side_effect=lambda old, identity, *args: self.docker.inspect(identity)), patch.object(m, 'refresh_admission'):
            m.apply_job('job-1', stored)
        self.assertEqual(self.docker.inspect('enterprise-control-center')['Id'], 'new-container')
        self.assertEqual(endpoint.stat().st_ino, socket_identity)
        status, operation = request({'action': 'operation', 'operationId': 'job-1'})
        self.assertEqual(status, 200)
        self.assertEqual(operation['status'], 'succeeded')

    def test_run_redacts_subprocess_stdout_stderr(self):
        result = types.SimpleNamespace(returncode=1, stdout=SECRET.encode(), stderr=('/etc/private ' + SECRET).encode())
        with patch.object(m.subprocess, 'run', return_value=result):
            with self.assertRaises(m.Rejected) as error:
                m.run(['fixture-command'])
        self.assertNotIn(SECRET, str(error.exception))
        self.assertNotIn('/etc/private', str(error.exception))

    def test_root_config_rejects_invalid_scope_and_unknown_strategy(self):
        for mutate in [lambda c: c['components'].append(copy.deepcopy(c['components'][0])), lambda c: c['components'][0].update(containers=['../root']), lambda c: c['components'][0].update(strategy='shell')]:
            value = copy.deepcopy(self.config)
            mutate(value)
            self.config_path.write_text(json.dumps(value))
            with self.assertRaises(m.Rejected) as error:
                m.configuration()
            self.assertEqual(error.exception.status, 503)

    def test_recoverypoint_required_for_database_update(self):
        # Database data may be irreversibly changed by merely starting a new engine.
        self.config['components'][0].update(category='Database')
        self.config_path.write_text(json.dumps(self.config))
        item = m.catalog()['components'][0]
        self.assertFalse(item['canUpdate'], 'Database update needs an explicit verified recent recovery point before any start')
        with patch.object(m, 'submit') as submit:
            with self.assertRaises(m.Rejected):
                self.plan()
            submit.assert_not_called()

    def test_malformed_typed_fields_raise_rejected_instead_of_internal_errors(self):
        for body in [{'action': []}, {'action': 'plan', 'componentId': 'php', 'revision': {}}, {'action': 'apply', 'componentId': 'php', 'revision': 'x', 'planId': 'plan-1', 'confirmation': 'UPDATE', 'idempotencyKey': []}]:
            with self.subTest(body=body):
                with self.assertRaises(m.Rejected) as error:
                    m.handle(body)
                self.assertEqual(error.exception.status, 400)


class ProtectedPathTests(unittest.TestCase):
    def test_nonroot_writable_and_symlink_ancestors_rejected_without_real_root_files(self):
        for uid, mode in [(501, stat.S_IFREG | 0o600), (0, stat.S_IFREG | 0o666), (0, stat.S_IFLNK | 0o777)]:
            info = types.SimpleNamespace(st_uid=uid, st_mode=mode)
            fake = types.SimpleNamespace(is_absolute=lambda: True, resolve=lambda: fake, parents=[], lstat=lambda: info)
            with patch.object(m.pathlib, 'Path', return_value=fake):
                with self.assertRaises(m.Rejected) as error:
                    m.protected('/protected/config.json')
                self.assertEqual(error.exception.status, 503)


class InstallerDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = LIBEXEC.parents[2] / 'scripts/install-runtime-updates.py'
        spec = importlib.util.spec_from_file_location('runtime_updates_installer_fixture', source)
        cls.installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.installer)

    def runtime(self, name, image, env=None, running=True):
        row = container(running)
        row.update(Name='/' + name, Image='sha256:' + hashlib.sha256(image.encode()).hexdigest())
        row['Config'].update(Image=image, Env=env or [], Labels={'com.docker.compose.project': 'fixture-platform', 'com.docker.compose.service': name})
        return row

    def test_custom_waf_and_name_matches_cannot_become_official_plain_images(self):
        rows = [self.runtime('generic-nginx-waf', 'owasp/modsecurity-crs:4.12-nginx'),
                self.runtime('custom-proxy', 'platform/nginx-waf:reviewed'),
                self.runtime('prometheus-labelled-job', 'platform/processor:1.0.0'),
                self.runtime('custom-web', 'nginxinc/nginx-unprivileged:1.30-alpine')]
        components = self.installer.discover(rows, pathlib.Path('/fixture/platform'))
        self.assertEqual(len(components), len(rows))
        for component in components:
            self.assertEqual(component['strategy'], 'observe', component['label'])
            self.assertNotIn('repository', component)

    def test_only_exact_official_provider_repositories_are_updateable(self):
        rows = [self.runtime('web-proxy', 'nginx:1.30.5-alpine'),
                self.runtime('monitor-one', 'docker.io/prom/prometheus:v3.12.0')]
        components = self.installer.discover(rows, pathlib.Path('/fixture/platform'))
        self.assertEqual({x['repository'] for x in components}, {'library/nginx', 'prom/prometheus'})
        self.assertTrue(all(x['strategy'] == 'image' for x in components))

    def test_stopped_tools_included_retained_rollbacks_excluded_and_no_missing_runtimes_invented(self):
        rows = [self.runtime('web-proxy', 'nginx:1.30.5-alpine', running=False),
                self.runtime('web-proxy-rollback-old', 'nginx:1.30.4-alpine', running=False),
                self.runtime('web-proxy-update-old', 'nginx:1.30.3-alpine', running=False)]
        components = self.installer.discover(rows, pathlib.Path('/fixture/platform'))
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]['containers'], ['web-proxy'])
        self.assertEqual(self.installer.discover([], pathlib.Path('/fixture/platform')), [])

    def test_node_applications_form_one_stable_family_across_different_images(self):
        rows = [self.runtime('node-app-a', 'platform/custom-app-a:deployed', ['NODE_VERSION=26.10.0']),
                self.runtime('node-app-b', 'platform/custom-app-b:deployed', ['NODE_VERSION=26.10.0'])]
        components = self.installer.discover(rows, pathlib.Path('/fixture/platform'))
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]['strategy'], 'node-layer')
        self.assertEqual(components[0]['id'], 'node')
        self.assertEqual(components[0]['label'], 'Node.js')
        self.assertEqual(components[0]['containers'], ['node-app-a', 'node-app-b'])
        self.assertEqual(len(components[0]['initialImages']), 2)
        rerun = copy.deepcopy(rows); rerun[0]['Image'] = NEW_IMAGE
        self.assertEqual(self.installer.discover(rerun, pathlib.Path('/fixture/platform'))[0]['id'], 'node')

    def test_traefik_root_route_probes_survive_enrollment_with_new_image_identity(self):
        row = self.runtime('web-proxy', 'traefik:v3.7.16')
        components = self.installer.discover([row], pathlib.Path('/fixture/platform'))
        probes = [{'host': 'portal.example.test', 'port': 8080, 'path': '/', 'expectedStatuses': [200, 401]}]
        previous = [{'id': 'legacy-traefik-oldimage', 'repository': 'library/traefik', 'containers': ['previous-router-name'], 'routeProbes': probes}]
        self.installer.preserve_enrollment_policy(components, previous)
        self.assertEqual(components[0]['id'], 'traefik')
        self.assertEqual(components[0]['routeProbes'], probes)

    def test_reenrollment_keeps_traefik_family_after_recreate_sets_only_image_sha(self):
        old = self.runtime('web-proxy', 'traefik:v3.7.5')
        previous = self.installer.discover([old], pathlib.Path('/fixture/platform'))
        previous[0]['routeProbes'] = [{'host': 'portal.example.test', 'port': 8080, 'path': '/', 'expectedStatuses': [200, 401]}]
        fresh = copy.deepcopy(old)
        fresh.update(Id='updated-router', Image=NEW_IMAGE)
        fresh['Config']['Image'] = NEW_IMAGE  # Exact updater recreate() output.
        metadata = [{'Id': NEW_IMAGE, 'RepoDigests': ['traefik@' + NEW_IMAGE]}]
        components = self.installer.discover([fresh], pathlib.Path('/fixture/platform'), image_metadata=metadata)
        self.installer.preserve_enrollment_policy(components, previous)
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]['id'], 'traefik'); self.assertEqual(components[0]['repository'], 'library/traefik')
        self.assertEqual(components[0]['strategy'], 'image'); self.assertEqual(components[0]['probe'], ['traefik', 'version'])
        self.assertEqual(components[0]['containers'], previous[0]['containers'])
        self.assertEqual(components[0]['routeProbes'], previous[0]['routeProbes'])

    def test_official_repo_digests_restore_providers_but_unverified_sha_or_foreign_images_do_not(self):
        for reference, expected in [('docker.io/library/nginx@' + NEW_IMAGE, 'library/nginx'),
                                    ('prom/prometheus@' + NEW_IMAGE, 'prom/prometheus'),
                                    ('grafana/loki@' + NEW_IMAGE, 'grafana/loki')]:
            with self.subTest(reference=reference):
                row = self.runtime('generic-service', NEW_IMAGE)
                metadata = [{'Id': row['Image'], 'RepoDigests': [reference]}]
                result = self.installer.discover([row], pathlib.Path('/fixture/platform'), image_metadata=metadata)
                self.assertEqual(result[0]['repository'], expected); self.assertEqual(result[0]['strategy'], 'image')
        row = self.runtime('generic-nginx', NEW_IMAGE)
        for references in [[], ['owasp/modsecurity-crs@' + NEW_IMAGE], ['evil.test/library/nginx@' + NEW_IMAGE], ['nginx@' + NEW_IMAGE, 'traefik@' + NEW_IMAGE]]:
            with self.subTest(references=references):
                result = self.installer.discover([row], pathlib.Path('/fixture/platform'), image_metadata=[{'Id': row['Image'], 'RepoDigests': references}])
                self.assertEqual(result[0]['strategy'], 'observe'); self.assertNotIn('repository', result[0])
        # A local official-looking tag alone cannot override foreign provenance.
        row['Config']['Image'] = 'nginx:1.30.5'
        result = self.installer.discover([row], pathlib.Path('/fixture/platform'), image_metadata=[{'Id': row['Image'], 'RepoDigests': ['owasp/modsecurity-crs@' + NEW_IMAGE]}])
        self.assertEqual(result[0]['strategy'], 'observe')

    def test_completed_initialization_helpers_are_not_runtime_update_targets(self):
        rows = [self.runtime('web-proxy', 'nginx:1.30.5-alpine'),
                self.runtime('storage-volume-init', 'nginx:1.30.5-alpine', running=False),
                self.runtime('auth-bootstrap', 'platform/bootstrap:deployed', ['NODE_VERSION=26.10.0'], running=False)]
        components = self.installer.discover(rows, pathlib.Path('/fixture/platform'))
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]['containers'], ['web-proxy'])


if __name__ == '__main__':
    unittest.main()
