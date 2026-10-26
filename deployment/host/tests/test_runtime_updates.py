import copy
import datetime
import importlib.util
import hashlib
import hmac
import http.client
import socket
import threading
import time
import uuid
import json
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

    def inspect(self, identity):
        for key, row in self.rows.items():
            if identity in (key, row['Name'], row['Name'].lstrip('/')):
                return copy.deepcopy(row)
        return None

    def docker(self, method, endpoint, body=None):
        self.calls.append((method, endpoint, copy.deepcopy(body)))
        if endpoint.startswith('/images/'):
            return {'Id': NEW_IMAGE, 'Config': {'Env': ['PHP_VERSION=8.5.12']}}
        if endpoint.startswith('/containers/create?'):
            if self.fail_create:
                raise m.Rejected('updates_unavailable', 'Simulated Docker failure', 503)
            name = endpoint.split('name=', 1)[1]
            row = copy.deepcopy(self.old)
            row.update(Id='new-container', Name='/' + name, Image=body['Image'])
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
                row['NetworkSettings']['Networks'][network] = copy.deepcopy(body['EndpointConfig'])
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

    def http_server(self):
        endpoint = self.root / 'u.sock'
        server = m.Server(str(endpoint), m.Handler)
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

    def test_node_application_keeps_its_custom_image_strategy_and_separate_image_targets(self):
        rows = [self.runtime('node-app-a', 'platform/custom-app-a:deployed', ['NODE_VERSION=26.10.0']),
                self.runtime('node-app-b', 'platform/custom-app-b:deployed', ['NODE_VERSION=26.10.0'])]
        components = self.installer.discover(rows, pathlib.Path('/fixture/platform'))
        self.assertEqual(len(components), 2)
        self.assertTrue(all(x['strategy'] == 'node-layer' for x in components))
        self.assertNotEqual(components[0]['id'], components[1]['id'])

    def test_completed_initialization_helpers_are_not_runtime_update_targets(self):
        rows = [self.runtime('web-proxy', 'nginx:1.30.5-alpine'),
                self.runtime('storage-volume-init', 'nginx:1.30.5-alpine', running=False),
                self.runtime('auth-bootstrap', 'platform/bootstrap:deployed', ['NODE_VERSION=26.10.0'], running=False)]
        components = self.installer.discover(rows, pathlib.Path('/fixture/platform'))
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]['containers'], ['web-proxy'])


if __name__ == '__main__':
    unittest.main()
