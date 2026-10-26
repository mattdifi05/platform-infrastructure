import copy
import datetime
import importlib.util
import json
import pathlib
import sys
import threading
import time
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'libexec/platform_server_events.py'
spec = importlib.util.spec_from_file_location('server_events_test_module', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class EventsTests(unittest.TestCase):
    def setUp(self):
        self.at = [1770000000.0]
        self.units, self.containers, self.journal, self.jobs, self.calls = [], [], [], [], []
        self.host = {'diskPercent': 20, 'inodePercent': 10, 'memoryPercent': 40}
        self.fail = set()
        self.collector = m.create_collector(run=self.command, read_operations=lambda: copy.deepcopy(self.jobs),
                                            metrics=lambda: self.host, now=lambda: self.at[0])

    def command(self, args, **options):
        self.calls.append((args, options))
        if args[0] in self.fail:
            raise OSError('password=PRIVATE_EXCEPTION_MUST_NOT_LEAK')
        if args[0] == 'systemctl':
            return json.dumps(self.units)
        if args[:2] == ['docker', 'ps']:
            return '\n'.join('%064x' % (index + 1) for index in range(len(self.containers)))
        if args[:2] == ['docker', 'inspect']:
            return '\n'.join(json.dumps(row) for row in self.containers)
        if args[0] == 'journalctl':
            return '\n'.join(json.dumps(row) for row in self.journal)
        raise AssertionError(args)

    def journal_row(self, message, **fields):
        return {'_SYSTEMD_UNIT': 'docker.service', 'PRIORITY': '3',
                '__REALTIME_TIMESTAMP': str(int(self.at[0] * 1000000)), 'MESSAGE': message, **fields}

    def container(self, name='generic-app', **fields):
        return {'name': '/' + name, 'service': name, 'state': 'running', 'running': True, 'health': 'healthy',
                'oom': False, 'error': False, 'exitCode': 0, 'restart': 'unless-stopped', **fields}

    def refresh(self):
        self.at[0] += 13
        return self.collector()

    def test_healthy_sources_are_available_and_empty_without_mutating_commands(self):
        value = self.collector()
        self.assertTrue(value['available']); self.assertFalse(value['partial'])
        self.assertEqual(value['issues'], []); self.assertEqual(value['events'], [])
        self.assertEqual(len(value['sources']), 5)
        self.assertTrue(all(source['available'] for source in value['sources']))
        self.assertEqual([args[0] for args, options in self.calls], ['systemctl', 'docker', 'journalctl'])
        for args, options in self.calls:
            self.assertLessEqual(options['timeout'], 3)
            self.assertNotIn('restart', args); self.assertNotIn('reset-failed', args); self.assertNotIn('logs', args)

    def test_secrets_urls_pii_pem_tokens_and_control_characters_are_redacted(self):
        raw = ('DB_PASSWORD="short private value" client_secret=hidden Bearer shortBearer '
               'https://user:pass@example.test/path?token=urlSecret&key=urlKey '
               'name.person@example.test 187.7.64.76 2001:db8::1 '
               'AKIAABCDEFGHIJKLMNOP /home/privateperson/file\x00\x1b[31m '
               '-----BEGIN PRIVATE KEY-----\nprivate material\n-----END PRIVATE KEY-----')
        self.journal = [self.journal_row(raw)]
        value = json.dumps(self.collector())
        for secret in ['short private value', 'hidden', 'shortBearer', 'urlSecret', 'urlKey', 'user:pass',
                       'name.person@example.test', '187.7.64.76', '2001:db8::1', 'AKIAABCDEFGHIJKLMNOP', 'privateperson', 'private material']:
            self.assertNotIn(secret, value)
        message = self.collector()['events'][0]['message']
        self.assertFalse(any(ord(character) < 32 for character in message)); self.assertLessEqual(len(message), 400)

    def test_short_credentials_with_json_and_singlequoted_keys_are_redacted(self):
        for raw, secret in [('{"password":"short-password"}', 'short-password'),
                            ("{'api_key':'short-key'}", 'short-key'),
                            ('{"Authorization":"short-auth"}', 'short-auth'),
                            ("{'client_secret': 'short-client'}", 'short-client'),
                            ('DB_PASSWORD=short-env', 'short-env'),
                            ('Invalid user privateusername from remote', 'privateusername'),
                            ('{"username":"private-account"}', 'private-account')]:
            with self.subTest(raw=raw):
                self.assertNotIn(secret, m.redact(raw))

    def test_journal_is_bounded_allowlisted_history_and_deduplicates_real_occurrences(self):
        self.journal = [self.journal_row('Kernel route failure'), self.journal_row('Kernel route failure', __REALTIME_TIMESTAMP=str(int((self.at[0] - 30) * 1000000))),
                        self.journal_row('PRIVATE_BUSINESS_OUTPUT', _SYSTEMD_UNIT='private-business.service'),
                        self.journal_row('too old', __REALTIME_TIMESTAMP=str(int((self.at[0] - 90000) * 1000000))),
                        self.journal_row('information', PRIORITY='6')]
        value = self.collector()
        self.assertEqual(len(value['events']), 1); self.assertFalse(value['events'][0]['active'])
        self.assertEqual(value['events'][0]['count'], 2)
        self.assertEqual(value['events'][0]['firstSeen'], m.iso(self.at[0] - 30))
        self.assertEqual(value['events'][0]['lastSeen'], m.iso(self.at[0]))
        self.assertEqual(value['issues'], [])
        args = next(args for args, _ in self.calls if args[0] == 'journalctl')
        for expected in ['--boot=0', '--since=-24h', '--lines=100', '--priority=0..4', '_TRANSPORT=kernel', '_SYSTEMD_UNIT=docker.service']:
            self.assertIn(expected, args)
        self.assertNotIn('private-business.service', args)

    def test_docker_projection_excludes_env_health_stdout_and_intentional_stops(self):
        self.containers = [self.container('unhealthy', health='unhealthy'), self.container('restarting', state='restarting'),
                           self.container('oom', running=False, state='exited', oom=True, exitCode=137),
                           self.container('start-error', running=False, state='exited', error=True),
                           self.container('unexpected', running=False, state='exited', exitCode=1, restart='on-failure'),
                           self.container('intentionally-offline', running=False, state='exited', exitCode=0),
                           self.container('manual-term', running=False, state='exited', exitCode=143),
                           self.container('manual-kill', running=False, state='exited', exitCode=137),
                           self.container('unknown-intent', running=False, state='exited', exitCode=1),
                           self.container('old-update-retained', health='unhealthy'),
                           self.container('old-rollback-retained', health='unhealthy'),
                           self.container('volume-init', running=False, state='exited', error=True),
                           self.container('service-bootstrap', running=False, state='exited', error=True)]
        value = self.collector()
        self.assertEqual({item['service'] for item in value['issues']}, {'unhealthy', 'restarting', 'oom', 'start-error', 'unexpected'})
        args = next(args for args, _ in self.calls if args[:2] == ['docker', 'inspect'])
        projection = args[args.index('--format') + 1]
        self.assertNotIn('.Env', projection); self.assertNotIn('.Log', projection)
        self.assertNotIn('Health.Log', projection); self.assertIn('.State.OOMKilled', projection)

    def test_failed_read_is_partial_and_never_claims_no_errors_or_leaks_exception(self):
        self.fail = {'journalctl'}
        value = self.collector()
        self.assertTrue(value['available']); self.assertTrue(value['partial'])
        self.assertTrue(any(item['code'] == 'source-unavailable' for item in value['issues']))
        self.assertFalse(next(source for source in value['sources'] if source['id'] == 'journal')['available'])
        self.assertNotIn('PRIVATE_EXCEPTION', json.dumps(value))

    def test_all_unavailable_remains_explicitly_unavailable(self):
        def fail(*args, **kwargs):
            raise RuntimeError('private')
        collector = m.create_collector(run=fail, read_operations=fail, metrics=fail, now=lambda: self.at[0])
        value = collector()
        self.assertFalse(value['available']); self.assertTrue(value['partial'])
        self.assertTrue(all(not source['available'] for source in value['sources']))

    def test_legacy_failed_update_is_not_active_after_later_success_or_operator_reconcile(self):
        self.jobs = [{'kind': 'host-upgrade', 'status': 'succeeded', 'operatorReconciled': True},
                     {'kind': 'host-upgrade', 'status': 'interrupted', 'recoveryRequired': True, 'finishedAt': m.iso(self.at[0] - 60)}]
        value = self.collector()
        self.assertEqual(value['issues'], [])
        self.assertTrue(any(item['source'] == 'updates' and not item['active'] for item in value['events']))
        self.jobs = [{'kind': 'apply', 'status': 'failed', 'componentResults': [{'componentId': 'php'}]},
                     {'kind': 'apply', 'status': 'succeeded', 'componentResults': [{'componentId': 'node'}]},
                     {'kind': 'apply', 'status': 'failed', 'componentResults': [{'componentId': 'node'}]}]
        value = self.refresh()
        active = [item for item in value['issues'] if item['source'] == 'updates']
        self.assertEqual(len(active), 1); self.assertEqual(active[0]['service'], 'runtime:php')

    def test_current_unresolved_recovery_is_active_without_using_error_payload(self):
        self.jobs = [{'kind': 'host-upgrade', 'status': 'interrupted', 'recoveryRequired': True, 'error': 'password=TOP_SECRET'}]
        value = self.collector()
        self.assertEqual(len(value['issues']), 1)
        self.assertEqual(value['issues'][0]['code'], 'update-recovery-required')
        self.assertEqual(value['issues'][0]['severity'], 'error'); self.assertNotIn('TOP_SECRET', json.dumps(value))

    def test_active_first_seen_stays_stable_and_resolution_is_explicit_history(self):
        self.units = [{'unit': 'docker.service', 'active': 'failed'}]
        first = self.collector()['issues'][0]
        again = self.refresh()['issues'][0]
        self.assertEqual(again['firstSeen'], first['firstSeen']); self.assertEqual(again['count'], 1)
        self.units = []
        resolved = self.refresh()
        self.assertEqual(resolved['issues'], []); self.assertTrue(resolved['events'][0]['message'].startswith('Risolto:'))
        self.assertFalse(resolved['events'][0]['active'])

    def test_unavailable_source_is_not_misreported_as_resolved(self):
        self.units = [{'unit': 'docker.service', 'active': 'failed'}]
        self.collector(); self.fail = {'systemctl'}
        value = self.refresh()
        self.assertFalse(any(item['message'].startswith('Risolto:') for item in value['events']))
        self.assertTrue(value['partial'])

    def test_real_host_thresholds_and_output_budget_truncation(self):
        self.host = {'diskPercent': 96, 'inodePercent': 99, 'memoryPercent': 98}
        self.units = [{'unit': 'service-%s.service' % index, 'active': 'failed'} for index in range(60)]
        self.journal = [self.journal_row('Detailed diagnostic message %s ' % index + 'context words ' * 60) for index in range(100)]
        value = self.collector()
        self.assertTrue(value['partial']); self.assertLessEqual(len(value['issues']), 40); self.assertLessEqual(len(value['events']), 80)
        self.assertLess(len(json.dumps(value).encode()), 120 * 1024)
        self.assertTrue(all(source['available'] for source in value['sources']))
        self.assertTrue(any(item['code'] == 'inodes-critical' for item in value['issues']))

    def test_cache_is_coalesced_and_does_not_mutate_shared_payload(self):
        values = []
        threads = [threading.Thread(target=lambda: values.append(self.collector())) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)
        self.assertEqual(len(values), 8); self.assertEqual(len(self.calls), 3)
        values[0]['sources'].clear()
        self.assertEqual(len(self.collector()['sources']), 5)
        self.refresh(); self.assertEqual(len(self.calls), 6)

    def test_output_and_runtime_of_diagnostic_children_are_bounded(self):
        with self.assertRaises(m.SourceUnavailable):
            m.read_command([sys.executable, '-c', 'print("x" * 10000)'], max_bytes=1024)
        began = time.monotonic()
        with self.assertRaises(m.SourceUnavailable):
            m.read_command([sys.executable, '-c', 'import time; time.sleep(2)'], timeout=.03)
        self.assertLess(time.monotonic() - began, 1)


if __name__ == '__main__':
    unittest.main()
