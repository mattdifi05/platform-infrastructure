import copy
import importlib.util
import pathlib
import unittest
from unittest.mock import patch

PATH = pathlib.Path(__file__).resolve().parents[1] / 'libexec/platform_host_updates.py'
spec = importlib.util.spec_from_file_location('host_updates', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
BOOT = '11111111-1111-1111-1111-111111111111'
INSTALLED = {'openssl': '1.0', 'curl': '2.0'}
SIMULATION = '''Reading package lists...
The following packages have been kept back:
  kernel-special
The following packages will be upgraded:
  openssl
Inst openssl [1.0] (1.1 Debian:stable [amd64])
Conf openssl (1.1 Debian:stable [amd64])
'''


class HostTests(unittest.TestCase):
    def setUp(self):
        busy = patch.object(m, 'package_manager_busy', return_value=False)
        busy.start()
        self.addCleanup(busy.stop)
        recovery = patch.object(m, '_persist_package_recovery')
        self.recovery = recovery.start()
        self.addCleanup(recovery.stop)
        self.boot = patch.object(m, '_boot_id', return_value=BOOT)
        self.boot.start()
        self.addCleanup(self.boot.stop)
        self.inv = patch.object(m, 'inventory', return_value={'bootId': BOOT, 'rebootRequired': True, 'rebootPackages': []})
        self.inv.start()
        self.addCleanup(self.inv.stop)

    def make_plan(self):
        packages, kept = m._simulation(SIMULATION, INSTALLED)
        return m.plan({'bootId': BOOT, 'checkedAt': int(m.time.time()), 'packages': packages, 'keptBack': kept,
                       'installedFingerprint': m._digest(INSTALLED), 'candidateFingerprint': m._digest(packages), 'rebootRequired': False})

    def test_simulation_exact_packages_and_kept_back(self):
        packages, kept = m._simulation(SIMULATION, INSTALLED)
        self.assertEqual(packages, [{'name': 'openssl', 'currentVersion': '1.0', 'targetVersion': '1.1'}])
        self.assertEqual(kept, ['kernel-special'])
        for text in ['Remv openssl [1.0]', 'Inst new-package (1.0 Debian [amd64])', 'Inst openssl [0.9] (1.1 Debian [amd64])']:
            with self.assertRaises(m.HostUpdateError):
                m._simulation(text, INSTALLED)

    def test_check_refreshes_then_simulates_without_mutation(self):
        calls = []
        def run(args, *unused, **kwargs):
            calls.append(args)
            return SIMULATION if '-s' in args else ''
        with patch.object(m, '_run', side_effect=run), patch.object(m, '_installed', return_value=INSTALLED):
            result = m.check()
        self.assertIn('update', calls[0])
        self.assertIn('--error-on=any', calls[0])
        self.assertIn('-s', calls[1])
        self.assertEqual(result['packages'][0]['targetVersion'], '1.1')
        self.assertFalse(any('dist-upgrade' in args or 'remove' in args for args in calls))

    def test_apply_uses_exact_approved_versions_and_verifies_install(self):
        value, events = self.make_plan(), []
        with patch.object(m, '_installed', side_effect=[INSTALLED, {**INSTALLED, 'openssl': '1.1'}]), patch.object(m, '_run', side_effect=[SIMULATION, SIMULATION, '', '']) as run:
            result = m.apply(value, events.append)
        self.assertEqual(result['state'], 'succeeded')
        self.assertEqual(result['packages'][0]['state'], 'succeeded')
        command = run.call_args_list[-1].args[0]
        self.assertIn('openssl=1.1', command)
        self.assertIn('--no-remove', command)
        self.assertIn('--only-upgrade', command)
        self.assertIn('Dpkg::Options::=--force-confold', command)
        self.assertNotIn('--allow-downgrades', command)
        self.assertEqual(events[-1]['state'], 'succeeded')

    def test_changed_inventory_candidates_or_plan_block_before_upgrade(self):
        value = self.make_plan()
        tampered = copy.deepcopy(value)
        tampered['packages'][0]['targetVersion'] = '9.9'
        with patch.object(m, '_run') as run:
            with self.assertRaisesRegex(m.HostUpdateError, 'immutable'):
                m.apply(tampered)
            run.assert_not_called()
        with patch.object(m, '_installed', return_value={'openssl': '0.9'}), patch.object(m, '_run') as run:
            with self.assertRaisesRegex(m.HostUpdateError, 'installed package'):
                m.apply(value)
            run.assert_not_called()
        with patch.object(m, '_installed', return_value=INSTALLED), patch.object(m, '_run', return_value=SIMULATION.replace('(1.1 ', '(1.2 ')) as run:
            with self.assertRaisesRegex(m.HostUpdateError, 'candidates changed'):
                m.apply(value)
            self.assertEqual(run.call_count, 1)

    def test_expired_plan_and_failed_apt_do_not_claim_rollback(self):
        value = self.make_plan()
        with patch.object(m.time, 'time', return_value=value['expiresAt'] + 1):
            with self.assertRaisesRegex(m.HostUpdateError, 'expired'):
                m.apply(value)
        with patch.object(m, '_installed', return_value=INSTALLED), patch.object(m, '_run', side_effect=m.HostUpdateError('package lock held')):
            with self.assertRaisesRegex(m.HostUpdateError, 'lock held'):
                m.apply(value)

    def test_machine_progress_keeps_arch_and_does_not_expose_messages(self):
        events = []
        m._status('pmstatus:libssl:amd64:42.5:Installing https://user:secret@proxy/', events.append)
        self.assertEqual(events, [{'stage': 'packages', 'package': 'libssl:amd64', 'percent': 42.5, 'state': 'running', 'protocol': 'pmstatus'}])
        m._status('arbitrary prose completed', events.append)
        self.assertEqual(len(events), 1)

    def test_reboot_persists_before_separate_scheduling_and_checks_new_boot(self):
        value, persisted = m.reboot_plan(), []
        with patch.object(m, '_run') as run:
            with self.assertRaisesRegex(m.HostUpdateError, 'REBOOT'):
                m.prepare_reboot(value, persisted.append, 'UPDATE')
            intent = m.prepare_reboot(value, persisted.append, 'REBOOT')
            run.assert_not_called()
        self.assertEqual(persisted, [intent])
        with patch.object(m, '_run', return_value='') as run:
            self.assertEqual(m.schedule_reboot(intent)['state'], 'waiting-reboot')
            self.assertIn('--on-active=5s', run.call_args.args[0])
        self.assertEqual(m.reconcile_reboot(intent, lambda: True)['state'], 'waiting-reboot')
        with patch.object(m, '_boot_id', return_value='22222222-2222-2222-2222-222222222222'):
            self.assertEqual(m.reconcile_reboot(intent)['state'], 'verifying-services')
            self.assertEqual(m.reconcile_reboot(intent, lambda: True)['state'], 'succeeded')
            self.assertEqual(m.reconcile_reboot(intent, lambda: False)['state'], 'verifying-services')

    def test_failed_durable_reboot_intent_never_schedules(self):
        def fail(value):
            raise OSError('durable write failed')
        with patch.object(m, '_run') as run:
            with self.assertRaises(OSError):
                m.prepare_reboot(m.reboot_plan(), fail, 'REBOOT')
            run.assert_not_called()

    def test_reboot_is_unavailable_when_not_required(self):
        with patch.object(m, 'inventory', return_value={'bootId': BOOT, 'rebootRequired': False}):
            with self.assertRaisesRegex(m.HostUpdateError, 'not required'):
                m.reboot_plan()

    def test_transient_delegation_has_only_fixed_root_worker_actions(self):
        payload = '{"type":"result","value":{"packages":[]}}\n'
        with patch.object(m, '_run', return_value=payload) as run:
            result = m.run_transient('check', operation_id='a' * 32)
            command = run.call_args.args[0]
        self.assertEqual(result, {'packages': []})
        self.assertIn('--property=NoNewPrivileges=yes', command)
        self.assertIn('--property=PrivateTmp=yes', command)
        self.assertEqual(command[-4:], ['/usr/bin/python3', '/usr/local/libexec/platform_host_updates.py', '--worker', 'check'])
        with patch.object(m, '_run') as run:
            for action in ['reboot;sh', 'shell', '/bin/sh']:
                with self.assertRaises(m.HostUpdateError):
                    m.run_transient(action)
            with self.assertRaises(m.HostUpdateError):
                m.run_transient('apply', plan_file='/tmp/attacker.json')
            with self.assertRaises(m.HostUpdateError):
                m.run_transient('check', operation_id='../../evil')
            run.assert_not_called()

    def test_worker_json_progress_is_forwarded(self):
        events = []
        m._status('{"type":"progress","value":{"stage":"refresh","state":"running"}}', events.append)
        self.assertEqual(events, [{'stage': 'refresh', 'state': 'running'}])

    def test_external_apt_lock_blocks_reboot(self):
        with patch.object(m, 'package_manager_busy', return_value=True):
            with self.assertRaisesRegex(m.HostUpdateError, 'reboot blocked'):
                m.prepare_reboot(m.reboot_plan(), lambda _: None, 'REBOOT')

    def test_plan_reader_rejects_symlink_and_nonprivate_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            name = root / ('a' * 32 + '.json')
            name.write_text('{"planId":"' + 'a' * 32 + '"}')
            name.chmod(0o644)
            with patch.object(m, '_PLAN_DIRECTORY', root), patch.object(m, '_private_directory'):
                with self.assertRaises(m.HostUpdateError):
                    m._read_plan_file(str(name))
                link = root / ('b' * 32 + '.json')
                link.symlink_to(name)
                with self.assertRaises(OSError):
                    m._read_plan_file(str(link))

    def test_exact_solver_cannot_add_unapproved_packages(self):
        value = self.make_plan()
        with patch.object(m, '_installed', return_value=INSTALLED), patch.object(m, '_run', side_effect=[SIMULATION, SIMULATION + 'Inst new-package (1.0 Debian [amd64])\n']) as run:
            with self.assertRaisesRegex(m.HostUpdateError, 'adds packages'):
                m.apply(value)
            self.assertEqual(run.call_count, 2)

    def test_apply_restores_only_original_automatic_package_marks(self):
        value = self.make_plan()
        with patch.object(m, '_installed', side_effect=[INSTALLED, {**INSTALLED, 'openssl': '1.1'}]), patch.object(m, '_run', side_effect=[SIMULATION, SIMULATION, 'openssl\ncurl\n', '', '']) as run:
            self.assertEqual(m.apply(value)['state'], 'succeeded')
        self.assertEqual(run.call_args_list[-1].args[0], ['apt-mark', 'auto', '--', 'openssl'])

    def test_upgrade_failure_restores_marks_and_never_claims_success(self):
        with patch.object(m, '_installed', return_value=INSTALLED), patch.object(m, '_run', side_effect=[SIMULATION, SIMULATION, 'openssl\n', m.HostUpdateError('upgrade failed'), '']) as run:
            with self.assertRaisesRegex(m.HostUpdateError, 'upgrade failed'):
                m.apply(self.make_plan())
        self.assertEqual(run.call_args_list[-1].args[0], ['apt-mark', 'auto', '--', 'openssl'])

    def test_mark_restore_failure_reports_required_recovery(self):
        events = []
        with patch.object(m, '_installed', return_value=INSTALLED), patch.object(m, '_run', side_effect=[SIMULATION, SIMULATION, 'openssl\n', '', m.HostUpdateError('mark write failed')]):
            with self.assertRaisesRegex(m.HostUpdateError, 'recovery required'):
                m.apply(self.make_plan(), events.append)
        self.assertEqual(self.recovery.call_args.args[-1], 'mark-restoration-required')
        self.assertEqual(events[-1]['recoveryRequired'], True)
        self.assertEqual(events[-1]['state'], 'failed')

    def test_running_maintenance_blocks_reboot(self):
        with patch.object(m, 'active_maintenance', return_value=True):
            with self.assertRaisesRegex(m.HostUpdateError, 'reboot blocked'):
                m.prepare_reboot(m.reboot_plan(), lambda _: None, 'REBOOT')


if __name__ == '__main__':
    unittest.main()
