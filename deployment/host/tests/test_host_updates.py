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
        # These existing unit tests isolate upgrade/recovery behavior. The
        # combined solver and real cleanup path have dedicated fixtures below.
        self.automatic = []
        cleanup = patch.object(m, '_autoremove_plan', side_effect=lambda installed, packages: self.cleanup(packages))
        cleanup.start()
        self.addCleanup(cleanup.stop)
        cleanup_apply = patch.object(m, '_apply_autoremove', return_value=0)
        cleanup_apply.start()
        self.addCleanup(cleanup_apply.stop)
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

    def cleanup(self, packages):
        return {'packages': packages, 'autoremove': [], 'automaticPackages': self.automatic,
                'protectedPackages': [], 'automaticFingerprint': m._digest(self.automatic),
                'protectedPackageFingerprint': m._digest([]), 'autoremoveFingerprint': m._digest([])}

    def make_plan(self):
        packages, kept = m._simulation(SIMULATION, INSTALLED)
        return m.plan({'bootId': BOOT, 'checkedAt': int(m.time.time()), 'packages': packages, 'keptBack': kept,
                       'installedFingerprint': m._digest(INSTALLED), 'candidateFingerprint': m._digest(packages), 'rebootRequired': False, **self.cleanup(packages)})

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
        self.assertEqual(command[-6:], ['/usr/bin/python3', '/usr/local/libexec/platform_host_updates.py', '--worker', 'check', '--operation-id', 'a' * 32])
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
        self.automatic = ['curl', 'openssl']
        value = self.make_plan()
        with patch.object(m, '_installed', side_effect=[INSTALLED, {**INSTALLED, 'openssl': '1.1'}]), patch.object(m, '_run', side_effect=[SIMULATION, SIMULATION, 'openssl\ncurl\n', '', '']) as run:
            self.assertEqual(m.apply(value)['state'], 'succeeded')
        self.assertEqual(run.call_args_list[-1].args[0], ['apt-mark', 'auto', '--', 'openssl'])

    def test_upgrade_failure_restores_marks_and_never_claims_success(self):
        self.automatic = ['openssl']
        with patch.object(m, '_installed', return_value=INSTALLED), patch.object(m, '_run', side_effect=[SIMULATION, SIMULATION, 'openssl\n', m.HostUpdateError('upgrade failed'), '']) as run:
            with self.assertRaisesRegex(m.HostUpdateError, 'upgrade failed'):
                m.apply(self.make_plan())
        self.assertEqual(run.call_args_list[-1].args[0], ['apt-mark', 'auto', '--', 'openssl'])

    def test_mark_restore_failure_reports_required_recovery(self):
        self.automatic = ['openssl']
        events = []
        with patch.object(m, '_installed', return_value=INSTALLED), patch.object(m, '_run', side_effect=[SIMULATION, SIMULATION, 'openssl\n', '', m.HostUpdateError('mark write failed')]):
            with self.assertRaisesRegex(m.HostUpdateError, 'recovery required'):
                m.apply(self.make_plan(), events.append)
        self.assertEqual(self.recovery.call_args.args[-1], 'mark-restoration-required')
        self.assertEqual(events[-1]['recoveryRequired'], True)
        self.assertEqual(events[-1]['state'], 'failed')

    def test_real_multiarch_simulation_uses_canonical_installed_identity(self):
        installed = {'libsystemd0:amd64': '259.5-0ubuntu3.4'}
        simulation = 'Inst libsystemd0 [259.5-0ubuntu3.4] (259.5-0ubuntu3.5 Ubuntu [amd64])\n'
        packages, _ = m._simulation(simulation, installed)
        self.assertEqual(packages, [{'name': 'libsystemd0:amd64', 'currentVersion': '259.5-0ubuntu3.4', 'targetVersion': '259.5-0ubuntu3.5'}])
        with self.assertRaisesRegex(m.HostUpdateError, 'ambiguous'):
            m._simulation(simulation, {**installed, 'libsystemd0:i386': '259.5-0ubuntu3.4'})
        self.assertEqual(m._canonical_package('curl:amd64', {'curl': '2.0'}), 'curl')
        with self.assertRaises(m.HostUpdateError):
            m._canonical_package('curl:arm64', {'curl': '2.0', 'curl:i386': '2.0'})
        with self.assertRaises(m.HostUpdateError):
            m._canonical_package('libsystemd0:arm64', installed)

    def test_multiarch_automatic_flags_restore_using_canonical_plan_name(self):
        installed = {'libsystemd0:amd64': '259.5-0ubuntu3.4'}
        simulation = 'Inst libsystemd0 [259.5-0ubuntu3.4] (259.5-0ubuntu3.5 Ubuntu [amd64])\n'
        packages, kept = m._simulation(simulation, installed)
        self.automatic = ['libsystemd0:amd64']
        value = m.plan({'bootId': BOOT, 'checkedAt': int(m.time.time()), 'packages': packages, 'keptBack': kept,
                        'installedFingerprint': m._digest(installed), 'candidateFingerprint': m._digest(packages), 'rebootRequired': False, **self.cleanup(packages)})
        with patch.object(m, '_installed', side_effect=[installed, {'libsystemd0:amd64': '259.5-0ubuntu3.5'}]), patch.object(m, '_run', side_effect=[simulation, simulation, 'libsystemd0\n', '', '']) as run:
            result = m.apply(value)
        self.assertEqual(result['state'], 'succeeded')
        self.assertIn('libsystemd0:amd64=259.5-0ubuntu3.5', run.call_args_list[-2].args[0])
        self.assertEqual(run.call_args_list[-1].args[0], ['apt-mark', 'auto', '--', 'libsystemd0:amd64'])
        self.assertEqual(self.recovery.call_args.args[1], ['libsystemd0:amd64'])

    def test_worker_closed_stdout_continues_apply_and_persists_verified_result(self):
        value, persisted, stages = self.make_plan(), [], []
        def apply(plan, progress):
            progress({'stage': 'upgrade', 'state': 'running'})
            stages.append('packages configured')
            progress({'stage': 'restore-package-marks', 'state': 'running'})
            stages.append('automatic marks restored')
            return {'state': 'succeeded', 'packages': [{**value['packages'][0], 'state': 'succeeded'}]}
        def persist(record):
            persisted.append(copy.deepcopy(record))
        with patch.object(m, '_read_plan_file', return_value=value), patch.object(m, '_persist_worker_status', side_effect=persist), patch.object(m, 'apply', side_effect=apply), patch.object(m, '_run', return_value='') as run, patch('builtins.print', side_effect=BrokenPipeError), patch.object(m, '_silence_stdout') as silence:
            result = m._execute_worker('apply', 'a' * 32, '/root/private-plan')
        self.assertEqual(stages, ['packages configured', 'automatic marks restored'])
        self.assertEqual(persisted[0]['state'], 'running')
        self.assertEqual(persisted[-1]['state'], 'succeeded')
        self.assertEqual(persisted[-1]['result'], result)
        self.assertTrue(result['packageVersionsVerified'])
        self.assertTrue(result['dpkgAuditClean'])
        self.assertTrue(result['marksRestored'])
        self.assertEqual(result['planId'], value['planId'])
        self.assertEqual(run.call_args.args[0], ['dpkg', '--audit'])
        self.assertEqual(silence.call_count, 3)

    def test_real_broken_stdout_flush_exits_zero_without_apt(self):
        import subprocess
        import sys
        code = ('import importlib.util,os;'
                's=importlib.util.spec_from_file_location("host",' + repr(str(PATH)) + ');'
                'm=importlib.util.module_from_spec(s);s.loader.exec_module(m);'
                'r,w=os.pipe();os.close(r);os.dup2(w,1);os.close(w);'
                'm._worker_print({"type":"progress"});m._worker_print({"type":"result"})')
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_worker_dirty_dpkg_audit_persists_failure_not_success(self):
        persisted = []
        with patch.object(m, '_read_plan_file', return_value=self.make_plan()), patch.object(m, '_persist_worker_status', side_effect=lambda value: persisted.append(copy.deepcopy(value))), patch.object(m, 'apply', return_value={'state': 'succeeded', 'packages': []}), patch.object(m, '_run', return_value='half configured package'), patch.object(m, '_worker_print'):
            with self.assertRaisesRegex(m.HostUpdateError, 'audit is not clean'):
                m._execute_worker('apply', 'a' * 32, '/root/private-plan')
        self.assertEqual(persisted[-1]['state'], 'failed')
        self.assertNotIn('result', persisted[-1])

    def test_worker_alive_checks_unit_without_relaunch(self):
        with patch.object(m, '_run', return_value='active\n') as run:
            self.assertIs(m.worker_alive('a' * 32), True)
            self.assertEqual(run.call_args.args[0][0], 'systemctl')
        with patch.object(m, '_run', return_value='inactive\n'):
            self.assertIs(m.worker_alive('a' * 32), False)
        with patch.object(m, '_run', return_value='inactive\n'), patch.object(m, 'package_manager_busy', return_value=True):
            self.assertIsNone(m.worker_alive('a' * 32))
        with patch.object(m, '_run', side_effect=m.HostUpdateError('query unavailable')):
            self.assertIsNone(m.worker_alive('a' * 32))

    def test_running_maintenance_blocks_reboot(self):
        with patch.object(m, 'active_maintenance', return_value=True):
            with self.assertRaisesRegex(m.HostUpdateError, 'reboot blocked'):
                m.prepare_reboot(m.reboot_plan(), lambda _: None, 'REBOOT')


class AutoremoveTests(unittest.TestCase):
    """Exercise the actual combined-solver/cleanup path with command fixtures."""
    def setUp(self):
        import tempfile
        import types
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.guard_directory = pathlib.Path(temporary.name)
        original_fstat = m.os.fstat
        def root_file_info(descriptor):
            value = original_fstat(descriptor)
            return types.SimpleNamespace(st_mode=value.st_mode, st_uid=0, st_nlink=value.st_nlink, st_size=value.st_size)
        for name, options in [('_PLAN_DIRECTORY', {'new': self.guard_directory}),
                               ('_private_directory', {'return_value': None})]:
            mocked = patch.object(m, name, **options)
            mocked.start()
            self.addCleanup(mocked.stop)
        mocked = patch.object(m.os, 'fstat', side_effect=root_file_info)
        mocked.start()
        self.addCleanup(mocked.stop)
        self.installed = {'example-tool': '1.0', 'unused-lib': '2.0', 'manual-tool': '1.0', 'linux-image-fallback': '6.0'}
        self.original = dict(self.installed)
        self.automatic = {'unused-lib', 'linux-image-fallback'}
        self.calls, self.records, self.events = [], [], []
        self.upgrade = 'Inst example-tool [1.0] (1.1 Debian [amd64])\n'
        # unused-lib becomes orphaned only AFTER the approved example-tool upgrade.
        self.combined = self.upgrade + 'Remv unused-lib [2.0]\n'
        self.post = 'Remv unused-lib [2.0]\n'
        self.fail_cleanup = False
        self.extra_after_cleanup = False
        self.files = {}
        self.before_hook = None
        for name, value in [('_boot_id', BOOT), ('inventory', {'bootId': BOOT, 'rebootRequired': False})]:
            mocked = patch.object(m, name, return_value=value)
            mocked.start()
            self.addCleanup(mocked.stop)
        for name, function in [('_installed', lambda: dict(self.installed)), ('_run', self.run_command),
                               ('_persist_package_recovery', lambda value, automatic, state: self.records.append((state, list(automatic))))]:
            mocked = patch.object(m, name, side_effect=function)
            mocked.start()
            self.addCleanup(mocked.stop)

    def run_command(self, args, *unused, **kwargs):
        self.calls.append(list(args))
        if args == ['apt-mark', 'showauto']:
            return '\n'.join(sorted(self.automatic))
        if args[:3] == ['apt-mark', 'auto', '--']:
            self.automatic.update(args[3:])
            return ''
        if args[:2] == ['dpkg-query', '-W']:
            return '\n'.join(name + '\tno\tno\toptional' for name in self.installed)
        if args[:2] == ['dpkg-query', '-L']:
            return self.files.get(args[2], '/usr/lib/' + args[2] + '.so')
        if args == ['dpkg', '--audit']:
            return ''
        if args[0] != 'apt-get':
            self.fail('unexpected command: ' + repr(args))
        if 'update' in args:
            return ''
        if '-s' in args:
            if '--autoremove' in args:
                return self.combined
            if 'autoremove' in args:
                return self.post
            return self.upgrade
        if 'install' in args:
            for argument in args:
                if re_match := m.re.fullmatch(r'([a-z][a-z0-9-]*)=([^=]+)', argument):
                    self.installed[re_match[1]] = re_match[2]
                    self.automatic.discard(re_match[1])
            return ''
        if 'autoremove' in args:
            hook = next(argument for argument in args if argument.startswith('DPkg::Pre-Invoke::='))
            import shlex
            words = shlex.split(hook.split('=', 1)[1])
            self.assertEqual(words[:3], ['/usr/bin/python3', m._WORKER, '--autoremove-guard'])
            if self.before_hook:
                self.before_hook()
            m._autoremove_guard(words[3])  # Model APT invoking the hook before dpkg.
            if self.fail_cleanup:
                raise m.HostUpdateError('cleanup fixture failed')
            if unused and unused[0]:
                unused[0]({'stage': 'packages', 'state': 'running', 'percent': 50})
            self.installed.pop('unused-lib', None)
            self.automatic.discard('unused-lib')
            if self.extra_after_cleanup:
                self.installed.pop('manual-tool', None)
            return ''
        self.fail('unexpected apt command: ' + repr(args))

    def make_plan(self):
        return m.plan(m.check())

    def mutations(self):
        return [args for args in self.calls if args[0] == 'apt-get' and '-s' not in args and ('install' in args or 'autoremove' in args)]

    def test_predicts_post_upgrade_orphan_then_removes_only_after_upgrade_and_marks(self):
        self.automatic.add('example-tool')
        value = self.make_plan()
        self.assertEqual(value['autoremove'], [{'name': 'unused-lib', 'installedVersion': '2.0'}])
        self.assertEqual(value['autoremoveCount'], 1)
        self.assertTrue(any('--autoremove' in args and 'upgrade' in args for args in self.calls))
        self.assertFalse(any('autoremove' in args for args in self.calls))  # no pre-upgrade orphan-only prediction
        result = m.apply(value, self.events.append)
        self.assertEqual(result['removedCount'], 1)
        self.assertTrue(result['autoremoveVerified'])
        upgrade, cleanup = self.mutations()
        self.assertIn('example-tool=1.1', upgrade)
        restore = self.calls.index(['apt-mark', 'auto', '--', 'example-tool'])
        self.assertLess(restore, self.calls.index(cleanup))
        self.assertIn('APT::Get::Purge=false', cleanup)
        self.assertFalse(any('--purge' in args or 'autopurge' in args for args in self.calls))
        self.assertIn('example-tool', self.automatic)
        self.assertIn('linux-image-fallback', self.installed)
        self.assertIn('manual-tool', self.installed)
        self.assertEqual([event['stage'] for event in self.events][-4:], ['autoremove', 'autoremove', 'verify-autoremove', 'complete'])
        self.assertEqual(self.records[-1][0], 'autoremove-verified')

    def test_no_orphans_still_verifies_without_running_autoremove_mutation(self):
        self.combined, self.post = self.upgrade, ''
        value = self.make_plan()
        result = m.apply(value)
        self.assertEqual(value['autoremoveCount'], 0)
        self.assertEqual(result['removedCount'], 0)
        self.assertTrue(result['autoremoveVerified'])
        self.assertEqual(len(self.mutations()), 1)

    def test_cleanup_only_plan_is_valid_and_does_not_run_empty_install(self):
        self.upgrade, self.combined = '', 'Remv unused-lib [2.0]\n'
        value = self.make_plan()
        result = m.apply(value)
        self.assertEqual(value['packages'], [])
        self.assertEqual(result['removedCount'], 1)
        self.assertEqual(len(self.mutations()), 1)
        self.assertIn('autoremove', self.mutations()[0])

    def test_changed_cleanup_plan_or_automatic_marks_abort_before_any_mutation(self):
        value = self.make_plan()
        self.combined = self.upgrade
        with self.assertRaisesRegex(m.HostUpdateError, 'autoremove plan'):
            m.apply(value)
        self.assertEqual(self.mutations(), [])
        self.combined = self.upgrade + 'Remv unused-lib [2.0]\n'
        self.automatic.add('manual-tool')
        with self.assertRaisesRegex(m.HostUpdateError, 'autoremove plan'):
            m.apply(value)
        self.assertEqual(self.mutations(), [])

    def test_legacy_check_and_plan_require_fresh_check_without_package_mutation(self):
        value = self.make_plan()
        for key in m._CLEANUP_FIELDS:
            value.pop(key)
        value.pop('revision')
        m._seal(value)
        self.calls.clear()
        with self.assertRaisesRegex(m.HostUpdateError, 'predates autoremove'):
            m.apply(value)
        with self.assertRaisesRegex(m.HostUpdateError, 'fresh check'):
            m.plan({'checkedAt': int(m.time.time())})
        self.assertEqual(self.calls, [])

    def test_post_upgrade_solver_change_removes_nothing_and_retains_upgrade(self):
        value = self.make_plan()
        self.post = ''
        with self.assertRaisesRegex(m.HostUpdateError, 'post-upgrade autoremove candidates changed'):
            m.apply(value)
        self.assertEqual(self.installed['example-tool'], '1.1')
        self.assertIn('unused-lib', self.installed)
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(self.records[-1][0], 'marks-restored')

    def test_cleanup_failure_retains_recovery_marks_without_claiming_rollback(self):
        value = self.make_plan()
        self.fail_cleanup = True
        with self.assertRaisesRegex(m.HostUpdateError, 'cleanup fixture failed'):
            m.apply(value)
        self.assertEqual(self.records[-1], ('autoremove-failed', sorted(self.automatic)))
        self.assertEqual(self.installed['example-tool'], '1.1')
        self.assertIn('unused-lib', self.installed)

    def test_manual_kernel_essential_and_service_provider_cannot_be_removed(self):
        for name in ['manual-tool', 'linux-image-fallback']:
            self.combined = self.upgrade + 'Remv ' + name + ' [' + self.installed[name] + ']\n'
            with self.assertRaisesRegex(m.HostUpdateError, 'protected/manual'):
                self.make_plan()
        self.combined = self.upgrade + 'Remv unused-lib [2.0]\n'
        self.files['unused-lib'] = '/lib/systemd/system/example.service\n'
        with self.assertRaisesRegex(m.HostUpdateError, 'host service provider'):
            self.make_plan()
        self.files.clear()
        original = self.run_command
        def essential(args, *values, **kwargs):
            result = original(args, *values, **kwargs)
            return result.replace('unused-lib\tno\tno\toptional', 'unused-lib\tyes\tno\trequired') if args[:2] == ['dpkg-query', '-W'] else result
        with patch.object(m, '_run', side_effect=essential):
            with self.assertRaisesRegex(m.HostUpdateError, 'protected/manual'):
                self.make_plan()
        self.assertEqual(self.mutations(), [])

    def test_extra_removed_package_or_wrong_version_fails_verification(self):
        value = self.make_plan()
        self.extra_after_cleanup = True
        with self.assertRaisesRegex(m.HostUpdateError, 'verification failed'):
            m.apply(value)
        self.assertNotEqual(self.records[-1][0], 'autoremove-verified')
        with self.assertRaisesRegex(m.HostUpdateError, 'changed version'):
            m._removals('Remv unused-lib [9.0]', self.original, ['unused-lib'], [])

    def test_actual_command_protects_every_nonapproved_automatic_package(self):
        self.installed['other-auto-lib'] = '3.0'
        self.automatic.add('other-auto-lib')
        value = self.make_plan()
        m.apply(value)
        command = self.mutations()[-1]
        self.assertIn('APT::NeverAutoRemove::=^other\\-auto\\-lib$', command)
        self.assertNotIn('APT::NeverAutoRemove::=^unused\\-lib$', command)
        self.assertIn('other-auto-lib', self.installed)

    def test_lock_time_hook_blocks_new_or_upgraded_package_marks_and_service_drift(self):
        changes = [lambda: self.installed.update({'new-orphan': '1.0'}),
                   lambda: self.installed.update({'unused-lib': '2.1'}),
                   lambda: self.automatic.add('manual-tool'),
                   lambda: self.files.update({'unused-lib': '/lib/systemd/system/new.service'})]
        for change in changes:
            with self.subTest(change=change):
                self.installed = dict(self.original)
                self.automatic = {'unused-lib', 'linux-image-fallback'}
                self.files = {}
                value = self.make_plan()
                self.before_hook = change
                with self.assertRaises(m.HostUpdateError):
                    m.apply(value)
                self.assertIn('unused-lib', self.installed)
                self.assertNotEqual(self.records[-1][0], 'autoremove-verified')
                self.assertFalse(list(self.guard_directory.glob('*.autoremove-guard.json')))

    def test_multiarch_protection_uses_base_names_and_retains_sibling_architectures(self):
        self.installed.update({'libexample:amd64': '1.0', 'libexample:i386': '1.0'})
        self.automatic.add('libexample:amd64')
        options = m._cleanup_options(['libexample:amd64', 'libexample:i386'])
        self.assertIn('APT::NeverAutoRemove::=^libexample$', options)
        self.assertFalse(any(':amd64$' in value or ':i386$' in value for value in options))
        protected = m._protected_packages(self.installed)
        self.assertIn('libexample:amd64', protected)
        self.assertIn('libexample:i386', protected)
        value = self.make_plan()
        m.apply(value)
        self.assertIn('libexample:amd64', self.installed)
        self.assertIn('libexample:i386', self.installed)

    def test_guard_rejects_untrusted_paths_permissions_and_modified_record(self):
        value = self.make_plan()
        path = m._write_autoremove_guard(value, self.installed, sorted(self.automatic), value['protectedPackages'])
        self.assertTrue(m._autoremove_guard(str(path)))
        with self.assertRaisesRegex(m.HostUpdateError, 'outside private'):
            m._autoremove_guard('/tmp/unapproved.json')
        link = self.guard_directory / ('b' * 32 + '.autoremove-guard.json')
        link.symlink_to(path)
        with self.assertRaises(OSError):
            m._autoremove_guard(str(link))
        path.chmod(0o644)
        with self.assertRaisesRegex(m.HostUpdateError, 'private root-owned'):
            m._autoremove_guard(str(path))
        path.chmod(0o600)
        import json
        record = json.loads(path.read_text())
        record['autoremove'] = []
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(m.HostUpdateError, 'immutable'):
            m._autoremove_guard(str(path))


if __name__ == '__main__':
    unittest.main()
