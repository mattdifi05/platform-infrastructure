import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'libexec'))
import platform_runtime_updates as worker


CONTAINER = 'a' * 64
IMAGE = 'sha256:' + 'b' * 64
PROFILE = {'id': 'project-db', 'projectId': 'project', 'containerId': CONTAINER, 'imageId': IMAGE, 'name': 'app'}
OTHER = {**PROFILE, 'id': 'other-db', 'projectId': 'other', 'containerId': 'c' * 64, 'name': 'other'}
ROW = ('project-db', 'project', CONTAINER, IMAGE, 'app')
OTHER_ROW = ('other-db', 'other', 'c' * 64, IMAGE, 'other')


class DatabaseSizeTests(unittest.TestCase):
    def test_admission_requires_private_regular_file_and_exact_unique_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'profiles.json'
            original_fstat = os.fstat

            def root_fstat(fd):
                info = original_fstat(fd)
                return types.SimpleNamespace(st_uid=0, st_mode=info.st_mode)

            with patch.object(worker, 'DATABASE_SIZE_PROFILES', path), patch.object(worker, 'protected', return_value=path), patch.object(worker.os, 'fstat', side_effect=root_fstat):
                path.write_text(json.dumps({'profiles': [PROFILE, OTHER]}))
                path.chmod(0o600)
                self.assertEqual(worker.database_size_profiles(), [ROW, OTHER_ROW])
                path.chmod(0o640)
                self.assertEqual(worker.database_size_profiles(), [])
                path.chmod(0o600)
                path.write_text(json.dumps({'profiles': [PROFILE, {**PROFILE, 'id': 'foreign-db', 'projectId': 'other'}]}))
                self.assertEqual(worker.database_size_profiles(), [])
                path.write_text(json.dumps({'profiles': [{**PROFILE, 'name': 'host=unsafe'}]}))
                self.assertEqual(worker.database_size_profiles(), [])

    def test_action_scopes_measurements_and_caches_known_zero(self):
        with patch.object(worker, 'database_size_profiles', return_value=[ROW, OTHER_ROW]), patch.object(worker, 'DATABASE_SIZE_CACHE', {}), patch.object(worker, 'measure_database_size', return_value=0) as measure:
            action = {'action': 'database-sizes', 'projectId': 'project'}
            result = worker.handle(action)
            self.assertEqual(result['databases'][0]['id'], 'project-db')
            self.assertEqual(result['databases'][0]['name'], 'app')
            self.assertEqual(result['databases'][0]['sizeBytes'], 0)
            self.assertTrue(result['databases'][0]['measuredAt'])
            self.assertEqual(worker.handle(action), result)
            self.assertEqual(worker.handle({'action': 'database-sizes', 'projectId': 'unknown'}), {'databases': []})
            self.assertEqual(measure.call_count, 1)
            self.assertEqual(measure.call_args.args[0], ROW)
            with self.assertRaises(worker.Rejected):
                worker.handle({**action, 'containerId': CONTAINER})
            with self.assertRaises(worker.Rejected):
                worker.handle({**action, 'projectId': ['project', 'other']})

    def test_null_metadata_when_measurement_fails(self):
        with patch.object(worker, 'database_size_profiles', return_value=[ROW]), patch.object(worker, 'DATABASE_SIZE_CACHE', {}), patch.object(worker, 'measure_database_size', return_value=None):
            self.assertEqual(worker.handle({'action': 'database-sizes', 'projectId': 'project'}), {
                'databases': [{'id': 'project-db', 'name': 'app', 'sizeBytes': None, 'measuredAt': None}],
            })

    def test_exec_pins_running_container_and_image_and_uses_fixed_local_query(self):
        inspected = f'{CONTAINER} {IMAGE} true\n'.encode()
        completed = lambda stdout: subprocess.CompletedProcess([], 0, stdout)
        with patch.object(worker.subprocess, 'run', side_effect=[completed(inspected), completed(b'1024\n')]) as run:
            self.assertEqual(worker.measure_database_size(ROW, time.monotonic() + 3.5), 1024)
            inspect, query = (call.args[0] for call in run.call_args_list)
            self.assertEqual(inspect[-1], CONTAINER)
            self.assertIn('--host=unix:///var/run/docker.sock', query)
            self.assertIn('--user=postgres', query)
            self.assertIn('--host=/var/run/postgresql', query)
            self.assertIn('--dbname=app', query)
            self.assertIn(CONTAINER, query)
            self.assertEqual(query[-1], '--command=SELECT pg_catalog.pg_database_size(pg_catalog.current_database())')
            self.assertTrue(all(call.kwargs['stderr'] == subprocess.DEVNULL for call in run.call_args_list))
        with patch.object(worker.subprocess, 'run', return_value=completed(inspected.replace(b'true', b'false'))) as run:
            self.assertIsNone(worker.measure_database_size(ROW, time.monotonic() + 3.5))
            self.assertEqual(run.call_count, 1)
        with patch.object(worker.subprocess, 'run', side_effect=[completed(inspected), completed(b'12\nunexpected\n')]):
            self.assertIsNone(worker.measure_database_size(ROW, time.monotonic() + 3.5))


if __name__ == '__main__':
    unittest.main()
