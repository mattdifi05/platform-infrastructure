"""Storage OTA contracts; all Docker and filesystem admission are fixtures."""
import hashlib
import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch
from test_runtime_updates import m, container

ROOT = pathlib.Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('storage_installer', ROOT / 'scripts/install-runtime-updates.py')
i = importlib.util.module_from_spec(spec)
spec.loader.exec_module(i)


class StorageUpdates(unittest.TestCase):
    def test_waf_readback_accepts_the_exact_image_environment_merge(self):
        rules = '/etc/nginx/conf.d/zz-reviewed-body-limits.conf'
        old = container()
        old['Config']['Env'] = ['PREVIOUS=keep', 'OVERRIDE=local']
        new = container()
        new['Config']['Env'] = ['NEW=default', 'OVERRIDE=local', 'PREVIOUS=keep']
        image = {'Config': {'Env': ['NEW=default', 'OVERRIDE=image']}}
        with patch.object(m, 'docker', return_value=image), patch.object(m, 'run', return_value='fixture-checksum  path'):
            qualified = m.waf_input_fingerprint(old, rules)
            m.verify_waf_inputs(old, new, qualified, rules)
            for changed in [['NEW=modified', 'OVERRIDE=local', 'PREVIOUS=keep'],
                            ['NEW=default', 'OVERRIDE=image', 'PREVIOUS=keep'],
                            new['Config']['Env'] + ['DUPLICATE=1', 'DUPLICATE=2']]:
                with self.subTest(environment=changed), self.assertRaises(m.Rejected):
                    m.verify_waf_inputs(old, {**new, 'Config': {**new['Config'], 'Env': changed}}, qualified, rules)
            with patch.object(m, 'run', return_value='changed-checksum  path'), self.assertRaises(m.Rejected):
                m.verify_waf_inputs(old, new, qualified, rules)

    def test_waf_uses_only_the_file_in_the_qualified_recipe(self):
        with tempfile.TemporaryDirectory() as temporary:
            context = pathlib.Path(temporary).resolve()
            target = '/etc/nginx/conf.d/zz-reviewed-body-limits.conf'
            recipe = context / 'Dockerfile'
            recipe.write_text('COPY --chmod=0644 reviewed-limits.conf ' + target + '\n')
            rules = context / 'reviewed-limits.conf'
            rules.write_text('client_max_body_size 2m;\n')
            row = {'dockerfile': str(recipe), 'buildContext': str(context),
                   'qualifiedBuildHashes': [hashlib.sha256(path.read_bytes()).hexdigest() for path in [recipe, rules]]}
            with patch.object(m, 'protected', side_effect=pathlib.Path):
                self.assertEqual(m.qualified_waf_body_rules(row), target)
                rules.write_text('client_max_body_size 4m;\n')
                with self.assertRaises(m.Rejected) as changed:
                    m.qualified_waf_body_rules(row)
                self.assertEqual(changed.exception.code, 'stale_plan')
                recipe.write_text('COPY ../unreviewed.conf ' + target + '\n')
                with self.assertRaises(m.Rejected) as unsupported:
                    m.qualified_waf_body_rules(row)
                self.assertEqual(unsupported.exception.code, 'unsupported')

    def test_waf_only_offers_qualified_digest(self):
        digest = 'sha256:' + '1' * 64
        other = 'sha256:' + '2' * 64
        row = dict(runtimeFamily='modsecurity-crs', strategy='reviewed-build', category='Sicurezza', qualifiedDigest=digest)
        latest = dict(version='4.30.0', imageDigest=digest)
        self.assertEqual(m.common_release(row, {'latestStable': latest}, '4.26.0', False)[0], latest)
        with self.assertRaises(m.Rejected):
            m.waf_runtime_checks(row, {**latest, 'imageDigest': other}, [])
        self.assertIsNone(m.common_release(row, {'latestStable': {**latest, 'imageDigest': other}}, '4.26.0', False)[0])

    def test_rustfs_requires_major_recovery_and_persistence(self):
        row = dict(repository='rustfs/rustfs', strategy='image', probe=['rustfs', '--version'],
                   requiresRecovery=True, compatibility='major', recoveryPolicy='offline-snapshot-v1')
        with patch.object(m, 'recovery_sources', return_value=['fixture']):
            m.storage_runtime_checks(row, [container()])
            for key, value in [('requiresRecovery', False), ('compatibility', 'latest'), ('probe', ['sh', '-c', 'rustfs --version'])]:
                with self.assertRaises(m.Rejected):
                    m.storage_runtime_checks({**row, key: value}, [container()])
        sensitive = dict(row, category='Archiviazione')
        self.assertIsNone(m.common_release(sensitive, {'latestStable': {'version': '2.0.0'}}, '1.0.0', False)[0])

    def test_gateway_isolated_exact_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary).resolve()
            source = pathlib.Path(directory) / 'nginx.conf'
            source.write_text('events {}\nhttp {}\n')
            old = container()
            old['Mounts'] = [dict(Type='bind', Source=str(source), Destination='/etc/nginx/nginx.conf', RW=False)]
            row = dict(gatewayConfigSha256=hashlib.sha256(source.read_bytes()).hexdigest())
            with patch.object(m, 'run') as run:
                m.gateway_preflight(old, row, 'candidate-image', directory)
                args = run.call_args.args[0]
                self.assertEqual(args[args.index('--network') + 1], 'none')
                self.assertEqual(args[-2:], ['candidate-image', '-t'])
                reviewed = directory / 'nginx.reviewed.conf'
                self.assertEqual(reviewed.read_bytes(), source.read_bytes())
                self.assertIn('type=bind,src=' + str(reviewed) + ',dst=/etc/nginx/nginx.conf,readonly', args)
            source.write_text('changed')
            with self.assertRaises(m.Rejected):
                m.gateway_config(old, row)

    def test_enrollment_keeps_gateway_separate_and_policy(self):
        gateway, nginx, rustfs = [container() for _ in range(3)]
        for row, name, service, image in [(gateway, 'gf-minio-gateway', 'rustfs-gateway', 'platform/custom:local'),
                                           (nginx, 'ordinary-nginx', 'nginx', 'nginx:1.30.5-alpine'),
                                           (rustfs, 'gf-rustfs', 'rustfs-backend', 'rustfs/rustfs:1.0.0')]:
            row['Name'] = '/' + name
            row['Image'] = 'sha256:' + hashlib.sha256(name.encode()).hexdigest()
            row['Config'].update(Image=image, Env=[], Labels={'com.docker.compose.project': 'platform_infra_vps', 'com.docker.compose.service': service})
        rows = i.discover([gateway, nginx, rustfs], ROOT)
        by_id = {r['id']: r for r in rows}
        self.assertEqual(by_id['rustfs-gateway']['containers'], ['gf-minio-gateway'])
        self.assertEqual(by_id['nginx']['containers'], ['ordinary-nginx'])
        self.assertTrue(by_id['rustfs-rustfs']['requiresRecovery'])
        previous = [{**by_id['rustfs-gateway'], 'gatewayConfigSha256': 'old-admitted-hash'}]
        i.preserve_enrollment_policy(rows, previous)
        self.assertEqual(by_id['rustfs-gateway']['gatewayConfigSha256'], 'old-admitted-hash')


if __name__ == '__main__':
    unittest.main()
