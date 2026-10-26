import importlib.util
import pathlib
import unittest
from unittest.mock import patch

PATH = pathlib.Path(__file__).resolve().parents[1] / 'libexec/platform_runtime_releases.py'
spec = importlib.util.spec_from_file_location('runtime_releases', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
D = 'sha256:' + 'a' * 64


def tag(name, architecture='amd64', digest=D):
    return {'name': name, 'digest': digest, 'images': [{'os': 'linux', 'architecture': architecture, 'digest': D}]}


class ReleasesTests(unittest.TestCase):
    def setUp(self):
        self.component = {'repository': 'example/php', 'tagSuffix': '-apache', 'compatibility': 'minor', 'versionScheme': 'semver', 'architecture': 'amd64'}

    def resolve(self, tags, current='8.5.10'):
        def get(client, url, headers=None):
            if 'auth.docker.io' in url:
                return {'token': 'token'}, {}
            if 'registry-1.docker.io' in url:
                return {'manifests': [{'platform': {'os': 'linux', 'architecture': self.component['architecture']}, 'digest': D}]}, {'Docker-Content-Digest': D}
            if 'raw.githubusercontent.com' in url:
                return 'Tags: ' + ', '.join(t['name'] for t in tags), {}
            if '?page_size=' not in url:
                return next(t for t in tags if url.endswith('/' + t['name'] + '/')), {}
            return {'results': tags, 'next': None}, {}
        with patch.object(m._Client, 'get', get):
            return m.resolve_release(self.component, current)

    def test_stable_suffix_and_compatibility(self):
        result = self.resolve([tag(n) for n in ['8.5.12-apache', '9.0.0-apache', '8.5.99-rc1-apache', '8.5.50-alpine', 'latest', '8.5.13-beta-apache']])
        self.assertEqual(result['latestStable']['version'], '9.0.0')
        self.assertEqual(result['candidateRelease']['version'], '9.0.0')
        self.assertEqual(result['candidateRelease']['imageReference'], 'docker.io/example/php:9.0.0-apache')
        self.assertEqual(result['candidateRelease']['imageDigest'], D)

    def test_no_downgrade(self):
        self.assertIsNone(self.resolve([tag('8.5.9-apache')])['candidateRelease'])

    def test_alignment_targets_latest_and_reuses_current_only_when_explicit(self):
        tags = [tag('8.5.12-apache'), tag('8.6.0-apache'), tag('8.5.11-apache')]
        self.assertEqual(self.resolve(tags, '8.5.12')['candidateRelease']['version'], '8.6.0')
        self.assertIsNone(self.resolve(tags, '8.6.0')['candidateRelease'])
        self.component['includeCurrent'] = True
        result = self.resolve(tags, '8.6.0')
        self.assertEqual(result['candidateRelease'], result['latestStable'])
        self.assertIsNone(self.resolve([tag('8.5.11-apache')], '8.5.12')['candidateRelease'])
        self.component['includeCurrent'] = 'true'
        self.assertIsNone(self.resolve(tags, '8.6.0')['candidateRelease'])

    def test_database_major_requires_migration_without_patch_fallback(self):
        self.component.update(repository='library/postgres', category='Database', tagSuffix='-alpine')
        result = self.resolve([tag('18.6-alpine'), tag('19.0-alpine')], '18.5')
        self.assertEqual(result['latestStable']['version'], '19.0')
        self.assertIsNone(result['candidateRelease'])
        self.assertIn('migration required', result['reason'])
        result = self.resolve([tag('18.6-alpine')], '18.5')
        self.assertEqual(result['candidateRelease'], result['latestStable'])

    def test_observe_remains_assisted(self):
        self.component['strategy'] = 'observe'
        result = self.resolve([tag('9.0.0-apache')])
        self.assertEqual(result['latestStable']['version'], '9.0.0')
        self.assertIsNone(result['candidateRelease'])
        self.assertIn('assisted', result['reason'])

    def test_architecture_and_duplicates(self):
        same = tag('8.5.12-apache')
        result = self.resolve([tag('8.5.99-apache', 'arm64'), same, same])
        self.assertEqual(result['latestStable']['version'], '8.5.12')

    def test_prefix_and_two_part_version(self):
        self.component.update(repository='library/postgres', tagPrefix='v', tagSuffix='-alpine', compatibility='major')
        self.assertEqual(self.resolve([tag('v18.6-alpine')], '18.5')['candidateRelease']['version'], '18.6')

    def test_untrusted_repository_and_pagination(self):
        for repository in ['https://evil.test/x', '../library/php', 'library/php/extra', 'library/php?x=1']:
            self.component['repository'] = repository
            with patch.object(m._Client, 'get') as get:
                self.assertIsNone(m.resolve_release(self.component, '8.5.10')['latestStable'])
                get.assert_not_called()
        self.component['repository'] = 'example/php'
        with patch.object(m._Client, 'get', return_value=({'results': [], 'next': 'https://evil.test/a'}, {})):
            self.assertIn('untrusted', m.resolve_release(self.component, '8.5.10')['reason'])

    def test_network_failure_and_rate_limit(self):
        for error in [TimeoutError('timeout'), m.urllib.error.HTTPError('https://hub.docker.com', 429, 'rate limited', {}, None)]:
            with patch.object(m._Client, 'get', side_effect=error):
                result = m.resolve_release(self.component, '8.5.10')
                self.assertIsNone(result['latestStable'])
                self.assertTrue(result['reason'].startswith('unavailable:'))

    def test_pagination_and_limit(self):
        url = 'https://hub.docker.com/v2/repositories/example/php/tags/?page=2'
        with patch.object(m._Client, 'get', side_effect=[({'results': [tag('8.5.11-apache')], 'next': url}, {}), ({'results': [tag('8.5.12-apache')], 'next': None}, {}), ({'token': 'token'}, {}), ({'manifests': [{'platform': {'os': 'linux', 'architecture': 'amd64'}, 'digest': D}]}, {'Docker-Content-Digest': D})]):
            self.assertEqual(m.resolve_release(self.component, '8.5.10')['candidateRelease']['version'], '8.5.12')
        with patch.object(m._Client, 'get', return_value=({'results': [], 'next': url}, {})) as get:
            self.assertIsNone(m.resolve_release(self.component, '8.5.10')['latestStable'])
            self.assertEqual(get.call_count, 8)

    def test_registry_digest_fallback(self):
        with patch.object(m._Client, 'get', side_effect=[({'results': [tag('8.5.12-apache', digest=None)], 'next': None}, {}), ({'token': 'public-token'}, {}), ({'manifests': [{'platform': {'os': 'linux', 'architecture': 'amd64'}, 'digest': D}]}, {'Docker-Content-Digest': D})]):
            self.assertEqual(m.resolve_release(self.component, '8.5.10')['candidateRelease']['imageDigest'], D)

    def test_official_images_exact_lookup(self):
        self.component['repository'] = 'library/php'
        result = self.resolve([tag('8.5.%d-apache' % n) for n in range(10, 20)] + [tag('9.0.0-rc1-apache')])
        self.assertEqual(result['latestStable']['version'], '8.5.19')
        self.assertEqual(result['candidateRelease']['imageDigest'], D)

    def test_registry_requires_matching_index_architecture(self):
        for manifest in [{'schemaVersion': 2}, {'manifests': [{'platform': {'os': 'linux', 'architecture': 'arm64'}, 'digest': D}]}]:
            with patch.object(m._Client, 'get', side_effect=[({'results': [tag('8.5.12-apache')], 'next': None}, {}), ({'token': 'token'}, {}), (manifest, {'Docker-Content-Digest': D})]):
                self.assertIsNone(m.resolve_release(self.component, '8.5.10')['latestStable'])

    def test_curated_github_stable_and_compatible(self):
        self.component.update(repository='prom/prometheus', tagSuffix='', tagPrefix='v', compatibility='major')
        calls = []
        def get(client, url, headers=None):
            calls.append(url)
            if url.endswith('/releases/latest'):
                return {'tag_name': 'v4.0.0', 'prerelease': False}, {}
            if '/releases?' in url:
                return [{'tag_name': 'v3.9.0'}, {'tag_name': 'v4.1.0-rc1', 'prerelease': True}, {'tag_name': 'v99.0.0', 'draft': True}], {}
            if 'hub.docker.com' in url:
                return tag(url.rstrip('/').rsplit('/', 1)[1]), {}
            if 'auth.docker.io' in url:
                return {'token': 'token'}, {}
            return {'manifests': [{'platform': {'os': 'linux', 'architecture': 'amd64'}, 'digest': D}]}, {'Docker-Content-Digest': D}
        with patch.object(m._Client, 'get', get):
            result = m.resolve_release(self.component, '3.8.0')
        self.assertEqual(result['latestStable']['version'], '4.0.0')
        self.assertEqual(result['candidateRelease']['version'], '4.0.0')
        self.assertTrue(any('/prometheus/prometheus/releases?' in url for url in calls))
        self.assertFalse(any('page_size=' in url for url in calls))

    def test_curated_github_rate_limit_unavailable(self):
        self.component['repository'] = 'grafana/grafana'
        with patch.object(m._Client, 'get', side_effect=m.urllib.error.HTTPError('https://api.github.com', 403, 'rate limit', {}, None)):
            result = m.resolve_release(self.component, '12.0.0')
        self.assertIsNone(result['latestStable'])
        self.assertIn('unavailable', result['reason'])

    def test_manifest_body_hash_is_verified(self):
        from io import BytesIO
        class Response(BytesIO):
            headers = {'Docker-Content-Digest': D}
        opener = unittest.mock.Mock()
        opener.open.return_value = Response(b'{"manifests":[]}')
        with patch.object(m.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                m._Client().get('https://registry-1.docker.io/v2/prom/prometheus/manifests/v3.9.0')

    def test_installer_enrolls_direct_latest_policy_for_runtime_families(self):
        installer_path = PATH.parents[3] / 'scripts/install-runtime-updates.py'
        installer_spec = importlib.util.spec_from_file_location('runtime_installer', installer_path)
        installer = importlib.util.module_from_spec(installer_spec)
        installer_spec.loader.exec_module(installer)
        row = {
            'Name': '/app', 'Image': 'sha256:' + 'b' * 64,
            'State': {'Running': True}, 'Mounts': [],
            'Config': {'Image': 'platform/app:deployed', 'Env': ['NODE_VERSION=24.22.0'],
                       'Labels': {'com.docker.compose.project': 'app', 'com.docker.compose.service': 'app'}},
        }
        component, = installer.discover([row], PATH.parents[3])
        self.assertEqual(component['compatibility'], 'latest')
        self.assertEqual(component['targetPolicy'], 'latest-stable-direct-v1')
        self.assertEqual(component['strategy'], 'node-layer')
        self.assertEqual(component['familyPolicy'], 'single-version-v1')

    def test_compare(self):
        self.assertEqual(m.compare_versions('18.6', '18.6.0'), 0)
        self.assertGreater(m.compare_versions('8.5.12', '8.5.9'), 0)
        with self.assertRaises(ValueError):
            m.compare_versions('latest', '8.5.9')


if __name__ == '__main__':
    unittest.main()
