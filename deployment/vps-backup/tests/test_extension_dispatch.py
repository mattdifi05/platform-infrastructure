import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'extension-dispatch.py'
SPEC = importlib.util.spec_from_file_location('extension_dispatch', SOURCE)
extension = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(extension)


class ExtensionDispatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = pathlib.Path(self.temp.name) / 'config'
        self.config.mkdir()
        self.bundle = self.config / 'extensions' / 'legacy-vps-backup'
        self.bundle.mkdir(parents=True)
        self.profile = self.config / 'profile.json'
        self.patches = [
            patch.object(extension, 'CONFIG', self.config),
            patch.object(extension, 'PROFILE', self.profile),
            patch.object(extension, 'EXTENSION', self.bundle),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def signed_profile(self, extra=False):
        profile = dict.fromkeys(extension.REQUIRED_FIELDS, None)
        if extra:
            profile['applicationRuntime'] = {'profile': 'signed'}
        self.profile.write_text(json.dumps(profile))
        (self.config / 'profile.sig').write_bytes(b'signature')
        (self.config / 'authority-public.pem').write_bytes(b'public')

    def manifest(self):
        entries = []
        for name in sorted(extension.COMMANDS):
            relative = 'deployment/vps-backup/' + name
            file = self.bundle / relative
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text('# exact installed code\n')
            entries.append({'path': relative, 'sha256': hashlib.sha256(file.read_bytes()).hexdigest()})
        (self.bundle / 'manifest.json').write_text(json.dumps({
            'schema': 'platform.vps-backup-code-extension/v1', 'files': entries,
        }))
        return entries

    def test_clean_install_does_not_require_extension(self):
        self.assertIsNone(extension.extension_script('platform-vps-backup-runner.py'))

    def test_legacy_profile_requires_exact_bundle_and_detects_change(self):
        self.signed_profile(extra=True)
        self.manifest()
        with patch.object(extension, 'protected', side_effect=lambda file, directory=False: file), patch.object(
            extension.subprocess, 'run', return_value=SimpleNamespace(returncode=0)
        ):
            target = extension.extension_script('platform-vps-backup-runner.py')
            self.assertEqual(target, self.bundle / 'deployment/vps-backup/platform-vps-backup-runner.py')
            target.write_text('# changed\n')
            with self.assertRaisesRegex(RuntimeError, 'differs from manifest'):
                extension.extension_script('platform-vps-backup-runner.py')

    def test_signed_extra_fields_never_fall_back_to_generic_runner(self):
        self.signed_profile(extra=True)
        with patch.object(extension, 'protected', side_effect=lambda file, directory=False: file), patch.object(
            extension.subprocess, 'run', return_value=SimpleNamespace(returncode=0)
        ):
            with self.assertRaises(FileNotFoundError):
                extension.extension_script('platform-vps-backup-runner.py')

    def test_invalid_signature_blocks_dispatch(self):
        self.signed_profile(extra=True)
        with patch.object(extension, 'protected', side_effect=lambda file, directory=False: file), patch.object(
            extension.subprocess, 'run', return_value=SimpleNamespace(returncode=1)
        ):
            with self.assertRaisesRegex(RuntimeError, 'signature is invalid'):
                extension.extension_script('platform-vps-backup-runner.py')

    def test_symlink_or_writable_bundle_file_is_rejected(self):
        file = self.bundle / 'file.py'
        file.write_text('pass\n')
        file.chmod(0o666)
        with self.assertRaisesRegex(RuntimeError, 'not root protected'):
            extension.protected(file)
        file.unlink()
        file.symlink_to(self.profile)
        with self.assertRaisesRegex(RuntimeError, 'not root protected'):
            extension.protected(file)


if __name__ == '__main__':
    unittest.main()
