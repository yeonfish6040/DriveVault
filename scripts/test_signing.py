"""Signing boundary tests use mocks, never real credentials or remote services."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from signing import required, run, sign, macos
from package import TARGETS, package
from build_complete import combine
from test_packaging import mock_header

class Signing(unittest.TestCase):
    def test_missing_secret_errors_expose_names_only(self):
        with patch.dict(os.environ, {'EXISTING':'super-secret-value'}, clear=True):
            with self.assertRaises(ValueError) as raised:
                required(('EXISTING','MISSING'))
            self.assertIn('MISSING', str(raised.exception))
            self.assertNotIn('super-secret-value', str(raised.exception))

    def test_tool_errors_do_not_echo_credentials_or_stderr(self):
        result = subprocess.CompletedProcess([], 1, '', 'secret-password')
        with patch('signing.subprocess.run', return_value=result):
            with self.assertRaises(ValueError) as raised:
                run(['signtool', '/p', 'secret-password'])
            self.assertNotIn('secret-password', str(raised.exception))

    def test_linux_requires_no_signing_credentials(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(sign(Path('/unused'), 'i686-unknown-linux-gnu')['kind'], 'not-applicable')

    def test_development_certificate_is_not_accepted_for_distribution(self):
        from signing import MAC_SECRETS
        env = {name:'dummy' for name in MAC_SECRETS}
        env['MACOS_SIGNING_IDENTITY'] = 'Apple Development: Test'
        with patch.dict(os.environ, env, clear=True), patch('signing.platform.system', return_value='Darwin'):
            with self.assertRaisesRegex(ValueError, 'Developer ID Application'):
                macos(Path('/unused'))

    def test_release_assembler_rejects_unsigned_platform(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); binaries = base / 'binaries'; binaries.mkdir()
            for name in ('vault-gui','vault'):
                (binaries/name).write_bytes(mock_header(TARGETS[0]))
            package(TARGETS[0], binaries, out=base/'artifacts')
            with self.assertRaisesRegex(ValueError, 'signed release metadata'):
                combine(base/'artifacts', base/'out', allow_partial=True, require_signatures=True)
            self.assertFalse((base/'out/VaultDrive-partial.zip').exists())

    def test_signing_happens_after_bundle_creation_and_before_manifest(self):
        import json, zipfile
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); binaries = base/'binaries'; binaries.mkdir()
            for name in ('vault-gui','vault'):
                (binaries/name).write_bytes(mock_header(TARGETS[0]))
            def fake_sign(destination, target):
                self.assertTrue((destination/'VaultDrive.app/Contents/Info.plist').exists())
                (destination/'signature-test-marker').write_text('mock signature')
                return {'kind':'macos-notarized','submissionId':'mock-only'}
            with patch('signing.sign', side_effect=fake_sign), patch('signing.verify_macos_archive') as verify:
                archive=package(TARGETS[0], binaries, out=base/'artifacts', signed=True)
                verify.assert_called_once_with(archive,TARGETS[0])
            with zipfile.ZipFile(archive) as z:
                manifest=json.loads(z.read(f'VaultDrive-{TARGETS[0]}/manifest.json'))
                self.assertEqual(manifest['signing'][TARGETS[0]]['kind'],'macos-notarized')
                self.assertTrue(any(name.endswith('signature-test-marker') for name in manifest['files']))
            assembled=combine(base/'artifacts', base/'out', allow_partial=True, require_signatures=True)
            with zipfile.ZipFile(assembled) as z:
                manifest=json.loads(z.read('VaultDrive/manifest.json'))
                self.assertEqual(manifest['signing'][TARGETS[0]]['submissionId'],'mock-only')

if __name__ == '__main__':
    unittest.main()
