"""Packaging/routing regression tests; all mock binaries remain in temp directories."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile
from package import ROOT, TARGETS, package, validate_executable
from build_complete import combine


def mock_header(target):
    cpu = target.split('-')[0]
    data = bytearray(128)
    if 'apple' in target:
        data[:4] = b'\xcf\xfa\xed\xfe'
        data[4:8] = {'aarch64': 0x100000c, 'x86_64': 0x1000007}[cpu].to_bytes(4, 'little')
    elif 'windows' in target:
        data[:2] = b'MZ'; data[60:64] = (64).to_bytes(4, 'little'); data[64:68] = b'PE\0\0'
        data[68:70] = {'i686': 0x14c, 'x86_64': 0x8664, 'aarch64': 0xaa64}[cpu].to_bytes(2, 'little')
    else:
        data[:4] = b'\x7fELF'; data[4] = 1 if cpu == 'i686' else 2; data[5] = 1
        data[18:20] = {'i686': 3, 'x86_64': 62, 'aarch64': 183}[cpu].to_bytes(2, 'little')
    return bytes(data)


class Packaging(unittest.TestCase):
    def artifact(self, base, target):
        binaries = base / target; binaries.mkdir()
        for name in ('vault-gui', 'vault'):
            f = binaries / (name + '.exe' if 'windows' in target else name)
            f.write_bytes(mock_header(target)); f.chmod(0o755)
        return package(target, binaries, out=base / 'artifacts')

    def test_complete_requires_all_targets_and_keeps_cpu_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            self.artifact(base, TARGETS[0])
            with self.assertRaisesRegex(ValueError, 'missing'):
                combine(base / 'artifacts', base / 'out')
            self.assertFalse((base / 'out/VaultDrive-complete.zip').exists())
            for target in TARGETS[1:]:
                self.artifact(base, target)
            archive = combine(base / 'artifacts', base / 'out')
            with zipfile.ZipFile(archive) as z:
                data = json.loads(z.read('VaultDrive/manifest.json'))
                self.assertTrue(data['complete']); self.assertEqual(len(data['targets']), 8)
                self.assertIn('VaultDrive/VaultDrive.bat', z.namelist())
                self.assertEqual(z.getinfo('VaultDrive/VaultDrive.sh').external_attr >> 16 & 0o111, 0o111)
            self.assertTrue(archive.with_suffix('.zip.sha256').exists())

    def test_cli_default_packages_available_targets_and_require_all_fails(self):
        import sys
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            self.artifact(base, TARGETS[0])
            command = [sys.executable, str(ROOT / 'scripts/build_complete.py'), '--skip-build', '--artifact-dir', str(base / 'artifacts')]
            normal = subprocess.run(command + ['--out', str(base / 'default')], capture_output=True, text=True)
            self.assertEqual(normal.returncode, 0, normal.stderr)
            self.assertTrue((base / 'default/VaultDrive-partial.zip').is_file())
            with zipfile.ZipFile(base / 'default/VaultDrive-partial.zip') as z:
                data = json.loads(z.read('VaultDrive/manifest.json'))
                self.assertFalse(data['complete'])
                self.assertEqual(len(data['missingTargets']), 7)
            strict = subprocess.run(command + ['--require-all', '--out', str(base / 'strict')], capture_output=True, text=True)
            self.assertNotEqual(strict.returncode, 0)
            self.assertIn('missing', strict.stderr)
            self.assertFalse((base / 'strict/VaultDrive-complete.zip').exists())

    def test_wrong_cpu_header_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_executable(mock_header('aarch64-apple-darwin'), 'x86_64-apple-darwin')

    def test_tampered_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); archive = self.artifact(base, TARGETS[0])
            with zipfile.ZipFile(archive) as z:
                files = [(i, z.read(i)) for i in z.infolist()]
            with zipfile.ZipFile(archive, 'w') as z:
                for info, data in files:
                    z.writestr(info, data + b'bad' if info.filename.endswith('/vault') else data)
            with self.assertRaisesRegex(ValueError, 'checksum'):
                combine(base / 'artifacts', base / 'out', allow_partial=True)

    @unittest.skipUnless(os.name == "posix", "POSIX shell routing test")
    def test_shell_routes_linux_bitness_with_spaces_in_location(self):
        for cpu, bits, target in [('x86_64', '32', 'i686-unknown-linux-gnu'), ('x86_64', '64', 'x86_64-unknown-linux-gnu'), ('aarch64', '64', 'aarch64-unknown-linux-gnu')]:
            with self.subTest(target=target), tempfile.TemporaryDirectory(prefix='vault test ') as tmp:
                base = Path(tmp); tools = base / 'tools'; tools.mkdir()
                for name, text in {'uname': f'#!/bin/sh\n[ "$1" = -s ] && echo Linux || echo {cpu}\n', 'getconf': f'#!/bin/sh\necho {bits}\n'}.items():
                    f = tools / name; f.write_text(text); f.chmod(0o755)
                binary = base / 'bin' / target / 'vault-gui'; binary.parent.mkdir(parents=True)
                binary.write_text('#!/bin/sh\nprintf "%s|%s" "$VAULTDRIVE_PORTABLE_HOME" "$1"\n'); binary.chmod(0o755)
                launcher = base / 'VaultDrive.sh'; launcher.write_bytes((ROOT / 'packaging/VaultDrive.sh').read_bytes())
                env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'])
                result = subprocess.run(['/bin/sh', str(launcher), 'argument with spaces'], env=env, capture_output=True, text=True, check=True)
                self.assertEqual(result.stdout, f'{base.resolve()}|argument with spaces')

    @unittest.skipUnless(os.name == "posix", "POSIX shell routing test")
    def test_shell_missing_binary_has_clear_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            launcher = Path(tmp) / 'VaultDrive.sh'; launcher.write_bytes((ROOT / 'packaging/VaultDrive.sh').read_bytes())
            result = subprocess.run(['/bin/sh', str(launcher)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 3)
            self.assertIn('does not contain', result.stderr)

if __name__ == '__main__':
    unittest.main()
