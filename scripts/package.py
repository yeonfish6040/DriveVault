"""Create portable per-platform archives; no build tools needed to run them."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import platform
import subprocess
import shutil
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = (
    'aarch64-apple-darwin', 'x86_64-apple-darwin',
    'x86_64-pc-windows-msvc', 'i686-pc-windows-msvc', 'aarch64-pc-windows-msvc',
    'x86_64-unknown-linux-gnu', 'i686-unknown-linux-gnu', 'aarch64-unknown-linux-gnu',
)

def validate_executable(data, target):
    """Check actual executable headers so wrong-CPU binaries cannot be mislabeled."""
    cpu = target.split('-', 1)[0]
    valid = False
    if 'apple-darwin' in target and len(data) >= 8 and data[:4] == b'\xcf\xfa\xed\xfe':
        valid = int.from_bytes(data[4:8], 'little') == {'x86_64': 0x01000007, 'aarch64': 0x0100000c}[cpu]
    elif 'linux' in target and len(data) >= 20 and data[:4] == b'\x7fELF' and data[5] == 1:
        valid = data[4] == (1 if cpu == 'i686' else 2) and int.from_bytes(data[18:20], 'little') == {'i686': 3, 'x86_64': 62, 'aarch64': 183}[cpu]
    elif 'windows' in target and len(data) >= 64 and data[:2] == b'MZ':
        offset = int.from_bytes(data[60:64], 'little')
        valid = data[offset:offset+4] == b'PE\0\0' and int.from_bytes(data[offset+4:offset+6], 'little') == {'i686': 0x14c, 'x86_64': 0x8664, 'aarch64': 0xaa64}[cpu]
    if not valid:
        raise ValueError(f'Executable OS/CPU header does not match {target}')


def build_id():
    digest = hashlib.sha256()
    paths = [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', ROOT / 'scripts/package.py', ROOT / 'scripts/build_complete.py', ROOT / 'scripts/signing.py']
    for crate in sorted(ROOT.glob('vault-*')):
        if crate.is_dir():
            paths += [crate / 'Cargo.toml', *sorted((crate / 'src').rglob('*.rs'))]
    paths += sorted((ROOT / 'packaging').glob('*'))
    for path in paths:
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()

def decorate(stage):
    for name in ('VaultDrive.sh', 'VaultDrive.bat'):
        shutil.copy2(ROOT / 'packaging' / name, stage / name)
    shutil.copy2(ROOT / 'packaging/VaultDrive.sh', stage / 'VaultDrive.command')
    (stage / 'VaultDrive.command').chmod(0o755)
    for name in ('README.md', 'docs/SECURITY.md', 'docs/PORTABILITY.md', 'docs/VALIDATION.md'):
        shutil.copy2(ROOT / name, stage / Path(name).name)

def mac_launcher(stage):
    """Build one native universal launcher for both Apple Silicon and Intel."""
    contents=stage/'VaultDrive.app/Contents'
    (contents/'MacOS').mkdir(parents=True)
    with (contents/'Info.plist').open('wb') as f:
        plistlib.dump(dict(CFBundleExecutable='VaultDriveLauncher',CFBundleIdentifier='dev.vaultdrive.launcher',CFBundleName='VaultDrive',CFBundlePackageType='APPL',CFBundleVersion='0.1.0',CFBundleShortVersionString='0.1.0',LSUIElement=True),f)
    subprocess.run(['xcrun','clang','-arch','arm64','-arch','x86_64','-mmacosx-version-min=11.0','-Os','-fobjc-arc','-framework','Cocoa',str(ROOT/'packaging/MacLauncher.m'),'-o',str(contents/'MacOS/VaultDriveLauncher')],check=True)


def manifest(stage, targets, profile, source_id=None, signing=None):
    files = {p.relative_to(stage).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(stage.rglob('*')) if p.is_file() and p.name != 'manifest.json'}
    data = dict(schema=1, buildId=source_id or build_id(), profile=profile,
                targets=sorted(targets), missingTargets=sorted(set(TARGETS) - set(targets)),
                complete=set(targets) == set(TARGETS), files=files, signing=signing or {})
    (stage / 'manifest.json').write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    return data

def archive(stage, output):
    output.parent.mkdir(parents=True, exist_ok=True)
    # Publish only a completely written archive; preserve the old one on error.
    with tempfile.NamedTemporaryFile(dir=output.parent, suffix='.zip', delete=False) as tmp:
        temporary = Path(tmp.name)
    try:
        with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED) as z:
            for p in sorted(stage.rglob('*')):
                if p.is_file():
                    z.write(p, Path(stage.name) / p.relative_to(stage))
        temporary.chmod(0o644)  # Docker-built artifacts must be readable by the Actions runner.
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    checksum = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix('.zip.sha256').write_text(f'{checksum}  {output.name}\n', encoding='utf-8')
    return output

def package(target, binary_dir=None, profile='release', out=None, signed=False):
    if target not in TARGETS:
        raise ValueError(f'Unsupported distribution target: {target}')
    binaries = binary_dir or ROOT / 'target' / target / profile
    with tempfile.TemporaryDirectory(prefix='vault-package-') as tmp:
        stage = Path(tmp) / f'VaultDrive-{target}'
        destination = stage / 'bin' / target
        destination.mkdir(parents=True)
        if 'apple-darwin' in target:
            app = destination / 'VaultDrive.app/Contents'
            (app / 'MacOS').mkdir(parents=True)
            shutil.copy2(binaries / 'vault-gui', app / 'MacOS/VaultDrive')
            with (app / 'Info.plist').open('wb') as f:
                plistlib.dump(dict(CFBundleExecutable='VaultDrive', CFBundleIdentifier='dev.vaultdrive.desktop', CFBundleName='VaultDrive', CFBundlePackageType='APPL', NSHighResolutionCapable=True, CFBundleVersion='0.1.0', CFBundleShortVersionString='0.1.0'), f)
        else:
            shutil.copy2(binaries / ('vault-gui.exe' if 'windows' in target else 'vault-gui'), destination)
        shutil.copy2(binaries / ('vault.exe' if 'windows' in target else 'vault'), destination)
        gui = destination / ('VaultDrive.app/Contents/MacOS/VaultDrive' if 'apple-darwin' in target else 'vault-gui.exe' if 'windows' in target else 'vault-gui')
        cli = destination / ('vault.exe' if 'windows' in target else 'vault')
        for binary in (gui, cli):
            validate_executable(binary.read_bytes(), target)
        decorate(stage)
        if 'apple-darwin' in target and platform.system()=='Darwin':
            mac_launcher(stage)
        attestation = {'kind': 'not-applicable' if 'linux' in target else 'unsigned'}
        if signed:
            if profile != 'release':
                raise ValueError('Distribution signing requires a release build')
            from signing import sign
            attestation = sign(destination, target)
        manifest(stage, [target], profile, signing={target: attestation})
        output = (out or ROOT / 'target/portable') / f'{stage.name}.zip'
        result = archive(stage, output)
        if signed and 'apple-darwin' in target:
            from signing import verify_macos_archive
            try:
                verify_macos_archive(result, target)
            except Exception:
                result.unlink(missing_ok=True)
                result.with_suffix('.zip.sha256').unlink(missing_ok=True)
                raise
        return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, choices=TARGETS)
    parser.add_argument('--binary-dir', type=Path)
    parser.add_argument('--profile', choices=('release', 'debug'), default='release')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--sign', action='store_true', help='Sign Windows/macOS and notarize macOS before packaging')
    args = parser.parse_args()
    try:
        print(package(args.target, args.binary_dir, args.profile, args.out, args.sign))
    except ValueError as error:
        parser.exit(1, f'Packaging failed: {error}\n')

if __name__ == '__main__':
    main()
