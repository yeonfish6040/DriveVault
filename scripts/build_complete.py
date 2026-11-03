"""Build this host, then verify and combine platform archives into one portable ZIP."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tempfile
import zipfile
from package import ROOT, TARGETS, archive, build_id, decorate, manifest, package, validate_executable


def read_artifact(path, stage, expected_id, seen, allow_debug=False):
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        manifests = [i for i in infos if len(PurePosixPath(i.filename).parts) == 2 and i.filename.endswith('/manifest.json')]
        if len(manifests) != 1 or manifests[0].file_size > 1024 * 1024:
            raise ValueError(f'{path.name}: missing or invalid manifest')
        data = json.loads(z.read(manifests[0]))
        if data.get('schema') != 1 or data.get('buildId') != expected_id:
            raise ValueError(f'{path.name}: source version does not match this checkout')
        if data.get('profile') != 'release' and not allow_debug:
            raise ValueError(f'{path.name}: release binaries required (use --allow-debug for development only)')
        targets = data.get('targets', [])
        if len(targets) != 1 or targets[0] not in TARGETS or targets[0] in seen:
            raise ValueError(f'{path.name}: unknown or duplicate platform')
        target = targets[0]
        prefix = PurePosixPath(manifests[0].filename).parts[0]
        found = set()
        expected = data.get('files', {})
        if sum(i.file_size for i in infos) > 512 * 1024 * 1024:
            raise ValueError(f'{path.name}: oversized archive')
        for info in infos:
            name = PurePosixPath(info.filename)
            if name.is_absolute() or '..' in name.parts or '\\' in info.filename or name.parts[0] != prefix:
                raise ValueError(f'{path.name}: unsafe archive path')
            if stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError(f'{path.name}: symbolic links are not permitted')
            relative = PurePosixPath(*name.parts[1:])
            if info.is_dir() or relative.as_posix() == 'manifest.json':
                continue
            if relative.as_posix() in found:
                raise ValueError(f'{path.name}: duplicate file')
            content = z.read(info)
            if hashlib.sha256(content).hexdigest() != expected.get(relative.as_posix()):
                raise ValueError(f'{path.name}: checksum mismatch: {relative}')
            found.add(relative.as_posix())
            if relative.parts[0] == 'bin':
                if len(relative.parts) < 3 or relative.parts[1] != target:
                    raise ValueError(f'{path.name}: mismatched binary directory')
                dest = stage.joinpath(*relative.parts)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content)
                dest.chmod((info.external_attr >> 16) & 0o777)
        if found != set(expected):
            raise ValueError(f'{path.name}: manifest file set mismatch')
        base = stage / 'bin' / target
        gui = base / ('VaultDrive.app/Contents/MacOS/VaultDrive' if 'apple-darwin' in target else 'vault-gui.exe' if 'windows' in target else 'vault-gui')
        cli = base / ('vault.exe' if 'windows' in target else 'vault')
        if not gui.is_file() or not cli.is_file():
            raise ValueError(f'{path.name}: GUI or CLI binary missing')
        validate_executable(gui.read_bytes(), target)
        validate_executable(cli.read_bytes(), target)
        seen.add(target)
        return data['profile']


def combine(artifact_dir, out, allow_partial=False, allow_debug=False):
    source_id = build_id()
    with tempfile.TemporaryDirectory(prefix='vault-complete-') as tmp:
        stage = Path(tmp) / 'VaultDrive'
        stage.mkdir()
        seen = set()
        profiles = set()
        candidates = [p for p in artifact_dir.rglob('VaultDrive-*.zip') if p.name not in ('VaultDrive-complete.zip', 'VaultDrive-partial.zip')]
        if not candidates:
            raise ValueError('No platform archives found; build the platform packages first')
        for candidate in sorted(candidates):
            profiles.add(read_artifact(candidate, stage, source_id, seen, allow_debug))
        missing = set(TARGETS) - seen
        if missing and not allow_partial:
            raise ValueError('Complete package is missing: ' + ', '.join(sorted(missing)))
        if len(profiles) != 1:
            raise ValueError('Cannot mix debug and release builds')
        if not missing and profiles != {'release'}:
            raise ValueError('A complete distribution requires release builds')
        decorate(stage)
        manifest(stage, seen, profiles.pop(), source_id)
        result = archive(stage, out / ('VaultDrive-partial.zip' if missing else 'VaultDrive-complete.zip'))
        print(f'Included {len(seen)}/{len(TARGETS)} platforms. Missing: {", ".join(sorted(missing)) or "none"}')
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--skip-build', action='store_true', help='Only combine existing artifacts')
    parser.add_argument('--artifact-dir', type=Path, default=ROOT / 'target/portable')
    parser.add_argument('--out', type=Path, default=ROOT / 'target/distribution')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--require-all', action='store_true', help='Fail unless all eight release platforms are present')
    mode.add_argument('--allow-partial', action='store_true', help='Compatibility alias for the default: package available platforms')
    parser.add_argument('--allow-debug', action='store_true', help='Development partial packages only')
    args = parser.parse_args()
    try:
        if not args.skip_build:
            verbose = subprocess.check_output(['rustc', '-vV'], text=True)
            host = next(line.split(': ', 1)[1] for line in verbose.splitlines() if line.startswith('host: '))
            if host not in TARGETS:
                raise ValueError(f'Unsupported distribution host {host}; use an MSVC Rust toolchain on Windows')
            subprocess.run(['cargo', 'build', '--workspace', '--release', '--locked', '--target', host], cwd=ROOT, check=True)
            package(host, out=args.artifact_dir)
        print(combine(args.artifact_dir, args.out, not args.require_all, args.allow_debug))
    except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile, KeyError, TypeError) as error:
        parser.exit(1, f'Packaging failed: {error}\n')

if __name__ == '__main__':
    main()
