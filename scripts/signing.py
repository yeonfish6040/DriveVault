"""Native signing/notarization. Credentials arrive through environment variables only."""
import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path
import platform
import secrets
import subprocess
import tempfile
import time

MAC_SECRETS = ('MACOS_CERTIFICATE_BASE64', 'MACOS_CERTIFICATE_PASSWORD', 'MACOS_SIGNING_IDENTITY', 'APPLE_API_KEY_P8', 'APPLE_API_KEY_ID', 'APPLE_API_ISSUER_ID')
WIN_SECRETS = ('WINDOWS_CERTIFICATE_BASE64', 'WINDOWS_CERTIFICATE_PASSWORD')


def required(names):
    missing = [name for name in names if not os.environ.get(name)]
    if missing:
        raise ValueError('Missing signing secrets: ' + ', '.join(missing))


def run(args):
    # Never include command arguments or native stderr in exceptions: they can
    # contain PFX passwords, API credentials or echoed secret material.
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True)
    if result.returncode:
        raise ValueError(f'{Path(args[0]).name}: signing operation failed (exit {result.returncode})')
    return result.stdout


@contextmanager
def mac_keychain(directory):
    keychain = directory / 'signing.keychain-db'
    certificate = directory / 'certificate.p12'
    certificate.write_bytes(base64.b64decode(os.environ['MACOS_CERTIFICATE_BASE64'], validate=True))
    certificate.chmod(0o600)
    password = secrets.token_urlsafe(32)
    original = run(['security', 'list-keychains', '-d', 'user'])
    import shlex
    search_list = shlex.split(original)
    created = False
    try:
        run(['security', 'create-keychain', '-p', password, keychain]); created = True
        run(['security', 'set-keychain-settings', '-lut', '21600', keychain])
        run(['security', 'unlock-keychain', '-p', password, keychain])
        run(['security', 'import', certificate, '-k', keychain, '-P', os.environ['MACOS_CERTIFICATE_PASSWORD'], '-T', '/usr/bin/codesign', '-T', '/usr/bin/security'])
        run(['security', 'set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:', '-s', '-k', password, keychain])
        run(['security', 'list-keychains', '-d', 'user', '-s', keychain, *search_list])
        yield keychain
    finally:
        try:
            if created:
                run(['security', 'list-keychains', '-d', 'user', '-s', *search_list])
        finally:
            if created:
                run(['security', 'delete-keychain', keychain])


def macos(destination):
    if platform.system() != 'Darwin':
        raise ValueError('macOS signing must run on macOS')
    required(MAC_SECRETS)
    identity = os.environ['MACOS_SIGNING_IDENTITY']
    if not identity.startswith('Developer ID Application:'):
        raise ValueError('A Developer ID Application identity is required for macOS distribution')
    app = destination / 'VaultDrive.app'
    cli = destination / 'vault'
    launcher=destination.parent.parent/'VaultDrive.app'
    with tempfile.TemporaryDirectory(prefix='vault-sign-') as tmp:
        private = Path(tmp)
        key = private / 'AuthKey.p8'
        key.write_text(os.environ['APPLE_API_KEY_P8'], encoding='utf-8'); key.chmod(0o600)
        with mac_keychain(private) as keychain:
            # Sign the bundle after Info.plist exists; hardened runtime and a
            # trusted timestamp are required. Never modify it after stapling.
            for binary in (cli, app, launcher):
                run(['codesign', '--force', '--options', 'runtime', '--timestamp', '--sign', identity, '--keychain', keychain, binary])
                run(['codesign', '--verify', '--strict', '--verbose=2', binary])
            submission = private / 'notarize.zip'
            run(['ditto', '-c', '-k', '--keepParent', destination.parent.parent, submission])
            auth = ['--key', key, '--key-id', os.environ['APPLE_API_KEY_ID'], '--issuer', os.environ['APPLE_API_ISSUER_ID']]
            result = json.loads(run(['xcrun', 'notarytool', 'submit', submission, *auth, '--wait', '--timeout', '30m', '--output-format', 'json']))
            if result.get('status') != 'Accepted':
                raise ValueError(f'Apple notarization was not accepted (submission {result.get("id", "unknown")})')
            for bundle in (app,launcher):
                for attempt in range(6):
                    try:
                        run(['xcrun', 'stapler', 'staple', bundle])
                        break
                    except ValueError:
                        if attempt == 5:
                            raise
                        time.sleep(10)
                run(['xcrun', 'stapler', 'validate', bundle])
                run(['codesign', '--verify', '--strict', '--verbose=2', bundle])
                run(['spctl', '--assess', '--type', 'execute', '--verbose=2', bundle])
    return {'kind': 'macos-notarized', 'submissionId': result['id']}


def windows(destination):
    if platform.system() != 'Windows':
        raise ValueError('Authenticode signing must run on Windows')
    required(WIN_SECRETS)
    root = Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')) / 'Windows Kits/10/bin'
    cpu = 'arm64' if platform.machine().lower() in ('arm64', 'aarch64') else 'x64'
    tools = sorted(root.glob(f'*/{cpu}/signtool.exe'), reverse=True)
    if not tools:
        raise ValueError('Windows SDK SignTool is not installed')
    with tempfile.TemporaryDirectory(prefix='vault-sign-') as tmp:
        cert = Path(tmp) / 'certificate.pfx'
        cert.write_bytes(base64.b64decode(os.environ['WINDOWS_CERTIFICATE_BASE64'], validate=True))
        cert.chmod(0o600)
        for binary in (destination / 'vault-gui.exe', destination / 'vault.exe'):
            run([tools[0], 'sign', '/fd', 'SHA256', '/f', cert, '/p', os.environ['WINDOWS_CERTIFICATE_PASSWORD'], '/tr', 'http://timestamp.digicert.com', '/td', 'SHA256', binary])
            run([tools[0], 'verify', '/pa', '/all', '/v', binary])
    return {'kind': 'windows-authenticode'}


def sign(destination, target):
    if 'apple-darwin' in target:
        return macos(destination)
    if 'windows' in target:
        return windows(destination)
    return {'kind': 'not-applicable'}


def check_release_secrets():
    """Cheap workflow preflight; fail before scheduling eight expensive jobs."""
    required(MAC_SECRETS + WIN_SECRETS)




def verify_macos_archive(archive, target):
    """Verify the actual distributed ZIP preserves both signature and ticket."""
    import zipfile
    with tempfile.TemporaryDirectory(prefix='vault-sign-verify-') as tmp:
        with zipfile.ZipFile(archive) as z:
            z.extractall(tmp)  # Only called on the archive just generated by package.py.
            for info in z.infolist():
                if not info.is_dir():
                    (Path(tmp) / info.filename).chmod((info.external_attr >> 16) & 0o777)
        app = Path(tmp) / f'VaultDrive-{target}' / 'bin' / target / 'VaultDrive.app'
        for bundle in (app, Path(tmp)/f'VaultDrive-{target}'/'VaultDrive.app'):
            run(['codesign', '--verify', '--strict', '--verbose=2', bundle])
            run(['xcrun', 'stapler', 'validate', bundle])
            run(['spctl', '--assess', '--type', 'execute', '--verbose=2', bundle])

if __name__ == '__main__':
    try:
        check_release_secrets()
    except ValueError as error:
        raise SystemExit(str(error))
