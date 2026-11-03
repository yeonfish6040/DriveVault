# Release signing and notarization

Tags always require macOS signing/notarization and Windows Authenticode signatures. Manual Run workflow defaults to the same policy. Select `unsigned_preview` only for development builds; a tag can never bypass signing. The preflight stops before expensive builds when required secrets are absent. Merely checking certificate metadata or configuring the workflow does not mean a signed release has been produced.

## GitHub Secrets

Set these in repository Settings → Secrets and variables → Actions. Never paste private keys/passwords into chat, commit them, or attach them to Actions artifacts.

| Secret | Value |
| --- | --- |
| `MACOS_CERTIFICATE_BASE64` | Base64 of a password-protected PKCS#12 export containing the intended Developer ID Application certificate and its private key |
| `MACOS_CERTIFICATE_PASSWORD` | Export password |
| `MACOS_SIGNING_IDENTITY` | Exact `Developer ID Application: Name (TEAMID)` identity; Apple Development/App Store Distribution identities are rejected |
| `APPLE_API_KEY_P8` | Contents of an App Store Connect team API key `.p8` authorized for notarization |
| `APPLE_API_KEY_ID` | API key ID |
| `APPLE_API_ISSUER_ID` | Team API issuer ID |
| `WINDOWS_CERTIFICATE_BASE64` | Base64 of an exportable, valid Authenticode code-signing PFX with its private key |
| `WINDOWS_CERTIFICATE_PASSWORD` | PFX export password |

Use an API key type that supports the team issuer argument; individual-key authentication is not implemented by this script. For macOS, export only the intended identity using Keychain Access (My Certificates → selected Developer ID Application identity → Export), not a bulk keychain export. This repository does not automatically export local private keys or upload them. The operator must authorize and register credentials. PKCS#12 should contain the certificate chain needed for trust verification.

The Windows PFX path is for an existing exportable certificate. Hardware-token-only or cloud-managed signing identities require a provider-specific integration; copying an HSM-backed private key to a PFX is not supported. A self-signed certificate does not establish public trust. Authenticode signing does not guarantee immediate SmartScreen reputation.

## Ordering and verification

`package.py --sign` stages the real binaries and complete Info.plist first. macOS then imports the selected identity into a temporary keychain, enables hardened runtime and trusted timestamps, signs both GUI bundle and CLI, submits a ZIP with `notarytool --wait`, and accepts only an `Accepted` response. It staples the ticket to the app, validates the ticket, verifies the signature and assesses the bundle with Gatekeeper. The CLI is included in the notarization submission, but Apple does not support stapling standalone executables. The packaged app is extracted from the final platform ZIP and reverified, so signature/ticket loss in that archive fails the build.

Windows signs both GUI and CLI with SignTool using SHA-256 and an RFC 3161 timestamp, then verifies under the Authenticode policy. Windows SDK SignTool must exist on the runner. Linux binaries have no native equivalent to these signing steps in this workflow.

Only after these operations does packaging generate file hashes, signing metadata and the archive. The complete assembler invoked with `--require-signatures` checks expected platform signing metadata, verifies every file hash and preserves the signing metadata. The Linux assembler does not independently cryptographically verify Apple/Windows signatures: it trusts the native verification performed by jobs in this same workflow and the protected Actions artifact channel. Manifests/checksums alone are not proof of publisher identity. Recipients can verify embedded native signatures independently.

Temporary certificates/API-key files and the temporary keychain are removed on normal completion/errors; the original keychain search list is restored. The GitHub hosted VM is ephemeral after cancellation. Signing tool failures are deliberately sanitized so command-line passwords/stderr are not echoed in Python exceptions. Do not enable shell tracing around secret-bearing commands.

## Local builds

Unsigned development builds remain available through the ordinary local builder. A locally configured operator can request signing with:

```sh
./build-complete.sh --require-signatures
```

This requires the applicable environment secrets and a matching native OS/SDK. Do not pass secret values as command-line arguments. `--sign` does not silently fall back to unsigned output when signing or notarization fails.

References: [Apple notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow), [Microsoft SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool).
