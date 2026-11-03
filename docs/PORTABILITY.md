# Portable execution and platform contract

Distribute a separate archive for each OS/CPU. Extract the correct archive onto the SSD and run it there. Rust, Python, a package manager and an installer are not required by the compiled app. Do not run the application from inside its ZIP. A writable directory beside the app holds `vaults.json` (names/paths only). Paths beneath that directory are relative, so moving the entire app/vault folder to another drive preserves the list. A vault selected outside this directory uses an absolute path and may need reopening on another computer. The app never writes passwords to the registry. An unreadable/corrupt registry is surfaced rather than overwritten. Read-only drives cannot save the list or modify a vault.

## Build targets

| OS | CPU | Rust target | Validation |
| --- | --- | --- | --- |
| macOS | ARM64 | aarch64-apple-darwin | Local build/tests on Apple Silicon |
| macOS | x86_64 | x86_64-apple-darwin | CI configured; native runtime not available here |
| Windows | x86_64 | x86_64-pc-windows-msvc | CI configured; native runtime not available here |
| Windows | x86 32-bit | i686-pc-windows-msvc | CI configured; native runtime not available here |
| Windows | ARM64 | aarch64-pc-windows-msvc | CI configured; native runtime not available here |
| Linux | x86_64 | x86_64-unknown-linux-gnu | CI configured on Ubuntu 24.04 |
| Linux | ARM64 | aarch64-unknown-linux-gnu | CI configured on Ubuntu 24.04 ARM |
| Linux | x86 32-bit | i686-unknown-linux-gnu | CI configured in Debian 12 i386 container |

Current macOS cannot execute 32-bit x86 applications. There is no supported current Rust/macOS i686 target; this combination is excluded. A configured CI matrix is not proof that remote builds have passed. Local cross-check results are recorded in VALIDATION.md. The repository has not been published or remote CI executed by this task.

## Dependencies and privileges

Default operations need normal user access to the SSD, loopback networking, and an OS-supported filesystem with locking. An unsupported/exFAT locking failure is reported; the app does not silently open an unsafe concurrent session. Filesystem locks coordinate cooperating VaultDrive processes; another process that ignores locks can still modify files. Do not remove `vault.lock` while an app is running. Locks are released by the OS after process termination; the file itself intentionally remains.

Linux binaries require a graphical session, compatible glibc, system window/OpenGL libraries and file-picker integration (desktop portal). These are not fully static Linux binaries and cannot run on arbitrary distributions or headless computers. Ubuntu 24.04 and Debian 12 i386 are initial build baselines, not tested compatibility guarantees. Windows may require the Microsoft C/C++ runtime; a completely self-contained Windows archive is not verified. macOS bundles are currently unsigned/unnotarized, and Windows binaries unsigned, so the OS may ask the user to authorize first launch. The app does not bypass security prompts.

Automatic connection means launching the native file manager with the loopback WebDAV address after unlock. It is not silent authentication, a verified mount, or an automatic unmount. macOS uses `open dav://vault@127.0.0.1:PORT/`, Windows uses Explorer with `\\127.0.0.1@PORT\DavWWWRoot`, Linux uses `xdg-open dav://vault@127.0.0.1:PORT/`. The temporary password stays out of command arguments and URLs. Native clients may request it in an OS dialog. Canceling that dialog leaves the encrypted server unlocked until Lock or app exit.

macOS's built-in `mount_webdav` explicitly makes Class 1 servers read-only when DAV LOCK is unavailable. This server has not implemented DAV LOCK yet, so **normal writable Finder mounting is not complete**. Windows WebClient may be absent/disabled, restrict Basic HTTP, or require configuration privileges. The app never changes global Windows authentication settings. Linux needs a file manager with a DAV backend (e.g. GVfs/KIO). Without it, the app can still start its loopback server and export plaintext, but cannot provide a mounted folder. A universally driver-free, privilege-free writable mount is not guaranteed by WebDAV.

## Build/package

On a matching build host:

```sh
cargo build --workspace --release --target YOUR_RUST_TARGET --locked
python3 scripts/package.py --target YOUR_RUST_TARGET
```

ZIP output is under `target/portable/`. The Python script is a build tool, not a runtime requirement. Portable archives contain only executables and documentation, not design reference fonts/media. Local development builds and distributable release builds are distinct.

## Automatic launch and complete package

Extract the entire archive. At its root, run `VaultDrive.sh` on Linux, double-click `VaultDrive.command` (or run the sh script) on macOS, and double-click `VaultDrive.bat` on Windows. The launchers select the native OS/CPU directory under `bin/`. Linux also checks process bitness so a 32-bit userspace on an x86_64 kernel uses i686. On Windows, the architecture exposed by WOW64 is preferred; on Apple Silicon, the ARM binary is preferred even when the shell runs through Rosetta. Unsupported combinations and missing executable files fail with an error. A noexec-mounted SSD may prevent launch and must be addressed through normal OS configuration, not privilege escalation by the app.

All launchers set `VAULTDRIVE_PORTABLE_HOME` to the extracted root. Direct app launches also search for that root's manifest and launcher. Thus all OS/CPU variants share the same portable vault list rather than creating a separate list under each binary directory. The `.command`/`.sh` launchers require a normal POSIX shell; `.bat` requires standard Windows cmd. No Python/Rust is needed by these runtime launchers.

Build and package this host, accepting a clearly named partial archive:

```sh
./build-complete.sh
```

Windows equivalent: `build-complete.bat` (Python and the MSVC Rust build toolchain required at build time).

For an actual complete distribution, run the per-target build/package jobs on compatible machines, collect all eight platform ZIPs, and combine them:

```sh
./build-complete.sh --skip-build --require-all --artifact-dir /path/to/platform-artifacts
```

Without `--skip-build`, the script first builds this host's release binaries. By default, available targets produce `VaultDrive-partial.zip` when some are missing; this is a successful local build. With `--require-all`, missing targets fail the operation and no complete archive is published. `--allow-partial` remains a compatibility alias for the default. `--allow-debug` is only for development partial packages; a complete distribution requires all release builds. Existing unrelated/old platform ZIPs in the input folder are rejected rather than silently mixed. Do not put vault data into artifact input folders.

The CI workflow has a final job that gathers successful platform artifacts and creates `VaultDrive-complete.zip`. It has not been remotely executed here. The assembler verifies source fingerprint, file SHA-256 hashes, executable OS/CPU headers, duplicate platforms and ZIP paths. These checks detect inconsistencies and accidental tampering, not malicious replacement of both binaries and manifests by an attacker. SHA-256 sidecars are integrity checks, not code signatures. macOS notarization, Windows signing, native runtime tests and clean-machine dependency checks are still required for a verified public release.

The final layout is:

```text
VaultDrive/
  VaultDrive.sh
  VaultDrive.command
  VaultDrive.bat
  manifest.json
  bin/
    aarch64-apple-darwin/VaultDrive.app
    x86_64-apple-darwin/VaultDrive.app
    x86_64-pc-windows-msvc/vault-gui.exe
    i686-pc-windows-msvc/vault-gui.exe
    aarch64-pc-windows-msvc/vault-gui.exe
    x86_64-unknown-linux-gnu/vault-gui
    i686-unknown-linux-gnu/vault-gui
    aarch64-unknown-linux-gnu/vault-gui
```

Each directory also contains its CLI. `vaults.json` and `vaults.lock` are created at the root during use, not included as user data in the distribution. Source/build scripts, private design references and font assets are excluded.

## GitHub Actions triggers

The `Portable builds` workflow runs automatically when any tag is pushed (`v0.1.0`, `release/test`, etc.). Ordinary branch pushes do not start release builds. Manual execution is also enabled: open Actions → Portable builds → Run workflow and choose the branch/tag.

For example, after committing the intended source:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The tag must point to a commit containing the workflow. A local tag without a push does not reach GitHub. The workflow must be on the default branch for the manual Run workflow button to appear. Build artifacts are retained for 30 days: eight platform archives, SHA-256 sidecars and a complete package assembled only after all targets succeed. The workflow uploads Actions artifacts; it does not automatically publish a GitHub Release. It uses read-only repository permissions, pinned Rust 1.96.0, and LF-normalized source for consistent cross-platform fingerprints. It includes no user vaults, runtime lists or passwords.
