# VaultDrive

Experimental Rust desktop app for a portable encrypted vault. Keep separate backups; the format is not audited and writable Finder integration is incomplete.

## Desktop

```sh
cargo run -p vault-gui
```

Home shows saved vaults and **Unlock / Lock / Create / Decrypt**. Each task opens a separate screen in the same native window. Choose a new vault folder to create; choose an existing vault to unlock. Unlock starts an authenticated loopback WebDAV server and, by default, requests a connection through your file manager. The GUI supports **Guest** access through a fresh per-unlock connection URL; choose Guest if Finder asks. The connection URL itself authorizes access and changes after locking. OS mounting is not verified. Eject the volume before Lock.

Decrypt exports files to a new unencrypted folder under your chosen destination and preserves the encrypted source. The password-free vault list is saved beside the app as `vaults.json`. Put the app and vault folders together on the SSD for relative paths to survive drive changes.

## CLI

```sh
cargo run -p vault-cli -- init /path/to/new-vault
cargo run -p vault-cli -- unlock /path/to/new-vault --port 49152
```

CLI shutdown: Ctrl-C. The GUI and CLI take the same OS file lock to prevent competing vault writers. Do not remove `vault.lock` while running. Writes preserve the previous ciphertext as `vault.bak` before atomically replacing `vault.dat`. A stale lock file is normal; the OS releases the actual lock at process exit.

## Scope

The entire encrypted snapshot is held in memory and rewritten on save. Serialized vault size is limited to 64 MiB, uploads to 32 MiB. This is not suitable for real SSD-scale workloads. DAV currently supports OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, MOVE and PROPFIND. File ETags, If-Match/If-None-Match checks and transactional MOVE are implemented. There is no DAV LOCK or COPY support; common editors and Finder may mount read-only or fail to save. Automatic connection launches the OS client and may still need OS authentication/configuration. It is not a guaranteed writable mount or automatic unmount.

Build/CI targets cover macOS x86_64/ARM64 and Windows/Linux x86 32-bit, x86_64 and ARM64. Only local macOS ARM64 execution is validated. Linux system libraries, Windows WebClient/runtime requirements and unsigned binaries mean this is not yet universally standalone on every clean computer.

- `docs/ARCHITECTURE.md`: module responsibilities and invariants
- `docs/SECURITY.md`: threat model, backup and durability limits
- `docs/PORTABILITY.md`: portable registry, OS/CPU matrix, native mount constraints
- `docs/VALIDATION.md`: actual checks versus untested configurations
- `design/README.md`: Design System Studio provenance

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Vault rows have a `...` menu to remove a shortcut without deleting encrypted files. Concurrent list updates reload under an OS lock. Windows-incompatible export names are rejected before creating plaintext output. Upload concurrency is bounded; partial PUT is rejected rather than silently truncating a file.

## SSD launchers / combined distribution

Extract the whole portable ZIP, then double-click the root `VaultDrive.app` on Mac (no Terminal window), `VaultDrive.sh` on Linux or `VaultDrive.bat` on Windows. The launcher chooses the OS/CPU and shares a single vault list at the root. `./build-complete.sh` builds this host's Release package. To create a complete package from all eight platform artifacts, run `./build-complete.sh --skip-build --require-all --artifact-dir /path/to/artifacts`. Windows has the equivalent `build-complete.bat`. Output ZIPs and SHA-256 checksums are under `target/distribution/`. See PORTABILITY.md for requirements and explicit partial-package behavior.

The default local build succeeds with the available platforms and labels incomplete output `VaultDrive-partial.zip`. Use `--require-all` to enforce a complete eight-platform distribution.

Tag builds and ordinary manual Actions builds now require code signing/notarization. Configure the repository secrets described in `docs/SIGNING.md`; absent credentials fail preflight. Manual `unsigned_preview` is available for development only. Local development packaging remains unsigned unless `--require-signatures` is supplied. Previous unsigned artifacts remain unsigned; this configuration does not retroactively sign them.

GUI password fields accept printable ASCII only (English letters, digits, spaces and symbols); IME composition and non-ASCII/mixed pasted text are rejected as a whole. Existing non-ASCII vault passwords remain supported by the CLI; the encrypted format is unchanged. `.command`/`.sh` remain terminal-based fallback launchers.
