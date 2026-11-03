# Boundaries and invariants

- `vault-core`: VDMVP001 format, pinned Argon2id parameters, authenticated chunks, authenticated content-tree validation. `storage.rs`: bounded reads, lifetime OS file lock, flushed same-directory temporary file and atomic persist, previous ciphertext backup. It owns secrets and the exclusive vault session.
- `vault-fs`: transactional in-memory edits and rollback on pre-commit failure; path rules; plaintext export to a new private directory. Export never edits the encrypted source and cleans partial output on ordinary errors.
- `vault-dav/http.rs`: HTTP auth, browser-Origin rejection, bounded/timed upload read, DAV request dispatch on blocking workers. `lib.rs`: listener lifecycle, CLI and controlled-server entry points. Mutex poisoning returns a server error. GUI and CLI share the same data/storage layer.
- `vault-gui/main.rs`: native window setup only. `app.rs`: screen/phase state and navigation. `session.rs`: worker/thread ownership, key derivation, server and plaintext export. `registry.rs`: atomic password-free portable list. `platform.rs`: native connection request with strict loopback address parsing and no credentials on the command line.
- `vault-cli`: password prompts and foreground server.

Screens: Home, Unlock, Create (location), CreatePassword, Decrypt, Connection, Forget (shortcut only). These are separate views in one native window, rather than launching independent vault processes. Phases: Idle, Working, Unlocked, Stopping. UI disables work while a worker is active. App drop signals shutdown, drops unread events (including Ready shutdown handles), and joins the worker. A server error or worker panic is surfaced. Server unlocked state must never be presented as proof of an OS mount.

Storage commit point is atomic replacement of `vault.dat`. `vault.bak` contains the preceding ciphertext, not a second plaintext copy. Returning a failure after commit would cause the Store to roll back RAM while disk holds new contents, so directory fsync after commit is best effort. Full power-loss durability across removable filesystems remains unverified. Registry replacement uses the same atomic tempfile strategy, with no passwords.

Plaintext Decrypt is an export: it creates a fresh directory under a user-selected destination and preserves the encrypted source. Exported files are unencrypted, and user applications/OS caches remain outside VaultDrive's control. A force-terminated export may leave a partial plaintext directory. It is not secure erasure or in-place conversion.

HTTP writes and MOVE evaluate supplied file preconditions under the same store mutex as mutation. File ETags hash the byte representation with SHA-256. This prevents lost updates only when clients supply conditions; unconditional writes can still overwrite one another. MOVE operates on the entire subtree in one Store transaction and rejects ancestor/descendant cycles. Four admitted requests bound buffered uploads/dispatch; excess requests receive 503. Unsupported partial PUT and DAV If lock conditions fail closed. PROPFIND borrows entry metadata instead of cloning file contents.

Protocol references: [RFC 4918 MOVE](https://www.rfc-editor.org/rfc/rfc4918.html#section-9.9), [RFC 9110 conditional requests](https://www.rfc-editor.org/rfc/rfc9110.html#name-if-match). This is a bounded subset implementation, not a WebDAV conformance claim.
