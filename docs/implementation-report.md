# SecureVault Implementation Report

## 1. Purpose and Scope

This report records the state of the repository as implemented on 2026-09-07. It compares the running code with `password-manager-spec.md`, identifies the security boundaries that are actually enforced, and lists the remaining work required before describing the project as production-ready.

The project is designed as a single-user, single-machine password manager with a local desktop UI, a CLI, encrypted local storage, optional Bluetooth verification, local notes import, and opt-in breach checks.

## 2. Executive Summary

The project has a substantial working core:

- Vault creation, unlock, lock, CRUD, search, audit logging, and trusted-device persistence are implemented.
- Master passwords are stretched with Argon2id using a 16-byte random salt and default parameters of 64 MiB memory, 3 iterations, parallelism 4, and a 32-byte output.
- Credential records receive application-level XChaCha20-Poly1305 encryption in addition to encrypted SQLite-compatible database storage.
- The desktop UI and CLI expose normal credential-management workflows.
- Import, password-health, HIBP parsing, clipboard handling, and BLE pairing logic have focused tests.

The most important qualification is that the original design and the current production paths are not identical. The CLI and GUI currently use Windows Bluetooth paired-device/RFCOMM presence verification, not the signed GATT challenge-response flow described in the specification. Biometric support is also not a real OS biometric prompt yet. These are material security and product-status limitations.

## 3. Implemented Components

### 3.1 Application surfaces

- `main.py` starts `src.app.run_app()` and launches the PySide6 UI.
- `cli.py` provides `create`, `add`, `list`, `copy`, `health`, `hibp`, and `import` commands.
- The GUI includes unlock/create flows, vault listing and search, entry editing, import review, pairing, settings, clipboard copy, auto-lock, and manual lock.

### 3.2 Vault and storage

`src/core/vault.py` owns the closed, locked, and unlocked lifecycle. It derives a key during creation or unlock, validates a stored encrypted verification token, delegates record operations to the database, and wipes the in-memory key during lock.

`src/core/database.py` stores metadata, timestamps, audit events, trusted Bluetooth devices, and encrypted entry blobs. Entry IDs are supplied as authenticated data so a record cannot be moved or relabeled without detection by the application encryption layer.

The database encryption layer uses the APSW/sqlite3mc dependency rather than SQLCipher. This is consistent with the specification's allowance for an encrypted SQLite-compatible design, but it is a different implementation choice from the specific SQLCipher recommendation.

KDF parameters are stored in a plaintext sidecar named `<vault>.kdf`. The salt and cost parameters are not secret, but the sidecar is required for recovery. A missing sidecar produces a clear unlock error; it cannot be reconstructed from the encrypted database with the current format.

### 3.3 Cryptography and key derivation

- `src/core/kdf.py` uses Argon2id and returns a mutable key buffer.
- `src/core/crypto.py` uses XChaCha20-Poly1305 with 32-byte keys and random 24-byte nonces.
- Ciphertext serialization is `nonce || ciphertext || authentication tag`.
- Wrong keys, altered ciphertext, altered authenticated data, and malformed blobs are rejected.
- `src/core/secure_memory.py` provides explicit wiping of mutable buffers where Python permits it.

This design avoids home-rolled cryptographic primitives, but memory wiping in a managed runtime cannot guarantee that no immutable copies ever existed.

### 3.4 Session and clipboard protection

The GUI starts a five-minute Qt idle timer and exposes settings for timeout configuration. The clipboard helper defaults to a 30-second timeout and only clears the clipboard if the copied text is still present. On Windows it sets privacy flags intended to suppress history, cloud upload, and monitoring integrations. Non-Windows behavior falls back to the Qt clipboard without those Windows-specific flags.

### 3.5 Bluetooth and pairing

The repository contains two Bluetooth layers:

- `src/ble/protocol.py` and `src/ble/central.py` implement protocol constants, challenge/response payload handling, and ECDSA P-256 verification for a signed GATT design.
- `src/ble/windows_bluetooth.py` is the path used by the current CLI and GUI and checks the presence of a Windows-paired device through the available Windows Bluetooth path.
- `src/ble/pairing.py` provides six-digit pairing codes, attempt limits, trusted-device registration, and emergency-override logging/delay.

The pairing and protocol primitives have tests, but live iOS interoperability and end-to-end signed GATT unlock are not currently verified by the application test suite.

### 3.6 Import ETL

The import pipeline is split into extraction, parsing, validation, deduplication, network guarding, and secure deletion:

1. Read notes using common text encodings and split them into manageable chunks.
2. Parse with a local Ollama model when requested and available, otherwise use the regex fallback.
3. Normalize and validate candidate entries, including confidence information.
4. Compare candidates against existing entries using fuzzy site and username matching.
5. Display candidates and require confirmation before inserting them into the vault.
6. Optionally overwrite and delete the source file after a second confirmation.

The secure-delete implementation is tested for in-place overwrite behavior. Secure deletion cannot guarantee removal from SSD wear-leveling storage; full-disk encryption remains the stronger control.

### 3.7 Breach and password health checks

`src/breach/password_health.py` reports approximate entropy, strength issues, reuse groups, and an overall score. `src/breach/hibp.py` hashes passwords locally and sends only the first five SHA-1 characters to the HIBP Pwned Passwords endpoint, with response parsing and retry behavior.

HIBP checking is currently a manual CLI operation. It is not a periodic background check and is not automatically run after import.

## 4. Security Model Actually Enforced

The implementation provides meaningful protection against offline vault-file theft when the master password is strong, because the attacker needs the password to derive the database and entry-encryption keys. It also reduces clipboard persistence and records important vault and pairing events locally.

The following remain outside the protection boundary:

- A compromised operating system, kernel, or Python runtime.
- Keyloggers, screen capture, malicious accessibility tools, or malicious OS updates.
- Physical coercion.
- Supply-chain compromise of dependencies.
- Data recovery guarantees after deleting files on SSDs.
- Exposure caused by a user copying or exporting plaintext credentials.

## 5. Specification Gap Register

| Area | Current implementation | Required follow-up |
|---|---|---|
| Biometric factor | Helper boundary exists; real Windows Hello/Touch ID invocation is not integrated | Implement and test a real platform biometric provider, with explicit failure behavior |
| BLE unlock | Windows paired-device/RFCOMM presence is used by CLI and GUI | Wire signed GATT challenge-response into the production unlock path and test against the iOS companion |
| Emergency override | Pairing manager supports logging and delay; GUI delay is shorter than the specification and does not require full password re-entry | Require fresh master-password entry and use the specified deliberate delay |
| Import duplicate handling | Duplicates are identified and displayed, but candidates are still imported after confirmation | Add skip/replace/merge decisions and make the selected action explicit |
| Import network isolation | Local Ollama calls use loopback checks; the whole import operation is not wrapped in a network guard | Enforce the guard around the entire import lifecycle |
| Post-import health | Health is available separately | Run health analysis after confirmed import and present rotation priorities |
| HIBP workflow | Manual CLI check with k-anonymity prefix | Add opt-in scheduling/settings and a needs-rotation state |
| KDF metadata | Stored in a required plaintext sidecar | Prefer a recoverable vault header or document and test backup/recovery procedures |
| Permissions | File restriction is best-effort, especially on Windows | Apply and verify explicit Windows ACLs for vault and sidecar files |
| GUI search | Filters site and username | Match the core search behavior for URL, notes, and tags, or document the intentional scope |
| End-to-end coverage | Focused unit tests exist | Add CLI, GUI workflow, live-provider-mocked, and iOS/BLE integration tests |

## 6. Test Coverage

The test suite currently includes:

- `test_crypto.py`: authenticated encryption, nonce uniqueness, tampering, wrong keys, sizes, and large payloads.
- `test_kdf.py`: determinism, salt/password separation, output shape, and parameter serialization.
- `test_database.py`: schema, metadata, CRUD, counts, audit events, and duplicate IDs.
- `test_vault.py`: creation, unlock, lock, wrong-password handling, CRUD, listing, and locked-state behavior.
- `test_clipboard.py`: construction and timeout configuration.
- `test_ble.py`: protocol parsing/signatures, pairing, emergency logging, biometric helper, and trusted-device persistence.
- `test_breach.py`: HIBP response parsing and password-health calculations.
- `test_import_etl.py`: extraction, parsing, validation, deduplication, network guard, and secure deletion.
- `test_ui_2fa.py`: Windows Bluetooth enumeration, pairing dialog basics, and 2FA lock-state behavior.
- `test_audit_fixes.py`: secure deletion, TLD-aware deduplication, pairing rate limiting, and missing-sidecar errors.

Run the suite with:

```powershell
python -m pytest -q
```

The highest-value missing tests are real CLI workflows, unlock and lock UI flows, mocked HIBP network behavior, Ollama availability/failure behavior, complete import transaction behavior, and end-to-end signed BLE communication.

## 7. Operational Recommendations

1. Use a long, unique master password and enable full-disk encryption on the host.
2. Protect and back up both the vault file and its `.kdf` sidecar together.
3. Do not commit `passwords.vault`, plaintext notes, exports, or test data containing real credentials.
4. Review every import candidate and duplicate before confirming the import.
5. Treat HIBP as opt-in network activity even though the API receives only a hash prefix.
6. Test recovery with disposable credentials before relying on the vault for important accounts.
7. Do not describe the current Bluetooth or biometric paths as equivalent to the full specification until the gaps above are closed.

## 8. Recommended Next Milestones

1. Complete and test the real platform biometric provider.
2. Replace production Bluetooth presence checks with signed GATT challenge-response.
3. Harden emergency override and Windows ACL behavior.
4. Make import duplicate actions and post-import health review explicit.
5. Add end-to-end and provider-mocked tests for the user-facing workflows.
6. Define a versioned vault header so KDF metadata is not a required sidecar.
