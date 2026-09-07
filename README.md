# SecureVault Password Manager

SecureVault is a local-first password manager for a single user and machine. It provides a PySide6 desktop application, an interactive command-line interface, encrypted vault storage, password-health analysis, optional Have I Been Pwned checks, Bluetooth device verification, and a plaintext-notes import pipeline.

This project is security-sensitive software. Read the security notes and implementation report before storing important credentials.

## Features

- Encrypted SQLite-compatible vault storage with per-entry authenticated encryption.
- Argon2id master-password key derivation.
- XChaCha20-Poly1305 encryption with random nonces and authenticated data.
- Vault lifecycle management with explicit lock, unlock, and key wiping behavior.
- Optional Windows Bluetooth verification when trusted devices are configured.
- Six-digit trusted-device pairing workflow and emergency-override audit logging.
- Secure clipboard copy with a timeout and Windows privacy flags.
- Password health scoring for weak and reused credentials.
- HIBP Pwned Passwords checks using the five-character SHA-1 k-anonymity prefix.
- Plaintext notes import with encoding detection, pattern parsing, validation, fuzzy duplicate detection, optional local Ollama parsing, and optional secure deletion.
- GUI settings for auto-lock and clipboard timeout.

## Current Status

The core vault, cryptography, KDF, database, clipboard, breach, BLE support, import ETL, and GUI are implemented and covered by focused tests. Some items in the original design specification remain partial; see [docs/implementation-report.md](docs/implementation-report.md) for the verified status and limitations.

The current Bluetooth production path checks Windows paired-device presence. The signed GATT challenge-response protocol is implemented as a lower-level component but is not yet the path used by the CLI and GUI. Biometric integration is currently a platform helper boundary rather than a complete Windows Hello or Touch ID integration.

## Requirements

- Python 3.10 or newer recommended.
- Windows is the primary supported desktop platform for Bluetooth presence checks and clipboard privacy behavior.
- PySide6 for the desktop GUI.
- A local Ollama installation is optional and only needed for the `--ollama` import mode.
- Bluetooth hardware and a configured trusted device are required for Bluetooth verification.

## Installation

From the repository root on Windows PowerShell:

```powershell
py -3 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, run the project with the virtual-environment interpreter directly:

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run the Desktop App

```powershell
python main.py
```

The application opens at the unlock screen. Use the create-vault flow for first-time setup, then unlock an existing vault. After unlock, the main window provides entry management, search, import, settings, pairing, copy, and manual lock actions.

## CLI Usage

The CLI is useful for scripted or terminal-based workflows:

```powershell
python cli.py create passwords.vault
python cli.py add passwords.vault
python cli.py list passwords.vault
python cli.py copy passwords.vault github
python cli.py health passwords.vault
python cli.py hibp passwords.vault
python cli.py import passwords.vault notes.txt
python cli.py import passwords.vault notes.txt --ollama
```

All existing-vault commands prompt for the master password. When trusted devices are registered, the CLI also performs its Bluetooth verification step. The `copy` command clears the clipboard after its configured delay; do not interrupt or bypass that behavior when copying sensitive credentials.

The import command displays candidates and asks for confirmation before writing them. It separately asks whether to securely delete the source notes file. Review the candidates carefully before either confirmation.

## Tests

Run the automated suite from the repository root:

```powershell
python -m pytest -q
```

The tests cover cryptographic round trips and tamper handling, KDF behavior, database operations, vault lifecycle, clipboard configuration, BLE protocol and pairing logic, password health, HIBP response parsing, import ETL, secure deletion, and selected UI 2FA behavior. Full GUI interaction, live Bluetooth hardware, live HIBP requests, Ollama, and the complete CLI are not covered end to end.

## Storage and Sensitive Files

A vault normally has two files:

- `passwords.vault`: encrypted database file.
- `passwords.vault.kdf`: non-secret KDF metadata required to derive the key.

The KDF sidecar is ignored by Git in this repository. The vault itself contains sensitive encrypted data and should also never be committed, copied to an untrusted location, or treated as a backup without protecting it appropriately. Losing the KDF sidecar makes the vault unrecoverable with the current format. Keep an offline, protected backup of both files if backup is part of your operating procedure.

The application is not a replacement for full-disk encryption. A compromised operating system, keylogger, malicious update, or physical coercion is outside the stated threat model. HIBP checks are opt-in network activity: only a five-character SHA-1 prefix is sent, but the request still leaves the machine.

## Project Layout

```text
main.py                 PySide6 application entry point
cli.py                  Interactive command-line entry point
password-manager-spec.md Original design specification
src/core/               Vault, database, crypto, KDF, session, clipboard
src/ble/                BLE protocol, pairing, and Windows presence checks
src/breach/             HIBP integration and password health analysis
src/import_etl/         Notes extraction, parsing, validation, deduplication, deletion
src/ui/                 Desktop dialogs and vault views
src/utils/              Biometric and logging helpers
tests/                  Automated tests
```

## Security Reporting

Do not include real passwords, vault files, KDF sidecars, plaintext notes, or HIBP response data in an issue or pull request. Reproduce issues with disposable test credentials and describe the affected component and conditions.
