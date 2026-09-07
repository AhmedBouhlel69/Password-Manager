# Local Password Manager — Specification

**Status:** Draft v1
**Owner:** You
**Scope:** Single-user, single-machine, fully offline password manager with Bluetooth-based iPhone approval as a second factor, and a local-LLM-assisted import pipeline for migrating from an existing plaintext notes file.

---

## 1. Goals & Non-Goals

**Goals**
- Fully offline vault — no cloud dependency, no server component.
- Two-factor unlock: something you know/are (master password + OS biometric) + something you have (iPhone, proven via Bluetooth).
- One-time secure migration of existing plaintext credentials via a local (non-cloud) LLM parser.
- Breach monitoring against known-compromised credentials (HIBP-style).
- Reasonable, well-documented crypto — no home-rolled primitives.

**Non-Goals (v1)**
- No cross-device sync (single machine only).
- No cloud backup.
- No browser extension or autofill (can be a v2 consideration).
- No multi-user / sharing features.

---

## 2. Threat Model

Explicitly defending against:
- Disk theft / vault file exfiltration (vault must be useless without master password + KDF).
- Shoulder-surfing / opportunistic access while you're away from the machine (BLE proximity factor).
- Credential reuse against known breaches (HIBP check).
- Accidental exposure of the plaintext notes file during/after migration.
- Clipboard sniffing after copying a password.

Explicitly **not** defending against (out of scope, document this so it's a conscious choice, not an oversight):
- A fully compromised OS/kernel (keyloggers with root access, malicious OS updates).
- Physical coercion attacks (rubber-hose).
- Supply-chain compromise of dependencies (mitigated only by using well-audited libraries and pinning versions).

---

## 3. High-Level Architecture

```
┌─────────────────────────────┐        BLE GATT        ┌───────────────────────┐
│   Desktop App (Python)      │◄───────────────────────►│  iOS Companion App    │
│   - Vault engine            │   challenge/response     │  (Swift, minimal)     │
│   - Unlock flow             │                          │  - Approve/Deny UI    │
│   - Import ETL              │                          │  - Signs challenges   │
│   - Breach monitor          │                          └───────────────────────┘
└─────────────┬────────────────┘
              │
      Encrypted vault file
      (local disk only)
```

Single desktop binary, single companion iPhone app. No servers anywhere in the picture.

---

## 4. Core Vault Security

### 4.1 Unlock flow
1. User enters **master password**.
2. OS-level biometric check (Touch ID / Windows Hello) as a corroborating factor on that same machine.
3. App issues a **BLE challenge** to the paired iPhone (see §5). Vault only fully unlocks once the phone approves.

### 4.2 Key derivation
- **Argon2id** for master-password stretching (memory-hard, resistant to GPU cracking).
  - Suggested starting params: 64 MB memory, 3 iterations, parallelism 4 — tune to your hardware so unlock takes ~0.5–1s.
- Derived key is never written to disk; held only in memory for the session.

### 4.3 Encryption
- **AES-256-GCM** or **XChaCha20-Poly1305** for the vault contents (either is fine; XChaCha20 has a larger nonce space, which is nice for an offline file you'll rewrite many times).
- Each vault entry encrypted individually (not just the whole file as one blob) so partial reads/writes don't require decrypting everything.
- Unique nonce per encryption operation — never reused.

### 4.4 Storage format
- SQLite database encrypted at rest via **SQLCipher**, *or* a custom encrypted single-file container if you want to avoid the SQLCipher dependency. SQLCipher is the pragmatic choice — mature, widely used, good Python bindings.
- File permissions locked to the current OS user only.

### 4.5 Session behavior
- Configurable auto-lock timeout (e.g. 5 min idle).
- Master key wiped from memory (not just dereferenced — explicitly overwritten where the language allows) on lock.
- Clipboard: copied passwords auto-clear after a short timeout (e.g. 20–30s), and clipboard history integrations should be identified and warned against.

---

## 5. Second Factor: iPhone BLE Approval

This is the most custom part of the system, so being precise about the protocol matters.

### 5.1 Design
- Desktop app acts as **BLE central**; iPhone runs a lightweight companion app acting as **BLE peripheral**.
- On unlock attempt, desktop:
  1. Generates a random challenge nonce.
  2. Connects to the paired iPhone over BLE and writes the challenge to a custom GATT characteristic.
  3. iPhone app receives it, shows a native **notification with Approve/Deny**, displaying which device/vault is requesting access (so you can catch a spoofed request).
  4. On Approve, iPhone signs the challenge with a device-specific key (generated at pairing time, stored in the iPhone Secure Enclave/Keychain) and writes the signature back over BLE.
  5. Desktop verifies the signature against the public key recorded at pairing. Only then does the vault fully unlock.
- This is a **challenge-response approval**, not just "is the phone nearby" — nearby-only proximity checks are spoofable (someone could just carry a BLE relay). Requiring an explicit tap + signed response is meaningfully stronger for very little added complexity.

### 5.2 Pairing (one-time setup)
- Desktop generates an ECDSA (P-256) keypair on the iPhone side during first pairing; public key stored on desktop, private key never leaves the iPhone's Secure Enclave.
- Pairing itself should require both: a code shown on desktop typed into the iPhone app, *and* physical proximity — to prevent pairing with an attacker's phone during setup.

### 5.3 Out-of-range / failure behavior
- If BLE connection fails or times out: vault shows **"locked, phone not detected"**.
- **Emergency override**: allows unlock via master password + biometric alone, but:
  - Requires re-typing the full master password (not cached).
  - Adds a deliberate delay (e.g. 10–15s) before granting access.
  - Logs the override event locally with a timestamp, visible next time the phone does connect (so you'll notice if it happened without your knowledge).

### 5.4 Backup devices
- Additional trusted devices (e.g. a second iPhone/iPad, or a spare phone kept in a safe) can be paired the same way, each with their own keypair, any of which can satisfy the second factor.
- Losing all trusted devices means falling back to the emergency-override path — there is no cloud recovery, by design.

---

## 6. Import ETL (Notes → Vault)

Goal: get everything out of the existing plaintext note reliably, then make sure the plaintext source doesn't linger anywhere.

### 6.1 Pipeline
1. **Extract**: Read the notes file locally (never leaves the machine).
2. **Transform**:
   - Since the format is mixed (some structured lines, some raw pasted logins), use a **local LLM via Ollama** (e.g. a small model like Llama 3.2 8B or Mistral 7B, run fully offline) to segment the text into candidate entries and extract `{site, username, password, notes}` fields.
   - Run a **validation pass** after the LLM step: regex sanity checks (does the "password" field look like a password, does "site" look like a domain/name), flag low-confidence extractions for manual review rather than silently importing garbage.
   - Deduplicate against existing vault entries (fuzzy match on site name).
3. **Load**: Write validated entries into the encrypted vault, entry-by-entry, inside the normal encryption path (§4.3) — the import pipeline never writes plaintext to disk itself.
4. **Review step**: Before finalizing, show a diff/summary UI — "47 entries extracted, 3 flagged for review, 2 possible duplicates" — for manual confirmation.
5. **Secure delete**: After confirmed import, securely delete (multi-pass overwrite where the filesystem allows, otherwise at minimum standard delete + note that SSDs make true secure-delete unreliable — recommend full-disk encryption as the real backstop) the original notes file. Prompt you explicitly before doing this — don't auto-delete without confirmation.

### 6.2 Why local LLM specifically
- Confirmed: this must be a **local model** (Ollama or equivalent) — no cloud API calls for this step, since the whole point is these are your live, unrotated credentials. This should be enforced in code (e.g. hard-fail if it detects any outbound network call during the import step), not just a policy note.

### 6.3 Post-import hygiene
- After import, the tool should flag which imported passwords are weak/reused, so you have a prioritized list for rotation (see breach monitoring below) — since the whole point of migrating is to leave the insecure note behind, not to carry its problems into the new vault.

---

## 7. Breach Monitoring (HIBP-style)

- On import and periodically thereafter, check each password's hash prefix against the **Have I Been Pwned Pwned Passwords** k-anonymity API (only a 5-character SHA-1 prefix is sent, never the full hash or password — this is HIBP's designed-for-privacy model).
- Flag any matches with a clear severity indicator and a one-click path to mark that entry "needs rotation."
- This is the one external network call the app makes — make it opt-in/toggleable and clearly labeled, since it's the one place data leaves the machine (in k-anonymized form).

---

## 8. Tech Stack

| Component | Choice | Notes |
|---|---|---|
| Desktop GUI | Python + PySide6 (Qt) | Native look across Mac/Win/Linux, mature |
| Packaging | PyInstaller or Briefcase | Produces a native-feeling standalone app |
| Crypto | `cryptography` (pyca) | Well-audited, avoid rolling your own |
| Vault storage | SQLCipher via `pysqlcipher3` (or equivalent) | Encrypted SQLite |
| KDF | `argon2-cffi` | Argon2id |
| BLE (desktop side) | `bleak` | Cross-platform async BLE, works on Mac/Win/Linux |
| Local LLM | Ollama (local server) + small model | Fully offline inference |
| iOS companion app | Swift, CoreBluetooth peripheral mode | Minimal — pairing, approve/deny UI, Secure Enclave key ops |

---

## 9. Open Questions Before Build

A few things worth deciding before implementation starts:

1. **BLE range tuning** — how close is "present"? RSSI-based proximity is noisy; the challenge-response model in §5 mostly sidesteps this since it's an explicit tap, not just signal strength, but worth confirming that's acceptable.
2. **Emergency override frequency** — if it's used often, it becomes the real security boundary and the BLE factor becomes theater. Worth deciding what "too often" looks like and whether repeated overrides should force phone re-pairing.
3. **Notes file location and format** — exact path/format so the import parser can be scoped correctly (plain `.txt`, Apple Notes export, etc.).
4. **HIBP toggle default** — on or off by default, given it's the one networked feature.

---

## 10. Milestones (suggested)

1. Vault core: encryption, KDF, SQLCipher storage, master password unlock. *(usable standalone at this point)*
2. iOS companion app + BLE pairing/challenge-response.
3. Import ETL: local LLM extraction + validation + review UI.
4. Breach monitoring integration.
5. Hardening pass: memory wiping, clipboard timeout, audit logging, secure-delete of source notes.
