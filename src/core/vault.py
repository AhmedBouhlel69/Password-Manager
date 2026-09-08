"""
Vault engine — coordinates KDF, crypto, database, and session lifecycle.

This is the central orchestrator. It owns the derived key, manages the
lock/unlock state machine, and provides the public API for the UI layer.

Lifecycle:
1. create_vault() — first-time setup: generate salt, derive key, create DB
2. unlock() — derive key from password, verify against stored token
3. (use vault — add/get/update/delete entries)
4. lock() — wipe key from memory, close DB
5. unlock() again when needed

The vault stores a "verification token" — a known plaintext encrypted with
the derived key. On unlock, we try to decrypt it; if it succeeds, the
password is correct. This avoids storing the password hash itself.
"""

import json
import os
from pathlib import Path
from typing import Optional

from src.core.kdf import KDFParams, derive_key, generate_salt
from src.core.crypto import encrypt, decrypt, CryptoError
from src.core.database import VaultDatabase, DatabaseError
from src.core.secure_memory import wipe, SecureByteArray


# Known plaintext used for password verification.
# We encrypt this with the derived key at vault creation; on unlock,
# we try to decrypt it. Success = correct password.
_VERIFICATION_PLAINTEXT = b"VAULT_VERIFICATION_TOKEN_v1"


class VaultError(Exception):
    """Raised on vault operation failures."""
    pass


class VaultState:
    """Enum-like constants for vault state."""
    CLOSED = "closed"       # No vault file loaded
    LOCKED = "locked"       # Vault file loaded but key not derived
    UNLOCKED = "unlocked"   # Key derived, ready for operations


class Vault:
    """Password vault engine.

    Thread safety: This class is NOT thread-safe. The UI should ensure
    all vault operations happen on the same thread (or use proper locking).
    """

    def __init__(self):
        self._state: str = VaultState.CLOSED
        self._db: Optional[VaultDatabase] = None
        self._key: Optional[bytearray] = None
        self._vault_path: Optional[str] = None
        self._kdf_params: Optional[KDFParams] = None

    @property
    def state(self) -> str:
        return self._state

    @property
    def is_unlocked(self) -> bool:
        return self._state == VaultState.UNLOCKED

    @property
    def is_locked(self) -> bool:
        return self._state == VaultState.LOCKED

    @property
    def vault_path(self) -> Optional[str]:
        return self._vault_path

    @property
    def entry_count(self) -> int:
        if self._db and self._db.is_open:
            return self._db.entry_count()
        return 0

    # ── Vault Lifecycle ────────────────────────────────────────────────

    def create_vault(self, path: str, master_password: str) -> None:
        """Create a new vault at the given path.

        Generates salt, derives key, creates encrypted database, stores
        KDF params and verification token.

        Args:
            path: Filesystem path for the vault database file.
            master_password: The master password chosen by the user.

        Raises:
            VaultError: If vault already exists at path or creation fails.
        """
        if os.path.exists(path):
            raise VaultError(f"Vault file already exists at {path}")

        salt = generate_salt()
        kdf_params = KDFParams(salt=salt)

        # Derive the encryption key
        key = derive_key(
            master_password,
            salt,
            memory_cost=kdf_params.memory_cost,
            time_cost=kdf_params.time_cost,
            parallelism=kdf_params.parallelism,
            hash_len=kdf_params.hash_len,
        )

        try:
            # Use hex of derived key as the DB-level passphrase
            db = VaultDatabase(path)
            db.open(key.hex())
            db.initialize_schema()

            # Store KDF params (these are NOT secret — salt, iteration counts, etc.)
            db.set_meta("kdf_params", json.dumps(kdf_params.to_dict()))
            db.set_meta("schema_version", str(1))

            # Store encrypted verification token
            verification_blob = encrypt(
                _VERIFICATION_PLAINTEXT, key, aad=b"verification"
            )
            db.set_meta("verification_token", verification_blob.hex())

            # Save KDF params to sidecar file (unencrypted — not secret)
            self._save_kdf_params(path, kdf_params)

            # Log creation event
            db.log_event("vault_created", f"path={path}")

            # Set file permissions (Windows: rely on NTFS ACLs, Unix: chmod 600)
            self._restrict_file_permissions(path)

            self._db = db
            self._key = key
            self._vault_path = path
            self._kdf_params = kdf_params
            self._state = VaultState.UNLOCKED

        except Exception as e:
            # Clean up on failure
            wipe(key)
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass
            raise VaultError(f"Failed to create vault: {e}") from e

    def unlock(self, path: str, master_password: str) -> bool:
        """Unlock an existing vault.

        Reads KDF params from the vault, derives the key, and verifies
        it against the stored verification token.

        Args:
            path: Path to the vault database file.
            master_password: The master password.

        Returns:
            True if unlock succeeded.

        Raises:
            VaultError: If vault file doesn't exist, is corrupted, or password is wrong.
        """
        if not os.path.exists(path):
            raise VaultError(f"Vault file not found: {path}")

        # First, we need to read KDF params. We open the DB with the key
        # derived from the password — if the password is wrong, DB open will fail
        # or verification will fail.

        # Try opening the DB with a temporary connection to read KDF params.
        # The challenge: we need the KDF params to derive the key, but we need
        # the key to open the encrypted DB. Solution: store KDF params as the
        # DB passphrase is derived with default params first, OR use a two-file
        # approach. For simplicity, we'll try with default params first.

        # Actually, let's try the password as-is with default KDF params.
        # If vault was created with non-default params, this approach fails.
        # Better approach: store KDF params in a small unencrypted header file
        # alongside the main vault, OR use a fixed derivation for the DB key
        # and store KDF params inside.

        # Pragmatic approach: The DB passphrase is the hex of the Argon2id-derived
        # key with whatever params were used at creation. We need to know the params
        # to derive the key. We'll store KDF params in a sidecar JSON file.
        kdf_params = self._load_kdf_params(path)

        key = derive_key(
            master_password,
            kdf_params.salt,
            memory_cost=kdf_params.memory_cost,
            time_cost=kdf_params.time_cost,
            parallelism=kdf_params.parallelism,
            hash_len=kdf_params.hash_len,
        )

        try:
            db = VaultDatabase(path)
            try:
                db.open(key.hex())
            except DatabaseError as e:
                raise VaultError("Could not unlock vault: wrong password or corrupted vault") from e

            # Verify the key by decrypting the verification token
            token_hex = db.get_meta("verification_token")
            if token_hex is None:
                wipe(key)
                db.close()
                raise VaultError("Vault is missing verification token — corrupted?")

            token_blob = bytes.fromhex(token_hex)
            try:
                plaintext = decrypt(token_blob, key, aad=b"verification")
                if plaintext != _VERIFICATION_PLAINTEXT:
                    raise CryptoError("Verification plaintext mismatch")
            except CryptoError:
                wipe(key)
                db.close()
                raise VaultError("Wrong master password")

            # Log the unlock
            db.log_event("vault_unlocked")

            # Close any previously open vault
            self.lock()

            self._db = db
            self._key = key
            self._vault_path = path
            self._kdf_params = kdf_params
            self._state = VaultState.UNLOCKED
            return True

        except VaultError:
            raise
        except Exception as e:
            wipe(key)
            raise VaultError(f"Failed to unlock vault: {e}") from e

    def lock(self) -> None:
        """Lock the vault — wipe key from memory, close DB.

        Safe to call even if already locked or closed.
        """
        if self._key is not None:
            wipe(self._key)
            self._key = None

        if self._db is not None:
            try:
                self._db.log_event("vault_locked")
            except Exception:
                pass
            self._db.close()
            self._db = None

        if self._state == VaultState.UNLOCKED:
            self._state = VaultState.LOCKED

    def close(self) -> None:
        """Fully close the vault — lock + forget the vault path."""
        self.lock()
        self._vault_path = None
        self._kdf_params = None
        self._state = VaultState.CLOSED

    # ── Entry Operations (delegates to database.py) ────────────────────

    def _ensure_unlocked(self) -> tuple[VaultDatabase, bytearray]:
        """Verify vault is unlocked and return (db, key)."""
        if self._state != VaultState.UNLOCKED:
            raise VaultError("Vault is not unlocked")
        assert self._db is not None
        assert self._key is not None
        return self._db, self._key

    def add_entry(self, entry_data: dict, category: str = "") -> str:
        """Add a new credential entry.

        Args:
            entry_data: Dict with site, username, password, url, notes, tags, etc.
            category: Optional category string.

        Returns:
            UUID string of the new entry.
        """
        db, key = self._ensure_unlocked()
        entry_id = db.add_entry(entry_data, key, category=category)
        db.log_event("entry_added", f"id={entry_id}")
        return entry_id

    def get_entry(self, entry_id: str) -> Optional[dict]:
        """Retrieve and decrypt a single entry."""
        db, key = self._ensure_unlocked()
        return db.get_entry(entry_id, key)

    def update_entry(self, entry_id: str, entry_data: dict) -> bool:
        """Update an existing entry."""
        db, key = self._ensure_unlocked()
        result = db.update_entry(entry_id, entry_data, key)
        if result:
            db.log_event("entry_updated", f"id={entry_id}")
        return result

    def delete_entry(self, entry_id: str) -> bool:
        """Delete an entry."""
        db, key = self._ensure_unlocked()
        result = db.delete_entry(entry_id)
        if result:
            db.log_event("entry_deleted", f"id={entry_id}")
        return result

    def list_entries(self) -> list[dict]:
        """List all entries (decrypted)."""
        db, key = self._ensure_unlocked()
        return db.list_entries(key)

    def search_entries(self, query: str) -> list[dict]:
        """Search entries by site name, username, or tags.

        Simple substring matching — runs client-side since entries are encrypted.

        Args:
            query: Search string (case-insensitive).

        Returns:
            List of matching entries.
        """
        all_entries = self.list_entries()
        query_lower = query.lower()
        results = []
        for entry in all_entries:
            searchable = " ".join([
                entry.get("site", ""),
                entry.get("username", ""),
                entry.get("url", ""),
                entry.get("notes", ""),
                " ".join(entry.get("tags", [])),
            ]).lower()
            if query_lower in searchable:
                results.append(entry)
        return results

    def get_audit_log(self, limit: int = 100) -> list[dict]:
        """Retrieve audit log entries."""
        db, _ = self._ensure_unlocked()
        return db.get_audit_log(limit)

    def get_trusted_devices(self) -> list[dict]:
        """Retrieve paired 2FA devices."""
        db, _ = self._ensure_unlocked()
        return db.get_trusted_devices()

    def add_trusted_device(self, device_id: str, device_name: str, public_key: bytes) -> None:
        """Register a paired 2FA device."""
        db, _ = self._ensure_unlocked()
        db.add_trusted_device(device_id, device_name, public_key)

    def remove_trusted_device(self, device_id: str) -> bool:
        """Remove a paired 2FA device."""
        db, _ = self._ensure_unlocked()
        return db.remove_trusted_device(device_id)

    # ── KDF Params Sidecar ─────────────────────────────────────────────

    def _kdf_params_path(self, vault_path: str) -> str:
        """Path for the KDF params sidecar file (unencrypted JSON)."""
        return vault_path + ".kdf"

    def _save_kdf_params(self, vault_path: str, params: KDFParams) -> None:
        """Save KDF params to a sidecar file."""
        sidecar = self._kdf_params_path(vault_path)
        with open(sidecar, "w") as f:
            json.dump(params.to_dict(), f, indent=2)

    def _load_kdf_params(self, vault_path: str) -> KDFParams:
        """Load KDF params from the sidecar file."""
        sidecar = self._kdf_params_path(vault_path)
        if not os.path.exists(sidecar):
            raise VaultError(
                f"KDF parameters file not found: {sidecar}\n"
                f"Cannot unlock vault without this file. It should be alongside the vault file."
            )
        with open(sidecar, "r") as f:
            return KDFParams.from_dict(json.load(f))

    # ── File Permissions ───────────────────────────────────────────────

    @staticmethod
    def _restrict_file_permissions(path: str) -> None:
        """Restrict file access to the current OS user only.

        On Windows, uses icacls. On Unix, uses chmod 600.
        """
        import platform
        if platform.system() == "Windows":
            try:
                import subprocess
                # Remove inherited permissions, grant only current user full control
                username = os.environ.get("USERNAME", "")
                if username:
                    subprocess.run(
                        ["icacls", path, "/inheritance:r",
                         "/grant:r", f"{username}:(F)"],
                        capture_output=True, timeout=10
                    )
            except Exception:
                pass  # Best effort — don't fail vault creation over permissions
        else:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
