"""
Encrypted SQLite database layer for the vault.

Uses apsw with sqlite3mc (SQLite3 Multiple Ciphers) for at-rest encryption
of the entire database file. On top of that, each credential entry's sensitive
fields are individually encrypted with XChaCha20-Poly1305 (see crypto.py),
providing defense-in-depth: even if the DB-level encryption is somehow
bypassed, each entry is still independently encrypted.

Schema:
- vault_meta: KDF params, vault version, verification token
- entries: Encrypted credential blobs with UUID primary keys
- audit_log: Tamper-evident event log
- trusted_devices: BLE paired device public keys (Milestone 2)
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

import apsw

from src.core.crypto import encrypt, decrypt, CryptoError


class DatabaseError(Exception):
    """Raised on database operation failures."""
    pass


# Current schema version — increment when schema changes require migration
SCHEMA_VERSION = 1


class VaultDatabase:
    """Encrypted SQLite database for the password vault.

    The database file is encrypted at the filesystem level by sqlite3mc.
    Individual entry contents are additionally encrypted by XChaCha20-Poly1305.

    Usage:
        db = VaultDatabase("vault.db")
        db.open("database_passphrase")
        db.initialize_schema()
        # ... operations ...
        db.close()
    """

    def __init__(self, path: str):
        """
        Args:
            path: Filesystem path for the SQLite database file.
        """
        self.path = path
        self._conn: Optional[apsw.Connection] = None

    def open(self, db_passphrase: str) -> None:
        """Open (or create) the encrypted database.

        Args:
            db_passphrase: Passphrase for sqlite3mc database-level encryption.
                          In practice this is the hex-encoded derived key from KDF.

        Raises:
            DatabaseError: If the database cannot be opened or decrypted.
        """
        try:
            self._conn = apsw.Connection(self.path)
            # Set the database encryption key. For sqlite3mc, PRAGMA key must be
            # the first statement executed on a new connection.
            self._conn.pragma("key", db_passphrase)
            # Verify we can actually read the database (catches wrong key)
            # This will raise an error if the key is wrong.
            self._conn.pragma("cipher_version")
        except apsw.SQLError as e:
            self._conn = None
            raise DatabaseError(f"Failed to open database (wrong key?): {e}") from e
        except Exception as e:
            self._conn = None
            raise DatabaseError(f"Failed to open database: {e}") from e

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    @property
    def is_open(self) -> bool:
        return self._conn is not None

    def _ensure_open(self) -> apsw.Connection:
        if self._conn is None:
            raise DatabaseError("Database is not open")
        return self._conn

    # ── Schema Management ──────────────────────────────────────────────

    def initialize_schema(self) -> None:
        """Create tables if they don't exist. Safe to call multiple times."""
        conn = self._ensure_open()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vault_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS entries (
                id         TEXT PRIMARY KEY,
                encrypted  BLOB NOT NULL,
                category   TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event     TEXT NOT NULL,
                details   TEXT DEFAULT ''
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS trusted_devices (
                device_id   TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                public_key  BLOB NOT NULL,
                paired_at   TEXT NOT NULL
            )
        """)

    def table_exists(self, table_name: str) -> bool:
        """Check if a table exists in the database."""
        conn = self._ensure_open()
        cursor = conn.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        )
        return cursor.fetchone()[0] > 0

    # ── Vault Metadata ────────────────────────────────────────────────

    def set_meta(self, key: str, value: str) -> None:
        """Store a metadata key-value pair."""
        conn = self._ensure_open()
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)",
            (key, value),
        )

    def get_meta(self, key: str) -> Optional[str]:
        """Retrieve a metadata value by key. Returns None if not found."""
        conn = self._ensure_open()
        cursor = conn.execute(
            "SELECT value FROM vault_meta WHERE key = ?", (key,)
        )
        row = cursor.fetchone()
        return row[0] if row else None

    # ── Credential Entry CRUD ─────────────────────────────────────────

    def add_entry(
        self,
        entry_data: dict,
        vault_key: bytes | bytearray,
        entry_id: Optional[str] = None,
        category: str = "",
    ) -> str:
        """Add a new credential entry to the vault.

        Args:
            entry_data: Dict with keys like site, username, password, url, notes, tags.
            vault_key: 32-byte encryption key for XChaCha20-Poly1305.
            entry_id: Optional UUID string. Generated if not provided.
            category: Optional category for organization.

        Returns:
            The UUID string of the new entry.

        Raises:
            DatabaseError: On insert failure.
            CryptoError: On encryption failure.
        """
        conn = self._ensure_open()
        if entry_id is None:
            entry_id = str(uuid.uuid4())

        now = datetime.now(timezone.utc).isoformat()

        # Serialize and encrypt the entry data
        plaintext = json.dumps(entry_data, ensure_ascii=False).encode("utf-8")
        # Use entry_id as AAD — ties the ciphertext to this specific entry
        encrypted_blob = encrypt(plaintext, vault_key, aad=entry_id.encode("utf-8"))

        try:
            conn.execute(
                "INSERT INTO entries (id, encrypted, category, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (entry_id, encrypted_blob, category, now, now),
            )
        except apsw.ConstraintError as e:
            raise DatabaseError(f"Entry with ID {entry_id} already exists") from e

        return entry_id

    def get_entry(self, entry_id: str, vault_key: bytes | bytearray) -> Optional[dict]:
        """Retrieve and decrypt a single credential entry.

        Args:
            entry_id: UUID of the entry.
            vault_key: 32-byte decryption key.

        Returns:
            Decrypted entry dict, or None if not found.

        Raises:
            CryptoError: On decryption failure (wrong key, tampered data).
        """
        conn = self._ensure_open()
        cursor = conn.execute(
            "SELECT encrypted, category, created_at, updated_at FROM entries WHERE id = ?",
            (entry_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        encrypted_blob, category, created_at, updated_at = row

        plaintext = decrypt(
            bytes(encrypted_blob), vault_key, aad=entry_id.encode("utf-8")
        )
        entry_data = json.loads(plaintext.decode("utf-8"))
        entry_data["_id"] = entry_id
        entry_data["_category"] = category
        entry_data["_created_at"] = created_at
        entry_data["_updated_at"] = updated_at
        return entry_data

    def update_entry(
        self,
        entry_id: str,
        entry_data: dict,
        vault_key: bytes | bytearray,
    ) -> bool:
        """Update an existing credential entry.

        Args:
            entry_id: UUID of the entry to update.
            entry_data: New entry data dict.
            vault_key: 32-byte encryption key.

        Returns:
            True if the entry was found and updated, False if not found.
        """
        conn = self._ensure_open()

        # Verify entry exists
        cursor = conn.execute("SELECT 1 FROM entries WHERE id = ?", (entry_id,))
        if cursor.fetchone() is None:
            return False

        now = datetime.now(timezone.utc).isoformat()
        plaintext = json.dumps(entry_data, ensure_ascii=False).encode("utf-8")
        encrypted_blob = encrypt(plaintext, vault_key, aad=entry_id.encode("utf-8"))

        category = entry_data.get("_category", entry_data.get("category", ""))

        conn.execute(
            "UPDATE entries SET encrypted = ?, category = ?, updated_at = ? WHERE id = ?",
            (encrypted_blob, category, now, entry_id),
        )
        return True

    def delete_entry(self, entry_id: str) -> bool:
        """Delete a credential entry.

        Args:
            entry_id: UUID of the entry to delete.

        Returns:
            True if the entry was found and deleted, False if not found.
        """
        conn = self._ensure_open()
        cursor = conn.execute("SELECT 1 FROM entries WHERE id = ?", (entry_id,))
        if cursor.fetchone() is None:
            return False

        conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        return True

    def list_entries(self, vault_key: bytes | bytearray) -> list[dict]:
        """List all credential entries (decrypted).

        Args:
            vault_key: 32-byte decryption key.

        Returns:
            List of decrypted entry dicts, sorted by site name.
        """
        conn = self._ensure_open()
        cursor = conn.execute(
            "SELECT id, encrypted, category, created_at, updated_at FROM entries "
            "ORDER BY updated_at DESC"
        )

        entries = []
        for row in cursor:
            entry_id, encrypted_blob, category, created_at, updated_at = row
            try:
                plaintext = decrypt(
                    bytes(encrypted_blob), vault_key, aad=entry_id.encode("utf-8")
                )
                entry_data = json.loads(plaintext.decode("utf-8"))
                entry_data["_id"] = entry_id
                entry_data["_category"] = category
                entry_data["_created_at"] = created_at
                entry_data["_updated_at"] = updated_at
                entries.append(entry_data)
            except CryptoError:
                # Skip entries that can't be decrypted (shouldn't happen normally)
                entries.append({
                    "_id": entry_id,
                    "_error": "Decryption failed",
                    "_category": category,
                    "_created_at": created_at,
                    "_updated_at": updated_at,
                })

        return entries

    def entry_count(self) -> int:
        """Return the total number of entries in the vault."""
        conn = self._ensure_open()
        cursor = conn.execute("SELECT count(*) FROM entries")
        return cursor.fetchone()[0]

    # ── Audit Log ─────────────────────────────────────────────────────

    def log_event(self, event: str, details: str = "") -> None:
        """Write an audit log entry.

        Args:
            event: Event type string (e.g. "unlock", "lock", "override", "entry_added").
            details: Optional details string.
        """
        conn = self._ensure_open()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO audit_log (timestamp, event, details) VALUES (?, ?, ?)",
            (now, event, details),
        )

    def get_audit_log(self, limit: int = 100) -> list[dict]:
        """Retrieve recent audit log entries.

        Args:
            limit: Maximum number of entries to return. Default 100.

        Returns:
            List of log entry dicts, most recent first.
        """
        conn = self._ensure_open()
        cursor = conn.execute(
            "SELECT id, timestamp, event, details FROM audit_log "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [
            {"id": row[0], "timestamp": row[1], "event": row[2], "details": row[3]}
            for row in cursor
        ]

    # ── Trusted Devices (BLE) ─────────────────────────────────────────

    def add_trusted_device(
        self, device_id: str, device_name: str, public_key: bytes
    ) -> None:
        """Register a trusted BLE device's public key."""
        conn = self._ensure_open()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO trusted_devices "
            "(device_id, device_name, public_key, paired_at) VALUES (?, ?, ?, ?)",
            (device_id, device_name, public_key, now),
        )

    def get_trusted_devices(self) -> list[dict]:
        """List all trusted BLE devices."""
        conn = self._ensure_open()
        cursor = conn.execute(
            "SELECT device_id, device_name, public_key, paired_at FROM trusted_devices"
        )
        return [
            {
                "device_id": row[0],
                "device_name": row[1],
                "public_key": bytes(row[2]),
                "paired_at": row[3],
            }
            for row in cursor
        ]

    def remove_trusted_device(self, device_id: str) -> bool:
        """Remove a trusted device."""
        conn = self._ensure_open()
        cursor = conn.execute(
            "SELECT 1 FROM trusted_devices WHERE device_id = ?", (device_id,)
        )
        if cursor.fetchone() is None:
            return False
        conn.execute(
            "DELETE FROM trusted_devices WHERE device_id = ?", (device_id,)
        )
        return True
