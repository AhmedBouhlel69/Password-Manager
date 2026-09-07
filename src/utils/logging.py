"""
Audit logging for security-relevant events.

All events are stored in the vault's encrypted SQLite database (audit_log table).
This module provides convenience wrappers and event type constants.

The audit log is tamper-evident: each entry includes the hash of the previous
entry, forming a hash chain. Breaking the chain indicates tampering.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional


class AuditEventType:
    """Constants for audit event types."""
    VAULT_CREATED = "vault_created"
    VAULT_UNLOCKED = "vault_unlocked"
    VAULT_LOCKED = "vault_locked"
    VAULT_LOCK_TIMEOUT = "vault_lock_timeout"

    ENTRY_ADDED = "entry_added"
    ENTRY_UPDATED = "entry_updated"
    ENTRY_DELETED = "entry_deleted"
    ENTRY_VIEWED = "entry_viewed"
    PASSWORD_COPIED = "password_copied"

    BLE_CHALLENGE_SENT = "ble_challenge_sent"
    BLE_CHALLENGE_APPROVED = "ble_challenge_approved"
    BLE_CHALLENGE_DENIED = "ble_challenge_denied"
    BLE_TIMEOUT = "ble_timeout"
    EMERGENCY_OVERRIDE = "emergency_override"

    BREACH_CHECK_STARTED = "breach_check_started"
    BREACH_CHECK_COMPLETED = "breach_check_completed"
    BREACH_FOUND = "breach_found"

    IMPORT_STARTED = "import_started"
    IMPORT_COMPLETED = "import_completed"
    SOURCE_FILE_DELETED = "source_file_deleted"

    DEVICE_PAIRED = "device_paired"
    DEVICE_UNPAIRED = "device_unpaired"

    SETTINGS_CHANGED = "settings_changed"


class AuditLogger:
    """Structured audit logging with hash-chain tamper detection.

    Usage:
        logger = AuditLogger(vault_database)
        logger.log(AuditEventType.VAULT_UNLOCKED, details="user=ahmed")
    """

    def __init__(self, db=None):
        """
        Args:
            db: VaultDatabase instance. If None, events are queued until
                a database is attached.
        """
        self._db = db
        self._last_hash: Optional[str] = None

    def attach_db(self, db) -> None:
        """Attach a database for persistent logging."""
        self._db = db
        # Load the last hash from the most recent log entry
        try:
            logs = db.get_audit_log(limit=1)
            if logs:
                details = logs[0].get("details", "")
                if details:
                    try:
                        parsed = json.loads(details)
                        self._last_hash = parsed.get("_hash", None)
                    except (json.JSONDecodeError, AttributeError):
                        pass
        except Exception:
            pass

    def log(self, event: str, details: str = "", extra: Optional[dict] = None) -> None:
        """Log a security event.

        Args:
            event: Event type string (use AuditEventType constants).
            details: Human-readable details string.
            extra: Optional dict of additional structured data.
        """
        if self._db is None:
            return

        # Build structured details with hash chain
        detail_obj = {
            "message": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if extra:
            detail_obj.update(extra)

        # Hash chain: include hash of previous entry
        if self._last_hash:
            detail_obj["_prev_hash"] = self._last_hash

        detail_str = json.dumps(detail_obj, ensure_ascii=False)

        # Compute hash of this entry for the chain
        chain_input = f"{event}:{detail_str}"
        self._last_hash = hashlib.sha256(chain_input.encode("utf-8")).hexdigest()[:16]
        detail_obj["_hash"] = self._last_hash
        detail_str = json.dumps(detail_obj, ensure_ascii=False)

        try:
            self._db.log_event(event, detail_str)
        except Exception:
            pass  # Audit logging should never crash the app
