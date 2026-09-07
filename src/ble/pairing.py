"""
BLE Device Pairing & Emergency Override Management.

Handles:
1. One-time pairing between Desktop and iPhone companion.
2. 6-digit verification code generation.
3. Registration of paired device ECDSA public key in vault DB.
4. Emergency override logic (deliberate delay + audit logging).
"""

import secrets
import time
from typing import Optional, Dict, Any
from src.core.database import VaultDatabase


def generate_pairing_code() -> str:
    """Generates a secure 6-digit pairing code shown on desktop screen."""
    return f"{secrets.randbelow(1_000_000):06d}"


class PairingManager:
    """Manages pairing session and trusted devices."""

    def __init__(self, db: VaultDatabase):
        self.db = db
        self.active_pairing_code: Optional[str] = None
        self.active_pairing_expires_at: float = 0.0
        self._attempts = 0
        self._max_attempts = 3

    def start_pairing(self, timeout_seconds: float = 120.0) -> str:
        """Starts a pairing session and returns a 6-digit code."""
        code = generate_pairing_code()
        self.active_pairing_code = code
        self.active_pairing_expires_at = time.time() + timeout_seconds
        return code

    def verify_pairing_code(self, entered_code: str) -> bool:
        """Verifies code entered on the iPhone during pairing."""
        if not self.active_pairing_code:
            return False
        
        self._attempts += 1
        if self._attempts > self._max_attempts:
            self.active_pairing_code = None
            return False

        if time.time() > self.active_pairing_expires_at:
            self.active_pairing_code = None
            return False
        # Constant-time comparison
        is_valid = secrets.compare_digest(self.active_pairing_code, entered_code.strip())
        if is_valid:
            self.active_pairing_code = None
        return is_valid

    def register_device(self, device_id: str, device_name: str, public_key: bytes) -> None:
        """Registers paired iPhone into the encrypted vault DB."""
        self.db.add_trusted_device(device_id, device_name, public_key)
        self.db.log_event("device_paired", f"name={device_name}, id={device_id}")

    def list_devices(self) -> list:
        return self.db.get_trusted_devices()

    def unpair_device(self, device_id: str) -> bool:
        result = self.db.remove_trusted_device(device_id)
        if result:
            self.db.log_event("device_unpaired", f"id={device_id}")
        return result


class EmergencyOverrideHandler:
    """
    Handles emergency override when the phone is absent, lost, or out-of-range.
    Enforces a deliberate delay (10-15s) and writes an immutable audit log entry.
    """

    def __init__(self, db: VaultDatabase, delay_seconds: float = 10.0):
        self.db = db
        self.delay_seconds = delay_seconds

    def execute_override(self) -> None:
        """
        Applies mandatory security delay and logs the override event.
        """
        # Audit log event recorded in encrypted DB
        self.db.log_event(
            "emergency_override",
            f"Emergency 2FA bypass executed with deliberate delay of {self.delay_seconds}s"
        )
        # Deliberate time penalty
        if self.delay_seconds > 0:
            time.sleep(self.delay_seconds)
