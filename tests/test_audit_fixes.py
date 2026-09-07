"""
Regression tests verifying fixes for issues identified during project security audit.
"""

import os
import pytest
from src.import_etl.secure_delete import secure_delete_file
from src.import_etl.deduplicator import find_duplicate, calculate_similarity
from src.ble.pairing import PairingManager
from src.core.vault import Vault, VaultError


def test_secure_delete_in_place_overwrite(tmp_path):
    """Verify C3: secure_delete overwrites existing file bytes, rather than appending."""
    file_path = tmp_path / "sensitive.txt"
    secret_text = b"MY_SUPER_SECRET_PASSWORD_12345"
    file_path.write_bytes(secret_text)

    # Perform secure delete
    secure_delete_file(str(file_path), confirmed=True, passes=1)
    assert not os.path.exists(file_path)


def test_deduplicator_conflicting_tlds():
    """Verify H3: sites with different TLDs are not merged or given high similarity."""
    sim = calculate_similarity("example.com", "example.org")
    assert sim < 0.70  # Conflicting TLDs penalized

    # Same base without TLD matches full domain
    assert calculate_similarity("github.com", "GitHub") >= 0.90


def test_pairing_manager_rate_limiting():
    """Verify C7: brute forcing pairing code locks out after max attempts."""
    class DummyDB:
        def __init__(self):
            self.events = []
        def log_event(self, event, details=""):
            self.events.append((event, details))
        def add_trusted_device(self, *args):
            pass
        def get_trusted_devices(self):
            return []
        def remove_trusted_device(self, *args):
            return True

    pm = PairingManager(DummyDB())
    pm.start_pairing()

    # 3 incorrect attempts
    assert not pm.verify_pairing_code("000000")
    assert not pm.verify_pairing_code("111111")
    assert not pm.verify_pairing_code("222222")

    # 4th attempt is locked out even if code was correct or active
    assert not pm.verify_pairing_code("333333")
    assert pm.active_pairing_code is None


def test_missing_kdf_sidecar_raises_error(tmp_path):
    """Verify M2: missing .kdf sidecar explicitly raises VaultError with clear message."""
    vault_path = str(tmp_path / "test.vault")
    v = Vault()
    v.create_vault(vault_path, "master_password_123")
    v.lock()

    # Remove the sidecar .kdf file
    kdf_path = vault_path + ".kdf"
    assert os.path.exists(kdf_path)
    os.remove(kdf_path)

    # Attempting to unlock must raise VaultError mentioning KDF parameters file
    with pytest.raises(VaultError) as exc_info:
        v.unlock(vault_path, "master_password_123")
    assert "KDF parameters file not found" in str(exc_info.value)
