import os
import pytest
from src.core.database import VaultDatabase
from src.ble.protocol import (
    generate_challenge_nonce,
    create_challenge_payload,
    parse_challenge_response,
    verify_ecdsa_p256_signature
)
from src.ble.pairing import generate_pairing_code, PairingManager, EmergencyOverrideHandler
from src.utils.biometric import is_biometric_supported, verify_user_biometric


def test_challenge_nonce_generation():
    n1 = generate_challenge_nonce(32)
    n2 = generate_challenge_nonce(32)
    assert len(n1) == 32
    assert len(n2) == 32
    assert n1 != n2


def test_challenge_payload_roundtrip():
    nonce = b"\x01" * 32
    payload = create_challenge_payload("Personal Vault", nonce)
    assert b"Personal Vault" in payload
    assert nonce.hex().encode('utf-8') in payload


def test_parse_challenge_response():
    sample_response = b'{"status": "approved", "device_id": "iPhone-123", "signature": "aabbcc"}'
    parsed = parse_challenge_response(sample_response)
    assert parsed["status"] == "approved"
    assert parsed["device_id"] == "iPhone-123"
    assert parsed["signature"] == bytes.fromhex("aabbcc")


def test_ecdsa_signature_verification():
    # If cryptography is installed, test full ECDSA P-256 signing and verification
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        # Generate test keypair
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        pub_bytes = public_key.public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.UncompressedPoint
        )

        nonce = os.urandom(32)
        signature = private_key.sign(nonce, ec.ECDSA(hashes.SHA256()))

        # Valid signature should verify
        assert verify_ecdsa_p256_signature(pub_bytes, nonce, signature) is True

        # Tampered nonce should fail verification
        tampered_nonce = os.urandom(32)
        assert verify_ecdsa_p256_signature(pub_bytes, tampered_nonce, signature) is False
    except ImportError:
        pytest.skip("cryptography library not yet installed in environment")


def test_pairing_manager(tmp_path):
    db_path = str(tmp_path / "test_pairing.db")
    db = VaultDatabase(db_path)
    db.open("test_key")
    db.initialize_schema()

    manager = PairingManager(db)
    code = manager.start_pairing(timeout_seconds=60.0)
    assert len(code) == 6
    assert code.isdigit()

    # Wrong code
    assert manager.verify_pairing_code("000000" if code != "000000" else "111111") is False

    # Right code
    code2 = manager.start_pairing(timeout_seconds=60.0)
    assert manager.verify_pairing_code(code2) is True

    # Register device
    manager.register_device("device-1", "Ahmed's iPhone", b"fake_pub_key")
    devices = manager.list_devices()
    assert len(devices) == 1
    assert devices[0]["device_name"] == "Ahmed's iPhone"

    # Unpair
    assert manager.unpair_device("device-1") is True
    assert len(manager.list_devices()) == 0

    db.close()


def test_emergency_override(tmp_path):
    db_path = str(tmp_path / "test_override.db")
    db = VaultDatabase(db_path)
    db.open("test_key")
    db.initialize_schema()

    # Use 0 second delay in tests to avoid test lag
    handler = EmergencyOverrideHandler(db, delay_seconds=0.0)
    handler.execute_override()

    logs = db.get_audit_log(limit=5)
    assert any(log["event"] == "emergency_override" for log in logs)

    db.close()


def test_biometric_check():
    supported = is_biometric_supported()
    assert isinstance(supported, bool)
    success, msg = verify_user_biometric("Test unlock")
    assert isinstance(success, bool)


def test_vault_trusted_devices_and_2fa_lock(tmp_path):
    from src.core.vault import Vault, VaultState

    vault_path = str(tmp_path / "test_2fa_vault.vault")
    vault = Vault()
    vault.create_vault(vault_path, "TestMasterPassword123!")

    # Initially empty
    devices = vault.get_trusted_devices()
    assert len(devices) == 0

    # Add trusted iPhone
    vault.add_trusted_device("iphone-test-id", "Ahmed's iPhone 15 Pro", b"\x04" + b"A" * 64)
    devices = vault.get_trusted_devices()
    assert len(devices) == 1
    assert devices[0]["device_name"] == "Ahmed's iPhone 15 Pro"
    assert devices[0]["device_id"] == "iphone-test-id"

    # Close and unlock
    vault.close()
    assert vault.state == VaultState.CLOSED

    # Unlock with password
    assert vault.unlock(vault_path, "TestMasterPassword123!") is True
    assert vault.state == VaultState.UNLOCKED

    # Verified devices are present after unlock
    devices_after = vault.get_trusted_devices()
    assert len(devices_after) == 1

    # Simulate 2FA failure / reject -> vault locks immediately
    vault.lock()
    assert vault.state == VaultState.LOCKED
    assert vault.is_unlocked is False

    # Unlock again and remove device
    vault.unlock(vault_path, "TestMasterPassword123!")
    assert vault.remove_trusted_device("iphone-test-id") is True
    assert len(vault.get_trusted_devices()) == 0

    vault.close()
