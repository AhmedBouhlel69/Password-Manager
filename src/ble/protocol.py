"""
BLE 2FA Challenge-Response Protocol Specification.

Defines GATT Service & Characteristic UUIDs, challenge formatting, and
cryptographic signature verification for the paired iPhone companion.

Apple Secure Enclave generates an ECDSA keypair using NIST P-256 (secp256r1).
During unlock:
1. Desktop generates a random 32-byte challenge nonce.
2. Desktop sends ChallengePayload (JSON: version, nonce_hex, vault_name, timestamp)
   to the CHALLENGE_CHAR_UUID characteristic.
3. iPhone prompts the user (Approve / Deny) with vault name.
4. On Approve, iPhone signs the 32-byte nonce using the Secure Enclave private key.
5. iPhone writes the signature back via RESPONSE_CHAR_UUID.
6. Desktop verifies the signature against the stored public key.
"""

import json
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional

# Custom 128-bit UUIDs for Password Manager GATT Service
SERVICE_UUID = "d4870001-9a72-4d56-b0e1-7e8c054e0001"
CHALLENGE_CHAR_UUID = "d4870002-9a72-4d56-b0e1-7e8c054e0001"  # Write (Desktop -> Phone)
RESPONSE_CHAR_UUID = "d4870003-9a72-4d56-b0e1-7e8c054e0001"   # Notify / Read (Phone -> Desktop)
PAIRING_CHAR_UUID = "d4870004-9a72-4d56-b0e1-7e8c054e0001"    # Write / Notify (Pairing exchange)

CHALLENGE_TIMEOUT_SECONDS = 30.0
PROTOCOL_VERSION = 1


def generate_challenge_nonce(length: int = 32) -> bytes:
    """Generates a random cryptographic challenge nonce."""
    return secrets.token_bytes(length)


def create_challenge_payload(vault_name: str, nonce: bytes) -> bytes:
    """Creates JSON payload sent to the iPhone companion over BLE."""
    payload = {
        "version": PROTOCOL_VERSION,
        "vault_name": vault_name,
        "nonce": nonce.hex(),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    return json.dumps(payload, separators=(',', ':')).encode('utf-8')


def parse_challenge_response(raw_bytes: bytes) -> Dict[str, Any]:
    """Parses response packet received from the iPhone companion."""
    data = json.loads(raw_bytes.decode('utf-8'))
    return {
        "status": data.get("status"),  # "approved" or "denied"
        "device_id": data.get("device_id"),
        "signature": bytes.fromhex(data["signature"]) if "signature" in data and data["signature"] else b""
    }


def verify_ecdsa_p256_signature(
    public_key_bytes: bytes,
    challenge_nonce: bytes,
    signature_bytes: bytes
) -> bool:
    """
    Verifies ECDSA P-256 (secp256r1) signature from iPhone's Secure Enclave.
    Supports both X9.62 uncompressed point (65 bytes: 0x04 || X || Y) and SubjectPublicKeyInfo (DER/PEM),
    as well as both IEEE P1363 (64 bytes: r || s) and ASN.1/DER formatted signatures.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_public_key
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        # Fallback if cryptography library is not yet loaded
        return False

    if not public_key_bytes or not signature_bytes or not challenge_nonce:
        return False

    # 1. Parse Public Key
    pub_key = None
    try:
        if public_key_bytes.startswith(b"-----BEGIN"):
            pub_key = load_pem_public_key(public_key_bytes)
        elif len(public_key_bytes) == 65 and public_key_bytes[0] == 0x04:
            # Raw uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes)
            curve = ec.SECP256R1()
            pub_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, public_key_bytes)
        else:
            pub_key = load_der_public_key(public_key_bytes)
    except Exception:
        return False

    # 2. Verify signature
    # If 64 bytes, signature is in IEEE P1363 format (r || s)
    if len(signature_bytes) == 64:
        # Convert IEEE P1363 to DER
        try:
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            r = int.from_bytes(signature_bytes[:32], 'big')
            s = int.from_bytes(signature_bytes[32:], 'big')
            der_signature = encode_dss_signature(r, s)
        except Exception:
            return False
    else:
        der_signature = signature_bytes

    try:
        pub_key.verify(der_signature, challenge_nonce, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
