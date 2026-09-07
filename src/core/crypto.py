"""
XChaCha20-Poly1305 AEAD encryption for vault entries.

Uses PyNaCl (libsodium bindings) for XChaCha20-Poly1305, which provides:
- 256-bit key
- 24-byte (192-bit) nonce — large enough for safe random generation
  (collision probability negligible even after 2^64 encryptions)
- 16-byte (128-bit) Poly1305 authentication tag
- Authenticated Associated Data (AAD) support

Each vault entry is encrypted individually with a unique random nonce.
The wire format is: nonce (24 bytes) || ciphertext+tag (len(plaintext) + 16 bytes).

Why XChaCha20-Poly1305 over AES-256-GCM:
- XChaCha20 has a 24-byte nonce vs AES-GCM's 12-byte nonce. With random nonces
  (which we use for simplicity), AES-GCM has a birthday-bound collision risk
  after ~2^32 encryptions under the same key. XChaCha20's 24-byte nonce pushes
  that to ~2^96, which is effectively infinite for our use case.
- Both are well-audited AEAD constructions. Performance is comparable.

Security notes:
- Never reuse a nonce with the same key. We generate a fresh random nonce
  per encryption call, which is safe given the 24-byte nonce space.
- The key must be exactly 32 bytes (256 bits), as produced by kdf.derive_key.
- AAD (additional authenticated data) is authenticated but NOT encrypted.
  Use it for metadata that must be tamper-proof but can be public (e.g. entry ID).
"""

import os
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    crypto_aead_xchacha20poly1305_ietf_ABYTES,
)

# Constants
KEY_SIZE = crypto_aead_xchacha20poly1305_ietf_KEYBYTES    # 32 bytes
NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  # 24 bytes
TAG_SIZE = crypto_aead_xchacha20poly1305_ietf_ABYTES       # 16 bytes


class CryptoError(Exception):
    """Raised on encryption/decryption failures (wrong key, tampered data, etc.)."""
    pass


def encrypt(plaintext: bytes, key: bytes | bytearray, aad: bytes = b"") -> bytes:
    """Encrypt plaintext using XChaCha20-Poly1305 AEAD.

    Generates a unique random 24-byte nonce per call. The nonce is prepended
    to the ciphertext so it's available for decryption.

    Args:
        plaintext: Data to encrypt. Can be empty (produces auth tag only).
        key: 32-byte encryption key (from KDF).
        aad: Additional authenticated data. Authenticated but not encrypted.
             Must be provided identically at decryption time.

    Returns:
        Encrypted blob: nonce (24) || ciphertext + tag (len(plaintext) + 16).

    Raises:
        CryptoError: If key is wrong size or encryption fails.
    """
    if len(key) != KEY_SIZE:
        raise CryptoError(f"Key must be exactly {KEY_SIZE} bytes, got {len(key)}")

    nonce = os.urandom(NONCE_SIZE)

    try:
        # libsodium appends the 16-byte Poly1305 tag to the ciphertext
        ciphertext_with_tag = crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, aad, nonce, bytes(key)
        )
    except Exception as e:
        raise CryptoError(f"Encryption failed: {e}") from e

    # Wire format: nonce || ciphertext || tag
    return nonce + ciphertext_with_tag


def decrypt(blob: bytes, key: bytes | bytearray, aad: bytes = b"") -> bytes:
    """Decrypt a blob produced by encrypt().

    Args:
        blob: Encrypted blob (nonce || ciphertext || tag).
        key: 32-byte encryption key (same key used for encryption).
        aad: Additional authenticated data (must match what was used at encryption).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        CryptoError: If key is wrong, data is tampered, AAD doesn't match,
                     or blob is too short.
    """
    if len(key) != KEY_SIZE:
        raise CryptoError(f"Key must be exactly {KEY_SIZE} bytes, got {len(key)}")

    min_blob_size = NONCE_SIZE + TAG_SIZE  # At minimum: nonce + tag (empty plaintext)
    if len(blob) < min_blob_size:
        raise CryptoError(
            f"Encrypted blob too short: {len(blob)} bytes "
            f"(minimum {min_blob_size} for nonce + tag)"
        )

    nonce = blob[:NONCE_SIZE]
    ciphertext_with_tag = blob[NONCE_SIZE:]

    try:
        plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext_with_tag, aad, nonce, bytes(key)
        )
    except Exception as e:
        raise CryptoError(
            "Decryption failed — wrong key, corrupted data, or tampered ciphertext"
        ) from e

    return plaintext


def generate_key() -> bytearray:
    """Generate a random 256-bit encryption key.

    Useful for testing or for generating per-entry keys if needed.
    In production, use kdf.derive_key() to derive from master password.

    Returns:
        A mutable 32-byte bytearray containing the key.
    """
    return bytearray(os.urandom(KEY_SIZE))
