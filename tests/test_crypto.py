import pytest
import os
from src.core.crypto import encrypt, decrypt, generate_key, CryptoError, KEY_SIZE, NONCE_SIZE, TAG_SIZE

def test_encrypt_decrypt_roundtrip():
    key = generate_key()
    plaintext = b"hello world"
    ciphertext = encrypt(plaintext, key)
    decrypted = decrypt(ciphertext, key)
    assert decrypted == plaintext

def test_encrypt_decrypt_with_aad():
    key = generate_key()
    plaintext = b"hello world"
    aad = b"header_data"
    ciphertext = encrypt(plaintext, key, aad=aad)
    decrypted = decrypt(ciphertext, key, aad=aad)
    assert decrypted == plaintext

def test_encrypt_unique_nonces():
    key = generate_key()
    plaintext = b"same data"
    ciphertext1 = encrypt(plaintext, key)
    ciphertext2 = encrypt(plaintext, key)
    assert ciphertext1 != ciphertext2
    assert decrypt(ciphertext1, key) == plaintext
    assert decrypt(ciphertext2, key) == plaintext

def test_decrypt_wrong_key():
    key1 = generate_key()
    key2 = generate_key()
    plaintext = b"data"
    ciphertext = encrypt(plaintext, key1)
    with pytest.raises(CryptoError):
        decrypt(ciphertext, key2)

def test_decrypt_tampered_data():
    key = generate_key()
    plaintext = b"sensitive info"
    ciphertext = bytearray(encrypt(plaintext, key))
    # Flip a bit in the ciphertext
    ciphertext[-1] ^= 1
    with pytest.raises(CryptoError):
        decrypt(bytes(ciphertext), key)

def test_decrypt_wrong_aad():
    key = generate_key()
    plaintext = b"data"
    ciphertext = encrypt(plaintext, key, aad=b"a")
    with pytest.raises(CryptoError):
        decrypt(ciphertext, key, aad=b"b")

def test_encrypt_empty_plaintext():
    key = generate_key()
    plaintext = b""
    ciphertext = encrypt(plaintext, key)
    decrypted = decrypt(ciphertext, key)
    assert decrypted == plaintext

def test_encrypt_large_payload():
    key = generate_key()
    plaintext = os.urandom(1024 * 1024)  # 1MB
    ciphertext = encrypt(plaintext, key)
    decrypted = decrypt(ciphertext, key)
    assert decrypted == plaintext

def test_key_size_validation():
    key = os.urandom(16)  # wrong size
    with pytest.raises(CryptoError):
        encrypt(b"data", key)
    with pytest.raises(CryptoError):
        decrypt(b"data" * 10, key)

def test_blob_too_short():
    key = generate_key()
    # NONCE_SIZE + TAG_SIZE = 40. Need at least this length.
    short_blob = os.urandom(39)
    with pytest.raises(CryptoError):
        decrypt(short_blob, key)

def test_generate_key():
    key = generate_key()
    assert isinstance(key, bytearray)
    assert len(key) == KEY_SIZE
