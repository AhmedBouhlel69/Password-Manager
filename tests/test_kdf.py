import pytest
import os
from src.core.kdf import derive_key, generate_salt, KDFParams

def test_derive_key_deterministic():
    password = "super_secure_password"
    salt = b"1234567890123456"
    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)
    assert key1 == key2

def test_derive_key_different_passwords():
    salt = b"1234567890123456"
    key1 = derive_key("pass1", salt)
    key2 = derive_key("pass2", salt)
    assert key1 != key2

def test_derive_key_different_salts():
    password = "super_secure_password"
    key1 = derive_key(password, b"1234567890123456")
    key2 = derive_key(password, b"6543210987654321")
    assert key1 != key2

def test_derive_key_returns_bytearray():
    password = "test"
    salt = b"salt" * 4
    key = derive_key(password, salt)
    assert isinstance(key, bytearray)

def test_derive_key_correct_length():
    password = "test"
    salt = b"salt" * 4
    key = derive_key(password, salt)
    assert len(key) == 32

def test_generate_salt_length():
    salt = generate_salt()
    assert len(salt) == 16

def test_generate_salt_unique():
    salt1 = generate_salt()
    salt2 = generate_salt()
    assert salt1 != salt2

def test_kdf_params_roundtrip():
    salt = generate_salt()
    params = KDFParams(salt=salt, time_cost=5, memory_cost=10240, parallelism=8, hash_len=32)
    data = params.to_dict()
    params2 = KDFParams.from_dict(data)
    assert params.time_cost == params2.time_cost
    assert params.memory_cost == params2.memory_cost
    assert params.parallelism == params2.parallelism
    assert params.hash_len == params2.hash_len
    assert params.salt == params2.salt

