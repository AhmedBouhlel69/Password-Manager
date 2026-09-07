"""
Argon2id Key Derivation for vault master key.

Uses argon2-cffi's low-level API to derive a raw 256-bit encryption key
from the master password. The high-level PasswordHasher API is designed for
password *verification* (produces encoded strings); we need raw bytes for
use as an encryption key, hence hash_secret_raw.

Security notes:
- Salt is generated once at vault creation and stored in the vault file header.
  Salts are not secret — their purpose is to prevent precomputation attacks.
- The derived key is NEVER written to disk. It is held in a mutable bytearray
  for the duration of the session and explicitly wiped on lock.
- Params are tuned so derivation takes ~0.5–1s on modern hardware.
"""

import os
from argon2.low_level import hash_secret_raw, Type

# Default Argon2id parameters — tune based on target hardware.
# 64 MiB memory, 3 iterations, 4 parallel lanes → ~0.5–1s on a modern laptop.
DEFAULT_MEMORY_COST = 65536  # KiB (64 MiB)
DEFAULT_TIME_COST = 3        # iterations
DEFAULT_PARALLELISM = 4      # parallel threads/lanes
DEFAULT_HASH_LEN = 32        # 256-bit output key
DEFAULT_SALT_LEN = 16        # 128-bit salt


def generate_salt(length: int = DEFAULT_SALT_LEN) -> bytes:
    """Generate a cryptographically secure random salt.

    Args:
        length: Salt length in bytes. Default 16 (128 bits).

    Returns:
        Random bytes suitable for use as a KDF salt.
    """
    return os.urandom(length)


def derive_key(
    password: str,
    salt: bytes,
    memory_cost: int = DEFAULT_MEMORY_COST,
    time_cost: int = DEFAULT_TIME_COST,
    parallelism: int = DEFAULT_PARALLELISM,
    hash_len: int = DEFAULT_HASH_LEN,
) -> bytearray:
    """Derive a raw encryption key from a master password using Argon2id.

    The returned key is a mutable bytearray so it can be explicitly zeroed
    when no longer needed (see secure_memory.wipe).

    Args:
        password: The master password (will be UTF-8 encoded).
        salt: Random salt bytes (from generate_salt or stored in vault header).
        memory_cost: Memory usage in KiB. Default 65536 (64 MiB).
        time_cost: Number of iterations. Default 3.
        parallelism: Degree of parallelism. Default 4.
        hash_len: Output key length in bytes. Default 32 (256 bits).

    Returns:
        A mutable bytearray containing the derived key.

    Raises:
        argon2.exceptions.HashingError: If hashing fails (e.g. invalid params).
    """
    raw_key = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID,  # Argon2id — combines side-channel resistance (i) + GPU resistance (d)
    )
    # Return as mutable bytearray so the caller can zero it when done.
    return bytearray(raw_key)


# KDF parameter set — stored in vault metadata so we can evolve params over time
# without breaking existing vaults.
class KDFParams:
    """Immutable record of KDF parameters stored in the vault header."""

    __slots__ = ("memory_cost", "time_cost", "parallelism", "hash_len", "salt")

    def __init__(
        self,
        salt: bytes,
        memory_cost: int = DEFAULT_MEMORY_COST,
        time_cost: int = DEFAULT_TIME_COST,
        parallelism: int = DEFAULT_PARALLELISM,
        hash_len: int = DEFAULT_HASH_LEN,
    ):
        self.salt = salt
        self.memory_cost = memory_cost
        self.time_cost = time_cost
        self.parallelism = parallelism
        self.hash_len = hash_len

    def to_dict(self) -> dict:
        """Serialize to a dict for storage in vault metadata."""
        return {
            "salt": self.salt.hex(),
            "memory_cost": self.memory_cost,
            "time_cost": self.time_cost,
            "parallelism": self.parallelism,
            "hash_len": self.hash_len,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KDFParams":
        """Deserialize from a dict stored in vault metadata."""
        return cls(
            salt=bytes.fromhex(d["salt"]),
            memory_cost=d["memory_cost"],
            time_cost=d["time_cost"],
            parallelism=d["parallelism"],
            hash_len=d["hash_len"],
        )
