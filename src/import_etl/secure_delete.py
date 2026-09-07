"""
Secure file deletion with multi-pass overwrite.

Performs a 3-pass overwrite (zeros, random bytes, zeros) before unlinking.
Includes explicit safety checks and warnings regarding modern SSD wear-leveling.
"""

import os
import secrets
from typing import Optional


class SecureDeleteError(Exception):
    pass


def secure_delete_file(file_path: str, confirmed: bool = False, passes: int = 3) -> None:
    """
    Securely overwrites and deletes a file.

    Args:
        file_path: Target path to shred.
        confirmed: Explicit confirmation flag. Must be True or raises ValueError.
        passes: Number of overwrite passes.

    Note on SSDs:
        Modern solid-state drives (SSDs) utilize wear-leveling algorithms in firmware.
        Writing to an existing block typically allocates a new block in the flash NAND,
        leaving remnants in the old cell until garbage collected/TRIMmed.
        Full disk encryption (BitLocker / LUKS / FileVault) is the true defense against
        hardware extraction on SSDs.
    """
    if not confirmed:
        raise ValueError("Cannot perform secure delete without explicit user confirmation.")

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Target file not found: {file_path}")

    file_size = os.path.getsize(file_path)

    if file_size > 0:
        with open(file_path, "r+b", buffering=0) as f:
            for p in range(passes):
                f.seek(0)
                if p % 2 == 0:
                    # Overwrite with zeros
                    f.write(b"\x00" * file_size)
                else:
                    # Overwrite with cryptographically secure random bytes
                    f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())

    # Finally truncate and delete
    with open(file_path, "w") as f:
        f.truncate(0)

    os.remove(file_path)
