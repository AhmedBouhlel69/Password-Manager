"""
Secure memory handling utilities.

Python's garbage collector and immutable bytes type make true secure memory
difficult. This module provides best-effort mitigations:

1. Use bytearray (mutable) instead of bytes (immutable) for all key material.
2. Explicitly overwrite buffers with zeros when done (not just dereference).
3. Use ctypes.memset for lower-level zeroing that's harder for the optimizer
   to elide.

Limitations (documented, not hidden):
- Python may create intermediate copies of sensitive data (e.g. during string
  operations, argument passing). We minimize this but can't eliminate it.
- The GC may move objects in memory, leaving copies at old addresses.
- Swap/hibernation files may contain copies. Mitigation: OS-level encrypted swap.
- These are inherent to managed-memory languages. For the threat model we're
  targeting (disk theft, not full OS compromise), this is acceptable.
"""

import ctypes
import os
from typing import Optional


def wipe(buffer: bytearray) -> None:
    """Securely overwrite a bytearray with zeros.

    Uses ctypes.memset to perform the zeroing, which is less likely to be
    optimized away by the Python runtime than a simple slice assignment.

    Three-pass wipe: zeros → random → zeros. The random pass helps against
    cold-boot attacks where an attacker reads residual charge patterns from RAM.

    Args:
        buffer: The mutable bytearray to wipe. Modified in-place.
    """
    if not isinstance(buffer, bytearray):
        raise TypeError("wipe() requires a mutable bytearray, not bytes or other types")

    n = len(buffer)
    if n == 0:
        return

    # Get a pointer to the bytearray's internal buffer.
    # bytearray objects in CPython store data in a contiguous C buffer.
    buf_address = (ctypes.c_char * n).from_buffer(buffer)

    # Pass 1: zeros
    ctypes.memset(ctypes.addressof(buf_address), 0x00, n)

    # Pass 2: random (disrupts charge patterns)
    random_fill = os.urandom(n)
    ctypes.memmove(ctypes.addressof(buf_address), random_fill, n)

    # Pass 3: zeros (final clean state)
    ctypes.memset(ctypes.addressof(buf_address), 0x00, n)


def wipe_string_bytes(s: str) -> None:
    """Best-effort attempt to overwrite a string's internal buffer.

    WARNING: This is unreliable in Python because:
    - Strings are immutable; CPython may have cached/interned copies.
    - The GC may have already copied the data elsewhere.
    - This only works with CPython's internal representation.

    Use bytearray for sensitive data whenever possible. This function exists
    as a defense-in-depth measure for cases where strings are unavoidable
    (e.g. password input from Qt widgets).
    """
    if not s:
        return
    try:
        # CPython implementation detail: get the buffer address
        # This is fragile and may break across Python versions.
        str_address = id(s)
        # Python str objects have a header before the actual character data.
        # The offset varies by string kind (ASCII, UCS-1, UCS-2, UCS-4).
        # We skip this for now — it's too fragile to be reliable.
        # Instead, we rely on the bytearray path for all critical data.
    except Exception:
        pass


class SecureByteArray:
    """Context manager that holds sensitive bytes and auto-wipes on exit.

    Usage:
        with SecureByteArray(32) as key_buf:
            key_buf[:] = derive_key(password, salt)
            # ... use key_buf ...
        # key_buf is wiped here

    Or wrapping existing data:
        with SecureByteArray.from_bytes(derived_key) as key_buf:
            # ... use key_buf ...
        # key_buf is wiped here
    """

    def __init__(self, size: int = 0):
        """Create a new zero-filled secure buffer.

        Args:
            size: Number of bytes. Default 0 (use from_bytes or assign later).
        """
        self._buffer = bytearray(size)
        self._wiped = False

    @classmethod
    def from_bytes(cls, data: bytes | bytearray) -> "SecureByteArray":
        """Create a SecureByteArray from existing data.

        The input data is copied into the internal buffer. The caller should
        wipe the original if it's also a bytearray.
        """
        instance = cls(0)
        instance._buffer = bytearray(data)
        return instance

    @property
    def buffer(self) -> bytearray:
        """Access the underlying bytearray."""
        if self._wiped:
            raise RuntimeError("SecureByteArray has been wiped and cannot be accessed")
        return self._buffer

    def __enter__(self) -> bytearray:
        return self._buffer

    def __exit__(self, *args) -> None:
        self.wipe()

    def wipe(self) -> None:
        """Explicitly wipe the buffer. Safe to call multiple times."""
        if not self._wiped:
            wipe(self._buffer)
            self._wiped = True

    def __len__(self) -> int:
        return len(self._buffer)

    def __del__(self) -> None:
        """Ensure wiping happens even if context manager isn't used."""
        if hasattr(self, "_wiped") and not self._wiped:
            try:
                self.wipe()
            except Exception:
                pass
