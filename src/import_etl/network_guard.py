"""
Network Guard for Import ETL.

Enforces offline-only / localhost-only execution during the plaintext credential import step.
Monitors or intercepts socket connections; any attempt to contact non-loopback addresses
(i.e. anything other than 127.0.0.1, ::1, or localhost) immediately triggers SecurityError
and halts processing.
"""

import socket
from contextlib import contextmanager
from typing import Generator


class SecurityError(Exception):
    """Raised when an unauthorized outbound network request is detected during sensitive operations."""
    pass


ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


@contextmanager
def local_only_network_guard() -> Generator[None, None, None]:
    """
    Context manager that intercepts socket creation and connect calls.
    Allows connections ONLY to localhost (e.g., local Ollama instance on 127.0.0.1:11434).
    Any external connection attempt immediately raises SecurityError.
    """
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def guarded_connect(self, address):
        # address is usually (host, port)
        if isinstance(address, tuple) and len(address) >= 2:
            host = str(address[0]).lower()
            # Resolve hostname to IP to prevent DNS-based bypass (e.g. 127.evil.com)
            try:
                resolved_ip = socket.getaddrinfo(host, address[1], proto=socket.IPPROTO_TCP)[0][4][0]
            except socket.gaierror:
                resolved_ip = host
            is_local = (
                resolved_ip in ALLOWED_HOSTS
                or resolved_ip.startswith("127.")
                or resolved_ip == "::1"
            )
            if not is_local:
                raise SecurityError(
                    f"CRITICAL SECURITY VIOLATION: Outbound network request to '{host}' "
                    f"(resolved: {resolved_ip}:{address[1]}) blocked during plaintext credential import!"
                )
        return original_connect(self, address)

    def guarded_connect_ex(self, address):
        if isinstance(address, tuple) and len(address) >= 2:
            host = str(address[0]).lower()
            try:
                resolved_ip = socket.getaddrinfo(host, address[1], proto=socket.IPPROTO_TCP)[0][4][0]
            except socket.gaierror:
                resolved_ip = host
            is_local = (
                resolved_ip in ALLOWED_HOSTS
                or resolved_ip.startswith("127.")
                or resolved_ip == "::1"
            )
            if not is_local:
                raise SecurityError(
                    f"CRITICAL SECURITY VIOLATION: Outbound network connection attempt to '{host}' "
                    f"(resolved: {resolved_ip}:{address[1]}) blocked during plaintext credential import!"
                )
        return original_connect_ex(self, address)

    # Patch socket
    socket.socket.connect = guarded_connect
    socket.socket.connect_ex = guarded_connect_ex

    try:
        yield
    finally:
        # Restore original functions
        socket.socket.connect = original_connect
        socket.socket.connect_ex = original_connect_ex
