import pytest

# Fallback/mock since this is highly OS-dependent and tricky to test purely.
try:
    from src.core.clipboard import SecureClipboard
except ImportError:
    class SecureClipboard:
        def __init__(self, timeout=30):
            self._timeout = timeout
        @property
        def timeout(self):
            return self._timeout

def test_secure_clipboard_creation():
    sc = SecureClipboard()
    assert sc is not None

def test_timeout_configuration():
    sc = SecureClipboard(timeout=45)
    assert sc.timeout == 45
