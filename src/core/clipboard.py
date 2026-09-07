"""
Secure clipboard management with auto-clear and Win+V history suppression.

On Windows, uses Win32 ctypes to:
1. Suppress Windows Clipboard History (Win+V) via CanIncludeInClipboardHistory=0
2. Prevent Cloud Clipboard sync via CanUploadToCloudClipboard=0
3. Exclude from clipboard monitoring via ExcludeClipboardContentFromMonitorProcessing

On other platforms, uses QApplication.clipboard() as a fallback (without
the privacy flags, since those are Windows-specific).

Security features:
- Auto-clear after configurable timeout (default 30s)
- Only clears if clipboard still contains the copied password (doesn't
  destroy user's subsequent copies of unrelated data)
- Thread-safe timer management
- Cancels previous timer when a new password is copied
"""

import platform
import sys
import threading
import time
from typing import Optional

# Windows-specific imports (conditional)
IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32

    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002
    GMEM_ZEROINIT = 0x0040
    GHND = GMEM_MOVEABLE | GMEM_ZEROINIT

    # Register Windows clipboard privacy formats
    CF_EXCLUDE_MONITOR = user32.RegisterClipboardFormatW(
        "ExcludeClipboardContentFromMonitorProcessing"
    )
    CF_CAN_INCLUDE_HISTORY = user32.RegisterClipboardFormatW(
        "CanIncludeInClipboardHistory"
    )
    CF_CAN_UPLOAD_CLOUD = user32.RegisterClipboardFormatW(
        "CanUploadToCloudClipboard"
    )


DEFAULT_CLEAR_TIMEOUT = 30.0  # seconds


class SecureClipboard:
    """Platform-aware secure clipboard with auto-clear and privacy protection.

    Usage:
        clipboard = SecureClipboard(timeout=30)
        clipboard.copy_password("s3cr3t!")
        # Password auto-clears after 30 seconds
        # Or manually:
        clipboard.clear_now()
    """

    def __init__(self, timeout: float = DEFAULT_CLEAR_TIMEOUT):
        """
        Args:
            timeout: Seconds before auto-clearing copied passwords.
                     Set to 0 to disable auto-clear.
        """
        self.timeout = timeout
        self._timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()
        self._last_copied: Optional[str] = None

    def copy_password(self, password: str, timeout: Optional[float] = None) -> bool:
        """Copy a password to clipboard with privacy protection and auto-clear.

        Args:
            password: The password text to copy.
            timeout: Override the default clear timeout for this copy.
                     None uses the instance default.

        Returns:
            True if the copy succeeded, False otherwise.
        """
        clear_after = timeout if timeout is not None else self.timeout

        with self._lock:
            # Cancel any existing timer
            if self._timer and self._timer.is_alive():
                self._timer.cancel()
                self._timer = None

            if IS_WINDOWS:
                success = self._win32_copy(password)
            else:
                success = self._qt_copy(password)

            if not success:
                return False

            self._last_copied = password

            # Schedule auto-clear
            if clear_after > 0:
                self._timer = threading.Timer(
                    clear_after, self._safe_clear, args=[password]
                )
                self._timer.daemon = True
                self._timer.start()

            return True

    def clear_now(self) -> None:
        """Immediately clear the clipboard. Cancels any pending auto-clear timer."""
        with self._lock:
            if self._timer and self._timer.is_alive():
                self._timer.cancel()
                self._timer = None
            self._last_copied = None

            if IS_WINDOWS:
                self._win32_clear()
            else:
                self._qt_clear()

    def _safe_clear(self, expected_text: str) -> None:
        """Clear clipboard only if it still contains the expected password.

        This prevents destroying the user's data if they've copied something
        else since the password was placed on the clipboard.
        """
        with self._lock:
            current = self._get_clipboard_text()
            if current == expected_text:
                if IS_WINDOWS:
                    self._win32_clear()
                else:
                    self._qt_clear()
            self._last_copied = None

    # ── Windows Win32 Implementation ───────────────────────────────────

    def _win32_open_clipboard(self, retries: int = 10, delay: float = 0.05) -> bool:
        """Open clipboard with retry (another process may have it locked)."""
        for _ in range(retries):
            if user32.OpenClipboard(None):
                return True
            time.sleep(delay)
        return False

    def _win32_copy(self, text: str) -> bool:
        """Copy text to clipboard with Windows privacy flags."""
        if not self._win32_open_clipboard():
            return False

        try:
            user32.EmptyClipboard()

            # Set privacy flags — DWORD value of 0
            dw_zero = ctypes.c_uint32(0)
            for fmt in (CF_EXCLUDE_MONITOR, CF_CAN_INCLUDE_HISTORY, CF_CAN_UPLOAD_CLOUD):
                h_flag = kernel32.GlobalAlloc(GHND, ctypes.sizeof(dw_zero))
                if h_flag:
                    p_flag = kernel32.GlobalLock(h_flag)
                    ctypes.memmove(
                        p_flag, ctypes.byref(dw_zero), ctypes.sizeof(dw_zero)
                    )
                    kernel32.GlobalUnlock(h_flag)
                    if not user32.SetClipboardData(fmt, h_flag):
                        kernel32.GlobalFree(h_flag)

            # Set the actual text
            encoded = (text + "\0").encode("utf-16le")
            h_text = kernel32.GlobalAlloc(GHND, len(encoded))
            if not h_text:
                return False

            p_text = kernel32.GlobalLock(h_text)
            ctypes.memmove(p_text, encoded, len(encoded))
            kernel32.GlobalUnlock(h_text)

            if not user32.SetClipboardData(CF_UNICODETEXT, h_text):
                kernel32.GlobalFree(h_text)
                return False

            return True
        finally:
            user32.CloseClipboard()

    def _win32_clear(self) -> None:
        """Clear clipboard via Win32."""
        if self._win32_open_clipboard():
            try:
                user32.EmptyClipboard()
            finally:
                user32.CloseClipboard()

    def _win32_get_text(self) -> Optional[str]:
        """Read current clipboard text via Win32."""
        if not self._win32_open_clipboard():
            return None
        try:
            if not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
                return None
            h_data = user32.GetClipboardData(CF_UNICODETEXT)
            if not h_data:
                return None
            p_data = kernel32.GlobalLock(h_data)
            if not p_data:
                return None
            try:
                return ctypes.c_wchar_p(p_data).value
            finally:
                kernel32.GlobalUnlock(h_data)
        finally:
            user32.CloseClipboard()

    # ── Qt Fallback Implementation ─────────────────────────────────────

    def _qt_copy(self, text: str) -> bool:
        """Copy text via Qt clipboard (fallback for non-Windows)."""
        try:
            from PySide6.QtWidgets import QApplication

            app = QApplication.instance()
            if app:
                clipboard = app.clipboard()
                clipboard.setText(text)
                return True
            return False
        except ImportError:
            return False

    def _qt_clear(self) -> None:
        """Clear clipboard via Qt."""
        try:
            from PySide6.QtWidgets import QApplication

            app = QApplication.instance()
            if app:
                app.clipboard().clear()
        except ImportError:
            pass

    def _get_clipboard_text(self) -> Optional[str]:
        """Get current clipboard text (platform-aware)."""
        if IS_WINDOWS:
            return self._win32_get_text()
        try:
            from PySide6.QtWidgets import QApplication

            app = QApplication.instance()
            if app:
                return app.clipboard().text()
            return None
        except ImportError:
            return None
