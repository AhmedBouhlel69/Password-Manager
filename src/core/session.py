"""
Session management — auto-lock timer and idle detection.

Tracks user activity and automatically locks the vault after a configurable
idle timeout. Integrates with the Qt event system to detect mouse/keyboard
activity without polling.

Usage:
    session = SessionManager(vault, timeout_seconds=300)
    session.start()
    # ... vault is auto-locked after 5 min idle ...
    session.stop()
"""

from PySide6.QtCore import QTimer, QObject, Signal


# Default idle timeout: 5 minutes
DEFAULT_TIMEOUT_SECONDS = 300


class SessionManager(QObject):
    """Manages vault auto-lock on idle.

    Emits session_locked signal when the vault is locked due to idle timeout.
    The UI layer should connect to this signal to show the unlock dialog.

    The timer resets on any call to reset_idle_timer(), which should be
    triggered by user input events in the UI.
    """

    # Emitted when the session auto-locks
    session_locked = Signal()

    # Emitted when the timer resets (for status bar display)
    timer_reset = Signal()

    def __init__(self, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS, parent=None):
        """
        Args:
            timeout_seconds: Seconds of inactivity before auto-lock.
                            Default 300 (5 minutes). Set to 0 to disable.
            parent: Qt parent object.
        """
        super().__init__(parent)
        self._timeout_seconds = timeout_seconds
        self._enabled = timeout_seconds > 0

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._on_timeout)

        self._lock_callback = None
        self._running = False

    @property
    def timeout_seconds(self) -> int:
        return self._timeout_seconds

    @timeout_seconds.setter
    def timeout_seconds(self, value: int) -> None:
        """Update the timeout. Takes effect on next timer reset."""
        self._timeout_seconds = value
        self._enabled = value > 0
        if self._running:
            if self._enabled:
                self.reset_idle_timer()
            else:
                self._timer.stop()

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def remaining_seconds(self) -> int:
        """Approximate seconds remaining before auto-lock."""
        if not self._timer.isActive():
            return 0
        return max(0, self._timer.remainingTime() // 1000)

    def set_lock_callback(self, callback) -> None:
        """Set a callable to invoke when auto-lock triggers.

        This is called IN ADDITION to the session_locked signal.
        Typically set to vault.lock().

        Args:
            callback: A callable with no arguments.
        """
        self._lock_callback = callback

    def start(self) -> None:
        """Start the auto-lock timer."""
        self._running = True
        if self._enabled:
            self._timer.start(self._timeout_seconds * 1000)

    def stop(self) -> None:
        """Stop the auto-lock timer."""
        self._running = False
        self._timer.stop()

    def reset_idle_timer(self) -> None:
        """Reset the idle timer. Call this on any user activity.

        The UI layer should call this on mouse moves, key presses, etc.
        """
        if self._running and self._enabled:
            self._timer.start(self._timeout_seconds * 1000)
            self.timer_reset.emit()

    def _on_timeout(self) -> None:
        """Called when the idle timer expires."""
        self._running = False
        if self._lock_callback:
            try:
                self._lock_callback()
            except Exception:
                pass
        self.session_locked.emit()
