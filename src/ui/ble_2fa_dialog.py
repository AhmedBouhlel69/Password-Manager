"""
Bluetooth 2FA Verification Dialog (Native Windows Bluetooth — No iOS App Required).

Displayed after the master password has been validated:
1. Identifies the enrolled Bluetooth device (e.g. iPhone) registered in the vault.
2. Checks Windows Bluetooth stack and performs an active RFCOMM handshake ping.
3. Confirms that the user's phone is physically connected and in proximity.
4. If connected: grants access to the vault.
5. If disconnected / out of range / denied: session immediately ends.
"""

import time
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QProgressBar, QMessageBox, QApplication
)
from PySide6.QtCore import Qt, QThread, Signal

from src.ble.windows_bluetooth import verify_bluetooth_2fa
from src.ble.pairing import EmergencyOverrideHandler
from src.ui.styles import get_stylesheet


class EmergencyOverrideWorker(QThread):
    """Worker handling the mandatory emergency override security delay without freezing the UI."""
    tick = Signal(int)
    finished_override = Signal()

    def __init__(self, db, delay_seconds: int = 5):
        super().__init__()
        self.db = db
        self.delay_seconds = delay_seconds

    def run(self):
        try:
            self.db.log_event(
                "emergency_override",
                f"Emergency 2FA bypass executed with deliberate delay of {self.delay_seconds}s"
            )
        except Exception:
            pass
        for remaining in range(self.delay_seconds, 0, -1):
            self.tick.emit(remaining)
            time.sleep(1.0)
        self.finished_override.emit()


class Bluetooth2FAWorker(QThread):
    """Worker executing Windows native Bluetooth verification."""
    status_updated = Signal(str, str)  # message, color_hex
    verification_finished = Signal(bool, str)  # success, reason

    def __init__(self, mac_address: str, device_name: str = "iPhone"):
        super().__init__()
        self.mac_address = mac_address
        self.device_name = device_name

    def run(self):
        self.status_updated.emit(f"📡 Verifying Bluetooth connection to '{self.device_name}'...", "#7aa2f7")
        try:
            ok, msg = verify_bluetooth_2fa(self.mac_address, timeout=3.0)
            self.verification_finished.emit(ok, msg)
        except Exception as e:
            self.verification_finished.emit(False, str(e))


class BLE2FADialog(QDialog):
    """Modal dialog managing 2FA connection to iPhone without requiring an iOS app."""

    def __init__(self, vault, parent=None):
        super().__init__(parent)
        self.vault = vault
        self.approved = False
        self.setWindowTitle("Two-Factor Authentication — iPhone Presence Check")
        self.setMinimumWidth(500)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setStyleSheet(get_stylesheet())
        self.init_ui()
        self.start_verification()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(16)

        # Icon and Title
        self.icon_lbl = QLabel("📲")
        self.icon_lbl.setStyleSheet("font-size: 52px; margin-top: 10px;")
        self.icon_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.icon_lbl)

        self.title_lbl = QLabel("iPhone Bluetooth Confirmation")
        self.title_lbl.setStyleSheet("font-size: 18px; font-weight: bold;")
        self.title_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.title_lbl)

        # Status text
        self.status_lbl = QLabel("Initializing Bluetooth 2FA...")
        self.status_lbl.setStyleSheet("color: #7aa2f7; font-size: 13px;")
        self.status_lbl.setAlignment(Qt.AlignCenter)
        self.status_lbl.setWordWrap(True)
        layout.addWidget(self.status_lbl)

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setFixedHeight(6)
        self.progress.setTextVisible(False)
        layout.addWidget(self.progress)




        # Button Row
        btn_row = QHBoxLayout()

        self.btn_override = QPushButton("Emergency Override")
        self.btn_override.setStyleSheet("background-color: #45475a; color: #f7768e;")
        self.btn_override.clicked.connect(self.trigger_emergency_override)
        btn_row.addWidget(self.btn_override)

        self.btn_retry = QPushButton("🔄 Retry Connection")
        self.btn_retry.setVisible(False)
        self.btn_retry.setStyleSheet("background-color: #313244; color: #7aa2f7;")
        self.btn_retry.clicked.connect(self.start_verification)
        btn_row.addWidget(self.btn_retry)

        btn_row.addStretch()

        self.btn_cancel = QPushButton("Cancel / End Session")
        self.btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(self.btn_cancel)

        layout.addLayout(btn_row)

    def start_verification(self):
        self.btn_retry.setVisible(False)
        self.progress.setRange(0, 0)

        devices = self.vault.get_trusted_devices()
        if not devices:
            self.status_lbl.setText("No 2FA device registered.")
            self.approved = True
            self.accept()
            return

        target = devices[0]
        mac = target.get("device_id", "")
        name = target.get("device_name", "iPhone")

        self.status_lbl.setText(f"🔍 Pinging '{name}' ({mac}) via Bluetooth...")
        self.status_lbl.setStyleSheet("color: #7aa2f7; font-size: 13px;")

        self.worker = Bluetooth2FAWorker(mac_address=mac, device_name=name)
        self.worker.status_updated.connect(self.on_status_updated)
        self.worker.verification_finished.connect(self.on_verification_finished)
        self.worker.start()

    def on_status_updated(self, msg: str, color_hex: str):
        self.status_lbl.setText(msg)
        self.status_lbl.setStyleSheet(f"color: {color_hex}; font-size: 13px;")

    def on_verification_finished(self, success: bool, reason: str):
        self.progress.setRange(0, 100)
        self.progress.setValue(100 if success else 0)

        if success:
            self.approved = True
            QApplication.beep()
            self.status_lbl.setText(f"✅ {reason}\nUnlocking vault...")
            self.status_lbl.setStyleSheet("color: #9ece6a; font-size: 13px; font-weight: bold;")
            self.accept()
        else:
            self.approved = False
            self.status_lbl.setText(f"❌ {reason}\nEnsure iPhone Bluetooth is ON and within range.")
            self.status_lbl.setStyleSheet("color: #f7768e; font-size: 13px;")
            self.btn_retry.setVisible(True)




    def trigger_emergency_override(self):
        confirm = QMessageBox.warning(
            self, "Emergency 2FA Override",
            "Emergency override bypasses Bluetooth 2FA if your phone is unavailable.\n\n"
            "Policy requirements:\n"
            "- A mandatory security delay is applied.\n"
            "- An immutable security event is logged to the encrypted audit log.\n\n"
            "Proceed with emergency override?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if confirm == QMessageBox.Yes:
            self._stop_worker()
            self.btn_override.setEnabled(False)
            self.btn_retry.setVisible(False)
            self.progress.setRange(0, 5)
            self.progress.setValue(0)

            db, _ = self.vault._ensure_unlocked()
            self.override_worker = EmergencyOverrideWorker(db, delay_seconds=5)
            self.override_worker.tick.connect(self._on_override_tick)
            self.override_worker.finished_override.connect(self._on_override_finished)
            self.override_worker.start()

    def _on_override_tick(self, remaining: int):
        self.status_lbl.setText(f"⏳ Emergency security delay active: {remaining}s remaining...")
        self.status_lbl.setStyleSheet("color: #e0af68; font-size: 13px; font-weight: bold;")
        self.progress.setValue(5 - remaining)

    def _on_override_finished(self):
        self.progress.setValue(5)
        self.approved = True
        self.status_lbl.setText("✅ Emergency override approved. Unlocking vault...")
        self.status_lbl.setStyleSheet("color: #9ece6a; font-size: 13px; font-weight: bold;")
        self.accept()

    def _stop_worker(self):
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.terminate()
            self.worker.wait(500)
        if hasattr(self, 'override_worker') and self.override_worker.isRunning():
            self.override_worker.terminate()
            self.override_worker.wait(500)

    def closeEvent(self, event):
        self._stop_worker()
        super().closeEvent(event)

    def reject(self):
        self._stop_worker()
        super().reject()
