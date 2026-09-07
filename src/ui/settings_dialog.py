from typing import Dict, Any
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                               QSpinBox, QCheckBox, QPushButton, QDialogButtonBox)
from PySide6.QtCore import Qt, Signal

class SettingsDialog(QDialog):
    settings_applied = Signal(dict)

    def __init__(self, current_settings: Dict[str, Any] = None, vault=None, parent=None):
        super().__init__(parent)
        self.vault = vault
        self.setWindowTitle("Settings")
        self.setMinimumWidth(340)
        self.current_settings = current_settings or {}
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Auto-lock timeout
        auto_lock_layout = QHBoxLayout()
        auto_lock_label = QLabel("Auto-lock timeout (minutes, 0 = disabled):")
        self.auto_lock_spinbox = QSpinBox()
        self.auto_lock_spinbox.setRange(0, 60)
        self.auto_lock_spinbox.setValue(self.current_settings.get("auto_lock_timeout_minutes", 5))
        auto_lock_layout.addWidget(auto_lock_label)
        auto_lock_layout.addWidget(self.auto_lock_spinbox)
        layout.addLayout(auto_lock_layout)

        # Clipboard clear timeout
        clip_clear_layout = QHBoxLayout()
        clip_clear_label = QLabel("Clipboard clear timeout (seconds):")
        self.clip_clear_spinbox = QSpinBox()
        self.clip_clear_spinbox.setRange(5, 120)
        self.clip_clear_spinbox.setValue(self.current_settings.get("clipboard_clear_timeout_seconds", 30))
        clip_clear_layout.addWidget(clip_clear_label)
        clip_clear_layout.addWidget(self.clip_clear_spinbox)
        layout.addLayout(clip_clear_layout)

        # HIBP check
        self.hibp_checkbox = QCheckBox("Enable HaveIBeenPwned breach checking")
        self.hibp_checkbox.setChecked(self.current_settings.get("hibp_enabled", False))
        layout.addWidget(self.hibp_checkbox)
        
        hibp_desc = QLabel("<small>Checks if passwords have been exposed in known data breaches.<br>Passwords are hashed locally before sending.</small>")
        hibp_desc.setTextFormat(Qt.RichText)
        hibp_desc.setStyleSheet("color: #6c7086;")
        layout.addWidget(hibp_desc)

        # Bluetooth 2FA Shortcut
        if self.vault:
            btn_2fa = QPushButton("📲 Manage Bluetooth 2FA (iPhone)...")
            btn_2fa.setStyleSheet("background-color: #2a2a3e; color: #7aa2f7; padding: 6px; margin-top: 6px;")
            btn_2fa.clicked.connect(self.open_2fa_pairing)
            layout.addWidget(btn_2fa)

        # Buttons
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel | QDialogButtonBox.Apply)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        self.button_box.button(QDialogButtonBox.Apply).clicked.connect(self.apply_settings)
        layout.addWidget(self.button_box)

    def open_2fa_pairing(self):
        from src.ui.pairing_dialog import PairingDialog
        dlg = PairingDialog(vault=self.vault, parent=self)
        dlg.exec()

    def get_settings(self) -> Dict[str, Any]:
        return {
            "auto_lock_timeout_minutes": self.auto_lock_spinbox.value(),
            "clipboard_clear_timeout_seconds": self.clip_clear_spinbox.value(),
            "hibp_enabled": self.hibp_checkbox.isChecked()
        }

    def apply_settings(self):
        self.settings_applied.emit(self.get_settings())
