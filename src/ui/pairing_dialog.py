"""
Bluetooth 2FA Device Pairing Dialog (No iOS App Required).

Uses standard Windows Bluetooth pairing:
1. Lists all Bluetooth devices paired with this Windows PC.
2. Allows selecting an iPhone / smartphone to act as the 2FA hardware presence token.
3. Verifies connection and registers the trusted device in the vault database.
"""

import os
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QMessageBox, QGroupBox
)
from PySide6.QtCore import Qt, QThread, Signal

from src.ble.windows_bluetooth import get_windows_bluetooth_devices, verify_bluetooth_2fa
from src.ui.styles import get_stylesheet


class DeviceScanWorker(QThread):
    devices_found = Signal(list)

    def run(self):
        devices = get_windows_bluetooth_devices()
        self.devices_found.emit(devices)


class PairingDialog(QDialog):
    """Dialog to select and pair an iPhone via native Windows Bluetooth."""

    def __init__(self, vault, parent=None):
        super().__init__(parent)
        self.vault = vault
        self.setWindowTitle("Bluetooth 2FA Setup — iPhone Presence Token")
        self.setMinimumWidth(540)
        self.setStyleSheet(get_stylesheet())
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        title = QLabel("📲 Bluetooth Two-Factor Authentication")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        desc = QLabel(
            "No iOS app required! Pair your iPhone in Windows Settings (Bluetooth & devices).\n"
            "When enabled, your vault requires your iPhone to be physically present and connected via Bluetooth."
        )
        desc.setStyleSheet("color: #a6adc8; font-size: 13px;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # Discovered Windows Bluetooth Devices Box
        win_box = QGroupBox("Available Windows Bluetooth Devices")
        w_layout = QVBoxLayout(win_box)

        self.win_dev_list = QListWidget()
        w_layout.addWidget(self.win_dev_list)

        btn_row_scan = QHBoxLayout()
        self.btn_refresh = QPushButton("🔄 Refresh Device List")
        self.btn_refresh.clicked.connect(self.scan_windows_devices)
        btn_row_scan.addWidget(self.btn_refresh)

        self.btn_set_2fa = QPushButton("✅ Enable 2FA with Selected Device")
        self.btn_set_2fa.setStyleSheet("background-color: #9ece6a; color: #1e1e2e; font-weight: bold;")
        self.btn_set_2fa.clicked.connect(self.set_selected_as_2fa)
        btn_row_scan.addWidget(self.btn_set_2fa)
        w_layout.addLayout(btn_row_scan)

        layout.addWidget(win_box)

        # Currently Active 2FA Devices Box
        active_box = QGroupBox("Active 2FA Devices (Registered in Vault)")
        a_layout = QVBoxLayout(active_box)

        self.active_dev_list = QListWidget()
        a_layout.addWidget(self.active_dev_list)

        btn_unpair = QPushButton("Unpair Selected Device (Disable 2FA)")
        btn_unpair.setStyleSheet("background-color: #45475a; color: #f7768e;")
        btn_unpair.clicked.connect(self.unpair_selected)
        a_layout.addWidget(btn_unpair)

        layout.addWidget(active_box)

        # Dialog Buttons
        bottom_row = QHBoxLayout()
        bottom_row.addStretch()
        btn_close = QPushButton("Done")
        btn_close.clicked.connect(self.accept)
        bottom_row.addWidget(btn_close)
        layout.addLayout(bottom_row)

        self.refresh_active_devices()
        self.scan_windows_devices()

    def scan_windows_devices(self):
        self.btn_refresh.setEnabled(False)
        self.btn_refresh.setText("🔄 Scanning...")
        self.win_dev_list.clear()

        self.worker = DeviceScanWorker()
        self.worker.devices_found.connect(self.on_devices_found)
        self.worker.start()

    def on_devices_found(self, devices: list):
        self.btn_refresh.setEnabled(True)
        self.btn_refresh.setText("🔄 Refresh Device List")

        if not devices:
            self.win_dev_list.addItem("No paired Bluetooth devices found in Windows.")
            return

        for d in devices:
            name = d.get("name", "Unknown Device")
            mac = d.get("mac", "")
            is_conn = d.get("connected", False)

            icon = "📱" if "iphone" in name.lower() or "phone" in name.lower() else "🎧"
            status_text = "🟢 Connected" if is_conn else "⚪ Disconnected"

            item = QListWidgetItem(f"{icon} {name}  [{mac}] — {status_text}")
            item.setData(Qt.UserRole, d)
            self.win_dev_list.addItem(item)

            # Auto-select iPhone if found
            if "iphone" in name.lower():
                self.win_dev_list.setCurrentItem(item)

    def set_selected_as_2fa(self):
        items = self.win_dev_list.selectedItems()
        if not items:
            QMessageBox.warning(self, "No Device Selected", "Please select a Bluetooth device from the list.")
            return

        dev_data = items[0].data(Qt.UserRole)
        if not dev_data:
            return

        name = dev_data.get("name", "iPhone")
        mac = dev_data.get("mac", "")

        # Verify live reachability
        ok, msg = verify_bluetooth_2fa(mac, timeout=2.5)

        # Register in vault DB
        # Store MAC address as device_id
        dummy_pubkey = mac.encode("utf-8")
        self.vault.add_trusted_device(
            device_id=mac,
            device_name=name,
            public_key=dummy_pubkey
        )

        self.refresh_active_devices()

        if ok:
            QMessageBox.information(
                self, "2FA Device Activated!",
                f"✅ '{name}' ({mac}) is now registered as your Bluetooth 2FA key!\n\n"
                "Live connection test: PASSED.\n"
                "Any future vault unlock will require your phone to be connected via Bluetooth."
            )
        else:
            QMessageBox.warning(
                self, "Device Registered with Warning",
                f"'{name}' ({mac}) has been saved as your 2FA device.\n\n"
                f"Note: {msg}\n"
                "Please make sure Bluetooth is ON and connected before your next unlock."
            )

    def refresh_active_devices(self):
        self.active_dev_list.clear()
        devices = self.vault.get_trusted_devices()
        if not devices:
            self.active_dev_list.addItem("No 2FA devices registered. (Vault unlocks with master password only).")
        else:
            for d in devices:
                name = d.get("device_name", "Device")
                mac = d.get("device_id", "")
                item = QListWidgetItem(f"🔒 2FA Enforced: 📱 {name} [{mac}]")
                item.setData(Qt.UserRole, mac)
                self.active_dev_list.addItem(item)

    def unpair_selected(self):
        items = self.active_dev_list.selectedItems()
        if not items:
            return
        mac = items[0].data(Qt.UserRole)
        if mac:
            self.vault.remove_trusted_device(mac)
            self.refresh_active_devices()
            QMessageBox.information(self, "2FA Disabled", "Selected device removed. 2FA is no longer required.")
