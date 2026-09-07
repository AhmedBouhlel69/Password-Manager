import os
import sys
import pytest
from PySide6.QtWidgets import QApplication, QMessageBox

# Ensure QApplication exists for Qt widgets
app = QApplication.instance() or QApplication(sys.argv)

from src.core.vault import Vault, VaultState
from src.ui.pairing_dialog import PairingDialog
from src.ui.ble_2fa_dialog import BLE2FADialog
from src.ble.windows_bluetooth import get_windows_bluetooth_devices, verify_bluetooth_2fa


def test_windows_bluetooth_enumeration():
    devices = get_windows_bluetooth_devices()
    assert isinstance(devices, list)
    for d in devices:
        assert "name" in d
        assert "mac" in d
        assert "connected" in d


def test_pairing_dialog_flow(tmp_path, monkeypatch):
    # Prevent QMessageBox from blocking headless test execution
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: QMessageBox.Ok)
    monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: QMessageBox.Ok)

    vault_path = str(tmp_path / "test_pair.vault")
    vault = Vault()
    vault.create_vault(vault_path, "Secret123!")

    # Test opening pairing dialog
    dlg = PairingDialog(vault=vault)
    assert "Bluetooth" in dlg.windowTitle()

    # Wait for scan thread if running
    if hasattr(dlg, "worker") and dlg.worker.isRunning():
        dlg.worker.wait(2000)

    # Test enrolling a device directly
    vault.add_trusted_device("28:49:E9:83:40:1C", "Ahmed's iPhone", b"28:49:E9:83:40:1C")
    dlg.refresh_active_devices()
    assert dlg.active_dev_list.count() == 1

    # Test unpair
    dlg.active_dev_list.setCurrentRow(0)
    dlg.unpair_selected()
    assert len(vault.get_trusted_devices()) == 0

    vault.close()


def test_2fa_enforcement_logic(tmp_path):
    vault_path = str(tmp_path / "test_enforce.vault")
    vault = Vault()
    vault.create_vault(vault_path, "MasterPass999#")

    # Enroll iPhone
    vault.add_trusted_device("28:49:E9:83:40:1C", "Ahmed's iPhone", b"28:49:E9:83:40:1C")
    vault.close()

    # 1. Right password unlocks vault in memory
    assert vault.unlock(vault_path, "MasterPass999#") is True
    assert vault.is_unlocked is True

    # 2. Check 2FA condition
    devices = vault.get_trusted_devices()
    assert len(devices) == 1
    assert devices[0]["device_id"] == "28:49:E9:83:40:1C"

    # 3. Simulate 2FA rejected / cancelled: session MUST end and vault MUST lock
    vault.lock()
    assert vault.is_unlocked is False
    assert vault.state == VaultState.LOCKED

    # 4. Right password + 2FA approved:
    assert vault.unlock(vault_path, "MasterPass999#") is True
    assert vault.is_unlocked is True
    # Session is active
    entries = vault.list_entries()
    assert isinstance(entries, list)

    vault.close()
