import os
import sys
import pytest
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon

# Ensure QApplication exists before any QIcon or QWidget is created
app = QApplication.instance() or QApplication(sys.argv)

from src.ui.unlock_dialog import UnlockDialog, _get_last_vault_path, _save_last_vault_path
from src.ui.vault_view import VaultView

def test_icon_assets_exist():
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    ico_path = os.path.join(project_root, "assets", "icon.ico")
    png_path = os.path.join(project_root, "assets", "icon.png")

    assert os.path.exists(ico_path), "assets/icon.ico must exist"
    assert os.path.exists(png_path), "assets/icon.png must exist"
    assert os.path.getsize(ico_path) > 1000, "assets/icon.ico should not be empty"
    assert os.path.getsize(png_path) > 1000, "assets/icon.png should not be empty"

    # Verify QIcon loads it successfully
    icon = QIcon(ico_path)
    assert not icon.isNull(), "QIcon should load icon.ico without errors"

def test_desktop_shortcut_exists():
    desktop = os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")
    shortcut_path = os.path.join(desktop, "SecureVault.lnk")
    assert os.path.exists(shortcut_path), f"Desktop shortcut {shortcut_path} must exist"

def test_unlock_dialog_accessibility_and_autodetect(tmp_path):
    # Test path saving and auto-detection
    fake_vault = str(tmp_path / "test.vault")
    with open(fake_vault, "w") as f:
        f.write("vault")
    _save_last_vault_path(fake_vault)
    assert _get_last_vault_path() == fake_vault

    dialog = UnlockDialog(mode="unlock")
    assert dialog.file_input.text() == fake_vault
    assert dialog.file_input.accessibleName() == "Encrypted vault file path"
    assert dialog.password_input.accessibleName() == "Master password"
    assert dialog.action_btn.accessibleName() == "Submit unlock or create vault"
    assert dialog.action_btn.isDefault()

def test_vault_view_accessibility_and_shortcuts():
    view = VaultView()
    assert "Ctrl+F" in view.search_bar.placeholderText()
    assert view.search_bar.accessibleName() == "Search vault entries"
    assert view.list_widget.accessibleName() == "Vault entries list"
    assert view.edit_btn.accessibleName() == "Edit selected entry"
    assert view.delete_btn.accessibleName() == "Delete selected entry"
    assert view.copy_pwd_btn.accessibleName() == "Copy password to clipboard"
    assert view.copy_user_btn.accessibleName() == "Copy username to clipboard"
    assert view.search_shortcut is not None
    assert view.copy_pwd_shortcut is not None
    assert view.copy_user_shortcut is not None
