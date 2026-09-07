import os
import datetime
from PySide6.QtWidgets import (QMainWindow, QToolBar, QStatusBar, QMessageBox, QApplication)
from PySide6.QtGui import QAction, QCloseEvent, QIcon, QKeySequence
from PySide6.QtCore import Qt, QEvent
from src.ui.vault_view import VaultView
from src.ui.entry_editor import EntryEditorDialog
from src.ui.settings_dialog import SettingsDialog
from src.ui.import_wizard import ImportWizardDialog
from src.ui.pairing_dialog import PairingDialog
from src.core.vault import Vault
from src.core.clipboard import SecureClipboard
from src.core.session import SessionManager

class MainWindow(QMainWindow):
    def __init__(self, vault: Vault, session: SessionManager, clipboard: SecureClipboard):
        super().__init__()
        self.vault = vault
        self.session = session
        self.clipboard = clipboard
        self.setWindowTitle("SecureVault - Password Manager")
        self.setAccessibleName("SecureVault Main Window")
        self.resize(900, 600)

        # Set window icon
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        icon_path = os.path.join(base_dir, "assets", "icon.ico")
        if not os.path.exists(icon_path):
            icon_path = os.path.join(base_dir, "assets", "icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        # Intercept events for session timeout
        QApplication.instance().installEventFilter(self)

        self.init_ui()
        self.refresh_vault_view()

    def init_ui(self):
        # Menu Bar
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")
        import_act = QAction("Import Plaintext Notes...", self)
        import_act.setShortcut(QKeySequence("Ctrl+I"))
        import_act.setStatusTip("Import credentials from plaintext notes")
        import_act.triggered.connect(self.open_import_wizard)
        file_menu.addAction(import_act)
        file_menu.addSeparator()

        lock_act = QAction("Lock Vault", self)
        lock_act.setShortcut(QKeySequence("Ctrl+L"))
        lock_act.setStatusTip("Immediately lock the vault")
        lock_act.triggered.connect(self.lock_vault)
        file_menu.addAction(lock_act)

        exit_act = QAction("Exit", self)
        exit_act.setShortcut(QKeySequence("Ctrl+Q"))
        exit_act.setStatusTip("Exit the application")
        exit_act.triggered.connect(self.close)
        file_menu.addAction(exit_act)

        edit_menu = menubar.addMenu("Edit")
        add_act = QAction("Add Entry", self)
        add_act.setShortcut(QKeySequence("Ctrl+N"))
        add_act.setStatusTip("Add a new password entry")
        add_act.triggered.connect(self.add_entry)
        edit_menu.addAction(add_act)

        pair_act = QAction("📲 Pair iPhone (Bluetooth 2FA)...", self)
        pair_act.setShortcut(QKeySequence("Ctrl+B"))
        pair_act.setStatusTip("Pair iPhone for Bluetooth 2-factor authentication")
        pair_act.triggered.connect(self.open_pairing_dialog)
        edit_menu.addAction(pair_act)

        settings_act = QAction("Settings", self)
        settings_act.setShortcut(QKeySequence("Ctrl+,"))
        settings_act.setStatusTip("Open application settings")
        settings_act.triggered.connect(self.open_settings)
        edit_menu.addAction(settings_act)

        help_menu = menubar.addMenu("Help")
        about_act = QAction("About", self)
        about_act.setShortcut(QKeySequence("F1"))
        about_act.triggered.connect(lambda: QMessageBox.about(self, "About SecureVault", "SecureVault Password Manager\nA secure, local-first encrypted password manager with Bluetooth 2FA."))
        help_menu.addAction(about_act)

        # Toolbar
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        toolbar.addAction(add_act)
        toolbar.addAction(import_act)
        toolbar.addAction(pair_act)
        toolbar.addAction(lock_act)
        toolbar.addAction(settings_act)

        # Central Widget
        self.vault_view = VaultView()
        self.setCentralWidget(self.vault_view)

        # Signals
        self.vault_view.edit_requested.connect(self.edit_entry)
        self.vault_view.delete_requested.connect(self.delete_entry)
        self.vault_view.copy_password_requested.connect(self.copy_password)
        self.vault_view.copy_username_requested.connect(self.copy_username)

        # Status Bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.update_status("Unlocked")

    def eventFilter(self, obj, event):
        if event.type() in (QEvent.MouseMove, QEvent.KeyPress, QEvent.MouseButtonPress):
            self.session.reset_idle_timer()
        return super().eventFilter(obj, event)

    def refresh_vault_view(self):
        if self.vault.is_unlocked:
            entries = self.vault.list_entries()
            self.vault_view.set_entries(entries)
            self.update_status(f"Unlocked | {len(entries)} entries")

    def update_status(self, msg):
        time_str = datetime.datetime.now().strftime("%H:%M:%S")
        self.statusBar.showMessage(f"{msg} | Last action: {time_str}")

    def add_entry(self):
        dlg = EntryEditorDialog(parent=self)
        if dlg.exec():
            data = dlg.get_entry_data()
            self.vault.add_entry(data)
            self.refresh_vault_view()
            self.update_status("Entry added")

    def edit_entry(self, entry_id: str):
        entry = self.vault.get_entry(entry_id)
        if not entry: return
        dlg = EntryEditorDialog(entry=entry, parent=self)
        if dlg.exec():
            data = dlg.get_entry_data()
            self.vault.update_entry(entry_id, data)
            self.refresh_vault_view()
            self.vault_view.select_entry(entry_id)
            self.update_status("Entry updated")

    def delete_entry(self, entry_id: str):
        reply = QMessageBox.question(self, "Confirm Delete", "Are you sure you want to delete this entry?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.vault.delete_entry(entry_id)
            self.refresh_vault_view()
            self.update_status("Entry deleted")

    def copy_password(self, entry_id: str):
        entry = self.vault.get_entry(entry_id)
        if entry and "password" in entry:
            self.clipboard.copy_password(entry["password"])
            self.update_status("Password copied to clipboard")

    def copy_username(self, entry_id: str):
        entry = self.vault.get_entry(entry_id)
        if entry and "username" in entry:
            self.clipboard.copy_password(entry["username"])
            self.update_status("Username copied to clipboard (protected)")

    def open_settings(self):
        current_settings = {
            "auto_lock_timeout_minutes": self.session.timeout_seconds // 60,
            "clipboard_clear_timeout_seconds": int(self.clipboard.timeout),
        }
        dlg = SettingsDialog(current_settings=current_settings, vault=self.vault, parent=self)
        dlg.settings_applied.connect(self._apply_settings_dict)
        if dlg.exec():
            self._apply_settings_dict(dlg.get_settings())

    def _apply_settings_dict(self, settings: dict):
        if settings.get("auto_lock_timeout_minutes", 0) > 0:
            self.session.timeout_seconds = settings["auto_lock_timeout_minutes"] * 60
        else:
            self.session.timeout_seconds = 0
        self.clipboard.timeout = settings.get("clipboard_clear_timeout_seconds", 30)
        self.update_status("Settings updated")

    def open_pairing_dialog(self):
        dlg = PairingDialog(vault=self.vault, parent=self)
        dlg.exec()
        devices = self.vault.get_trusted_devices()
        status_2fa = f"2FA Active ({len(devices)} device)" if devices else "2FA Inactive"
        self.update_status(f"Paired devices updated | {status_2fa}")

    def open_import_wizard(self):
        dlg = ImportWizardDialog(vault=self.vault, parent=self)
        dlg.entries_imported.connect(lambda count: self.refresh_vault_view())
        dlg.exec()

    def lock_vault(self):
        self.vault.lock()
        self.clipboard.clear_now()
        # The app.py manages showing the unlock dialog
        self.session.session_locked.emit()
        self.close()

    def closeEvent(self, event: QCloseEvent):
        self.vault.lock()
        self.clipboard.clear_now()
        event.accept()
