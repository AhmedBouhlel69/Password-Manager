import os
import sys
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon
from src.ui.styles import get_stylesheet
from src.ui.unlock_dialog import UnlockDialog
from src.ui.main_window import MainWindow
from src.ui.ble_2fa_dialog import BLE2FADialog
from src.core.vault import Vault, VaultError
from src.core.clipboard import SecureClipboard
from src.core.session import SessionManager

def run_app():
    # Set Windows AppUserModelID so taskbar icon and grouping match SecureVault
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SecureVault.PasswordManager")
        except Exception:
            pass

    app = QApplication(sys.argv)
    app.setApplicationName("SecureVault")
    app.setApplicationDisplayName("SecureVault Password Manager")
    app.setOrganizationName("SecureVault")

    # Set application-wide window icon
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    icon_path = os.path.join(base_dir, "assets", "icon.ico")
    if not os.path.exists(icon_path):
        icon_path = os.path.join(base_dir, "assets", "icon.png")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    app.setStyleSheet(get_stylesheet())

    vault = Vault()
    session = SessionManager(timeout_seconds=300)
    clipboard = SecureClipboard(timeout=30)
    
    main_window = None

    def show_unlock(mode='unlock'):
        dlg = UnlockDialog(mode=mode)
        
        def on_created(path, pwd):
            try:
                vault.create_vault(path, pwd)
                dlg.accept()
            except Exception as e:
                dlg.set_error(str(e))
                
        def on_unlocked(path, pwd):
            try:
                if vault.unlock(path, pwd):
                    # Enforce Bluetooth 2FA if trusted iPhone is registered
                    devices = vault.get_trusted_devices()
                    if devices:
                        ble_dlg = BLE2FADialog(vault=vault, parent=dlg)
                        res = ble_dlg.exec()
                        if res == 1 and ble_dlg.approved:
                            dlg.accept()
                        else:
                            vault.lock()
                            dlg.set_error("Bluetooth 2FA verification not approved. Session ended.")
                            dlg.reject()
                    else:
                        dlg.accept()
            except VaultError as e:
                dlg.set_error(str(e))

        def on_imported(path, pwd):
            try:
                if vault.unlock(path, pwd):
                    devices = vault.get_trusted_devices()
                    if devices:
                        ble_dlg = BLE2FADialog(vault=vault, parent=dlg)
                        res = ble_dlg.exec()
                        if res == 1 and ble_dlg.approved:
                            dlg.accept()
                        else:
                            vault.lock()
                            dlg.set_error("Bluetooth 2FA verification not approved. Session ended.")
                            dlg.reject()
                    else:
                        dlg.accept()
            except VaultError as e:
                dlg.set_error(str(e))

        dlg.vault_created.connect(on_created)
        dlg.vault_unlocked.connect(on_unlocked)
        dlg.vault_imported.connect(on_imported)
        
        res = dlg.exec()
        if res == 2: # switch mode
            show_unlock('create' if mode == 'unlock' else 'unlock')
        elif res == 1: # accepted
            nonlocal main_window
            main_window = MainWindow(vault, session, clipboard)
            main_window.show()
            session.start()
        else:
            # Cancelled/Closed
            app.quit()

    def on_locked():
        if main_window:
            main_window.close()
        show_unlock('unlock')

    session.session_locked.connect(on_locked)

    show_unlock('unlock')

    return app.exec()
