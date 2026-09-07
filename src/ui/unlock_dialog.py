import os
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                               QLineEdit, QPushButton, QFileDialog, QProgressBar, QStackedWidget, QWidget)
from PySide6.QtCore import Signal, Qt
from src.ui.styles import get_stylesheet

class UnlockDialog(QDialog):
    vault_created = Signal(str, str)
    vault_unlocked = Signal(str, str)
    vault_imported = Signal(str, str)

    def __init__(self, mode='unlock', parent=None):
        super().__init__(parent)
        self.mode = mode  # 'unlock' or 'create'
        self.setWindowTitle("SecureVault")
        self.setMinimumSize(480, 400)
        self.setStyleSheet(get_stylesheet())
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)

        # Title
        title_label = QLabel("🔒 SecureVault")
        title_label.setStyleSheet("font-size: 24px; font-weight: bold; margin-bottom: 10px;")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        sub_label = QLabel("Create or unlock your encrypted vault database (.vault)")
        sub_label.setStyleSheet("color: #6c7086; font-size: 12px; margin-bottom: 15px;")
        sub_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(sub_label)

        # File path
        file_layout = QHBoxLayout()
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("Select encrypted vault file (.vault)...")
        self.file_input.setReadOnly(True)
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_input)
        file_layout.addWidget(self.browse_btn)
        layout.addLayout(file_layout)

        # Password
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Master Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.textChanged.connect(self.on_password_changed)
        
        pwd_layout = QHBoxLayout()
        pwd_layout.addWidget(self.password_input)
        self.toggle_pwd_btn = QPushButton("👁")
        self.toggle_pwd_btn.setCheckable(True)
        self.toggle_pwd_btn.clicked.connect(self.toggle_password_visibility)
        pwd_layout.addWidget(self.toggle_pwd_btn)
        layout.addLayout(pwd_layout)

        # Create mode specific fields
        if self.mode == 'create':
            self.confirm_input = QLineEdit()
            self.confirm_input.setPlaceholderText("Confirm Password")
            self.confirm_input.setEchoMode(QLineEdit.Password)
            layout.addWidget(self.confirm_input)

            self.strength_bar = QProgressBar()
            self.strength_bar.setRange(0, 100)
            self.strength_bar.setTextVisible(False)
            self.strength_bar.setFixedHeight(8)
            layout.addWidget(self.strength_bar)

        # Status Label
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #f7768e;")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        # Action button
        self.action_btn = QPushButton("Create Vault" if self.mode == 'create' else "Unlock")
        self.action_btn.clicked.connect(self.submit)
        layout.addWidget(self.action_btn)
        
        # Switch mode button
        self.switch_mode_btn = QPushButton("Switch to Unlock" if self.mode == 'create' else "Create New Vault")
        self.switch_mode_btn.setStyleSheet("background: transparent; color: #7aa2f7; text-decoration: underline;")
        self.switch_mode_btn.clicked.connect(self.switch_mode)
        layout.addWidget(self.switch_mode_btn)

        # Direct Import Notes button
        self.import_btn = QPushButton("📄 Import from Notepad / Plaintext Notes (.txt)")
        self.import_btn.setStyleSheet(
            "background-color: #2a2a3e; color: #7aa2f7; border: 1px solid #45475a; "
            "border-radius: 4px; padding: 8px; margin-top: 15px; font-weight: normal;"
        )
        self.import_btn.clicked.connect(lambda: self.start_import_flow())
        layout.addWidget(self.import_btn)

    def browse_file(self):
        if self.mode == 'create':
            path, _ = QFileDialog.getSaveFileName(self, "Create Vault File", "", "Vault Files (*.vault);;All Files (*)")
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Open Vault File", "", "Vault Files (*.vault);;Text Files (*.txt);;All Files (*)")
        if path:
            if path.lower().endswith(".txt") or path.lower().endswith(".log"):
                from PySide6.QtWidgets import QMessageBox
                reply = QMessageBox.question(
                    self, "Plaintext File Detected",
                    f"'{os.path.basename(path)}' is a plaintext text file, not an encrypted vault database.\n\n"
                    "Would you like to import its credentials into a new encrypted vault?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
                )
                if reply == QMessageBox.Yes:
                    self.start_import_flow(initial_notes_path=path)
                    return
            self.file_input.setText(path)

    def start_import_flow(self, initial_notes_path=""):
        dlg = QuickImportModal(initial_notes_path=initial_notes_path, parent=self)
        if dlg.exec():
            vault_path, master_pwd = dlg.get_result()
            if vault_path and master_pwd:
                self.vault_imported.emit(vault_path, master_pwd)

    def toggle_password_visibility(self):
        if self.toggle_pwd_btn.isChecked():
            self.password_input.setEchoMode(QLineEdit.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.Password)

    def on_password_changed(self, text):
        if self.mode == 'create':
            strength = min(100, len(text) * 10)
            if any(c.isupper() for c in text): strength += 10
            if any(c.isdigit() for c in text): strength += 10
            if any(not c.isalnum() for c in text): strength += 15
            strength = min(100, strength)
            self.strength_bar.setValue(strength)
            if strength < 30:
                self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #f7768e; }")
            elif strength < 70:
                self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #e0af68; }")
            else:
                self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #9ece6a; }")

    def submit(self):
        path = self.file_input.text()
        pwd = self.password_input.text()

        if not path:
            self.status_label.setText("Please select a file path.")
            return
        if not pwd:
            self.status_label.setText("Please enter a master password.")
            return

        if self.mode == 'create':
            if pwd != self.confirm_input.text():
                self.status_label.setText("Passwords do not match.")
                return
            self.vault_created.emit(path, pwd)
        else:
            if not os.path.exists(path):
                self.status_label.setText("File not found.")
                return
            self.vault_unlocked.emit(path, pwd)

    def switch_mode(self):
        self.done(2)

    def set_error(self, msg: str):
        self.status_label.setText(msg)


class QuickImportModal(QDialog):
    """Simple, friendly wizard to convert a .txt notes file into an encrypted .vault file."""

    def __init__(self, initial_notes_path="", parent=None):
        super().__init__(parent)
        self.initial_notes_path = initial_notes_path
        self.vault_path = ""
        self.master_pwd = ""
        self.setWindowTitle("Import Notepad (.txt) to Encrypted Vault")
        self.setMinimumWidth(500)
        self.setStyleSheet(get_stylesheet())
        self.init_ui()

    def init_ui(self):
        from PySide6.QtWidgets import QFormLayout, QMessageBox
        layout = QVBoxLayout(self)

        title = QLabel("📝 Migrate Plaintext Notes to Secure Vault")
        title.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)

        desc = QLabel(
            "Select your existing Notepad (.txt) file and choose a Master Password.\n"
            "An encrypted vault database will be created, and all credentials will be imported safely offline."
        )
        desc.setStyleSheet("color: #a6adc8; margin-bottom: 15px;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        form = QFormLayout()

        # Notes File
        notes_row = QHBoxLayout()
        self.notes_edit = QLineEdit(self.initial_notes_path)
        self.notes_edit.setPlaceholderText("Path to notes file (.txt)...")
        btn_browse_notes = QPushButton("Browse...")
        btn_browse_notes.clicked.connect(self.browse_notes)
        notes_row.addWidget(self.notes_edit)
        notes_row.addWidget(btn_browse_notes)
        form.addRow("1. Plaintext File:", notes_row)

        # Destination Vault File
        vault_row = QHBoxLayout()
        default_vault = os.path.join(os.path.expanduser("~"), "Desktop", "passwords.vault")
        self.vault_edit = QLineEdit(default_vault)
        btn_browse_vault = QPushButton("Browse...")
        btn_browse_vault.clicked.connect(self.browse_vault)
        vault_row.addWidget(self.vault_edit)
        vault_row.addWidget(btn_browse_vault)
        form.addRow("2. Encrypted Vault:", vault_row)

        # Master Password
        self.pwd_edit = QLineEdit()
        self.pwd_edit.setEchoMode(QLineEdit.Password)
        self.pwd_edit.setPlaceholderText("Choose a strong master password")
        form.addRow("3. Master Password:", self.pwd_edit)

        self.confirm_edit = QLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.Password)
        self.confirm_edit.setPlaceholderText("Confirm master password")
        form.addRow("4. Confirm Password:", self.confirm_edit)

        layout.addLayout(form)

        self.status_lbl = QLabel("")
        self.status_lbl.setStyleSheet("color: #f7768e;")
        layout.addWidget(self.status_lbl)

        btn_box = QHBoxLayout()
        btn_box.addStretch()
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        self.btn_import = QPushButton("Import & Open Vault")
        self.btn_import.setStyleSheet("background-color: #9ece6a; color: #1e1e2e; font-weight: bold; padding: 8px 20px;")
        self.btn_import.clicked.connect(self.process_import)
        btn_box.addWidget(btn_cancel)
        btn_box.addWidget(self.btn_import)
        layout.addLayout(btn_box)

    def browse_notes(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Notepad (.txt) File", "", "Text Files (*.txt *.md *.log);;All Files (*)")
        if path:
            self.notes_edit.setText(path)

    def browse_vault(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save New Vault File", self.vault_edit.text(), "Vault Files (*.vault);;All Files (*)")
        if path:
            self.vault_edit.setText(path)

    def process_import(self):
        notes_path = self.notes_edit.text().strip()
        vault_path = self.vault_edit.text().strip()
        pwd = self.pwd_edit.text()
        confirm = self.confirm_edit.text()

        if not os.path.exists(notes_path):
            self.status_lbl.setText("Notes file does not exist.")
            return
        if not vault_path:
            self.status_lbl.setText("Please specify a vault save path.")
            return
        if not pwd:
            self.status_lbl.setText("Please enter a master password.")
            return
        if pwd != confirm:
            self.status_lbl.setText("Passwords do not match.")
            return

        from src.core.vault import Vault
        from src.import_etl.extractor import read_notes_file, segment_notes
        from src.import_etl.llm_parser import LocalLLMParser
        from src.import_etl.validator import validate_candidate_entry
        from PySide6.QtWidgets import QMessageBox

        try:
            # 1. Read & parse notes
            content = read_notes_file(notes_path)
            parser = LocalLLMParser()
            chunks = segment_notes(content, max_chunk_chars=2000)

            raw_entries = []
            for c in chunks:
                raw_entries.extend(parser.regex_fallback_parse(c))

            valid_entries = []
            for r in raw_entries:
                res = validate_candidate_entry(r)
                if res["is_valid"]:
                    valid_entries.append(res["entry"])

            if not valid_entries:
                QMessageBox.warning(
                    self, "No Credentials Found",
                    "Could not detect site and password patterns in this file.\n"
                    "Please verify that entries contain a service name and password."
                )
                return

            # 2. Create the vault
            if os.path.exists(vault_path):
                os.remove(vault_path)
            kdf_sidecar = vault_path + ".kdf"
            if os.path.exists(kdf_sidecar):
                os.remove(kdf_sidecar)

            v = Vault()
            v.create_vault(vault_path, pwd)

            # 3. Add all entries
            for e in valid_entries:
                v.add_entry(e)
            v.close()

            QMessageBox.information(
                self, "Import Successful!",
                f"Successfully extracted and imported {len(valid_entries)} credentials\n"
                f"into your new encrypted vault:\n{vault_path}"
            )

            self.vault_path = vault_path
            self.master_pwd = pwd
            self.accept()

        except Exception as err:
            self.status_lbl.setText(f"Error during import: {err}")

    def get_result(self):
        return self.vault_path, self.master_pwd
