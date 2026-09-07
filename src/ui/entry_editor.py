import string
import secrets
from typing import Dict, Any, Optional
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, 
                               QLabel, QLineEdit, QPushButton, QTextEdit, 
                               QDialogButtonBox, QSlider, QCheckBox, QGroupBox)
from PySide6.QtCore import Qt

class PasswordGenerator(QGroupBox):
    def __init__(self, parent=None):
        super().__init__("Password Generator", parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Length slider
        length_layout = QHBoxLayout()
        self.length_label = QLabel("Length: 16")
        self.length_slider = QSlider(Qt.Horizontal)
        self.length_slider.setRange(8, 64)
        self.length_slider.setValue(16)
        self.length_slider.valueChanged.connect(self.on_length_changed)
        length_layout.addWidget(self.length_label)
        length_layout.addWidget(self.length_slider)
        layout.addLayout(length_layout)

        # Checkboxes
        opts_layout = QHBoxLayout()
        self.cb_upper = QCheckBox("A-Z")
        self.cb_upper.setChecked(True)
        self.cb_lower = QCheckBox("a-z")
        self.cb_lower.setChecked(True)
        self.cb_digits = QCheckBox("0-9")
        self.cb_digits.setChecked(True)
        self.cb_symbols = QCheckBox("!@#")
        self.cb_symbols.setChecked(True)
        
        for cb in [self.cb_upper, self.cb_lower, self.cb_digits, self.cb_symbols]:
            opts_layout.addWidget(cb)
        layout.addLayout(opts_layout)

        self.gen_btn = QPushButton("Generate")
        layout.addWidget(self.gen_btn)

    def on_length_changed(self, val):
        self.length_label.setText(f"Length: {val}")

    def generate(self) -> str:
        chars = ""
        if self.cb_upper.isChecked(): chars += string.ascii_uppercase
        if self.cb_lower.isChecked(): chars += string.ascii_lowercase
        if self.cb_digits.isChecked(): chars += string.digits
        if self.cb_symbols.isChecked(): chars += string.punctuation

        if not chars:
            chars = string.ascii_letters # fallback
        
        length = self.length_slider.value()
        return "".join(secrets.choice(chars) for _ in range(length))

class EntryEditorDialog(QDialog):
    def __init__(self, entry: Optional[Dict[str, Any]] = None, parent=None):
        super().__init__(parent)
        self.entry = entry or {}
        self.setWindowTitle("Edit Entry" if self.entry else "Add Entry")
        self.setMinimumWidth(400)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.site_input = QLineEdit(self.entry.get("site", ""))
        self.url_input = QLineEdit(self.entry.get("url", ""))
        self.username_input = QLineEdit(self.entry.get("username", ""))
        
        self.password_input = QLineEdit(self.entry.get("password", ""))
        self.password_input.setEchoMode(QLineEdit.Password)
        
        pwd_layout = QHBoxLayout()
        pwd_layout.addWidget(self.password_input)
        self.toggle_pwd_btn = QPushButton("👁")
        self.toggle_pwd_btn.setCheckable(True)
        self.toggle_pwd_btn.clicked.connect(self.toggle_password)
        pwd_layout.addWidget(self.toggle_pwd_btn)

        self.notes_input = QTextEdit(self.entry.get("notes", ""))
        self.tags_input = QLineEdit(", ".join(self.entry.get("tags", [])))
        self.tags_input.setPlaceholderText("Comma-separated tags")

        form.addRow("Site Name:", self.site_input)
        form.addRow("URL:", self.url_input)
        form.addRow("Username:", self.username_input)
        form.addRow("Password:", pwd_layout)
        form.addRow("Notes:", self.notes_input)
        form.addRow("Tags:", self.tags_input)
        layout.addLayout(form)

        self.generator = PasswordGenerator()
        self.generator.gen_btn.clicked.connect(self.on_generate)
        layout.addWidget(self.generator)

        # Buttons
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

    def toggle_password(self):
        if self.toggle_pwd_btn.isChecked():
            self.password_input.setEchoMode(QLineEdit.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.Password)

    def on_generate(self):
        pwd = self.generator.generate()
        self.password_input.setText(pwd)
        self.password_input.setEchoMode(QLineEdit.Normal)
        self.toggle_pwd_btn.setChecked(True)

    def get_entry_data(self) -> Dict[str, Any]:
        tags = [t.strip() for t in self.tags_input.text().split(",") if t.strip()]
        data = {
            "site": self.site_input.text(),
            "url": self.url_input.text(),
            "username": self.username_input.text(),
            "password": self.password_input.text(),
            "notes": self.notes_input.toPlainText(),
            "tags": tags
        }
        if "_id" in self.entry:
            data["_id"] = self.entry["_id"]
        return data
