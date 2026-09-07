from typing import Dict, Any, List
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QListWidget, 
                               QListWidgetItem, QLineEdit, QLabel, QPushButton, 
                               QSplitter, QFormLayout, QTextBrowser, QApplication)
from PySide6.QtCore import Signal, Qt, QEvent
from PySide6.QtGui import QShortcut, QKeySequence

class VaultView(QWidget):
    entry_selected = Signal(str) # entry_id
    edit_requested = Signal(str)
    delete_requested = Signal(str)
    copy_password_requested = Signal(str)
    copy_username_requested = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_entry_id = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Splitter for left and right panels
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)

        # Left Panel (List)
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search (Ctrl+F)...")
        self.search_bar.setAccessibleName("Search vault entries")
        self.search_bar.setAccessibleDescription("Filter password entries by site or username")
        self.search_bar.textChanged.connect(self.on_search)
        left_layout.addWidget(self.search_bar)

        self.list_widget = QListWidget()
        self.list_widget.setAccessibleName("Vault entries list")
        self.list_widget.setAccessibleDescription("List of saved credentials. Use arrow keys to select, Enter to edit, Delete to remove.")
        self.list_widget.itemSelectionChanged.connect(self.on_selection_changed)
        self.list_widget.itemDoubleClicked.connect(lambda: self.edit_requested.emit(self.current_entry_id) if self.current_entry_id else None)
        self.list_widget.installEventFilter(self)
        left_layout.addWidget(self.list_widget)

        splitter.addWidget(left_widget)

        # Right Panel (Details)
        self.right_widget = QWidget()
        self.right_layout = QVBoxLayout(self.right_widget)
        self.right_layout.setContentsMargins(10, 0, 0, 0)

        # Toolbar for details
        toolbar_layout = QHBoxLayout()
        self.edit_btn = QPushButton("Edit (Enter)")
        self.edit_btn.setAccessibleName("Edit selected entry")
        self.delete_btn = QPushButton("Delete (Del)")
        self.delete_btn.setAccessibleName("Delete selected entry")
        self.edit_btn.clicked.connect(lambda: self.edit_requested.emit(self.current_entry_id) if self.current_entry_id else None)
        self.delete_btn.clicked.connect(lambda: self.delete_requested.emit(self.current_entry_id) if self.current_entry_id else None)
        toolbar_layout.addStretch()
        toolbar_layout.addWidget(self.edit_btn)
        toolbar_layout.addWidget(self.delete_btn)
        self.right_layout.addLayout(toolbar_layout)

        # Details form
        self.details_form = QFormLayout()
        
        self.lbl_site = QLabel()
        self.lbl_site.setStyleSheet("font-size: 18px; font-weight: bold;")
        self.right_layout.addWidget(self.lbl_site)

        self.lbl_url = QLabel()
        self.lbl_url.setOpenExternalLinks(True)
        self.details_form.addRow("URL:", self.lbl_url)

        user_layout = QHBoxLayout()
        self.lbl_username = QLabel()
        self.copy_user_btn = QPushButton("Copy")
        self.copy_user_btn.setAccessibleName("Copy username to clipboard")
        self.copy_user_btn.clicked.connect(lambda: self.copy_username_requested.emit(self.current_entry_id) if self.current_entry_id else None)
        user_layout.addWidget(self.lbl_username)
        user_layout.addWidget(self.copy_user_btn)
        self.details_form.addRow("Username:", user_layout)

        pwd_layout = QHBoxLayout()
        self.lbl_password = QLabel("********")
        self.copy_pwd_btn = QPushButton("Copy Password")
        self.copy_pwd_btn.setAccessibleName("Copy password to clipboard")
        self.copy_pwd_btn.clicked.connect(lambda: self.copy_password_requested.emit(self.current_entry_id) if self.current_entry_id else None)
        self.show_pwd_btn = QPushButton("Show")
        self.show_pwd_btn.setAccessibleName("Toggle show or hide password")
        self.show_pwd_btn.setCheckable(True)
        self.show_pwd_btn.clicked.connect(self.toggle_password_display)
        pwd_layout.addWidget(self.lbl_password)
        pwd_layout.addWidget(self.show_pwd_btn)
        pwd_layout.addWidget(self.copy_pwd_btn)
        self.details_form.addRow("Password:", pwd_layout)

        self.lbl_tags = QLabel()
        self.details_form.addRow("Tags:", self.lbl_tags)

        self.right_layout.addLayout(self.details_form)
        
        self.right_layout.addWidget(QLabel("Notes:"))
        self.txt_notes = QTextBrowser()
        self.txt_notes.setAccessibleName("Entry notes")
        self.right_layout.addWidget(self.txt_notes)

        self.lbl_meta = QLabel()
        self.lbl_meta.setStyleSheet("color: #6c7086; font-size: 11px;")
        self.right_layout.addWidget(self.lbl_meta)

        splitter.addWidget(self.right_widget)
        splitter.setSizes([300, 500])

        # Shortcuts
        self.search_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        self.search_shortcut.activated.connect(self.search_bar.setFocus)

        self.copy_pwd_shortcut = QShortcut(QKeySequence("Ctrl+C"), self)
        self.copy_pwd_shortcut.activated.connect(self._handle_copy_pwd_shortcut)

        self.copy_user_shortcut = QShortcut(QKeySequence("Ctrl+Shift+C"), self)
        self.copy_user_shortcut.activated.connect(lambda: self.copy_username_requested.emit(self.current_entry_id) if self.current_entry_id else None)

        self.clear_details()

    def eventFilter(self, obj, event):
        if obj is self.list_widget and event.type() == QEvent.KeyPress:
            if event.key() in (Qt.Key_Return, Qt.Key_Enter):
                if self.current_entry_id:
                    self.edit_requested.emit(self.current_entry_id)
                    return True
            elif event.key() == Qt.Key_Delete:
                if self.current_entry_id:
                    self.delete_requested.emit(self.current_entry_id)
                    return True
        return super().eventFilter(obj, event)

    def _handle_copy_pwd_shortcut(self):
        focus = QApplication.focusWidget()
        if isinstance(focus, (QLineEdit, QTextBrowser)) and focus.hasSelectedText():
            return
        if self.current_entry_id:
            self.copy_password_requested.emit(self.current_entry_id)

    def set_entries(self, entries: List[Dict[str, Any]]):
        self.list_widget.clear()
        for entry in entries:
            item = QListWidgetItem(f"{entry.get('site', 'Unknown')} ({entry.get('username', '')})")
            item.setData(Qt.UserRole, entry)
            self.list_widget.addItem(item)
        if self.current_entry_id:
            self.select_entry(self.current_entry_id)

    def on_search(self, text):
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            entry = item.data(Qt.UserRole)
            match = text.lower() in entry.get('site', '').lower() or text.lower() in entry.get('username', '').lower()
            item.setHidden(not match)

    def on_selection_changed(self):
        items = self.list_widget.selectedItems()
        if not items:
            self.clear_details()
            return
        
        entry = items[0].data(Qt.UserRole)
        self.current_entry_id = entry.get("_id")
        self._current_password = entry.get("password", "")
        
        self.lbl_site.setText(entry.get("site", ""))
        url = entry.get("url", "")
        self.lbl_url.setText(f'<a href="{url}">{url}</a>' if url else "")
        self.lbl_username.setText(entry.get("username", ""))
        self.lbl_password.setText("********")
        self.show_pwd_btn.setChecked(False)
        self.show_pwd_btn.setText("Show")
        self.lbl_tags.setText(", ".join(entry.get("tags", [])))
        self.txt_notes.setText(entry.get("notes", ""))
        
        created = entry.get("_created_at", "")
        updated = entry.get("_updated_at", "")
        self.lbl_meta.setText(f"Created: {created} | Updated: {updated}")
        
        self.right_widget.setEnabled(True)
        self.entry_selected.emit(self.current_entry_id)

    def toggle_password_display(self):
        if self.show_pwd_btn.isChecked():
            self.lbl_password.setText(getattr(self, "_current_password", ""))
            self.show_pwd_btn.setText("Hide")
        else:
            self.lbl_password.setText("********")
            self.show_pwd_btn.setText("Show")

    def clear_details(self):
        self.current_entry_id = None
        self.right_widget.setEnabled(False)
        self.lbl_site.clear()
        self.lbl_url.clear()
        self.lbl_username.clear()
        self.lbl_password.clear()
        self.lbl_tags.clear()
        self.txt_notes.clear()
        self.lbl_meta.clear()

    def select_entry(self, entry_id: str):
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            if item.data(Qt.UserRole).get("_id") == entry_id:
                self.list_widget.setCurrentItem(item)
                break
