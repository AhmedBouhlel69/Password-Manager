"""
Import Wizard Dialog for migrating plaintext notes into the encrypted vault.

Features:
1. Select plaintext notes file (.txt, .md, etc.)
2. Local parsing with Ollama LLM (if running) or Fast Heuristic Parser
3. Zero-telemetry network isolation via local_only_network_guard
4. Review & edit table with Confidence Badges (High/Medium/Low)
5. Duplicate detection against current vault entries
6. Secure multi-pass shredding of original plaintext file upon explicit confirmation
"""

import os
from typing import List, Dict, Any, Optional
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFileDialog,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox, QProgressBar,
    QCheckBox, QGroupBox, QComboBox, QLineEdit, QDialogButtonBox, QWidget
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor

from src.import_etl.extractor import read_notes_file, segment_notes
from src.import_etl.llm_parser import LocalLLMParser
from src.import_etl.validator import validate_candidate_entry
from src.import_etl.deduplicator import find_duplicate
from src.import_etl.secure_delete import secure_delete_file
from src.import_etl.network_guard import local_only_network_guard


class ParsingWorker(QThread):
    """Background worker to parse notes without blocking the UI thread."""
    progress = Signal(int, str)
    finished = Signal(list)
    error = Signal(str)

    def __init__(self, file_path: str, use_ollama: bool = False, model_name: str = "llama3.2:latest"):
        super().__init__()
        self.file_path = file_path
        self.use_ollama = use_ollama
        self.model_name = model_name

    def run(self):
        try:
            self.progress.emit(10, "Reading notes file...")
            content = read_notes_file(self.file_path)

            parser = LocalLLMParser(model=self.model_name)
            chunks = segment_notes(content, max_chunk_chars=2000)
            all_raw_entries = []

            ollama_available = self.use_ollama and parser.is_ollama_available()

            total_chunks = len(chunks)
            # Enforce network isolation during parsing — only localhost (Ollama) allowed
            with local_only_network_guard():
                for idx, chunk in enumerate(chunks, 1):
                    pct = int(10 + (idx / total_chunks) * 70)
                    if ollama_available:
                        self.progress.emit(pct, f"Ollama parsing section {idx}/{total_chunks}...")
                        extracted = parser.parse_chunk_with_ollama(chunk)
                    else:
                        self.progress.emit(pct, f"Pattern parsing section {idx}/{total_chunks}...")
                        extracted = parser.regex_fallback_parse(chunk)
                    all_raw_entries.extend(extracted)

            self.progress.emit(90, "Validating candidate credentials...")
            validated = []
            for raw in all_raw_entries:
                res = validate_candidate_entry(raw)
                if res["is_valid"]:
                    item = res["entry"]
                    item["_confidence"] = res["confidence"]
                    item["_score"] = res["score"]
                    item["_warnings"] = res["warnings"]
                    validated.append(item)

            self.progress.emit(100, "Done!")
            self.finished.emit(validated)
        except Exception as e:
            self.error.emit(str(e))


class ImportWizardDialog(QDialog):
    """Interactive GUI dialog to inspect, review, and import candidate logins."""

    entries_imported = Signal(int)

    def __init__(self, vault, parent=None):
        super().__init__(parent)
        self.vault = vault
        self.extracted_entries: List[Dict[str, Any]] = []
        self.selected_file_path: Optional[str] = None
        self.setWindowTitle("Import Credentials from Notes")
        self.resize(850, 580)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # 1. Header & Source File Selection
        file_box = QGroupBox("1. Select Plaintext Notes File")
        f_layout = QHBoxLayout(file_box)

        self.file_edit = QLineEdit()
        self.file_edit.setPlaceholderText("Select notes file (.txt, .md, etc.)...")
        self.file_edit.setReadOnly(True)
        self.browse_btn = QPushButton("Browse...")
        self.browse_btn.clicked.connect(self.browse_file)

        f_layout.addWidget(self.file_edit)
        f_layout.addWidget(self.browse_btn)
        layout.addWidget(file_box)

        # 2. Options (Ollama toggle)
        opt_box = QGroupBox("2. Parser Configuration")
        opt_layout = QHBoxLayout(opt_box)

        self.cb_ollama = QCheckBox("Use Local Ollama LLM (Offline, 127.0.0.1)")
        self.cb_ollama.setChecked(False)
        self.cb_ollama.setToolTip("Uses local llama3.2/mistral via Ollama on localhost. If unchecked, fast pattern extraction is used.")

        self.btn_start_extract = QPushButton("Extract Credentials")
        self.btn_start_extract.setStyleSheet("background-color: #9ece6a; color: #1e1e2e; font-weight: bold;")
        self.btn_start_extract.clicked.connect(self.start_extraction)
        self.btn_start_extract.setEnabled(False)

        opt_layout.addWidget(self.cb_ollama)
        opt_layout.addStretch()
        opt_layout.addWidget(self.btn_start_extract)
        layout.addWidget(opt_box)

        # Progress bar
        self.prog_bar = QProgressBar()
        self.prog_bar.setRange(0, 100)
        self.prog_bar.setValue(0)
        self.prog_bar.setTextVisible(True)
        self.prog_bar.hide()
        layout.addWidget(self.prog_bar)

        # 3. Review Table
        self.table_box = QGroupBox("3. Review Extracted Credentials (Edit or Remove Before Importing)")
        t_layout = QVBoxLayout(self.table_box)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Site / Service", "Username", "Password", "Notes", "Confidence", "Duplicate?"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        t_layout.addWidget(self.table)

        btn_row = QHBoxLayout()
        self.btn_delete_selected = QPushButton("Remove Selected Row")
        self.btn_delete_selected.clicked.connect(self.remove_selected_row)
        btn_row.addWidget(self.btn_delete_selected)
        btn_row.addStretch()
        self.status_lbl = QLabel("0 entries found.")
        btn_row.addWidget(self.status_lbl)
        t_layout.addLayout(btn_row)

        layout.addWidget(self.table_box)

        # 4. Final Import & Shred Action
        action_box = QGroupBox("4. Commit to Vault")
        a_layout = QHBoxLayout(action_box)

        self.cb_shred = QCheckBox("Securely shred (multi-pass overwrite) original notes file after import")
        self.cb_shred.setStyleSheet("color: #f7768e; font-weight: bold;")
        self.cb_shred.setChecked(False)

        self.btn_commit = QPushButton("Import to Vault")
        self.btn_commit.setStyleSheet("background-color: #7aa2f7; color: #1e1e2e; font-weight: bold; padding: 8px 24px;")
        self.btn_commit.setEnabled(False)
        self.btn_commit.clicked.connect(self.commit_import)

        a_layout.addWidget(self.cb_shred)
        a_layout.addStretch()
        a_layout.addWidget(self.btn_commit)
        layout.addWidget(action_box)

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Credentials Notes File", "",
            "Text and Markdown Files (*.txt *.md *.log);;All Files (*)"
        )
        if path:
            self.selected_file_path = path
            self.file_edit.setText(path)
            self.btn_start_extract.setEnabled(True)

    def start_extraction(self):
        if not self.selected_file_path:
            return

        self.btn_start_extract.setEnabled(False)
        self.prog_bar.show()
        self.prog_bar.setValue(5)
        self.prog_bar.setFormat("Initializing offline extraction...")

        self.worker = ParsingWorker(
            self.selected_file_path,
            use_ollama=self.cb_ollama.isChecked()
        )
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_finished)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_progress(self, val: int, msg: str):
        self.prog_bar.setValue(val)
        self.prog_bar.setFormat(msg)

    def on_finished(self, validated_entries: List[Dict[str, Any]]):
        self.prog_bar.hide()
        self.btn_start_extract.setEnabled(True)
        self.extracted_entries = validated_entries

        # Populate table
        self.populate_table()

    def on_error(self, err_msg: str):
        self.prog_bar.hide()
        self.btn_start_extract.setEnabled(True)
        QMessageBox.critical(self, "Extraction Error", f"Failed to extract credentials:\n{err_msg}")

    def populate_table(self):
        self.table.setRowCount(0)
        existing_entries = self.vault.list_entries() if self.vault.is_unlocked else []

        for row_idx, item in enumerate(self.extracted_entries):
            self.table.insertRow(row_idx)

            site_item = QTableWidgetItem(item.get("site", ""))
            user_item = QTableWidgetItem(item.get("username", ""))
            pass_item = QTableWidgetItem(item.get("password", ""))
            notes_item = QTableWidgetItem(item.get("notes", ""))

            conf = item.get("_confidence", "medium")
            conf_item = QTableWidgetItem(conf.upper())
            if conf == "high":
                conf_item.setForeground(QColor("#9ece6a"))
            elif conf == "medium":
                conf_item.setForeground(QColor("#e0af68"))
            else:
                conf_item.setForeground(QColor("#f7768e"))

            # Check duplicate against existing vault entries
            dup_match = find_duplicate(item, existing_entries)
            dup_text = f"Yes ({dup_match[0]['site']})" if dup_match else "No"
            dup_item = QTableWidgetItem(dup_text)
            if dup_match:
                dup_item.setForeground(QColor("#f7768e"))

            self.table.setItem(row_idx, 0, site_item)
            self.table.setItem(row_idx, 1, user_item)
            self.table.setItem(row_idx, 2, pass_item)
            self.table.setItem(row_idx, 3, notes_item)
            self.table.setItem(row_idx, 4, conf_item)
            self.table.setItem(row_idx, 5, dup_item)

        total = len(self.extracted_entries)
        self.status_lbl.setText(f"{total} candidate entries ready for review.")
        self.btn_commit.setEnabled(total > 0)

    def remove_selected_row(self):
        row = self.table.currentRow()
        if row >= 0:
            self.table.removeRow(row)
            if row < len(self.extracted_entries):
                self.extracted_entries.pop(row)
            self.status_lbl.setText(f"{self.table.rowCount()} candidate entries remaining.")
            self.btn_commit.setEnabled(self.table.rowCount() > 0)

    def commit_import(self):
        row_count = self.table.rowCount()
        if row_count == 0:
            return

        imported_count = 0
        for r in range(row_count):
            site = self.table.item(r, 0).text().strip()
            user = self.table.item(r, 1).text().strip()
            pwd = self.table.item(r, 2).text().strip()
            notes = self.table.item(r, 3).text().strip()

            if site and pwd:
                self.vault.add_entry({
                    "site": site,
                    "username": user,
                    "password": pwd,
                    "notes": notes,
                    "tags": ["imported"]
                })
                imported_count += 1

        # Secure delete if confirmed
        if self.cb_shred.isChecked() and self.selected_file_path:
            confirm = QMessageBox.warning(
                self, "Confirm Secure Shredding",
                f"Are you ABSOLUTELY sure you want to shred and delete:\n{self.selected_file_path}?\n\n"
                "This will perform a 3-pass overwrite and cannot be undone.",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if confirm == QMessageBox.Yes:
                try:
                    secure_delete_file(self.selected_file_path, confirmed=True)
                    QMessageBox.information(self, "Shred Complete", "Original notes file securely overwritten and deleted.")
                except Exception as e:
                    QMessageBox.warning(self, "Shred Warning", f"Could not shred file: {e}")

        QMessageBox.information(
            self, "Import Complete",
            f"Successfully imported {imported_count} credentials into your encrypted vault!"
        )
        self.entries_imported.emit(imported_count)
        self.accept()
