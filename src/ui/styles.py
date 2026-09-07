def get_stylesheet() -> str:
    return """
    QWidget {
        background-color: #1e1e2e;
        color: #cdd6f4;
        font-family: 'Segoe UI', Arial, sans-serif;
        font-size: 14px;
    }
    QMainWindow, QDialog {
        background-color: #1e1e2e;
    }
    QPushButton {
        background-color: #7aa2f7;
        color: #1e1e2e;
        border: none;
        border-radius: 4px;
        padding: 6px 16px;
        font-weight: bold;
    }
    QPushButton:hover {
        background-color: #8db3f8;
    }
    QPushButton:pressed {
        background-color: #6991e6;
    }
    QPushButton:disabled {
        background-color: #45475a;
        color: #6c7086;
    }
    QLineEdit, QTextEdit, QListWidget, QComboBox, QSpinBox {
        background-color: #2a2a3e;
        border: 1px solid #45475a;
        border-radius: 4px;
        padding: 6px;
        color: #cdd6f4;
        selection-background-color: #7aa2f7;
        selection-color: #1e1e2e;
    }
    QLineEdit:focus, QTextEdit:focus, QListWidget:focus {
        border: 1px solid #7aa2f7;
    }
    QListWidget::item:selected {
        background-color: #7aa2f7;
        color: #1e1e2e;
        border-radius: 4px;
    }
    QListWidget::item:hover:!selected {
        background-color: #313244;
        border-radius: 4px;
    }
    QLabel {
        background: transparent;
    }
    QScrollBar:vertical {
        border: none;
        background: #1e1e2e;
        width: 10px;
        border-radius: 5px;
    }
    QScrollBar::handle:vertical {
        background: #45475a;
        min-height: 20px;
        border-radius: 5px;
    }
    QScrollBar::handle:vertical:hover {
        background: #585b70;
    }
    QScrollBar:horizontal {
        border: none;
        background: #1e1e2e;
        height: 10px;
        border-radius: 5px;
    }
    QScrollBar::handle:horizontal {
        background: #45475a;
        min-width: 20px;
        border-radius: 5px;
    }
    QScrollBar::handle:horizontal:hover {
        background: #585b70;
    }
    QProgressBar {
        border: 1px solid #45475a;
        border-radius: 4px;
        background-color: #2a2a3e;
        text-align: center;
        color: #cdd6f4;
    }
    QProgressBar::chunk {
        background-color: #9ece6a;
        border-radius: 3px;
    }
    QMenuBar, QMenu {
        background-color: #1e1e2e;
        color: #cdd6f4;
    }
    QMenuBar::item:selected, QMenu::item:selected {
        background-color: #313244;
    }
    QToolBar {
        background-color: #1e1e2e;
        border-bottom: 1px solid #313244;
    }
    QStatusBar {
        background-color: #1e1e2e;
        border-top: 1px solid #313244;
    }
    QGroupBox {
        border: 1px solid #45475a;
        border-radius: 4px;
        margin-top: 1em;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        left: 10px;
        padding: 0 3px 0 3px;
        color: #cdd6f4;
    }
    QTabWidget::pane {
        border: 1px solid #45475a;
        border-radius: 4px;
    }
    QTabBar::tab {
        background: #2a2a3e;
        color: #6c7086;
        padding: 6px 12px;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
        margin-right: 2px;
    }
    QTabBar::tab:selected {
        background: #7aa2f7;
        color: #1e1e2e;
    }
    QTabBar::tab:hover:!selected {
        background: #313244;
        color: #cdd6f4;
    }
    """

def get_icon_color() -> str:
    return "#cdd6f4"
