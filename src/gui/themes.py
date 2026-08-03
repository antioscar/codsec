from __future__ import annotations

DARK_QSS = """
QMainWindow {
    background-color: #1e1e2e;
}
QToolBar {
    background-color: #252535;
    border-bottom: 1px solid #3a3a5a;
    padding: 4px;
    spacing: 6px;
}
QToolButton {
    background-color: #353555;
    color: #e8e8e8;
    border: 1px solid #4a4a6a;
    border-radius: 4px;
    padding: 6px 14px;
    font-size: 12px;
}
QToolButton:hover {
    background-color: #454575;
    border-color: #5a5a8a;
}
QToolButton:pressed {
    background-color: #2a2a4a;
}
QTabWidget::pane {
    border: 1px solid #3a3a5a;
    background-color: #1e1e2e;
}
QTabBar::tab {
    background-color: #252535;
    color: #a0a0b0;
    padding: 8px 20px;
    border: 1px solid #3a3a5a;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: #1e1e2e;
    color: #e8e8e8;
    border-bottom: 2px solid #569cd6;
}
QTableWidget {
    background-color: #1e1e2e;
    alternate-background-color: #252535;
    color: #e0e0e0;
    gridline-color: #3a3a5a;
    border: 1px solid #3a3a5a;
    font-size: 11px;
}
QTableWidget::item:selected {
    background-color: #264f78;
    color: #ffffff;
}
QHeaderView::section {
    background-color: #252535;
    color: #a0a0b0;
    padding: 6px;
    border: 1px solid #3a3a5a;
    font-weight: bold;
    font-size: 11px;
}
QPlainTextEdit {
    background-color: #16162a;
    color: #d4d4d4;
    border: 1px solid #3a3a5a;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 11px;
}
QGroupBox {
    color: #c0c0d0;
    border: 1px solid #3a3a5a;
    border-radius: 6px;
    margin-top: 8px;
    padding-top: 16px;
    font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
}
QPushButton {
    background-color: #353555;
    color: #e8e8e8;
    border: 1px solid #4a4a6a;
    border-radius: 4px;
    padding: 6px 16px;
    font-size: 12px;
}
QPushButton:hover {
    background-color: #454575;
}
QPushButton:pressed {
    background-color: #2a2a4a;
}
QPushButton#dashboardBtn {
    font-size: 13px;
    font-weight: bold;
    padding: 12px 24px;
    border-radius: 6px;
    min-height: 44px;
    min-width: 180px;
}
QLabel {
    color: #c0c0d0;
    font-size: 12px;
}
QCheckBox {
    color: #c0c0d0;
    font-size: 12px;
    spacing: 6px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #5a5a7a;
    border-radius: 3px;
    background-color: #252535;
}
QCheckBox::indicator:checked {
    background-color: #569cd6;
    border-color: #569cd6;
}
QComboBox {
    background-color: #252535;
    color: #e0e0e0;
    border: 1px solid #4a4a6a;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}
QComboBox::drop-down {
    border: none;
}
QComboBox QAbstractItemView {
    background-color: #252535;
    color: #e0e0e0;
    selection-background-color: #3a3a5a;
}
QLineEdit {
    background-color: #252535;
    color: #e0e0e0;
    border: 1px solid #4a4a6a;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}
QProgressBar {
    background-color: #252535;
    border: 1px solid #3a3a5a;
    border-radius: 4px;
    text-align: center;
    color: #e0e0e0;
    font-size: 11px;
}
QProgressBar::chunk {
    background-color: #569cd6;
    border-radius: 3px;
}
QStatusBar {
    background-color: #252535;
    color: #a0a0b0;
    border-top: 1px solid #3a3a5a;
}
QScrollBar:vertical {
    background-color: #1e1e2e;
    width: 10px;
    border: none;
}
QScrollBar::handle:vertical {
    background-color: #4a4a6a;
    border-radius: 5px;
    min-height: 20px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar:horizontal {
    background-color: #1e1e2e;
    height: 10px;
    border: none;
}
QScrollBar::handle:horizontal {
    background-color: #4a4a6a;
    border-radius: 5px;
    min-width: 20px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
QTableView {
    background-color: #1e1e2e;
    alternate-background-color: #252535;
    color: #e0e0e0;
    gridline-color: #3a3a5a;
    border: 1px solid #3a3a5a;
    font-size: 11px;
    selection-background-color: #264f78;
}
QHeaderView::section {
    background-color: #252535;
    color: #a0a0b0;
    padding: 6px;
    border: 1px solid #3a3a5a;
    font-weight: bold;
    font-size: 11px;
}
QTreeWidget {
    background-color: #1e1e2e;
    alternate-background-color: #252535;
    color: #e0e0e0;
    border: 1px solid #3a3a5a;
    font-size: 12px;
}
QTreeWidget::item {
    padding: 4px 6px;
}
QTreeWidget::item:selected {
    background-color: #264f78;
    color: #ffffff;
}
QChartView {
    background-color: #1e1e2e;
    border: 1px solid #3a3a5a;
    border-radius: 4px;
}
"""

LIGHT_QSS = """
QMainWindow {
    background-color: #f5f5f5;
}
QToolBar {
    background-color: #ffffff;
    border-bottom: 1px solid #e0e0e0;
    padding: 4px;
    spacing: 6px;
}
QToolButton {
    background-color: #e8e8e8;
    color: #212121;
    border: 1px solid #cccccc;
    border-radius: 4px;
    padding: 6px 14px;
    font-size: 12px;
}
QToolButton:hover {
    background-color: #d0d0d0;
    border-color: #aaaaaa;
}
QToolButton:pressed {
    background-color: #cccccc;
}
QTabWidget::pane {
    border: 1px solid #e0e0e0;
    background-color: #f5f5f5;
}
QTabBar::tab {
    background-color: #ffffff;
    color: #616161;
    padding: 8px 20px;
    border: 1px solid #e0e0e0;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: #f5f5f5;
    color: #212121;
    border-bottom: 2px solid #1976d2;
}
QTableWidget {
    background-color: #ffffff;
    alternate-background-color: #f5f5f5;
    color: #212121;
    gridline-color: #e0e0e0;
    border: 1px solid #e0e0e0;
    font-size: 11px;
}
QTableWidget::item:selected {
    background-color: #bbdefb;
    color: #212121;
}
QHeaderView::section {
    background-color: #f5f5f5;
    color: #616161;
    padding: 6px;
    border: 1px solid #e0e0e0;
    font-weight: bold;
    font-size: 11px;
}
QPlainTextEdit {
    background-color: #ffffff;
    color: #212121;
    border: 1px solid #e0e0e0;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 11px;
}
QGroupBox {
    color: #424242;
    border: 1px solid #e0e0e0;
    border-radius: 6px;
    margin-top: 8px;
    padding-top: 16px;
    font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
}
QPushButton {
    background-color: #e0e0e0;
    color: #212121;
    border: 1px solid #cccccc;
    border-radius: 4px;
    padding: 6px 16px;
    font-size: 12px;
}
QPushButton:hover {
    background-color: #d0d0d0;
}
QPushButton:pressed {
    background-color: #cccccc;
}
QPushButton#dashboardBtn {
    font-size: 13px;
    font-weight: bold;
    padding: 12px 24px;
    border-radius: 6px;
    min-height: 44px;
    min-width: 180px;
}
QLabel {
    color: #424242;
    font-size: 12px;
}
QCheckBox {
    color: #424242;
    font-size: 12px;
    spacing: 6px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #aaaaaa;
    border-radius: 3px;
    background-color: #ffffff;
}
QCheckBox::indicator:checked {
    background-color: #1976d2;
    border-color: #1976d2;
}
QComboBox {
    background-color: #ffffff;
    color: #212121;
    border: 1px solid #cccccc;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}
QComboBox::drop-down {
    border: none;
}
QComboBox QAbstractItemView {
    background-color: #ffffff;
    color: #212121;
    selection-background-color: #e0e0e0;
}
QLineEdit {
    background-color: #ffffff;
    color: #212121;
    border: 1px solid #cccccc;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}
QProgressBar {
    background-color: #e0e0e0;
    border: 1px solid #cccccc;
    border-radius: 4px;
    text-align: center;
    color: #212121;
    font-size: 11px;
}
QProgressBar::chunk {
    background-color: #1976d2;
    border-radius: 3px;
}
QStatusBar {
    background-color: #ffffff;
    color: #616161;
    border-top: 1px solid #e0e0e0;
}
QScrollBar:vertical {
    background-color: #f5f5f5;
    width: 10px;
    border: none;
}
QScrollBar::handle:vertical {
    background-color: #cccccc;
    border-radius: 5px;
    min-height: 20px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar:horizontal {
    background-color: #f5f5f5;
    height: 10px;
    border: none;
}
QScrollBar::handle:horizontal {
    background-color: #cccccc;
    border-radius: 5px;
    min-width: 20px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
QTableView {
    background-color: #ffffff;
    alternate-background-color: #f5f5f5;
    color: #212121;
    gridline-color: #e0e0e0;
    border: 1px solid #e0e0e0;
    font-size: 11px;
    selection-background-color: #bbdefb;
}
QHeaderView::section {
    background-color: #f5f5f5;
    color: #616161;
    padding: 6px;
    border: 1px solid #e0e0e0;
    font-weight: bold;
    font-size: 11px;
}
QTreeWidget {
    background-color: #ffffff;
    alternate-background-color: #f5f5f5;
    color: #212121;
    border: 1px solid #e0e0e0;
    font-size: 12px;
}
QTreeWidget::item {
    padding: 4px 6px;
}
QTreeWidget::item:selected {
    background-color: #bbdefb;
    color: #212121;
}
QChartView {
    background-color: #f5f5f5;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
}
"""


def apply_theme(app: "QApplication", theme: str) -> None:
    qss = DARK_QSS if theme == "dark" else LIGHT_QSS
    app.setStyleSheet(qss)
