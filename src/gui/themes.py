from __future__ import annotations

DARK_QSS = """
QMainWindow {
    background-color: #1a1a2e;
}
QToolBar {
    background-color: #22223a;
    border-bottom: 1px solid #3a3a5c;
    padding: 4px;
    spacing: 6px;
}
QToolButton {
    background-color: #3d3d5c;
    color: #d4d4e4;
    border: 1px solid #4e4e6e;
    border-radius: 6px;
    padding: 6px 14px;
    font-size: 12px;
}
QToolButton:hover {
    background-color: #4e4e6e;
    border-color: #6a6a8a;
}
QToolButton:pressed {
    background-color: #2e2e4a;
}
QToolButton::menu-button {
    border: none;
}
QTabWidget::pane {
    border: 1px solid #3a3a5c;
    background-color: #1a1a2e;
}
QTabBar::tab {
    background-color: #22223a;
    color: #8a8aaa;
    padding: 8px 20px;
    border: 1px solid #3a3a5c;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: #1a1a2e;
    color: #e8e8f0;
    border-bottom: 2px solid #569cd6;
}
QTableWidget {
    background-color: #1a1a2e;
    alternate-background-color: #22223a;
    color: #d4d4e4;
    gridline-color: #3a3a5c;
    border: 1px solid #3a3a5c;
    font-size: 11px;
}
QTableWidget::item:selected {
    background-color: #264f78;
    color: #ffffff;
}
QHeaderView::section {
    background-color: #22223a;
    color: #8a8aaa;
    padding: 6px;
    border: 1px solid #3a3a5c;
    font-weight: bold;
    font-size: 11px;
}
QPlainTextEdit {
    background-color: #13132a;
    color: #d4d4d4;
    border: 1px solid #3a3a5c;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 11px;
}
QGroupBox {
    color: #b0b0c8;
    border: 1px solid #4a4a6a;
    border-radius: 8px;
    margin-top: 10px;
    padding-top: 18px;
    font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 14px;
    padding: 0 6px;
    color: #c0c0d8;
}
QPushButton {
    background-color: #3d3d5c;
    color: #d4d4e4;
    border: 1px solid #4e4e6e;
    border-radius: 6px;
    padding: 6px 16px;
    font-size: 12px;
}
QPushButton:hover {
    background-color: #4e4e6e;
    border-color: #6a6a8a;
}
QPushButton:pressed {
    background-color: #2e2e4a;
}
QPushButton:disabled {
    background-color: #2a2a42;
    color: #5a5a7a;
    border-color: #33334a;
}
QPushButton#dashboardBtn {
    font-size: 13px;
    font-weight: bold;
    padding: 12px 24px;
    border-radius: 8px;
    min-height: 44px;
    min-width: 180px;
}
QPushButton#dashboardBtn:hover {
    background-color: #5a5a7e;
    border-color: #7a7a9a;
}
QLabel {
    color: #b0b0c8;
    font-size: 12px;
}
QCheckBox {
    color: #b0b0c8;
    font-size: 12px;
    spacing: 6px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #5a5a7a;
    border-radius: 3px;
    background-color: #22223a;
}
QCheckBox::indicator:checked {
    background-color: #569cd6;
    border-color: #569cd6;
}
QComboBox {
    background-color: #22223a;
    color: #d4d4e4;
    border: 1px solid #4e4e6e;
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 12px;
}
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox QAbstractItemView {
    background-color: #22223a;
    color: #d4d4e4;
    selection-background-color: #3d3d5c;
    border: 1px solid #4e4e6e;
}
QLineEdit {
    background-color: #1e1e35;
    color: #d4d4e4;
    border: 1px solid #4e4e6e;
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 12px;
}
QLineEdit:focus {
    border-color: #569cd6;
}
QProgressBar {
    background-color: #1e1e35;
    border: 1px solid #3a3a5c;
    border-radius: 6px;
    text-align: center;
    color: #d4d4e4;
    font-size: 11px;
    height: 18px;
}
QProgressBar::chunk {
    background-color: #569cd6;
    border-radius: 5px;
}
QStatusBar {
    background-color: #22223a;
    color: #8a8aaa;
    border-top: 1px solid #3a3a5c;
}
QScrollBar:vertical {
    background-color: #1a1a2e;
    width: 10px;
    border: none;
}
QScrollBar::handle:vertical {
    background-color: #4a4a6a;
    border-radius: 5px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover {
    background-color: #5a5a7a;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar:horizontal {
    background-color: #1a1a2e;
    height: 10px;
    border: none;
}
QScrollBar::handle:horizontal {
    background-color: #4a4a6a;
    border-radius: 5px;
    min-width: 20px;
}
QScrollBar::handle:horizontal:hover {
    background-color: #5a5a7a;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
QTableView {
    background-color: #1a1a2e;
    alternate-background-color: #22223a;
    color: #d4d4e4;
    gridline-color: #3a3a5c;
    border: 1px solid #3a3a5c;
    font-size: 11px;
    selection-background-color: #264f78;
}
QHeaderView::section {
    background-color: #22223a;
    color: #8a8aaa;
    padding: 6px;
    border: 1px solid #3a3a5c;
    font-weight: bold;
    font-size: 11px;
}
QTreeWidget {
    background-color: #1a1a2e;
    alternate-background-color: #22223a;
    color: #d4d4e4;
    border: 1px solid #3a3a5c;
    font-size: 12px;
}
QTreeWidget::item {
    padding: 4px 6px;
}
QTreeWidget::item:selected {
    background-color: #264f78;
    color: #ffffff;
}
QTreeWidget::branch:has-children:!has-siblings:closed,
QTreeWidget::branch:closed:has-children:has-siblings {
    border-image: none;
}
QMenu {
    background-color: #22223a;
    color: #d4d4e4;
    border: 1px solid #4a4a6a;
    border-radius: 6px;
    padding: 4px;
}
QMenu::item {
    padding: 6px 24px;
    border-radius: 4px;
}
QMenu::item:selected {
    background-color: #3d3d5c;
}
QMenu::separator {
    height: 1px;
    background-color: #3a3a5c;
    margin: 4px 8px;
}
QChartView {
    background-color: #1a1a2e;
    border: 1px solid #3a3a5c;
    border-radius: 8px;
}
QListWidget {
    background-color: #1a1a2e;
    color: #d4d4e4;
    border: 1px solid #3a3a5c;
    border-radius: 6px;
}
QListWidget::item:selected {
    background-color: #264f78;
}
QToolTip {
    background-color: #2e2e4a;
    color: #d4d4e4;
    border: 1px solid #4a4a6a;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 11px;
}
QSplitter::handle {
    background-color: #3a3a5c;
    width: 2px;
}
QMessageBox {
    background-color: #1a1a2e;
    color: #d4d4e4;
}
QMessageBox QLabel {
    color: #d4d4e4;
}
"""

LIGHT_QSS = """
QMainWindow {
    background-color: #f0f2f5;
}
QToolBar {
    background-color: #ffffff;
    border-bottom: 1px solid #d0d0d0;
    padding: 4px;
    spacing: 6px;
}
QToolButton {
    background-color: #e8e8ec;
    color: #212121;
    border: 1px solid #c0c0c0;
    border-radius: 6px;
    padding: 6px 14px;
    font-size: 12px;
}
QToolButton:hover {
    background-color: #d4d4d8;
    border-color: #a0a0a0;
}
QToolButton:pressed {
    background-color: #c8c8cc;
}
QToolButton::menu-button {
    border: none;
}
QTabWidget::pane {
    border: 1px solid #d0d0d0;
    background-color: #f0f2f5;
}
QTabBar::tab {
    background-color: #ffffff;
    color: #616161;
    padding: 8px 20px;
    border: 1px solid #d0d0d0;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: #f0f2f5;
    color: #212121;
    border-bottom: 2px solid #1976d2;
}
QTableWidget {
    background-color: #ffffff;
    alternate-background-color: #f5f5f5;
    color: #212121;
    gridline-color: #d0d0d0;
    border: 1px solid #d0d0d0;
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
    border: 1px solid #d0d0d0;
    font-weight: bold;
    font-size: 11px;
}
QPlainTextEdit {
    background-color: #fafafa;
    color: #212121;
    border: 1px solid #d0d0d0;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 11px;
}
QGroupBox {
    color: #424242;
    border: 1px solid #c0c0c0;
    border-radius: 8px;
    margin-top: 10px;
    padding-top: 18px;
    font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 14px;
    padding: 0 6px;
}
QPushButton {
    background-color: #e8e8ec;
    color: #212121;
    border: 1px solid #c0c0c0;
    border-radius: 6px;
    padding: 6px 16px;
    font-size: 12px;
}
QPushButton:hover {
    background-color: #d4d4d8;
    border-color: #a0a0a0;
}
QPushButton:pressed {
    background-color: #c8c8cc;
}
QPushButton:disabled {
    background-color: #e8e8e8;
    color: #a0a0a0;
    border-color: #d0d0d0;
}
QPushButton#dashboardBtn {
    font-size: 13px;
    font-weight: bold;
    padding: 12px 24px;
    border-radius: 8px;
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
    border: 1px solid #a0a0a0;
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
    border: 1px solid #c0c0c0;
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 12px;
}
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox QAbstractItemView {
    background-color: #ffffff;
    color: #212121;
    selection-background-color: #e0e0e0;
    border: 1px solid #c0c0c0;
}
QLineEdit {
    background-color: #ffffff;
    color: #212121;
    border: 1px solid #c0c0c0;
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 12px;
}
QLineEdit:focus {
    border-color: #1976d2;
}
QProgressBar {
    background-color: #e8e8ec;
    border: 1px solid #c0c0c0;
    border-radius: 6px;
    text-align: center;
    color: #212121;
    font-size: 11px;
    height: 18px;
}
QProgressBar::chunk {
    background-color: #1976d2;
    border-radius: 5px;
}
QStatusBar {
    background-color: #ffffff;
    color: #616161;
    border-top: 1px solid #d0d0d0;
}
QScrollBar:vertical {
    background-color: #f0f2f5;
    width: 10px;
    border: none;
}
QScrollBar::handle:vertical {
    background-color: #c0c0c0;
    border-radius: 5px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover {
    background-color: #b0b0b0;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar:horizontal {
    background-color: #f0f2f5;
    height: 10px;
    border: none;
}
QScrollBar::handle:horizontal {
    background-color: #c0c0c0;
    border-radius: 5px;
    min-width: 20px;
}
QScrollBar::handle:horizontal:hover {
    background-color: #b0b0b0;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
QTableView {
    background-color: #ffffff;
    alternate-background-color: #f5f5f5;
    color: #212121;
    gridline-color: #d0d0d0;
    border: 1px solid #d0d0d0;
    font-size: 11px;
    selection-background-color: #bbdefb;
}
QHeaderView::section {
    background-color: #f5f5f5;
    color: #616161;
    padding: 6px;
    border: 1px solid #d0d0d0;
    font-weight: bold;
    font-size: 11px;
}
QTreeWidget {
    background-color: #ffffff;
    alternate-background-color: #f5f5f5;
    color: #212121;
    border: 1px solid #d0d0d0;
    font-size: 12px;
}
QTreeWidget::item {
    padding: 4px 6px;
}
QTreeWidget::item:selected {
    background-color: #bbdefb;
    color: #212121;
}
QMenu {
    background-color: #ffffff;
    color: #212121;
    border: 1px solid #d0d0d0;
    border-radius: 6px;
    padding: 4px;
}
QMenu::item {
    padding: 6px 24px;
    border-radius: 4px;
}
QMenu::item:selected {
    background-color: #e0e0e0;
}
QMenu::separator {
    height: 1px;
    background-color: #d0d0d0;
    margin: 4px 8px;
}
QChartView {
    background-color: #f0f2f5;
    border: 1px solid #d0d0d0;
    border-radius: 8px;
}
QListWidget {
    background-color: #ffffff;
    color: #212121;
    border: 1px solid #d0d0d0;
    border-radius: 6px;
}
QListWidget::item:selected {
    background-color: #bbdefb;
}
QToolTip {
    background-color: #ffffff;
    color: #212121;
    border: 1px solid #c0c0c0;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 11px;
}
QSplitter::handle {
    background-color: #d0d0d0;
    width: 2px;
}
QMessageBox {
    background-color: #ffffff;
    color: #212121;
}
QMessageBox QLabel {
    color: #212121;
}
"""


def apply_theme(app: "QApplication", theme: str) -> None:
    qss = DARK_QSS if theme == "dark" else LIGHT_QSS
    app.setStyleSheet(qss)
