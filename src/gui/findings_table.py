from __future__ import annotations
import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTableView,
    QHeaderView, QCheckBox, QComboBox, QLineEdit, QLabel,
    QAbstractItemView, QGroupBox, QTextEdit, QStackedWidget,
    QApplication, QMenu, QPushButton,
)
from PySide6.QtCore import Qt, QSortFilterProxyModel, QAbstractTableModel, QModelIndex, Signal
from PySide6.QtGui import QColor

from src.models import Finding, Severity
from src.gui.code_viewer import CodeViewer

SEVERITY_COLORS_QCOLOR = {
    Severity.CRITICAL: QColor("#DC143C"),
    Severity.HIGH: QColor("#FF4500"),
    Severity.MEDIUM: QColor("#FFA500"),
    Severity.LOW: QColor("#228B22"),
}

SEVERITY_BG = {
    Severity.CRITICAL: QColor("#FDE8E8"),
    Severity.HIGH: QColor("#FFF3E0"),
    Severity.MEDIUM: QColor("#FFF8E1"),
    Severity.LOW: QColor("#E8F5E9"),
}


class FindingsModel(QAbstractTableModel):
    COLUMNS = ["ID", "Severidad", "Categoría", "CWE", "Archivo", "Línea", "Confianza"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._findings: list[Finding] = []

    def set_findings(self, findings: list[Finding]):
        self.beginResetModel()
        self._findings = sorted(findings, key=lambda f: (f.severity.order, f.category))
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self._findings)

    def columnCount(self, parent=QModelIndex()):
        return len(self.COLUMNS)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        finding = self._findings[index.row()]

        if role == Qt.ItemDataRole.DisplayRole:
            col = index.column()
            if col == 0:
                return finding.id
            elif col == 1:
                return str(finding.severity)
            elif col == 2:
                return finding.category.replace("_", " ").title()
            elif col == 3:
                return finding.cwe
            elif col == 4:
                return os.path.basename(finding.file_path)
            elif col == 5:
                return str(finding.line_number)
            elif col == 6:
                labels = {"high": self.tr("Alta"), "medium": self.tr("Media"), "low": self.tr("Baja")}
                return labels.get(finding.confidence, finding.confidence)

        if role == Qt.ItemDataRole.ForegroundRole:
            if index.column() == 1:
                return SEVERITY_COLORS_QCOLOR.get(finding.severity, QColor("#ffffff"))

        if role == Qt.ItemDataRole.BackgroundRole:
            if index.column() == 1:
                return SEVERITY_BG.get(finding.severity)

        if role == Qt.ItemDataRole.FontRole:
            if index.column() == 1:
                font = self.parent().font() if self.parent() else None
                if font:
                    font.setBold(True)
                    return font

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if index.column() in (5,):
                return Qt.AlignmentFlag.AlignCenter

        if role == Qt.ItemDataRole.UserRole:
            return finding.file_path

        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.tr(self.COLUMNS[section])

        return None

    def get_finding(self, row: int) -> Finding | None:
        if 0 <= row < len(self._findings):
            return self._findings[row]
        return None


class FindingsTable(QWidget):
    findingSelected = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._findings: list[Finding] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.filter_widget = QWidget()
        filter_layout = QHBoxLayout(self.filter_widget)
        filter_layout.setContentsMargins(8, 4, 8, 4)

        self.chk_critical = QCheckBox(self.tr("Crítica"))
        self.chk_critical.setChecked(True)
        self.chk_high = QCheckBox(self.tr("Alta"))
        self.chk_high.setChecked(True)
        self.chk_medium = QCheckBox(self.tr("Media"))
        self.chk_medium.setChecked(True)
        self.chk_low = QCheckBox(self.tr("Baja"))
        self.chk_low.setChecked(True)

        for cb in [self.chk_critical, self.chk_high, self.chk_medium, self.chk_low]:
            cb.toggled.connect(self._apply_filters)

        filter_layout.addWidget(self.chk_critical)
        filter_layout.addWidget(self.chk_high)
        filter_layout.addWidget(self.chk_medium)
        filter_layout.addWidget(self.chk_low)
        filter_layout.addSpacing(20)

        filter_layout.addWidget(QLabel(self.tr("Categoría:")))
        self.cmb_category = QComboBox()
        self.cmb_category.addItem(self.tr("Todas"))
        self.cmb_category.currentTextChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.cmb_category)

        filter_layout.addSpacing(10)
        filter_layout.addWidget(QLabel(self.tr("Buscar:")))
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText(self.tr("Buscar archivo, CWE..."))
        self.txt_search.textChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.txt_search)

        self._filter_widgets = [self.chk_critical, self.chk_high, self.chk_medium, self.chk_low,
                                self.cmb_category, self.txt_search]
        for i in range(filter_layout.count()):
            widget = filter_layout.itemAt(i).widget()
            if widget is not None and isinstance(widget, QLabel):
                self._filter_widgets.append(widget)

        self.btn_toggle_filters = QPushButton(self.tr("▼"))
        self.btn_toggle_filters.setFixedWidth(28)
        self.btn_toggle_filters.clicked.connect(self._toggle_filters)
        filter_layout.addWidget(self.btn_toggle_filters)
        self._filters_expanded = True

        layout.addWidget(self.filter_widget)

        self.empty_label = QLabel(self.tr("Ejecute un análisis para ver los hallazgos"))
        self.empty_label.setStyleSheet("color: #6a6a8a; font-size: 16px;")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.empty_label)

        self._content = QWidget()
        content_layout = QVBoxLayout(self._content)
        content_layout.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self.model = FindingsModel()
        self.proxy_model = QSortFilterProxyModel()
        self.proxy_model.setSourceModel(self.model)
        self.proxy_model.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy_model.setFilterKeyColumn(-1)

        self.table = QTableView()
        self.table.setModel(self.proxy_model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 100)
        self.table.setColumnWidth(1, 90)
        self.table.setColumnWidth(2, 160)
        self.table.setColumnWidth(3, 90)
        self.table.setColumnWidth(4, 180)
        self.table.setColumnWidth(5, 60)
        self.table.selectionModel().selectionChanged.connect(self._on_selection_changed)

        bottom_splitter = QSplitter(Qt.Orientation.Horizontal)

        self.code_viewer = CodeViewer()
        self.detail_panel = QGroupBox(self.tr("Detalle del hallazgo"))
        detail_layout = QVBoxLayout(self.detail_panel)
        self.lbl_title = QLabel()
        self.lbl_title.setWordWrap(True)
        self.lbl_title.setOpenExternalLinks(True)
        self.lbl_title.setStyleSheet("font-size: 13px; font-weight: bold;")
        detail_layout.addWidget(self.lbl_title)

        self.lbl_description = QLabel()
        self.lbl_description.setWordWrap(True)
        detail_layout.addWidget(self.lbl_description)

        self.txt_remediation = QTextEdit()
        self.txt_remediation.setReadOnly(True)
        self.txt_remediation.setMaximumHeight(200)
        detail_layout.addWidget(QLabel(self.tr("Remediación:")))
        detail_layout.addWidget(self.txt_remediation)

        self.btn_copy_remediation = QPushButton(self.tr("📋 Copiar remediación"))
        self.btn_copy_remediation.clicked.connect(self._copy_remediation)
        detail_layout.addWidget(self.btn_copy_remediation)
        detail_layout.addStretch()

        bottom_splitter.addWidget(self.code_viewer)
        bottom_splitter.addWidget(self.detail_panel)
        bottom_splitter.setStretchFactor(0, 3)
        bottom_splitter.setStretchFactor(1, 2)

        splitter.addWidget(self.table)
        splitter.addWidget(bottom_splitter)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        content_layout.addWidget(splitter)
        layout.addWidget(self._content)

    def _show_context_menu(self, pos):
        menu = QMenu(self.table)

        action_copy_paths = menu.addAction(self.tr("Copiar ruta(s) al portapapeles"))
        action_filter = menu.addAction(self.tr("Filtrar por esta categoría"))
        menu.addSeparator()
        action_select_all = menu.addAction(self.tr("Seleccionar todas"))
        action_deselect_all = menu.addAction(self.tr("Deseleccionar todas"))

        action = menu.exec(self.table.mapToGlobal(pos))

        if action == action_copy_paths:
            lines = []
            for idx in self.table.selectionModel().selectedRows():
                source_idx = self.proxy_model.mapToSource(idx)
                finding = self.model.get_finding(source_idx.row())
                if finding:
                    lines.append(f"{finding.file_path}:{finding.line_number}")
            if lines:
                QApplication.clipboard().setText("\n".join(lines))

        elif action == action_filter:
            indexes = self.table.selectionModel().selectedRows()
            if indexes:
                source_idx = self.proxy_model.mapToSource(indexes[0])
                finding = self.model.get_finding(source_idx.row())
                if finding:
                    cat_text = finding.category.replace("_", " ").title()
                    idx = self.cmb_category.findText(cat_text)
                    if idx >= 0:
                        self.cmb_category.setCurrentIndex(idx)

        elif action == action_select_all:
            self.table.selectAll()

        elif action == action_deselect_all:
            self.table.clearSelection()

    def _toggle_filters(self):
        self._filters_expanded = not self._filters_expanded
        self.btn_toggle_filters.setText(self.tr("▼") if self._filters_expanded else self.tr("▲"))
        for widget in self._filter_widgets:
            widget.setVisible(self._filters_expanded)

    def _copy_remediation(self):
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return
        source_idx = self.proxy_model.mapToSource(indexes[0])
        finding = self.model.get_finding(source_idx.row())
        if finding:
            QApplication.clipboard().setText(finding.remediation)

    def set_findings(self, findings: list[Finding]):
        self._findings = findings
        self.model.set_findings(findings)

        has_findings = len(findings) > 0
        self._content.setVisible(has_findings)
        self.empty_label.setVisible(not has_findings)

        has_findings = len(findings) > 0
        self.empty_label.setVisible(not has_findings)

        categories = sorted(set(f.category for f in findings))
        self.cmb_category.blockSignals(True)
        self.cmb_category.clear()
        self.cmb_category.addItem(self.tr("Todas"))
        for cat in categories:
            self.cmb_category.addItem(cat.replace("_", " ").title(), cat)
        self.cmb_category.blockSignals(False)

    def _apply_filters(self):
        proxy = self.proxy_model
        filters = []

        sev_filter = []
        if self.chk_critical.isChecked():
            sev_filter.append(self.tr("Crítica"))
        if self.chk_high.isChecked():
            sev_filter.append(self.tr("Alta"))
        if self.chk_medium.isChecked():
            sev_filter.append(self.tr("Media"))
        if self.chk_low.isChecked():
            sev_filter.append(self.tr("Baja"))

        category = self.cmb_category.currentData() or self.cmb_category.currentText().lower().replace(" ", "_")
        search = self.txt_search.text().strip()

        for row in range(self.model.rowCount()):
            finding = self.model.get_finding(row)
            if finding is None:
                continue
            visible = True

            if str(finding.severity) not in sev_filter:
                visible = False

            if category and category != self.tr("todas") and finding.category != category:
                visible = False

            if search:
                search_lower = search.lower()
                if (search_lower not in finding.file_path.lower()
                        and search_lower not in finding.cwe.lower()
                        and search_lower not in finding.category.lower()):
                    visible = False

            source_idx = self.model.index(row, 0)
            proxy_idx = proxy.mapFromSource(source_idx)
            self.table.setRowHidden(proxy_idx.row(), not visible)

    def _on_selection_changed(self, selected, deselected):
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return
        proxy_idx = indexes[0]
        source_idx = self.proxy_model.mapToSource(proxy_idx)
        finding = self.model.get_finding(source_idx.row())
        if finding is None:
            return

        self.findingSelected.emit(finding)

        color = SEVERITY_COLORS_QCOLOR.get(finding.severity, QColor("#ffffff")).name()
        cwe_display = finding.cwe
        if finding.cwe.startswith("CWE-"):
            cwe_num = finding.cwe[4:]
            cwe_display = f"<a href='https://cwe.mitre.org/data/definitions/{cwe_num}.html'>{finding.cwe}</a>"
        self.lbl_title.setText(
            f"[<span style='color:{color};font-weight:bold;'>{str(finding.severity).upper()}</span>] "
            f"{finding.category.replace('_', ' ').title()} — {cwe_display}"
        )
        self.lbl_description.setText(self.tr("<b>Descripción:</b> {}").format(finding.description))

        remediation_html = finding.remediation.replace("\n", "<br>")
        self.txt_remediation.setHtml(remediation_html)

        try:
            with open(finding.file_path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
            self.code_viewer.set_source(source, finding.language)
            self.code_viewer.set_highlighted_line(finding.line_number,
                                                  SEVERITY_COLORS_QCOLOR.get(finding.severity))

            cursor = self.code_viewer.textCursor()
            block = self.code_viewer.document().findBlockByNumber(finding.line_number - 1)
            if block.isValid():
                cursor.setPosition(block.position())
                self.code_viewer.setTextCursor(cursor)
                self.code_viewer.centerCursor()
        except Exception:
            self.code_viewer.set_source(finding.code_snippet, finding.language)
