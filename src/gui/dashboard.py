from __future__ import annotations
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QSizePolicy,
    QPushButton, QCheckBox,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtCharts import QChart, QChartView, QBarSet, QBarSeries, QBarCategoryAxis, QValueAxis

from src.models import ScanReport, Severity

SEVERITY_NAMES = {
    Severity.CRITICAL: "Crítica",
    Severity.HIGH: "Alta",
    Severity.MEDIUM: "Media",
    Severity.LOW: "Baja",
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "#DC143C",
    Severity.HIGH: "#FF4500",
    Severity.MEDIUM: "#FFA500",
    Severity.LOW: "#228B22",
}


class KpiCard(QFrame):
    def __init__(self, title: str, value: str, color: str, parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        self.setMinimumSize(160, 80)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(f"color: {color}; font-size: 11px; font-weight: bold;")
        layout.addWidget(title_lbl)

        value_lbl = QLabel(value)
        value_lbl.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: bold;")
        layout.addWidget(value_lbl)


class Dashboard(QWidget):
    selectFolderRequested = Signal()
    scanRequested = Signal()
    pdfRequested = Signal()
    llmToggled = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        self._setup_actions_bar()
        layout.addLayout(self._actions)

        self.cards_layout = QHBoxLayout()
        self.cards_layout.setSpacing(10)
        layout.addLayout(self.cards_layout)

        self.info_label = QLabel()
        self.info_label.setStyleSheet("font-size: 11px;")
        self.info_label.setVisible(False)
        layout.addWidget(self.info_label)

        self.chart_view = QChartView()
        self.chart_view.setMinimumHeight(250)
        self.chart_view.setVisible(False)
        layout.addWidget(self.chart_view)

        self.placeholder = QLabel("Seleccioná un proyecto para comenzar el análisis")
        self.placeholder.setStyleSheet("color: #6a6a8a; font-size: 16px;")
        self.placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.placeholder)

        layout.addStretch()

        self._report: ScanReport | None = None
        self._has_folder = False
        self._has_report = False
        self._theme = "dark"

    def set_theme(self, theme: str):
        self._theme = theme

    def _setup_actions_bar(self):
        self._actions = QHBoxLayout()
        self._actions.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._actions.setSpacing(12)

        self.btn_select = QPushButton("📂 Seleccionar proyecto")
        self.btn_select.setObjectName("dashboardBtn")
        self.btn_select.clicked.connect(self.selectFolderRequested.emit)
        self._actions.addWidget(self.btn_select)

        self.btn_scan = QPushButton("▶ Analizar")
        self.btn_scan.setObjectName("dashboardBtn")
        self.btn_scan.setEnabled(False)
        self.btn_scan.clicked.connect(self.scanRequested.emit)
        self._actions.addWidget(self.btn_scan)

        self.btn_pdf = QPushButton("📄 Generar PDF")
        self.btn_pdf.setObjectName("dashboardBtn")
        self.btn_pdf.setEnabled(False)
        self.btn_pdf.clicked.connect(self.pdfRequested.emit)
        self._actions.addWidget(self.btn_pdf)

        self.chk_llm = QCheckBox("🤖 Análisis con IA")
        self.chk_llm.toggled.connect(self.llmToggled.emit)
        self._actions.addWidget(self.chk_llm)

    def set_has_folder(self, has: bool):
        self._has_folder = has
        self.btn_scan.setEnabled(has)

    def set_has_report(self, has: bool):
        self._has_report = has
        self.btn_pdf.setEnabled(has)

    def set_llm_enabled(self, enabled: bool):
        self.chk_llm.blockSignals(True)
        self.chk_llm.setChecked(enabled)
        self.chk_llm.blockSignals(False)

    def set_report(self, report: ScanReport):
        self._report = report
        self.placeholder.setVisible(False)

        for i in reversed(range(self.cards_layout.count())):
            widget = self.cards_layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()

        sev_counts = report.by_severity
        dep_count = sum(1 for f in report.findings if f.category == "vulnerable_dependency")
        cards_data = [
            ("CRÍTICAS", str(len(sev_counts[Severity.CRITICAL])), SEVERITY_COLORS[Severity.CRITICAL]),
            ("ALTAS", str(len(sev_counts[Severity.HIGH])), SEVERITY_COLORS[Severity.HIGH]),
            ("MEDIAS", str(len(sev_counts[Severity.MEDIUM])), SEVERITY_COLORS[Severity.MEDIUM]),
            ("BAJAS", str(len(sev_counts[Severity.LOW])), SEVERITY_COLORS[Severity.LOW]),
            ("DEP. VULN.", str(dep_count), "#FF6347"),
            ("TOTAL", str(report.total_findings), "#569cd6"),
        ]
        for title, value, color in cards_data:
            card = KpiCard(title, value, color)
            self.cards_layout.addWidget(card)

        self.info_label.setVisible(True)
        self.info_label.setText(
            f"Ruta: {report.target_path}  |  Archivos: {report.total_files_scanned}  |  Duración: {report.scan_duration_seconds:.2f}s"
        )

        self.chart_view.setVisible(True)
        self._build_chart(sev_counts)

    def _build_chart(self, sev_counts: dict[Severity, list]):
        chart = QChart()
        chart.setTitle("Distribución por severidad")
        chart.setAnimationOptions(QChart.AnimationOption.SeriesAnimations)

        is_dark = self._theme == "dark"
        bar_color = "#569cd6" if is_dark else "#1976d2"
        label_color = QColor("#a0a0b0") if is_dark else QColor("#616161")
        bg_color = QColor("#1e1e2e") if is_dark else QColor("#f5f5f5")
        title_color = QColor("#c0c0d0") if is_dark else QColor("#212121")

        bar_set = QBarSet("Hallazgos")
        bar_set.setColor(bar_color)

        categories = []
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            bar_set.append(len(sev_counts[sev]))
            categories.append(SEVERITY_NAMES[sev])

        series = QBarSeries()
        series.append(bar_set)
        chart.addSeries(series)

        axis_x = QBarCategoryAxis()
        axis_x.append(categories)
        axis_x.setLabelsColor(label_color)
        chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
        series.attachAxis(axis_x)

        axis_y = QValueAxis()
        max_val = max(max(len(sev_counts[s]) for s in sev_counts), 1)
        axis_y.setRange(0, max_val + 2)
        axis_y.setLabelsColor(label_color)
        axis_y.setLabelFormat("%d")
        chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
        series.attachAxis(axis_y)

        chart.setBackgroundBrush(bg_color)
        chart.setTitleBrush(title_color)
        chart.legend().setVisible(False)

        self.chart_view.setChart(chart)
