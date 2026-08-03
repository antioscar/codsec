from __future__ import annotations
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QSizePolicy,
    QPushButton, QCheckBox, QGridLayout,
)
from PySide6.QtCore import Qt, Signal, QTimer, QPropertyAnimation, QEasingCurve, Property
from PySide6.QtGui import QColor, QFont
from PySide6.QtCharts import QChart, QChartView, QBarSet, QBarSeries, QBarCategoryAxis, QValueAxis, QPieSeries, QPieSlice

from src.models import ScanReport, Severity

SEVERITY_NAMES = {
    Severity.CRITICAL: "Cr\u00edtica",
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

SEVERITY_HEX = {
    Severity.CRITICAL: QColor("#DC143C"),
    Severity.HIGH: QColor("#FF4500"),
    Severity.MEDIUM: QColor("#FFA500"),
    Severity.LOW: QColor("#228B22"),
}


class AnimatedLabel(QLabel):
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self._target = 0
        self._current = 0

    def _get_value(self):
        return self._current

    def _set_value(self, value):
        self._current = value
        self.setText(str(int(value)))

    value = Property(int, _get_value, _set_value)

    def animate_to(self, target: int):
        self._target = target
        self._anim = QPropertyAnimation(self, b"value")
        self._anim.setDuration(600)
        self._anim.setStartValue(self._current)
        self._anim.setEndValue(target)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.start()


class KpiCard(QFrame):
    def __init__(self, title: str, value: str, color: str, icon: str = "", parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        self.setMinimumSize(155, 90)
        self.setStyleSheet(
            f"KpiCard {{ background-color: {color}18; border: 1px solid {color}40; border-radius: 10px; }}"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(4)

        header = QHBoxLayout()
        if icon:
            icon_lbl = QLabel(icon)
            icon_lbl.setStyleSheet("font-size: 14px;")
            header.addWidget(icon_lbl)
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(f"color: {color}; font-size: 10px; font-weight: 600;")
        title_lbl.setTextFormat(Qt.TextFormat.PlainText)
        header.addWidget(title_lbl)
        header.addStretch()
        layout.addLayout(header)

        self.value_lbl = AnimatedLabel(value)
        self.value_lbl.setStyleSheet(f"color: {color}; font-size: 30px; font-weight: 800;")
        self.value_lbl.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.value_lbl)

    def set_value(self, value: str):
        self.value_lbl.setText(value)

    def animate_value(self, target: int):
        self.value_lbl.animate_to(target)


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

        self.stats_row = QHBoxLayout()
        self.stats_row.setSpacing(10)
        layout.addLayout(self.stats_row)

        self.cards_layout = QHBoxLayout()
        self.cards_layout.setSpacing(10)
        layout.addLayout(self.cards_layout)

        self.info_row = QHBoxLayout()
        self.info_label = QLabel()
        self.info_label.setStyleSheet("font-size: 11px;")
        self.info_label.setVisible(False)
        self.info_row.addWidget(self.info_label)
        self.info_row.addStretch()
        layout.addLayout(self.info_row)

        self.charts_layout = QHBoxLayout()
        self.charts_layout.setSpacing(10)

        self.chart_view = QChartView()
        self.chart_view.setMinimumHeight(240)
        self.chart_view.setVisible(False)
        self.charts_layout.addWidget(self.chart_view)

        self.donut_view = QChartView()
        self.donut_view.setMinimumHeight(240)
        self.donut_view.setVisible(False)
        self.charts_layout.addWidget(self.donut_view)

        layout.addLayout(self.charts_layout)

        self.top_findings_label = QLabel()
        self.top_findings_label.setVisible(False)
        self.top_findings_label.setStyleSheet("font-size: 11px; padding: 8px;")
        self.top_findings_label.setWordWrap(True)
        self.top_findings_label.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(self.top_findings_label)

        self.placeholder = QLabel("Seleccion\u00e1 un proyecto para comenzar el an\u00e1lisis")
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

        self.btn_select = QPushButton("\U0001f4c2 Seleccionar proyecto")
        self.btn_select.setObjectName("dashboardBtn")
        self.btn_select.clicked.connect(self.selectFolderRequested.emit)
        self._actions.addWidget(self.btn_select)

        self.btn_scan = QPushButton("\u25b6 Analizar")
        self.btn_scan.setObjectName("dashboardBtn")
        self.btn_scan.setEnabled(False)
        self.btn_scan.clicked.connect(self.scanRequested.emit)
        self._actions.addWidget(self.btn_scan)

        self.btn_pdf = QPushButton("\U0001f4c4 Generar PDF")
        self.btn_pdf.setObjectName("dashboardBtn")
        self.btn_pdf.setEnabled(False)
        self.btn_pdf.clicked.connect(self.pdfRequested.emit)
        self._actions.addWidget(self.btn_pdf)

        self.chk_llm = QCheckBox("\U0001f916 An\u00e1lisis con IA")
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

        for i in reversed(range(self.stats_row.count())):
            widget = self.stats_row.itemAt(i).widget()
            if widget:
                widget.deleteLater()

        sev_counts = report.by_severity
        dep_count = sum(1 for f in report.findings if f.category == "vulnerable_dependency")

        cards_data: list[tuple[str, str, str, str]] = [
            (str(len(sev_counts[Severity.CRITICAL])), SEVERITY_NAMES[Severity.CRITICAL], SEVERITY_COLORS[Severity.CRITICAL], "\ud83d\udd34"),
            (str(len(sev_counts[Severity.HIGH])), SEVERITY_NAMES[Severity.HIGH], SEVERITY_COLORS[Severity.HIGH], "\ud83d\udfe0"),
            (str(len(sev_counts[Severity.MEDIUM])), SEVERITY_NAMES[Severity.MEDIUM], SEVERITY_COLORS[Severity.MEDIUM], "\ud83d\udfe1"),
            (str(len(sev_counts[Severity.LOW])), SEVERITY_NAMES[Severity.LOW], SEVERITY_COLORS[Severity.LOW], "\ud83d\udfe2"),
            (str(dep_count), "Dep. Vulnerables", "#FF6347", "\ud83d\udce6"),
            (str(report.total_findings), "Total", "#569cd6", "\ud83d\udcca"),
        ]

        self._cards = []
        for value, title, color, icon in cards_data:
            card = KpiCard(title, value, color, icon)
            self.cards_layout.addWidget(card)
            self._cards.append(card)

        for card in self._cards:
            try:
                target = int(card.value_lbl.text())
            except ValueError:
                target = 0
            card.animate_value(target)

        self._build_stats_row(report)
        self._build_top_findings(report)

        self.info_label.setVisible(True)
        self.info_label.setText(
            f"Ruta: {report.target_path}  |  Archivos: {report.total_files_scanned}  |  "
            f"Duraci\u00f3n: {report.scan_duration_seconds:.2f}s"
        )

        self.chart_view.setVisible(True)
        self.donut_view.setVisible(True)
        self._build_bar_chart(sev_counts)
        self._build_donut_chart(sev_counts, dep_count)

    def _build_stats_row(self, report: ScanReport):
        languages = set()
        for f in report.findings:
            if f.language:
                languages.add(f.language)
        lang_count = len(languages) if languages else 1

        stats = [
            ("Archivos", str(report.total_files_scanned)),
            ("Lenguajes", str(lang_count)),
            ("Duraci\u00f3n", f"{report.scan_duration_seconds:.1f}s"),
            ("Densidad", f"{report.total_findings / max(report.total_files_scanned, 1):.1f}/arch"),
        ]

        for label, value in stats:
            lbl = QLabel(f"{label}\n{value}")
            lbl.setStyleSheet(
                "font-size: 10px; color: #8a8aaa; background: transparent; padding: 4px 12px; "
                "border-right: 1px solid #3a3a5c; text-align: center;"
            )
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setMinimumWidth(100)
            self.stats_row.addWidget(lbl)

    def _build_top_findings(self, report: ScanReport):
        by_sev = report.by_severity
        lines = []
        for sev in (Severity.CRITICAL, Severity.HIGH):
            findings = by_sev[sev][:3]
            if findings:
                color = SEVERITY_COLORS[sev]
                items = [f'<span style="color:{color};font-weight:bold;">{f.file_path.split("/")[-1]}:{f.line_number}</span> {f.category.replace("_"," ").title()}'
                         for f in findings]
                sev_name = SEVERITY_NAMES[sev]
                lines.append(f'<b style="color:{color};">{sev_name}:</b> {", ".join(items)}')

        if lines:
            self.top_findings_label.setText(" | ".join(lines))
        self.top_findings_label.setVisible(bool(lines))

    def _build_bar_chart(self, sev_counts: dict[Severity, list]):
        chart = QChart()
        chart.setTitle("Distribuci\u00f3n por severidad")
        chart.setAnimationOptions(QChart.AnimationOption.SeriesAnimations)

        is_dark = self._theme == "dark"
        bar_color = "#569cd6" if is_dark else "#1976d2"
        label_color = QColor("#a0a0b0") if is_dark else QColor("#616161")
        bg_color = QColor("#1a1a2e") if is_dark else QColor("#f0f2f5")
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

    def _build_donut_chart(self, sev_counts: dict[Severity, list], dep_count: int):
        chart = QChart()
        chart.setTitle("Proporci\u00f3n de hallazgos")
        chart.setAnimationOptions(QChart.AnimationOption.SeriesAnimations)

        series = QPieSeries()
        series.setHoleSize(0.45)

        total = sum(len(v) for v in sev_counts.values()) + dep_count
        if total == 0:
            total = 1

        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            count = len(sev_counts[sev])
            if count > 0:
                pct = count / total * 100
                name = SEVERITY_NAMES[sev]
                sl = series.append(f"{name} ({count})", count)
                sl.setColor(SEVERITY_HEX[sev])
                sl.setLabelVisible(True)
                sl.setLabelPosition(QPieSlice.LabelPosition.LabelOutside)
                sl.setLabelColor(QColor("#a0a0b0") if self._theme == "dark" else QColor("#616161"))

        if dep_count > 0:
            sl = series.append(f"Dep. Vuln. ({dep_count})", dep_count)
            sl.setColor(QColor("#FF6347"))
            sl.setLabelVisible(True)
            sl.setLabelPosition(QPieSlice.LabelPosition.LabelOutside)
            sl.setLabelColor(QColor("#a0a0b0") if self._theme == "dark" else QColor("#616161"))

        chart.addSeries(series)

        is_dark = self._theme == "dark"
        bg_color = QColor("#1a1a2e") if is_dark else QColor("#f0f2f5")
        title_color = QColor("#c0c0d0") if is_dark else QColor("#212121")
        chart.setBackgroundBrush(bg_color)
        chart.setTitleBrush(title_color)
        chart.legend().setVisible(False)

        self.donut_view.setChart(chart)
