from __future__ import annotations
import pytest
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt


@pytest.fixture(scope="module")
def qapp():
    import sys
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app


def test_gui_imports():
    from PySide6.QtWidgets import QApplication
    import sys

    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)

    from src.gui.themes import DARK_QSS, LIGHT_QSS, apply_theme
    assert len(DARK_QSS) > 100
    assert len(LIGHT_QSS) > 100

    from src.gui.scan_worker import ScanWorker
    from src.gui.code_viewer import CodeViewer
    from src.gui.dashboard import Dashboard
    from src.gui.findings_table import FindingsTable, FindingsModel
    from src.gui.settings_panel import SettingsPanel
    from src.gui.main_window import MainWindow

    app.quit()


def test_dashboard_signals(qapp):
    from src.gui.dashboard import Dashboard
    dash = Dashboard()
    assert dash.selectFolderRequested is not None
    assert dash.scanRequested is not None
    assert dash.pdfRequested is not None
    assert dash.llmToggled is not None


def test_dashboard_action_buttons(qapp):
    from src.gui.dashboard import Dashboard
    dash = Dashboard()
    assert dash.btn_select.text() == "📂 Seleccionar proyecto"
    assert dash.btn_scan.text() == "▶ Analizar"
    assert dash.btn_pdf.text() == "📄 Generar PDF"
    assert dash.chk_llm.text() == "🤖 Análisis con IA"
    assert not dash.btn_scan.isEnabled()
    assert not dash.btn_pdf.isEnabled()


def test_dashboard_set_has_folder(qapp):
    from src.gui.dashboard import Dashboard
    dash = Dashboard()
    dash.set_has_folder(True)
    assert dash.btn_scan.isEnabled()
    dash.set_has_folder(False)
    assert not dash.btn_scan.isEnabled()


def test_dashboard_set_has_report(qapp):
    from src.gui.dashboard import Dashboard
    dash = Dashboard()
    dash.set_has_report(True)
    assert dash.btn_pdf.isEnabled()
    dash.set_has_report(False)
    assert not dash.btn_pdf.isEnabled()


def test_dashboard_llm_toggle_signal(qapp):
    from src.gui.dashboard import Dashboard
    dash = Dashboard()
    toggled_values = []

    dash.llmToggled.connect(lambda v: toggled_values.append(v))
    dash.chk_llm.setChecked(True)
    assert toggled_values == [True]
    dash.chk_llm.setChecked(False)
    assert toggled_values == [True, False]


def test_mainwindow_llm_action(qapp):
    from src.gui.main_window import MainWindow
    w = MainWindow()
    assert w.llm_action.isCheckable()
    assert isinstance(w.llm_action.text(), str)
    assert w._use_llm is not None


def test_mainwindow_llm_toggle_sync(qapp):
    from src.gui.main_window import MainWindow
    w = MainWindow()
    w._set_llm_enabled(True)
    assert w._use_llm is True
    assert w.llm_action.isChecked()
    assert w.dashboard_tab.chk_llm.isChecked()

    w._set_llm_enabled(False)
    assert w._use_llm is False
    assert not w.llm_action.isChecked()
    assert not w.dashboard_tab.chk_llm.isChecked()


def test_mainwindow_dashboard_toggle_sync(qapp):
    from src.gui.main_window import MainWindow
    w = MainWindow()
    w.dashboard_tab.llmToggled.emit(True)
    assert w._use_llm is True
    assert w.llm_action.isChecked()

    w.dashboard_tab.llmToggled.emit(False)
    assert w._use_llm is False
    assert not w.llm_action.isChecked()


def test_mainwindow_tabs_exist(qapp):
    from src.gui.main_window import MainWindow
    w = MainWindow()
    tab_texts = [w.tab_widget.tabText(i) for i in range(w.tab_widget.count())]
    assert "📊 Resumen" in tab_texts
    assert "🔍 Hallazgos" in tab_texts
    assert "⚙ Configuración" in tab_texts
    assert "🛡 Cumplimiento" in tab_texts


def test_findings_model_data(qapp):
    from src.gui.findings_table import FindingsModel
    from src.models import Finding, Severity

    findings = [
        Finding(id="SQLI-0001", category="sql_injection", severity=Severity.CRITICAL,
                cwe="CWE-89", language="python", file_path="app.py",
                line_number=10, code_snippet="execute(sql)",
                description="SQL injection", remediation="Use params", confidence="high"),
        Finding(id="XSS-0001", category="xss", severity=Severity.HIGH,
                cwe="CWE-79", language="javascript", file_path="app.js",
                line_number=5, code_snippet="innerHTML = x",
                description="XSS", remediation="textContent", confidence="high"),
    ]

    model = FindingsModel()
    model.set_findings(findings)

    assert model.rowCount() == 2
    assert model.columnCount() == 7

    severity_display = model.data(model.index(0, 1))
    assert "Crítica" in severity_display

    category_display = model.data(model.index(0, 2))
    assert "Sql Injection" in str(category_display)


def test_findings_model_sort_by_severity(qapp):
    from src.gui.findings_table import FindingsModel
    from src.models import Finding, Severity

    findings = [
        Finding(id="LOW-0001", category="log_injection", severity=Severity.LOW,
                cwe="CWE-117", language="python", file_path="a.py",
                line_number=1, code_snippet="x", description="low",
                remediation="fix", confidence="low"),
        Finding(id="CRIT-0001", category="sql_injection", severity=Severity.CRITICAL,
                cwe="CWE-89", language="python", file_path="b.py",
                line_number=1, code_snippet="y", description="crit",
                remediation="fix", confidence="high"),
    ]

    model = FindingsModel()
    model.set_findings(findings)

    first_id = model.data(model.index(0, 0))
    assert "CRIT" in str(first_id)


def test_code_viewer_basic(qapp):
    from src.gui.code_viewer import CodeViewer
    viewer = CodeViewer()
    viewer.setPlainText("line 1\nline 2\nline 3")
    assert viewer.toPlainText() == "line 1\nline 2\nline 3"


def test_code_viewer_highlight_line(qapp):
    from src.gui.code_viewer import CodeViewer
    viewer = CodeViewer()
    viewer.setPlainText("line one\nline two\nline three\nline four\n")
    viewer.set_highlighted_line(2)
    extra = viewer.extraSelections()
    assert isinstance(extra, list)


def test_scan_worker_signals(qapp):
    from src.gui.scan_worker import ScanWorker
    from src.models import Severity
    worker = ScanWorker(
        target_path=".",
        languages=["python"],
        min_severity=Severity.LOW,
        use_llm=False,
    )
    assert hasattr(worker.signals, "progress")
    assert hasattr(worker.signals, "finished")


def test_settings_panel_get_settings_default(qapp):
    from src.gui.settings_panel import SettingsPanel
    panel = SettingsPanel()
    settings = panel.get_settings()

    assert "exclude_dirs" in settings
    assert isinstance(settings["exclude_dirs"], list)
    assert "min_severity" in settings
    assert settings["min_severity"] in ("low", "medium", "high", "critical")


def test_compliance_tab_basic(qapp):
    from src.gui.compliance_tab import ComplianceTab
    from src.models import ScanReport, Finding, Severity

    tab = ComplianceTab()
    report = ScanReport(
        target_path="test", total_files_scanned=1, total_findings=2,
        findings=[
            Finding(id="SQLI-0001", category="sql_injection", severity=Severity.CRITICAL,
                    cwe="CWE-89", language="python", file_path="app.py",
                    line_number=5, code_snippet="x", description="SQLi",
                    remediation="fix", confidence="high"),
            Finding(id="XSS-0001", category="xss", severity=Severity.HIGH,
                    cwe="CWE-79", language="javascript", file_path="app.js",
                    line_number=3, code_snippet="y", description="XSS",
                    remediation="fix", confidence="high"),
        ],
        scan_duration_seconds=0.1,
    )
    tab.set_compliance(report)
    assert tab.tree.topLevelItemCount() >= 1
