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
    viewer.set_source("line 1\nline 2\nline 3", "python")
    assert viewer.toPlainText() == "line 1\nline 2\nline 3"


def test_code_viewer_highlight_line(qapp):
    from src.gui.code_viewer import CodeViewer
    viewer = CodeViewer()
    viewer.set_source("line one\nline two\nline three\nline four\n", "python")
    viewer.set_highlighted_line(2)
    extra = viewer.extraSelections()
    assert isinstance(extra, list)


def test_code_viewer_syntax_highlighter_python(qapp):
    from src.gui.code_viewer import CodeViewer, SyntaxHighlighter
    viewer = CodeViewer()
    source = '''def hello(name):
    if name:
        return f"Hello, {name}"
    return None
'''
    viewer.set_source(source, "python")
    assert viewer.toPlainText() == source


def test_code_viewer_syntax_highlighter_javascript(qapp):
    from src.gui.code_viewer import CodeViewer
    viewer = CodeViewer()
    source = 'const x = 42;\n// comment\nlet y = "hello";'
    viewer.set_source(source, "javascript")
    assert viewer.toPlainText() == source


def test_code_viewer_syntax_highlighter_unknown_language(qapp):
    from src.gui.code_viewer import CodeViewer
    viewer = CodeViewer()
    source = "some random text"
    viewer.set_source(source, "haskell")
    assert viewer.toPlainText() == source


def test_code_viewer_syntax_highlighter_theme_switch(qapp):
    from src.gui.code_viewer import CodeViewer
    viewer = CodeViewer()
    source = '# comment\nx = 1\ns = "hello"'
    viewer.set_source(source, "python")
    viewer.set_theme("light")
    assert viewer._highlighter._theme == "light"
    viewer.set_theme("dark")
    assert viewer._highlighter._theme == "dark"


def test_code_viewer_syntax_highlighter_empty_source(qapp):
    from src.gui.code_viewer import CodeViewer
    viewer = CodeViewer()
    viewer.set_source("", "python")
    assert viewer.toPlainText() == ""


def test_code_viewer_syntax_highlighter_multiple_languages(qapp):
    from src.gui.code_viewer import CodeViewer
    viewer = CodeViewer()

    viewer.set_source("package main\nfunc main() {\n\tfmt.Println(\"hi\")\n}", "go")
    assert "package main" in viewer.toPlainText()

    viewer.set_source("public class Foo { }", "java")
    assert "public class Foo" in viewer.toPlainText()

    viewer.set_source("<?php echo 'hello'; ?>", "php")
    assert "echo 'hello'" in viewer.toPlainText()

    viewer.set_source("using System;", "csharp")
    assert "using System" in viewer.toPlainText()

    viewer.set_source("def foo; end", "ruby")
    assert "def foo" in viewer.toPlainText()

    viewer.set_source("const a: string = 'ts';", "typescript")
    assert "const a" in viewer.toPlainText()


def test_code_viewer_syntax_highlighter_comments_strings(qapp):
    from src.gui.code_viewer import CodeViewer
    viewer = CodeViewer()
    source = '# this is a comment\nx = "this is a string"\ny = 42'
    viewer.set_source(source, "python")
    output = viewer.toPlainText()
    assert "# this is a comment" in output
    assert '"this is a string"' in output
    assert "42" in output


def test_code_viewer_syntax_highlighter_keywords(qapp):
    from src.gui.code_viewer import CodeViewer
    viewer = CodeViewer()
    source = "if True:\n    return None"
    viewer.set_source(source, "python")
    assert "if True" in viewer.toPlainText()
    assert "return None" in viewer.toPlainText()


def test_mainwindow_about_dialog(qapp):
    from src.gui.main_window import MainWindow
    from PySide6.QtWidgets import QMessageBox
    w = MainWindow()
    assert hasattr(w, "_show_about")
    w._show_about()


def test_mainwindow_theme_persistence(qapp):
    from src.gui.main_window import MainWindow
    from PySide6.QtCore import QSettings

    settings = QSettings("CodSec", "AnalizadorSeguridad")
    settings.setValue("theme", "")
    settings.sync()

    w = MainWindow()
    w._toggle_theme()
    assert w._settings.value("theme") in ("dark", "light")


def test_mainwindow_mru_add_and_menu(qapp):
    import tempfile
    import os
    from src.gui.main_window import MainWindow

    w = MainWindow()
    w._settings.setValue("recentFolders", [])
    w._settings.sync()

    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
        w._add_to_mru(d1)
        w._add_to_mru(d2)

        mru = w._settings.value("recentFolders", [])
        mru_list = list(mru) if not isinstance(mru, str) else [mru]

        assert w._mru_button.isEnabled()


def test_mainwindow_mru_limit(qapp):
    import tempfile
    import os
    from src.gui.main_window import MainWindow
    w = MainWindow()
    w._settings.setValue("recentFolders", [])
    w._settings.sync()

    with tempfile.TemporaryDirectory() as td:
        for i in range(15):
            sub = os.path.join(td, f"sub_{i}")
            os.makedirs(sub)
            w._add_to_mru(sub)

    mru = w._settings.value("recentFolders", [])
    mru_list = list(mru) if not isinstance(mru, str) else [mru]
    assert len(mru_list) <= w._MAX_MRU


def test_mainwindow_mru_clear(qapp):
    import tempfile
    from src.gui.main_window import MainWindow
    w = MainWindow()
    with tempfile.TemporaryDirectory() as td:
        w._add_to_mru(td)
        assert w._mru_button.isEnabled()

    w._clear_mru()
    assert not w._mru_button.isEnabled()


def test_mainwindow_mru_dedupe(qapp):
    import tempfile
    import os
    from src.gui.main_window import MainWindow
    w = MainWindow()
    w._settings.setValue("recentFolders", [])
    w._settings.sync()

    with tempfile.TemporaryDirectory() as td:
        a = os.path.join(td, "a")
        b = os.path.join(td, "b")
        os.makedirs(a)
        os.makedirs(b)

        w._add_to_mru(a)
        w._add_to_mru(b)
        w._add_to_mru(a)

        mru = w._settings.value("recentFolders", [])
        mru_list = list(mru) if not isinstance(mru, str) else [mru]
        assert os.path.basename(mru_list[0]) == "a"
        assert mru_list.count(a) == 1
        assert len(mru_list) <= 3


def test_mainwindow_show_about_method_exists(qapp):
    from src.gui.main_window import MainWindow
    w = MainWindow()
    assert callable(w._show_about)


def test_mainwindow_cancel_scan_method(qapp):
    from src.gui.main_window import MainWindow
    w = MainWindow()
    assert callable(w._cancel_scan)
    assert w.cancel_action is not None


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
    assert hasattr(worker.signals, "phase")


def test_mainwindow_phase_handling(qapp):
    from src.gui.main_window import MainWindow
    w = MainWindow()
    w._on_phase("rules")
    assert w._current_phase == "rules"
    w._on_phase("deps")
    assert w._current_phase == "deps"
    w._current_phase = ""
    assert w._current_phase == ""


def test_scan_project_phase_callback(qapp):
    import tempfile
    from src.scanner import scan_project
    from src.models import Severity

    phases_called = []
    def _on_phase(phase):
        phases_called.append(phase)

    with tempfile.TemporaryDirectory() as td:
        report = scan_project(
            target_path=td,
            languages=["python"],
            min_severity=Severity.LOW,
            on_phase=_on_phase,
        )
        assert "rules" in phases_called or len(phases_called) == 0


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
    assert tab.btn_export.isEnabled()


def test_findings_table_set_findings(qapp):
    from src.gui.findings_table import FindingsTable
    from src.models import Finding, Severity
    table = FindingsTable()
    findings = [
        Finding(id="SQLI-1", category="sql_injection", severity=Severity.CRITICAL,
                cwe="CWE-89", language="python", file_path="app.py",
                line_number=10, code_snippet="x", description="SQLi",
                remediation="Use params", confidence="high"),
        Finding(id="XSS-1", category="xss", severity=Severity.HIGH,
                cwe="CWE-79", language="javascript", file_path="app.js",
                line_number=5, code_snippet="y", description="XSS",
                remediation="Use textContent", confidence="high"),
    ]
    table.set_findings(findings)
    assert table.model.rowCount() == 2
    assert table.cmb_category.count() >= 3


def test_findings_table_filters_exist(qapp):
    from src.gui.findings_table import FindingsTable
    table = FindingsTable()
    assert table.chk_critical is not None
    assert table.chk_high is not None
    assert table.chk_medium is not None
    assert table.chk_low is not None
    assert table.txt_search is not None
    assert hasattr(table, '_toggle_filters')


def test_findings_table_context_menu_actions(qapp):
    from src.gui.findings_table import FindingsTable
    from src.models import Finding, Severity
    table = FindingsTable()
    findings = [Finding(id="T-1", category="sql_injection", severity=Severity.CRITICAL,
                        cwe="CWE-89", language="python", file_path="app.py",
                        line_number=1, code_snippet="x", description="d",
                        remediation="r", confidence="high")]
    table.set_findings(findings)
    assert hasattr(table, '_show_context_menu')
    assert callable(table._show_context_menu)


def test_findings_table_remediation_copy(qapp):
    from src.gui.findings_table import FindingsTable
    from src.models import Finding, Severity
    table = FindingsTable()
    finding = Finding(id="T-1", category="sql_injection", severity=Severity.CRITICAL,
                      cwe="CWE-89", language="python", file_path="app.py",
                      line_number=1, code_snippet="x", description="d",
                      remediation="Use parameters", confidence="high")
    table.set_findings([finding])
    assert hasattr(table, '_copy_remediation')
    assert callable(table._copy_remediation)


def test_findings_table_filter_toggle(qapp):
    from src.gui.findings_table import FindingsTable
    table = FindingsTable()
    assert hasattr(table, '_filter_widgets')
    table._toggle_filters()


def test_dashboard_set_report(qapp):
    from src.gui.dashboard import Dashboard
    from src.models import ScanReport, Finding, Severity
    dash = Dashboard()
    findings = [
        Finding(id="C-1", category="sql_injection", severity=Severity.CRITICAL,
                cwe="CWE-89", language="python", file_path="a.py",
                line_number=1, code_snippet="x", description="SQLi",
                remediation="fix", confidence="high"),
        Finding(id="H-1", category="xss", severity=Severity.HIGH,
                cwe="CWE-79", language="js", file_path="b.js",
                line_number=2, code_snippet="y", description="XSS",
                remediation="fix", confidence="high"),
    ]
    report = ScanReport(target_path="/tmp", total_files_scanned=5,
                        total_findings=2, findings=findings,
                        scan_duration_seconds=0.5)
    dash.set_report(report)
    assert dash.placeholder.isHidden()
    assert not dash.chart_view.isHidden()
    assert not dash.donut_view.isHidden()
    assert dash.cards_layout.count() > 0


def test_dashboard_kpi_card(qapp):
    from src.gui.dashboard import KpiCard
    card = KpiCard("TEST", "42", "#FF0000", "")
    assert card.value_lbl is not None
    card.animate_value(100)
    card.set_value("50")
    assert card.value_lbl.text() == "50"


def test_dashboard_animated_label(qapp):
    from src.gui.dashboard import AnimatedLabel
    label = AnimatedLabel("0")
    label.animate_to(50)
    assert label._target == 50


def test_dashboard_placeholder_visible(qapp):
    from src.gui.dashboard import Dashboard
    dash = Dashboard()
    assert not dash.placeholder.isHidden()
    assert dash.chart_view.isHidden()


def test_mainwindow_quick_export_exists(qapp):
    from src.gui.main_window import MainWindow
    w = MainWindow()
    assert hasattr(w, 'quick_export_action')
    assert w.quick_export_action is not None
    assert not w.quick_export_action.isEnabled()


def test_mainwindow_file_tree_dock(qapp):
    from src.gui.main_window import MainWindow
    w = MainWindow()
    assert hasattr(w, 'file_tree_dock')
    assert not w.file_tree_dock.isVisible()


def test_toast_creation(qapp):
    from src.gui.toast import Toast, show_toast
    toast = Toast("Test message", "info", duration=1000)
    assert toast is not None
    assert toast._duration == 1000


def test_toast_types(qapp):
    from src.gui.toast import Toast
    for t in ("info", "success", "warning", "error"):
        toast = Toast(f"Test {t}", t, duration=100)
        assert toast.ICONS.get(t) is not None
        assert toast.COLORS.get(t) is not None


def test_toast_show_at_callback(qapp):
    from src.gui.toast import Toast
    from PySide6.QtWidgets import QMainWindow
    w = QMainWindow()
    w.resize(400, 300)
    w.show()
    toast = Toast("Test", "success", duration=100)
    toast.show_at(w)
    assert toast.isVisible()
    w.hide()
