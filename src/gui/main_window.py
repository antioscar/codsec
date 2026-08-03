from __future__ import annotations
import os
from PySide6.QtWidgets import (
    QMainWindow, QToolBar, QTabWidget, QStatusBar, QFileDialog,
    QProgressBar, QLabel, QMessageBox, QWidget, QVBoxLayout, QMenu,
)
from PySide6.QtGui import QAction, QIcon, QKeySequence
from PySide6.QtCore import Qt, QSize, QSettings
from PySide6.QtWidgets import QStyle

from src.models import Severity, ScanReport
from src.config import load_config
from src.gui.scan_worker import ScanWorker
from src.gui.dashboard import Dashboard
from src.gui.findings_table import FindingsTable
from src.gui.compliance_tab import ComplianceTab
from src.gui.settings_panel import SettingsPanel
from src.gui.themes import apply_theme


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Analizador de Seguridad de Código")
        self.setGeometry(100, 100, 1280, 800)

        self._settings = QSettings("CodSec", "AnalizadorSeguridad")

        self._config = load_config()
        self._theme = self._config.get("theme", "dark")
        self._target_path: str | None = None
        self._report: ScanReport | None = None
        self._worker: ScanWorker | None = None
        self._use_llm = self._read_llm_enabled()

        self._setup_toolbar()
        self._setup_tabs()
        self._setup_statusbar()
        self._connect_dashboard()

        self._restore_state()

    def _read_llm_enabled(self) -> bool:
        from src.llm.provider import is_llm_enabled
        return is_llm_enabled()

    def _setup_toolbar(self):
        toolbar = QToolBar("Principal")
        toolbar.setIconSize(QSize(20, 20))
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        style = self.style()
        icon_open = style.standardIcon(QStyle.StandardPixmap.SP_DirOpenIcon)
        icon_play = style.standardIcon(QStyle.StandardPixmap.SP_MediaPlay)
        icon_stop = style.standardIcon(QStyle.StandardPixmap.SP_MediaStop)
        icon_file = style.standardIcon(QStyle.StandardPixmap.SP_FileIcon)
        icon_export = style.standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView)

        select_action = QAction(icon_open, "Seleccionar carpeta", self)
        select_action.setShortcut(QKeySequence("Ctrl+O"))
        select_action.triggered.connect(self._select_folder)
        toolbar.addAction(select_action)

        toolbar.addSeparator()

        self.scan_action = QAction(icon_play, "Analizar", self)
        self.scan_action.setShortcut(QKeySequence("Ctrl+R"))
        self.scan_action.triggered.connect(self._start_scan)
        self.scan_action.setEnabled(False)
        toolbar.addAction(self.scan_action)

        self.cancel_action = QAction(icon_stop, "Cancelar", self)
        self.cancel_action.triggered.connect(self._cancel_scan)
        self.cancel_action.setEnabled(False)
        toolbar.addAction(self.cancel_action)

        toolbar.addSeparator()

        self.llm_action = QAction("🤖 IA", self)
        self.llm_action.setCheckable(True)
        self.llm_action.setChecked(self._use_llm)
        self.llm_action.setToolTip(
            "Análisis con IA: verificación, semántico y remediación"
        )
        self.llm_action.triggered.connect(self._toggle_llm)
        self._update_llm_action_style()
        toolbar.addAction(self.llm_action)

        toolbar.addSeparator()

        self.pdf_action = QAction(icon_file, "Generar PDF", self)
        self.pdf_action.setShortcut(QKeySequence("Ctrl+E"))
        self.pdf_action.triggered.connect(self._generate_pdf)
        self.pdf_action.setEnabled(False)

        export_menu = QMenu("Exportar", self)
        export_menu.addAction(self.pdf_action)
        html_action = QAction("HTML", self)
        html_action.triggered.connect(self._generate_html)
        html_action.setEnabled(False)
        export_menu.addAction(html_action)
        self._html_action = html_action
        sarif_action = QAction("SARIF", self)
        sarif_action.triggered.connect(self._generate_sarif)
        sarif_action.setEnabled(False)
        export_menu.addAction(sarif_action)
        self._sarif_action = sarif_action

        self._export_action = QAction(icon_export, "Exportar", self)
        self._export_action.setMenu(export_menu)
        self._export_action.setEnabled(False)
        toolbar.addAction(self._export_action)

        toolbar.addSeparator()

        theme_text = "☀️ Tema Claro" if self._theme == "dark" else "🌙 Tema Oscuro"
        self.theme_action = QAction(theme_text, self)
        self.theme_action.triggered.connect(self._toggle_theme)
        toolbar.addAction(self.theme_action)

        toolbar.addSeparator()

        icon_settings = style.standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView)
        settings_action = QAction("Configuración", self)
        settings_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(2))
        toolbar.addAction(settings_action)

    def _setup_tabs(self):
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)

        self.dashboard_tab = Dashboard()
        self.tab_widget.addTab(self.dashboard_tab, "📊 Resumen")

        self.findings_tab = FindingsTable()
        self.tab_widget.addTab(self.findings_tab, "🔍 Hallazgos")

        self.settings_tab = SettingsPanel()
        self.tab_widget.addTab(self.settings_tab, "⚙ Configuración")

        self.compliance_tab = ComplianceTab()
        self.tab_widget.addTab(self.compliance_tab, "🛡 Cumplimiento")

    def _connect_dashboard(self):
        self.dashboard_tab.selectFolderRequested.connect(self._select_folder)
        self.dashboard_tab.scanRequested.connect(self._start_scan)
        self.dashboard_tab.pdfRequested.connect(self._generate_pdf)
        self.dashboard_tab.llmToggled.connect(self._set_llm_enabled)
        self.dashboard_tab.set_llm_enabled(self._use_llm)

    def _setup_statusbar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.status_label = QLabel("Listo")
        self.status_bar.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(250)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

    def _select_folder(self):
        last_dir = self._settings.value("lastFolder", "")
        folder = QFileDialog.getExistingDirectory(self, "Seleccionar proyecto", last_dir)
        if folder:
            self._target_path = folder
            self._settings.setValue("lastFolder", folder)
            self.scan_action.setEnabled(True)
            self.dashboard_tab.set_has_folder(True)
            self.status_label.setText(f"Proyecto: {folder} — Presione 'Analizar' para iniciar")

    def _start_scan(self):
        if not self._target_path:
            return

        self._load_settings()

        settings = self.settings_tab.get_settings()
        min_sev = Severity(settings["min_severity"])
        exclude_dirs = set(settings["exclude_dirs"])
        baseline_path = settings.get("baseline_path") or None
        new_only = bool(settings.get("new_only", False))
        online_cve = bool(settings.get("online_cve", False))
        rules_dir = settings.get("rules_dir") or None

        lang_keys = {
            "python": self.settings_tab.chk_python.isChecked(),
            "javascript": self.settings_tab.chk_javascript.isChecked(),
            "typescript": self.settings_tab.chk_typescript.isChecked(),
            "php": self.settings_tab.chk_php.isChecked(),
            "java": self.settings_tab.chk_java.isChecked(),
            "go": self.settings_tab.chk_go.isChecked(),
            "csharp": self.settings_tab.chk_csharp.isChecked(),
            "ruby": self.settings_tab.chk_ruby.isChecked(),
        }
        languages = [k for k, v in lang_keys.items() if v]

        self._report = None
        self._set_scanning_state(True)
        self.progress_bar.setVisible(True)
        self.status_label.setText("Escaneando...")

        self._worker = ScanWorker(
            target_path=self._target_path,
            languages=languages,
            min_severity=min_sev,
            exclude_dirs=exclude_dirs,
            use_llm=self._use_llm,
            baseline_path=baseline_path,
            new_only=new_only,
            online_cve=online_cve,
            rules_dir=rules_dir,
        )
        self._worker.signals.progress.connect(self._on_progress)
        self._worker.signals.finished.connect(self._on_scan_finished)
        self._worker.signals.error.connect(self._on_scan_error)
        self._worker.start()

    def _cancel_scan(self):
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self.status_label.setText("Cancelando...")

    def _on_progress(self, current: int, total: int, file_path: str):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        if "IA" in file_path:
            self.status_label.setText(file_path)
        else:
            fname = os.path.basename(file_path)
            self.status_label.setText(f"Escaneando ({current}/{total}): {fname}")

    def _on_scan_finished(self, report: ScanReport):
        self._report = report
        self._set_scanning_state(False)
        self.progress_bar.setVisible(False)

        total = report.total_findings
        critical = len(report.by_severity[Severity.CRITICAL])
        high = len(report.by_severity[Severity.HIGH])
        self.status_label.setText(
            f"Escaneo completado: {total} hallazgos ({critical} críticas, {high} altas) en {report.scan_duration_seconds:.2f}s"
        )

        self.dashboard_tab.set_report(report)
        self.dashboard_tab.set_has_report(True)
        self.findings_tab.set_findings(report.findings)
        self.compliance_tab.set_compliance(report)
        self.pdf_action.setEnabled(True)
        self._html_action.setEnabled(True)
        self._sarif_action.setEnabled(True)
        self._export_action.setEnabled(True)

        tab_text = f"🔍 Hallazgos ({total})"
        self.tab_widget.setTabText(1, tab_text)

        most_severe = Severity.LOW
        if total > 0:
            for f in report.findings:
                if f.severity.order < most_severe.order:
                    most_severe = f.severity

        if most_severe in (Severity.CRITICAL, Severity.HIGH):
            self.tab_widget.setCurrentIndex(0)
        else:
            self.tab_widget.setCurrentIndex(1)

    def _on_scan_error(self, error_msg: str):
        self._set_scanning_state(False)
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Error: {error_msg}")
        if "cancel" not in error_msg.lower():
            QMessageBox.warning(self, "Error", f"Error durante el escaneo:\n{error_msg}")

    def _set_scanning_state(self, scanning: bool):
        self.scan_action.setEnabled(not scanning)
        self.cancel_action.setEnabled(scanning)

    def _generate_pdf(self):
        if not self._report:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Guardar informe PDF", "informe_seguridad.pdf", "PDF (*.pdf)"
        )
        if not file_path:
            return

        from src.report.pdf_generator import generate_pdf_report
        try:
            generate_pdf_report(self._report, file_path)
            self.status_label.setText(f"PDF guardado: {file_path}")
            QMessageBox.information(self, "PDF generado", f"Informe guardado en:\n{file_path}")

            os.startfile(file_path)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"No se pudo generar el PDF:\n{e}")

    def _generate_html(self):
        if not self._report:
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Guardar informe HTML", "informe_seguridad.html", "HTML (*.html)"
        )
        if not file_path:
            return
        from src.report.html_generator import generate_html_report
        try:
            generate_html_report(self._report, file_path)
            self.status_label.setText(f"HTML guardado: {file_path}")
            os.startfile(file_path)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"No se pudo generar el HTML:\n{e}")

    def _generate_sarif(self):
        if not self._report:
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Guardar informe SARIF", "informe_seguridad.sarif", "SARIF (*.sarif *.json)"
        )
        if not file_path:
            return
        from src.report.sarif_output import save_sarif
        try:
            save_sarif(self._report, file_path)
            self.status_label.setText(f"SARIF guardado: {file_path}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"No se pudo generar el SARIF:\n{e}")

    def _toggle_theme(self):
        from PySide6.QtWidgets import QApplication
        self._theme = "light" if self._theme == "dark" else "dark"
        app = QApplication.instance()
        if app:
            apply_theme(app, self._theme)
        self.dashboard_tab.set_theme(self._theme)
        self.compliance_tab.set_theme(self._theme)

        theme_text = "☀️ Tema Claro" if self._theme == "dark" else "🌙 Tema Oscuro"
        self.theme_action.setText(theme_text)

    def _toggle_llm(self, checked: bool):
        self._use_llm = checked
        self._update_llm_action_style()
        self.dashboard_tab.set_llm_enabled(checked)
        status = "activado" if checked else "desactivado"
        self.status_label.setText(f"Análisis con IA {status}")

    def _set_llm_enabled(self, enabled: bool):
        if self._use_llm != enabled:
            self._use_llm = enabled
            self.llm_action.blockSignals(True)
            self.llm_action.setChecked(enabled)
            self.llm_action.blockSignals(False)
            self._update_llm_action_style()
            self.dashboard_tab.set_llm_enabled(enabled)
            status = "activado" if enabled else "desactivado"
            self.status_label.setText(f"Análisis con IA {status}")

    def _update_llm_action_style(self):
        if self._use_llm:
            self.llm_action.setText("🟢 IA activa")
        else:
            self.llm_action.setText("🔘 IA inactiva")

    def _load_settings(self):
        config = load_config()
        self._theme = config.get("theme", self._theme)

    def _restore_state(self):
        geometry = self._settings.value("windowGeometry")
        if geometry:
            self.restoreGeometry(geometry)
        state = self._settings.value("windowState")
        if state:
            self.restoreState(state)
        last_folder = self._settings.value("lastFolder", "")
        if last_folder and os.path.isdir(last_folder):
            self._target_path = last_folder
            self.scan_action.setEnabled(True)
            self.dashboard_tab.set_has_folder(True)
            self.status_label.setText(f"Proyecto: {last_folder} — Presione 'Analizar' para iniciar")

    def _save_state(self):
        self._settings.setValue("windowGeometry", self.saveGeometry())
        self._settings.setValue("windowState", self.saveState())

    def closeEvent(self, event):
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(3000)
        self._save_state()
        super().closeEvent(event)
