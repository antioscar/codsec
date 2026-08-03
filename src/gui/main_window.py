from __future__ import annotations
import os
from PySide6.QtWidgets import (
    QMainWindow, QToolBar, QTabWidget, QStatusBar, QFileDialog,
    QProgressBar, QLabel, QMessageBox, QWidget, QVBoxLayout, QMenu,
    QToolButton, QDockWidget, QTreeWidget, QTreeWidgetItem,
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
from src.gui.toast import show_toast

_PHASE_LABELS = {
    "discover": "Descubriendo",
    "rules": "Reglas",
    "deps": "Dependencias",
    "llm": "IA",
    "baseline": "Baseline",
}


class MainWindow(QMainWindow):
    _MAX_MRU = 10

    def __init__(self):
        super().__init__()
        self.setWindowTitle(self.tr("Analizador de Seguridad de Código"))
        self.setGeometry(100, 100, 1280, 800)

        self._settings = QSettings("CodSec", "AnalizadorSeguridad")

        self._config = load_config()
        saved_theme = self._settings.value("theme")
        self._theme = saved_theme if saved_theme else self._config.get("theme", "dark")
        self._target_path: str | None = None
        self._report: ScanReport | None = None
        self._worker: ScanWorker | None = None
        self._use_llm = self._read_llm_enabled()
        self._current_phase = ""

        self._setup_toolbar()
        self._setup_tabs()
        self._setup_statusbar()
        self._connect_dashboard()

        self._restore_state()

    def _read_llm_enabled(self) -> bool:
        from src.llm.provider import is_llm_enabled
        return is_llm_enabled()

    def _setup_toolbar(self):
        toolbar = QToolBar(self.tr("Principal"))
        toolbar.setIconSize(QSize(20, 20))
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        style = self.style()
        icon_open = style.standardIcon(QStyle.StandardPixmap.SP_DirOpenIcon)
        icon_play = style.standardIcon(QStyle.StandardPixmap.SP_MediaPlay)
        icon_stop = style.standardIcon(QStyle.StandardPixmap.SP_MediaStop)
        icon_file = style.standardIcon(QStyle.StandardPixmap.SP_FileIcon)
        icon_export = style.standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView)

        select_action = QAction(icon_open, self.tr("Seleccionar carpeta"), self)
        select_action.setShortcut(QKeySequence("Ctrl+O"))
        select_action.triggered.connect(self._select_folder)
        toolbar.addAction(select_action)

        self._mru_button = QToolButton()
        self._mru_button.setText("▼")
        self._mru_button.setToolTip(self.tr("Proyectos recientes"))
        self._mru_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self._mru_menu = QMenu(self.tr("Proyectos recientes"), self)
        self._mru_button.setMenu(self._mru_menu)
        self._mru_button.setEnabled(False)
        toolbar.addWidget(self._mru_button)

        toolbar.addSeparator()

        self.scan_action = QAction(icon_play, self.tr("Analizar"), self)
        self.scan_action.setShortcut(QKeySequence("Ctrl+R"))
        self.scan_action.triggered.connect(self._start_scan)
        self.scan_action.setEnabled(False)
        toolbar.addAction(self.scan_action)

        self.cancel_action = QAction(icon_stop, self.tr("Cancelar"), self)
        self.cancel_action.triggered.connect(self._cancel_scan)
        self.cancel_action.setEnabled(False)
        toolbar.addAction(self.cancel_action)

        toolbar.addSeparator()

        self.llm_action = QAction(self.tr("🤖 IA"), self)
        self.llm_action.setCheckable(True)
        self.llm_action.setChecked(self._use_llm)
        self.llm_action.setToolTip(
            self.tr("Análisis con IA: verificación, semántico y remediación")
        )
        self.llm_action.triggered.connect(self._toggle_llm)
        self._update_llm_action_style()
        toolbar.addAction(self.llm_action)

        toolbar.addSeparator()

        self.pdf_action = QAction(icon_file, self.tr("Generar PDF"), self)
        self.pdf_action.setShortcut(QKeySequence("Ctrl+E"))
        self.pdf_action.triggered.connect(self._generate_pdf)
        self.pdf_action.setEnabled(False)

        export_menu = QMenu(self.tr("Exportar"), self)
        export_menu.addAction(self.pdf_action)
        html_action = QAction(self.tr("HTML"), self)
        html_action.triggered.connect(self._generate_html)
        html_action.setEnabled(False)
        export_menu.addAction(html_action)
        self._html_action = html_action
        sarif_action = QAction(self.tr("SARIF"), self)
        sarif_action.triggered.connect(self._generate_sarif)
        sarif_action.setEnabled(False)
        export_menu.addAction(sarif_action)
        self._sarif_action = sarif_action

        self._export_action = QAction(icon_export, self.tr("Exportar"), self)
        self._export_action.setMenu(export_menu)
        self._export_action.setEnabled(False)
        toolbar.addAction(self._export_action)

        self.quick_export_action = QAction(icon_export, self.tr("⚡ Exportar PDF"), self)
        self.quick_export_action.triggered.connect(self._generate_pdf)
        self.quick_export_action.setEnabled(False)
        toolbar.addAction(self.quick_export_action)

        toolbar.addSeparator()

        theme_text = self.tr("☀️ Tema Claro") if self._theme == "dark" else self.tr("🌙 Tema Oscuro")
        self.theme_action = QAction(theme_text, self)
        self.theme_action.triggered.connect(self._toggle_theme)
        toolbar.addAction(self.theme_action)

        toolbar.addSeparator()

        icon_settings = style.standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView)
        settings_action = QAction(self.tr("Configuración"), self)
        settings_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(2))
        toolbar.addAction(settings_action)

        toolbar.addSeparator()

        about_action = QAction(self.tr("❓ Acerca de"), self)
        about_action.triggered.connect(self._show_about)
        toolbar.addAction(about_action)

        shortcut_action = QAction(self.tr("⌨ Atajos"), self)
        shortcut_action.setShortcut(QKeySequence("Ctrl+?"))
        shortcut_action.triggered.connect(self._show_shortcuts)
        toolbar.addAction(shortcut_action)

    def _setup_tabs(self):
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)

        self.dashboard_tab = Dashboard()
        self.tab_widget.addTab(self.dashboard_tab, self.tr("📊 Resumen"))

        self.findings_tab = FindingsTable()
        self.tab_widget.addTab(self.findings_tab, self.tr("🔍 Hallazgos"))

        self.settings_tab = SettingsPanel()
        self.tab_widget.addTab(self.settings_tab, self.tr("⚙ Configuración"))

        self.compliance_tab = ComplianceTab()
        self.tab_widget.addTab(self.compliance_tab, self.tr("🛡 Cumplimiento"))

        self.file_tree_dock = QDockWidget(self.tr("Archivos del proyecto"), self)
        self.file_tree_dock.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea)
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderHidden(True)
        self.file_tree_dock.setWidget(self.file_tree)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self.file_tree_dock)
        self.file_tree_dock.hide()

    def _connect_dashboard(self):
        self.dashboard_tab.selectFolderRequested.connect(self._select_folder)
        self.dashboard_tab.scanRequested.connect(self._start_scan)
        self.dashboard_tab.pdfRequested.connect(self._generate_pdf)
        self.dashboard_tab.llmToggled.connect(self._set_llm_enabled)
        self.dashboard_tab.set_llm_enabled(self._use_llm)

    def _setup_statusbar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.status_label = QLabel(self.tr("Listo"))
        self.status_bar.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(250)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

    def _select_folder(self, folder_path: str | None = None):
        if folder_path and os.path.isdir(folder_path):
            folder = folder_path
        else:
            last_dir = self._settings.value("lastFolder", "")
            folder = QFileDialog.getExistingDirectory(self, self.tr("Seleccionar proyecto"), last_dir)
        if folder:
            self._target_path = folder
            self._settings.setValue("lastFolder", folder)
            self._add_to_mru(folder)
            self.scan_action.setEnabled(True)
            self.dashboard_tab.set_has_folder(True)
            self.status_label.setText(self.tr("Proyecto: {} — Presione 'Analizar' para iniciar").format(folder))

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
            "kotlin": self.settings_tab.chk_kotlin.isChecked(),
            "swift": self.settings_tab.chk_swift.isChecked(),
            "rust": self.settings_tab.chk_rust.isChecked(),
        }
        languages = [k for k, v in lang_keys.items() if v]

        self._report = None
        self._current_phase = ""
        self._set_scanning_state(True)
        self.progress_bar.setVisible(True)
        self.status_label.setText(self.tr("Escaneando..."))

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
        self._worker.signals.phase.connect(self._on_phase)
        self._worker.signals.finished.connect(self._on_scan_finished)
        self._worker.signals.error.connect(self._on_scan_error)
        self._worker.start()

    def _cancel_scan(self):
        if self._worker and self._worker.isRunning():
            reply = QMessageBox.question(
                self, self.tr("Cancelar escaneo"),
                self.tr("¿Está seguro de que desea cancelar el escaneo en curso?"),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self._worker.cancel()
                self.status_label.setText(self.tr("Cancelando..."))

    def _on_phase(self, phase: str):
        self._current_phase = phase

    def _on_progress(self, current: int, total: int, file_path: str):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        phase_label = _PHASE_LABELS.get(self._current_phase, "")
        prefix = f"[{phase_label}] " if phase_label else ""
        if "IA" in file_path or "Verific" in file_path or "Análisis" in file_path or "Mejora" in file_path or "Consulta" in file_path or "Baseline" in file_path:
            self.status_label.setText(f"{prefix}{file_path}")
        else:
            fname = os.path.basename(file_path)
            self.status_label.setText(f"{prefix}Escaneando ({current}/{total}): {fname}")

    def _on_scan_finished(self, report: ScanReport):
        self._report = report
        self._set_scanning_state(False)
        self.progress_bar.setVisible(False)

        total = report.total_findings
        critical = len(report.by_severity[Severity.CRITICAL])
        high = len(report.by_severity[Severity.HIGH])
        self.status_label.setText(
            self.tr("Escaneo completado: {total} hallazgos ({critical} críticas, {high} altas) en {elapsed:.2f}s").format(
                total=total, critical=critical, high=high, elapsed=report.scan_duration_seconds)
        )

        self.dashboard_tab.set_report(report)
        self.dashboard_tab.set_has_report(True)
        self.findings_tab.set_findings(report.findings)
        self.compliance_tab.set_compliance(report)
        self.pdf_action.setEnabled(True)
        self._html_action.setEnabled(True)
        self._sarif_action.setEnabled(True)
        self._export_action.setEnabled(True)
        self.quick_export_action.setEnabled(True)

        self._populate_file_tree(report)

        tab_text = self.tr("🔍 Hallazgos ({})").format(total)
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
        self.status_label.setText(self.tr("Error: {}").format(error_msg))
        if "cancel" not in error_msg.lower():
            QMessageBox.warning(self, self.tr("Error"), self.tr("Error durante el escaneo:\n{}").format(error_msg))

    def _set_scanning_state(self, scanning: bool):
        self.scan_action.setEnabled(not scanning)
        self.cancel_action.setEnabled(scanning)

    def _generate_pdf(self):
        if not self._report:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, self.tr("Guardar informe PDF"), "informe_seguridad.pdf", self.tr("PDF (*.pdf)")
        )
        if not file_path:
            return

        from src.report.pdf_generator import generate_pdf_report
        try:
            generate_pdf_report(self._report, file_path)
            show_toast(self, "PDF guardado: " + file_path, "success")

            os.startfile(file_path)
        except Exception as e:
            QMessageBox.warning(self, self.tr("Error"), self.tr("No se pudo generar el PDF:\n{}").format(e))

    def _generate_html(self):
        if not self._report:
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self, self.tr("Guardar informe HTML"), "informe_seguridad.html", self.tr("HTML (*.html)")
        )
        if not file_path:
            return
        from src.report.html_generator import generate_html_report
        try:
            generate_html_report(self._report, file_path)
            os.startfile(file_path)
            show_toast(self, "HTML guardado: " + file_path, "success")
        except Exception as e:
            QMessageBox.warning(self, self.tr("Error"), self.tr("No se pudo generar el HTML:\n{}").format(e))

    def _generate_sarif(self):
        if not self._report:
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self, self.tr("Guardar informe SARIF"), "informe_seguridad.sarif", self.tr("SARIF (*.sarif *.json)")
        )
        if not file_path:
            return
        from src.report.sarif_output import save_sarif
        try:
            save_sarif(self._report, file_path)
            self.status_label.setText(self.tr("SARIF guardado: {}").format(file_path))
            show_toast(self, "SARIF guardado: " + file_path, "success")
        except Exception as e:
            QMessageBox.warning(self, self.tr("Error"), self.tr("No se pudo generar el SARIF:\n{}").format(e))

    def _toggle_theme(self):
        from PySide6.QtWidgets import QApplication
        self._theme = "light" if self._theme == "dark" else "dark"
        self._settings.setValue("theme", self._theme)
        app = QApplication.instance()
        if app:
            apply_theme(app, self._theme)
        self.dashboard_tab.set_theme(self._theme)
        self.compliance_tab.set_theme(self._theme)
        self.findings_tab.code_viewer.set_theme(self._theme)

        theme_text = self.tr("☀️ Tema Claro") if self._theme == "dark" else self.tr("🌙 Tema Oscuro")
        self.theme_action.setText(theme_text)

    def _toggle_llm(self, checked: bool):
        self._use_llm = checked
        self._update_llm_action_style()
        self.dashboard_tab.set_llm_enabled(checked)
        status = self.tr("activado") if checked else self.tr("desactivado")
        self.status_label.setText(self.tr("Análisis con IA {}").format(status))

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
            self.llm_action.setText(self.tr("🟢 IA activa"))
        else:
            self.llm_action.setText(self.tr("🔘 IA inactiva"))

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
            self.status_label.setText(self.tr("Proyecto: {} — Presione 'Analizar' para iniciar").format(last_folder))
        self._update_mru_menu()

    def _save_state(self):
        self._settings.setValue("windowGeometry", self.saveGeometry())
        self._settings.setValue("windowState", self.saveState())

    def _show_about(self):
        QMessageBox.about(
            self, self.tr("Acerca de Analizador de Seguridad"),
            self.tr(
                "<h3>Analizador de Seguridad de Código</h3>"
                "<p><b>Versión 1.0.0</b></p>"
                "<p>Herramienta SAST con análisis estático, taint analysis, "
                "dependencias vulnerables y cumplimiento multi-estándar.</p>"
                "<p>11 lenguajes · 20 categorías de reglas · 279 tests</p>"
                "<p><b>GitHub:</b> <a href='https://github.com/antioscar/codsec'>"
                "github.com/antioscar/codsec</a></p>"
            ),
        )

    def _add_to_mru(self, folder: str):
        mru = self._settings.value("recentFolders", [])
        if isinstance(mru, str):
            mru = [mru]
        else:
            mru = list(mru)

        folder = os.path.abspath(folder)
        if folder in mru:
            mru.remove(folder)
        mru.insert(0, folder)
        mru = mru[:self._MAX_MRU]

        self._settings.setValue("recentFolders", mru)
        self._update_mru_menu()

    def _update_mru_menu(self):
        self._mru_menu.clear()
        mru = self._settings.value("recentFolders", [])
        if isinstance(mru, str):
            mru = [mru]
        else:
            mru = list(mru)

        mru = [f for f in mru if isinstance(f, str) and os.path.isdir(f)]

        if not mru:
            empty_action = QAction(self.tr("Sin proyectos recientes"), self)
            empty_action.setEnabled(False)
            self._mru_menu.addAction(empty_action)
            self._mru_button.setEnabled(False)
            return

        self._mru_button.setEnabled(True)
        for folder in mru:
            action = QAction(os.path.basename(folder), self)
            action.setToolTip(folder)
            action.triggered.connect(lambda checked, f=folder: self._open_mru_folder(f))
            self._mru_menu.addAction(action)

        self._mru_menu.addSeparator()
        clear_action = QAction(self.tr("Limpiar proyectos recientes"), self)
        clear_action.triggered.connect(self._clear_mru)
        self._mru_menu.addAction(clear_action)

    def _open_mru_folder(self, folder: str):
        self._select_folder(folder)

    def _clear_mru(self):
        self._settings.remove("recentFolders")
        self._update_mru_menu()

    def _show_shortcuts(self):
        shortcuts = [
            (self.tr("Ctrl+O"), self.tr("Seleccionar carpeta")),
            (self.tr("Ctrl+R"), self.tr("Analizar")),
            (self.tr("Ctrl+E"), self.tr("Exportar PDF")),
            (self.tr("Ctrl+?"), self.tr("Mostrar atajos")),
        ]
        rows = "".join(f"<tr><td><b>{sc}</b></td><td>{desc}</td></tr>" for sc, desc in shortcuts)
        html = f"<h3>{self.tr('Atajos de teclado')}</h3><table>{rows}</table>"
        QMessageBox.information(self, self.tr("Atajos de teclado"), html)

    def _populate_file_tree(self, report):
        self.file_tree.clear()
        dirs = {}
        for finding in report.findings:
            file_path = finding.file_path
            if file_path not in dirs:
                dirs[file_path] = file_path

        tree_root = self.file_tree.invisibleRootItem()
        nodes: dict[str, QTreeWidgetItem] = {}

        for file_path in sorted(dirs.keys()):
            parts = file_path.replace("\\", "/").split("/")
            current_path = ""
            parent = tree_root
            for part in parts:
                current_path = current_path + "/" + part if current_path else part
                if current_path not in nodes:
                    item = QTreeWidgetItem([part])
                    parent.addChild(item)
                    nodes[current_path] = item
                parent = nodes[current_path]

        self.file_tree.expandAll()
        self.file_tree_dock.show()

    def closeEvent(self, event):
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(3000)
        self._save_state()
        super().closeEvent(event)
