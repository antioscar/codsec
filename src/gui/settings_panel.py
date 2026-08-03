from __future__ import annotations
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QCheckBox,
    QComboBox, QPushButton, QLabel, QListWidget, QListWidgetItem,
    QLineEdit, QMessageBox, QFileDialog, QTabWidget, QGridLayout,
)
from PySide6.QtCore import Qt

from src.config import load_config, SETTINGS_PATH
from src.llm.provider import LLM_CONFIG_PATH, load_llm_config
from src.gui.toast import show_toast

ALL_RULE_CATEGORIES = [
    "sql_injection", "xss", "command_injection", "hardcoded_secrets",
    "path_traversal", "ssrf", "insecure_crypto", "insecure_deserialization",
    "dynamic_exec", "open_redirect", "csrf", "security_headers",
    "info_disclosure", "ssti", "xxe", "ldap_injection",
    "prototype_pollution", "log_injection", "zip_slip", "weak_hash",
    "cors_misconfiguration", "cookie_security", "insecure_jwt",
    "nosql_injection", "insecure_random", "idor_access_control",
    "unsafe_deserialization_advanced", "http_parameter_pollution",
    "graphql_injection", "missing_auth", "unsafe_redirect",
    "host_header_injection", "insecure_file_upload",
]


class SettingsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        tabs = QTabWidget()

        # ── Tab 1: General ──
        general_tab = QWidget()
        general_layout = QVBoxLayout(general_tab)

        sev_group = QGroupBox("Severidad mínima")
        sev_layout = QHBoxLayout(sev_group)
        sev_layout.addWidget(QLabel("Mostrar hallazgos con severidad mínima:"))
        self.cmb_severity = QComboBox()
        self.cmb_severity.addItems(["low", "medium", "high", "critical"])
        self.cmb_severity.setCurrentText("low")
        sev_layout.addWidget(self.cmb_severity)
        general_layout.addWidget(sev_group)

        theme_group = QGroupBox("Tema")
        theme_layout = QHBoxLayout(theme_group)
        theme_layout.addWidget(QLabel("Tema de la interfaz:"))
        self.cmb_theme = QComboBox()
        self.cmb_theme.addItems(["dark", "light"])
        self.cmb_theme.setCurrentText("dark")
        theme_layout.addWidget(self.cmb_theme)
        general_layout.addWidget(theme_group)

        exclude_group = QGroupBox("Directorios excluidos")
        exclude_layout = QVBoxLayout(exclude_group)
        self.exclude_list = QListWidget()
        self.exclude_list.setMaximumHeight(200)
        exclude_layout.addWidget(self.exclude_list)

        add_layout = QHBoxLayout()
        self.txt_add_exclude = QLineEdit()
        self.txt_add_exclude.setPlaceholderText("Nombre del directorio a excluir...")
        add_layout.addWidget(self.txt_add_exclude)
        btn_add = QPushButton("Agregar")
        btn_add.clicked.connect(self._add_exclude)
        add_layout.addWidget(btn_add)
        btn_remove = QPushButton("Quitar")
        btn_remove.clicked.connect(self._remove_exclude)
        add_layout.addWidget(btn_remove)
        exclude_layout.addLayout(add_layout)
        general_layout.addWidget(exclude_group)

        btn_save = QPushButton("Guardar configuración")
        btn_save.clicked.connect(self.save_settings)
        general_layout.addWidget(btn_save)

        tabs.addTab(general_tab, self.tr("General"))

        # ── Tab 2: Lenguajes ──
        lang_tab = QWidget()
        lang_tab_layout = QVBoxLayout(lang_tab)
        lang_group = QGroupBox("Lenguajes activos")
        lang_inner = QGridLayout(lang_group)
        self.chk_python = QCheckBox("Python")
        self.chk_python.setChecked(True)
        self.chk_javascript = QCheckBox("JavaScript")
        self.chk_javascript.setChecked(True)
        self.chk_typescript = QCheckBox("TypeScript")
        self.chk_typescript.setChecked(True)
        self.chk_php = QCheckBox("PHP")
        self.chk_php.setChecked(True)
        self.chk_java = QCheckBox("Java")
        self.chk_java.setChecked(True)
        self.chk_go = QCheckBox("Go")
        self.chk_go.setChecked(True)
        self.chk_csharp = QCheckBox("C#")
        self.chk_csharp.setChecked(True)
        self.chk_ruby = QCheckBox("Ruby")
        self.chk_ruby.setChecked(True)
        self.chk_kotlin = QCheckBox("Kotlin")
        self.chk_kotlin.setChecked(False)
        self.chk_swift = QCheckBox("Swift")
        self.chk_swift.setChecked(False)
        self.chk_rust = QCheckBox("Rust")
        self.chk_rust.setChecked(False)
        lang_inner.addWidget(self.chk_python, 0, 0)
        lang_inner.addWidget(self.chk_javascript, 0, 1)
        lang_inner.addWidget(self.chk_typescript, 0, 2)
        lang_inner.addWidget(self.chk_php, 1, 0)
        lang_inner.addWidget(self.chk_java, 1, 1)
        lang_inner.addWidget(self.chk_go, 1, 2)
        lang_inner.addWidget(self.chk_csharp, 2, 0)
        lang_inner.addWidget(self.chk_ruby, 2, 1)
        lang_inner.addWidget(self.chk_kotlin, 2, 2)
        lang_inner.addWidget(self.chk_swift, 3, 0)
        lang_inner.addWidget(self.chk_rust, 3, 1)
        lang_tab_layout.addWidget(lang_group)
        lang_tab_layout.addStretch()
        tabs.addTab(lang_tab, self.tr("Lenguajes"))

        # ── Tab 3: IA / LLM ──
        llm_tab = QWidget()
        llm_tab_layout = QVBoxLayout(llm_tab)
        llm_group = QGroupBox("IA / LLM")
        llm_layout = QVBoxLayout(llm_group)

        llm_row1 = QHBoxLayout()
        self.chk_llm_enabled = QCheckBox("Habilitar análisis con IA")
        self.chk_llm_enabled.setToolTip("Activa la verificación, análisis semántico y remediación con IA")
        llm_row1.addWidget(self.chk_llm_enabled)
        llm_layout.addLayout(llm_row1)

        llm_row2 = QHBoxLayout()
        llm_row2.addWidget(QLabel("Proveedor:"))
        self.cmb_provider = QComboBox()
        self.cmb_provider.addItems(["ollama", "openai_compatible"])
        self.cmb_provider.currentTextChanged.connect(self._on_provider_changed)
        llm_row2.addWidget(self.cmb_provider)

        llm_row2.addWidget(QLabel("Modelo:"))
        self.txt_model = QLineEdit()
        self.txt_model.setPlaceholderText("qwen2.5-coder")
        self.txt_model.setMaximumWidth(180)
        llm_row2.addWidget(self.txt_model)
        llm_layout.addLayout(llm_row2)

        llm_row3 = QHBoxLayout()
        llm_row3.addWidget(QLabel("URL base:"))
        self.txt_base_url = QLineEdit()
        self.txt_base_url.setPlaceholderText("http://localhost:11434")
        llm_row3.addWidget(self.txt_base_url)

        llm_row3.addWidget(QLabel("API key env:"))
        self.txt_api_key_env = QLineEdit()
        self.txt_api_key_env.setPlaceholderText("OPENAI_API_KEY")
        self.txt_api_key_env.setMaximumWidth(180)
        llm_row3.addWidget(self.txt_api_key_env)
        llm_layout.addLayout(llm_row3)

        llm_features = QHBoxLayout()
        self.chk_verify = QCheckBox("Verificación")
        self.chk_verify.setChecked(True)
        self.chk_semantic = QCheckBox("Análisis semántico")
        self.chk_semantic.setChecked(True)
        self.chk_remediation = QCheckBox("Remediación")
        self.chk_remediation.setChecked(True)
        llm_features.addWidget(QLabel("Features:"))
        llm_features.addWidget(self.chk_verify)
        llm_features.addWidget(self.chk_semantic)
        llm_features.addWidget(self.chk_remediation)
        llm_features.addStretch()
        llm_layout.addLayout(llm_features)

        llm_tab_layout.addWidget(llm_group)
        llm_tab_layout.addStretch()
        tabs.addTab(llm_tab, self.tr("IA / LLM"))

        # ── Tab 4: Avanzado ──
        avanzado_tab = QWidget()
        avanzado_layout = QVBoxLayout(avanzado_tab)

        baseline_group = QGroupBox("Baseline (delta de hallazgos)")
        baseline_layout = QVBoxLayout(baseline_group)

        bl_row1 = QHBoxLayout()
        bl_row1.addWidget(QLabel("Archivo baseline:"))
        self.txt_baseline = QLineEdit()
        self.txt_baseline.setPlaceholderText("Ruta al JSON de un escaneo anterior...")
        bl_row1.addWidget(self.txt_baseline)
        btn_browse = QPushButton("Buscar...")
        btn_browse.clicked.connect(self._browse_baseline)
        bl_row1.addWidget(btn_browse)
        baseline_layout.addLayout(bl_row1)

        self.chk_new_only = QCheckBox("Solo hallazgos nuevos")
        self.chk_new_only.setToolTip("Oculta los hallazgos ya conocidos del baseline")
        baseline_layout.addWidget(self.chk_new_only)

        self.chk_online_cve = QCheckBox("Consulta online OSV (CVE)")
        self.chk_online_cve.setToolTip("Consulta la API de OSV para buscar CVEs actualizados. Requiere conexión a internet.")
        baseline_layout.addWidget(self.chk_online_cve)

        avanzado_layout.addWidget(baseline_group)

        rules_group = QGroupBox("Reglas personalizadas")
        rules_layout = QHBoxLayout(rules_group)
        rules_layout.addWidget(QLabel("Directorio de reglas:"))
        self.txt_rules_dir = QLineEdit()
        self.txt_rules_dir.setPlaceholderText("Ruta a carpeta con reglas YAML (opcional)...")
        rules_layout.addWidget(self.txt_rules_dir)
        btn_rules_browse = QPushButton("Buscar...")
        btn_rules_browse.clicked.connect(self._browse_rules_dir)
        rules_layout.addWidget(btn_rules_browse)
        avanzado_layout.addWidget(rules_group)

        avanzado_layout.addStretch()
        tabs.addTab(avanzado_tab, self.tr("Avanzado"))

        layout.addWidget(tabs)
        self.load_current()

    def load_current(self):
        config = load_config()

        exclude_dirs = config.get("exclude_dirs", [])
        self.exclude_list.clear()
        for d in exclude_dirs:
            self.exclude_list.addItem(d)

        min_sev = config.get("min_severity", "low")
        idx = self.cmb_severity.findText(min_sev)
        if idx >= 0:
            self.cmb_severity.setCurrentIndex(idx)

        theme = config.get("theme", "dark")
        idx = self.cmb_theme.findText(theme)
        if idx >= 0:
            self.cmb_theme.setCurrentIndex(idx)

        try:
            llm_config = load_llm_config()
            self.chk_llm_enabled.setChecked(True if self._read_llm_enabled() else False)
            idx = self.cmb_provider.findText(llm_config.provider)
            if idx >= 0:
                self.cmb_provider.setCurrentIndex(idx)
            self.txt_model.setText(llm_config.model if llm_config.provider == "ollama" else llm_config.openai_model)
            self.txt_base_url.setText(llm_config.base_url if llm_config.provider == "ollama" else llm_config.openai_base_url)
            self.txt_api_key_env.setText(llm_config.api_key_env)

            features = self._read_llm_features()
            self.chk_verify.setChecked(features.get("verify", True))
            self.chk_semantic.setChecked(features.get("semantic", True))
            self.chk_remediation.setChecked(features.get("remediation", True))

            self._on_provider_changed(llm_config.provider)
        except Exception:
            pass

    def _read_llm_enabled(self) -> bool:
        import yaml
        try:
            if LLM_CONFIG_PATH.exists():
                with open(str(LLM_CONFIG_PATH), "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                return bool(data.get("enabled", False))
        except Exception:
            pass
        return False

    def _read_llm_features(self) -> dict:
        import yaml
        try:
            if LLM_CONFIG_PATH.exists():
                with open(str(LLM_CONFIG_PATH), "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                features = data.get("features", {})
                return {
                    "verify": features.get("verify", True),
                    "semantic": features.get("semantic", True),
                    "remediation": features.get("remediation", True),
                }
        except Exception:
            pass
        return {"verify": True, "semantic": True, "remediation": True}

    def _on_provider_changed(self, provider: str):
        is_openai = provider == "openai_compatible"
        self.txt_api_key_env.setEnabled(is_openai)

    def save_settings(self):
        import yaml

        exclude_dirs = []
        for i in range(self.exclude_list.count()):
            exclude_dirs.append(self.exclude_list.item(i).text())

        settings = {
            "exclude_dirs": exclude_dirs,
            "min_severity": self.cmb_severity.currentText(),
            "theme": self.cmb_theme.currentText(),
            "exclude_files": [],
            "enabled_rules": list(ALL_RULE_CATEGORIES),
        }

        with open(str(SETTINGS_PATH), "r", encoding="utf-8") as f:
            existing = yaml.safe_load(f) or {}

        existing.update(settings)

        with open(str(SETTINGS_PATH), "w", encoding="utf-8") as f:
            yaml.dump(existing, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

        provider = self.cmb_provider.currentText()
        llm_data = {
            "provider": provider,
            "enabled": self.chk_llm_enabled.isChecked(),
            "timeout": 60,
            "temperature": 0.1,
            "max_verify_findings": 30,
            "max_semantic_files": 20,
            "features": {
                "verify": self.chk_verify.isChecked(),
                "semantic": self.chk_semantic.isChecked(),
                "remediation": self.chk_remediation.isChecked(),
            },
        }

        if provider == "ollama":
            llm_data["base_url"] = self.txt_base_url.text().strip() or "http://localhost:11434"
            llm_data["model"] = self.txt_model.text().strip() or "qwen2.5-coder"
        else:
            llm_data["openai_compatible"] = {
                "base_url": self.txt_base_url.text().strip() or "https://api.openai.com/v1",
                "model": self.txt_model.text().strip() or "gpt-4o-mini",
                "api_key_env": self.txt_api_key_env.text().strip() or "OPENAI_API_KEY",
            }

        with open(str(LLM_CONFIG_PATH), "w", encoding="utf-8") as f:
            yaml.dump(llm_data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

        show_toast(self, "Configuración guardada correctamente.", "success")

    def _add_exclude(self):
        text = self.txt_add_exclude.text().strip()
        if text:
            self.exclude_list.addItem(text)
            self.txt_add_exclude.clear()

    def _remove_exclude(self):
        for item in self.exclude_list.selectedItems():
            self.exclude_list.takeItem(self.exclude_list.row(item))

    def _browse_baseline(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Seleccionar baseline JSON", "", "JSON (*.json)"
        )
        if file_path:
            self.txt_baseline.setText(file_path)

    def _browse_rules_dir(self):
        folder = QFileDialog.getExistingDirectory(self, "Seleccionar directorio de reglas")
        if folder:
            self.txt_rules_dir.setText(folder)

    def get_settings(self) -> dict:
        exclude_dirs = []
        for i in range(self.exclude_list.count()):
            exclude_dirs.append(self.exclude_list.item(i).text())

        return {
            "exclude_dirs": exclude_dirs,
            "min_severity": self.cmb_severity.currentText(),
            "theme": self.cmb_theme.currentText(),
            "use_llm": self.chk_llm_enabled.isChecked(),
            "baseline_path": self.txt_baseline.text().strip() or None,
            "new_only": self.chk_new_only.isChecked(),
            "online_cve": self.chk_online_cve.isChecked(),
            "rules_dir": self.txt_rules_dir.text().strip() or None,
        }
