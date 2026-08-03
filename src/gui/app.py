from __future__ import annotations
import sys
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QSettings, Qt
from src.gui.themes import apply_theme
from src.gui.main_window import MainWindow


def _detect_system_theme(app: QApplication) -> str:
    try:
        scheme = app.styleHints().colorScheme()
        if scheme == Qt.ColorScheme.Dark:
            return "dark"
        return "light"
    except Exception:
        return "dark"


def create_app() -> QApplication:
    app = QApplication(sys.argv)
    app.setApplicationName("Analizador de Seguridad")
    app.setOrganizationName("AnalizadorCodigo")

    settings = QSettings("CodSec", "AnalizadorSeguridad")
    theme = settings.value("theme")

    if theme is None:
        theme = _detect_system_theme(app)

    apply_theme(app, theme)

    return app


def run():
    app = create_app()
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run()
