from __future__ import annotations
import sys
from PySide6.QtWidgets import QApplication
from src.gui.themes import apply_theme
from src.gui.main_window import MainWindow
from src.config import load_config


def create_app() -> QApplication:
    app = QApplication(sys.argv)
    app.setApplicationName("Analizador de Seguridad")
    app.setOrganizationName("AnalizadorCodigo")

    config = load_config()
    theme = config.get("theme", "dark")
    apply_theme(app, theme)

    return app


def run():
    app = create_app()
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run()
