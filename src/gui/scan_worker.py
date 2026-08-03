from __future__ import annotations
from PySide6.QtCore import QThread, Signal, QObject

from src.models import ScanReport, Severity
from src.scanner import scan_project


class ScanWorkerSignals(QObject):
    progress = Signal(int, int, str)
    finished = Signal(object)
    error = Signal(str)


class ScanWorker(QThread):
    def __init__(
        self,
        target_path: str,
        languages: list[str] | None = None,
        min_severity: Severity = Severity.LOW,
        exclude_dirs: set[str] | None = None,
        use_llm: bool = False,
        baseline_path: str | None = None,
        new_only: bool = False,
        online_cve: bool = False,
        rules_dir: str | None = None,
        parent: QObject | None = None,
    ):
        super().__init__(parent)
        self.target_path = target_path
        self.languages = languages
        self.min_severity = min_severity
        self.exclude_dirs = exclude_dirs
        self.use_llm = use_llm
        self.baseline_path = baseline_path
        self.new_only = new_only
        self.online_cve = online_cve
        self.rules_dir = rules_dir
        self.signals = ScanWorkerSignals()
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        try:
            def _progress(current: int, total: int, file_path: str):
                if self._cancelled:
                    raise InterruptedError()
                self.signals.progress.emit(current, total, file_path)

            report = scan_project(
                target_path=self.target_path,
                languages=self.languages,
                min_severity=self.min_severity,
                exclude_dirs=self.exclude_dirs,
                on_progress=_progress,
                use_llm=self.use_llm,
                baseline_path=self.baseline_path,
                new_only=self.new_only,
                online_cve=self.online_cve,
                rules_dir=self.rules_dir,
            )
            self.signals.finished.emit(report)
        except InterruptedError:
            self.signals.error.emit("Escaneo cancelado")
        except Exception as e:
            self.signals.error.emit(str(e))
