from __future__ import annotations

from PySide6.QtCore import QThread, Signal

from ..analysis import analyze_file
from ..parser import PcapError


class AnalysisWorker(QThread):
    progress = Signal(int)
    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(self, path: str) -> None:
        super().__init__()
        self.path = path

    def run(self) -> None:
        try:
            summary = analyze_file(
                self.path, progress=self.progress.emit, should_stop=self.isInterruptionRequested
            )
        except (PcapError, OSError) as exc:
            self.failed.emit(str(exc))
            return
        except Exception as exc:
            self.failed.emit(f"unexpected error: {exc}")
            return
        self.finished_ok.emit(summary)
