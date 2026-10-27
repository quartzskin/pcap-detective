from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from .main_window import MainWindow


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    app = QApplication([sys.argv[0]])
    window = MainWindow()
    window.resize(1100, 720)
    window.show()
    if args:
        window.load_path(args[0])
    return app.exec()
