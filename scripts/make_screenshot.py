"""Save offscreen screenshots of the main window to docs/.

Usage: python scripts/make_screenshot.py [CAPTURE]
With no argument it builds a synthetic capture in a temp folder.
"""

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# the offscreen platform finds no fonts on its own and draws tofu boxes
os.environ.setdefault("QT_QPA_FONTDIR", os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Fonts"))

from PySide6.QtWidgets import QApplication  # noqa: E402

from pcap_detective.synthetic import demo_capture, write_pcap  # noqa: E402
from pcap_detective.ui.main_window import MainWindow  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "docs"


def main() -> None:
    app = QApplication([])
    if sys.argv[1:]:
        path = sys.argv[1]
    else:
        path = str(Path(tempfile.mkdtemp()) / "demo.pcap")
        write_pcap(path, demo_capture())
    w = MainWindow()
    w.resize(1100, 720)
    w.show()
    w.load_path(path)
    w.wait_idle()
    OUT.mkdir(exist_ok=True)
    for index, name in ((4, "screenshot-timeline.png"), (5, "screenshot-hints.png")):
        w.tabs.setCurrentIndex(index)
        app.processEvents()
        w.grab().save(str(OUT / name))
        print("saved", OUT / name)


if __name__ == "__main__":
    main()
