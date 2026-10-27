from __future__ import annotations

from collections import defaultdict

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QPainter
from PySide6.QtWidgets import QWidget

from ..analysis import Flow

ROW = 16
LABEL_W = 250
MAX_ROWS = 30


class TimelineWidget(QWidget):
    # one row per src > dst:port, one bar per connection

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[tuple[str, list[Flow]]] = []
        self.span = (0.0, 1.0)
        self.setMinimumHeight(60)

    def set_flows(self, flows: list[Flow]) -> None:
        groups: dict[tuple, list[Flow]] = defaultdict(list)
        for f in flows:
            groups[(f.transport, f.src, f.dst, f.dport)].append(f)
        busiest = sorted(groups.values(), key=lambda g: (-len(g), g[0].start))[:MAX_ROWS]
        self.rows = []
        for g in busiest:
            label = f"{g[0].src} > {g[0].dst}:{g[0].dport}"
            self.rows.append((f"{label} ({len(g)})" if len(g) > 1 else label, g))
        if flows:
            self.span = (min(f.start for f in flows), max(f.end for f in flows))
        self.setMinimumHeight(max(60, len(self.rows) * ROW + 28))
        self.update()

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        pal = self.palette()
        p.fillRect(self.rect(), pal.base())
        if not self.rows:
            p.setPen(pal.color(pal.ColorRole.Text))
            p.drawText(self.rect(), Qt.AlignCenter, "no TCP/UDP connections")
            return
        t0, t1 = self.span
        span = max(t1 - t0, 1e-6)
        plot_w = max(self.width() - LABEL_W - 16, 50)
        small = p.font()
        small.setPointSize(8)
        p.setFont(small)
        for i in range(5):
            x = int(LABEL_W + plot_w * i / 4)
            p.setPen(pal.color(pal.ColorRole.Mid))
            p.drawLine(x, 16, x, self.height())
            p.setPen(pal.color(pal.ColorRole.Text))
            p.drawText(x - 45 if i == 4 else x + 3, 12, f"+{span * i / 4:.0f}s")
        for row, (label, group) in enumerate(self.rows):
            y = 22 + row * ROW
            p.setPen(pal.color(pal.ColorRole.Text))
            p.drawText(QRectF(4, y - 2, LABEL_W - 8, ROW), Qt.AlignVCenter | Qt.AlignLeft, label)
            color = pal.color(pal.ColorRole.Highlight)
            for f in group:
                x = LABEL_W + plot_w * (f.start - t0) / span
                w = max(plot_w * (f.end - f.start) / span, 3)
                p.fillRect(QRectF(x, y, w, ROW - 6), color)
