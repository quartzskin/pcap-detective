from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFileDialog,
    QHeaderView,
    QLabel,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from ..analysis import Summary
from ..report import fmt_bytes, fmt_ts, to_json, to_markdown
from .timeline import TimelineWidget
from .worker import AnalysisWorker


class _NumItem(QTableWidgetItem):
    def __init__(self, value: float, text: str | None = None) -> None:
        super().__init__(text if text is not None else str(value))
        self.value = value
        self.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

    def __lt__(self, other) -> bool:
        if isinstance(other, _NumItem):
            return self.value < other.value
        return super().__lt__(other)


def _table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setAlternatingRowColors(True)
    t.verticalHeader().setVisible(False)
    t.horizontalHeader().setStretchLastSection(True)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    return t


def _fill(table: QTableWidget, rows: list[list]) -> None:
    table.setSortingEnabled(False)
    table.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, value in enumerate(row):
            table.setItem(
                r, c, value if isinstance(value, QTableWidgetItem) else QTableWidgetItem(str(value))
            )
    table.setSortingEnabled(True)
    table.resizeColumnsToContents()


def _bytes_item(n: int) -> _NumItem:
    return _NumItem(n, fmt_bytes(n))


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("PCAP Detective")
        self.setAcceptDrops(True)
        self.summary: Summary | None = None
        self.worker: AnalysisWorker | None = None

        bar = QToolBar()
        bar.setMovable(False)
        self.addToolBar(bar)
        self.act_open = QAction("Open...", self)
        self.act_open.setShortcut(QKeySequence.Open)
        self.act_open.triggered.connect(self.open_dialog)
        self.act_md = QAction("Export Markdown", self)
        self.act_md.triggered.connect(lambda: self.export("md"))
        self.act_json = QAction("Export JSON", self)
        self.act_json.triggered.connect(lambda: self.export("json"))
        for a in (self.act_open, self.act_md, self.act_json):
            bar.addAction(a)
        self.act_md.setEnabled(False)
        self.act_json.setEnabled(False)

        self.status_label = QLabel("Drop a .pcap or .pcapng file here, or press Ctrl+O")
        self.status_label.setWordWrap(True)
        self.warning_label = QLabel()
        self.warning_label.setWordWrap(True)
        self.warning_label.hide()

        self.tabs = QTabWidget()
        self.proto_table = _table(["Protocol", "Packets", "Bytes"])
        self.endpoint_table = _table(
            ["Address", "Packets sent", "Packets received", "Bytes sent", "Bytes received"]
        )
        self.talker_table = _table(["Address A", "Address B", "Packets", "Bytes"])
        self.dns_table = _table(["Name", "Type", "Queries", "NXDOMAIN"])
        self.flow_table = _table(
            ["Start (+s)", "Duration (s)", "Proto", "Source", "Destination", "Packets", "Bytes"]
        )
        self.timeline = TimelineWidget()
        self.flag_list = QListWidget()
        self.flag_text = QTextEdit()
        self.flag_text.setReadOnly(True)
        self.flag_packets = _table(["No.", "Time", "Proto", "Source", "Destination", "Info"])
        self.flag_list.currentRowChanged.connect(self._show_flag)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.timeline)
        timeline_tab = QSplitter(Qt.Vertical)
        timeline_tab.addWidget(scroll)
        timeline_tab.addWidget(self.flow_table)
        timeline_tab.setSizes([420, 260])

        detail = QSplitter(Qt.Vertical)
        detail.addWidget(self.flag_text)
        detail.addWidget(self.flag_packets)
        flags_tab = QSplitter(Qt.Horizontal)
        flags_tab.addWidget(self.flag_list)
        flags_tab.addWidget(detail)
        flags_tab.setSizes([320, 700])

        self.tabs.addTab(self.proto_table, "Protocols")
        self.tabs.addTab(self.endpoint_table, "Endpoints")
        self.tabs.addTab(self.talker_table, "Top talkers")
        self.tabs.addTab(self.dns_table, "DNS")
        self.tabs.addTab(timeline_tab, "Timeline")
        self.tabs.addTab(flags_tab, "Hints")

        body = QWidget()
        lay = QVBoxLayout(body)
        lay.addWidget(self.status_label)
        lay.addWidget(self.warning_label)
        lay.addWidget(self.tabs, 1)
        self.setCentralWidget(body)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setMaximumWidth(160)
        self.progress.hide()
        self.statusBar().addPermanentWidget(self.progress)

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        paths = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.load_path(paths[0])

    def closeEvent(self, event) -> None:
        self.wait_idle(cancel=True)
        super().closeEvent(event)

    def open_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open capture", "", "Captures (*.pcap *.pcapng *.cap);;All files (*)"
        )
        if path:
            self.load_path(path)

    def load_path(self, path: str) -> None:
        self.wait_idle(cancel=True)
        self.status_label.setText(f"Reading {os.path.basename(path)}...")
        self.warning_label.hide()
        self.act_md.setEnabled(False)
        self.act_json.setEnabled(False)
        self.progress.show()
        self.worker = AnalysisWorker(path)
        self.worker.progress.connect(lambda n: self.statusBar().showMessage(f"{n} packets read"))
        self.worker.finished_ok.connect(self._on_done)
        self.worker.failed.connect(self._on_failed)
        self.worker.start()

    def wait_idle(self, cancel: bool = False) -> None:
        if self.worker is not None:
            if cancel:
                self.worker.requestInterruption()
            self.worker.wait()
            QApplication.processEvents()

    def _on_failed(self, message: str) -> None:
        self.progress.hide()
        self.statusBar().clearMessage()
        self.summary = None
        self.status_label.setText(f"Could not open file: {message}")
        for t in (self.proto_table, self.endpoint_table, self.talker_table, self.dns_table, self.flow_table):
            t.setRowCount(0)
        self.timeline.set_flows([])
        self.flag_list.clear()

    def _on_done(self, s: Summary) -> None:
        self.progress.hide()
        self.statusBar().clearMessage()
        self.summary = s
        self.act_md.setEnabled(True)
        self.act_json.setEnabled(True)
        self.status_label.setText(
            f"{s.source}: {s.packets} packets, {fmt_bytes(s.bytes)}, {s.duration:.1f}s, "
            f"from {fmt_ts(s.first_ts)}"
        )
        notes = [
            w for w in (s.warning, f"{s.skipped} non-IP/ARP packets skipped" if s.skipped else None) if w
        ]
        self.warning_label.setText("; ".join(notes))
        self.warning_label.setVisible(bool(notes))

        _fill(
            self.proto_table,
            [[p["protocol"], _NumItem(p["packets"]), _bytes_item(p["bytes"])] for p in s.protocols],
        )
        _fill(
            self.endpoint_table,
            [
                [
                    e["address"],
                    _NumItem(e["packets_sent"]),
                    _NumItem(e["packets_received"]),
                    _bytes_item(e["bytes_sent"]),
                    _bytes_item(e["bytes_received"]),
                ]
                for e in s.endpoints
            ],
        )
        _fill(
            self.talker_table,
            [[t["a"], t["b"], _NumItem(t["packets"]), _bytes_item(t["bytes"])] for t in s.talkers],
        )
        _fill(
            self.dns_table,
            [[d["name"], d["qtype"], _NumItem(d["queries"]), _NumItem(d["nxdomain"])] for d in s.dns],
        )
        t0 = s.first_ts or 0.0
        _fill(
            self.flow_table,
            [
                [
                    _NumItem(f.start - t0, f"{f.start - t0:.3f}"),
                    _NumItem(f.end - f.start, f"{f.end - f.start:.3f}"),
                    f.transport,
                    f"{f.src}:{f.sport}",
                    f"{f.dst}:{f.dport}",
                    _NumItem(f.packets),
                    _bytes_item(f.bytes),
                ]
                for f in s.flows
            ],
        )
        self.flow_table.sortByColumn(0, Qt.AscendingOrder)
        self.timeline.set_flows(s.flows)

        self.flag_list.clear()
        for f in s.flags:
            self.flag_list.addItem(f.title)
        if not s.flags:
            self.flag_text.setPlainText("Nothing stood out.")
            self.flag_packets.setRowCount(0)
        else:
            self.flag_list.setCurrentRow(0)
        self.tabs.setTabText(5, f"Hints ({len(s.flags)})")

    def _show_flag(self, row: int) -> None:
        if self.summary is None or row < 0:
            return
        f = self.summary.flags[row]
        note = "These are patterns worth a look, not findings."
        more = f" (showing {len(f.packets)} of {f.packet_total})" if f.packet_total > len(f.packets) else ""
        self.flag_text.setPlainText(
            f"{f.title}\n\n{f.explanation}\n\n{note}\nSupporting packets: {f.packet_total}{more}"
        )
        t0 = self.summary.first_ts or 0.0
        rows = []
        for i in f.packets:
            p = self.summary.flag_packets[i]
            src = f"{p.src}:{p.sport}" if p.sport is not None else p.src
            dst = f"{p.dst}:{p.dport}" if p.dport is not None else p.dst
            info = p.dns_name or p.flags or ""
            rows.append([_NumItem(p.idx), f"+{p.ts - t0:.3f}s", p.proto, src, dst, info])
        _fill(self.flag_packets, rows)

    def render_export(self, fmt: str) -> str:
        if self.summary is None:
            raise ValueError("nothing loaded")
        return to_json(self.summary) if fmt == "json" else to_markdown(self.summary)

    def export(self, fmt: str) -> None:
        if self.summary is None:
            return
        stem = Path(self.summary.source).stem
        ext, label = ("json", "JSON") if fmt == "json" else ("md", "Markdown")
        path, _ = QFileDialog.getSaveFileName(self, f"Export {label}", f"{stem}.{ext}", f"{label} (*.{ext})")
        if not path:
            return
        try:
            Path(path).write_text(self.render_export(fmt), encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", exc.strerror or str(exc))
