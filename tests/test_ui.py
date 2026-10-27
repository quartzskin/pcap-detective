import json
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from pcap_detective.ui.main_window import MainWindow  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(app):
    w = MainWindow()
    yield w
    w.wait_idle()
    w.close()


def test_loads_in_background_and_fills_tabs(window, demo_pcap):
    window.load_path(str(demo_pcap))
    window.wait_idle()
    assert window.summary is not None
    assert window.proto_table.rowCount() == 6
    assert window.dns_table.rowCount() > 0
    assert window.flow_table.rowCount() == len(window.summary.flows)
    assert window.flag_list.count() == 5
    assert window.flag_packets.rowCount() > 0
    assert window.act_json.isEnabled()
    assert json.loads(window.render_export("json"))["packets"] == window.summary.packets
    assert "## Protocols" in window.render_export("md")


def test_selecting_a_hint_shows_its_packets(window, demo_pcap):
    window.load_path(str(demo_pcap))
    window.wait_idle()
    window.flag_list.setCurrentRow(1)
    assert window.flag_packets.rowCount() == window.summary.flags[1].packet_total


def test_bad_file_shows_error_not_crash(window, tmp_path):
    p = tmp_path / "bad.pcap"
    p.write_bytes(b"nope" * 10)
    window.load_path(str(p))
    window.wait_idle()
    assert window.summary is None
    assert "Could not open" in window.status_label.text()
    assert not window.act_md.isEnabled()


def test_empty_file_shows_error(window, tmp_path):
    p = tmp_path / "e.pcap"
    p.write_bytes(b"")
    window.load_path(str(p))
    window.wait_idle()
    assert "empty" in window.status_label.text()
