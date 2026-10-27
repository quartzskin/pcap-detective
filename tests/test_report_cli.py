import json
import sqlite3

from pcap_detective import synthetic as syn
from pcap_detective.analysis import analyze_file
from pcap_detective.cli import main
from pcap_detective.report import md_escape, to_json, to_markdown, to_text


def test_summary_numbers(demo_pcap):
    s = analyze_file(str(demo_pcap))
    assert s.packets == len(syn.demo_capture())
    protos = {p["protocol"]: p["packets"] for p in s.protocols}
    assert protos["ARP"] == 1 and protos["ICMP"] == 1
    assert sum(protos.values()) == s.packets
    assert s.endpoints[0]["packets_sent"] + s.endpoints[0]["packets_received"] > 0
    assert {"10.0.0.1", "10.0.0.5"} == {s.talkers[0]["a"], s.talkers[0]["b"]}
    assert any(d["name"] == "example.com" for d in s.dns)
    assert any(f.dport == 53 for f in s.flows)


def test_json_is_valid_and_has_packets_behind_hints(demo_pcap):
    data = json.loads(to_json(analyze_file(str(demo_pcap))))
    assert {f["kind"] for f in data["flags"]} == {
        "dns-nxdomain",
        "port-scan",
        "host-sweep",
        "dns-entropy",
        "beacon",
    }
    beacon = next(f for f in data["flags"] if f["kind"] == "beacon")
    assert len(beacon["packet_details"]) == len(beacon["packets"])


def test_markdown_and_text_render(demo_pcap):
    s = analyze_file(str(demo_pcap))
    md = to_markdown(s)
    assert "## Hints" in md and "not findings" in md
    assert "Hints (5)" in to_text(s)


def test_markdown_escapes_names_from_the_capture(make_pcap):
    name = "evil<img>|[x](y).example"
    s = analyze_file(make_pcap(syn.dns_exchange(syn.T0, name)))
    md = to_markdown(s)
    assert "<img>" not in md and "\\|" in md
    assert md_escape("a\nb") == "a b"


def test_cli_text_and_exit_codes(demo_pcap, capsys, tmp_path):
    assert main([str(demo_pcap)]) == 0
    assert "Protocols" in capsys.readouterr().out
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"junk" * 20)
    assert main([str(bad)]) == 2
    assert "error:" in capsys.readouterr().err
    assert main([str(tmp_path / "missing.pcap")]) == 2


def test_cli_output_not_overwritten_without_force(demo_pcap, tmp_path, capsys):
    out = tmp_path / "r.json"
    out.write_text("keep me")
    assert main([str(demo_pcap), "--format", "json", "-o", str(out)]) == 2
    assert out.read_text() == "keep me"
    assert "--force" in capsys.readouterr().err
    assert main([str(demo_pcap), "--format", "json", "-o", str(out), "--force"]) == 0
    assert json.loads(out.read_text())["packets"] > 0


def test_cli_never_overwrites_the_input(demo_pcap, tmp_path):
    copy = tmp_path / "copy.pcap"
    copy.write_bytes(demo_pcap.read_bytes())
    assert main([str(copy), "-o", str(copy), "--force"]) == 2
    assert copy.read_bytes() == demo_pcap.read_bytes()


def test_cli_db(demo_pcap, tmp_path):
    db = tmp_path / "x.db"
    assert main([str(demo_pcap), "--db", str(db)]) == 0
    count = sqlite3.connect(db).execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    assert count == len(syn.demo_capture())
    assert main([str(demo_pcap), "--db", str(db)]) == 2
    assert main([str(demo_pcap), "--db", str(db), "--force"]) == 0
