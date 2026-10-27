import pytest

from pcap_detective import synthetic as syn
from pcap_detective.analysis import analyze_file
from pcap_detective.parser import PcapError, parse_pcap


def test_pcap_and_pcapng_give_same_rows(tmp_path):
    pkts = syn.normal_traffic()
    syn.write_pcap(tmp_path / "a.pcap", pkts)
    syn.write_pcapng(tmp_path / "a.pcapng", pkts)
    a = parse_pcap(str(tmp_path / "a.pcap"))
    b = parse_pcap(str(tmp_path / "a.pcapng"))
    assert len(a.rows) == len(b.rows) == len(pkts)
    assert [r.proto for r in a.rows] == [r.proto for r in b.rows]


def test_row_fields(make_pcap):
    rows = parse_pcap(make_pcap(syn.normal_traffic())).rows
    by_proto = {r.proto: r for r in rows}
    assert {"ARP", "ICMP", "DNS", "TLS", "HTTP"} <= set(by_proto)
    dns = [r for r in rows if r.proto == "DNS"]
    assert dns[0].dns_name == "example.com" and dns[0].dns_qtype == "A" and not dns[0].dns_response
    assert dns[1].dns_response and dns[1].dns_rcode == 0
    syn_row = next(r for r in rows if r.flags == "S")
    assert (syn_row.dport, syn_row.transport) == (443, "TCP")


def test_empty_file(tmp_path):
    p = tmp_path / "empty.pcap"
    p.write_bytes(b"")
    with pytest.raises(PcapError, match="empty"):
        parse_pcap(str(p))


def test_missing_file(tmp_path):
    with pytest.raises(PcapError, match="cannot read"):
        parse_pcap(str(tmp_path / "nope.pcap"))


@pytest.mark.parametrize("data", [b"not a capture file at all" * 4, b"\x00" * 100, b"\xd4\xc3"])
def test_garbage_is_rejected(tmp_path, data):
    p = tmp_path / "bad.pcap"
    p.write_bytes(data)
    with pytest.raises(PcapError):
        parse_pcap(str(p))


def test_header_only_is_an_empty_capture(tmp_path):
    src = tmp_path / "full.pcap"
    syn.write_pcap(src, syn.normal_traffic())
    p = tmp_path / "hdr.pcap"
    p.write_bytes(src.read_bytes()[:24])
    s = analyze_file(str(p))
    assert s.packets == 0 and s.flags == [] and s.duration == 0


@pytest.mark.parametrize("writer", [syn.write_pcap, syn.write_pcapng])
def test_truncated_file_keeps_what_it_read_and_warns(tmp_path, writer):
    src = tmp_path / "full.cap"
    writer(src, syn.normal_traffic())
    data = src.read_bytes()
    p = tmp_path / "cut.cap"
    p.write_bytes(data[: len(data) // 2 + 7])
    result = parse_pcap(str(p))
    assert 0 < len(result.rows) < len(syn.normal_traffic())
    assert "truncated" in result.warning


def test_corrupt_record_after_good_ones(tmp_path):
    src = tmp_path / "full.pcap"
    syn.write_pcap(src, syn.normal_traffic())
    data = bytearray(src.read_bytes())
    data[24 + 8 : 24 + 12] = b"\xff\xff\xff\x7f"
    p = tmp_path / "corrupt.pcap"
    p.write_bytes(bytes(data))
    result = parse_pcap(str(p))
    assert len(result.rows) == 1
    assert "corrupt" in result.warning


def test_stop_callback_ends_early(make_pcap):
    result = parse_pcap(make_pcap(syn.demo_capture()), progress=None, should_stop=lambda: True)
    assert len(result.rows) == 1
    assert "stopped" in result.warning
