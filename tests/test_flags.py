from pcap_detective import synthetic as syn
from pcap_detective.analysis import analyze_file
from pcap_detective.flags import shannon_entropy


def kinds(make_pcap, packets):
    return {f.kind: f for f in analyze_file(make_pcap(packets)).flags}


def test_normal_traffic_has_no_hints(make_pcap):
    assert kinds(make_pcap, syn.normal_traffic()) == {}


def test_nxdomain_burst(make_pcap):
    flags = kinds(make_pcap, syn.normal_traffic() + syn.nxdomain_burst(12))
    f = flags["dns-nxdomain"]
    assert f.packet_total == 12
    assert "does not exist" in f.explanation


def test_nxdomain_below_threshold(make_pcap):
    assert "dns-nxdomain" not in kinds(make_pcap, syn.nxdomain_burst(9))


def test_port_scan_points_at_the_syns(make_pcap):
    path = make_pcap(syn.normal_traffic() + syn.port_scan(20))
    s = analyze_file(path)
    f = next(f for f in s.flags if f.kind == "port-scan")
    assert f.packet_total == 20
    assert all(s.flag_packets[i].flags == "S" and s.flag_packets[i].src == "10.0.0.66" for i in f.packets)


def test_few_ports_is_not_a_scan(make_pcap):
    assert kinds(make_pcap, syn.port_scan(5)) == {}


def test_host_sweep(make_pcap):
    flags = kinds(make_pcap, syn.host_sweep(20))
    assert "host-sweep" in flags and "port-scan" not in flags


def test_entropy_names(make_pcap):
    f = kinds(make_pcap, syn.normal_traffic() + syn.entropy_names(4))["dns-entropy"]
    assert f.packet_total == 4


def test_ordinary_long_names_are_left_alone(make_pcap):
    pkts = []
    for i, name in enumerate(
        ["a" * 30 + ".example.com", "www.some-very-long-but-boring-hostname.example.com"] * 3
    ):
        pkts += syn.dns_exchange(syn.T0 + i, name, sport=40000 + i)
    assert "dns-entropy" not in kinds(make_pcap, pkts)


def test_beacon(make_pcap):
    s = analyze_file(make_pcap(syn.beacon(8, interval=30)))
    f = next(f for f in s.flags if f.kind == "beacon")
    assert f.packet_total == 8
    assert all(s.flag_packets[i].flags == "S" for i in f.packets)


def test_irregular_connections_are_not_beacons(make_pcap):
    assert "beacon" not in kinds(make_pcap, syn.irregular_connections(8))


def test_too_few_connections_are_not_beacons(make_pcap):
    assert "beacon" not in kinds(make_pcap, syn.beacon(4))


def test_entropy_values():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert abs(shannon_entropy("abcd") - 2.0) < 1e-9
