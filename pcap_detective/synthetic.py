"""Synthetic packets for tests and the screenshot. Nothing here is a real capture."""

from __future__ import annotations

import random
import string

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapNgWriter, wrpcap

T0 = 1_700_000_000.0
CLIENT = "10.0.0.5"
RESOLVER = "10.0.0.1"


def _stamp(pkt, t: float):
    pkt.time = t
    return pkt


def dns_exchange(t: float, name: str, rcode: int = 0, sport: int = 40000) -> list:
    q = Ether() / IP(src=CLIENT, dst=RESOLVER) / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=name))
    a = (
        Ether()
        / IP(src=RESOLVER, dst=CLIENT)
        / UDP(sport=53, dport=sport)
        / DNS(qr=1, rcode=rcode, qd=DNSQR(qname=name))
    )
    return [_stamp(q, t), _stamp(a, t + 0.02)]


def tcp_connection(t: float, src: str, dst: str, dport: int, sport: int, data: int = 0) -> list:
    base = Ether() / IP(src=src, dst=dst)
    pkts = [
        base / TCP(sport=sport, dport=dport, flags="S", seq=100),
        Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=500, ack=101),
        base / TCP(sport=sport, dport=dport, flags="A", seq=101, ack=501),
    ]
    if data:
        pkts.append(base / TCP(sport=sport, dport=dport, flags="PA", seq=101, ack=501) / ("x" * data))
    pkts.append(base / TCP(sport=sport, dport=dport, flags="FA", seq=101 + data, ack=501))
    return [_stamp(p, t + i * 0.01) for i, p in enumerate(pkts)]


def normal_traffic() -> list:
    pkts = [_stamp(Ether() / ARP(psrc=CLIENT, pdst=RESOLVER), T0)]
    pkts.append(_stamp(Ether() / IP(src=CLIENT, dst="10.0.0.9") / ICMP(), T0 + 0.1))
    pkts += dns_exchange(T0 + 1, "example.com")
    pkts += dns_exchange(T0 + 1.5, "www.example.org", sport=40001)
    pkts += tcp_connection(T0 + 2, CLIENT, "93.184.216.34", 443, 50001, data=600)
    pkts += tcp_connection(T0 + 3, CLIENT, "93.184.216.35", 80, 50002, data=200)
    return pkts


def nxdomain_burst(count: int = 12, start: float = T0 + 20) -> list:
    pkts = []
    for i in range(count):
        pkts += dns_exchange(start + i * 0.5, f"host{i}.missing.example", rcode=3, sport=41000 + i)
    return pkts


def port_scan(ports: int = 20, start: float = T0 + 40) -> list:
    return [
        _stamp(
            Ether() / IP(src="10.0.0.66", dst="10.0.0.20") / TCP(sport=44444, dport=1000 + i, flags="S"),
            start + i * 0.01,
        )
        for i in range(ports)
    ]


def host_sweep(hosts: int = 20, start: float = T0 + 50) -> list:
    return [
        _stamp(
            Ether() / IP(src="10.0.0.67", dst=f"10.0.1.{i + 1}") / TCP(sport=44445, dport=445, flags="S"),
            start + i * 0.01,
        )
        for i in range(hosts)
    ]


def random_label(rng: random.Random, n: int = 32) -> str:
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def entropy_names(count: int = 4, start: float = T0 + 60) -> list:
    rng = random.Random(7)
    pkts = []
    for i in range(count):
        pkts += dns_exchange(start + i, f"{random_label(rng)}.tunnel.example", sport=42000 + i)
    return pkts


def beacon(count: int = 8, interval: float = 30.0, jitter: float = 0.5, start: float = T0 + 100) -> list:
    rng = random.Random(3)
    pkts = []
    for i in range(count):
        t = start + i * interval + rng.uniform(-jitter, jitter)
        pkts += tcp_connection(t, "10.0.0.8", "203.0.113.50", 8443, 51000 + i, data=64)
    return pkts


def irregular_connections(count: int = 8, start: float = T0 + 100) -> list:
    rng = random.Random(5)
    pkts = []
    t = start
    for i in range(count):
        t += rng.uniform(2, 90)
        pkts += tcp_connection(t, "10.0.0.9", "203.0.113.60", 8443, 52000 + i)
    return pkts


def demo_capture() -> list:
    return normal_traffic() + nxdomain_burst() + port_scan() + host_sweep() + entropy_names() + beacon()


def write_pcap(path, packets: list) -> None:
    wrpcap(str(path), sorted(packets, key=lambda p: float(p.time)))


def write_pcapng(path, packets: list) -> None:
    writer = PcapNgWriter(str(path))
    for p in sorted(packets, key=lambda p: float(p.time)):
        writer.write(p)
    writer.close()
