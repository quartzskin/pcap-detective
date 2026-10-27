from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.utils import PcapReader

QTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}
HTTP_PORTS = {80, 8000, 8080}
TLS_PORTS = {443, 8443}


class PcapError(Exception):
    pass


class _LogCatcher(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


@dataclass(slots=True)
class PacketRow:
    idx: int
    ts: float
    length: int
    proto: str
    src: str
    dst: str
    sport: int | None = None
    dport: int | None = None
    flags: str = ""
    dns_name: str | None = None
    dns_qtype: str | None = None
    dns_response: bool = False
    dns_rcode: int | None = None
    transport: str = ""


@dataclass
class ParseResult:
    rows: list[PacketRow]
    skipped: int = 0
    warning: str | None = None


def _app_proto(transport: str, sport: int, dport: int) -> str:
    ports = {sport, dport}
    if transport == "TCP":
        if ports & HTTP_PORTS:
            return "HTTP"
        if ports & TLS_PORTS:
            return "TLS"
    return transport


def _dns_fields(row: PacketRow, dns) -> None:
    qd = dns.qd
    if isinstance(qd, list):
        qd = qd[0] if qd else None
    row.proto = "DNS"
    row.dns_response = bool(dns.qr)
    if row.dns_response:
        row.dns_rcode = int(dns.rcode)
    if qd is not None and hasattr(qd, "qname"):
        name = qd.qname.decode("ascii", errors="replace") if isinstance(qd.qname, bytes) else str(qd.qname)
        row.dns_name = name.rstrip(".").lower()
        row.dns_qtype = QTYPES.get(int(qd.qtype), str(int(qd.qtype)))


def _to_row(idx: int, pkt) -> PacketRow | None:
    ts = float(pkt.time)
    length = int(getattr(pkt, "wirelen", None) or len(pkt))
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        return PacketRow(idx, ts, length, "ARP", arp.psrc, arp.pdst)
    if pkt.haslayer(IP):
        ip = pkt[IP]
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
    else:
        return None
    row = PacketRow(idx, ts, length, "IP", ip.src, ip.dst)
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        row.sport, row.dport, row.flags = int(t.sport), int(t.dport), str(t.flags)
        row.transport = "TCP"
        row.proto = _app_proto("TCP", row.sport, row.dport)
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        row.sport, row.dport = int(u.sport), int(u.dport)
        row.transport = "UDP"
        row.proto = "UDP"
    elif pkt.haslayer(ICMP):
        row.proto = "ICMP"
    elif ip.__class__ is IPv6 and ip.nh == 58:
        row.proto = "ICMPv6"
    if pkt.haslayer(DNS) and row.proto in ("UDP", "TCP"):
        _dns_fields(row, pkt[DNS])
    return row


def parse_pcap(
    path: str,
    progress: Callable[[int], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> ParseResult:
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise PcapError(f"cannot read file: {exc.strerror or exc}") from exc
    if size == 0:
        raise PcapError("file is empty")

    try:
        reader = PcapReader(path)
    except Exception as exc:
        raise PcapError(f"not a readable pcap or pcapng file ({exc})") from exc

    # scapy only logs when a record is cut off, it does not raise
    catcher = _LogCatcher()
    scapy_log = logging.getLogger("scapy")
    old_level = scapy_log.level
    scapy_log.setLevel(logging.WARNING)
    scapy_log.addHandler(catcher)
    result = ParseResult(rows=[])
    with reader:
        try:
            for idx, pkt in enumerate(_iter(reader), start=1):
                row = _to_row(idx, pkt)
                if row is None:
                    result.skipped += 1
                else:
                    result.rows.append(row)
                if progress and idx % 500 == 0:
                    progress(idx)
                if should_stop and should_stop():
                    result.warning = "stopped before the end of the file"
                    break
        except Exception as exc:
            result.warning = f"stopped early, file looks truncated or corrupt ({exc})"
        finally:
            scapy_log.removeHandler(catcher)
            scapy_log.setLevel(old_level)
    if catcher.messages and not result.warning:
        result.warning = (
            f"file may be truncated or corrupt (scapy: {catcher.messages[0].removeprefix('more ')})"
        )
    if not result.rows and not result.skipped and result.warning:
        raise PcapError(result.warning)
    return result


def _iter(reader) -> Iterator:
    while True:
        try:
            pkt = reader.read_packet()
        except EOFError:
            return
        if pkt is None:
            return
        yield pkt
