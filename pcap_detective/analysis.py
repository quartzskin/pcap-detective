from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import asdict, dataclass, field

from .flags import Flag, find_flags
from .parser import PacketRow, parse_pcap
from .store import Store


@dataclass
class Flow:
    transport: str
    src: str
    dst: str
    sport: int
    dport: int
    start: float
    end: float
    packets: int
    bytes: int
    first_idx: int


@dataclass
class Summary:
    source: str
    packets: int = 0
    bytes: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    skipped: int = 0
    warning: str | None = None
    protocols: list[dict] = field(default_factory=list)
    endpoints: list[dict] = field(default_factory=list)
    talkers: list[dict] = field(default_factory=list)
    dns: list[dict] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)
    flags: list[Flag] = field(default_factory=list)
    flag_packets: dict[int, PacketRow] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return self.last_ts - self.first_ts

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "packets": self.packets,
            "bytes": self.bytes,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "duration": self.duration,
            "skipped_non_ip": self.skipped,
            "warning": self.warning,
            "protocols": self.protocols,
            "endpoints": self.endpoints,
            "top_talkers": self.talkers,
            "dns": self.dns,
            "flows": [asdict(f) for f in self.flows],
            "flags": [
                {**asdict(f), "packet_details": [_packet_dict(self.flag_packets[i]) for i in f.packets]}
                for f in self.flags
            ],
        }


def _packet_dict(p: PacketRow) -> dict:
    return {
        "number": p.idx,
        "time": p.ts,
        "length": p.length,
        "protocol": p.proto,
        "src": p.src,
        "dst": p.dst,
        "sport": p.sport,
        "dport": p.dport,
        "flags": p.flags,
        "dns_name": p.dns_name,
    }


def build_flows(store: Store) -> list[Flow]:
    flows: dict[tuple, Flow] = {}
    for idx, ts, length, transport, src, dst, sport, dport in store.flow_packets():
        key = (transport, *sorted([(src, sport), (dst, dport)]))
        f = flows.get(key)
        if f is None:
            flows[key] = Flow(transport, src, dst, sport, dport, ts, ts, 1, length, idx)
        else:
            f.end = max(f.end, ts)
            f.packets += 1
            f.bytes += length
    return sorted(flows.values(), key=lambda f: (f.start, f.first_idx))


def summarize(store: Store, source: str) -> Summary:
    count, size, first, last = store.totals()
    s = Summary(source=source, packets=count, bytes=size, first_ts=first, last_ts=last)
    s.protocols = [{"protocol": p, "packets": n, "bytes": b} for p, n, b in store.protocols()]
    s.endpoints = [
        {"address": a, "packets_sent": ps, "packets_received": pr, "bytes_sent": bs, "bytes_received": br}
        for a, ps, pr, bs, br in store.endpoints()
    ]
    s.talkers = [
        {"a": a, "b": b, "packets": n, "bytes": size} for a, b, n, size in store.conversations()[:20]
    ]
    s.dns = [{"name": n, "qtype": q, "queries": c, "nxdomain": nx} for n, q, c, nx in store.dns_names()]
    s.flows = build_flows(store)
    s.flags = find_flags(store, s.flows)
    wanted = {i for f in s.flags for i in f.packets}
    s.flag_packets = {p.idx: p for p in store.packets(wanted)}
    return s


def analyze_file(
    path: str,
    db_path: str = ":memory:",
    progress: Callable[[int], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> Summary:
    parsed = parse_pcap(path, progress, should_stop)
    if db_path != ":memory:" and os.path.exists(db_path):
        os.remove(db_path)
    store = Store(db_path)
    try:
        store.add(parsed.rows)
        store.set_meta("source", os.path.basename(path))
        s = summarize(store, os.path.basename(path))
    finally:
        store.close()
    s.skipped = parsed.skipped
    s.warning = parsed.warning
    return s
