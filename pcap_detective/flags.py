from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass

from .store import Store

NXDOMAIN_MIN = 10
SCAN_MIN_TARGETS = 15
LONG_LABEL_MIN = 20
ENTROPY_MIN = 3.5
ENTROPY_NAMES_MIN = 3
BEACON_MIN_CONNECTIONS = 6
BEACON_MAX_JITTER = 0.15
BEACON_MIN_INTERVAL = 1.0
MAX_SUPPORT = 200


@dataclass
class Flag:
    kind: str
    title: str
    explanation: str
    packets: list[int]
    packet_total: int


def _flag(kind: str, title: str, explanation: str, packets: list[int]) -> Flag:
    packets = sorted(packets)
    return Flag(kind, title, explanation, packets[:MAX_SUPPORT], len(packets))


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


def nxdomain_burst(store: Store) -> list[Flag]:
    rows = store.execute("SELECT idx, dns_name FROM packets WHERE dns_response = 1 AND dns_rcode = 3")
    if len(rows) < NXDOMAIN_MIN:
        return []
    names = {r[1] for r in rows if r[1]}
    return [
        _flag(
            "dns-nxdomain",
            f"{len(rows)} DNS lookups answered NXDOMAIN",
            f"{len(rows)} responses said the name does not exist ({len(names)} distinct names). "
            "A lot of failed lookups can come from malware trying generated domains, but also from "
            "typos, stale config or search-suffix noise.",
            [r[0] for r in rows],
        )
    ]


def scan_like_fanout(store: Store) -> list[Flag]:
    out = []
    syn = "flags = 'S' AND transport = 'TCP'"
    by_port = store.execute(
        f"""
        SELECT src, dst, COUNT(DISTINCT dport) FROM packets WHERE {syn}
        GROUP BY src, dst HAVING COUNT(DISTINCT dport) >= ?
        """,
        (SCAN_MIN_TARGETS,),
    )
    for src, dst, n in by_port:
        idx = [
            r[0]
            for r in store.execute(f"SELECT idx FROM packets WHERE {syn} AND src = ? AND dst = ?", (src, dst))
        ]
        out.append(
            _flag(
                "port-scan",
                f"{src} sent SYNs to {n} ports on {dst}",
                f"{src} opened (or tried to open) TCP connections to {n} different ports on {dst}. "
                "That is what a port scan looks like. Vulnerability scanners, service discovery and "
                "some apps that probe several ports can look the same.",
                idx,
            )
        )
    by_host = store.execute(
        f"""
        SELECT src, dport, COUNT(DISTINCT dst) FROM packets WHERE {syn}
        GROUP BY src, dport HAVING COUNT(DISTINCT dst) >= ?
        """,
        (SCAN_MIN_TARGETS,),
    )
    for src, dport, n in by_host:
        idx = [
            r[0]
            for r in store.execute(
                f"SELECT idx FROM packets WHERE {syn} AND src = ? AND dport = ?", (src, dport)
            )
        ]
        out.append(
            _flag(
                "host-sweep",
                f"{src} sent SYNs to port {dport} on {n} hosts",
                f"{src} tried TCP port {dport} on {n} different hosts. That fan-out is typical of a sweep "
                "looking for one service. It can also be a legitimate inventory or monitoring job.",
                idx,
            )
        )
    return out


def high_entropy_dns(store: Store) -> list[Flag]:
    hits = []
    for name, _qtype, queries, _nx in store.dns_names():
        if not queries:
            continue
        label = max(name.split("."), key=len)
        if len(label) >= LONG_LABEL_MIN and shannon_entropy(label) >= ENTROPY_MIN:
            hits.append(name)
    if len(hits) < ENTROPY_NAMES_MIN:
        return []
    packets: list[int] = []
    for name in hits:
        rows = store.execute("SELECT idx FROM packets WHERE dns_name = ? AND dns_response = 0", (name,))
        packets += [r[0] for r in rows]
    shown = ", ".join(hits[:3])
    return [
        _flag(
            "dns-entropy",
            f"{len(hits)} long, random-looking DNS names",
            f"{len(hits)} queried names have a label of {LONG_LABEL_MIN}+ characters that looks random "
            f"(for example {shown}). DNS tunnelling and generated domains look like this. "
            "So do some CDN and tracking hostnames.",
            packets,
        )
    ]


def beacon_like(store: Store, flows) -> list[Flag]:
    groups: dict[tuple, list] = defaultdict(list)
    for f in flows:
        groups[(f.transport, f.src, f.dst, f.dport)].append(f)
    out = []
    for (transport, src, dst, dport), items in groups.items():
        if len(items) < BEACON_MIN_CONNECTIONS:
            continue
        items.sort(key=lambda f: f.start)
        gaps = [b.start - a.start for a, b in zip(items, items[1:], strict=False)]
        mean = statistics.fmean(gaps)
        if mean < BEACON_MIN_INTERVAL:
            continue
        jitter = statistics.pstdev(gaps) / mean
        if jitter > BEACON_MAX_JITTER:
            continue
        out.append(
            _flag(
                "beacon",
                f"{src} contacts {dst}:{dport} every {mean:.1f}s",
                f"{len(items)} separate {transport} connections from {src} to {dst} port {dport} start "
                f"about every {mean:.1f}s (spread {jitter:.0%} of the interval). Command-and-control "
                "check-ins behave like this. So do update checks, health checks and anything on a timer.",
                [f.first_idx for f in items],
            )
        )
    return out


def find_flags(store: Store, flows) -> list[Flag]:
    return (
        nxdomain_burst(store) + scan_like_fanout(store) + high_entropy_dns(store) + beacon_like(store, flows)
    )
