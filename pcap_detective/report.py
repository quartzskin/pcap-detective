from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from .analysis import Summary

TOP_N = 15
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>()#+!|~&])")


def fmt_ts(ts: float | None) -> str:
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


def fmt_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def md_escape(text: object) -> str:
    return _MD_SPECIAL.sub(r"\\\1", " ".join(str(text).split()))


def to_json(s: Summary) -> str:
    return json.dumps(s.to_dict(), indent=2)


def to_text(s: Summary) -> str:
    lines = [
        f"File:      {s.source}",
        f"Packets:   {s.packets} ({fmt_bytes(s.bytes)}), {s.skipped} non-IP/ARP skipped",
        f"Time:      {fmt_ts(s.first_ts)} to {fmt_ts(s.last_ts)} ({s.duration:.1f}s)",
    ]
    if s.warning:
        lines.append(f"WARNING:   {s.warning}")
    lines += ["", "Protocols"]
    lines += [f"  {p['protocol']:<8}{p['packets']:>8}  {fmt_bytes(p['bytes'])}" for p in s.protocols]
    lines += ["", f"Top talkers (top {TOP_N})"]
    lines += [
        f"  {t['a']} <-> {t['b']}  {t['packets']} pkts, {fmt_bytes(t['bytes'])}" for t in s.talkers[:TOP_N]
    ]
    lines += ["", f"DNS queries (top {TOP_N})"]
    lines += [
        f"  {d['name']}  {d['qtype']}  x{d['queries']}  nxdomain {d['nxdomain']}" for d in s.dns[:TOP_N]
    ]
    lines += ["", f"Hints ({len(s.flags)})"]
    if not s.flags:
        lines.append("  nothing stood out")
    for f in s.flags:
        lines.append(f"  [{f.kind}] {f.title}")
        lines.append(f"      {f.explanation}")
        lines.append(f"      packets: {_packet_list(f.packets, f.packet_total)}")
    return "\n".join(lines)


def _packet_list(packets: list[int], total: int) -> str:
    shown = ", ".join(str(p) for p in packets[:20])
    return shown + (f" ... ({total} total)" if total > 20 else "")


def to_markdown(s: Summary) -> str:
    out = [f"# PCAP summary: {md_escape(s.source)}", ""]
    out += [
        f"- Packets: {s.packets} ({fmt_bytes(s.bytes)}), {s.skipped} non-IP/ARP skipped",
        f"- Time: {fmt_ts(s.first_ts)} to {fmt_ts(s.last_ts)} ({s.duration:.1f}s)",
    ]
    if s.warning:
        out.append(f"- Warning: {md_escape(s.warning)}")

    out += ["", "## Protocols", "", "| Protocol | Packets | Bytes |", "|---|---:|---:|"]
    out += [f"| {md_escape(p['protocol'])} | {p['packets']} | {fmt_bytes(p['bytes'])} |" for p in s.protocols]

    out += ["", "## Top talkers", "", "| Pair | Packets | Bytes |", "|---|---:|---:|"]
    out += [
        f"| {md_escape(t['a'])} - {md_escape(t['b'])} | {t['packets']} | {fmt_bytes(t['bytes'])} |"
        for t in s.talkers[:TOP_N]
    ]

    out += ["", "## Endpoints", "", "| Address | Sent | Received |", "|---|---:|---:|"]
    out += [
        f"| {md_escape(e['address'])} | {e['packets_sent']} pkts, {fmt_bytes(e['bytes_sent'])} "
        f"| {e['packets_received']} pkts, {fmt_bytes(e['bytes_received'])} |"
        for e in s.endpoints[:TOP_N]
    ]

    out += ["", "## DNS queries", "", "| Name | Type | Queries | NXDOMAIN |", "|---|---|---:|---:|"]
    out += [
        f"| {md_escape(d['name'])} | {md_escape(d['qtype'])} | {d['queries']} | {d['nxdomain']} |"
        for d in s.dns[:TOP_N]
    ]

    out += ["", "## Hints", "", "These are patterns worth a look, not findings.", ""]
    if not s.flags:
        out.append("Nothing stood out.")
    for f in s.flags:
        out += [f"### {md_escape(f.title)}", "", md_escape(f.explanation), ""]
        out.append(f"Supporting packets ({f.packet_total}): {_packet_list(f.packets, f.packet_total)}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"
