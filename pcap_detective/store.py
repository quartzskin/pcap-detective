from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import astuple, fields

from .parser import PacketRow

_COLUMNS = [f.name for f in fields(PacketRow)]

_SCHEMA = """
CREATE TABLE packets (
    idx INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    length INTEGER NOT NULL,
    proto TEXT NOT NULL,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    sport INTEGER,
    dport INTEGER,
    flags TEXT NOT NULL,
    dns_name TEXT,
    dns_qtype TEXT,
    dns_response INTEGER NOT NULL,
    dns_rcode INTEGER,
    transport TEXT NOT NULL
);
CREATE INDEX packets_src ON packets (src);
CREATE INDEX packets_dns ON packets (dns_name);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
"""


class Store:
    def __init__(self, path: str = ":memory:") -> None:
        self.db = sqlite3.connect(path)
        self.db.executescript(_SCHEMA)

    def close(self) -> None:
        self.db.close()

    def add(self, rows: Iterable[PacketRow]) -> None:
        marks = ",".join("?" * len(_COLUMNS))
        self.db.executemany(f"INSERT INTO packets VALUES ({marks})", (astuple(r) for r in rows))
        self.db.commit()

    def set_meta(self, key: str, value: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, value))
        self.db.commit()

    def execute(self, sql: str, args: tuple = ()) -> list[tuple]:
        return self.db.execute(sql, args).fetchall()

    def packets(self, indexes: Iterable[int]) -> list[PacketRow]:
        wanted = sorted(set(indexes))
        out: list[PacketRow] = []
        for i in range(0, len(wanted), 500):
            chunk = wanted[i : i + 500]
            marks = ",".join("?" * len(chunk))
            sql = f"SELECT * FROM packets WHERE idx IN ({marks}) ORDER BY idx"
            out += [PacketRow(*r) for r in self.db.execute(sql, chunk)]
        return out

    def totals(self) -> tuple[int, int, float | None, float | None]:
        return self.db.execute(
            "SELECT COUNT(*), COALESCE(SUM(length), 0), MIN(ts), MAX(ts) FROM packets"
        ).fetchone()

    def protocols(self) -> list[tuple[str, int, int]]:
        return self.execute(
            "SELECT proto, COUNT(*), SUM(length) FROM packets GROUP BY proto ORDER BY COUNT(*) DESC, proto"
        )

    def endpoints(self) -> list[tuple[str, int, int, int, int]]:
        return self.execute(
            """
            SELECT addr, SUM(sent), SUM(recv), SUM(sent_bytes), SUM(recv_bytes) FROM (
                SELECT src AS addr, 1 AS sent, 0 AS recv, length AS sent_bytes, 0 AS recv_bytes FROM packets
                UNION ALL
                SELECT dst, 0, 1, 0, length FROM packets
            ) GROUP BY addr ORDER BY SUM(sent_bytes) + SUM(recv_bytes) DESC, addr
            """
        )

    def conversations(self) -> list[tuple[str, str, int, int]]:
        return self.execute(
            """
            SELECT MIN(src, dst), MAX(src, dst), COUNT(*), SUM(length) FROM packets
            GROUP BY MIN(src, dst), MAX(src, dst) ORDER BY SUM(length) DESC, 1, 2
            """
        )

    def dns_names(self) -> list[tuple[str, str, int, int]]:
        # name, qtype, number of queries, number of NXDOMAIN answers
        return self.execute(
            """
            SELECT dns_name, COALESCE(MAX(dns_qtype), ''),
                   SUM(dns_response = 0), SUM(dns_response = 1 AND dns_rcode = 3)
            FROM packets WHERE dns_name IS NOT NULL
            GROUP BY dns_name ORDER BY SUM(dns_response = 0) DESC, dns_name
            """
        )

    def flow_packets(self) -> list[tuple]:
        return self.execute(
            """
            SELECT idx, ts, length, transport, src, dst, sport, dport FROM packets
            WHERE transport != '' ORDER BY idx
            """
        )
