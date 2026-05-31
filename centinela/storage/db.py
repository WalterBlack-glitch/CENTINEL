"""Capa de persistencia: event store en SQLite (sin deps externas).

Guarda cada evento normalizado para auditoría/forense posterior. Las escrituras
van en un hilo aparte vía run_in_executor para no bloquear el loop async.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path

from ..core import ThreatEvent

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    source    TEXT,
    kind      TEXT,
    src_ip    TEXT,
    dst_ip    TEXT,
    src_port  INTEGER,
    dst_port  INTEGER,
    mac       TEXT,
    user      TEXT,
    severity  INTEGER,
    score     REAL,
    message   TEXT,
    enrichment TEXT,
    tags      TEXT,
    raw       TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
"""


class EventStore:
    def __init__(self, path: str = "centinela.db") -> None:
        self.path = str(Path(path))
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._lock = asyncio.Lock()

    async def save(self, ev: ThreatEvent) -> None:
        async with self._lock:
            await asyncio.get_event_loop().run_in_executor(None, self._insert, ev)

    def _insert(self, ev: ThreatEvent) -> None:
        self._conn.execute(
            """INSERT INTO events
               (ts,source,kind,src_ip,dst_ip,src_port,dst_port,mac,user,
                severity,score,message,enrichment,tags,raw)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ev.ts, ev.source, ev.kind, ev.src_ip, ev.dst_ip, ev.src_port,
             ev.dst_port, ev.mac, ev.user, int(ev.severity), ev.score,
             ev.message, json.dumps(ev.enrichment), json.dumps(sorted(ev.tags)),
             ev.raw),
        )
        self._conn.commit()

    def top_actors(self, limit: int = 20) -> list[dict]:
        cur = self._conn.execute(
            """SELECT src_ip, mac, MAX(score) s, COUNT(*) n, MAX(severity) sev
               FROM events WHERE src_ip IS NOT NULL
               GROUP BY src_ip ORDER BY s DESC LIMIT ?""", (limit,))
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()
