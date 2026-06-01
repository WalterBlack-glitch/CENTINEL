"""Capa de persistencia: event store en SQLite (sin deps externas).

Guarda cada evento normalizado para auditoría/forense posterior. Las escrituras
van en un hilo aparte vía run_in_executor para no bloquear el loop async.
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
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
    def __init__(self, path: str = "centinel.db",
                 commit_every: int = 50, flush_secs: float = 1.0) -> None:
        self.path = str(Path(path))
        # M-5: el .db contiene IPs/usuarios/logs sensibles -> no world-readable.
        old = os.umask(0o077)
        try:
            self._conn = sqlite3.connect(self.path, check_same_thread=False)
        finally:
            os.umask(old)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        # WAL: lecturas concurrentes (top_actors) sin bloquear escrituras.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._lock = asyncio.Lock()
        self._pending = 0
        self._last_commit = time.monotonic()
        self._commit_every = commit_every
        self._flush_secs = flush_secs

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
        # M-5: commit por lote (N inserts o cada flush_secs) en vez de por evento,
        # evita el vector de DoS de I/O bajo flood.
        self._pending += 1
        now = time.monotonic()
        if (self._pending >= self._commit_every
                or now - self._last_commit >= self._flush_secs):
            self._conn.commit()
            self._pending = 0
            self._last_commit = now

    def top_actors(self, limit: int = 20) -> list[dict]:
        cur = self._conn.execute(
            """SELECT src_ip, mac, MAX(score) s, COUNT(*) n, MAX(severity) sev
               FROM events WHERE src_ip IS NOT NULL
               GROUP BY src_ip ORDER BY s DESC LIMIT ?""", (limit,))
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def close(self) -> None:
        try:
            self._conn.commit()
        except sqlite3.Error:
            pass
        self._conn.close()
