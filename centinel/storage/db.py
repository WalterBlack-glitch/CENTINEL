"""Capa de persistencia: event store en SQLite con cadena tamper-evident.

Guarda cada evento normalizado para auditoría/forense. Cada fila lleva un hash
HMAC-SHA256 **encadenado** con la fila anterior (estilo ledger): el hash de la
fila N depende del hash de la fila N-1 y del contenido de N. Si un atacante
edita, borra o reordena eventos para tapar sus huellas, la cadena deja de
cuadrar y `verify_chain()` lo detecta señalando la primera fila afectada.

Modelo de amenaza (honesto, sin vender humo):
  - La clave HMAC vive en `<db>.hmac` (0600). Un atacante que YA es root puede
    leer la clave y RECOMPUTAR la cadena tras manipular la BD. La cadena, por sí
    sola, NO es mágica contra root local.
  - Defensa real contra root: ANCLA `head_hash()` fuera de la máquina (syslog
    remoto, el webhook de alertas, incluso en papel) cada cierto tiempo.
    Cualquier reescritura de la historia divergirá del ancla externa.
  - Aun con la clave comprometida, un borrado de filas deja **huecos de id**
    (SQLite no reusa los AUTOINCREMENT): `verify_chain()` los reporta aparte.
  - Contra atacante NO-root, contra robo/edición OFFLINE de la BD, y contra
    corrupción/borrado accidental, la cadena es efectiva por sí misma.

Las escrituras van en un hilo aparte vía run_in_executor para no bloquear el
loop async; los inserts se serializan con un asyncio.Lock, así la cadena se
construye en orden estricto.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import sqlite3
import time
from pathlib import Path

from ..core import ThreatEvent
from ..keyring import load_or_create_key

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
    raw       TEXT,
    chain     TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
"""

# Hash semilla de la cadena (la "fila 0" imaginaria).
_GENESIS = "0" * 64
_LINK = b"\x1e"   # separador prev_hash || payload


def _row_payload(row: tuple) -> bytes:
    """Serialización determinista de (ts..raw) para el HMAC.

    JSON de una lista: sin ambigüedad de inyección de campos (las cadenas van
    entre comillas y escapadas). `ts`/`score` se normalizan a float ANTES de
    insertar, así el valor que se hashea es idéntico al que SQLite devuelve al
    verificar (REAL round-trip exacto)."""
    return json.dumps(list(row), separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8", "surrogatepass")


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
        self._migrate_chain()
        self._conn.commit()
        # Clave HMAC de la cadena (endurecida en keyring), junto al .db.
        self._key = load_or_create_key(self.path + ".hmac")
        self._last_hash = self._load_head()
        self._lock = asyncio.Lock()
        self._pending = 0
        self._last_commit = time.monotonic()
        self._commit_every = commit_every
        self._flush_secs = flush_secs

    # ---- cadena ----

    def _migrate_chain(self) -> None:
        """Añade la columna `chain` a BDs creadas antes de esta feature."""
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(events)")}
        if "chain" not in cols:
            self._conn.execute("ALTER TABLE events ADD COLUMN chain TEXT")

    def _load_head(self) -> str:
        cur = self._conn.execute(
            "SELECT chain FROM events WHERE chain IS NOT NULL "
            "ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        return row[0] if row and row[0] else _GENESIS

    def _chain_hash(self, prev: str, payload: bytes) -> str:
        return hmac.new(self._key, prev.encode() + _LINK + payload,
                        hashlib.sha256).hexdigest()

    def head_hash(self) -> str:
        """Hash de la cabeza actual. Ánclalo fuera de la máquina (anti-root)."""
        return self._last_hash

    # ---- escritura ----

    async def save(self, ev: ThreatEvent) -> None:
        async with self._lock:
            await asyncio.get_event_loop().run_in_executor(None, self._insert, ev)

    def _insert(self, ev: ThreatEvent) -> None:
        # Normaliza floats para que el valor hasheado == valor almacenado.
        ts = float(ev.ts)
        score = float(ev.score)
        enr = json.dumps(ev.enrichment)
        tags = json.dumps(sorted(ev.tags))
        row = (ts, ev.source, ev.kind, ev.src_ip, ev.dst_ip, ev.src_port,
               ev.dst_port, ev.mac, ev.user, int(ev.severity), score,
               ev.message, enr, tags, ev.raw)
        chain = self._chain_hash(self._last_hash, _row_payload(row))
        self._conn.execute(
            """INSERT INTO events
               (ts,source,kind,src_ip,dst_ip,src_port,dst_port,mac,user,
                severity,score,message,enrichment,tags,raw,chain)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (*row, chain))
        self._last_hash = chain
        # M-5: commit por lote (N inserts o cada flush_secs) en vez de por
        # evento, evita el vector de DoS de I/O bajo flood.
        self._pending += 1
        now = time.monotonic()
        if (self._pending >= self._commit_every
                or now - self._last_commit >= self._flush_secs):
            self._flush()

    def _flush(self) -> None:
        if self._pending:
            self._conn.commit()
            self._pending = 0
            self._last_commit = time.monotonic()

    # ---- verificación de integridad ----

    def verify_chain(self) -> dict:
        """Recorre la cadena y reporta si la BD fue manipulada.

        Devuelve un dict con:
          ok          -> bool: cadena intacta
          checked     -> nº de filas encadenadas verificadas
          legacy      -> filas antiguas sin encadenar (anteriores a la feature)
          gaps        -> [[id_prev, id_actual], ...] huecos de id (borrado)
          broken_at   -> id de la primera fila manipulada (si ok=False)
          reason      -> motivo legible (si ok=False)
          head        -> hash de la última fila verificada
        """
        self._flush()
        cur = self._conn.execute(
            "SELECT id,ts,source,kind,src_ip,dst_ip,src_port,dst_port,mac,user,"
            "severity,score,message,enrichment,tags,raw,chain "
            "FROM events ORDER BY id ASC")
        prev = _GENESIS
        started = False
        checked = 0
        legacy = 0
        last_id: int | None = None
        first_id: int | None = None
        gaps: list[list[int]] = []
        for r in cur:
            id_, chain = r[0], r[16]
            if chain is None:
                if started:
                    # Una fila sin hash DENTRO de la cadena = manipulación.
                    return {"ok": False, "checked": checked, "legacy": legacy,
                            "gaps": gaps, "broken_at": id_,
                            "reason": "fila sin hash dentro de la cadena "
                                      "(¿chain puesto a NULL?)"}
                legacy += 1
                continue
            if not started:
                started = True
                first_id = id_
            elif last_id is not None and id_ != last_id + 1:
                gaps.append([last_id, id_])
            want = self._chain_hash(prev, _row_payload(r[1:16]))
            if not hmac.compare_digest(chain, want):
                return {"ok": False, "checked": checked, "legacy": legacy,
                        "gaps": gaps, "broken_at": id_,
                        "reason": "hash no coincide "
                                  "(fila editada, eliminada o reordenada)"}
            prev = chain
            last_id = id_
            checked += 1
        return {"ok": True, "checked": checked, "legacy": legacy, "gaps": gaps,
                "first_id": first_id, "last_id": last_id, "head": prev}

    # ---- consultas ----

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def time_range(self) -> tuple[float | None, float | None]:
        r = self._conn.execute("SELECT MIN(ts), MAX(ts) FROM events").fetchone()
        return (r[0], r[1]) if r else (None, None)

    def by_severity(self) -> dict[int, int]:
        cur = self._conn.execute(
            "SELECT severity, COUNT(*) FROM events "
            "WHERE severity IS NOT NULL GROUP BY severity")
        return {int(s): n for s, n in cur.fetchall()}

    def by_kind(self, limit: int = 15) -> list[dict]:
        cur = self._conn.execute(
            "SELECT kind, COUNT(*) n, MAX(severity) sev FROM events "
            "WHERE kind IS NOT NULL AND kind != '' "
            "GROUP BY kind ORDER BY n DESC LIMIT ?", (limit,))
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def top_actors(self, limit: int = 20) -> list[dict]:
        cur = self._conn.execute(
            """SELECT src_ip, mac, MAX(score) s, COUNT(*) n, MAX(severity) sev
               FROM events WHERE src_ip IS NOT NULL
               GROUP BY src_ip ORDER BY s DESC LIMIT ?""", (limit,))
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def close(self) -> None:
        try:
            self._flush()
        except sqlite3.Error:
            pass
        self._conn.close()
