"""Tests de la cadena tamper-evident del event store.

Cubre: integridad en el camino feliz, detección de edición/borrado de filas,
persistencia de la cadena entre sesiones y tolerancia a BDs antiguas sin
columna `chain` (migración + filas legacy).
"""
import asyncio
import sqlite3

from centinel.core import ThreatEvent, Severity
from centinel.storage.db import EventStore


def _ev(kind, ip, sev=Severity.LOW, msg="x"):
    return ThreatEvent(kind=kind, src_ip=ip, severity=sev, message=msg)


def _save_many(store, evs):
    async def go():
        for e in evs:
            await store.save(e)
    asyncio.run(go())


def test_cadena_intacta_verifica_ok(tmp_path):
    db = str(tmp_path / "c.db")
    st = EventStore(db)
    _save_many(st, [_ev("login_fail", f"1.2.3.{i}") for i in range(10)])
    res = st.verify_chain()
    head = st.head_hash()
    st.close()
    assert res["ok"] is True
    assert res["checked"] == 10
    assert res["gaps"] == []
    assert head != "0" * 64        # la cabeza avanzó respecto al génesis


def test_tampering_de_fila_se_detecta(tmp_path):
    db = str(tmp_path / "c.db")
    st = EventStore(db)
    _save_many(st, [_ev("login_fail", f"9.9.9.{i}") for i in range(8)])
    st.close()
    # Atacante edita el contenido de una fila SIN recomputar el hash (no tiene
    # la clave HMAC).
    conn = sqlite3.connect(db)
    conn.execute("UPDATE events SET message='benigno' WHERE id=4")
    conn.commit()
    conn.close()
    st2 = EventStore(db)
    res = st2.verify_chain()
    st2.close()
    assert res["ok"] is False
    assert res["broken_at"] == 4


def test_borrado_de_fila_se_detecta(tmp_path):
    db = str(tmp_path / "c.db")
    st = EventStore(db)
    _save_many(st, [_ev("port_scan", f"8.8.8.{i}") for i in range(8)])
    st.close()
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM events WHERE id=5")
    conn.commit()
    conn.close()
    st2 = EventStore(db)
    res = st2.verify_chain()
    st2.close()
    # La fila 6 ya no encadena con la 4 -> rompe en id=6, y deja hueco 4->6.
    assert res["ok"] is False
    assert res["broken_at"] == 6
    assert [4, 6] in res["gaps"]


def test_cadena_persiste_entre_sesiones(tmp_path):
    db = str(tmp_path / "c.db")
    st = EventStore(db)
    _save_many(st, [_ev("x", "1.1.1.1") for _ in range(4)])
    st.close()
    # Reabrir y seguir escribiendo: la cadena debe continuar, no reiniciarse.
    st2 = EventStore(db)
    _save_many(st2, [_ev("x", "2.2.2.2") for _ in range(4)])
    res = st2.verify_chain()
    st2.close()
    assert res["ok"] is True
    assert res["checked"] == 8


def test_filas_legacy_sin_cadena_se_toleran(tmp_path):
    """Una BD creada antes de la feature (sin columna chain) debe migrar y
    seguir verificando: las filas viejas se marcan como 'legacy', las nuevas
    se encadenan."""
    db = str(tmp_path / "old.db")
    conn = sqlite3.connect(db)
    conn.executescript(
        """CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, source TEXT, kind TEXT,
            src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER, mac TEXT,
            user TEXT, severity INTEGER, score REAL, message TEXT, enrichment TEXT,
            tags TEXT, raw TEXT);""")
    for i in range(2):
        conn.execute(
            "INSERT INTO events (ts,kind,severity,score,enrichment,tags) "
            "VALUES (?,?,?,?,?,?)", (float(i), "old", 0, 0.0, "{}", "[]"))
    conn.commit()
    conn.close()
    st = EventStore(db)   # migra: añade la columna chain
    _save_many(st, [_ev("new", "3.3.3.3") for _ in range(3)])
    res = st.verify_chain()
    st.close()
    assert res["ok"] is True
    assert res["legacy"] == 2
    assert res["checked"] == 3
