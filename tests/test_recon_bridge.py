"""Tests del puente RECON → event store firmado.

Cubren: el traductor PURO para varios tipos de hallazgo, el dedupe por clave
natural, la integración real con el EventStore (cadena HMAC intacta) y el
degradado sin tumbar cuando el store falla (store mockeado).
"""
import asyncio

import pytest

from centinel.core import Severity
from centinel.recon import bridge
from centinel.recon.diff import key as diff_key
from centinel.recon.model import Finding
from centinel.storage.db import EventStore


# --------------------------------------------------------------------------
# Traductor puro
# --------------------------------------------------------------------------

def test_port_finding_se_traduce():
    f = Finding(kind="port", port=22, proto="tcp", state="open",
                service="ssh", version="OpenSSH 8.9p1")
    ev = bridge.finding_to_event(f, target="10.0.0.5", tool="nmap",
                                 scan_kind="quick", ts=123.0)
    assert ev.source == "recon"
    assert ev.kind == "recon_port"
    assert ev.dst_ip == "10.0.0.5"
    assert ev.dst_port == 22
    assert ev.ts == 123.0
    assert ev.severity == Severity.LOW          # puerto abierto = superficie
    assert "recon" in ev.tags and "nmap" in ev.tags
    assert ev.enrichment["recon_key"] == "port|22|tcp||"
    assert ev.enrichment["target"] == "10.0.0.5"
    assert ev.enrichment["tool"] == "nmap"
    assert "22" in ev.message and "ssh" in ev.message


def test_path_finding_se_traduce():
    f = Finding(kind="path", url="http://t/admin", status=200, length=512,
                fuzz="admin")
    ev = bridge.finding_to_event(f, target="t", tool="ffuf", ts=1.0)
    assert ev.kind == "recon_path"
    assert ev.dst_port is None
    assert ev.severity == Severity.LOW
    assert ev.enrichment["recon_key"] == "path|||http://t/admin|admin"
    assert "admin" in ev.message


def test_subdomain_finding_se_traduce():
    f = Finding(kind="subdomain", url="https://api.t", status=200, fuzz="api")
    ev = bridge.finding_to_event(f, target="t", tool="ffuf", ts=1.0)
    assert ev.kind == "recon_subdomain"
    assert ev.enrichment["recon_key"] == "subdomain|||https://api.t|api"
    assert ev.severity == Severity.LOW


def test_puerto_filtrado_es_info():
    f = Finding(kind="port", port=80, proto="tcp", state="filtered")
    ev = bridge.finding_to_event(f, target="t", ts=1.0)
    assert ev.severity == Severity.INFO


def test_ts_es_parametro_no_reloj():
    """La traducción es determinista: mismo input -> mismo ts (sin reloj)."""
    f = Finding(kind="port", port=443, proto="tcp", state="open")
    a = bridge.finding_to_event(f, target="t", ts=0.0)
    b = bridge.finding_to_event(f, target="t", ts=0.0)
    assert a.ts == 0.0 and b.ts == 0.0


def test_natural_key_coincide_con_clave_de_diff():
    """La clave del puente deriva de la misma tupla natural que diff/dedupe."""
    f = Finding(kind="port", port=22, proto="tcp", state="open", service="ssh")
    assert bridge.natural_key(f) == "|".join(
        "" if x is None else str(x) for x in diff_key(f))


# --------------------------------------------------------------------------
# Dedupe por clave natural
# --------------------------------------------------------------------------

def test_dedupe_por_clave_natural():
    f1 = Finding(kind="port", port=22, proto="tcp", state="open", service="ssh")
    # mismo puerto/proto, version distinta -> misma clave natural -> 1 solo evento
    f2 = Finding(kind="port", port=22, proto="tcp", state="open",
                 service="ssh", version="OpenSSH 9.0")
    f3 = Finding(kind="port", port=443, proto="tcp", state="open")
    evs = bridge.findings_to_events([f1, f2, f3], target="t", ts=1.0)
    assert len(evs) == 2
    keys = {e.enrichment["recon_key"] for e in evs}
    assert keys == {"port|22|tcp||", "port|443|tcp||"}


# --------------------------------------------------------------------------
# Integración real: cadena HMAC intacta (no se debilita)
# --------------------------------------------------------------------------

def test_persistencia_real_y_cadena_intacta(tmp_path):
    db = str(tmp_path / "ev.db")
    finds = [
        Finding(kind="port", port=22, proto="tcp", state="open", service="ssh"),
        Finding(kind="path", url="http://t/admin", status=200, fuzz="admin"),
    ]
    r = bridge.persist_findings(finds, target="10.0.0.5", tool="nmap",
                                scan_kind="quick", ts=5.0, db_path=db)
    assert r["ok"] and r["saved"] == 2
    assert r["head"] and r["head"] != "0" * 64

    st = EventStore(db)
    try:
        assert st.count() == 2
        chk = st.verify_chain()
        assert chk["ok"] and chk["checked"] == 2   # firmados igual que el resto
    finally:
        st.close()


def test_eventos_recon_conviven_con_eventos_ids(tmp_path):
    """Un evento del IDS y luego recon: la cadena sigue cuadrando."""
    from centinel.core import ThreatEvent

    db = str(tmp_path / "mix.db")
    st = EventStore(db)
    try:
        asyncio.run(st.save(ThreatEvent(source="authlog", kind="login_fail",
                                        src_ip="1.2.3.4")))
    finally:
        st.close()

    f = Finding(kind="port", port=22, proto="tcp", state="open", service="ssh")
    r = bridge.persist_findings([f], target="t", tool="nmap", ts=9.0, db_path=db)
    assert r["ok"] and r["saved"] == 1

    st2 = EventStore(db)
    try:
        assert st2.count() == 2
        assert st2.verify_chain()["ok"]
    finally:
        st2.close()


def test_sin_eventos_no_abre_store(tmp_path):
    db = str(tmp_path / "vacio.db")
    r = bridge.persist_findings([], target="t", db_path=db)
    assert r["ok"] and r["saved"] == 0


def test_dos_escritores_no_bifurcan_la_cadena(tmp_path):
    """Regresión: un store vivo (daemon) con la cabeza en memoria DESFASADA y un
    segundo escritor (recon --to-store) que confirma en medio. El daemon debe
    reencadenar sobre la fila del recon, no sobre su cabeza vieja, o verify_chain
    reportaría manipulación falsa."""
    from centinel.core import ThreatEvent

    db = str(tmp_path / "live.db")
    daemon = EventStore(db)                       # "daemon" de larga vida
    try:
        # El daemon escribe y confirma su primera fila.
        asyncio.run(daemon.save(ThreatEvent(source="authlog", kind="a",
                                            src_ip="1.1.1.1")))
        daemon.flush()
        cabeza_vieja = daemon.head_hash()

        # Otro proceso (recon) abre la MISMA bd, escribe y confirma. El daemon
        # aún tiene `cabeza_vieja` en memoria.
        f = Finding(kind="port", port=22, proto="tcp", state="open")
        r = bridge.persist_findings([f], target="t", tool="nmap", ts=9.0,
                                    db_path=db)
        assert r["ok"] and r["saved"] == 1
        assert r["head"] != cabeza_vieja          # recon encadenó sobre el daemon

        # El daemon escribe de nuevo: debe reencadenar sobre la fila del recon.
        asyncio.run(daemon.save(ThreatEvent(source="authlog", kind="b",
                                            src_ip="2.2.2.2")))
        daemon.flush()
    finally:
        daemon.close()

    st = EventStore(db)
    try:
        assert st.count() == 3
        chk = st.verify_chain()
        assert chk["ok"] and chk["checked"] == 3   # cadena intacta, sin bifurcar
    finally:
        st.close()


# --------------------------------------------------------------------------
# Degradar sin tumbar (store mockeado que falla)
# --------------------------------------------------------------------------

def test_degrada_si_el_store_no_construye(monkeypatch):
    import centinel.storage.db as dbmod

    def _boom(*a, **k):
        raise OSError("disco de solo lectura")

    monkeypatch.setattr(dbmod, "EventStore", _boom)
    logs = []
    f = Finding(kind="port", port=22, proto="tcp", state="open")
    # No debe lanzar: devuelve ok=False y loguea.
    r = bridge.persist_findings([f], target="t", ts=1.0, db_path="x.db",
                                log=logs.append)
    assert r["ok"] is False and r["saved"] == 0
    assert r["error"] and logs                       # se registró el motivo


def test_no_reporta_exito_si_el_commit_falla(monkeypatch):
    """Los inserts entran pero el commit por lote falla: persist_events debe
    devolver ok=False (antes `close()` tragaba el error y mentía éxito)."""
    import centinel.storage.db as dbmod

    class _FakeStore:
        def __init__(self, *a, **k):
            self.closed = False

        async def save(self, ev):
            pass                                  # el insert "va bien"

        def flush(self):
            raise RuntimeError("disco lleno")     # ...pero el commit revienta

        def head_hash(self):
            return "x"

        def close(self):
            self.closed = True

    monkeypatch.setattr(dbmod, "EventStore", _FakeStore)
    logs = []
    f = Finding(kind="port", port=22, proto="tcp", state="open")
    r = bridge.persist_findings([f], target="t", ts=1.0, db_path="x.db",
                                log=logs.append)
    assert r["ok"] is False and r["saved"] == 0
    assert "lleno" in r["error"] and logs


def test_degrada_si_save_falla(monkeypatch):
    import centinel.storage.db as dbmod

    class _FakeStore:
        def __init__(self, *a, **k):
            self.closed = False

        async def save(self, ev):
            raise RuntimeError("bd corrupta")

        def head_hash(self):
            return "x"

        def close(self):
            self.closed = True

    monkeypatch.setattr(dbmod, "EventStore", _FakeStore)
    logs = []
    f = Finding(kind="port", port=22, proto="tcp", state="open")
    r = bridge.persist_findings([f], target="t", ts=1.0, db_path="x.db",
                                log=logs.append)
    assert r["ok"] is False and r["saved"] == 0
    assert "corrupta" in r["error"] and logs
