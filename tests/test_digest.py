"""Tests del digest periódico.

`build_digest` es pura: se prueba con resúmenes a mano, sin red ni BD. El
extremo a extremo (summary_since -> build_digest) se prueba con una BD temporal.
"""
import time

from centinel.digest import build_digest, DigestService, _sev_label
from centinel.storage.db import EventStore
from centinel.core import ThreatEvent, Severity


# ---- build_digest (pura) ----

def test_digest_vacio_lo_dice():
    out = build_digest({"total": 0, "severity": {}, "kinds": [], "actors": []},
                       window_h=24.0)
    assert "sin eventos" in out["text"]
    assert out["centinel"]["total"] == 0
    assert out["centinel"]["digest"] is True


def test_digest_cuenta_critical_y_high():
    summary = {"total": 7, "severity": {4: 2, 3: 3, 1: 2},
               "kinds": [{"kind": "beacon_c2", "n": 4}],
               "actors": [{"src_ip": "10.0.0.9", "n": 4}]}
    out = build_digest(summary, window_h=12.0)
    c = out["centinel"]
    assert c["critical"] == 2 and c["high"] == 3 and c["total"] == 7
    assert "beacon_c2×4" in out["text"]
    assert "10.0.0.9(4)" in out["text"]
    assert c["window_hours"] == 12.0


def test_digest_marca_cadena_manipulada():
    out = build_digest({"total": 1, "severity": {3: 1}, "kinds": [], "actors": []},
                       window_h=24.0, chain={"ok": False, "head": "deadbeef"})
    assert "MANIPULADA" in out["text"]
    assert out["centinel"]["chain_ok"] is False


def test_digest_cadena_integra():
    out = build_digest({"total": 0, "severity": {}, "kinds": [], "actors": []},
                       window_h=24.0, chain={"ok": True, "head": "a" * 64})
    assert "íntegra" in out["text"]
    assert out["centinel"]["chain_head"] == "a" * 64


def test_sev_label_acota():
    assert _sev_label(4) == "CRITICAL"
    assert _sev_label(99) == "CRITICAL"
    assert _sev_label(-5) == "INFO"


# ---- URL peligrosa -> servicio desactivado ----

def test_digest_url_metadata_se_desactiva():
    dg = DigestService("x.db", "http://169.254.169.254/latest/")
    assert dg.available() is False


def test_digest_url_valida_se_activa():
    dg = DigestService("x.db", "https://hooks.example.com/abc")
    assert dg.available() is True


# ---- extremo a extremo: summary_since -> build_digest ----

def test_summary_since_filtra_por_ventana(tmp_path):
    db = str(tmp_path / "d.db")
    st = EventStore(db)
    now = time.time()
    # Un evento viejo (fuera de ventana) y dos recientes.
    st._insert(ThreatEvent(kind="old", severity=Severity.LOW,
                           message="viejo", ts=now - 100000))
    st._insert(ThreatEvent(kind="beacon_c2", severity=Severity.HIGH,
                           message="reciente", src_ip="1.2.3.4", ts=now))
    st._insert(ThreatEvent(kind="beacon_c2", severity=Severity.CRITICAL,
                           message="reciente2", src_ip="1.2.3.4", ts=now))
    summary = st.summary_since(now - 3600)
    st.close()
    assert summary["total"] == 2
    out = build_digest(summary, window_h=1.0)
    assert out["centinel"]["total"] == 2
    assert out["centinel"]["high"] == 1 and out["centinel"]["critical"] == 1
    assert any(k["kind"] == "beacon_c2" for k in summary["kinds"])
