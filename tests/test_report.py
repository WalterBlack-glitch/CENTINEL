"""Tests del informe forense y la verificación de integridad desde la CLI."""
import asyncio
import sqlite3

from centinel.core import ThreatEvent, Severity
from centinel.storage.db import EventStore
from centinel.storage.report import forensic_report, verify_log


def _populate(db):
    st = EventStore(db)

    async def go():
        for _ in range(6):
            await st.save(ThreatEvent(kind="auth_bruteforce", src_ip="1.2.3.4",
                                      severity=Severity.HIGH, score=80.0,
                                      message="fuerza bruta"))
        await st.save(ThreatEvent(kind="exfil_dns", src_ip="5.6.7.8",
                                  severity=Severity.CRITICAL, message="exfil"))
    asyncio.run(go())
    st.close()


def test_report_incluye_secciones_clave(tmp_path):
    db = str(tmp_path / "r.db")
    _populate(db)
    txt = forensic_report(db)
    assert "informe forense" in txt
    assert "auth_bruteforce" in txt
    assert "T1110.001" in txt              # TTP MITRE de la fuerza bruta
    assert "integridad de la cadena" in txt
    assert "intacta" in txt
    assert "1.2.3.4" in txt                # actor principal


def test_report_db_vacia_no_revienta(tmp_path):
    db = str(tmp_path / "empty.db")
    txt = forensic_report(db)
    assert "vacío" in txt
    assert "integridad de la cadena" in txt


def test_verify_log_ok(tmp_path):
    db = str(tmp_path / "r.db")
    _populate(db)
    ok, txt = verify_log(db)
    assert ok is True
    assert "[OK]" in txt


def test_verify_log_detecta_tampering(tmp_path):
    db = str(tmp_path / "r.db")
    _populate(db)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE events SET src_ip='0.0.0.0' WHERE id=2")
    conn.commit()
    conn.close()
    ok, txt = verify_log(db)
    assert ok is False
    assert "MANIPULACIÓN" in txt


def test_verify_log_bd_inexistente(tmp_path):
    ok, txt = verify_log(str(tmp_path / "nope.db"))
    assert ok is False
    assert "no existe" in txt
