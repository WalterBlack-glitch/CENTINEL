"""Bitácora JSONL: formato, rotación, degradado y conveniencias."""
from __future__ import annotations

import json
import os

import pytest

from centinel.core import Severity, ThreatEvent
from centinel.snapshots import diff, snapshot
from centinel.storage.audit import AuditLog, default_audit_path


@pytest.fixture
def log(tmp_path):
    return AuditLog(str(tmp_path / "logs" / "audit.jsonl"))


def ev(name="svchost.exe", sev=Severity.CRITICAL):
    return ThreatEvent(kind="proc_impersonation", severity=sev,
                       message="sospechoso",
                       enrichment={"name": name, "pid": 7, "path": r"C:\T\s.exe",
                                   "signer": "", "reasons": ["sin firma"]})


class TestEscritura:
    def test_una_linea_json_por_registro(self, log):
        assert log.write("scan", "hecho")
        assert log.write("scan", "otra vez")
        with open(log.path, encoding="utf-8") as f:
            lineas = [l for l in f.read().splitlines() if l]
        assert len(lineas) == 2
        assert json.loads(lineas[0])["kind"] == "scan"

    def test_campos_obligatorios(self, log):
        log.write("scan", "hecho", level="WARNING")
        rec = log.read_last()[0]
        assert rec["kind"] == "scan" and rec["message"] == "hecho"
        assert rec["level"] == "WARNING"
        assert isinstance(rec["ts"], float) and rec["iso"].startswith("20")

    def test_los_extras_van_en_data(self, log):
        log.write("scan", "x", total=3, host="PC1")
        assert log.read_last()[0]["data"] == {"total": 3, "host": "PC1"}

    def test_sin_extras_no_hay_data(self, log):
        log.write("scan")
        assert "data" not in log.read_last()[0]

    def test_crea_el_directorio(self, tmp_path):
        p = tmp_path / "a" / "b" / "audit.jsonl"
        AuditLog(str(p)).write("x")
        assert os.path.exists(p)

    def test_cuenta_lo_escrito(self, log):
        for _ in range(3):
            log.write("x")
        assert log.written == 3

    def test_acentos_tal_cual(self, log):
        log.write("scan", "España ñandú")
        assert "ñandú" in open(log.path, encoding="utf-8").read()

    def test_dato_no_serializable_no_pierde_la_linea(self, log):
        log.write("scan", "x", raro=object())
        rec = log.read_last()[0]
        assert rec["kind"] in ("scan", "audit_encode_error")

    def test_append_no_pisa_lo_anterior(self, tmp_path):
        p = str(tmp_path / "audit.jsonl")
        AuditLog(p).write("primero")
        AuditLog(p).write("segundo")
        assert len(AuditLog(p).read_last()) == 2

    def test_disco_fallando_devuelve_false(self, log, monkeypatch):
        monkeypatch.setattr(os, "open",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("lleno")))
        assert log.write("x") is False

    def test_deshabilitado_si_no_se_puede_crear_el_directorio(self, tmp_path,
                                                              monkeypatch):
        monkeypatch.setattr(os, "makedirs",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("no")))
        lg = AuditLog(str(tmp_path / "x" / "audit.jsonl"))
        assert lg.disabled
        assert lg.write("x") is False and lg.read_last() == []


class TestLectura:
    def test_devuelve_los_ultimos_en_orden(self, log):
        for i in range(5):
            log.write("scan", str(i))
        recs = log.read_last(3)
        assert [r["message"] for r in recs] == ["2", "3", "4"]

    def test_sin_fichero_lista_vacia(self, log):
        assert log.read_last() == []

    def test_salta_lineas_corruptas(self, log):
        log.write("bueno")
        with open(log.path, "a", encoding="utf-8") as f:
            f.write("no soy json\n\n")
            f.write(json.dumps(["lista", "no", "dict"]) + "\n")
        recs = log.read_last()
        assert len(recs) == 1 and recs[0]["kind"] == "bueno"

    def test_n_cero_o_negativo(self, log):
        log.write("x")
        assert log.read_last(0) == [] and log.read_last(-1) == []

    def test_size(self, log):
        assert log.size() == 0
        log.write("x")
        assert log.size() > 0


class TestRotacion:
    def test_rota_al_pasarse_de_tamano(self, tmp_path):
        lg = AuditLog(str(tmp_path / "audit.jsonl"), max_bytes=200, keep=2)
        for i in range(20):
            lg.write("scan", "x" * 50)
        assert os.path.exists(lg.path)
        assert os.path.exists(lg.path + ".1")
        assert lg.size() <= 400

    def test_no_guarda_mas_de_keep(self, tmp_path):
        lg = AuditLog(str(tmp_path / "audit.jsonl"), max_bytes=100, keep=2)
        for i in range(40):
            lg.write("scan", "y" * 50)
        assert not os.path.exists(lg.path + ".3")

    def test_keep_cero_descarta_lo_viejo(self, tmp_path):
        lg = AuditLog(str(tmp_path / "audit.jsonl"), max_bytes=100, keep=0)
        for i in range(10):
            lg.write("scan", "z" * 50)
        assert not os.path.exists(lg.path + ".1")
        assert os.path.exists(lg.path)

    def test_max_bytes_cero_no_rota_nunca(self, tmp_path):
        lg = AuditLog(str(tmp_path / "audit.jsonl"), max_bytes=0)
        for i in range(30):
            lg.write("scan", "w" * 50)
        assert not os.path.exists(lg.path + ".1")
        assert len(lg.read_last(100)) == 30

    def test_lo_rotado_conserva_json_valido(self, tmp_path):
        lg = AuditLog(str(tmp_path / "audit.jsonl"), max_bytes=200, keep=2)
        for i in range(20):
            lg.write("scan", "x" * 50)
        with open(lg.path + ".1", encoding="utf-8") as f:
            for linea in f.read().splitlines():
                if linea.strip():
                    assert isinstance(json.loads(linea), dict)


class TestConveniencias:
    def test_log_event_recoge_el_enrichment(self, log):
        log.log_event(ev())
        rec = log.read_last()[0]
        assert rec["kind"] == "proc_impersonation"
        assert rec["level"] == "CRITICAL"
        assert rec["data"]["name"] == "svchost.exe"
        assert rec["data"]["pid"] == 7
        assert rec["data"]["reasons"] == ["sin firma"]

    def test_log_event_de_evento_pelado(self, log):
        log.log_event(ThreatEvent(kind="x", severity=Severity.LOW))
        assert log.read_last()[0]["level"] == "LOW"

    def test_log_event_con_severidad_invalida(self, log):
        e = ThreatEvent(kind="x")
        e.severity = "no-es-severidad"
        log.log_event(e)
        assert log.read_last()[0]["level"] == "INFO"

    def test_log_scan_resume_el_diff(self, log):
        prev = snapshot([], ts=1.0)
        cur = snapshot([ev()], ts=2.0)
        d = diff(prev, cur)
        log.log_scan(d, cur, host="PC1")
        rec = log.read_last()[0]
        assert rec["kind"] == "scan"
        assert rec["level"] == "WARNING"        # hubo cambios
        assert rec["data"]["nuevos"] == 1
        assert rec["data"]["total"] == 1
        assert rec["data"]["host"] == "PC1"

    def test_log_scan_sin_cambios_es_info(self, log):
        cur = snapshot([ev()], ts=2.0)
        log.log_scan(diff(snapshot([ev()], ts=1.0), cur), cur)
        assert log.read_last()[0]["level"] == "INFO"

    def test_log_scan_sin_diff(self, log):
        log.log_scan(None, snapshot([], ts=1.0))
        rec = log.read_last()[0]
        assert rec["level"] == "INFO" and rec["data"]["nuevos"] == 0

    def test_log_scan_toma_el_host_del_retrato(self, log):
        cur = snapshot([], ts=1.0, host="DESDE-SNAP")
        log.log_scan(None, cur)
        assert log.read_last()[0]["data"]["host"] == "DESDE-SNAP"


class TestRutaPorDefecto:
    def test_cuelga_del_mismo_sitio_que_el_historial(self, monkeypatch):
        monkeypatch.setattr(os, "name", "nt")
        monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\x\AppData\Local")
        p = default_audit_path()
        assert p.endswith("audit.jsonl") and "CENTINEL" in p
