"""Orquestación del escritorio: filtrado, historial, bitácora y modo --once.

Nada de esto llama a PowerShell: `collect` se simula siempre. Lo que se prueba
es el pegamento — que el umbral se respete, que el diff se calcule contra el
escaneo anterior y que la bitácora reciba lo que debe.
"""
from __future__ import annotations

import json
import os

import pytest

from centinel import desktop
from centinel.config import Config
from centinel.core import Severity, ThreatEvent
from centinel.snapshots import SnapshotStore
from centinel.storage.audit import AuditLog


def ev(name="svchost.exe", path=r"C:\Temp\svchost.exe", sev=Severity.CRITICAL,
       pid=100, reasons=("sin firma",), kind="proc_impersonation"):
    return ThreatEvent(kind=kind, severity=sev, message="sospechoso",
                       enrichment={"name": name, "path": path, "pid": pid,
                                   "reasons": list(reasons)})


@pytest.fixture
def entorno(tmp_path, monkeypatch):
    """Store y bitácora en tmp, y un `collect` simulado que no toca el sistema."""
    monkeypatch.setattr(os, "name", "nt")      # el modo --once exige Windows
    estado = {"events": [ev()], "n_procs": 42,
              "mem": {"total_mb": 8192, "free_mb": 4096, "top": []}}

    def fake_collect(cfg=None):
        return {"n_procs": estado["n_procs"], "events": list(estado["events"]),
                "mem": estado["mem"]}

    monkeypatch.setattr(desktop, "collect", fake_collect)
    monkeypatch.setattr(desktop, "default_history_dir",
                        lambda: str(tmp_path / "hist"))
    monkeypatch.setattr(desktop, "default_audit_path",
                        lambda: str(tmp_path / "audit.jsonl"))
    return estado, tmp_path


class TestVisibleEvents:
    def test_filtra_por_debajo_del_umbral(self):
        cfg = Config(min_severity=int(Severity.HIGH))
        events = [ev(sev=Severity.LOW), ev(sev=Severity.CRITICAL)]
        assert len(desktop.visible_events(events, cfg)) == 1

    def test_el_umbral_es_inclusivo(self):
        cfg = Config(min_severity=int(Severity.MEDIUM))
        assert desktop.visible_events([ev(sev=Severity.MEDIUM)], cfg)

    def test_umbral_cero_no_filtra_nada(self):
        cfg = Config(min_severity=0)
        assert len(desktop.visible_events([ev(sev=Severity.INFO)], cfg)) == 1


class TestRunScan:
    def test_devuelve_datos_diff_y_retrato(self, entorno):
        _estado, tmp = entorno
        data, d, snap = desktop.run_scan(Config(), host="PC1")
        assert data["n_procs"] == 42
        assert d.sin_historial and len(d.nuevos) == 1
        assert snap["host"] == "PC1" and snap["findings"]
        assert data["diff"] is d and data["snapshot"] is snap

    def test_el_segundo_escaneo_ve_lo_nuevo(self, entorno):
        estado, tmp = entorno
        cfg = Config()
        store = SnapshotStore(str(tmp / "h"))
        desktop.run_scan(cfg, store=store)
        estado["events"] = [ev(), ev(name="otro.exe", path=r"C:\T\otro.exe")]
        _data, d, _snap = desktop.run_scan(cfg, store=store)
        assert [f.name for f in d.nuevos] == ["otro.exe"]
        assert len(d.persistentes) == 1

    def test_hallazgo_que_desaparece_sale_como_resuelto(self, entorno):
        estado, tmp = entorno
        cfg = Config()
        store = SnapshotStore(str(tmp / "h"))
        desktop.run_scan(cfg, store=store)
        estado["events"] = []
        _data, d, _snap = desktop.run_scan(cfg, store=store)
        assert len(d.resueltos) == 1

    def test_respeta_el_umbral_antes_de_archivar(self, entorno):
        estado, tmp = entorno
        estado["events"] = [ev(sev=Severity.LOW), ev(name="g.exe", path="p",
                                                     sev=Severity.CRITICAL)]
        cfg = Config(min_severity=int(Severity.HIGH))
        data, _d, snap = desktop.run_scan(cfg, store=SnapshotStore(str(tmp / "h")))
        assert len(data["events"]) == 1
        assert len(snap["findings"]) == 1

    def test_anota_cada_evento_y_el_escaneo(self, entorno):
        _estado, tmp = entorno
        log = AuditLog(str(tmp / "a.jsonl"))
        desktop.run_scan(Config(), store=SnapshotStore(str(tmp / "h")), audit=log,
                         host="PC1")
        kinds = [r["kind"] for r in log.read_last()]
        assert "proc_impersonation" in kinds
        assert kinds[-1] == "scan"
        scan_rec = log.read_last()[-1]
        assert scan_rec["data"]["nuevos"] == 1 and scan_rec["data"]["host"] == "PC1"

    def test_usa_el_host_de_la_maquina_si_no_le_dan_uno(self, entorno):
        import platform
        _data, _d, snap = desktop.run_scan(Config())
        assert snap["host"] == platform.node()

    def test_respeta_el_tope_de_historial_del_config(self, entorno):
        _estado, tmp = entorno
        store = SnapshotStore(str(tmp / "h"))
        cfg = Config(history_keep=2)
        for _ in range(4):
            desktop.run_scan(cfg, store=store)
        assert len(store.load_all()) == 2

    def test_escaneo_limpio(self, entorno):
        estado, tmp = entorno
        estado["events"] = []
        data, d, snap = desktop.run_scan(Config(), store=SnapshotStore(str(tmp / "h")))
        assert data["events"] == [] and snap["findings"] == []
        assert "limpio" in d.resumen()


class TestEstadoDe:
    def test_marca_nuevo_y_agravado(self):
        from centinel.snapshots import diff, finding_from_event, snapshot
        prev = snapshot([ev(sev=Severity.LOW)], ts=1.0)
        e_agravado = ev(sev=Severity.CRITICAL)
        e_nuevo = ev(name="otro.exe", path=r"C:\T\o.exe")
        cur = snapshot([e_agravado, e_nuevo], ts=2.0)
        d = diff(prev, cur)
        assert desktop._estado_de(finding_from_event(e_agravado).key, d) == "agravado"
        assert desktop._estado_de(finding_from_event(e_nuevo).key, d) == "nuevo"

    def test_sin_historial_no_marca_nada(self):
        from centinel.snapshots import diff, finding_from_event, snapshot
        e = ev()
        d = diff(None, snapshot([e], ts=1.0))
        assert desktop._estado_de(finding_from_event(e).key, d) == ""

    def test_sin_diff_no_marca_nada(self):
        assert desktop._estado_de("k", None) == ""


class TestPrintScan:
    def test_limpio(self, capsys, entorno):
        estado, tmp = entorno
        estado["events"] = []
        data, d, _ = desktop.run_scan(Config(), store=SnapshotStore(str(tmp / "h")))
        desktop.print_scan(data, d)
        assert "LIMPIO" in capsys.readouterr().out

    def test_lista_los_hallazgos_con_severidad_y_motivo(self, capsys, entorno):
        _estado, tmp = entorno
        data, d, _ = desktop.run_scan(Config(), store=SnapshotStore(str(tmp / "h")))
        desktop.print_scan(data, d)
        out = capsys.readouterr().out
        assert "CRITICAL" in out and "svchost.exe" in out and "sin firma" in out

    def test_marca_los_nuevos_respecto_al_anterior(self, capsys, entorno):
        estado, tmp = entorno
        store = SnapshotStore(str(tmp / "h"))
        desktop.run_scan(Config(), store=store)
        estado["events"] = [ev(), ev(name="recien.exe", path=r"C:\T\r.exe")]
        data, d, _ = desktop.run_scan(Config(), store=store)
        desktop.print_scan(data, d)
        out = capsys.readouterr().out
        assert "NUEVO" in out and "recien.exe" in out

    def test_sin_diff_no_revienta(self, capsys):
        desktop.print_scan({"events": []}, None)
        assert "LIMPIO" in capsys.readouterr().out


class TestCli:
    def test_parser_acepta_las_opciones(self):
        a = desktop.build_parser().parse_args(
            ["--once", "--export", "json", "--outdir", "X", "--config", "c.toml"])
        assert a.once and a.export == "json" and a.outdir == "X"

    def test_export_solo_admite_formatos_conocidos(self):
        with pytest.raises(SystemExit):
            desktop.build_parser().parse_args(["--export", "pdf"])

    def test_write_config_sin_valor_usa_el_nombre_estandar(self):
        assert desktop.build_parser().parse_args(
            ["--write-config"]).write_config == "centinel.toml"

    def test_write_config_escribe_y_sale(self, tmp_path, capsys, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert desktop.main(["--write-config", "mi.toml"]) == 0
        assert (tmp_path / "mi.toml").exists()
        assert "ejemplo" in capsys.readouterr().out.lower()

    def test_once_devuelve_2_si_hay_hallazgos(self, entorno, capsys):
        assert desktop.main(["--once"]) == 2
        assert "svchost.exe" in capsys.readouterr().out

    def test_once_devuelve_0_si_esta_limpio(self, entorno, capsys):
        estado, _tmp = entorno
        estado["events"] = []
        assert desktop.main(["--once"]) == 0

    def test_once_con_export_deja_el_informe(self, entorno, tmp_path, capsys):
        destino = tmp_path / "informes"
        assert desktop.main(["--once", "--export", "json",
                             "--outdir", str(destino)]) == 2
        ficheros = list(destino.glob("centinel-*.json"))
        assert len(ficheros) == 1
        doc = json.loads(ficheros[0].read_text(encoding="utf-8"))
        assert doc["findings"][0]["name"] == "svchost.exe"
        assert "Informe:" in capsys.readouterr().out

    def test_export_html_escapado(self, entorno, tmp_path):
        estado, _tmp = entorno
        estado["events"] = [ev(name="<img src=x onerror=alert(1)>")]
        desktop.main(["--once", "--export", "html", "--outdir", str(tmp_path)])
        html = list(tmp_path.glob("centinel-*.html"))[0].read_text(encoding="utf-8")
        assert "<img src=x" not in html and "&lt;img" in html

    def test_fuera_de_windows_avisa_y_no_escanea(self, monkeypatch, capsys):
        monkeypatch.setattr(os, "name", "posix")
        monkeypatch.setattr(desktop, "collect",
                            lambda cfg=None: pytest.fail("no debe escanear"))
        assert desktop.main(["--once"]) == 1
        assert "Windows" in capsys.readouterr().out

    def test_muestra_los_avisos_del_config(self, entorno, tmp_path, capsys):
        malo = tmp_path / "malo.toml"
        malo.write_text("[deteccion]\nmin_severity = 99\n", encoding="utf-8")
        desktop.main(["--once", "--config", str(malo)])
        assert "config:" in capsys.readouterr().out

    def test_el_config_cambia_el_umbral_efectivo(self, entorno, tmp_path, capsys):
        estado, _tmp = entorno
        estado["events"] = [ev(sev=Severity.LOW)]
        cfg_file = tmp_path / "c.toml"
        cfg_file.write_text('[deteccion]\nmin_severity = "HIGH"\n', encoding="utf-8")
        assert desktop.main(["--once", "--config", str(cfg_file)]) == 0


class TestCollectRespetaElConfig:
    @pytest.fixture(autouse=True)
    def sin_salir_al_sistema(self, monkeypatch):
        """collect() habla con PowerShell: aquí nada de eso debe ocurrir."""
        from centinel.collectors import winpersist
        monkeypatch.setattr(desktop, "enumerate_windows_procs", lambda: [])
        monkeypatch.setattr(desktop, "scan", lambda *a, **k: [])
        monkeypatch.setattr(desktop, "windows_memory_summary", lambda: {})
        monkeypatch.setattr(winpersist, "enumerate_autoruns", lambda *a, **k: [])

    def test_sin_injectwatch_no_lo_llama(self, monkeypatch):
        from centinel.collectors import injectwatch
        monkeypatch.setattr(injectwatch, "enumerate_module_candidates",
                            lambda *a, **k: pytest.fail("no debe llamarse"))
        desktop.collect(Config(watch_injection=False, watch_hashes=False,
                               watch_persistence=False))

    def test_con_hashwatch_lo_llama(self, monkeypatch, tmp_path):
        llamado = {}
        monkeypatch.setattr(desktop, "_scan_hashes",
                            lambda cfg: llamado.setdefault("si", True) and [])
        desktop.collect(Config(watch_injection=False, watch_hashes=True,
                               watch_persistence=False))
        assert llamado.get("si")

    def test_las_rutas_del_config_llegan_al_clasificador(self, monkeypatch):
        visto = {}

        def fake_scan(procs, *, win_dir, writable_dirs, allowed_paths):
            visto["allowed"] = allowed_paths
            return []
        monkeypatch.setattr(desktop, "enumerate_windows_procs", lambda: [])
        monkeypatch.setattr(desktop, "scan", fake_scan)
        monkeypatch.setattr(desktop, "windows_memory_summary", lambda: {})
        desktop.collect(Config(allow_paths=(r"c:\tools",), watch_injection=False))
        assert visto["allowed"] == (r"c:\tools",)


    def test_sin_persistencia_no_la_llama(self, monkeypatch):
        from centinel.collectors import winpersist
        monkeypatch.setattr(winpersist, "scan",
                            lambda *a, **k: pytest.fail("no debe llamarse"))
        desktop.collect(Config(watch_injection=False, watch_hashes=False,
                               watch_persistence=False))

    def test_con_persistencia_suma_sus_hallazgos(self, monkeypatch):
        from centinel.collectors import winpersist
        monkeypatch.setattr(winpersist, "scan",
                            lambda *a, **k: [ev(kind="win_persistence")])
        data = desktop.collect(Config(watch_injection=False, watch_hashes=False,
                                      watch_persistence=True))
        assert [e.kind for e in data["events"]] == ["win_persistence"]

class TestConsolaLimitada:
    """La consola de Windows suele ser cp1252 y no sabe escribir '⚠' ni '✓'."""

    def test_imprimible_detecta_lo_que_cabe(self, monkeypatch):
        class Salida:
            encoding = "cp1252"
        monkeypatch.setattr(desktop.sys, "stdout", Salida())
        assert desktop._imprimible("hola") is True
        assert desktop._imprimible("⚠") is False

    def test_imprimible_con_encoding_desconocido(self, monkeypatch):
        class Salida:
            encoding = "no-existe-este-codec"
        monkeypatch.setattr(desktop.sys, "stdout", Salida())
        assert desktop._imprimible("x") is False

    def test_imprimible_sin_encoding(self, monkeypatch):
        class Salida:
            encoding = None
        monkeypatch.setattr(desktop.sys, "stdout", Salida())
        assert desktop._imprimible("⚠") is False
        assert desktop._imprimible("x") is True

    def test_print_scan_en_consola_cp1252_no_revienta(self, tmp_path, monkeypatch):
        import io
        crudo = io.BytesIO()
        salida = io.TextIOWrapper(crudo, encoding="cp1252", errors="strict",
                                  newline="")
        monkeypatch.setattr(desktop.sys, "stdout", salida)
        data = {"events": [ev(reasons=("sin firma",))]}
        desktop.print_scan(data, None)          # antes: UnicodeEncodeError
        salida.flush()
        texto = crudo.getvalue().decode("cp1252")
        assert "!!" in texto and "svchost.exe" in texto

    def test_print_scan_limpio_en_cp1252(self, monkeypatch):
        import io
        crudo = io.BytesIO()
        salida = io.TextIOWrapper(crudo, encoding="cp1252", errors="strict",
                                  newline="")
        monkeypatch.setattr(desktop.sys, "stdout", salida)
        desktop.print_scan({"events": []}, None)
        salida.flush()
        assert "OK LIMPIO" in crudo.getvalue().decode("cp1252")

    def test_en_consola_utf8_usa_los_simbolos_bonitos(self, monkeypatch, capsys):
        desktop.print_scan({"events": []}, None)
        assert "✓" in capsys.readouterr().out

