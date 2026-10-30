"""Historial de escaneos y diff: identidad estable, cambios y firma del historial."""
from __future__ import annotations

import json
import os

import pytest

from centinel.core import Severity, ThreatEvent
from centinel.snapshots import (
    Diff, Finding, SnapshotStore, default_history_dir, diff, finding_key,
    finding_from_event, findings_of, norm_path, record_and_diff, snapshot,
)


def ev(name="svchost.exe", path=r"C:\Temp\svchost.exe", sev=Severity.CRITICAL,
       pid=100, reasons=("sin firma",), kind="proc_impersonation"):
    return ThreatEvent(kind=kind, severity=sev, message="x",
                       enrichment={"name": name, "path": path, "pid": pid,
                                   "reasons": list(reasons)})


# ------------------------------------------------------------------ identidad
class TestIdentidad:
    def test_misma_ruta_distinto_caso_o_separador_es_el_mismo_hallazgo(self):
        a = finding_key("k", "Svchost.exe", r"C:\Temp\Svchost.exe")
        b = finding_key("k", "svchost.exe", "c:/temp/svchost.exe")
        assert a == b

    def test_prefijo_extendido_se_normaliza(self):
        assert norm_path(r"\\?\C:\X\a.exe") == r"c:\x\a.exe"
        assert norm_path("") == ""

    def test_el_pid_no_entra_en_la_identidad(self):
        f1 = finding_from_event(ev(pid=100))
        f2 = finding_from_event(ev(pid=999))
        assert f1.key == f2.key

    def test_distinta_ruta_es_otro_hallazgo(self):
        assert (finding_from_event(ev(path=r"C:\A\x.exe")).key
                != finding_from_event(ev(path=r"C:\B\x.exe")).key)

    def test_distinto_kind_es_otro_hallazgo(self):
        assert (finding_from_event(ev(kind="proc_impersonation")).key
                != finding_from_event(ev(kind="dll_injection")).key)

    def test_evento_sin_enrichment_no_revienta(self):
        f = finding_from_event(ThreatEvent(kind="x", severity=Severity.LOW))
        assert f.key and f.name == "" and f.pid is None

    def test_usa_module_cuando_no_hay_path(self):
        e = ThreatEvent(kind="dll_injection", severity=Severity.HIGH,
                        enrichment={"name": "host.exe", "module": r"C:\T\n.dll"})
        assert norm_path(r"C:\T\n.dll") in norm_path(finding_from_event(e).path)

    def test_round_trip_de_finding(self):
        f = finding_from_event(ev())
        assert Finding.from_dict(f.to_dict()) == f

    def test_from_dict_tolera_basura(self):
        f = Finding.from_dict({"key": "k", "pid": "no-es-int", "severity": None})
        assert f.pid is None and f.severity == 0


# ------------------------------------------------------------------- snapshot
class TestSnapshot:
    def test_ordena_por_severidad_descendente(self):
        snap = snapshot([ev(name="a.exe", path="p1", sev=Severity.LOW),
                         ev(name="b.exe", path="p2", sev=Severity.CRITICAL)])
        assert [f["name"] for f in snap["findings"]] == ["b.exe", "a.exe"]

    def test_colapsa_duplicados_quedandose_con_lo_peor(self):
        snap = snapshot([ev(sev=Severity.LOW), ev(sev=Severity.CRITICAL)])
        assert len(snap["findings"]) == 1
        assert snap["findings"][0]["severity"] == int(Severity.CRITICAL)

    def test_guarda_ts_y_host(self):
        snap = snapshot([], ts=123.0, host="pc1")
        assert snap["ts"] == 123.0 and snap["host"] == "pc1"
        assert snap["findings"] == []

    def test_eventos_none_es_retrato_vacio(self):
        assert snapshot(None)["findings"] == []

    def test_es_serializable_a_json(self):
        json.dumps(snapshot([ev()]))

    def test_findings_of_ignora_entradas_corruptas(self):
        d = findings_of({"findings": [None, "x", {}, {"key": "k", "name": "n"}]})
        assert list(d) == ["k"]

    def test_findings_of_de_none(self):
        assert findings_of(None) == {}


# ----------------------------------------------------------------------- diff
class TestDiff:
    def test_primer_escaneo_todo_nuevo_y_sin_historial(self):
        d = diff(None, snapshot([ev()]))
        assert d.sin_historial and len(d.nuevos) == 1
        assert "Primer escaneo" in d.resumen()

    def test_primer_escaneo_limpio(self):
        assert "limpio" in diff(None, snapshot([])).resumen()

    def test_hallazgo_nuevo(self):
        prev = snapshot([ev(name="a.exe", path="p1")])
        cur = snapshot([ev(name="a.exe", path="p1"), ev(name="b.exe", path="p2")])
        d = diff(prev, cur)
        assert [f.name for f in d.nuevos] == ["b.exe"]
        assert len(d.persistentes) == 1 and not d.resueltos
        assert "1 nuevo(s)" in d.resumen()

    def test_hallazgo_resuelto(self):
        d = diff(snapshot([ev()]), snapshot([]))
        assert len(d.resueltos) == 1 and not d.nuevos
        assert "1 resuelto(s)" in d.resumen()

    def test_persistente_no_cuenta_como_cambio(self):
        d = diff(snapshot([ev()]), snapshot([ev()]))
        assert not d.hay_cambios
        assert "Sin cambios" in d.resumen()

    def test_mismo_hallazgo_con_otro_pid_sigue_siendo_persistente(self):
        d = diff(snapshot([ev(pid=1)]), snapshot([ev(pid=2)]))
        assert len(d.persistentes) == 1 and not d.nuevos

    def test_agravado_cuando_sube_la_severidad(self):
        d = diff(snapshot([ev(sev=Severity.LOW)]), snapshot([ev(sev=Severity.CRITICAL)]))
        assert len(d.agravados) == 1
        viejo, nuevo = d.agravados[0]
        assert viejo.severity < nuevo.severity
        assert d.hay_cambios and "1 agravado(s)" in d.resumen()

    def test_bajar_de_severidad_no_es_agravado(self):
        d = diff(snapshot([ev(sev=Severity.CRITICAL)]), snapshot([ev(sev=Severity.LOW)]))
        assert not d.agravados and len(d.persistentes) == 1

    def test_peor_nuevo_informa_la_severidad_mas_alta(self):
        cur = snapshot([ev(name="a.exe", path="p1", sev=Severity.LOW),
                        ev(name="b.exe", path="p2", sev=Severity.HIGH)])
        d = diff(snapshot([]), cur)
        assert d.peor_nuevo == int(Severity.HIGH)
        assert "HIGH" in d.resumen()

    def test_peor_nuevo_sin_nuevos_es_cero(self):
        assert diff(snapshot([]), snapshot([])).peor_nuevo == 0

    def test_nuevos_vienen_ordenados_por_gravedad(self):
        cur = snapshot([ev(name="leve.exe", path="p1", sev=Severity.LOW),
                        ev(name="grave.exe", path="p2", sev=Severity.CRITICAL)])
        assert [f.name for f in diff(snapshot([]), cur).nuevos] == ["grave.exe",
                                                                    "leve.exe"]

    def test_guarda_las_marcas_de_tiempo(self):
        d = diff(snapshot([], ts=1.0), snapshot([], ts=2.0))
        assert (d.prev_ts, d.cur_ts) == (1.0, 2.0)


# ---------------------------------------------------------------------- store
class TestSnapshotStore:
    def test_append_y_load_last(self, tmp_path):
        st = SnapshotStore(str(tmp_path / "h"))
        assert st.append(snapshot([ev()], ts=1.0))
        assert st.append(snapshot([], ts=2.0))
        assert st.load_last()["ts"] == 2.0
        assert len(st.load_all()) == 2

    def test_load_sin_fichero_devuelve_vacio(self, tmp_path):
        st = SnapshotStore(str(tmp_path / "h"))
        assert st.load_all() == [] and st.load_last() is None

    def test_limit_devuelve_los_mas_recientes(self, tmp_path):
        st = SnapshotStore(str(tmp_path / "h"))
        for i in range(5):
            st.append(snapshot([], ts=float(i)))
        assert [s["ts"] for s in st.load_all(limit=2)] == [3.0, 4.0]

    def test_linea_manipulada_se_rechaza(self, tmp_path):
        st = SnapshotStore(str(tmp_path / "h"))
        st.append(snapshot([ev(name="bueno.exe")], ts=1.0))
        with open(st.path, encoding="utf-8") as f:
            linea = json.loads(f.read().strip())
        # Un atacante inyecta su implante como "ya estaba ayer" sin tocar la firma.
        linea["snapshot"]["findings"].append(
            {"key": "falso", "kind": "k", "name": "implante.exe", "severity": 4})
        with open(st.path, "w", encoding="utf-8") as f:
            f.write(json.dumps(linea) + "\n")
        assert st.load_all() == []
        assert st.rejected == 1

    def test_firma_de_otra_clave_no_vale(self, tmp_path):
        st1 = SnapshotStore(str(tmp_path / "a"))
        st1.append(snapshot([ev()], ts=1.0))
        with open(st1.path, encoding="utf-8") as f:
            linea = f.read()
        st2 = SnapshotStore(str(tmp_path / "b"))
        with open(st2.path, "w", encoding="utf-8") as f:
            f.write(linea)
        assert st2.load_all() == [] and st2.rejected == 1

    def test_lineas_vacias_y_basura_no_revientan(self, tmp_path):
        st = SnapshotStore(str(tmp_path / "h"))
        st.append(snapshot([], ts=1.0))
        with open(st.path, "a", encoding="utf-8") as f:
            f.write("\n")
            f.write("no soy json\n")
            f.write(json.dumps({"sin": "snapshot"}) + "\n")
            f.write(json.dumps({"snapshot": "no es dict", "__hmac__": "x"}) + "\n")
        assert len(st.load_all()) == 1
        assert st.rejected == 3

    def test_linea_desmesurada_se_descarta(self, tmp_path):
        st = SnapshotStore(str(tmp_path / "h"))
        with open(st.path, "w", encoding="utf-8") as f:
            f.write("x" * (1 << 21) + "\n")
        assert st.load_all() == [] and st.rejected == 1

    def test_prune_conserva_los_ultimos(self, tmp_path):
        st = SnapshotStore(str(tmp_path / "h"))
        for i in range(10):
            st.append(snapshot([], ts=float(i)))
        assert st.prune(3) == 3
        assert [s["ts"] for s in st.load_all()] == [7.0, 8.0, 9.0]

    def test_prune_no_toca_si_hay_menos(self, tmp_path):
        st = SnapshotStore(str(tmp_path / "h"))
        st.append(snapshot([], ts=1.0))
        assert st.prune(5) == 1
        assert len(st.load_all()) == 1

    def test_prune_cero_vacia_el_historial(self, tmp_path):
        st = SnapshotStore(str(tmp_path / "h"))
        for i in range(3):
            st.append(snapshot([], ts=float(i)))
        assert st.prune(0) == 0
        assert st.load_all() == []

    def test_lo_guardado_sobrevive_a_otra_instancia(self, tmp_path):
        d = str(tmp_path / "h")
        SnapshotStore(d).append(snapshot([ev(name="persiste.exe")], ts=1.0))
        snap = SnapshotStore(d).load_last()
        assert snap["findings"][0]["name"] == "persiste.exe"

    def test_acentos_y_rutas_unicode(self, tmp_path):
        st = SnapshotStore(str(tmp_path / "h"))
        st.append(snapshot([ev(name="ñandú.exe", path=r"C:\Música\ñ.exe")]))
        assert st.load_last()["findings"][0]["name"] == "ñandú.exe"

    def test_store_deshabilitado_degrada_sin_reventar(self, tmp_path, monkeypatch):
        monkeypatch.setattr(os, "makedirs",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("no")))
        st = SnapshotStore(str(tmp_path / "x"))
        assert st.disabled
        assert st.append(snapshot([])) is False
        assert st.load_all() == [] and st.load_last() is None
        assert st.prune(5) == 0

    def test_append_con_disco_fallando_devuelve_false(self, tmp_path, monkeypatch):
        st = SnapshotStore(str(tmp_path / "h"))
        monkeypatch.setattr(os, "open",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("lleno")))
        assert st.append(snapshot([])) is False


# ------------------------------------------------------------- orquestación
class TestRecordAndDiff:
    def test_primer_escaneo_archiva_la_linea_base(self, tmp_path):
        st = SnapshotStore(str(tmp_path / "h"))
        d, snap = record_and_diff([ev()], store=st, ts=1.0)
        assert d.sin_historial and len(d.nuevos) == 1
        assert st.load_last()["ts"] == 1.0

    def test_segundo_escaneo_compara_con_el_primero_no_consigo_mismo(self, tmp_path):
        st = SnapshotStore(str(tmp_path / "h"))
        record_and_diff([ev(name="a.exe", path="p1")], store=st, ts=1.0)
        d, _ = record_and_diff([ev(name="a.exe", path="p1"),
                                ev(name="b.exe", path="p2")], store=st, ts=2.0)
        assert not d.sin_historial
        assert [f.name for f in d.nuevos] == ["b.exe"]
        assert len(d.persistentes) == 1

    def test_respeta_el_tope_del_historial(self, tmp_path):
        st = SnapshotStore(str(tmp_path / "h"))
        for i in range(6):
            record_and_diff([], store=st, ts=float(i), keep=3)
        assert len(st.load_all()) == 3

    def test_con_store_deshabilitado_sigue_dando_diff(self, tmp_path, monkeypatch):
        monkeypatch.setattr(os, "makedirs",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("no")))
        st = SnapshotStore(str(tmp_path / "x"))
        d, snap = record_and_diff([ev()], store=st, ts=1.0)
        assert d.sin_historial and snap["findings"]


class TestRutaPorDefecto:
    def test_windows_usa_localappdata(self, monkeypatch):
        monkeypatch.setattr(os, "name", "nt")
        monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\x\AppData\Local")
        assert default_history_dir().startswith(r"C:\Users\x\AppData\Local")
        assert "CENTINEL" in default_history_dir()

    def test_posix_usa_xdg(self, monkeypatch):
        monkeypatch.setattr(os, "name", "posix")
        monkeypatch.setenv("XDG_DATA_HOME", "/home/x/.local/share")
        assert default_history_dir() == os.path.join(
            "/home/x/.local/share", "centinel", "history")
