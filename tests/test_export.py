"""Exportación de informes: fidelidad, escapado HTML y CSV injection."""
from __future__ import annotations

import csv
import io
import json
import os

import pytest

from centinel.core import Severity, ThreatEvent
from centinel.snapshots import diff, snapshot
from centinel.storage.export import (
    FORMATOS, csv_safe, render, stamp, to_csv, to_html, to_json, write_report,
)


def ev(name="svchost.exe", path=r"C:\Temp\svchost.exe", sev=Severity.CRITICAL,
       pid=100, reasons=("sin firma",), kind="proc_impersonation"):
    return ThreatEvent(kind=kind, severity=sev,
                       enrichment={"name": name, "path": path, "pid": pid,
                                   "reasons": list(reasons)})


@pytest.fixture
def snap():
    return snapshot([ev()], ts=1000.0, host="PC1")


@pytest.fixture
def d(snap):
    return diff(snapshot([], ts=900.0), snap)


# -------------------------------------------------------------------- JSON
class TestJson:
    def test_lleva_findings_y_marcas_de_tiempo(self, snap):
        doc = json.loads(to_json(snap))
        assert doc["total"] == 1
        assert doc["host"] == "PC1"
        assert doc["escaneo_ts"] == 1000.0
        assert doc["findings"][0]["name"] == "svchost.exe"
        assert doc["generado"] and doc["escaneo"]

    def test_sin_diff_no_inventa_la_clave(self, snap):
        assert "diff" not in json.loads(to_json(snap))

    def test_con_diff_detalla_cada_grupo(self, snap, d):
        doc = json.loads(to_json(snap, d))
        assert doc["diff"]["resumen"]
        assert len(doc["diff"]["nuevos"]) == 1
        assert doc["diff"]["anterior_ts"] == 900.0
        for k in ("agravados", "resueltos", "persistentes"):
            assert k in doc["diff"]

    def test_agravados_llevan_antes_y_ahora(self):
        prev = snapshot([ev(sev=Severity.LOW)], ts=1.0)
        cur = snapshot([ev(sev=Severity.CRITICAL)], ts=2.0)
        doc = json.loads(to_json(cur, diff(prev, cur)))
        par = doc["diff"]["agravados"][0]
        assert par["antes"]["severity"] < par["ahora"]["severity"]

    def test_resueltos_aparecen_en_el_diff(self):
        prev = snapshot([ev(name="fue.exe")], ts=1.0)
        cur = snapshot([], ts=2.0)
        doc = json.loads(to_json(cur, diff(prev, cur)))
        assert doc["diff"]["resueltos"][0]["name"] == "fue.exe"

    def test_unicode_sin_escapar(self):
        s = snapshot([ev(name="ñandú.exe")], ts=1.0)
        assert "ñandú" in to_json(s)

    def test_retrato_vacio(self):
        doc = json.loads(to_json(snapshot([], ts=1.0)))
        assert doc["total"] == 0 and doc["findings"] == []


# --------------------------------------------------------------------- CSV
class TestCsv:
    def test_cabecera_y_fila(self, snap):
        filas = list(csv.reader(io.StringIO(to_csv(snap))))
        assert filas[0] == ["severidad", "tipo", "proceso", "pid", "ruta",
                            "motivos", "estado"]
        assert filas[1][0] == "CRITICAL"
        assert filas[1][2] == "svchost.exe"

    def test_estado_del_diff_en_la_fila(self, snap, d):
        filas = list(csv.reader(io.StringIO(to_csv(snap, d))))
        assert filas[1][6] == "nuevo"

    def test_incluye_los_resueltos(self):
        prev = snapshot([ev(name="fue.exe")], ts=1.0)
        cur = snapshot([], ts=2.0)
        filas = list(csv.reader(io.StringIO(to_csv(cur, diff(prev, cur)))))
        assert filas[1][2] == "fue.exe" and filas[1][6] == "resuelto"

    def test_motivos_juntos_en_una_celda(self):
        s = snapshot([ev(reasons=("uno", "dos"))], ts=1.0)
        filas = list(csv.reader(io.StringIO(to_csv(s))))
        assert filas[1][5] == "uno; dos"

    def test_ordena_por_severidad(self):
        s = snapshot([ev(name="leve.exe", path="p1", sev=Severity.LOW),
                      ev(name="grave.exe", path="p2", sev=Severity.CRITICAL)],
                     ts=1.0)
        filas = list(csv.reader(io.StringIO(to_csv(s))))
        assert [f[2] for f in filas[1:]] == ["grave.exe", "leve.exe"]

    @pytest.mark.parametrize("payload", [
        "=cmd|' /c calc'!A1", "+1+1", "-2+3", "@SUM(A1)", "\tx", "\rx"])
    def test_csv_injection_neutralizada(self, payload):
        assert csv_safe(payload).startswith("'")
        assert payload in csv_safe(payload)

    def test_valores_normales_intactos(self):
        assert csv_safe("svchost.exe") == "svchost.exe"
        assert csv_safe(100) == "100"
        assert csv_safe(None) == ""

    def test_formula_en_el_nombre_del_proceso_sale_neutralizada(self):
        s = snapshot([ev(name="=cmd|' /c calc'!A1")], ts=1.0)
        filas = list(csv.reader(io.StringIO(to_csv(s))))
        assert filas[1][2].startswith("'=")

    def test_vacio_solo_cabecera(self):
        assert len(list(csv.reader(io.StringIO(to_csv(snapshot([], ts=1.0)))))) == 1


# -------------------------------------------------------------------- HTML
class TestHtml:
    def test_documento_completo(self, snap):
        h = to_html(snap)
        assert h.startswith("<!doctype html>")
        assert h.rstrip().endswith("</html>")
        assert "<table" in h and "svchost.exe" in h

    def test_muestra_el_resumen_del_diff(self, snap, d):
        assert d.resumen() in to_html(snap, d).replace("&middot;", "·")

    def test_marca_lo_nuevo_con_insignia(self, snap, d):
        assert 'class="badge nuevo"' in to_html(snap, d)

    def test_retrato_limpio_lo_dice(self):
        assert "Sin hallazgos" in to_html(snapshot([], ts=1.0))

    def test_escapa_el_nombre_del_proceso(self):
        s = snapshot([ev(name="<img src=x onerror=alert(1)>")], ts=1.0)
        h = to_html(s)
        assert "<img src=x" not in h
        assert "&lt;img src=x" in h

    def test_escapa_la_ruta_y_los_motivos(self):
        s = snapshot([ev(path=r"C:\<script>evil</script>",
                         reasons=("<b>raro</b>",))], ts=1.0)
        h = to_html(s)
        assert "<script>evil" not in h and "<b>raro</b>" not in h
        assert "&lt;script&gt;" in h

    def test_escapa_el_nombre_del_equipo(self):
        assert "<script>" not in to_html(snapshot([], ts=1.0),
                                         host="<script>x</script>")

    def test_escapa_el_titulo(self):
        assert "<script>" not in to_html(snapshot([], ts=1.0),
                                         title="<script>x</script>")

    def test_tiene_estilos_para_tema_oscuro(self, snap):
        assert "prefers-color-scheme:dark" in to_html(snap)

    def test_color_por_severidad(self):
        s = snapshot([ev(sev=Severity.CRITICAL)], ts=1.0)
        assert "#c0392b" in to_html(s)

    def test_incluye_el_equipo_si_lo_hay(self, snap):
        assert "PC1" in to_html(snap)


# ------------------------------------------------------------------ render
class TestRender:
    @pytest.mark.parametrize("fmt", ["json", "csv", "html"])
    def test_cada_formato_devuelve_texto(self, snap, fmt):
        assert isinstance(render(fmt, snap), str) and render(fmt, snap)

    def test_no_distingue_mayusculas(self, snap):
        assert render("HTML", snap).startswith("<!doctype")

    def test_formato_desconocido_explica_las_opciones(self, snap):
        with pytest.raises(ValueError) as exc:
            render("pdf", snap)
        assert "json" in str(exc.value)

    def test_formatos_publicados(self):
        assert set(FORMATOS) == {"json", "csv", "html"}


class TestWriteReport:
    def test_escribe_con_fecha_en_el_nombre(self, snap, tmp_path):
        p = write_report(snap, outdir=str(tmp_path), ts=1000.0)
        assert os.path.exists(p)
        assert os.path.basename(p).startswith("centinel-")
        assert p.endswith(".html")
        assert stamp(1000.0) in p

    @pytest.mark.parametrize("fmt,ext", [("json", ".json"), ("csv", ".csv"),
                                         ("html", ".html")])
    def test_extension_por_formato(self, snap, tmp_path, fmt, ext):
        assert write_report(snap, fmt=fmt, outdir=str(tmp_path)).endswith(ext)

    def test_crea_el_directorio_si_falta(self, snap, tmp_path):
        destino = tmp_path / "informes" / "2026"
        p = write_report(snap, outdir=str(destino))
        assert os.path.exists(p)

    def test_el_contenido_es_el_del_render(self, snap, tmp_path):
        p = write_report(snap, fmt="json", outdir=str(tmp_path), ts=1000.0)
        with open(p, encoding="utf-8") as f:
            assert json.load(f)["findings"][0]["name"] == "svchost.exe"

    def test_usa_el_ts_del_escaneo_si_no_le_dan_otro(self, snap, tmp_path):
        p = write_report(snap, outdir=str(tmp_path))
        assert stamp(1000.0) in p

    def test_stamp_es_ordenable(self):
        assert stamp(1000.0) < stamp(2000.0)
