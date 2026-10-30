"""Tests del informe HTML del recon (puro) y del export a disco."""
from centinel.recon.report import render_html, export
from centinel.recon.session import Session
from centinel.recon.model import Finding


def _sesion():
    s = Session(name="demo", target="10.0.0.5")
    s.findings = [
        Finding(kind="port", port=22, proto="tcp", state="open",
                service="ssh", version="OpenSSH 9.0"),
        Finding(kind="path", url="http://t/admin", status=200, length=12),
    ]
    s.commands = ["nmap -T4 -Pn 10.0.0.5"]
    return s


def test_html_tiene_estructura_y_datos():
    h = render_html(_sesion())
    assert h.startswith("<!doctype html>")
    assert h.rstrip().endswith("</html>")
    assert "OpenSSH 9.0" in h and "http://t/admin" in h
    assert "10.0.0.5" in h
    # tema claro/oscuro
    assert "prefers-color-scheme: dark" in h


def test_html_escapa_contenido_del_objetivo():
    # un servicio con nombre malicioso no debe inyectar etiquetas vivas
    s = Session(name="x", target="t")
    s.findings = [Finding(kind="port", port=1, proto="tcp", state="open",
                          service="<img src=x onerror=alert(1)>")]
    h = render_html(s)
    assert "<img src=x" not in h
    assert "&lt;img src=x onerror=alert(1)&gt;" in h


def test_html_sesion_vacia_no_revienta():
    h = render_html(Session(name="vacia"))
    assert "Sin hallazgos todavía." in h


def test_export_escribe_txt_md_y_html(tmp_path):
    files = export(_sesion(), tmp_path)
    exts = sorted(f.suffix for f in files)
    assert exts == [".html", ".md", ".txt"]
    for f in files:
        assert f.is_file() and f.stat().st_size > 0
    html = next(f for f in files if f.suffix == ".html")
    assert "OpenSSH 9.0" in html.read_text(encoding="utf-8")
