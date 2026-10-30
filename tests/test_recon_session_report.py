"""Tests de slug de sesión, dedupe de hallazgos y render del reporte."""
from centinel.recon.session import slugify, Session
from centinel.recon.report import render_txt, render_md
from centinel.recon.model import Finding
from centinel.recon import theme, verify
from centinel.recon.config import Config


def test_slugify_normaliza():
    assert slugify("HTB · Target 10.10.10.5") == "htb-target-10-10-10-5"
    assert slugify("   ") == "sesion"
    assert slugify("web/app") == "web-app"


def test_add_findings_dedup_y_conteo():
    s = Session("t")
    n1 = s.add_findings([Finding(kind="port", port=22, proto="tcp"),
                         Finding(kind="port", port=80, proto="tcp")])
    assert n1 == 2
    n2 = s.add_findings([Finding(kind="port", port=22, proto="tcp"),
                         Finding(kind="port", port=443, proto="tcp")])
    assert n2 == 1 and len(s.findings) == 3


def test_render_txt_incluye_secciones():
    s = Session("t", target="10.0.0.1")
    s.findings = [
        Finding(kind="port", port=22, proto="tcp", state="open", service="ssh"),
        Finding(kind="path", url="http://t/admin", status=301, length=0),
    ]
    txt = render_txt(s)
    assert "10.0.0.1" in txt and "PUERTOS ABIERTOS" in txt
    assert "22/tcp" in txt and "/admin" in txt


def test_render_md_tabla_de_puertos():
    s = Session("t", target="h")
    s.findings = [Finding(kind="port", port=80, proto="tcp", state="open",
                          service="http", version="Apache")]
    md = render_md(s)
    assert md.startswith("# PARANOID")
    assert "| Puerto |" in md and "| 80 |" in md


def test_render_sin_hallazgos():
    assert "sin hallazgos" in render_txt(Session("t")).lower()


def test_themes_completos():
    for name in theme.names():
        t = theme.get(name)
        assert t.title and t.accent and t.cmd
    assert theme.get("no-existe").name == theme.DEFAULT_THEME


def test_preflight_reporta_nmap_como_error_si_falta():
    checks = verify.preflight(
        tool_avail={"nmap": False, "ffuf": True, "tcpdump": False},
        is_root=False, cfg=Config())
    nmap = next(c for c in checks if c[0].endswith("nmap"))
    assert nmap[1] is False and nmap[3] == "err"
    ffuf = next(c for c in checks if c[0].endswith("ffuf"))
    assert ffuf[1] is True and ffuf[3] == "ok"
