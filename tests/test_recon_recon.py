"""Tests de construcción pura de comandos nmap/ffuf."""
import pytest

from centinel.recon.scanner import build_nmap_cmd, build_ffuf_cmd, NMAP_NEEDS_ROOT


def test_nmap_quick_puertos_comunes():
    cmd = build_nmap_cmd("quick", "10.0.0.1")
    assert cmd[0] == "nmap"
    assert "-p" in cmd and "21,22,80,443" in cmd
    assert cmd[-1] == "10.0.0.1"


def test_nmap_full_barrido_completo():
    assert "-p-" in build_nmap_cmd("full", "host")


def test_nmap_service_flags():
    cmd = build_nmap_cmd("service", "host")
    assert "-sV" in cmd and "-sC" in cmd


def test_nmap_stealth_es_syn_y_necesita_root():
    cmd = build_nmap_cmd("stealth", "host")
    assert "-sS" in cmd and "-T2" in cmd
    assert "stealth" in NMAP_NEEDS_ROOT


def test_nmap_outfile_se_inserta():
    cmd = build_nmap_cmd("quick", "host", outfile="/tmp/o.txt")
    assert "-oN" in cmd and "/tmp/o.txt" in cmd


def test_nmap_modo_desconocido_o_target_vacio():
    with pytest.raises(ValueError):
        build_nmap_cmd("nope", "host")
    with pytest.raises(ValueError):
        build_nmap_cmd("quick", "")


def test_ffuf_dir_fuzzea_ruta():
    cmd = build_ffuf_cmd("dir", "example.com", "/wl.txt")
    u = cmd[cmd.index("-u") + 1]
    assert u == "http://example.com/FUZZ"
    assert "/wl.txt" in cmd and "-of" in cmd


def test_ffuf_subdomain_fuzzea_host_header():
    cmd = build_ffuf_cmd("subdomain", "https://example.com", "/wl.txt")
    h = cmd[cmd.index("-H") + 1]
    assert h == "Host: FUZZ.example.com"
    u = cmd[cmd.index("-u") + 1]
    assert u == "https://example.com"


def test_ffuf_valida_entradas():
    with pytest.raises(ValueError):
        build_ffuf_cmd("dir", "", "/wl.txt")
    with pytest.raises(ValueError):
        build_ffuf_cmd("dir", "host", "")
    with pytest.raises(ValueError):
        build_ffuf_cmd("nope", "host", "/wl.txt")


def test_nmap_xmlfile_se_inserta():
    cmd = build_nmap_cmd("quick", "host", xmlfile="/tmp/o.xml")
    assert "-oX" in cmd and "/tmp/o.xml" in cmd
    # el objetivo va al final, despues de los ficheros de salida
    assert cmd[-1] == "host"


def test_nmap_texto_y_xml_conviven():
    cmd = build_nmap_cmd("quick", "host", outfile="/tmp/o.txt", xmlfile="-")
    assert cmd.count("-oN") == 1 and cmd.count("-oX") == 1
    assert cmd[cmd.index("-oX") + 1] == "-"
