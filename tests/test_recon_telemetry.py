"""Tests del resumen puro de la captura del sniffer."""
from centinel.recon.telemetry import summarize_capture, build_sniff_cmd
import pytest

CAP = """
10:00:00.1 IP 192.168.1.10.51000 > 93.184.216.34.443: tcp 0
10:00:00.2 IP 93.184.216.34.443 > 192.168.1.10.51000: tcp 100
10:00:00.3 IP 192.168.1.10.51001 > 8.8.8.8.53: UDP, length 30 A? example.com.
10:00:00.4 IP 192.168.1.10.51002 > 1.1.1.1.80: tcp 0
"""


def test_summarize_cuenta_paquetes_y_protocolos():
    s = summarize_capture(CAP)
    assert s["packets"] == 4
    assert s["by_proto"].get("https") == 2
    assert s["by_proto"].get("dns") == 1
    assert s["by_proto"].get("http") == 1


def test_summarize_top_talkers_incluye_la_ip_local():
    s = summarize_capture(CAP)
    talkers = dict(s["top_talkers"])
    assert talkers["192.168.1.10"] == 4   # aparece en 4 paquetes


def test_summarize_extrae_dns():
    s = summarize_capture(CAP)
    assert ("example.com", 1) in s["dns_queries"]


def test_summarize_vacio():
    s = summarize_capture("")
    assert s["packets"] == 0 and s["by_proto"] == {}


def test_build_sniff_cmd():
    cmd = build_sniff_cmd("eth0", count=50)
    assert cmd[:3] == ["tcpdump", "-i", "eth0"]
    assert "-c" in cmd and "50" in cmd
    with pytest.raises(ValueError):
        build_sniff_cmd("")
