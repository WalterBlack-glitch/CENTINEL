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


CAP6 = """
10:00:01.1 IP6 2001:db8::10.51000 > 2606:4700:4700::1111.443: tcp 0
10:00:01.2 IP6 2606:4700:4700::1111.443 > 2001:db8::10.51000: tcp 120
10:00:01.3 IP6 fe80::1.51001 > fe80::2.53: UDP, length 40 AAAA? ipv6.example.com.
"""


def test_summarize_parsea_ipv6():
    s = summarize_capture(CAP6)
    assert s["packets"] == 3
    assert s["by_proto"].get("https") == 2
    assert s["by_proto"].get("dns") == 1
    talkers = dict(s["top_talkers"])
    assert talkers["2001:db8::10"] == 2
    assert talkers["fe80::1"] == 1


def test_summarize_ipv6_extrae_dns_aaaa():
    s = summarize_capture(CAP6)
    assert dict(s["dns_queries"]).get("ipv6.example.com") == 1


def test_summarize_mezcla_v4_y_v6():
    s = summarize_capture(CAP + CAP6)
    assert s["packets"] == 7   # 4 IPv4 + 3 IPv6


def test_build_sniff_cmd_a_pcap():
    cmd = build_sniff_cmd("eth0", count=50, pcap="/tmp/cap.pcap")
    assert "-w" in cmd and "/tmp/cap.pcap" in cmd
    assert cmd[cmd.index("-w") + 1] == "/tmp/cap.pcap"
    # sin pcap no aparece -w
    assert "-w" not in build_sniff_cmd("eth0")
