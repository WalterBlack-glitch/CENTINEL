"""Tests del parseo puro de nmap y ffuf."""
import json

from centinel.recon.parse import parse_nmap, parse_nmap_xml, parse_ffuf, dedupe
from centinel.recon.model import Finding

NMAP_OUT = """
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.10s latency).
PORT      STATE    SERVICE  VERSION
22/tcp    open     ssh      OpenSSH 8.9p1 Ubuntu
80/tcp    open     http     Apache httpd 2.4.52
443/tcp   closed   https
9929/tcp  filtered nping-echo
Nmap done: 1 IP address (1 host up) scanned in 3.2s
"""


def test_parse_nmap_solo_abiertos_por_defecto():
    fs = parse_nmap(NMAP_OUT)
    ports = {f.port for f in fs}
    assert ports == {22, 80}
    ssh = next(f for f in fs if f.port == 22)
    assert ssh.service == "ssh" and "OpenSSH 8.9p1" in ssh.version
    assert ssh.proto == "tcp" and ssh.state == "open"


def test_parse_nmap_incluye_cerrados_si_se_pide():
    fs = parse_nmap(NMAP_OUT, only_open=False)
    assert {f.port for f in fs} == {22, 80, 443, 9929}


def test_parse_nmap_texto_vacio():
    assert parse_nmap("") == []


def test_parse_ffuf_extrae_rutas():
    payload = json.dumps({"results": [
        {"url": "http://t/admin", "status": 301, "length": 0, "words": 1,
         "input": {"FUZZ": "admin"}},
        {"url": "http://t/login", "status": 200, "length": 42, "words": 3,
         "input": {"FUZZ": "login"}},
    ]})
    fs = parse_ffuf(payload)
    assert [f.fuzz for f in fs] == ["admin", "login"]
    assert fs[0].status == 301 and fs[0].kind == "path"


def test_parse_ffuf_subdominio_marca_kind():
    payload = json.dumps({"results": [
        {"url": "http://t", "status": 200, "input": {"FUZZ": "dev"}}]})
    fs = parse_ffuf(payload, kind="subdomain")
    assert fs[0].kind == "subdomain" and fs[0].fuzz == "dev"


def test_parse_ffuf_json_invalido():
    assert parse_ffuf("no soy json") == []
    assert parse_ffuf("{}") == []


def test_dedupe_quita_repetidos_conservando_orden():
    a = Finding(kind="port", port=22, proto="tcp")
    b = Finding(kind="port", port=80, proto="tcp")
    a2 = Finding(kind="port", port=22, proto="tcp")
    out = dedupe([a, b, a2])
    assert [f.port for f in out] == [22, 80]


# --------------------------------------------------------------------- nmap XML
NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <ports>
      <extraports state="closed" count="996"/>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu Linux"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.52"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
      </port>
      <port protocol="udp" portid="123">
        <state state="open|filtered" reason="no-response"/>
        <service name="ntp"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml_solo_abiertos_por_defecto():
    fs = parse_nmap_xml(NMAP_XML)
    # 443 esta cerrado -> fuera; 123 es open|filtered -> empieza por "open", dentro.
    assert {f.port for f in fs} == {22, 80, 123}


def test_parse_nmap_xml_arma_version_rica():
    ssh = next(f for f in parse_nmap_xml(NMAP_XML) if f.port == 22)
    assert ssh.service == "ssh"
    assert ssh.version == "OpenSSH 8.9p1 (Ubuntu Linux)"
    assert ssh.proto == "tcp" and ssh.state == "open"


def test_parse_nmap_xml_servicio_sin_version():
    ntp = next(f for f in parse_nmap_xml(NMAP_XML) if f.port == 123)
    assert ntp.service == "ntp" and ntp.version == ""
    assert ntp.proto == "udp" and ntp.state == "open|filtered"


def test_parse_nmap_xml_incluye_cerrados_si_se_pide():
    assert {f.port for f in parse_nmap_xml(NMAP_XML, only_open=False)} == {22, 80, 443, 123}


def test_parse_nmap_xml_multiples_hosts():
    xml = """<nmaprun>
      <host><ports><port protocol="tcp" portid="22">
        <state state="open"/><service name="ssh"/></port></ports></host>
      <host><ports><port protocol="tcp" portid="3389">
        <state state="open"/><service name="ms-wbt-server"/></port></ports></host>
    </nmaprun>"""
    assert {f.port for f in parse_nmap_xml(xml)} == {22, 3389}


def test_parse_nmap_xml_vacio_o_corrupto():
    assert parse_nmap_xml("") == []
    assert parse_nmap_xml("   ") == []
    assert parse_nmap_xml("<nmaprun><host><ports>") == []   # XML roto -> []
    assert parse_nmap_xml("no es xml") == []
