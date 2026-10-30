"""run_nmap: que prefiera el XML y caiga al texto, sin nmap real (subprocess simulado)."""
import subprocess
import types

from centinel.recon import scanner

XML = """<nmaprun><host><ports>
  <port protocol="tcp" portid="22"><state state="open"/>
    <service name="ssh" product="OpenSSH" version="9.0"/></port>
</ports></host></nmaprun>"""

TXT = """PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.0
"""


def _fake_run(stdout):
    def run(cmd, **kw):
        return types.SimpleNamespace(stdout=stdout, stderr="", returncode=0)
    return run


def test_run_nmap_prefiere_xml_de_stdout(monkeypatch):
    # sin out_dir -> xmlfile="-", el XML llega por stdout
    monkeypatch.setattr(scanner, "have", lambda _t: True)
    monkeypatch.setattr(subprocess, "run", _fake_run(XML))
    res = scanner.run_nmap("quick", "host")
    assert res.ok and len(res.findings) == 1
    f = res.findings[0]
    assert f.port == 22 and f.service == "ssh" and f.version == "OpenSSH 9.0"


def test_run_nmap_cae_a_texto_si_el_xml_no_sirve(monkeypatch):
    # stdout no es XML parseable -> usa parse_nmap sobre el texto normal
    monkeypatch.setattr(scanner, "have", lambda _t: True)
    monkeypatch.setattr(subprocess, "run", _fake_run(TXT))
    res = scanner.run_nmap("quick", "host")
    assert len(res.findings) == 1 and res.findings[0].port == 22


def test_run_nmap_sin_binario_degrada(monkeypatch):
    monkeypatch.setattr(scanner, "have", lambda _t: False)
    res = scanner.run_nmap("quick", "host")
    assert not res.ok and "nmap" in res.error
