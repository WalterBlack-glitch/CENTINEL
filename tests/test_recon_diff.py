"""Tests del diff puro entre hallazgos."""
from centinel.recon.diff import diff_findings, headline, render_txt, key
from centinel.recon.model import Finding


def P(port, service="", version=""):
    return Finding(kind="port", port=port, proto="tcp", state="open",
                   service=service, version=version)


def test_identidad_ignora_version_pero_no_puerto():
    # mismo puerto/proto = mismo hallazgo aunque cambie la versión del servicio
    assert key(P(22, "ssh", "8.9")) == key(P(22, "ssh", "9.0"))
    assert key(P(22)) != key(P(80))


def test_nuevos_idos_y_comunes():
    antes = [P(22), P(80)]
    ahora = [P(22), P(443)]
    d = diff_findings(antes, ahora)
    assert [f.port for f in d.nuevos] == [443]
    assert [f.port for f in d.idos] == [80]
    assert [f.port for f in d.comunes] == [22]
    assert not d.sin_cambios


def test_sin_cambios():
    d = diff_findings([P(22), P(80)], [P(80), P(22)])   # orden no importa
    assert d.sin_cambios
    assert headline(d) == "Sin cambios desde la corrida anterior."


def test_headline_cuenta_y_singular_plural():
    d = diff_findings([P(80)], [P(80), P(22)])
    assert headline(d) == "Desde la corrida anterior: 1 nuevo."
    d2 = diff_findings([P(80), P(443)], [P(22), P(8080)])
    assert "2 nuevos" in headline(d2) and "2 desaparecidos" in headline(d2)


def test_render_txt_lista_los_cambios():
    d = diff_findings([P(80, "http")], [P(80, "http"), P(22, "ssh", "OpenSSH 9")])
    txt = render_txt(d)
    assert "NUEVOS (1)" in txt
    assert "+ 22/tcp ssh OpenSSH 9" in txt
    assert "DESAPARECIDOS" not in txt   # no hubo idos


def test_vacio_contra_vacio():
    assert diff_findings([], []).sin_cambios
