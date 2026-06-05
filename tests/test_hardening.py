"""Tests de los endurecimientos del audit de seguridad.

Cubre las regresiones que podrían reintroducir las vulnerabilidades arregladas:
  - Alerter: SSRF a metadata IMDS / loopback
  - Alerter: esquemas distintos a http/https
  - Firewall: IP no canonicalizada / no-IP llegando a nft
  - BaselineStore: rechazo de owner/perms inseguros en POSIX
"""
import os
import sys

import pytest


# ---- Alerter: validación de URL ----

from centinel.alerter import _validate_webhook_url


def test_alerter_rechaza_aws_metadata():
    ok, why = _validate_webhook_url("http://169.254.169.254/latest/meta-data/")
    assert not ok and "metadata" in why.lower()


def test_alerter_rechaza_gcp_metadata():
    ok, why = _validate_webhook_url(
        "http://metadata.google.internal/computeMetadata/v1/")
    assert not ok and "metadata" in why.lower()


def test_alerter_rechaza_file_scheme():
    ok, why = _validate_webhook_url("file:///etc/passwd")
    assert not ok and "esquema" in why.lower()


def test_alerter_rechaza_ftp_scheme():
    ok, _ = _validate_webhook_url("ftp://example.com/upload")
    assert not ok


def test_alerter_rechaza_loopback_ip():
    ok, why = _validate_webhook_url("http://127.0.0.1:8080/hook")
    assert not ok and "loopback" in why.lower()


def test_alerter_rechaza_url_vacia():
    ok, _ = _validate_webhook_url("")
    assert not ok


def test_alerter_acepta_https_externo():
    ok, _ = _validate_webhook_url("https://hooks.slack.com/services/X/Y/Z")
    assert ok


def test_alerter_constructor_silencia_url_peligrosa(capsys):
    """Si pasan una URL hostil, el alerter queda con url='' y no envía nada."""
    from centinel.alerter import WebhookAlerter
    from centinel.core import EventBus
    al = WebhookAlerter(EventBus(), "http://169.254.169.254/")
    assert al.url == ""
    captured = capsys.readouterr()
    assert "rechazada" in captured.out.lower()


# ---- Firewall: canonicalización ----

def test_firewall_rechaza_input_no_ip():
    from centinel.response.firewall import Firewall
    fw = Firewall(mode="dry-run")
    ok, detail = fw.block("8.8.8.8; rm -rf /")
    assert not ok and "inv" in detail.lower()


def test_firewall_canonicaliza_ipv4_con_ceros():
    """'8.8.008.008' es válido para ipaddress pero podría confundir nft."""
    from centinel.response.firewall import Firewall
    fw = Firewall(mode="dry-run")
    # Python 3.10+ ipaddress: octal con ceros a la izquierda lanza ValueError,
    # así que la entrada se rechaza limpiamente.
    ok, detail = fw.block("8.8.008.008")
    assert not ok  # tanto si la rechaza por inválida como por canónica protegida


def test_firewall_rechaza_lan_aunque_canonica():
    from centinel.response.firewall import Firewall
    fw = Firewall(mode="dry-run")
    ok, detail = fw.block("192.168.1.10")
    assert not ok and ("privada" in detail.lower() or "lan" in detail.lower())


# ---- BaselineStore: TOCTOU POSIX ----

@pytest.mark.skipif(os.name != "posix", reason="POSIX-only TOCTOU check")
def test_baseline_store_rechaza_dir_world_writable(tmp_path):
    """Si el dir tiene perms world-accesibles, BaselineStore aborta."""
    from centinel.baseline_store import BaselineStore
    d = tmp_path / "weak"
    d.mkdir(mode=0o777)
    try:
        os.chmod(d, 0o777)
    except OSError:
        pytest.skip("no se puede ajustar chmod a 0o777")
    if os.stat(d).st_mode & 0o077 == 0:
        pytest.skip("FS no respeta 0o777 (probable mount con umask restrictivo)")
    with pytest.raises(RuntimeError, match="inseguros"):
        BaselineStore(str(d))


def test_baseline_store_funciona_con_dir_seguro(tmp_path):
    """Sanity: el camino feliz sigue funcionando tras el endurecimiento."""
    from centinel.baseline_store import BaselineStore
    d = tmp_path / "ok"
    bs = BaselineStore(str(d))
    bs.save("suid_test", ["/usr/bin/sudo"])
    assert bs.load("suid_test") == ["/usr/bin/sudo"]


def test_baseline_store_load_rechaza_firma_mala(tmp_path):
    """Tampering del JSON debe romper HMAC y devolver None (no cargar)."""
    import json
    from centinel.baseline_store import BaselineStore
    bs = BaselineStore(str(tmp_path / "bs"))
    bs.save("xx", {"path": "/usr/bin/legit"})
    p = os.path.join(bs.dir, "xx.json")
    with open(p) as f:
        obj = json.load(f)
    obj["data"] = {"path": "/tmp/attacker_bin"}   # firma queda obsoleta
    with open(p, "w") as f:
        json.dump(obj, f)
    assert bs.load("xx") is None   # tampering detectado
