"""Tests puros del threat-intel blocklist (sin red)."""
import json

from centinel.intel.blocklist import parse_ip_feed, BlockList


# --- parse_ip_feed -----------------------------------------------------------

def test_parse_ips_simples():
    txt = "45.135.232.17\n185.234.219.84\n"
    assert parse_ip_feed(txt) == {"45.135.232.17", "185.234.219.84"}


def test_parse_ignora_comentarios_y_vacias():
    txt = "# Feodo Tracker\n\n; otro comentario\n45.135.232.17\n"
    assert parse_ip_feed(txt) == {"45.135.232.17"}


def test_parse_ignora_tokens_no_ip():
    txt = "no-soy-ip\n45.135.232.17\nbanana 1.2.3\n"
    # 'banana 1.2.3' -> primer token 'banana' -> descartado.
    assert parse_ip_feed(txt) == {"45.135.232.17"}


def test_parse_ip_con_puerto():
    txt = "45.135.232.17:443\n"
    assert parse_ip_feed(txt) == {"45.135.232.17"}


def test_parse_ip_tab_fecha():
    txt = "45.135.232.17\t2026-01-01\n"
    assert parse_ip_feed(txt) == {"45.135.232.17"}


def test_parse_descarta_privadas_y_loopback():
    txt = "192.168.1.66\n10.0.0.5\n127.0.0.1\n45.135.232.17\n"
    # Solo la pública sobrevive.
    assert parse_ip_feed(txt) == {"45.135.232.17"}


def test_parse_vacio():
    assert parse_ip_feed("") == set()


# --- BlockList (caché en disco, sin red) -------------------------------------

def test_blocklist_carga_cache_json(tmp_path):
    cache = tmp_path / "bl.json"
    cache.write_text(json.dumps({
        "ips": {"45.135.232.17": "feodo"},
        "updated": "2026-01-01T00:00:00Z",
    }), encoding="utf-8")
    bl = BlockList(str(cache))
    assert bl.available
    assert bl.count == 1
    assert bl.contains("45.135.232.17")
    assert bl.source_of("45.135.232.17") == "feodo"
    assert not bl.contains("8.8.8.8")


def test_blocklist_cache_inexistente_vacia(tmp_path):
    bl = BlockList(str(tmp_path / "no-existe.json"))
    assert not bl.available
    assert bl.count == 0
    assert not bl.contains("45.135.232.17")


def test_blocklist_load_plaintext(tmp_path):
    feed = tmp_path / "feed.txt"
    feed.write_text("# mi lista\n45.135.232.17\n1.2.3.4\n", encoding="utf-8")
    bl = BlockList(str(tmp_path / "bl.json"))
    n = bl.load_plaintext(str(feed), source="mi-feed")
    assert n == 2
    assert bl.contains("1.2.3.4")
    assert bl.source_of("1.2.3.4") == "mi-feed"


def test_blocklist_load_plaintext_inexistente(tmp_path):
    bl = BlockList(str(tmp_path / "bl.json"))
    assert bl.load_plaintext(str(tmp_path / "no.txt")) == 0
