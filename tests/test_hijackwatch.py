"""Tests de clasificación pura de HijackWatch (sin tocar /proc)."""
from centinel.collectors.hijackwatch import (
    classify_preload, classify_path, _parse_environ,
)


# --- LD_PRELOAD ---------------------------------------------------------------

def test_preload_vacio_no_alerta():
    bad, _ = classify_preload("")
    assert not bad


def test_preload_ruta_estandar_no_alerta():
    # libnss/libnsl en /usr/lib son extensiones legitimas.
    bad, _ = classify_preload("/usr/lib/libnss_files.so.2")
    assert not bad


def test_preload_desde_tmp_es_critico():
    bad, why = classify_preload("/tmp/rootkit.so")
    assert bad and "efímero" in why


def test_preload_desde_dev_shm_es_critico():
    bad, why = classify_preload("/dev/shm/x.so")
    assert bad


def test_preload_desde_home_es_critico():
    bad, why = classify_preload("/home/user/payload.so")
    assert bad and "$HOME" in why


def test_preload_world_writable_es_critico():
    bad, why = classify_preload("/opt/weird.so", world_writable=True)
    assert bad and "world-writable" in why


def test_preload_fuera_de_rutas_confiables_es_critico():
    # /opt/* no esta en _SAFE_PRELOAD: el atacante puede usar paths "creibles".
    bad, _ = classify_preload("/opt/strange/path/lib.so")
    assert bad


def test_preload_multiple_paths_alguno_malo():
    bad, _ = classify_preload("/usr/lib/ok.so /tmp/bad.so")
    assert bad


# --- PATH ---------------------------------------------------------------------

def test_path_vacio_no_alerta():
    bad, _ = classify_path("")
    assert not bad


def test_path_estandar_no_alerta():
    bad, _ = classify_path("/usr/local/bin:/usr/bin:/bin")
    assert not bad


def test_path_tmp_antes_de_usr_bin_es_hijack():
    bad, why = classify_path("/tmp:/usr/bin:/bin")
    assert bad and "efímero" in why


def test_path_home_antes_de_usr_bin_es_hijack():
    bad, _ = classify_path("/home/u/.local/bin:/usr/bin")
    assert bad


def test_path_dot_antes_de_usr_bin_es_hijack():
    bad, _ = classify_path(".:/usr/bin")
    assert bad


def test_path_tmp_despues_de_usr_bin_no_alerta():
    # Si /usr/bin va primero, ya no es hijack (el orden importa).
    bad, _ = classify_path("/usr/bin:/tmp")
    assert not bad


# --- /proc/<pid>/environ ------------------------------------------------------

def test_parse_environ_nul_separado():
    blob = b"PATH=/usr/bin\x00LD_PRELOAD=/tmp/x.so\x00HOME=/root\x00"
    env = _parse_environ(blob)
    assert env["PATH"] == "/usr/bin"
    assert env["LD_PRELOAD"] == "/tmp/x.so"
    assert env["HOME"] == "/root"


def test_parse_environ_vacio():
    assert _parse_environ(b"") == {}


def test_parse_environ_ignora_lineas_sin_igual():
    env = _parse_environ(b"BROKEN\x00VAR=val\x00")
    assert env == {"VAR": "val"}
