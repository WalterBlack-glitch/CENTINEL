"""Tests del tracker proceso-malicioso <-> IP (netwatch)."""
import os

from centinela.collectors.netwatch import (
    _parse_addr, _is_external, NetWatchCollector,
)


def test_parse_ipv4_loopback():
    # 0100007F:1F90 -> 127.0.0.1:8080 (IP little-endian por bytes)
    assert _parse_addr("0100007F:1F90") == ("127.0.0.1", 8080)


def test_parse_ipv4_publica():
    ip, port = _parse_addr("08080808:01BB")   # 8.8.8.8:443
    assert ip == "8.8.8.8" and port == 443


def test_parse_basura_devuelve_none():
    assert _parse_addr("zzzz") is None
    assert _parse_addr("XYZ:01") is None
    assert _parse_addr("0100007F") is None


def test_is_external():
    assert _is_external("8.8.8.8") is True
    assert _is_external("45.135.232.17") is True
    assert _is_external("127.0.0.1") is False
    assert _is_external("192.168.1.10") is False
    assert _is_external("10.0.0.5") is False
    assert _is_external("::1") is False
    assert _is_external("no-ip") is False


def test_suspect_flags_binario_normal_no_marca():
    w = NetWatchCollector(bus=None)
    info = {"exe": "/usr/bin/sshd", "comm": "sshd", "cmdline": "/usr/bin/sshd"}
    assert w._suspect_flags(info) == []


def test_suspect_flags_backdoor_borrado_en_tmp():
    w = NetWatchCollector(bus=None)
    info = {"exe": "/tmp/.kworker (deleted)", "comm": ".kworker",
            "cmdline": "/tmp/.kworker"}
    flags = w._suspect_flags(info)
    assert any("borrado" in f for f in flags)
    assert any("efímero" in f for f in flags)
    assert any("oculto" in f for f in flags)


def test_suspect_flags_script_backdoor_interprete_legitimo():
    # exe legítimo (python) pero ejecutando un script desde /tmp -> sospechoso.
    w = NetWatchCollector(bus=None)
    info = {"exe": "/usr/bin/python3", "comm": "python3",
            "cmdline": "/usr/bin/python3 /tmp/.rev.py"}
    flags = w._suspect_flags(info)
    assert any("script" in f for f in flags)


def test_suspect_flags_world_writable(tmp_path):
    if os.name == "nt":
        return  # modos POSIX no aplican en Windows
    b = tmp_path / "mal"
    b.write_text("x")
    os.chmod(b, 0o777)
    w = NetWatchCollector(bus=None)
    info = {"exe": str(b), "comm": "mal", "cmdline": str(b)}
    assert any("world-writable" in f for f in w._suspect_flags(info))


def test_available_solo_en_linux_con_proc():
    w = NetWatchCollector(bus=None)
    expected = os.name == "posix" and os.path.exists("/proc/net/tcp")
    assert w.available() == expected
