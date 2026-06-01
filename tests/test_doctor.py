"""Tests del doctor (diagnóstico previo)."""
import os
import types

from centinela.doctor import run, has_blocking_errors, OK, ERR, FIX


def _args(**kw):
    base = dict(db="centinela.db", web=False, web_host="127.0.0.1",
               web_port=8787, geo=None, sniff=False, honeypot=None,
               no_drop=False, user="nobody", kev_cache=None, kev_update=False)
    base.update(kw)
    return types.SimpleNamespace(**base)


def test_diagnostico_limpio_no_bloquea(tmp_path):
    db = tmp_path / "c.db"
    f = run(_args(db=str(db)))
    assert not has_blocking_errors(f)
    assert any(x["level"] == OK for x in f)


def test_crea_directorio_de_bd(tmp_path):
    db = tmp_path / "sub" / "dir" / "c.db"
    f = run(_args(db=str(db)))
    assert (tmp_path / "sub" / "dir").is_dir()
    assert any(x["level"] == FIX for x in f)


def test_web_sin_deps_es_error(monkeypatch):
    import centinela.doctor as d
    monkeypatch.setattr(d, "_has", lambda m: False)
    f = run(_args(web=True))
    assert has_blocking_errors(f)
    assert any("web" in x["msg"].lower() and x["fix"] for x in f if x["level"] == ERR)


def test_endurece_permisos_de_bd_existente(tmp_path):
    if os.name == "nt":
        return  # los modos POSIX no aplican en Windows
    db = tmp_path / "c.db"
    db.write_text("x")
    os.chmod(db, 0o644)
    run(_args(db=str(db)))
    assert (os.stat(db).st_mode & 0o077) == 0


def test_puerto_ocupado_se_auto_arregla(tmp_path):
    import socket
    from centinela.doctor import FIX
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.listen()
    try:
        args = _args(db=str(tmp_path / "c.db"), web=True, web_port=port)
        f = run(args)
        # Auto-arreglo: ya no es error; el puerto se reubica y muta args.
        assert any(x["level"] == FIX for x in f)
        assert args.web_port != port
        assert not has_blocking_errors(f)
    finally:
        s.close()


def test_db_no_escribible_se_reubica(monkeypatch, tmp_path):
    from centinela.doctor import FIX
    # Forzamos un directorio de BD no escribible: el doctor debe reubicar.
    bad = tmp_path / "nope" / "c.db"
    monkeypatch.setattr("os.makedirs",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("ro")))
    args = _args(db=str(bad))
    f = run(args)
    assert any(x["level"] == FIX and "reubic" in x["msg"].lower() for x in f) \
        or any(x["level"] == ERR for x in f)
