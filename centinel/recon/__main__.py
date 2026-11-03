"""Entrypoint del modo recon. Habilita ANSI en Windows y arranca la TUI."""
from __future__ import annotations

import os
import sys


def _enable_ansi_on_windows() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        k = ctypes.windll.kernel32   # type: ignore[attr-defined]
        k.SetConsoleMode(k.GetStdHandle(-11), 7)   # ENABLE_VIRTUAL_TERMINAL
    except Exception:   # noqa: BLE001
        pass


def _force_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


def _parse(argv):
    import argparse
    p = argparse.ArgumentParser(prog="centinel.recon", add_help=True)
    p.add_argument("--to-store", action="store_true",
                   help="OPT-IN: vuelca los hallazgos de recon al event store "
                        "firmado del IDS (misma línea de tiempo forense; aún no "
                        "se correlacionan). Apagado por defecto.")
    p.add_argument("--db", default="centinel.db",
                   help="ruta del event store al que volcar con --to-store")
    return p.parse_args(argv)


def main(argv=None, *, to_store=None, db_path=None) -> int:
    _enable_ansi_on_windows()
    _force_utf8()
    # Si app.py ya resolvió el flag, úsalo tal cual; si no, parsea argv (entrada
    # autónoma `python -m centinel.recon`).
    if to_store is None:
        ns = _parse(argv)
        to_store = ns.to_store
        db_path = ns.db
    from .tui import run
    try:
        return run(to_store=bool(to_store), db_path=db_path or "centinel.db")
    except KeyboardInterrupt:
        print("\nInterrumpido.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
