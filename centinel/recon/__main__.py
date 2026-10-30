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


def main() -> int:
    _enable_ansi_on_windows()
    _force_utf8()
    from .tui import run
    try:
        return run()
    except KeyboardInterrupt:
        print("\nInterrumpido.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
