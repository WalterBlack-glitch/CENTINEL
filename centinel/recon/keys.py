"""Lectura de una tecla sin Enter, multiplataforma con solo la stdlib.

Windows -> msvcrt; POSIX -> termios/tty. Devuelve tokens normalizados:
"up", "down", "enter", "quit", o el carácter tal cual. Si no hay TTY (p.ej.
tests o pipe), `read_key` devuelve "" para que el llamador caiga a modo línea.
"""
from __future__ import annotations

import sys

UP, DOWN, ENTER, QUIT = "up", "down", "enter", "quit"


def _posix_key() -> str:
    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x1b":                      # posible secuencia de flecha
            seq = sys.stdin.read(2)
            return {"[A": UP, "[B": DOWN}.get(seq, "")
        if ch in ("\r", "\n"):
            return ENTER
        if ch == "\x03":                      # Ctrl-C
            raise KeyboardInterrupt
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _win_key() -> str:
    import msvcrt
    ch = msvcrt.getwch()
    if ch in ("\x00", "\xe0"):                # prefijo de tecla extendida
        ext = msvcrt.getwch()
        return {"H": UP, "P": DOWN}.get(ext, "")
    if ch in ("\r", "\n"):
        return ENTER
    if ch == "\x03":
        raise KeyboardInterrupt
    return ch


def has_tty() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (ValueError, AttributeError):
        return False


def read_key() -> str:
    if not has_tty():
        return ""
    try:
        import msvcrt  # noqa: F401
        return _win_key()
    except ImportError:
        return _posix_key()
