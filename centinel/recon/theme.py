"""Temas de color de la TUI (ANSI 256). Puro: solo define paletas y helpers."""
from __future__ import annotations

from dataclasses import dataclass

RESET = "\x1b[0m"


@dataclass(frozen=True)
class Theme:
    name: str
    title: str      # color del banner
    section: str    # cabeceras de sección
    cmd: str        # nombre del comando
    help: str       # texto de ayuda
    accent: str     # selección / resaltado
    dim: str
    ok: str
    warn: str
    err: str


def _c(code: str) -> str:
    return f"\x1b[{code}m"


# 6 temas. Los colores son códigos ANSI (fg). El resaltado usa fondo (accent).
THEMES: dict[str, Theme] = {
    "matrix":  Theme("matrix",  _c("1;32"), _c("32"), _c("1;92"), _c("2;37"),
                     _c("30;42"), _c("2;32"), _c("92"), _c("93"), _c("91")),
    "amber":   Theme("amber",   _c("1;33"), _c("33"), _c("1;93"), _c("2;37"),
                     _c("30;43"), _c("2;33"), _c("92"), _c("93"), _c("91")),
    "ice":     Theme("ice",     _c("1;36"), _c("36"), _c("1;96"), _c("2;37"),
                     _c("30;46"), _c("2;36"), _c("92"), _c("93"), _c("91")),
    "blood":   Theme("blood",   _c("1;31"), _c("31"), _c("1;91"), _c("2;37"),
                     _c("30;41"), _c("2;31"), _c("92"), _c("93"), _c("91")),
    "violet":  Theme("violet",  _c("1;35"), _c("35"), _c("1;95"), _c("2;37"),
                     _c("30;45"), _c("2;35"), _c("92"), _c("93"), _c("91")),
    "mono":    Theme("mono",    _c("1;97"), _c("37"), _c("1;97"), _c("2;37"),
                     _c("30;47"), _c("2;37"), _c("92"), _c("93"), _c("91")),
}
DEFAULT_THEME = "matrix"


def get(name: str) -> Theme:
    return THEMES.get(name, THEMES[DEFAULT_THEME])


def names() -> list[str]:
    return list(THEMES)


def paint(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"
