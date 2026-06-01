"""Ventanas de mantenimiento: distingue cambios legítimos de hostiles.

Centinela vigilaba todo en frío. En un sistema vivo eso = ruido: `apt upgrade`,
`git pull` sobre el propio Centinela, `modprobe` al insertar un USB, `passwd`
del usuario. Todos esos cambios SON legítimos y NO deben gritar CRITICAL.

Este módulo expone `MaintenanceContext`:

  - dpkg_recent_paths(seconds): paths tocados por dpkg en los últimos N seg.
  - self_update_in_progress(): True si el repo git de Centinela ha movido HEAD
    en los últimos N seg (estás haciendo git pull mientras dev).
  - in_grace_period(): True durante los primeros N seg desde el arranque
    (deja que las baselines se estabilicen sin alertar).

Los colectores consultan estas funciones para SILENCIAR la alerta o bajarla
a INFO. Si quieres saberlo de todos modos, se loguea como info; si no, se
descarta. Nunca enmascara una alerta que NO entra en el patrón legítimo.
"""
from __future__ import annotations

import os
import re
import time


class MaintenanceContext:
    def __init__(self, *, grace_seconds: float = 90.0,
                 dpkg_window: float = 120.0,
                 self_update_window: float = 300.0) -> None:
        self._started = time.time()
        self.grace = grace_seconds
        self.dpkg_window = dpkg_window
        self.selfup_window = self_update_window
        self._self_head_path = self._find_self_head()

    def in_grace_period(self) -> bool:
        return (time.time() - self._started) < self.grace

    def _find_self_head(self) -> str | None:
        """Si Centinela vive bajo un repo git, devuelve la ruta de .git/HEAD."""
        try:
            import centinela
            d = os.path.dirname(os.path.abspath(centinela.__file__))
        except Exception:
            return None
        # Sube hasta encontrar .git/
        for _ in range(6):
            cand = os.path.join(d, ".git", "HEAD")
            if os.path.exists(cand):
                return cand
            new = os.path.dirname(d)
            if new == d:
                break
            d = new
        return None

    def self_update_in_progress(self) -> bool:
        if not self._self_head_path:
            return False
        try:
            mt = os.path.getmtime(self._self_head_path)
        except OSError:
            return False
        return (time.time() - mt) < self.selfup_window

    _DPKG_LINE = re.compile(
        r"^(\S+\s\S+)\s+(install|upgrade|remove|configure)\s+(\S+)")

    def dpkg_recent_paths(self) -> set[str]:
        """Lee /var/log/dpkg.log y devuelve un set de paths que probablemente
        haya tocado dpkg en la última ventana. Aproximación pragmática: si un
        paquete acaba de instalarse, las rutas en /usr/bin /usr/sbin /etc
        suelen ser suyas — no podemos resolver qué fichero exactamente sin
        leer la base de dpkg, así que devolvemos un MARCADOR especial y los
        colectores tratan cualquier ruta del sistema como 'probable dpkg' si
        ha habido actividad reciente."""
        log = "/var/log/dpkg.log"
        if not os.path.exists(log):
            return set()
        try:
            mt = os.path.getmtime(log)
        except OSError:
            return set()
        if (time.time() - mt) > self.dpkg_window:
            return set()
        # Marcador: actividad reciente. Los colectores lo interpretan como
        # "downgrade alertas de paths de sistema a INFO durante la ventana".
        return {"__DPKG_ACTIVE__"}

    def is_legitimate(self, kind: str, path: str | None = None) -> tuple[bool, str]:
        """Decide si una alerta probablemente sea mantenimiento legítimo.

        Devuelve (es_legítimo, motivo). Si True, el colector debe descartar
        o degradar la alerta a INFO en vez de gritar CRITICAL."""
        if self.in_grace_period():
            return True, f"periodo de gracia ({int(self.grace)}s tras arranque)"
        if kind == "persistence_selftamper" and self.self_update_in_progress():
            return True, "git pull reciente sobre el propio Centinela"
        if self.dpkg_recent_paths():
            if kind in ("persistence_integrity", "persistence_authfile",
                        "persistence_pam", "persistence_kmod"):
                if path is None or path.startswith(("/usr/", "/bin/", "/sbin/",
                                                    "/lib/", "/etc/")):
                    return True, "dpkg/apt activo en los últimos 2 min"
        return False, ""
