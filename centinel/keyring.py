"""Carga/crea claves HMAC en disco con O_NOFOLLOW + O_EXCL (anti-symlink/TOCTOU).

Helper compartido por las baselines firmadas (`baseline_store`) y la cadena
tamper-evident del event store (`storage/db`). Centraliza la creación segura
de la clave para no duplicar la lógica de endurecimiento en cada módulo.

Garantías:
  - Lectura O_NOFOLLOW: si un atacante sustituye el fichero por un symlink, la
    apertura falla en vez de leer un archivo arbitrario del sistema con perms
    de root.
  - Creación O_EXCL: evita la carrera con un atacante que pre-cree el path.
  - Perms 0600: la clave nunca es legible por otros usuarios.
  - Si todo falla (FS de solo lectura, etc.) devuelve una clave EFÍMERA en RAM:
    las firmas valen durante la sesión pero no persisten entre reinicios. El
    llamador decide si eso es aceptable (mejor degradar que reventar).
"""
from __future__ import annotations

import os
import secrets

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
# En Windows os.open usa modo TEXTO por defecto y traduce 0x0A<->0x0D0A, lo que
# corrompe una clave binaria (los bytes escritos != leídos). O_BINARY lo evita;
# en POSIX no existe y vale 0.
_BINARY = getattr(os, "O_BINARY", 0)


def load_or_create_key(path: str, size: int = 32) -> bytes:
    """Devuelve la clave de `path`, creándola (0600) si no existe."""
    try:
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW | _BINARY)
        try:
            k = os.read(fd, max(4096, size))
        finally:
            os.close(fd)
        if len(k) >= size:
            return k
    except OSError:
        pass
    k = secrets.token_bytes(size)
    try:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | _NOFOLLOW | _BINARY, 0o600)
        except FileExistsError:
            # Existe pero era ilegible/corta: sobreescribimos sin seguir symlinks.
            fd = os.open(path, os.O_WRONLY | os.O_TRUNC | _NOFOLLOW | _BINARY,
                         0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(k)
    except OSError:
        pass
    return k
