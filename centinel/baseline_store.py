"""Baselines persistentes y firmadas (HMAC-SHA256).

Las baselines de integridad/SUID/fcaps/kmod/PAM viven en RAM. Si Centinel
reinicia (o un atacante lo provoca), se reconstruyen "desde cero" y un
implante ya presente entra en la nueva baseline como legítimo.

Este módulo persiste cada baseline a disco como JSON firmado con HMAC,
usando una clave que se crea (0600) en la primera ejecución. Si el fichero
falta o la firma no cuadra, NO se carga: se loguea y se reconstruye en RAM.

API minimal:
    bs = BaselineStore("/var/lib/centinel/baselines")
    data = bs.load("suid")        # devuelve dict | list | None
    bs.save("suid", baseline_dict_o_list_o_set)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile


_KEY_NAME = ".key"


class BaselineStore:
    def __init__(self, dirpath: str) -> None:
        self.dir = os.path.abspath(dirpath)
        try:
            os.makedirs(self.dir, mode=0o700, exist_ok=True)
        except OSError:
            # Fallback degradado. Endurecimiento: si CENTINEL corre como root,
            # NO caemos a /tmp (un atacante local puede pre-crear el dir o
            # poner symlinks). En ese caso, el caller verá baselines en RAM.
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                raise RuntimeError(
                    f"BaselineStore: '{dirpath}' no escribible y soy root; "
                    f"rechazo fallback a /tmp (riesgo de TOCTOU). Pasa una "
                    f"ruta válida en --baseline-dir.") from None
            self.dir = os.path.join(tempfile.gettempdir(), "centinel-baselines")
            os.makedirs(self.dir, mode=0o700, exist_ok=True)
        # Anti-TOCTOU (solo POSIX: en Windows el modelo de perms es distinto).
        # Si el dir ya existía con otro owner o con perms world-accesibles,
        # abortamos para no exponer la clave HMAC. Si no podemos endurecerlo,
        # el caller usará baselines en RAM.
        if os.name == "posix":
            try:
                st = os.stat(self.dir)
                if st.st_uid != os.geteuid() or (st.st_mode & 0o077):
                    raise RuntimeError(
                        f"BaselineStore: '{self.dir}' tiene owner/perms "
                        f"inseguros (uid={st.st_uid}, "
                        f"mode={oct(st.st_mode & 0o777)}); abortamos para no "
                        f"exponer la clave HMAC.")
            except OSError as exc:
                raise RuntimeError(
                    f"BaselineStore: stat falló en '{self.dir}': {exc}")
        self._key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        kp = os.path.join(self.dir, _KEY_NAME)
        # Lectura O_NOFOLLOW: si alguien sustituye .key por symlink, fallará
        # (en vez de leer un archivo arbitrario del sistema con perms de root).
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(kp, os.O_RDONLY | nofollow)
            try:
                k = os.read(fd, 4096)
            finally:
                os.close(fd)
            if len(k) >= 32:
                return k
        except OSError:
            pass
        k = secrets.token_bytes(32)
        try:
            # O_EXCL evita race con un atacante que pre-cree el path; si falla
            # porque ya existe, lo intentamos sobreescribir sin seguir symlinks.
            try:
                fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | nofollow, 0o600)
            except FileExistsError:
                fd = os.open(kp, os.O_WRONLY | os.O_TRUNC | nofollow, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(k)
        except OSError:
            pass
        return k

    def _path(self, name: str) -> str:
        # `name` viene del propio código, pero saneamos por si acaso.
        safe = "".join(c for c in name if c.isalnum() or c in "._-")[:64]
        return os.path.join(self.dir, safe + ".json")

    def load(self, name: str):
        p = self._path(name)
        try:
            with open(p, "rb") as f:
                raw = f.read()
        except OSError:
            return None
        try:
            obj = json.loads(raw)
            sig = obj.pop("__hmac__", "")
            payload = json.dumps(obj, sort_keys=True).encode()
            want = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, want):
                # Firma rota → baseline manipulada. NO la cargamos.
                return None
            return obj.get("data")
        except (ValueError, KeyError):
            return None

    def save(self, name: str, data) -> None:
        # Normaliza set -> list para que sea JSON-serializable.
        if isinstance(data, set):
            data = sorted(data)
        payload = json.dumps({"data": data}, sort_keys=True).encode()
        sig = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        obj = {"data": data, "__hmac__": sig}
        p = self._path(name)
        tmp = p + ".tmp"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(obj, f, sort_keys=True)
            os.replace(tmp, p)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
