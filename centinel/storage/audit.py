"""Bitácora de auditoría en JSONL append-only.

Cada escaneo y cada hallazgo dejan una línea JSON. Una línea por registro, el
fichero solo crece por el final y se rota por tamaño: es el formato que después
se puede leer con `grep`, cargar en jq, o mandar a un SIEM sin convertir nada.

Por qué append-only y no un log normal: la bitácora es evidencia. Abrir en modo
`"a"` mediante `O_APPEND` hace que cada escritura vaya al final de forma atómica
para registros pequeños, así que ni dos procesos de CENTINEL a la vez se pisan
las líneas. No pretende ser inviolable — quien sea root o Administrador puede
reescribir el fichero; para integridad verificable está la cadena HMAC del event
store (`storage/db`) y el historial firmado (`snapshots`). Esto es la capa de
*trazabilidad legible*, y conviene ser honesto sobre lo que cada capa da.

La rotación conserva `keep` ficheros (`audit.jsonl.1`, `.2`, …) y nunca falla
hacia arriba: si no se puede rotar o escribir, la bitácora queda deshabilitada
y el escaneo sigue. Un IDS no se cae porque su log esté lleno.
"""
from __future__ import annotations

import json
import os
import time

_MAX_BYTES = 5 << 20       # 5 MiB por fichero
_KEEP = 3                  # audit.jsonl.1 .. .3
_NOMBRE = "audit.jsonl"


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))


def default_audit_path() -> str:
    """Junto al historial: LOCALAPPDATA en Windows, XDG fuera."""
    from ..snapshots import default_history_dir
    return os.path.join(os.path.dirname(default_history_dir()), _NOMBRE)


class AuditLog:
    """Bitácora JSONL con rotación por tamaño. Degrada sin reventar."""

    def __init__(self, path: str, *, max_bytes: int = _MAX_BYTES,
                 keep: int = _KEEP) -> None:
        self.path = os.path.abspath(path)
        self.max_bytes = max(0, int(max_bytes))
        self.keep = max(0, int(keep))
        self.disabled = False
        self.written = 0
        try:
            carpeta = os.path.dirname(self.path)
            if carpeta:
                os.makedirs(carpeta, mode=0o700, exist_ok=True)
        except OSError:
            self.disabled = True

    # ------------------------------------------------------------- escritura
    def write(self, kind: str, message: str = "", *, level: str = "INFO",
              **data) -> bool:
        """Añade un registro. Devuelve si se pudo escribir."""
        if self.disabled:
            return False
        ts = time.time()
        rec = {"ts": round(ts, 3), "iso": _iso(ts), "level": str(level),
               "kind": str(kind), "message": str(message)}
        if data:
            rec["data"] = data
        try:
            linea = json.dumps(rec, ensure_ascii=False, sort_keys=True,
                               default=str)
        except (TypeError, ValueError):
            linea = json.dumps({"ts": round(ts, 3), "iso": _iso(ts),
                                "level": "ERROR", "kind": "audit_encode_error",
                                "message": f"registro no serializable: {kind}"})
        try:
            self._rotate_if_needed(len(linea) + 1)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND
                         | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(fd, "ab") as f:
                f.write(linea.encode("utf-8") + b"\n")
        except OSError:
            return False
        self.written += 1
        return True

    def _rotate_if_needed(self, entrante: int) -> None:
        if not self.max_bytes:
            return
        try:
            actual = os.path.getsize(self.path)
        except OSError:
            return
        if actual + entrante <= self.max_bytes:
            return
        if not self.keep:
            try:
                os.unlink(self.path)
            except OSError:
                pass
            return
        for i in range(self.keep, 0, -1):
            viejo = f"{self.path}.{i}"
            if i == self.keep:
                try:
                    os.unlink(viejo)
                except OSError:
                    pass
                continue
            try:
                os.replace(viejo, f"{self.path}.{i + 1}")
            except OSError:
                pass
        try:
            os.replace(self.path, f"{self.path}.1")
        except OSError:
            pass

    # --------------------------------------------------------- conveniencias
    def log_event(self, ev) -> bool:
        """Registra un ThreatEvent tal como lo ve el usuario."""
        from ..core import Severity
        enr = getattr(ev, "enrichment", None) or {}
        try:
            sev = Severity(int(getattr(ev, "severity", 0) or 0)).name
        except (ValueError, TypeError):
            sev = "INFO"
        return self.write(getattr(ev, "kind", "") or "event",
                          getattr(ev, "message", "") or "", level=sev,
                          name=enr.get("name"), pid=enr.get("pid"),
                          path=enr.get("path"), signer=enr.get("signer"),
                          reasons=list(enr.get("reasons") or ()))

    def log_scan(self, d, snap: dict, *, host: str = "") -> bool:
        """Registra el resultado de un escaneo completo y su diff."""
        return self.write(
            "scan", d.resumen() if d is not None else "escaneo completado",
            level=("WARNING" if d is not None and d.hay_cambios else "INFO"),
            host=host or snap.get("host", ""),
            total=len(snap.get("findings") or ()),
            nuevos=len(getattr(d, "nuevos", ()) or ()) if d is not None else 0,
            agravados=len(getattr(d, "agravados", ()) or ()) if d is not None else 0,
            resueltos=len(getattr(d, "resueltos", ()) or ()) if d is not None else 0,
            escaneo_ts=snap.get("ts"))

    # ---------------------------------------------------------------- lectura
    def read_last(self, n: int = 50) -> list[dict]:
        """Últimos `n` registros válidos (los corruptos se saltan)."""
        if self.disabled or n <= 0:
            return []
        try:
            with open(self.path, encoding="utf-8") as f:
                lineas = f.readlines()
        except OSError:
            return []
        out: list[dict] = []
        for linea in reversed(lineas):
            linea = linea.strip()
            if not linea:
                continue
            try:
                rec = json.loads(linea)
            except ValueError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
            if len(out) >= n:
                break
        out.reverse()
        return out

    def size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0
