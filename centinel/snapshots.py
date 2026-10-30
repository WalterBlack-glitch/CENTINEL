"""Historial de escaneos y diff entre ellos: «esto es nuevo desde ayer».

Un escaneo aislado dice *qué hay*. Lo que un analista necesita es *qué cambió*:
un hallazgo que lleva seis meses ahí (una app portable legítima) no merece la
misma atención que uno que apareció esta mañana.

Dos piezas, siguiendo el patrón del repo (clasificador puro / I-O aparte):

  - Puro: `snapshot()` convierte eventos en un retrato comparable, y `diff()`
    compara dos retratos → nuevos / resueltos / persistentes / agravados.
  - I/O: `SnapshotStore` guarda el historial como JSONL **firmado con HMAC**.

Por qué firmar el historial: el diff decide qué se le enseña al usuario. Si el
fichero fuera editable, un atacante podría inyectar su propio implante en el
retrato de "ayer" para que mañana apareciera como *persistente conocido* y se
perdiera entre el ruido — o borrar el historial para que todo vuelva a ser
"nuevo" y el usuario se acostumbre a ignorarlo. Una línea con firma inválida
no se carga: se descarta y se avisa, igual que en `baseline_store`.

La identidad de un hallazgo es `kind|nombre|ruta`, **nunca el PID**: el PID
cambia en cada reinicio y haría que todo pareciese nuevo siempre. Cuando el
proceso está protegido y no expone su ruta (lsass, PPL), la ruta va vacía y
dos hallazgos del mismo nombre colapsan en uno: es el precio de no tener
ruta, y se documenta aquí para que nadie lo lea como un bug.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field

from .core import Severity
from .keyring import load_or_create_key

_HISTORY = "history.jsonl"
_KEY_NAME = ".snapkey"
_MAX_LINE = 1 << 20          # 1 MiB por retrato: corta un fichero envenenado


# --------------------------------------------------------------- puro: modelo
@dataclass(frozen=True)
class Finding:
    """Un hallazgo en forma comparable entre escaneos."""
    key: str
    kind: str
    name: str
    path: str
    severity: int
    reasons: tuple[str, ...] = ()
    pid: int | None = None          # informativo: NO forma parte de la identidad

    def to_dict(self) -> dict:
        return {"key": self.key, "kind": self.kind, "name": self.name,
                "path": self.path, "severity": int(self.severity),
                "reasons": list(self.reasons), "pid": self.pid}

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(
            key=str(d.get("key") or ""), kind=str(d.get("kind") or ""),
            name=str(d.get("name") or ""), path=str(d.get("path") or ""),
            severity=int(d.get("severity") or 0),
            reasons=tuple(d.get("reasons") or ()),
            pid=d.get("pid") if isinstance(d.get("pid"), int) else None)


def norm_path(path: str) -> str:
    """Igual que `procwatch.norm_path`, duplicado aquí para no importar un
    módulo de colector (que arrastra I/O de Windows) desde el núcleo."""
    if not path:
        return ""
    if path.startswith("\\\\?\\"):
        path = path[4:]
    return path.replace("/", "\\").lower()


def finding_key(kind: str, name: str, path: str) -> str:
    """Identidad estable de un hallazgo entre escaneos."""
    base = "{}|{}|{}".format(kind or "", (name or "").lower(), norm_path(path))
    return hashlib.sha256(base.encode("utf-8", "replace")).hexdigest()[:16]


def finding_from_event(ev) -> Finding:
    """Extrae un `Finding` de un ThreatEvent de procwatch/injectwatch."""
    enr = getattr(ev, "enrichment", None) or {}
    name = str(enr.get("name") or "")
    path = str(enr.get("path") or enr.get("module") or "")
    kind = str(getattr(ev, "kind", "") or "")
    pid = enr.get("pid")
    return Finding(
        key=finding_key(kind, name, path), kind=kind, name=name, path=path,
        severity=int(getattr(ev, "severity", 0) or 0),
        reasons=tuple(str(r) for r in (enr.get("reasons") or ())),
        pid=pid if isinstance(pid, int) else None)


def snapshot(events, *, ts: float | None = None, host: str = "") -> dict:
    """Retrato comparable de un escaneo. Puro (salvo el reloj por defecto).

    Si dos eventos comparten identidad (mismo nombre y ruta), se conserva el
    de mayor severidad: el retrato describe *el estado*, no cada aviso.
    """
    mejores: dict[str, Finding] = {}
    for ev in events or ():
        f = finding_from_event(ev)
        previo = mejores.get(f.key)
        if previo is None or f.severity > previo.severity:
            mejores[f.key] = f
    orden = sorted(mejores.values(), key=lambda f: (-f.severity, f.name, f.key))
    return {"ts": float(ts if ts is not None else time.time()),
            "host": host,
            "findings": [f.to_dict() for f in orden]}


def findings_of(snap: dict | None) -> dict[str, Finding]:
    """Hallazgos de un retrato, indexados por identidad."""
    if not snap:
        return {}
    out: dict[str, Finding] = {}
    for d in snap.get("findings") or ():
        if not isinstance(d, dict):
            continue
        f = Finding.from_dict(d)
        if f.key:
            out[f.key] = f
    return out


# ----------------------------------------------------------------- puro: diff
@dataclass
class Diff:
    """Qué cambió entre dos escaneos."""
    nuevos: list[Finding] = field(default_factory=list)
    resueltos: list[Finding] = field(default_factory=list)
    persistentes: list[Finding] = field(default_factory=list)
    agravados: list[tuple[Finding, Finding]] = field(default_factory=list)
    prev_ts: float | None = None
    cur_ts: float | None = None

    @property
    def sin_historial(self) -> bool:
        """True en el primer escaneo: no hay con qué comparar."""
        return self.prev_ts is None

    @property
    def hay_cambios(self) -> bool:
        return bool(self.nuevos or self.resueltos or self.agravados)

    @property
    def peor_nuevo(self) -> int:
        return max((f.severity for f in self.nuevos), default=0)

    def resumen(self) -> str:
        if self.sin_historial:
            n = len(self.nuevos)
            return ("Primer escaneo: {} hallazgo(s) registrados como línea "
                    "base.".format(n) if n else
                    "Primer escaneo: limpio, línea base guardada.")
        if not self.hay_cambios:
            return ("Sin cambios desde el escaneo anterior ({} hallazgo(s) "
                    "ya conocidos).".format(len(self.persistentes)))
        partes = []
        if self.nuevos:
            partes.append("{} nuevo(s) [{}]".format(
                len(self.nuevos), Severity(self.peor_nuevo).name))
        if self.agravados:
            partes.append("{} agravado(s)".format(len(self.agravados)))
        if self.resueltos:
            partes.append("{} resuelto(s)".format(len(self.resueltos)))
        if self.persistentes:
            partes.append("{} sin cambio".format(len(self.persistentes)))
        return "Desde el escaneo anterior: " + ", ".join(partes) + "."


def diff(prev: dict | None, cur: dict) -> Diff:
    """Compara dos retratos. Pura. `prev=None` = primer escaneo."""
    antes = findings_of(prev)
    ahora = findings_of(cur)
    d = Diff(prev_ts=(prev or {}).get("ts") if prev else None,
             cur_ts=cur.get("ts"))
    for key, f in ahora.items():
        viejo = antes.get(key)
        if viejo is None:
            d.nuevos.append(f)
        elif f.severity > viejo.severity:
            d.agravados.append((viejo, f))
        else:
            d.persistentes.append(f)
    for key, f in antes.items():
        if key not in ahora:
            d.resueltos.append(f)
    peor = lambda f: (-f.severity, f.name)      # noqa: E731
    d.nuevos.sort(key=peor)
    d.resueltos.sort(key=peor)
    d.persistentes.sort(key=peor)
    d.agravados.sort(key=lambda par: peor(par[1]))
    return d


# ------------------------------------------------------------------ I/O: store
class SnapshotStore:
    """Historial append-only de retratos, cada línea firmada con HMAC.

    Degradado honesto: si el directorio no se puede crear o escribir, el store
    queda `disabled` y el llamador sigue funcionando sin historial (igual que
    las baselines en RAM). Nunca revienta el escaneo por no poder guardar.
    """

    def __init__(self, dirpath: str) -> None:
        self.dir = os.path.abspath(dirpath)
        self.path = os.path.join(self.dir, _HISTORY)
        self.disabled = False
        self.rejected = 0        # líneas descartadas por firma/formato inválidos
        try:
            os.makedirs(self.dir, mode=0o700, exist_ok=True)
            self._key = load_or_create_key(os.path.join(self.dir, _KEY_NAME))
        except (OSError, RuntimeError):
            self.disabled = True
            self._key = b""

    # --- firma
    def _sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def _wrap(self, snap: dict) -> str:
        payload = json.dumps(snap, sort_keys=True, ensure_ascii=False).encode()
        return json.dumps({"snapshot": snap, "__hmac__": self._sign(payload)},
                          sort_keys=True, ensure_ascii=False)

    def _unwrap(self, line: str) -> dict | None:
        try:
            obj = json.loads(line)
            snap = obj["snapshot"]
            sig = obj.get("__hmac__") or ""
        except (ValueError, KeyError, TypeError):
            return None
        if not isinstance(snap, dict):
            return None
        payload = json.dumps(snap, sort_keys=True, ensure_ascii=False).encode()
        if not hmac.compare_digest(str(sig), self._sign(payload)):
            return None
        return snap

    # --- lectura / escritura
    def append(self, snap: dict) -> bool:
        """Añade un retrato al final. Devuelve si se pudo guardar."""
        if self.disabled:
            return False
        try:
            fd = os.open(self.path,
                         os.O_WRONLY | os.O_CREAT | os.O_APPEND
                         | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(fd, "ab") as f:
                f.write(self._wrap(snap).encode("utf-8") + b"\n")
            return True
        except OSError:
            return False

    def load_all(self, limit: int | None = None) -> list[dict]:
        """Retratos válidos, del más viejo al más nuevo. Las líneas con firma
        inválida se cuentan en `rejected` y se ignoran."""
        if self.disabled:
            return []
        try:
            with open(self.path, encoding="utf-8") as f:
                lineas = f.readlines()
        except OSError:
            return []
        self.rejected = 0
        out: list[dict] = []
        for linea in lineas:
            linea = linea.strip()
            if not linea:
                continue
            if len(linea) > _MAX_LINE:
                self.rejected += 1
                continue
            snap = self._unwrap(linea)
            if snap is None:
                self.rejected += 1
                continue
            out.append(snap)
        return out[-limit:] if limit else out

    def load_last(self) -> dict | None:
        todos = self.load_all()
        return todos[-1] if todos else None

    def prune(self, keep: int) -> int:
        """Conserva los `keep` retratos más recientes. Devuelve cuántos quedaron."""
        if self.disabled or keep < 0:
            return 0
        todos = self.load_all()
        if len(todos) <= keep:
            return len(todos)
        quedan = todos[-keep:] if keep else []
        tmp = self.path + ".tmp"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                         | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(fd, "ab") as f:
                for snap in quedan:
                    f.write(self._wrap(snap).encode("utf-8") + b"\n")
            os.replace(tmp, self.path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return len(todos)
        return len(quedan)


def default_history_dir() -> str:
    """Dónde vive el historial: LOCALAPPDATA en Windows, ~/.local/share fuera."""
    env = os.environ
    if os.name == "nt":
        base = env.get("LOCALAPPDATA") or env.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "CENTINEL", "history")
    base = env.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"),
                                                    ".local", "share")
    return os.path.join(base, "centinel", "history")


def record_and_diff(events, *, store: SnapshotStore, host: str = "",
                    ts: float | None = None, keep: int = 200) -> tuple[Diff, dict]:
    """Toma el escaneo actual, lo compara con el anterior y lo archiva.

    Devuelve (diff, retrato). El orden importa: se lee el anterior ANTES de
    escribir el nuevo, o el diff se compararía consigo mismo.
    """
    previo = store.load_last()
    cur = snapshot(events, ts=ts, host=host)
    d = diff(previo, cur)
    if store.append(cur) and keep:
        store.prune(keep)
    return d, cur
