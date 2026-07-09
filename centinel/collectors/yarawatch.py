"""YaraWatch: escaneo de firmas YARA — la capa que cierra "sin firmas".

CENTINEL detecta por comportamiento (sin firmas), lo que le da zero-day pero
le deja ciego ante malware *conocido* que aún no ha actuado. YARA cubre ese
hueco: escanea el CONTENIDO de ficheros en directorios efímeros (/tmp,
/dev/shm, /var/tmp, /run/shm) — donde caen droppers, webshells, mineros y
reverse shells — contra un juego de reglas.

Es una capa **opcional**: requiere `yara-python` (extra `[yara]`). Si no está
instalado, el colector se declara no-disponible y CENTINEL sigue sin él. El
core no gana ni una dependencia obligatoria.

Reglas: por defecto usa `centinel/rules/default.yar` (firmas genéricas de
alta señal, sin copyright). `--yara-rules <ruta>` acepta un fichero .yar o un
directorio de .yar propios (p.ej. las reglas de tu equipo o de un feed).

La lógica de qué escanear (`should_scan_file`) y el mapeo severidad
(`severity_for_match`) son PURAS y se testean sin yara instalado.

MITRE: cobertura transversal (T1059, T1105, T1027, T1496…) según la regla.
"""
from __future__ import annotations

import asyncio
import os
import stat as _stat
import time

from ..core import Severity, ThreatEvent
from .base import Collector

_SCAN_DIRS = ("/tmp", "/var/tmp", "/dev/shm", "/run/shm")
_MAX_FILE_BYTES = 32 * 1024 * 1024      # no escanear ficheros gigantes (>32MB)
_ALERT_TTL = 600.0
_MAX_EVENTS_PER_SCAN = 32
_MAX_FILES_PER_SCAN = 2000


def _default_rules_path() -> str:
    """Ruta al fichero de reglas empaquetado."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(here, "rules", "default.yar")


def should_scan_file(path: str, size: int, *,
                     max_bytes: int = _MAX_FILE_BYTES) -> tuple[bool, str]:
    """¿Vale la pena escanear este fichero? → (sí, razón_si_no).

    Pura: no toca el FS. El caller pasa size (y garantiza que es un fichero
    regular). Salta vacíos y gigantes.
    """
    if size <= 0:
        return False, "vacío"
    if size > max_bytes:
        return False, f"demasiado grande ({size} > {max_bytes})"
    return True, ""


def severity_for_match(meta: dict | None) -> Severity:
    """Deriva la severidad del match desde meta.severity de la regla.

    Convención: la regla puede declarar `severity = "critical|high|medium|low"`.
    Sin meta → HIGH (un match de firma es fuerte por defecto).
    """
    if not meta:
        return Severity.HIGH
    raw = str(meta.get("severity", "")).strip().lower()
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }.get(raw, Severity.HIGH)


def _match_meta(match) -> dict:
    """Extrae meta de un objeto match de yara (robusto a versiones)."""
    m = getattr(match, "meta", None)
    return dict(m) if isinstance(m, dict) else {}


class YaraWatch(Collector):
    name = "yarawatch"

    def __init__(self, bus, rules_path: str | None = None,
                 interval: float = 30.0,
                 scan_dirs: tuple[str, ...] = _SCAN_DIRS) -> None:
        super().__init__(bus)
        self.rules_path = rules_path or _default_rules_path()
        self.interval = max(5.0, float(interval))
        self.scan_dirs = scan_dirs
        self._rules = None
        self._seen: dict[str, float] = {}     # (path:mtime) ya alertado
        self._compile_error: str | None = None

    def available(self) -> bool:
        try:
            import yara  # noqa: F401
        except ImportError:
            print("[yarawatch] yara-python no instalado "
                  "(pip install 'centinel[yara]'); capa desactivada.")
            return False
        if not os.path.exists(self.rules_path):
            print(f"[yarawatch] reglas no encontradas: {self.rules_path}")
            return False
        # Compila una vez; si las reglas están rotas, no arrancamos la capa.
        try:
            self._rules = self._compile()
        except Exception as exc:   # noqa: BLE001
            print(f"[yarawatch] error compilando reglas: {exc}")
            return False
        return True

    def _compile(self):
        import yara
        if os.path.isdir(self.rules_path):
            # Directorio: compila todos los .yar/.yara juntos.
            files = {}
            for name in sorted(os.listdir(self.rules_path)):
                if name.endswith((".yar", ".yara")):
                    files[name] = os.path.join(self.rules_path, name)
            if not files:
                raise ValueError("directorio sin ficheros .yar")
            return yara.compile(filepaths=files)
        return yara.compile(filepath=self.rules_path)

    async def run(self) -> None:
        while True:
            try:
                await asyncio.to_thread(self._scan_sync)
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(self.interval)

    def _iter_files(self):
        """Genera (path, size, mtime) de ficheros regulares en los dirs objetivo."""
        count = 0
        for base in self.scan_dirs:
            if not os.path.isdir(base):
                continue
            for root, _dirs, files in os.walk(base):
                for fn in files:
                    full = os.path.join(root, fn)
                    try:
                        st = os.lstat(full)
                    except OSError:
                        continue
                    # Solo ficheros regulares (no symlinks, sockets, fifos).
                    if not _stat.S_ISREG(st.st_mode):
                        continue
                    yield full, st.st_size, st.st_mtime
                    count += 1
                    if count >= _MAX_FILES_PER_SCAN:
                        return

    def _scan_sync(self) -> None:
        if self._rules is None:
            return
        loop = asyncio.get_event_loop()
        now = time.time()
        pending: list[ThreatEvent] = []

        for path, size, mtime in self._iter_files():
            ok, _why = should_scan_file(path, size)
            if not ok:
                continue
            key = f"{path}:{int(mtime)}"
            if now - self._seen.get(key, 0.0) < _ALERT_TTL:
                continue
            try:
                matches = self._rules.match(path, timeout=10)
            except Exception:  # noqa: BLE001 — fichero desaparecido, permiso, etc.
                continue
            if not matches:
                continue
            self._seen[key] = now
            for m in matches:
                meta = _match_meta(m)
                sev = severity_for_match(meta)
                desc = meta.get("description", "")
                pending.append(ThreatEvent(
                    kind="yara_match", severity=sev,
                    message=f"YARA '{getattr(m, 'rule', '?')}'"
                            f"{' — ' + desc if desc else ''} en {path}",
                    tags={"yara", "signature", str(getattr(m, "rule", ""))}))
                if len(pending) >= _MAX_EVENTS_PER_SCAN:
                    break
            if len(pending) >= _MAX_EVENTS_PER_SCAN:
                break

        # Purga TTL.
        self._seen = {k: t for k, t in self._seen.items()
                      if now - t < _ALERT_TTL}
        for ev in pending:
            asyncio.run_coroutine_threadsafe(self.emit(ev), loop)
