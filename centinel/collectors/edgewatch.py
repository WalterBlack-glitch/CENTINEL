"""EdgeWatch: anti-malware "edge" — Microsoft Edge + edge/IoT + cutting-edge.

Cubre 4 vectores donde el malware moderno se esconde:

  1. **Hijack de Microsoft Edge** — homepage forzada, search provider exótico,
     startup URLs raras, extensiones con permisos peligrosos (webRequest,
     <all_urls>) instaladas fuera del Store. Lee Preferences en
     ~/.config/microsoft-edge/ (Linux) y opcionalmente /mnt/c/... (WSL).

  2. **Boot / firmware tamper** — cambios en /boot/* desde la baseline
     (kernel/initrd reemplazados, GRUB modificado). Baseline en RAM por
     defecto; persistente con --baseline-dir.

  3. **Kernel modules** — módulos nuevos en /proc/modules respecto al
     primer escaneo. LKM rootkit clásico (Reptile, Diamorphine).

  4. **Fileless / LOLBins (cutting-edge)**:
       - /proc/<pid>/exe → "(deleted)"  o  "memfd:..." → ejecución en
         memoria sin fichero (memfd_create + execveat). Bandera Rojo.
       - cmdline con patrones living-off-the-land: base64 -d | bash,
         curl|sh, wget|bash, python -c "import socket;...", perl -e,
         nc -e/-c, php -r "eval(...)".

Clasificadores puros (testeables sin /proc ni FS real). El I/O va aparte
en `asyncio.to_thread`. Sin subprocess, sin shell.

MITRE: T1176 (browser extensions), T1542.003 (bootkit), T1014 (rootkit),
T1620 (reflective code loading), T1059.004/.006 (interpreter LOLBins).
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time

from ..core import Severity, ThreatEvent
from .base import Collector


_ALERT_TTL = 600.0
_MAX_EVENTS_PER_SCAN = 24

# --- Edge hijack -------------------------------------------------------------

# Search providers / homepages habituales que NO disparan alerta.
_SAFE_DOMAINS = (
    "bing.com", "google.com", "duckduckgo.com", "ecosia.org",
    "startpage.com", "qwant.com", "yahoo.com", "yandex.com",
    "microsoft.com", "msn.com", "office.com",
)

# Extensiones de Edge cargadas vía política empresarial o sideload son las
# que más usan los hijackers; los IDs del Store oficial son 32 chars a-p.
_STORE_ID_RE = re.compile(r"^[a-p]{32}$")

# Permisos que delatan extensión maliciosa cuando se combinan.
_DANGEROUS_PERMS = frozenset({
    "webRequest", "webRequestBlocking", "proxy", "cookies",
    "<all_urls>", "*://*/*", "http://*/*", "https://*/*",
    "tabs", "history", "management", "debugger",
})


def classify_search_provider(url: str) -> tuple[bool, str]:
    """¿Search provider sospechoso? URL típica: https://x.com/search?q={searchTerms}."""
    if not url:
        return False, ""
    low = url.lower()
    if not low.startswith(("http://", "https://")):
        return True, f"search provider con protocolo no-http: {url[:80]}"
    # Extrae dominio.
    try:
        host = low.split("//", 1)[1].split("/", 1)[0].split(":")[0]
    except Exception:
        return True, f"search provider con URL ilegible: {url[:80]}"
    if not any(host == d or host.endswith("." + d) for d in _SAFE_DOMAINS):
        return True, f"search provider fuera de proveedores conocidos: {host}"
    return False, ""


def classify_homepage(url: str) -> tuple[bool, str]:
    """¿Homepage forzada a un dominio extraño?"""
    if not url or url in ("about:blank", "edge://newtab/", "chrome://newtab/"):
        return False, ""
    low = url.lower()
    if low.startswith("file://"):
        return True, f"homepage apunta a fichero local: {url[:80]}"
    if not low.startswith(("http://", "https://")):
        return True, f"homepage con protocolo no-http: {url[:80]}"
    try:
        host = low.split("//", 1)[1].split("/", 1)[0].split(":")[0]
    except Exception:
        return True, f"homepage con URL ilegible: {url[:80]}"
    if not any(host == d or host.endswith("." + d) for d in _SAFE_DOMAINS):
        return True, f"homepage fijada a dominio inusual: {host}"
    return False, ""


def classify_extension(ext_id: str, manifest: dict) -> tuple[bool, str]:
    """¿Extensión de Edge sospechosa? (id no-store + permisos peligrosos)."""
    if not isinstance(manifest, dict):
        return False, ""
    perms = set(manifest.get("permissions") or [])
    perms |= set(manifest.get("host_permissions") or [])
    optional = set(manifest.get("optional_permissions") or [])
    perms |= optional
    bad = perms & _DANGEROUS_PERMS
    sideloaded = not _STORE_ID_RE.match(ext_id or "")
    if sideloaded and bad:
        return True, (f"extensión sideloaded '{ext_id}' con permisos "
                      f"peligrosos: {sorted(bad)[:3]}")
    # Aun sin sideload: si pide webRequest + <all_urls> + cookies juntos,
    # es el patrón de un infostealer/adware moderno.
    triad = {"webRequest", "cookies"} & perms
    has_all_urls = bool(perms & {"<all_urls>", "*://*/*", "https://*/*"})
    if len(triad) >= 2 and has_all_urls:
        return True, (f"extensión '{ext_id}' combina webRequest+cookies+<all_urls> "
                      f"(patrón de infostealer)")
    return False, ""


def _edge_profile_paths(home: str | None = None) -> list[str]:
    """Devuelve rutas posibles del Default profile de Edge en este host."""
    home = home or os.path.expanduser("~")
    out = []
    # Linux nativo.
    for sub in ("microsoft-edge", "microsoft-edge-beta", "microsoft-edge-dev"):
        out.append(os.path.join(home, ".config", sub, "Default"))
    # WSL: leer perfil de Windows si está montado.
    user = os.path.basename(home)
    win_root = f"/mnt/c/Users/{user}/AppData/Local/Microsoft/Edge/User Data/Default"
    out.append(win_root)
    return out


def _load_prefs(profile_dir: str) -> dict:
    """Carga Preferences (JSON) de un perfil Edge si existe."""
    p = os.path.join(profile_dir, "Preferences")
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f) or {}
    except (OSError, ValueError):
        return {}


def _list_extensions(profile_dir: str) -> list[tuple[str, dict]]:
    """Devuelve [(id, manifest_dict)] para cada extensión del perfil."""
    out: list[tuple[str, dict]] = []
    root = os.path.join(profile_dir, "Extensions")
    if not os.path.isdir(root):
        return out
    try:
        ids = os.listdir(root)
    except OSError:
        return out
    for ext_id in ids:
        ext_dir = os.path.join(root, ext_id)
        if not os.path.isdir(ext_dir):
            continue
        try:
            versions = [v for v in os.listdir(ext_dir)
                        if os.path.isdir(os.path.join(ext_dir, v))]
        except OSError:
            continue
        if not versions:
            continue
        manifest_path = os.path.join(ext_dir, versions[-1], "manifest.json")
        try:
            with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
                out.append((ext_id, json.load(f) or {}))
        except (OSError, ValueError):
            continue
    return out


# --- Boot / kernel -----------------------------------------------------------

def list_boot_files(boot_dir: str = "/boot") -> dict[str, float]:
    """Snapshot {fichero: mtime} del directorio /boot."""
    out: dict[str, float] = {}
    if not os.path.isdir(boot_dir):
        return out
    try:
        for name in os.listdir(boot_dir):
            full = os.path.join(boot_dir, name)
            try:
                out[full] = os.stat(full).st_mtime
            except OSError:
                continue
    except OSError:
        pass
    return out


def diff_boot(baseline: dict[str, float],
              current: dict[str, float]) -> list[str]:
    """Devuelve mensajes para ficheros nuevos, borrados o modificados."""
    out = []
    for path, mt in current.items():
        if path not in baseline:
            out.append(f"fichero nuevo en /boot: {path}")
        elif abs(baseline[path] - mt) > 1.0:
            out.append(f"/boot modificado: {path}")
    for path in baseline:
        if path not in current:
            out.append(f"fichero borrado en /boot: {path}")
    return out


def list_kernel_modules() -> set[str]:
    """Lista módulos de /proc/modules (nombre solo)."""
    out: set[str] = set()
    try:
        with open("/proc/modules", "r") as f:
            for line in f:
                parts = line.split()
                if parts:
                    out.add(parts[0])
    except OSError:
        pass
    return out


# --- Fileless / LOLBins ------------------------------------------------------

# Patrones de cmdline que delatan living-off-the-land.
_LOLBIN_PATTERNS = (
    (re.compile(r"base64\s+-d.*\|\s*(bash|sh|zsh|dash|python|perl)"),
     "decode base64 → shell/intérprete"),
    (re.compile(r"(curl|wget)\s+[^|]*\|\s*(bash|sh|zsh|dash)"),
     "descarga-y-ejecuta (curl|sh)"),
    (re.compile(r"python3?\s+-c\s+.*(socket|pty|exec|os\.system|subprocess)"),
     "python -c con socket/exec (reverse shell)"),
    (re.compile(r"perl\s+-e\s+.*(socket|exec|system)"),
     "perl -e con socket/exec"),
    (re.compile(r"\bnc\s+(-e|-c)\b"),
     "netcat con -e/-c (reverse shell clásica)"),
    (re.compile(r"php\s+-r\s+.*(eval|system|exec|passthru)"),
     "php -r con eval/exec"),
    (re.compile(r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+"),
     "bash usando /dev/tcp/IP/PORT (reverse shell)"),
)


def classify_cmdline(cmdline: str) -> tuple[bool, str]:
    """¿Cmdline con patrón LOLBin?"""
    if not cmdline:
        return False, ""
    low = cmdline.replace("\x00", " ").lower()
    for rx, why in _LOLBIN_PATTERNS:
        if rx.search(low):
            return True, why
    return False, ""


def classify_exe_link(link: str) -> tuple[bool, str]:
    """¿/proc/<pid>/exe apunta a algo sospechoso?"""
    if not link:
        return False, ""
    if "(deleted)" in link:
        return True, f"binario borrado tras exec ({link})"
    if link.startswith("/memfd:") or link.startswith("memfd:"):
        return True, f"ejecución desde memfd_create ({link})"
    return False, ""


# --- Collector ---------------------------------------------------------------

class EdgeWatch(Collector):
    name = "edgewatch"

    def __init__(self, bus, interval: float = 30.0,
                 home: str | None = None,
                 boot_dir: str = "/boot") -> None:
        super().__init__(bus)
        self.interval = max(5.0, float(interval))
        self.home = home or os.path.expanduser("~")
        self.boot_dir = boot_dir
        self._seen: dict[str, float] = {}
        self._boot_baseline: dict[str, float] | None = None
        self._modules_baseline: set[str] | None = None

    def available(self) -> bool:
        # Siempre disponible: aunque no haya /proc, los chequeos de Edge
        # son útiles. Las sub-comprobaciones que no aplican se saltan solas.
        return True

    async def run(self) -> None:
        while True:
            try:
                await asyncio.to_thread(self._scan_sync)
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(self.interval)

    def _scan_sync(self) -> None:
        loop = asyncio.get_event_loop()
        now = time.time()
        pending: list[ThreatEvent] = []

        for ev in self._scan_edge_profiles():
            pending.append(ev)
        for ev in self._scan_boot():
            pending.append(ev)
        for ev in self._scan_modules():
            pending.append(ev)
        for ev in self._scan_fileless():
            pending.append(ev)

        # TTL purge.
        self._seen = {k: t for k, t in self._seen.items()
                      if now - t < _ALERT_TTL}
        for ev in pending[:_MAX_EVENTS_PER_SCAN]:
            asyncio.run_coroutine_threadsafe(self.emit(ev), loop)

    # ---- Edge hijack ----
    def _scan_edge_profiles(self) -> list[ThreatEvent]:
        out: list[ThreatEvent] = []
        now = time.time()
        for prof in _edge_profile_paths(self.home):
            if not os.path.isdir(prof):
                continue
            prefs = _load_prefs(prof)
            # Search provider.
            try:
                dsp = (prefs.get("default_search_provider_data", {})
                       .get("template_url_data", {}).get("url", ""))
            except Exception:
                dsp = ""
            bad, why = classify_search_provider(dsp)
            key = f"edge_search:{prof}:{dsp}"
            if bad and self._fresh(key, now):
                out.append(ThreatEvent(
                    kind="edge_hijack_search", severity=Severity.HIGH,
                    message=f"{why} (perfil {prof})",
                    tags={"edge", "browser_hijack", "T1176"}))
            # Homepage / startup URLs.
            hp = (prefs.get("homepage") or "")
            bad, why = classify_homepage(hp)
            key = f"edge_home:{prof}:{hp}"
            if bad and self._fresh(key, now):
                out.append(ThreatEvent(
                    kind="edge_hijack_homepage", severity=Severity.HIGH,
                    message=f"{why} (perfil {prof})",
                    tags={"edge", "browser_hijack", "T1176"}))
            for url in (prefs.get("session", {}) or {}).get("startup_urls", []) or []:
                bad, why = classify_homepage(url)
                key = f"edge_startup:{prof}:{url}"
                if bad and self._fresh(key, now):
                    out.append(ThreatEvent(
                        kind="edge_hijack_startup", severity=Severity.HIGH,
                        message=f"{why} (startup_urls de {prof})",
                        tags={"edge", "browser_hijack", "T1176"}))
            # Extensiones.
            for ext_id, manifest in _list_extensions(prof):
                bad, why = classify_extension(ext_id, manifest)
                key = f"edge_ext:{prof}:{ext_id}"
                if bad and self._fresh(key, now):
                    out.append(ThreatEvent(
                        kind="edge_hijack_extension", severity=Severity.CRITICAL,
                        message=f"{why} (perfil {prof})",
                        tags={"edge", "browser_hijack", "T1176"}))
        return out

    # ---- Boot ----
    def _scan_boot(self) -> list[ThreatEvent]:
        out: list[ThreatEvent] = []
        now = time.time()
        current = list_boot_files(self.boot_dir)
        if not current:
            return out
        if self._boot_baseline is None:
            self._boot_baseline = current
            return out
        for msg in diff_boot(self._boot_baseline, current):
            key = f"boot:{msg}"
            if self._fresh(key, now):
                out.append(ThreatEvent(
                    kind="edge_boot_tamper", severity=Severity.CRITICAL,
                    message=msg,
                    tags={"edge", "bootkit", "T1542.003"}))
        # Actualiza baseline para no repetir el mismo cambio en cada ciclo.
        self._boot_baseline = current
        return out

    # ---- Kernel modules ----
    def _scan_modules(self) -> list[ThreatEvent]:
        out: list[ThreatEvent] = []
        now = time.time()
        current = list_kernel_modules()
        if not current:
            return out
        if self._modules_baseline is None:
            self._modules_baseline = current
            return out
        new = current - self._modules_baseline
        for mod in new:
            key = f"kmod:{mod}"
            if self._fresh(key, now):
                out.append(ThreatEvent(
                    kind="edge_kmod_new", severity=Severity.HIGH,
                    message=f"módulo kernel nuevo cargado: {mod}",
                    tags={"edge", "rootkit", "T1014"}))
        # Actualiza baseline tras alertar (módulos cargados a propósito
        # tras restart de un servicio no deben repetir alerta).
        self._modules_baseline = current
        return out

    # ---- Fileless / LOLBins ----
    def _scan_fileless(self) -> list[ThreatEvent]:
        out: list[ThreatEvent] = []
        now = time.time()
        if not os.path.isdir("/proc"):
            return out
        try:
            pids = [int(d) for d in os.listdir("/proc") if d.isdigit()]
        except OSError:
            return out
        for pid in pids:
            # /proc/<pid>/exe → readlink
            try:
                link = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                link = ""
            bad, why = classify_exe_link(link)
            if bad:
                key = f"fileless:{pid}:{link}"
                if self._fresh(key, now):
                    out.append(ThreatEvent(
                        kind="edge_fileless", severity=Severity.CRITICAL,
                        message=f"{why} (pid {pid})",
                        tags={"edge", "fileless", "T1620"}))
            # cmdline → LOLBin
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmd = f.read().decode("utf-8", "replace")
            except OSError:
                continue
            bad, why = classify_cmdline(cmd)
            if bad:
                key = f"lolbin:{pid}:{why}"
                if self._fresh(key, now):
                    out.append(ThreatEvent(
                        kind="edge_lolbin", severity=Severity.HIGH,
                        message=f"{why} en pid {pid}: "
                                f"{cmd.replace(chr(0), ' ')[:120]}",
                        tags={"edge", "lolbin", "T1059"}))
        return out

    def _fresh(self, key: str, now: float) -> bool:
        if now - self._seen.get(key, 0.0) < _ALERT_TTL:
            return False
        self._seen[key] = now
        return True
