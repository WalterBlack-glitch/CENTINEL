"""ProcWatch: caza malware que se disfraza de proceso del sistema (Windows).

El truco más viejo del malware de Windows es llamarse como un proceso del SO
(`svchost.exe`, `lsass.exe`, `services.exe`…) para esconderse entre los cientos
que corren de verdad. ProcWatch lo caza con una regla **basada en firma**, no en
el nombre:

  1. **Suplantación** — un binario que se llama como un proceso del sistema pero
     NO está firmado válidamente por Microsoft (o vive fuera de C:\\Windows).
  2. **Padre anómalo** — un `svchost.exe` cuyo padre no es `services.exe` es la
     huella clásica de un falso svchost lanzado por un dropper.
  3. **Residente escribible** — un ejecutable corriendo desde `%TEMP%`,
     `%APPDATA%`, `Downloads`, `ProgramData`… sin firma de un editor de
     confianza. Ahí casi nunca vive software legítimo residente.

La decisión (`classify_process`) es **pura y testeable**: entra un `ProcInfo`
normalizado (nombre, ruta, firmante, firma-válida, padre), salen motivos +
severidad. El I/O específico de Windows (enumerar procesos y verificar la firma
Authenticode vía PowerShell) vive en `enumerate_windows_procs`, separado y
sustituible. En Linux el colector se desactiva solo (`available()` -> False):
el core sigue siendo el IDS de Linux; esto es su compañero para hosts Windows.

MITRE: T1036.005 (Masquerading: Match Legitimate Name), T1055 (Process
Injection, señal indirecta vía padre anómalo).
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
from dataclasses import dataclass

from ..core import Severity, ThreatEvent
from .base import Collector

# Nombres de procesos que el SO ejecuta y que el malware suele imitar.
SYSTEM_PROCESS_NAMES = frozenset({
    "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
    "winlogon.exe", "svchost.exe", "lsaiso.exe", "fontdrvhost.exe", "dwm.exe",
    "spoolsv.exe", "taskhostw.exe", "runtimebroker.exe", "ctfmon.exe",
    "conhost.exe", "searchindexer.exe", "sihost.exe", "explorer.exe",
    "searchhost.exe", "startmenuexperiencehost.exe", "audiodg.exe",
    "dllhost.exe", "wininit.exe", "userinit.exe",
})
# Editores en cuya firma confiamos aunque el binario viva en carpeta de usuario.
TRUSTED_SIGNERS = (
    "microsoft", "anthropic", "google", "valve", "discord", "mozilla",
    "opera", "nvidia", "advanced micro devices", "malwarebytes", "spotify",
    "python software foundation", "steam",
)


@dataclass(frozen=True)
class ProcInfo:
    """Proceso normalizado, listo para clasificar. Sin dependencia del SO."""
    pid: int
    name: str            # "svchost.exe" (tal cual)
    path: str            # ruta del ejecutable ("" si desconocida/protegida)
    signer: str          # nombre del firmante ("" si sin firma)
    sig_valid: bool      # ¿firma Authenticode válida?
    parent_name: str     # nombre del proceso padre ("" si desconocido)


def norm_path(path: str) -> str:
    """Normaliza una ruta de Windows: quita el prefijo extendido \\\\?\\ y baja
    a minúsculas para comparar de forma estable."""
    if not path:
        return ""
    if path.startswith("\\\\?\\"):
        path = path[4:]
    return path.lower()


def _is_trusted(signer: str) -> bool:
    s = signer.lower()
    return any(t in s for t in TRUSTED_SIGNERS)


def classify_process(
    p: ProcInfo,
    *,
    win_dir: str,
    writable_dirs: tuple[str, ...],
    system_names: frozenset[str] = SYSTEM_PROCESS_NAMES,
) -> tuple[list[str], int]:
    """Clasifica un proceso. Devuelve (motivos, severidad_int). Pura.

    `win_dir` y `writable_dirs` llegan ya en minúsculas (los normaliza el
    llamador según el host). No toca disco ni procesos: solo razona sobre el
    `ProcInfo` que recibe.
    """
    name = p.name.lower()
    path_l = norm_path(p.path)
    win_l = win_dir.lower()
    reasons: list[str] = []
    sev = 0

    def bump(reason: str, level: int) -> None:
        nonlocal sev
        reasons.append(reason)
        sev = max(sev, level)

    # 1) Suplantación de nombre de sistema (solo si conocemos la ruta: los
    #    procesos protegidos sin ruta legible no son, por sí, sospechosos).
    if name in system_names and path_l:
        ms_signed = p.sig_valid and "microsoft" in p.signer.lower()
        if not ms_signed:
            bump(f"SUPLANTACIÓN: '{p.name}' usa nombre de proceso del sistema "
                 f"sin firma válida de Microsoft "
                 f"(firma_válida={p.sig_valid}, firmante='{p.signer}')",
                 int(Severity.CRITICAL))
        elif not path_l.startswith(win_l):
            bump(f"'{p.name}' firmado por Microsoft pero fuera de "
                 f"{win_dir} ({p.path})", int(Severity.HIGH))

    # 2) svchost con padre anómalo: el real siempre cuelga de services.exe.
    if name == "svchost.exe" and p.parent_name and \
            p.parent_name.lower() != "services.exe":
        bump(f"svchost.exe con padre anómalo '{p.parent_name}' "
             f"(el legítimo cuelga de services.exe)", int(Severity.CRITICAL))

    # 3) Ejecutable residente en carpeta de usuario escribible sin firma de
    #    confianza (droppers en %TEMP%/%APPDATA%/Downloads…).
    if path_l:
        for d in writable_dirs:
            if d and path_l.startswith(d):
                if not (p.sig_valid and _is_trusted(p.signer)):
                    bump(f"corre desde carpeta escribible sin firma de "
                         f"confianza ({p.path}; firmante='{p.signer}')",
                         int(Severity.HIGH))
                break

    return reasons, sev


def scan(
    procs: list[ProcInfo],
    *,
    win_dir: str,
    writable_dirs: tuple[str, ...],
) -> list[ThreatEvent]:
    """Clasifica una lista de procesos y devuelve los eventos de amenaza. Pura."""
    events: list[ThreatEvent] = []
    for p in procs:
        reasons, sev = classify_process(
            p, win_dir=win_dir, writable_dirs=writable_dirs)
        if not reasons:
            continue
        events.append(ThreatEvent(
            kind="proc_impersonation", severity=Severity(sev),
            message=(f"Proceso sospechoso '{p.name}' (pid {p.pid}, padre "
                     f"'{p.parent_name}') — {'; '.join(reasons)}"),
            tags={"proc", "host", "windows"},
            enrichment={"pid": p.pid, "name": p.name, "path": p.path,
                        "signer": p.signer, "sig_valid": p.sig_valid,
                        "parent": p.parent_name, "reasons": list(reasons)}))
    return events


# --------------------------------------------------------------------------
# I/O específico de Windows (no puro): enumerar procesos + verificar firma.
# Se apoya en PowerShell (viene con Windows) para no añadir dependencias pip.
# --------------------------------------------------------------------------

def default_win_dir() -> str:
    return os.environ.get("WinDir", r"C:\Windows")


def default_writable_dirs() -> tuple[str, ...]:
    env = os.environ
    home = env.get("USERPROFILE", "")
    cand = [
        env.get("TEMP", ""), env.get("APPDATA", ""),
        os.path.join(env.get("LOCALAPPDATA", ""), "Temp") if env.get("LOCALAPPDATA") else "",
        os.path.join(home, "Downloads") if home else "",
        env.get("PUBLIC", ""), env.get("ProgramData", ""),
    ]
    return tuple(norm_path(c) for c in cand if c)


# PowerShell que enumera procesos y firma SOLO a los candidatos (nombre de
# sistema o ruta escribible) para no verificar cientos de firmas (lento). Es un
# pre-filtro de rendimiento; la decisión final la toma classify_process.
_PS_ENUM = r"""
$ErrorActionPreference='SilentlyContinue'
$sys=@('smss.exe','csrss.exe','wininit.exe','services.exe','lsass.exe','winlogon.exe','svchost.exe','lsaiso.exe','fontdrvhost.exe','dwm.exe','spoolsv.exe','taskhostw.exe','runtimebroker.exe','ctfmon.exe','conhost.exe','searchindexer.exe','sihost.exe','explorer.exe','searchhost.exe','startmenuexperiencehost.exe','audiodg.exe','dllhost.exe','userinit.exe')
$wr=@($env:TEMP,$env:APPDATA,"$env:LOCALAPPDATA\Temp","$env:USERPROFILE\Downloads",$env:PUBLIC,$env:ProgramData)|?{$_}|%{$_.ToLower()}
$procs=Get-CimInstance Win32_Process|Select-Object ProcessId,Name,ExecutablePath,ParentProcessId
$byId=@{}; foreach($p in $procs){$byId[[int]$p.ProcessId]=$p}
$out=foreach($p in $procs){
  $path=$p.ExecutablePath; $pl=if($path){($path -replace '^\\\\\?\\','').ToLower()}else{''}
  $isSys=$sys -contains $p.Name.ToLower()
  $inWr=$false; foreach($d in $wr){if($pl -and $pl.StartsWith($d)){$inWr=$true;break}}
  $signer=''; $valid=$false
  if($path -and ($isSys -or $inWr)){
    $s=Get-AuthenticodeSignature $path
    $valid=($s.Status -eq 'Valid')
    if($s.SignerCertificate){$signer=($s.SignerCertificate.Subject -replace '^CN=','').Split(',')[0].Trim('"',' ')}
  } else { $valid=$true }
  $par=if($byId[[int]$p.ParentProcessId]){$byId[[int]$p.ParentProcessId].Name}else{''}
  [PSCustomObject]@{pid=[int]$p.ProcessId;name=$p.Name;path=$path;signer=$signer;sig_valid=[bool]$valid;parent=$par}
}
$out|ConvertTo-Json -Compress -Depth 3
"""


def enumerate_windows_procs(timeout: float = 90.0) -> list[ProcInfo]:
    """Enumera procesos de Windows con firma de los candidatos. I/O, no puro."""
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_ENUM],
            capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return []
    data = (res.stdout or "").strip()
    if not data:
        return []
    try:
        rows = json.loads(data)
    except json.JSONDecodeError:
        return []
    if isinstance(rows, dict):   # ConvertTo-Json colapsa 1 elemento a objeto
        rows = [rows]
    procs: list[ProcInfo] = []
    for r in rows:
        try:
            procs.append(ProcInfo(
                pid=int(r.get("pid", 0)), name=str(r.get("name", "")),
                path=str(r.get("path") or ""), signer=str(r.get("signer") or ""),
                sig_valid=bool(r.get("sig_valid", False)),
                parent_name=str(r.get("parent") or "")))
        except (ValueError, TypeError):
            continue
    return procs


class ProcWatchCollector(Collector):
    """Colector: escanea procesos de Windows buscando suplantación del sistema."""
    name = "procwatch"

    def __init__(self, bus, interval: float = 30.0) -> None:
        super().__init__(bus)
        self.interval = max(5.0, interval)
        self._alerted: dict[str, float] = {}
        self._win_dir = default_win_dir()
        self._writable = default_writable_dirs()

    def available(self) -> bool:
        return os.name == "nt"

    async def run(self) -> None:
        if not self.available():
            return
        while True:
            try:
                procs = await asyncio.to_thread(enumerate_windows_procs)
                for ev in scan(procs, win_dir=self._win_dir,
                               writable_dirs=self._writable):
                    key = f"{ev.enrichment.get('path')}\x1f{ev.enrichment.get('pid')}"
                    now = time.time()
                    last = self._alerted.get(key)
                    if last is not None and now - last < 600.0:
                        continue
                    self._alerted[key] = now
                    await self.emit(ev)
            except Exception:   # noqa: BLE001 — nunca tumbar el colector
                pass
            await asyncio.sleep(self.interval)
