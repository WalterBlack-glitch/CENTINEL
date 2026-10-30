"""InjectWatch: caza inyección de DLL y side-loading en Windows (T1055 / T1574).

Es el compañero de `hijackwatch` (que hace lo propio en Linux vía LD_PRELOAD /
ptrace). Aquí el vector "invisible" es que **no hay un proceso malicioso**: el
código del atacante corre DENTRO de un proceso legítimo, cargado como una DLL.
`procwatch` mira el ejecutable; `injectwatch` mira las **DLLs que cada proceso
tiene cargadas** y busca dos huellas clásicas que no dejan un .exe sospechoso:

  1. **DLL desde carpeta escribible** — una librería cargada desde `%TEMP%`,
     `%APPDATA%`, `Downloads`, `ProgramData`, `Public`… sin firma de confianza.
     Es reflective loading / inyección / side-loading desde disco. Si el proceso
     anfitrión está firmado por un editor de confianza, la señal sube a CRITICAL
     (código no confiable dentro de un proceso confiable).
  2. **DLL de sistema fuera de sitio** — una DLL con nombre de librería del SO
     (`kernel32.dll`, `ntdll.dll`…) cargada desde FUERA de System32/SysWOW64.
     Es DLL search-order hijacking / masquerading (T1574.001/002): dejas un
     `version.dll` junto al .exe y Windows lo carga antes que el real.

La decisión (`classify_modules`) es **pura y testeable**: entra un proceso con
su lista de módulos normalizada, salen motivos + severidad. El I/O de Windows
(enumerar módulos y firmar solo a los candidatos vía PowerShell) vive en
`enumerate_module_candidates`, separado y sustituible. En Linux se desactiva
solo (`available()` -> False): allí el vector equivalente lo cubre hijackwatch.

Alcance honesto: ve la inyección/side-loading en procesos ACCESIBLES (navegador,
explorer, Office, apps de usuario — donde vive la mayoría del malware user-land).
La inyección en procesos protegidos (lsass, servicios PPL) no expone su lista de
módulos sin un driver de kernel, y queda fuera; para esos, procwatch cubre el
flanco de padre anómalo / hollowing indirecto.

MITRE: T1055.001 (DLL Injection), T1574.001 (DLL Search Order Hijacking),
T1574.002 (DLL Side-Loading).
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
from dataclasses import dataclass, field

from ..core import Severity, ThreatEvent
from .base import Collector
from .procwatch import (
    NO_WINDOW, SYSTEM_PROCESS_NAMES, _is_trusted, default_allowed_paths,
    default_win_dir, default_writable_dirs, norm_path,
)

# DLLs del núcleo de Windows: SIEMPRE viven en System32/SysWOW64. Verlas cargadas
# desde otra carpeta es search-order hijacking / masquerading, casi nunca legítimo.
KNOWN_SYSTEM_DLLS = frozenset({
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
    "advapi32.dll", "ole32.dll", "oleaut32.dll", "shell32.dll", "shlwapi.dll",
    "ws2_32.dll", "ws2help.dll", "crypt32.dll", "sechost.dll", "rpcrt4.dll",
    "combase.dll", "msvcrt.dll", "ucrtbase.dll", "bcrypt.dll", "ncrypt.dll",
    "wininet.dll", "winhttp.dll", "secur32.dll", "wintrust.dll", "psapi.dll",
    "version.dll", "setupapi.dll", "userenv.dll", "netapi32.dll",
})
_CANONICAL_SUBDIRS = ("system32", "syswow64", "winsxs")


@dataclass(frozen=True)
class ModuleInfo:
    """Una DLL cargada por un proceso, normalizada. Sin dependencia del SO."""
    name: str            # "version.dll" (tal cual, minúsculas al comparar)
    path: str            # ruta de la DLL en disco ("" si desconocida)
    signer: str          # firmante ("" si sin firma)
    sig_valid: bool      # ¿firma Authenticode válida?


@dataclass(frozen=True)
class ProcModules:
    """Proceso anfitrión + sus módulos candidatos, listo para clasificar."""
    pid: int
    name: str                # nombre del proceso anfitrión
    path: str                # ruta del ejecutable anfitrión
    host_trusted: bool       # ¿el .exe anfitrión está firmado por editor de confianza?
    modules: tuple[ModuleInfo, ...] = field(default_factory=tuple)


def _under_windows_system(path_l: str, win_l: str) -> bool:
    """¿La ruta (normalizada) cuelga de System32/SysWOW64/WinSxS de Windows?"""
    if not path_l or not win_l or not path_l.startswith(win_l):
        return False
    rel = path_l[len(win_l):].lstrip("\\/")
    return rel.startswith(_CANONICAL_SUBDIRS)


def classify_modules(
    p: ProcModules,
    *,
    win_dir: str,
    writable_dirs: tuple[str, ...],
    system_dlls: frozenset[str] = KNOWN_SYSTEM_DLLS,
    allowed_paths: tuple[str, ...] = (),
) -> tuple[list[str], int]:
    """Clasifica los módulos de un proceso. Devuelve (motivos, severidad). Pura.

    `win_dir` y `writable_dirs` llegan ya en minúsculas (los normaliza el
    llamador). No toca disco: solo razona sobre el `ProcModules` recibido.
    """
    win_l = win_dir.lower()
    host_is_system = p.name.lower() in SYSTEM_PROCESS_NAMES
    reasons: list[str] = []
    sev = 0

    def bump(reason: str, level: int) -> None:
        nonlocal sev
        reasons.append(reason)
        sev = max(sev, level)

    for m in p.modules:
        mname = m.name.lower()
        mpath = norm_path(m.path)

        # 1) DLL de sistema cargada desde FUERA de System32/SysWOW64/WinSxS:
        #    search-order hijacking / masquerading. Muy raro que sea legítimo.
        if mname in system_dlls and mpath and \
                not _under_windows_system(mpath, win_l):
            bump(f"DLL de sistema '{m.name}' cargada fuera de System32 "
                 f"({m.path}) — search-order hijacking / side-loading",
                 int(Severity.CRITICAL))
            continue

        # 2) DLL desde carpeta escribible sin firma de confianza: reflective
        #    load / inyección / side-loading desde disco.
        if not mpath or any(pref and mpath.startswith(pref)
                            for pref in allowed_paths):
            continue
        for d in writable_dirs:
            if d and mpath.startswith(d):
                if m.sig_valid and _is_trusted(m.signer):
                    break  # DLL legítima de un editor de confianza (p. ej. app portable)
                # Dentro de un proceso de confianza/sistema = inyección: sube a CRITICAL.
                if host_is_system or p.host_trusted:
                    bump(f"DLL no confiable '{m.name}' desde carpeta escribible "
                         f"({m.path}) inyectada en proceso de confianza "
                         f"'{p.name}' (firmante DLL='{m.signer}')",
                         int(Severity.CRITICAL))
                else:
                    bump(f"'{p.name}' carga DLL desde carpeta escribible sin "
                         f"firma de confianza ({m.path}; firmante='{m.signer}')",
                         int(Severity.HIGH))
                break

    return reasons, sev


def scan(
    procs: list[ProcModules],
    *,
    win_dir: str,
    writable_dirs: tuple[str, ...],
    allowed_paths: tuple[str, ...] = (),
) -> list[ThreatEvent]:
    """Clasifica una lista de procesos y devuelve los eventos de amenaza. Pura."""
    events: list[ThreatEvent] = []
    for p in procs:
        reasons, sev = classify_modules(
            p, win_dir=win_dir, writable_dirs=writable_dirs,
            allowed_paths=allowed_paths)
        if not reasons:
            continue
        events.append(ThreatEvent(
            kind="dll_injection", severity=Severity(sev),
            message=(f"Inyección/side-loading en '{p.name}' (pid {p.pid}) — "
                     f"{'; '.join(reasons)}"),
            tags={"inject", "host", "windows", "T1055.001", "T1574.002"},
            enrichment={"pid": p.pid, "name": p.name, "path": p.path,
                        "reasons": list(reasons)}))
    return events


# --------------------------------------------------------------------------
# I/O específico de Windows (no puro): enumerar módulos + firmar candidatos.
# Se apoya en PowerShell para no añadir dependencias pip.
# --------------------------------------------------------------------------

# Enumera los módulos de cada proceso ACCESIBLE y emite una fila por DLL
# CANDIDATA (fuera de System32 con nombre de sistema, o en carpeta escribible),
# firmándola solo a ella. Los procesos protegidos lanzan Access Denied y se
# omiten en silencio (SilentlyContinue). La decisión final la toma
# classify_modules; esto es un pre-filtro de rendimiento.
_PS_ENUM = r"""
$ErrorActionPreference='SilentlyContinue'
$win=$env:WinDir.ToLower()
$wr=@($env:TEMP,$env:APPDATA,"$env:LOCALAPPDATA\Temp","$env:USERPROFILE\Downloads",$env:PUBLIC,$env:ProgramData)|?{$_}|%{$_.ToLower()}
$sysdll=@('ntdll.dll','kernel32.dll','kernelbase.dll','user32.dll','gdi32.dll','advapi32.dll','ole32.dll','oleaut32.dll','shell32.dll','shlwapi.dll','ws2_32.dll','crypt32.dll','sechost.dll','rpcrt4.dll','combase.dll','msvcrt.dll','ucrtbase.dll','bcrypt.dll','ncrypt.dll','wininet.dll','winhttp.dll','secur32.dll','wintrust.dll','psapi.dll','version.dll','setupapi.dll','userenv.dll','netapi32.dll')
$rows=New-Object System.Collections.ArrayList
foreach($proc in Get-Process){
  $mods=$null; try{ $mods=$proc.Modules }catch{ continue }
  if(-not $mods){continue}
  $hostPath=''; try{ $hostPath=$proc.MainModule.FileName }catch{}
  $hostTrusted=$null  # se firma perezosamente solo si hay candidato
  foreach($m in $mods){
    $mp=$m.FileName; if(-not $mp){continue}
    $mpl=($mp -replace '^\\\\\?\\','').ToLower()
    $mn=$m.ModuleName.ToLower()
    $cand=$false
    if(($sysdll -contains $mn) -and -not ($mpl.StartsWith("$win\system32") -or $mpl.StartsWith("$win\syswow64") -or $mpl.StartsWith("$win\winsxs"))){ $cand=$true }
    if(-not $cand){ foreach($d in $wr){ if($mpl.StartsWith($d)){ $cand=$true; break } } }
    if(-not $cand){ continue }
    if($hostTrusted -eq $null -and $hostPath){
      $hs=Get-AuthenticodeSignature $hostPath
      $hsi=if($hs.SignerCertificate){($hs.SignerCertificate.Subject -replace '^CN=','').Split(',')[0].Trim('"',' ')}else{''}
      $hostTrusted=($hs.Status -eq 'Valid')
      $hostSigner=$hsi
    }
    $ms=Get-AuthenticodeSignature $mp
    $sg=if($ms.SignerCertificate){($ms.SignerCertificate.Subject -replace '^CN=','').Split(',')[0].Trim('"',' ')}else{''}
    [void]$rows.Add([PSCustomObject]@{
      pid=[int]$proc.Id; pname=$proc.ProcessName+'.exe'; ppath=$hostPath;
      host_trusted=[bool]$hostTrusted; host_signer=$hostSigner;
      mname=$m.ModuleName; mpath=$mp; signer=$sg; sig_valid=($ms.Status -eq 'Valid')})
  }
}
$rows|ConvertTo-Json -Compress -Depth 3
"""


def enumerate_module_candidates(timeout: float = 120.0) -> list[ProcModules]:
    """Enumera módulos candidatos de cada proceso accesible. I/O, no puro."""
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_ENUM],
            capture_output=True, text=True, timeout=timeout,
            creationflags=NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return []
    data = (res.stdout or "").strip()
    if not data:
        return []
    try:
        rows = json.loads(data)
    except json.JSONDecodeError:
        return []
    if isinstance(rows, dict):   # ConvertTo-Json colapsa 1 fila a objeto
        rows = [rows]
    # Agrupa las filas (una por DLL) por proceso.
    by_pid: dict[int, dict] = {}
    for r in rows:
        try:
            pid = int(r.get("pid", 0))
        except (ValueError, TypeError):
            continue
        host = by_pid.setdefault(pid, {
            "name": str(r.get("pname", "")), "path": str(r.get("ppath") or ""),
            "host_trusted": bool(r.get("host_trusted", False)),
            "host_signer": str(r.get("host_signer") or ""), "modules": []})
        host["modules"].append(ModuleInfo(
            name=str(r.get("mname", "")), path=str(r.get("mpath") or ""),
            signer=str(r.get("signer") or ""),
            sig_valid=bool(r.get("sig_valid", False))))
    out: list[ProcModules] = []
    for pid, h in by_pid.items():
        # Un editor de confianza en la firma del anfitrión también cuenta.
        trusted = h["host_trusted"] and _is_trusted(h["host_signer"])
        out.append(ProcModules(
            pid=pid, name=h["name"], path=h["path"],
            host_trusted=trusted, modules=tuple(h["modules"])))
    return out


class InjectWatchCollector(Collector):
    """Colector: caza inyección de DLL / side-loading en procesos de Windows."""
    name = "injectwatch"

    def __init__(self, bus, interval: float = 60.0) -> None:
        super().__init__(bus)
        self.interval = max(10.0, interval)
        self._alerted: dict[str, float] = {}
        self._win_dir = default_win_dir()
        self._writable = default_writable_dirs()
        self._allowed = default_allowed_paths()

    def available(self) -> bool:
        return os.name == "nt"

    async def run(self) -> None:
        if not self.available():
            return
        while True:
            try:
                procs = await asyncio.to_thread(enumerate_module_candidates)
                for ev in scan(procs, win_dir=self._win_dir,
                               writable_dirs=self._writable,
                               allowed_paths=self._allowed):
                    key = f"{ev.enrichment.get('name')}\x1f{ev.enrichment.get('pid')}"
                    now = time.time()
                    last = self._alerted.get(key)
                    if last is not None and now - last < 600.0:
                        continue
                    self._alerted[key] = now
                    await self.emit(ev)
            except Exception:   # noqa: BLE001 — nunca tumbar el colector
                pass
            await asyncio.sleep(self.interval)
