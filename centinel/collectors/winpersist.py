"""winpersist — vectores de arranque en Windows (lectura, nunca escritura).

Compañero de Windows de `persistence.py` (que cubre Linux: SUID, cron, systemd).
Tras entrar, el atacante quiere QUEDARSE, y en Windows eso se consigue casi
siempre por uno de estos cuatro sitios:

  1. `Run` / `RunOnce` del registro (HKLM y HKCU) — el clásico absoluto.
  2. La carpeta `Startup` del usuario o de todos los usuarios.
  3. Un servicio cuyo binario vive fuera de `System32`.
  4. Una tarea programada que relanza el implante.

Lo que delata a un arranque malicioso no es *estar* ahí — hay decenas de
entradas legítimas — sino la combinación de **dónde vive el binario** y **cómo
se invoca**:

  - ejecutable en carpeta escribible (Temp, AppData, Descargas) sin firma de
    confianza → HIGH; es el patrón del 90 % del malware de consumo;
  - un intérprete del sistema con banderas de ofuscación o descarga
    (`powershell -enc`, `-w hidden`, `mshta http…`, `rundll32 javascript:`,
    `certutil -decode`, `curl|iex`) → CRITICAL: *living-off-the-land*, el
    binario es legítimo y firmado, así que solo la línea de comando lo delata;
  - `RunOnce` apuntando a algo escribible → HIGH: se ejecuta una vez y se
    borra, justo lo que quiere un dropper.

Honestidad sobre el alcance: esto **lee**. No desactiva ni borra nada; la
decisión es del humano. Y no pretende cubrir los vectores exóticos (WMI event
subscriptions, COM hijacking, IFEO, AppInit_DLLs): están documentados como
límite conocido, no silenciados.

Patrón del repo: `parse_command` y `classify_autoruns` son puros y se prueban
sin Windows; el PowerShell de lectura vive abajo y aparte.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass

from ..core import Severity, ThreatEvent
from .procwatch import NO_WINDOW, _is_trusted, norm_path

# Sitios desde los que se arranca algo. El nombre se usa en el mensaje.
UBICACIONES = ("HKLM\\Run", "HKLM\\RunOnce", "HKCU\\Run", "HKCU\\RunOnce",
               "Startup", "Startup (común)", "Servicio", "Tarea programada")

# Intérpretes que el atacante usa porque ya vienen firmados por Microsoft.
_INTERPRETES = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "msiexec.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "curl.exe",
    "msbuild.exe", "forfiles.exe", "pcalua.exe", "conhost.exe",
})

# Patrones FUERTES: por sí solos bastan para un veredicto grave, porque no
# tienen uso legítimo conocido en un arranque automático.
_FUERTES = (
    (re.compile(r"\s-enc(?:odedcommand)?\b", re.I), "comando PowerShell codificado en base64"),
    (re.compile(r"\s-e\s+[A-Za-z0-9+/=]{40,}"), "carga base64 larga en la línea de comando"),
    (re.compile(r"\b(?:iex|invoke-expression)\b", re.I), "Invoke-Expression (ejecuta texto como código)"),
    (re.compile(r"\b(?:downloadstring|downloadfile|invoke-webrequest|iwr|wget)\b", re.I), "descarga desde la línea de comando"),
    (re.compile(r"\bfrombase64string\b", re.I), "decodifica base64 en memoria"),
    (re.compile(r"\bcertutil\b.*\s-(?:decode|urlcache)\b", re.I), "certutil usado para descargar o decodificar"),
    (re.compile(r"\bbitsadmin\b.*\s/transfer\b", re.I), "bitsadmin usado para descargar"),
    (re.compile(r"\bmshta\b.*(?:https?:|javascript:|vbscript:)", re.I), "mshta ejecutando script remoto"),
    (re.compile(r"\brundll32\b.*(?:javascript:|url\.dll|\.dll\s*,\s*#\d+)", re.I), "rundll32 con invocación anómala"),
    (re.compile(r"\bregsvr32\b.*\s/i:\s*https?:", re.I), "regsvr32 con scriptlet remoto (squiblydoo)"),
    (re.compile(r"\|\s*(?:iex|invoke-expression|cmd|powershell)\b", re.I), "salida canalizada a un intérprete"),
)

# Patrones DÉBILES: frecuentes en software legítimo (y en las propias tareas de
# Windows, que no tienen ventana que mostrar). Acompañan a un veredicto, nunca
# lo deciden solos: tratarlos como graves llena la pantalla de ruido y enseña
# al usuario a ignorar las alertas, que es el peor resultado posible.
_DEBILES = (
    (re.compile(r"\s-(?:w|windowstyle)\s+hidden\b", re.I), "ventana oculta"),
    (re.compile(r"\s-nop(?:rofile)?\b.*\s-(?:c|command)\b", re.I), "PowerShell sin perfil ejecutando comando"),
    (re.compile(r"-executionpolicy\s+bypass", re.I), "política de ejecución anulada"),
)

# Las tareas programadas corren sin escritorio: la ventana oculta es lo normal.
_DEBIL_ESPERADO = {"Tarea programada": {"ventana oculta"}}

# Extensiones que Authenticode no puede firmar: exigirles firma es exigir algo
# imposible, así que su ausencia no puede pesar como la de un .exe sin firmar.
_NO_FIRMABLE = (".lnk", ".cmd", ".bat", ".vbs", ".js", ".ps1", ".url", ".hta")

# «No he podido comprobarlo» no es «no está firmado». Los binarios protegidos
# (el motor de Defender, por ejemplo) no se dejan leer ni siquiera para
# verificar. Un estado vacío NO entra aquí: significa que nadie preguntó por la
# firma, y entonces vale la regla de siempre.
_SIG_NO_VERIFICABLE = frozenset({"unknownerror", "unsupportedfileformat"})

_EXT_DOBLE = re.compile(
    r"\.(?:pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|mp3|mp4|zip)\.(?:exe|scr|com|pif|bat|cmd|js|vbs)$",
    re.I)


@dataclass(frozen=True)
class AutorunEntry:
    """Una entrada de arranque ya normalizada. Sin dependencia del SO."""
    location: str          # una de UBICACIONES
    name: str              # nombre del valor / servicio / tarea
    command: str           # línea de comando tal cual
    path: str = ""         # ejecutable resuelto ("" si no se pudo)
    signer: str = ""
    sig_valid: bool = False
    user: str = ""         # con qué cuenta arranca, si se sabe
    sig_status: str = ""   # estado crudo de Authenticode (NotSigned, Valid...)

    def to_dict(self) -> dict:
        return {"location": self.location, "name": self.name,
                "command": self.command, "path": self.path,
                "signer": self.signer, "sig_valid": bool(self.sig_valid),
                "user": self.user, "sig_status": self.sig_status}


# ------------------------------------------------------------------ puro
def parse_command(command: str) -> str:
    """Saca el ejecutable de una línea de comando del registro.

    El registro guarda cosas como `"C:\\Program Files\\App\\a.exe" -min`,
    `C:\\Windows\\system32\\a.exe,1`, `%SystemRoot%\\a.exe /x` o incluso
    `C:\\ruta sin comillas\\con espacios\\a.exe -flag`. Acertar aquí importa:
    si se extrae mal la ruta, la regla de "carpeta escribible" mira el sitio
    equivocado y el hallazgo se pierde.
    """
    if not command:
        return ""
    cmd = os.path.expandvars(command.strip())
    if cmd.startswith('"'):
        fin = cmd.find('"', 1)
        return cmd[1:fin].strip() if fin > 0 else cmd[1:].strip()
    if cmd.startswith("'"):
        fin = cmd.find("'", 1)
        return cmd[1:fin].strip() if fin > 0 else cmd[1:].strip()

    # Sin comillas: el truco es que una ruta puede llevar espacios. Vamos
    # ampliando hasta la última posición que acabe en una extensión ejecutable.
    sin_args = re.split(r"\s+(?=[-/])", cmd, maxsplit=1)[0]
    m = re.search(r"^(.*?\.(?:exe|com|bat|cmd|scr|pif|js|vbs|msi|dll|lnk))(?:\b|$)",
                  sin_args, re.I)
    if m:
        return m.group(1).strip().rstrip(",")
    return sin_args.split(",")[0].strip()


_PARECE_RUTA = re.compile(
    r"(?:^[a-z]:[\\/]|^\\\\|\.(?:exe|com|bat|cmd|scr|pif|js|vbs|msi|dll|lnk)$)",
    re.I)


def _resuelto(path_l: str) -> bool:
    """¿Lo que sacamos del comando parece de verdad un ejecutable?

    `parse_command` siempre devuelve *algo*; si ese algo no es una ruta ni
    tiene extensión ejecutable (p. ej. «algo»), no hemos resuelto nada y hay
    que decirlo, no dar por bueno un camino que no existe.
    """
    return bool(path_l) and bool(_PARECE_RUTA.search(path_l))


def _en_escribible(path_l: str, writable_dirs: tuple[str, ...]) -> bool:
    return any(d and path_l.startswith(d) for d in writable_dirs)


def _permitido(path_l: str, allowed_paths: tuple[str, ...]) -> bool:
    return any(p and path_l.startswith(p) for p in allowed_paths)


def command_flags(command: str, location: str = "") -> tuple[list[str], list[str]]:
    """(motivos fuertes, motivos débiles) de una línea de comando. Puro.

    Los débiles que son normales en esa ubicación se descartan: una tarea
    programada con la ventana oculta no es noticia.
    """
    cmd = command or ""
    fuertes = [m for p, m in _FUERTES if p.search(cmd)]
    esperados = _DEBIL_ESPERADO.get(location, frozenset())
    debiles = [m for p, m in _DEBILES if p.search(cmd) and m not in esperados]
    return fuertes, debiles


def _firmable(path_l: str) -> bool:
    """¿Es un formato al que Authenticode pueda ponerle firma?"""
    return not path_l.endswith(_NO_FIRMABLE)


def classify_autorun(
    e: AutorunEntry,
    *,
    win_dir: str,
    writable_dirs: tuple[str, ...],
    allowed_paths: tuple[str, ...] = (),
) -> tuple[list[str], int]:
    """Motivos y severidad de una entrada de arranque. Pura."""
    razones: list[str] = []
    sev = int(Severity.INFO)

    path_l = norm_path(e.path or parse_command(e.command))
    base = os.path.basename(path_l)
    confiable = bool(e.sig_valid) and _is_trusted(e.signer)
    firmable = _firmable(path_l)
    no_verificable = (e.sig_status or "").strip().lower() in _SIG_NO_VERIFICABLE \
        and not e.sig_valid

    # 1. Living-off-the-land: intérprete legítimo con banderas de ataque. Un
    #    patrón fuerte decide por sí solo; los débiles solo acompañan.
    fuertes, debiles = command_flags(e.command, e.location)
    if fuertes:
        razones.extend(fuertes)
        razones.extend(debiles)
        sev = max(sev, int(Severity.CRITICAL) if (base in _INTERPRETES or not confiable)
                  else int(Severity.HIGH))
    elif debiles:
        razones.extend(debiles)
        # Sin nada fuerte detrás esto es, como mucho, algo que mirar.
        sev = max(sev, int(Severity.MEDIUM) if not confiable else int(Severity.LOW))

    # 2. Binario en carpeta escribible sin firma de confianza.
    if _resuelto(path_l) and not _permitido(path_l, allowed_paths):
        if _en_escribible(path_l, writable_dirs) and not confiable:
            if not firmable:
                # Un .lnk o un .cmd nunca van firmados: decirlo tal cual en vez
                # de acusarlo de «sin firma», que suena a hallazgo y no lo es.
                razones.append("script o acceso directo en carpeta escribible, "
                               "no verificable por firma ({})".format(
                                   e.path or path_l))
                sev = max(sev, int(Severity.MEDIUM))
            elif no_verificable:
                razones.append("no se pudo verificar la firma ({}) de {}".format(
                    e.sig_status or "sin estado", e.path or path_l))
                sev = max(sev, int(Severity.MEDIUM))
            else:
                razones.append("arranca desde carpeta escribible sin firma de "
                               "confianza ({})".format(e.path or path_l))
                sev = max(sev, int(Severity.HIGH))
        # 3. RunOnce es de usar y tirar: un dropper clásico.
        if "RunOnce" in e.location and _en_escribible(path_l, writable_dirs):
            razones.append("RunOnce (se ejecuta una vez y se borra)")
            sev = max(sev, int(Severity.HIGH))

    # 4. Doble extensión: se disfraza de documento.
    if base and _EXT_DOBLE.search(base):
        razones.append("doble extensión que finge ser un documento")
        sev = max(sev, int(Severity.HIGH))

    # 5. Servicio cuyo binario no está donde deberían estar los servicios.
    if e.location == "Servicio" and _resuelto(path_l) and not confiable \
            and not no_verificable and firmable:
        win_l = norm_path(win_dir)
        if win_l and not path_l.startswith(win_l) and \
                "program files" not in path_l:
            razones.append("servicio con binario fuera de Windows y de "
                           "Program Files, sin firma de confianza")
            sev = max(sev, int(Severity.HIGH))

    # 6. No se pudo resolver el ejecutable: ni se afirma ni se calla.
    if not _resuelto(path_l) and e.command.strip():
        razones.append("no se pudo resolver el ejecutable de «{}»".format(
            e.command[:80]))
        sev = max(sev, int(Severity.LOW))

    return razones, sev


def classify_autoruns(
    entries: list[AutorunEntry],
    *,
    win_dir: str,
    writable_dirs: tuple[str, ...],
    allowed_paths: tuple[str, ...] = (),
) -> list[ThreatEvent]:
    """Clasifica entradas de arranque y devuelve los eventos. Pura."""
    events: list[ThreatEvent] = []
    for e in entries:
        razones, sev = classify_autorun(
            e, win_dir=win_dir, writable_dirs=writable_dirs,
            allowed_paths=allowed_paths)
        if not razones:
            continue
        events.append(ThreatEvent(
            kind="win_persistence", severity=Severity(sev),
            message=("Arranque sospechoso en {}: '{}' — {}".format(
                e.location, e.name, "; ".join(razones))),
            tags={"persistence", "host", "windows", "autorun"},
            enrichment={"name": e.name, "location": e.location,
                        "command": e.command, "path": e.path,
                        "signer": e.signer, "sig_valid": e.sig_valid,
                        "sig_status": e.sig_status,
                        "user": e.user, "reasons": razones}))
    return events


# --------------------------------------------------------------------------
# I/O: leer el registro, Startup, servicios y tareas. SOLO LECTURA.
# --------------------------------------------------------------------------

_PS_AUTORUNS = r"""
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$out=@()
$claves=@(
  @{p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';     l='HKLM\Run'},
  @{p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; l='HKLM\RunOnce'},
  @{p='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';     l='HKCU\Run'},
  @{p='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; l='HKCU\RunOnce'}
)
foreach($k in $claves){
  $item=Get-Item -LiteralPath $k.p
  if($item){
    foreach($n in $item.GetValueNames()){
      if($n){ $out+=[PSCustomObject]@{location=$k.l;name=$n;command=[string]$item.GetValue($n);user=''} }
    }
  }
}
$carpetas=@(
  @{p=[Environment]::GetFolderPath('Startup');l='Startup'},
  @{p=[Environment]::GetFolderPath('CommonStartup');l='Startup (comun)'}
)
foreach($c in $carpetas){
  if($c.p -and (Test-Path $c.p)){
    foreach($f in Get-ChildItem -LiteralPath $c.p -File){
      $out+=[PSCustomObject]@{location=$c.l;name=$f.Name;command=$f.FullName;user=''}
    }
  }
}
foreach($s in Get-CimInstance Win32_Service){
  if($s.PathName){
    $out+=[PSCustomObject]@{location='Servicio';name=$s.Name;command=$s.PathName;user=[string]$s.StartName}
  }
}
foreach($t in Get-ScheduledTask){
  foreach($a in $t.Actions){
    $ex=$a.Execute
    if($ex){
      $arg=[string]$a.Arguments
      $out+=[PSCustomObject]@{location='Tarea programada';name=$t.TaskName;command=($ex+' '+$arg).Trim();user=[string]$t.Principal.UserId}
    }
  }
}
$out|ConvertTo-Json -Compress -Depth 3
"""


def _normaliza_ubicacion(raw: str) -> str:
    """PowerShell no lleva acentos en el script: los reponemos aquí."""
    return "Startup (común)" if raw == "Startup (comun)" else raw


def enumerate_autoruns(timeout: float = 120.0) -> list[AutorunEntry]:
    """Lee todos los vectores de arranque. Solo lectura. I/O."""
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             _PS_AUTORUNS],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
            creationflags=NO_WINDOW)
        data = json.loads((res.stdout or "").strip() or "[]")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []
    if isinstance(data, dict):
        data = [data]
    entries: list[AutorunEntry] = []
    for row in data:
        if not isinstance(row, dict):
            continue
        command = str(row.get("command") or "")
        if not command.strip():
            continue
        entries.append(AutorunEntry(
            location=_normaliza_ubicacion(str(row.get("location") or "")),
            name=str(row.get("name") or ""), command=command,
            path=parse_command(command), user=str(row.get("user") or "")))
    return entries


def attach_signatures(entries: list[AutorunEntry],
                      timeout: float = 120.0) -> list[AutorunEntry]:
    """Añade la firma Authenticode del ejecutable de cada entrada.

    Reutiliza `hashwatch.signatures_for`: un solo PowerShell para todas las
    rutas en vez de uno por entrada.
    """
    from .hashwatch import signatures_detail
    rutas = sorted({e.path for e in entries if e.path})
    if not rutas:
        return list(entries)
    firmas = signatures_detail(rutas, timeout=timeout)
    out = []
    for e in entries:
        signer, valid, status = firmas.get(norm_path(e.path), ("", False, ""))
        out.append(AutorunEntry(
            location=e.location, name=e.name, command=e.command, path=e.path,
            signer=signer, sig_valid=valid, user=e.user, sig_status=status))
    return out


def scan(entries: list[AutorunEntry] | None = None, *, win_dir: str,
         writable_dirs: tuple[str, ...], allowed_paths: tuple[str, ...] = (),
         with_signatures: bool = True) -> list[ThreatEvent]:
    """Escaneo completo de persistencia de Windows."""
    if entries is None:
        entries = enumerate_autoruns()
    if with_signatures and os.name == "nt":
        entries = attach_signatures(entries)
    return classify_autoruns(entries, win_dir=win_dir,
                             writable_dirs=writable_dirs,
                             allowed_paths=allowed_paths)
