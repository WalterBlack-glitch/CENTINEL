"""hashwatch — integridad en disco de los binarios del sistema (Windows).

Compañero de Windows del baseline de integridad que `persistence.py` ya hace en
Linux. `procwatch` mira *qué se está ejecutando*; esto mira *qué hay en disco*:
si alguien reemplaza `C:\\Windows\\System32\\svchost.exe` por su propia copia,
el proceso resultante tendrá el nombre correcto, la ruta canónica correcta y el
padre correcto — las tres reglas de procwatch pasan — y solo el hash lo delata.

Cómo no convertirlo en un generador de falsos positivos: Windows Update cambia
binarios del sistema con toda legitimidad, varias veces al mes. Un «el hash
cambió» a secas sería ruido insoportable y el usuario aprendería a ignorarlo.
La regla que lo hace usable es combinar hash **y** firma:

  - cambió y sigue firmado por Microsoft con firma válida → LOW, "probable
    actualización" (informativo, no alarma);
  - cambió y la firma ya no es válida o no es de confianza → CRITICAL, que es
    exactamente la huella de un reemplazo en disco;
  - apareció en la carpeta vigilada sin firma de confianza → MEDIUM;
  - desapareció un binario que estaba en la línea base → MEDIUM (puede ser
    desinstalación legítima, pero también borrado de evidencia).

Patrón del repo: `classify_hashes` es puro y testeable sin Windows; el I/O
(leer ficheros, pedir firmas a PowerShell) vive abajo y separado.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass

from ..core import Severity, ThreatEvent
from .procwatch import NO_WINDOW, SYSTEM_PROCESS_NAMES, _is_trusted, norm_path

_CHUNK = 1 << 20          # 1 MiB por lectura: hashea binarios grandes sin cargarlos
_MAX_BYTES = 512 << 20    # tope de 512 MiB por fichero (evita colgarse en algo raro)


@dataclass(frozen=True)
class FileHash:
    """Un fichero vigilado, ya resuelto. Sin dependencia del SO."""
    path: str
    sha256: str
    size: int = 0
    signer: str = ""
    sig_valid: bool = False

    def to_dict(self) -> dict:
        return {"path": self.path, "sha256": self.sha256, "size": self.size,
                "signer": self.signer, "sig_valid": bool(self.sig_valid)}

    @classmethod
    def from_dict(cls, d: dict) -> "FileHash":
        return cls(path=str(d.get("path") or ""),
                   sha256=str(d.get("sha256") or ""),
                   size=int(d.get("size") or 0),
                   signer=str(d.get("signer") or ""),
                   sig_valid=bool(d.get("sig_valid")))


def make_baseline(files: list[FileHash]) -> dict[str, dict]:
    """Línea base serializable: ruta normalizada -> datos del fichero."""
    return {norm_path(f.path): f.to_dict() for f in files if f.path and f.sha256}


def _trusted(f: FileHash) -> bool:
    """¿Firma válida de un editor de confianza?"""
    return bool(f.sig_valid) and _is_trusted(f.signer)


def classify_hashes(
    current: list[FileHash],
    baseline: dict[str, dict] | None,
    *,
    report_new: bool = True,
    report_missing: bool = True,
) -> list[ThreatEvent]:
    """Compara el estado actual del disco con la línea base. Pura.

    `baseline` vacío o None = primera ejecución: no se inventan alertas, solo
    se devuelve lista vacía para que el llamador fije la línea base.
    """
    if not baseline:
        return []
    events: list[ThreatEvent] = []
    vistos: set[str] = set()

    for f in current:
        key = norm_path(f.path)
        if not key or not f.sha256:
            continue
        vistos.add(key)
        previo = baseline.get(key)
        if previo is None:
            if not report_new or _trusted(f):
                continue
            events.append(ThreatEvent(
                kind="file_integrity_new", severity=Severity.MEDIUM,
                message=(f"Binario nuevo sin firma de confianza en carpeta "
                         f"vigilada: {f.path}"),
                tags={"file", "host", "windows", "integrity"},
                enrichment={"path": f.path, "sha256": f.sha256,
                            "signer": f.signer, "sig_valid": f.sig_valid,
                            "reasons": ["no estaba en la línea base",
                                        "sin firma válida de confianza"]}))
            continue

        viejo_hash = str(previo.get("sha256") or "")
        if viejo_hash and viejo_hash != f.sha256:
            if _trusted(f):
                events.append(ThreatEvent(
                    kind="file_integrity_update", severity=Severity.LOW,
                    message=(f"{os.path.basename(f.path)} cambió en disco pero "
                             f"mantiene firma válida de {f.signer} — probable "
                             f"actualización del sistema"),
                    tags={"file", "host", "windows", "integrity"},
                    enrichment={"path": f.path, "sha256_old": viejo_hash,
                                "sha256_new": f.sha256, "signer": f.signer,
                                "sig_valid": f.sig_valid,
                                "reasons": ["hash distinto",
                                            "firma de confianza válida"]}))
            else:
                events.append(ThreatEvent(
                    kind="file_integrity_tamper", severity=Severity.CRITICAL,
                    message=(f"Binario del sistema REEMPLAZADO en disco: "
                             f"{f.path} (sha256 {viejo_hash[:12]}…→"
                             f"{f.sha256[:12]}…) sin firma válida de confianza"),
                    tags={"file", "host", "windows", "integrity"},
                    enrichment={"path": f.path, "sha256_old": viejo_hash,
                                "sha256_new": f.sha256, "signer": f.signer,
                                "sig_valid": f.sig_valid,
                                "reasons": ["hash distinto al de la línea base",
                                            "sin firma válida de confianza"]}))

    if report_missing:
        for key, previo in baseline.items():
            if key in vistos:
                continue
            events.append(ThreatEvent(
                kind="file_integrity_missing", severity=Severity.MEDIUM,
                message=("Binario de la línea base que ya no está en disco: "
                         f"{previo.get('path') or key}"),
                tags={"file", "host", "windows", "integrity"},
                enrichment={"path": previo.get("path") or key,
                            "sha256": previo.get("sha256", ""),
                            "reasons": ["estaba en la línea base",
                                        "ya no existe en disco"]}))
    return events


def update_baseline(baseline: dict[str, dict] | None,
                    current: list[FileHash]) -> dict[str, dict]:
    """Línea base nueva tras revisar los hallazgos: lo actual manda.

    Se llama DESPUÉS de clasificar, nunca antes, o un reemplazo malicioso
    entraría en la línea base como legítimo y no volvería a avisar.
    """
    out = dict(baseline or {})
    out.update(make_baseline(current))
    return out


# --------------------------------------------------------------------------
# I/O: leer ficheros y pedir firmas. No puro.
# --------------------------------------------------------------------------

def sha256_file(path: str, *, max_bytes: int = _MAX_BYTES) -> str | None:
    """SHA-256 de un fichero, por trozos. None si no se puede leer."""
    h = hashlib.sha256()
    leidos = 0
    try:
        with open(path, "rb") as f:
            while True:
                trozo = f.read(_CHUNK)
                if not trozo:
                    break
                leidos += len(trozo)
                if leidos > max_bytes:
                    return None
                h.update(trozo)
    except OSError:
        return None
    return h.hexdigest()


_PS_SIGN = r"""
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$out=@()
foreach($p in {RUTAS}){
  $s=Get-AuthenticodeSignature -LiteralPath $p
  $out+=[PSCustomObject]@{
    path=$p
    signer=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{''}
    valid=($s.Status -eq 'Valid')
    status=if($null -ne $s){[string]$s.Status}else{'UnknownError'}
  }
}
$out|ConvertTo-Json -Compress -Depth 3
"""


def _ps_literal(paths: list[str]) -> str:
    """Las rutas, como array literal de PowerShell entrecomillado simple.

    Hay que incrustarlas en el script: con `-Command` los argumentos que van
    después de `--` **no** llegan a `$args` (eso solo ocurre con `-File`), así
    que la versión que los pasaba por ahí recibía una lista vacía y no
    verificaba ninguna firma. En comillas simples PowerShell no interpola
    nada — ni `$`, ni backtick, ni `;` — y la única comilla simple que pueda
    traer una ruta se escapa duplicándola, que es como se escapa en PowerShell.
    """
    return "@(" + ",".join("'" + p.replace("'", "''") + "'"
                           for p in paths) + ")"


def signatures_detail(paths: list[str],
                      timeout: float = 120.0) -> dict[str, tuple[str, bool, str]]:
    """Firma de cada ruta: {ruta: (firmante, válida, estado)}.

    El `estado` crudo de `Get-AuthenticodeSignature` importa más de lo que
    parece: «NotSigned» (no está firmado) y «UnknownError» (no se ha podido
    comprobar, por ejemplo porque el fichero está protegido, como el motor de
    Defender) **no son lo mismo**, y tratarlos igual produce falsos positivos
    en binarios legítimos que el usuario no puede ni leer.

    Un solo proceso de PowerShell para todas las rutas: verificar firmas es
    caro y abrir un proceso por fichero multiplicaría el coste del escaneo.
    """
    if not paths:
        return {}
    script = _PS_SIGN.replace("{RUTAS}", _ps_literal(paths))
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            # Los subjects de certificado traen acentos y guiones tipograficos:
            # con la cp1252 por defecto, leer la salida lanza UnicodeDecodeError
            # en el hilo lector y el escaneo entero se queda sin datos.
            encoding="utf-8", errors="replace",
            creationflags=NO_WINDOW)
        data = json.loads((res.stdout or "").strip() or "[]")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return {}
    if isinstance(data, dict):
        data = [data]
    out: dict[str, tuple[str, bool, str]] = {}
    for row in data:
        if not isinstance(row, dict):
            continue
        p = str(row.get("path") or "")
        if p:
            out[norm_path(p)] = (str(row.get("signer") or ""),
                                 bool(row.get("valid")),
                                 str(row.get("status") or "UnknownError"))
    return out


def signatures_for(paths: list[str], timeout: float = 120.0) -> dict[str, tuple[str, bool]]:
    """Igual que `signatures_detail` pero solo (firmante, válida)."""
    return {k: (signer, valid)
            for k, (signer, valid, _st) in signatures_detail(paths, timeout).items()}


def default_watched_paths(win_dir: str | None = None) -> list[str]:
    """Los binarios del sistema que procwatch ya considera suplantables.

    Vigilar System32 entero serían miles de ficheros y minutos de hashing en
    cada escaneo; estos son los que de verdad usa el malware para esconderse.
    """
    win = win_dir or os.environ.get("WinDir", r"C:\Windows")
    sys32 = os.path.join(win, "System32")
    rutas = [os.path.join(sys32, n) for n in sorted(SYSTEM_PROCESS_NAMES)]
    rutas.append(os.path.join(win, "explorer.exe"))
    return rutas


def collect_file_hashes(paths: list[str], *, with_signatures: bool = True,
                        timeout: float = 120.0) -> list[FileHash]:
    """Hashea las rutas que existan y les añade la firma. I/O."""
    presentes: list[tuple[str, str, int]] = []
    for p in paths:
        h = sha256_file(p)
        if h is None:
            continue
        try:
            size = os.path.getsize(p)
        except OSError:
            size = 0
        presentes.append((p, h, size))
    firmas: dict[str, tuple[str, bool]] = {}
    if with_signatures and presentes and os.name == "nt":
        firmas = signatures_for([p for p, _, _ in presentes], timeout=timeout)
    out = []
    for p, h, size in presentes:
        signer, valid = firmas.get(norm_path(p), ("", False))
        out.append(FileHash(path=p, sha256=h, size=size, signer=signer,
                            sig_valid=valid))
    return out


def scan(baseline: dict[str, dict] | None, *, paths: list[str] | None = None,
         with_signatures: bool = True) -> tuple[list[ThreatEvent], dict[str, dict]]:
    """Escaneo completo: devuelve (eventos, línea base nueva).

    En la primera ejecución no hay alertas: se fija la línea base y se avisa
    de ello por la vía de siempre (el llamador mira si la base estaba vacía).
    """
    files = collect_file_hashes(paths or default_watched_paths(),
                               with_signatures=with_signatures)
    events = classify_hashes(files, baseline)
    return events, update_baseline(baseline, files)
