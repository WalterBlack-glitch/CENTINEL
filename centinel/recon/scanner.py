"""Construcción de comandos (pura) y ejecución (I/O) de nmap y ffuf.

`build_*` son puras y testeables: entra el objetivo y el modo, sale la lista de
argumentos exacta. `run_*` las ejecutan por subprocess y parsean el resultado a
`ScanResult`. Si el binario no está, devuelven un `ScanResult` con `error` en
vez de reventar.
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path

from . import parse
from .model import ScanResult
from .tools import have

# Suprime la ventana de consola que Windows abre por cada subprocess lanzado
# desde una app con GUI. En POSIX el atributo no existe y cae a 0.
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# nmap: modo -> flags (sin objetivo ni fichero de salida, que se añaden aparte).
NMAP_MODES: dict[str, list[str]] = {
    "quick":   ["-T4", "-Pn", "-p", "21,22,80,443"],
    "full":    ["-T4", "-Pn", "-p-"],
    "service": ["-Pn", "-sV", "-sC"],
    "stealth": ["-sS", "-T2", "-Pn"],       # requiere root
}
# Modos que exigen privilegios (SYN scan crudo).
NMAP_NEEDS_ROOT = frozenset({"stealth"})


def build_nmap_cmd(mode: str, target: str, *, outfile: str | None = None,
                   xmlfile: str | None = None, binary: str = "nmap") -> list[str]:
    """Devuelve la lista de argumentos de nmap para `mode`+`target`. Pura.

    `outfile` (-oN) es el texto legible para el humano; `xmlfile` (-oX) es el
    formato estable que luego parseamos. `xmlfile="-"` manda el XML a stdout.
    """
    if mode not in NMAP_MODES:
        raise ValueError(f"modo nmap desconocido: {mode!r}")
    if not target:
        raise ValueError("objetivo vacío")
    cmd = [binary, *NMAP_MODES[mode]]
    if outfile:
        cmd += ["-oN", outfile]
    if xmlfile:
        cmd += ["-oX", xmlfile]
    cmd.append(target)
    return cmd


def build_ffuf_cmd(mode: str, target: str, wordlist: str, *,
                   outfile: str | None = None, binary: str = "ffuf") -> list[str]:
    """Devuelve los argumentos de ffuf para fuzzing de `dir`/`subdomain`. Pura.

    `target` debe ser un host/URL sin esquema o con http(s). Para directorios
    se fuzzea la ruta; para subdominios se fuzzea la cabecera Host.
    """
    if mode not in ("dir", "subdomain"):
        raise ValueError(f"modo ffuf desconocido: {mode!r}")
    if not target:
        raise ValueError("objetivo vacío")
    if not wordlist:
        raise ValueError("wordlist vacía")
    host = target.split("://", 1)[-1].strip("/")
    base = target if "://" in target else f"http://{host}"
    cmd = [binary, "-w", wordlist, "-mc", "200,204,301,302,307,401,403",
           "-of", "json"]
    if mode == "dir":
        cmd += ["-u", f"{base}/FUZZ"]
    else:  # subdomain
        cmd += ["-u", base, "-H", f"Host: FUZZ.{host}"]
    if outfile:
        cmd += ["-o", outfile]
    return cmd


# --------------------------------------------------------------------------
# Ejecución (I/O)
# --------------------------------------------------------------------------

def run_nmap(mode: str, target: str, *, out_dir: Path | None = None,
             is_root: bool = False, timeout: float = 900.0) -> ScanResult:
    res = ScanResult(tool="nmap", kind=mode, target=target, ts=time.time())
    if not have("nmap"):
        res.error = "nmap no está instalado (instálalo o usa 'verify')"
        return res
    if mode in NMAP_NEEDS_ROOT and not is_root:
        res.error = "el scan sigiloso (-sS) requiere privilegios de root"
        return res
    if out_dir:
        outfile = str(out_dir / f"nmap_{mode}.txt")
        xmlfile = str(out_dir / f"nmap_{mode}.xml")
    else:
        outfile, xmlfile = None, "-"   # sin carpeta de sesión: XML por stdout
    res.command = build_nmap_cmd(mode, target, outfile=outfile, xmlfile=xmlfile)
    try:
        p = subprocess.run(res.command, capture_output=True, text=True,
                           timeout=timeout, creationflags=NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired) as e:
        res.error = f"fallo al ejecutar nmap: {e}"
        return res
    res.raw = p.stdout or ""
    res.returncode = p.returncode
    # Preferimos el XML (estable entre versiones); si falta o no parsea, caemos
    # al texto normal, que siempre está en stdout o en el .txt.
    xml_text = ""
    if xmlfile == "-":
        xml_text = res.raw
    elif Path(xmlfile).is_file():
        xml_text = Path(xmlfile).read_text(encoding="utf-8", errors="replace")
    res.findings = parse.parse_nmap_xml(xml_text) or parse.parse_nmap(res.raw)
    return res


def run_ffuf(mode: str, target: str, wordlist: str, *,
             out_dir: Path | None = None, timeout: float = 600.0) -> ScanResult:
    res = ScanResult(tool="ffuf", kind=mode, target=target, ts=time.time())
    if not have("ffuf"):
        res.error = "ffuf no está instalado (instálalo o usa 'verify')"
        return res
    if not wordlist or not Path(wordlist).is_file():
        res.error = f"wordlist no encontrada: {wordlist!r}"
        return res
    outfile = str(out_dir / f"ffuf_{mode}.json") if out_dir else None
    res.command = build_ffuf_cmd(mode, target, wordlist, outfile=outfile)
    try:
        p = subprocess.run(res.command, capture_output=True, text=True,
                           timeout=timeout, creationflags=NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired) as e:
        res.error = f"fallo al ejecutar ffuf: {e}"
        return res
    res.returncode = p.returncode
    json_text = ""
    if outfile and Path(outfile).is_file():
        json_text = Path(outfile).read_text(encoding="utf-8", errors="replace")
    res.raw = json_text or (p.stdout or "")
    res.findings = parse.parse_ffuf(res.raw, kind="subdomain"
                                    if mode == "subdomain" else "path")
    return res
