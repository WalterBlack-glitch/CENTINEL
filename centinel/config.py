"""Configuración de CENTINEL en un `centinel.toml` opcional.

Hasta ahora los ajustes vivían en variables de entorno (`CENTINEL_PROCWATCH_ALLOW`)
y en constantes. Esto les da un sitio donde el usuario pueda verlos y editarlos
sin tocar código, sin añadir dependencias: `tomllib` viene en la biblioteca
estándar desde 3.11.

Principio: **la configuración nunca tumba el programa.** Un fichero ausente,
mal escrito o con un valor imposible produce valores por defecto más una lista
de avisos en `Config.errors` que el llamador puede mostrar. Un IDS que no
arranca porque sobra una coma en su TOML es un IDS que no te está protegiendo.

Orden de búsqueda (el primero que exista gana):
  1. la ruta que pida el llamador / `CENTINEL_CONFIG`
  2. `./centinel.toml` (junto a donde se ejecuta)
  3. `%APPDATA%\\CENTINEL\\centinel.toml` (Windows) o
     `$XDG_CONFIG_HOME/centinel/centinel.toml` (resto)

Las rutas de `allow_paths` se suman a `CENTINEL_PROCWATCH_ALLOW`: el entorno no
se pierde al estrenar fichero de configuración.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, fields

try:
    import tomllib
except ModuleNotFoundError:        # Python 3.10: sin TOML en la estándar
    tomllib = None                 # type: ignore[assignment]

from .core import Severity

NOMBRE = "centinel.toml"

_SEVERIDADES = {s.name: int(s) for s in Severity}


@dataclass
class Config:
    """Ajustes efectivos. Todo campo tiene un valor por defecto sensato."""

    # --- detección
    min_severity: int = int(Severity.LOW)   # por debajo de esto no se muestra
    allow_paths: tuple[str, ...] = ()       # rutas eximidas de 'carpeta escribible'
    watch_injection: bool = True            # inyección de DLL (injectwatch)
    watch_hashes: bool = False              # integridad en disco (hashwatch)
    watch_persistence: bool = True          # vectores de arranque (winpersist)

    # --- historial e informes
    history_keep: int = 200                 # retratos a conservar (0 = sin tope)
    history_dir: str = ""                   # "" = ruta por defecto del sistema
    report_format: str = "html"             # html | json | csv
    report_dir: str = "."

    # --- comportamiento
    auto_scan_seconds: int = 0              # 0 = solo escaneo manual

    # --- IA (explicador local opcional; ver centinel/ai/)
    explain_model: str = "llama3.2"         # modelo Ollama para --explain
    explain_url: str = "http://localhost:11434"  # Ollama local (solo loopback)
    explain_allow_remote: bool = False      # permitir URL no local (privacidad)

    # --- meta (no viene del fichero)
    path: str = ""                          # de dónde se cargó ("" = defaults)
    errors: list[str] = field(default_factory=list)

    @property
    def min_severity_name(self) -> str:
        return Severity(self.min_severity).name

    def to_dict(self) -> dict:
        omitir = {"path", "errors"}
        out = {}
        for f in fields(self):
            if f.name in omitir:
                continue
            v = getattr(self, f.name)
            out[f.name] = list(v) if isinstance(v, tuple) else v
        return out


# ------------------------------------------------------------- localización
def candidate_paths(explicit: str | None = None) -> list[str]:
    """Rutas donde buscar el fichero, en orden de preferencia."""
    out: list[str] = []
    if explicit:
        out.append(explicit)
    env = os.environ.get("CENTINEL_CONFIG")
    if env:
        out.append(env)
    out.append(os.path.join(os.getcwd(), NOMBRE))
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.environ.get("LOCALAPPDATA")
        if base:
            out.append(os.path.join(base, "CENTINEL", NOMBRE))
    else:
        base = (os.environ.get("XDG_CONFIG_HOME")
                or os.path.join(os.path.expanduser("~"), ".config"))
        out.append(os.path.join(base, "centinel", NOMBRE))
    return out


def find_config(explicit: str | None = None) -> str | None:
    for p in candidate_paths(explicit):
        if p and os.path.isfile(p):
            return p
    return None


# ------------------------------------------------------------- parseo puro
def _as_bool(valor, nombre, errors, actual):
    if isinstance(valor, bool):
        return valor
    errors.append(f"{nombre}: se esperaba true/false, no {valor!r}")
    return actual


def _as_int(valor, nombre, errors, actual, *, minimo=0):
    if isinstance(valor, bool) or not isinstance(valor, int):
        errors.append(f"{nombre}: se esperaba un entero, no {valor!r}")
        return actual
    if valor < minimo:
        errors.append(f"{nombre}: {valor} es menor que {minimo}")
        return actual
    return valor


def _as_str(valor, nombre, errors, actual):
    if not isinstance(valor, str):
        errors.append(f"{nombre}: se esperaba texto, no {valor!r}")
        return actual
    return valor


def _as_severity(valor, nombre, errors, actual):
    """Acepta "HIGH" o 3. Nunca deja el umbral en un valor imposible."""
    if isinstance(valor, bool):
        errors.append(f"{nombre}: se esperaba severidad, no {valor!r}")
        return actual
    if isinstance(valor, int):
        if valor in _SEVERIDADES.values():
            return valor
        errors.append(f"{nombre}: {valor} fuera de rango (0..4)")
        return actual
    if isinstance(valor, str):
        v = _SEVERIDADES.get(valor.strip().upper())
        if v is not None:
            return v
        errors.append("{}: '{}' no es una severidad ({})".format(
            nombre, valor, "/".join(_SEVERIDADES)))
        return actual
    errors.append(f"{nombre}: se esperaba severidad, no {valor!r}")
    return actual


def _as_paths(valor, nombre, errors, actual):
    if isinstance(valor, str):
        valor = [valor]
    if not isinstance(valor, list):
        errors.append(f"{nombre}: se esperaba una lista de rutas, no {valor!r}")
        return actual
    out = []
    for p in valor:
        if isinstance(p, str) and p.strip():
            out.append(_norm(p))
        else:
            errors.append(f"{nombre}: ruta ignorada, no es texto: {p!r}")
    return tuple(out)


def _norm(path: str) -> str:
    """Normaliza como lo hace procwatch, para que comparen igual."""
    p = os.path.expanduser(os.path.expandvars(path.strip()))
    if p.startswith("\\\\?\\"):
        p = p[4:]
    return p.replace("/", "\\").lower() if os.name == "nt" else p


def env_allow_paths() -> tuple[str, ...]:
    """`CENTINEL_PROCWATCH_ALLOW`, que sigue siendo válida."""
    raw = os.environ.get("CENTINEL_PROCWATCH_ALLOW", "")
    return tuple(_norm(p) for p in raw.split(os.pathsep) if p.strip())


_SECCIONES = {
    "deteccion": {
        "min_severity": ("min_severity", _as_severity),
        "allow_paths": ("allow_paths", _as_paths),
        "watch_injection": ("watch_injection", _as_bool),
        "watch_hashes": ("watch_hashes", _as_bool),
        "watch_persistence": ("watch_persistence", _as_bool),
    },
    "historial": {
        "keep": ("history_keep", _as_int),
        "dir": ("history_dir", _as_str),
    },
    "informe": {
        "formato": ("report_format", _as_str),
        "dir": ("report_dir", _as_str),
    },
    "escaneo": {
        "auto_seconds": ("auto_scan_seconds", _as_int),
    },
    "ia": {
        "modelo": ("explain_model", _as_str),
        "url": ("explain_url", _as_str),
        "allow_remote": ("explain_allow_remote", _as_bool),
    },
}


def from_mapping(data: dict, *, path: str = "") -> Config:
    """Construye un Config desde un dict ya parseado. Puro."""
    cfg = Config(path=path)
    errors = cfg.errors
    if not isinstance(data, dict):
        errors.append("el contenido no es una tabla TOML")
        return cfg
    for seccion, campos in _SECCIONES.items():
        bloque = data.get(seccion)
        if bloque is None:
            continue
        if not isinstance(bloque, dict):
            errors.append(f"[{seccion}]: se esperaba una sección")
            continue
        for clave, valor in bloque.items():
            par = campos.get(clave)
            if par is None:
                errors.append(f"[{seccion}] {clave}: opción desconocida")
                continue
            attr, conv = par
            setattr(cfg, attr, conv(valor, f"[{seccion}] {clave}", errors,
                                    getattr(cfg, attr)))
    for clave in data:
        if clave not in _SECCIONES and isinstance(data[clave], dict):
            errors.append(f"[{clave}]: sección desconocida")

    # Validaciones cruzadas: dejar el valor usable, nunca a medias.
    from .storage.export import FORMATOS
    if cfg.report_format.lower() not in FORMATOS:
        errors.append("[informe] formato: '{}' no es válido ({})".format(
            cfg.report_format, "/".join(FORMATOS)))
        cfg.report_format = "html"
    else:
        cfg.report_format = cfg.report_format.lower()

    # El entorno no se pierde: se suma, sin duplicar.
    extra = tuple(p for p in env_allow_paths() if p not in cfg.allow_paths)
    cfg.allow_paths = cfg.allow_paths + extra
    return cfg


def load_config(path: str | None = None) -> Config:
    """Carga la configuración efectiva. Nunca lanza: los problemas van en `errors`."""
    encontrado = find_config(path)
    if encontrado is None:
        cfg = Config()
        if path:
            cfg.errors.append(f"no existe el fichero de configuración: {path}")
        cfg.allow_paths = env_allow_paths()
        return cfg
    if tomllib is None:
        cfg = Config()
        cfg.errors.append(
            "se encontró {} pero esta versión de Python ({}) no trae tomllib; "
            "hace falta 3.11+ para leer la configuración".format(
                encontrado, ".".join(__import__("sys").version.split(".")[:2])))
        cfg.allow_paths = env_allow_paths()
        return cfg
    try:
        with open(encontrado, "rb") as f:
            data = tomllib.load(f)
    except OSError as exc:
        cfg = Config()
        cfg.errors.append(f"no se pudo leer {encontrado}: {exc}")
        cfg.allow_paths = env_allow_paths()
        return cfg
    except tomllib.TOMLDecodeError as exc:
        cfg = Config()
        cfg.errors.append(f"{encontrado} no es TOML válido: {exc}")
        cfg.allow_paths = env_allow_paths()
        return cfg
    return from_mapping(data, path=encontrado)


EJEMPLO = """\
# centinel.toml — todos los valores son opcionales; lo que falte usa su defecto.

[deteccion]
# Severidad mínima que se muestra: INFO, LOW, MEDIUM, HIGH, CRITICAL
min_severity = "LOW"
# Rutas eximidas de la regla de "carpeta escribible" (se suman a
# CENTINEL_PROCWATCH_ALLOW). No eximen de la suplantación de nombre.
allow_paths = []
watch_injection = true     # inyección de DLL / side-loading
watch_hashes = false       # integridad en disco de binarios del sistema
watch_persistence = true   # Run/RunOnce, Startup, servicios y tareas programadas

[historial]
keep = 200                 # retratos de escaneo a conservar (0 = sin tope)
dir = ""                   # "" = ruta por defecto del sistema

[informe]
formato = "html"           # html | json | csv
dir = "."

[escaneo]
auto_seconds = 0           # 0 = solo cuando pulsas Reescanear

[ia]
# Explicador de alertas con un LLM local (Ollama). OPCIONAL y apagado hasta
# que uses --explain. Todo offline: nunca sale de tu máquina.
modelo = "llama3.2"                  # modelo Ollama a usar
url = "http://localhost:11434"       # Ollama local (por privacidad, solo loopback)
allow_remote = false                 # true = permitir una URL no local (bajo tu riesgo)
"""


def write_example(path: str) -> str:
    """Deja un `centinel.toml` comentado para que el usuario lo edite."""
    carpeta = os.path.dirname(os.path.abspath(path))
    if carpeta:
        os.makedirs(carpeta, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(EJEMPLO)
    return path
