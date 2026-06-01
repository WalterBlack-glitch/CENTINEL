"""Doctor: diagnostica (y arregla lo seguro) antes de arrancar.

Filosofía: que Centinela no falle con un traceback opaco. Antes de levantar las
capas, revisa las causas habituales de error según los flags pedidos, ARREGLA
automáticamente lo que es seguro (crear el directorio de la BD, ajustar permisos)
y para el resto imprime el COMANDO exacto de arreglo. Nunca instala paquetes ni
ejecuta acciones de red: solo inspecciona y recomienda.

`run(args)` devuelve la lista de hallazgos e imprime un informe. No aborta el
arranque salvo en errores irrecuperables (que el llamador decide).
"""
from __future__ import annotations

import os
import socket
import sys

OK, WARN, ERR, FIX = "ok", "warn", "error", "fixed"
_ICON = {OK: "[ok]", WARN: "[!]", ERR: "[X]", FIX: "[fix]"}


def _has(mod: str) -> bool:
    import importlib.util
    return importlib.util.find_spec(mod) is not None


def _port_free(host: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((host if host != "0.0.0.0" else "", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def run(args) -> list[dict]:
    f: list[dict] = []

    def add(level, msg, fix=None):
        f.append({"level": level, "msg": msg, "fix": fix})

    # 1) Versión de Python
    if sys.version_info < (3, 10):
        add(ERR, f"Python {sys.version.split()[0]} es muy antiguo (se requiere 3.10+).",
            "Instala python3.10+ y recrea el venv: python3 -m venv .venv")
    else:
        add(OK, f"Python {sys.version.split()[0]}")

    # 2) Dependencias opcionales según los flags pedidos
    if getattr(args, "web", False):
        miss = [m for m in ("fastapi", "uvicorn") if not _has(m)]
        if miss:
            add(ERR, f"--web requiere paquetes ausentes: {', '.join(miss)}.",
                "pip install '.[web]'")
        else:
            add(OK, "Dependencias web (fastapi, uvicorn)")
    if getattr(args, "geo", None):
        if not _has("geoip2"):
            add(ERR, "--geo requiere el paquete 'geoip2', ausente.",
                "pip install '.[geo]'")
        elif not os.path.exists(args.geo):
            add(ERR, f"Base GeoLite2 no encontrada: {args.geo}",
                "Descarga GeoLite2-City.mmdb de MaxMind (gratis con cuenta).")
        else:
            add(OK, "Geolocalización (geoip2 + mmdb)")
    if getattr(args, "sniff", False) and not _has("scapy"):
        add(ERR, "--sniff requiere 'scapy', ausente.",
            "pip install scapy")

    # 3) Privilegios para capas que abren recursos privilegiados
    if not _is_root():
        if getattr(args, "sniff", False):
            add(WARN, "--sniff necesita root para abrir el socket de captura.",
                "Ejecuta con sudo, o concede capacidad: "
                "sudo setcap cap_net_raw+ep $(readlink -f $(which python3))")
        lowp = [p for p in (getattr(args, "honeypot", None) or "").split(",")
                if p.strip().isdigit() and int(p) < 1024]
        if lowp:
            add(WARN, f"El honeypot en puertos <1024 ({','.join(lowp)}) necesita root.",
                "Usa sudo, o un puerto alto (p.ej. 2222), o setcap cap_net_bind_service.")
    else:
        add(OK, "Ejecutando como root (se soltarán privilegios tras abrir recursos)")
        if not getattr(args, "no_drop", False):
            add(OK, f"Privilegios se soltarán a '{getattr(args,'user','nobody')}'")

    # 4) Directorio y permisos de la base de datos (ARREGLO automático seguro)
    db = getattr(args, "db", "centinela.db")
    d = os.path.dirname(os.path.abspath(db))
    if not os.path.isdir(d):
        try:
            os.makedirs(d, mode=0o700, exist_ok=True)
            add(FIX, f"Directorio de la BD creado: {d}")
        except OSError as e:
            add(ERR, f"No se puede crear el directorio de la BD ({d}): {e}",
                f"Crea el directorio a mano o usa --db con una ruta escribible.")
    elif not os.access(d, os.W_OK):
        add(ERR, f"Sin permiso de escritura en {d}.",
            f"Usa --db con una ruta escribible, p.ej. --db ~/centinela.db")
    else:
        add(OK, f"BD escribible: {db}")
    # endurece permisos de una BD ya existente (debe ser 0600)
    if os.path.exists(db):
        try:
            mode = os.stat(db).st_mode & 0o777
            if mode & 0o077:
                os.chmod(db, 0o600)
                add(FIX, f"Permisos de {db} endurecidos a 0600 (eran {oct(mode)}).")
        except OSError:
            pass

    # 5) Puertos libres
    if getattr(args, "web", False):
        host, port = getattr(args, "web_host", "127.0.0.1"), getattr(args, "web_port", 8787)
        if not _port_free(host, port):
            add(ERR, f"El puerto web {host}:{port} ya está en uso.",
                f"Cierra el proceso que lo ocupa o usa --web-port OTRO. "
                f"Ver quién lo usa: sudo ss -tlnp | grep {port}")
        else:
            add(OK, f"Puerto web {host}:{port} libre")

    # 6) KEV: aviso si se pide caché sin datos
    if getattr(args, "kev_cache", None) and not getattr(args, "kev_update", False):
        if not os.path.exists(args.kev_cache):
            add(WARN, "Caché KEV indicada pero inexistente; sin datos de CVEs.",
                "Añade --kev-update una vez para descargar el feed de CISA.")

    _print(f)
    return f


def _print(findings: list[dict]) -> None:
    errs = sum(1 for x in findings if x["level"] == ERR)
    warns = sum(1 for x in findings if x["level"] == WARN)
    print("[centinela] diagnóstico previo (doctor):")
    for x in findings:
        line = f"  {_ICON[x['level']]} {x['msg']}"
        print(line)
        if x.get("fix") and x["level"] in (ERR, WARN):
            print(f"        ↳ arreglo: {x['fix']}")
    if errs:
        print(f"[centinela] {errs} error(es) y {warns} aviso(s). "
              f"Revisa los arreglos sugeridos arriba.")
    elif warns:
        print(f"[centinela] {warns} aviso(s); se puede continuar.")
    else:
        print("[centinela] todo en orden.")


def has_blocking_errors(findings: list[dict]) -> bool:
    return any(x["level"] == ERR for x in findings)
