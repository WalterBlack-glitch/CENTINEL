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


def _free_port(host: str, start: int, tries: int = 50) -> int | None:
    """Busca el primer puerto libre desde `start` (auto-arreglo de colisión)."""
    for p in range(start, min(start + tries, 65536)):
        if _port_free(host, p):
            return p
    return None


def _writable_fallback_db(name: str = "centinela.db") -> str | None:
    """Devuelve una ruta de BD escribible (home -> XDG -> temp)."""
    import tempfile
    home = os.path.expanduser("~")
    candidates = [home,
                  os.path.join(home, ".local", "share", "centinela"),
                  tempfile.gettempdir()]
    for d in candidates:
        try:
            os.makedirs(d, mode=0o700, exist_ok=True)
            if os.access(d, os.W_OK):
                return os.path.join(d, name)
        except OSError:
            continue
    return None


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
    db_ok = False
    if not os.path.isdir(d):
        try:
            os.makedirs(d, mode=0o700, exist_ok=True)
            add(FIX, f"Directorio de la BD creado: {d}")
            db_ok = True
        except OSError:
            pass
    elif os.access(d, os.W_OK):
        add(OK, f"BD escribible: {db}")
        db_ok = True
    if not db_ok:
        # Auto-arreglo: reubica la BD a una ruta escribible y muta args.
        alt = _writable_fallback_db()
        if alt:
            args.db = alt
            db = alt
            add(FIX, f"Ruta de BD no escribible; reubicada automáticamente a {alt}")
        else:
            add(ERR, f"Sin ubicación escribible para la BD (probé home y temp).",
                "Usa --db con una ruta escribible, p.ej. --db ~/centinela.db")
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
        if _port_free(host, port):
            add(OK, f"Puerto web {host}:{port} libre")
        else:
            # Auto-arreglo: salta al siguiente puerto libre y muta args.
            alt = _free_port(host, port + 1)
            if alt:
                args.web_port = alt
                add(FIX, f"Puerto {port} ocupado; el web usará {alt} automáticamente.")
            else:
                add(ERR, f"Puerto web {host}:{port} en uso y sin alternativa libre.",
                    f"Cierra el proceso: sudo ss -tlnp | grep {port}")

    # 5b) Exposición del dashboard web (sin autenticación) fuera de loopback
    if getattr(args, "web", False):
        wh = getattr(args, "web_host", "127.0.0.1")
        if wh not in ("127.0.0.1", "::1", "localhost"):
            add(WARN, f"El dashboard web escuchará en {wh} (no loopback) y NO "
                      f"tiene autenticación: cualquiera en la red verá tus datos.",
                "Usa --web-host 127.0.0.1 y túnel SSH, o pon un proxy con auth "
                "delante. (El bloqueo /api/block ya está restringido a loopback.)")

    # 5c) Respuesta activa real vs soltado de privilegios.
    # La app ya retiene root automáticamente si detecta capas que lo necesitan
    # (respond-live / rootcheck / netwatch). El aviso es informativo.
    if getattr(args, "respond_live", False) and not getattr(args, "no_drop", False):
        add(OK, "--respond-live: root se retendrá automáticamente "
                "(drop omitido por capa que requiere privilegios sostenidos).")

    # 5d) NetWatch sin root: visibilidad parcial de procesos
    if getattr(args, "netwatch", False) and not _is_root():
        add(WARN, "--netwatch sin root solo ve TUS procesos; un backdoor de root "
                  "quedaría invisible.",
            "Para visión total ejecútalo con sudo o concede CAP_SYS_PTRACE.")

    # 5e) Rootcheck sin root: no puede leer cron de root ni todos los SUID
    if getattr(args, "rootcheck", False) and not _is_root():
        add(WARN, "--rootcheck sin root no lee el cron de root ni todos los SUID; "
                  "cobertura parcial de persistencia.",
            "Ejecútalo con sudo para revisar todo el sistema.")

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
