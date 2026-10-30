"""Modelo del menú y lógica *consciente del contexto* (pura y testeable).

Define las secciones/ítems exactos de la pantalla de PARANOID y, dado un
`Ctx` (foto ligera del estado), decide qué ítems están disponibles y por qué.
La TUI solo renderiza esto: aquí no hay I/O.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MenuItem:
    id: str          # "scan_quick"
    label: str       # "scan quick"
    help: str        # descripción de la fila


@dataclass(frozen=True)
class Section:
    title: str
    items: tuple[MenuItem, ...]


@dataclass(frozen=True)
class Ctx:
    """Foto del estado que gobierna la disponibilidad de cada ítem."""
    has_target: bool = False
    is_root: bool = False
    active_session: bool = False
    sessions_exist: bool = False
    has_findings: bool = False
    has_capture: bool = False
    iface_set: bool = False
    ffuf_ready: bool = False        # ffuf instalado
    dir_wordlist: bool = False
    sub_wordlist: bool = False
    tcpdump_ready: bool = False


# Menú declarativo — refleja 1:1 la pantalla.
MENU: tuple[Section, ...] = (
    Section("SCAN", (
        MenuItem("scan_quick",     "scan quick",     "Puertos comunes (21,22,80,443)"),
        MenuItem("scan_full",      "scan full",      "Barrido completo de 65535 puertos"),
        MenuItem("scan_service",   "scan service",   "Versión + scripts (-sV -sC)"),
        MenuItem("scan_stealth",   "scan stealth",   "SYN scan sigiloso (-sS -T2) · requiere root"),
        MenuItem("scan_dir",       "scan dir",       "Fuzzing de directorios (ffuf · wordlist del)"),
        MenuItem("scan_subdomain", "scan subdomain", "Fuzzing de subdominios (ffuf · wordlist del)"),
    )),
    Section("OBJETIVO", (
        MenuItem("set_target", "set target", "Fijar o cambiar el target (IP / CIDR / hostname)"),
    )),
    Section("TELEMETRÍA", (
        MenuItem("set_interface",   "set interface",   "Interfaz del sniffer pasivo (eth0/tun0/…)"),
        MenuItem("telemetry_panel", "telemetry panel", "Ver telemetría de la última captura"),
    )),
    Section("SESIONES", (
        MenuItem("session_new",   "session new",   "Crear y activar una sesión"),
        MenuItem("session_use",   "session use",   "Activar una sesión existente"),
        MenuItem("session_close", "session close", "Cerrar la sesión (vuelve a global)"),
        MenuItem("session_list",  "session list",  "Listar sesiones"),
        MenuItem("session_info",  "session info",  "Detalle de la sesión activa"),
    )),
    Section("REPORTE", (
        MenuItem("view",   "view",   "Ver el recon (findings raw+parseado)"),
        MenuItem("export", "export", "Exportar la sesión activa a tu PWD (txt+md)"),
    )),
    Section("SISTEMA", (
        MenuItem("theme",   "theme",   "Elegir tema de color (en vivo, se recuerda)"),
        MenuItem("config",  "config",  "Configuración y estado actual"),
        MenuItem("logs",    "logs",    "Registro de acciones de esta corrida"),
        MenuItem("history", "history", "Historial persistente de la sesión"),
        MenuItem("verify",  "verify",  "Verificar integridad / preflight de herramientas"),
        MenuItem("quit",    "quit",    "Salir de PARANOID"),
    )),
)


def all_items() -> list[MenuItem]:
    return [it for sec in MENU for it in sec.items]


def item_by_id(item_id: str) -> MenuItem | None:
    for it in all_items():
        if it.id == item_id:
            return it
    return None


def availability(item_id: str, ctx: Ctx) -> tuple[bool, str]:
    """¿Está disponible el ítem? Devuelve (ok, motivo_si_no). Pura.

    El motivo se muestra atenuado junto a la fila deshabilitada, para que el
    usuario sepa QUÉ le falta (fija un target, abre sesión, instala ffuf…).
    """
    needs_target = {"scan_quick", "scan_full", "scan_service", "scan_stealth",
                    "scan_dir", "scan_subdomain"}
    if item_id in needs_target and not ctx.has_target:
        return False, "fija un target primero (set target)"
    if item_id == "scan_stealth" and not ctx.is_root:
        return False, "requiere root"
    if item_id in ("scan_dir", "scan_subdomain"):
        if not ctx.ffuf_ready:
            return False, "ffuf no instalado"
        if item_id == "scan_dir" and not ctx.dir_wordlist:
            return False, "sin wordlist de dirs (config)"
        if item_id == "scan_subdomain" and not ctx.sub_wordlist:
            return False, "sin wordlist de subs (config)"
    if item_id == "telemetry_panel" and not ctx.has_capture:
        return False, "aún no hay captura (usa el sniffer)"
    if item_id in ("session_use", "session_list") and not ctx.sessions_exist:
        return False, "no hay sesiones guardadas"
    if item_id in ("session_close", "session_info") and not ctx.active_session:
        return False, "no hay sesión activa"
    if item_id in ("view", "export") and not ctx.has_findings:
        return False, "sin hallazgos que reportar"
    return True, ""
