"""Firmas de explotación: detecta rastros de frameworks de ataque en los logs.

Un exploit (Metasploit, escáneres, kits de RCE) deja huellas características en
los logs de sshd ANTES o DURANTE la fase de autenticación: banners de cliente de
herramientas ofensivas, protocolos malformados (un GET de HTTP contra el puerto
22), negociaciones de algoritmos imposibles, o el patrón de la vulnerabilidad
concreta que se está explotando.

Estas firmas se anclan al MESSAGE de sshd (sin el prefijo de syslog, que ya
separa journald). Cada una lleva, cuando aplica, el CVE asociado para dar
contexto accionable en la alerta.

IMPORTANTE: las firmas son señales de alta confianza pero NO sustituyen al
scoring por comportamiento; complementan las capas de correlación. Una firma no
dispara por sí sola un bloqueo: alimenta el score del actor como cualquier otro
evento (la respuesta activa decide por score + allowlist).

Fundamentado en CVEs explotados activamente (KEV de CISA, 2024-2026) que usan
SSH como vector inicial; ver docs/DEFENSA_IA.md y referencias en README.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from ..core import Severity, ThreatEvent

_IP = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)"
# Para extraer una IP de origen del mensaje cuando la firma no la captura.
_FIND_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass(frozen=True)
class Signature:
    name: str
    pattern: re.Pattern
    severity: Severity
    cve: str | None = None
    tag: str = "exploit"
    note: str = ""


# Banners de cliente típicos de herramientas ofensivas / escáneres. sshd los
# refleja en "Bad protocol version identification 'X'" o "Connection from ...".
_OFFENSIVE_BANNERS = (
    "libssh", "paramiko", "Go", "zgrab", "masscan", "Nmap", "nmap",
    "Ruby", "Net::SSH", "python-", "WinSCP-release", "PUTTY",
)

SIGNATURES: tuple[Signature, ...] = (
    # Probe no-SSH contra el puerto SSH (escaneo/explotación): sshd registra el
    # banner crudo. Un verbo HTTP es señal clara de escáner web apuntando al 22.
    Signature(
        "http_probe_on_ssh",
        re.compile(r"Bad protocol version identification '(?:GET|POST|HEAD|"
                   r"OPTIONS|CONNECT|\\x16\\x03)"),
        Severity.HIGH, tag="exploit", note="Probe HTTP/TLS contra puerto SSH"),
    # Cualquier 'Bad protocol version identification' es un cliente no-SSH:
    # escáner o intento de explotación de pila de protocolo.
    Signature(
        "non_ssh_protocol",
        re.compile(r"Bad protocol version identification"),
        Severity.MEDIUM, tag="recon", note="Cliente no-SSH (escáner/sonda)"),
    # regreSSHion (CVE-2024-6387): la explotación de la condición de carrera en
    # sshd produce ráfagas de 'Timeout before authentication'.
    Signature(
        "regresshion_timeout",
        re.compile(rf"Timeout before authentication for {_IP}"),
        Severity.HIGH, cve="CVE-2024-6387", tag="exploit",
        note="Patrón de regreSSHion (race de preauth)"),
    # libssh auth bypass (CVE-2018-10933): clientes basados en libssh.
    Signature(
        "libssh_client",
        re.compile(r"Connection (?:from|closed by).*libssh"),
        Severity.HIGH, cve="CVE-2018-10933", tag="exploit",
        note="Cliente libssh (posible bypass de autenticación)"),
    # Negociación imposible: clientes viejos/escáneres que fuerzan algoritmos.
    Signature(
        "no_kex_match",
        re.compile(r"Unable to negotiate with .* no matching "
                   r"(?:key exchange method|cipher|host key type)"),
        Severity.LOW, tag="recon", note="Negociación fallida (escáner/cliente raro)"),
    # Reset durante el intercambio de identificación: típico de escaneo masivo
    # y de kits que cierran tras fingerprintear.
    Signature(
        "kex_identification_reset",
        re.compile(r"kex_exchange_identification: (?:Connection closed|"
                   r"banner exchange|client sent invalid)"),
        Severity.LOW, tag="recon", note="Corte en banner exchange (escaneo masivo)"),
    # Tooling de fuerza bruta que agota los intentos por conexión.
    Signature(
        "max_auth_exceeded",
        re.compile(r"error: maximum authentication attempts exceeded"),
        Severity.MEDIUM, tag="exploit", note="Herramienta de fuerza bruta"),
    # Usuario root explícito vía clave/preauth sospechoso tras múltiples kex.
    Signature(
        "user_enum_disconnect",
        re.compile(r"Disconnecting (?:invalid|authenticating) user "
                   r"\S+ .*: Too many authentication failures"),
        Severity.MEDIUM, tag="exploit", note="Enumeración/fuerza bruta agresiva"),
)


def scan(message: str) -> Signature | None:
    """Devuelve la primera firma que coincide con el MESSAGE, o None."""
    if not message:
        return None
    for sig in SIGNATURES:
        if sig.pattern.search(message):
            # Refina banners ofensivos dentro de 'Bad protocol version'.
            if sig.name == "non_ssh_protocol" and any(
                    b in message for b in _OFFENSIVE_BANNERS):
                return Signature(
                    "offensive_tool_banner", sig.pattern, Severity.HIGH,
                    tag="exploit", note="Banner de herramienta ofensiva/escáner")
            return sig
    return None


def _extract_ip(message: str) -> str | None:
    for m in _FIND_IP.findall(message):
        try:
            return str(ipaddress.ip_address(m))
        except ValueError:
            continue
    return None


def build_event(message: str, raw: str | None = None) -> ThreatEvent | None:
    """Si el MESSAGE coincide con una firma de explotación, construye el evento.

    Pensado como fallback en los colectores cuando la línea no es un intento de
    login normal. Solo emite si logra extraer una IP de origen (evita eventos
    sin atribución).
    """
    sig = scan(message)
    if sig is None:
        return None
    ip = _extract_ip(message)
    if ip is None:
        return None
    enrich = {"signature": sig.name, "note": sig.note}
    if sig.cve:
        enrich["cve"] = sig.cve
    tags = {"exploit-sig", sig.tag}
    if sig.cve:
        tags.add(sig.cve)
    return ThreatEvent(
        kind="exploit_attempt", src_ip=ip, severity=sig.severity,
        message=(f"Firma '{sig.name}'" + (f" [{sig.cve}]" if sig.cve else "")
                 + (f": {sig.note}" if sig.note else "")),
        tags=tags, enrichment=enrich, raw=(raw or message).strip()[:4096])
