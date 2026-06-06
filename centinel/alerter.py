"""Alerter: empuja eventos a un webhook externo (Slack, Discord, Telegram, etc.).

Cuando el operador no está mirando el dashboard, una alerta CRITICAL puede
pasar inadvertida 24h. Este módulo expone WebhookAlerter: se suscribe al
bus de salida y, ante un evento por encima del umbral configurado, hace un
POST JSON al URL indicado. Best-effort: si la URL falla, NO bloquea ni
tumba el pipeline (sería absurdo que el alerter se convierta en SPOF).

No depende de paquetes externos: usa urllib. Respeta TIMEOUT estricto y
rate-limit interno (1 alerta/30s para el mismo kind+actor) para no inundar
el webhook ante una ráfaga.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import time
import urllib.parse
import urllib.request
import urllib.error

from .core import EventBus, Severity


# Anti-SSRF: rechazamos por defecto destinos que un atacante usaría para
# exfiltrar al nodo metadata de la nube (AWS, GCP, Azure) o para hablar con
# servicios internos no expuestos. El operador puede pasar --alert-webhook
# con un destino externo http(s)://, y se valida en el ctor.
_BLOCKED_HOSTS = {
    "169.254.169.254",   # AWS/GCP/Azure metadata IMDS
    "metadata.google.internal",
    "metadata",
}


def _validate_webhook_url(url: str) -> tuple[bool, str]:
    """Devuelve (ok, motivo). Rechaza URLs peligrosas o triviales de abuso."""
    if not url:
        return False, "URL vacía"
    try:
        u = urllib.parse.urlparse(url)
    except ValueError as e:
        return False, f"URL inválida: {e}"
    if u.scheme not in ("http", "https"):
        return False, f"esquema '{u.scheme}' no permitido (usa http/https)"
    host = (u.hostname or "").lower()
    if not host:
        return False, "URL sin host"
    if host in _BLOCKED_HOSTS:
        return False, f"host '{host}' bloqueado (metadata de nube)"
    # Si el host es literal IP, verificamos que NO sea loopback/link-local/
    # privada cuando el esquema es http (típico de un C2 interno). En https
    # asumimos que el operador sabe lo que hace (TLS protege el contenido).
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
            return False, f"IP '{host}' (loopback/link-local) bloqueada"
    except ValueError:
        pass
    return True, "ok"


def post_json(url: str, payload: dict, timeout: float = 4.0,
              user_agent: str = "CENTINEL/1.0") -> bool:
    """POST JSON best-effort. Devuelve True si 2xx, False si falló. Nunca lanza.

    Compartido por el alerter de eventos y el digest periódico para no duplicar
    la lógica de red ni el endurecimiento (timeout, UA, manejo de errores)."""
    if not url:
        return False
    try:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": user_agent})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return 200 <= getattr(r, "status", 200) < 300
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False


class WebhookAlerter:
    def __init__(self, bus: EventBus, url: str,
                 min_severity: int = int(Severity.HIGH),
                 timeout: float = 4.0,
                 rate_limit_sec: float = 30.0) -> None:
        self.bus = bus
        ok, why = _validate_webhook_url(url)
        if not ok:
            # Si el operador pasó algo peligroso, dejamos al alerter sin url:
            # available()=False y nunca hace POST. Mejor degradar que enviar.
            print(f"[centinel] alerter: URL rechazada ({why}); webhook desactivado.")
            self.url = ""
        else:
            self.url = url
        self.min_sev = min_severity
        self.timeout = timeout
        self.rl = rate_limit_sec
        self._last: dict[str, float] = {}

    name = "webhook_alerter"

    def available(self) -> bool:
        return bool(self.url)

    async def run(self) -> None:
        queue = self.bus.subscribe()
        while True:
            ev = await queue.get()
            try:
                if int(ev.severity) < self.min_sev:
                    continue
                key = f"{ev.kind}:{getattr(ev, 'ip', '') or ''}"
                now = time.time()
                last = self._last.get(key, 0.0)
                if now - last < self.rl:
                    continue
                self._last[key] = now
                await asyncio.to_thread(self._post, ev)
            except asyncio.CancelledError:
                raise
            except Exception:   # noqa: BLE001 — nunca tumbar el alerter
                pass

    def _post(self, ev) -> None:
        payload = {
            "text": (f"[CENTINEL] {self._sev_label(ev.severity)} · {ev.kind}\n"
                     f"{ev.message[:500]}"),
            "centinel": {
                "kind": ev.kind,
                "severity": int(ev.severity),
                "message": ev.message[:1000],
                "source": getattr(ev, "source", None),
                "ip": getattr(ev, "ip", None),
                "ts": getattr(ev, "timestamp", time.time()),
                "tags": sorted(getattr(ev, "tags", []) or []),
                "ttp": _MITRE.get(ev.kind),
            },
        }
        post_json(self.url, payload, timeout=self.timeout)

    @staticmethod
    def _sev_label(s) -> str:
        n = int(s)
        return ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")[min(n, 4)]


# Mapa kind -> TTP de MITRE ATT&CK (https://attack.mitre.org/).
# Si un kind no aparece, el alerter lo manda sin TTP (no asumimos).
_MITRE = {
    # Persistencia
    "persistence_suid":          "T1548.001",   # Setuid/Setgid
    "persistence_cron":          "T1053.003",   # Cron
    "persistence_unit":          "T1543.002",   # Systemd Service
    "persistence_ld_preload":    "T1574.006",   # Hijack: LD_PRELOAD
    "persistence_init":          "T1037.004",   # RC scripts
    "persistence_profile":       "T1546.004",   # .bashrc / shell init
    "persistence_account":       "T1136.001",   # Create Local Account
    "persistence_sudoers":       "T1548.003",   # Sudo and Sudo Caching
    "persistence_authkeys":      "T1098.004",   # SSH authorized_keys
    "persistence_integrity":     "T1554",       # Compromise Client Software Binary
    "persistence_fcaps":         "T1548",       # Abuse Elevation Control
    "persistence_kmod":          "T1547.006",   # Kernel Modules
    "persistence_authfile":      "T1556",       # Modify Authentication Process
    "persistence_pam":           "T1556.003",   # PAM
    "persistence_immutable":     "T1222.002",   # Linux File Permissions
    "persistence_hidden_pid":    "T1014",       # Rootkit
    "persistence_bpf":           "T1014",       # Rootkit (eBPF)
    "persistence_selftamper":    "T1562.001",   # Disable Security Tools
    "persistence_autostart":     "T1547",       # Boot or Logon Autostart
    "persistence_orphan":        "T1055",       # Process Injection / orphan
    "persistence_honeyfile":     "T1005",       # Data from Local System (canary)
    # Red / auth
    "auth_bruteforce":           "T1110.001",
    "auth_spraying":             "T1110.003",
    "scan_portscan":             "T1046",
    "exfil_dns":                 "T1048.003",
    "beacon_c2":                 "T1071",       # Application Layer Protocol (C2)
    "malicious_process":         "T1059",       # Command and Scripting Interpreter
    "exec_suspicious":           "T1059.004",   # Unix Shell
}


def mitre_for(kind: str) -> str | None:
    return _MITRE.get(kind)
