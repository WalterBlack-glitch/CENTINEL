"""Backend de firewall para respuesta activa: nftables o iptables.

Seguridad por diseño:
  - DRY-RUN por defecto: solo imprime lo que haría; no toca el firewall hasta
    que se pide explícitamente modo `live`.
  - NUNCA bloquea IPs privadas, loopback, link-local ni multicast (evita
    cortarte tu propia LAN o el acceso de gestión).
  - Allowlist de IPs/redes que jamás se tocan (tu IP de admin, gateways...).
  - Idempotente: no reintenta una IP ya bloqueada.
  - Rutas absolutas + PATH controlado (sin hijacking aunque corra como root).
"""
from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess

_SAFE_ENV = {"PATH": "/usr/sbin:/sbin:/usr/bin:/bin", "LC_ALL": "C"}
_TABLE = "centinel"
_SET = "blocked"


def _resolve_bin(name: str) -> str | None:
    for cand in (f"/usr/sbin/{name}", f"/sbin/{name}",
                 f"/usr/bin/{name}", f"/bin/{name}"):
        if os.path.exists(cand):
            return cand
    return shutil.which(name)


class Firewall:
    def __init__(self, mode: str = "dry-run",
                 allowlist: list[str] | None = None) -> None:
        self.mode = mode  # "dry-run" | "live"
        self.blocked: set[str] = set()
        self._nets = [ipaddress.ip_network(c, strict=False)
                      for c in (allowlist or [])]
        self.backend, self._bin = self._detect_backend()
        self._initialized = False

    def _detect_backend(self) -> tuple[str | None, str | None]:
        for name in ("nft", "iptables"):
            b = _resolve_bin(name)
            if b:
                return name, b
        return None, None

    # ---- política de seguridad ----

    def _protected(self, ip: str) -> str | None:
        """Devuelve un motivo si la IP NO debe bloquearse, o None si se puede."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "ip inválida"
        if addr.is_private:
            return "privada/LAN"
        if addr.is_loopback:
            return "loopback"
        if addr.is_link_local:
            return "link-local"
        if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
            return "reservada"
        for net in self._nets:
            if addr in net:
                return f"en allowlist ({net})"
        return None

    # ---- acción ----

    def block(self, ip: str) -> tuple[bool, str]:
        """Intenta bloquear una IP. Devuelve (ejecutado, detalle)."""
        # Canonicaliza la IP: '::ffff:8.8.8.8', '8.8.008.008' o variantes raras
        # nunca llegan a nft/iptables como string crudo. ipaddress.ip_address
        # también valida — si no es IP, devolvemos error sin tocar firewall.
        try:
            ip = str(ipaddress.ip_address(ip))
        except (ValueError, TypeError):
            return False, "ip inválida"
        if ip in self.blocked:
            return False, "ya bloqueada"
        reason = self._protected(ip)
        if reason:
            return False, f"protegida: {reason}"
        if self.mode != "live":
            self.blocked.add(ip)
            return True, f"[DRY-RUN] bloquearía {ip} ({self.backend or 'sin backend'})"
        if not self._bin:
            return False, "sin backend de firewall (instala nftables o iptables)"
        try:
            self._ensure_init()
            self._do_block(ip)
        except (OSError, subprocess.SubprocessError) as e:
            return False, f"error firewall: {e}"
        self.blocked.add(ip)
        return True, f"BLOQUEADA {ip} vía {self.backend}"

    def _run(self, args: list[str]) -> None:
        subprocess.run([self._bin, *args], check=True, capture_output=True,
                       text=True, timeout=5, env=_SAFE_ENV)

    def _ensure_init(self) -> None:
        if self._initialized:
            return
        if self.backend == "nft":
            # Crea tabla/set/regla una sola vez (idempotente con `add`).
            self._run(["add", "table", "inet", _TABLE])
            self._run(["add", "set", "inet", _TABLE, _SET,
                       "{ type ipv4_addr; flags timeout; }"])
            self._run(["add", "chain", "inet", _TABLE, "input",
                       "{ type filter hook input priority -150; }"])
            self._run(["add", "rule", "inet", _TABLE, "input",
                       "ip", "saddr", f"@{_SET}", "drop"])
        self._initialized = True

    def _do_block(self, ip: str) -> None:
        if self.backend == "nft":
            self._run(["add", "element", "inet", _TABLE, _SET,
                       f"{{ {ip} timeout 24h }}"])
        else:  # iptables
            self._run(["-I", "INPUT", "-s", ip, "-j", "DROP"])
