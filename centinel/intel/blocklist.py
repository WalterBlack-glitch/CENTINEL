"""Threat intel en vivo: blocklist de IPs C2/botnet desde feeds gratuitos.

Mismo espíritu que `kev.py`: OFFLINE-FIRST + descarga opt-in + endurecido.
Enriquece cada evento con `src_ip`: si la IP aparece en un feed de C2/botnet
conocido, el evento sube a HIGH/CRITICAL y se etiqueta `threat-intel`.

Feeds por defecto (abuse.ch, sin API key, dominio público, texto plano):
  - Feodo Tracker  → IPs de C2 de troyanos bancarios (Emotet, Dridex, TrickBot…)
  - SSL Blacklist  → IPs asociadas a certificados de C2/botnet

Nota honesta: algunos feeds pueden empezar a pedir auth o cambiar de formato.
El diseño degrada con elegancia: sin red o con feed roto, se usa la caché
local; y `--intel-cache <fichero>` acepta CUALQUIER blocklist de texto plano
(una IP por línea, `#` = comentario) que ya tengas o descargues por tu cuenta.

Endurecimiento: solo hosts de la allowlist, HTTPS con TLS verificado, tamaño
acotado, timeout, parseo de texto (nunca ejecuta nada), caché 0600.
"""
from __future__ import annotations

import ipaddress
import json
import os
import ssl
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

# (nombre, url, host_esperado)
_FEEDS = (
    ("feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
     "feodotracker.abuse.ch"),
    ("sslbl", "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
     "sslbl.abuse.ch"),
)
_ALLOWED_HOSTS = frozenset(h for _, _, h in _FEEDS)
_MAX_BYTES = 16 * 1024 * 1024   # los feeds reales rondan KBs; cota anti-DoS


def parse_ip_feed(text: str) -> set[str]:
    """Extrae IPs válidas de un feed de texto plano.

    Pura: salta comentarios (`#`, `;`), líneas vacías y tokens no-IP. Acepta el
    formato de abuse.ch (una IP por línea, a veces con comentarios de cabecera)
    y blocklists genéricas.
    """
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;/":
            continue
        # Toma el primer token (algunos feeds ponen IP<TAB>fecha, o IP:puerto).
        token = line.split()[0].split(",")[0]
        token = token.split(":")[0] if token.count(":") == 1 and "." in token \
            else token   # IP:puerto pero no IPv6
        try:
            ip = ipaddress.ip_address(token)
        except ValueError:
            continue
        # Ignora privadas/loopback (nunca serían un C2 público; evita
        # falsos positivos si un feed viene sucio).
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            continue
        out.add(str(ip))
    return out


class BlockList:
    def __init__(self, cache_path: str = "intel_blocklist.json") -> None:
        self.cache_path = str(Path(cache_path))
        self._ips: dict[str, str] = {}   # ip -> fuente
        self.updated: str | None = None
        self._load_cache()

    # ---- consulta ----

    @property
    def available(self) -> bool:
        return bool(self._ips)

    @property
    def count(self) -> int:
        return len(self._ips)

    def contains(self, ip: str | None) -> bool:
        return bool(ip) and ip in self._ips

    def source_of(self, ip: str | None) -> str | None:
        return self._ips.get(ip or "")

    # ---- caché local ----

    def _load_cache(self) -> None:
        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        if isinstance(data, dict) and isinstance(data.get("ips"), dict):
            # Formato JSON propio {ip: fuente}.
            self._ips = {str(k): str(v)[:40] for k, v in data["ips"].items()}
            self.updated = str(data.get("updated", ""))[:40] or None
        elif isinstance(data, list):
            self._ips = {str(ip): "cache" for ip in data}
        else:
            # ¿Era texto plano por accidente? intenta parsear.
            pass

    def load_plaintext(self, path: str, source: str = "local") -> int:
        """Carga una blocklist de texto plano (IP por línea). Devuelve nº IPs."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                ips = parse_ip_feed(f.read())
        except OSError:
            return 0
        for ip in ips:
            self._ips.setdefault(ip, source)
        return len(ips)

    def _save_cache(self) -> None:
        old = os.umask(0o077)
        try:
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump({"ips": self._ips, "updated": self.updated}, f)
        except OSError:
            pass
        finally:
            os.umask(old)

    # ---- descarga (opt-in) ----

    def update(self) -> tuple[bool, str]:
        """Descarga todos los feeds permitidos y refresca la caché.

        Fuera del hot-path (arranque/cron). En async, envuélvelo en executor.
        """
        merged: dict[str, str] = {}
        errors = []
        for name, url, host in _FEEDS:
            ok, ips_or_err = self._fetch_one(url, host)
            if ok:
                for ip in ips_or_err:
                    merged.setdefault(ip, name)
            else:
                errors.append(f"{name}: {ips_or_err}")
        if not merged:
            detail = "; ".join(errors) or "sin datos"
            return False, f"ningún feed cargó ({detail})"
        self._ips = merged
        self.updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._save_cache()
        note = f"intel actualizado: {len(merged)} IPs C2/botnet"
        if errors:
            note += f" ({len(errors)} feed(s) fallaron: {'; '.join(errors)})"
        return True, note

    def _fetch_one(self, url: str, host: str):
        u = urlparse(url)
        if u.scheme != "https" or u.hostname not in _ALLOWED_HOSTS \
           or u.hostname != host:
            return False, "URL no permitida"
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers={
                "User-Agent": "Centinel-Intel/1.0", "Accept": "text/plain"})
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                if resp.status != 200:
                    return False, f"HTTP {resp.status}"
                final = urlparse(resp.geturl())
                if final.scheme != "https" or final.hostname != host:
                    return False, f"redirección a {final.hostname}"
                raw = resp.read(_MAX_BYTES + 1)
            if len(raw) > _MAX_BYTES:
                return False, "respuesta demasiado grande"
            return True, parse_ip_feed(raw.decode("utf-8", "replace"))
        except (OSError, ValueError, ssl.SSLError) as e:
            return False, f"{e}"
