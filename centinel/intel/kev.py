"""Integración con el catálogo KEV de CISA (Known Exploited Vulnerabilities).

KEV es la lista oficial y gratuita de CVEs con explotación CONFIRMADA en el
mundo real. Es la mejor señal pública de "esto se está usando ahora mismo".

Centinel lo usa para priorización: si una firma de explotación
(`correlation/signatures.py`) detecta un CVE presente en KEV, el evento sube de
severidad y se etiqueta `kev` (y `ransomware` si KEV marca uso en campañas de
ransomware).

Diseño:
  - OFFLINE-FIRST: funciona desde una caché local en disco; la descarga de red
    es opt-in (`--kev-update`). Sin caché ni red, es un no-op silencioso.
  - Sin dependencias: descarga con urllib (stdlib) sobre HTTPS (TLS verificado).
  - Endurecido: solo el host oficial, tamaño de respuesta acotado, timeout,
    parseo JSON seguro (nunca ejecuta nada), caché escrita con permisos 0600.
"""
from __future__ import annotations

import json
import os
import ssl
import time
import urllib.request
from pathlib import Path

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
_ALLOWED_HOST = "www.cisa.gov"
_MAX_BYTES = 32 * 1024 * 1024   # el feed real ronda ~2 MB; cota dura anti-DoS
_CVE_RE_OK = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-")


class KevCatalog:
    def __init__(self, cache_path: str = "kev.json") -> None:
        self.cache_path = str(Path(cache_path))
        self._by_cve: dict[str, dict] = {}
        self.released: str | None = None
        self._load_cache()

    # ---- consulta ----

    @property
    def available(self) -> bool:
        return bool(self._by_cve)

    @property
    def count(self) -> int:
        return len(self._by_cve)

    def contains(self, cve: str | None) -> bool:
        return bool(cve) and cve.upper() in self._by_cve

    def get(self, cve: str | None) -> dict | None:
        return self._by_cve.get((cve or "").upper())

    # ---- caché local ----

    def _load_cache(self) -> None:
        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._ingest(data)
        except (OSError, ValueError):
            pass

    def _save_cache(self, data: dict) -> None:
        old = os.umask(0o077)
        try:
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except OSError:
            pass
        finally:
            os.umask(old)

    # ---- descarga (opt-in) ----

    def update(self) -> tuple[bool, str]:
        """Descarga el feed de CISA y refresca la caché. Devuelve (ok, detalle).

        Pensado para llamarse fuera del hot-path (al arranque o por cron). En un
        contexto async, envuélvelo en run_in_executor.
        """
        # Validación estricta del destino (anti-SSRF / anti-redirección a otro host).
        from urllib.parse import urlparse
        u = urlparse(KEV_URL)
        if u.scheme != "https" or u.hostname != _ALLOWED_HOST:
            return False, "URL del feed no permitida"
        try:
            ctx = ssl.create_default_context()  # verifica certificado y hostname
            req = urllib.request.Request(KEV_URL, headers={
                "User-Agent": "Centinel-KEV/1.0", "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                if resp.status != 200:
                    return False, f"HTTP {resp.status}"
                # Anti-redirección a otro host: urllib ya siguió los redirects,
                # así que validamos el host FINAL antes de confiar en el cuerpo.
                final = urlparse(resp.geturl())
                if final.scheme != "https" or final.hostname != _ALLOWED_HOST:
                    return False, f"redirección no permitida a {final.hostname}"
                # Lee como mucho _MAX_BYTES+1 para detectar respuestas gigantes.
                raw = resp.read(_MAX_BYTES + 1)
            if len(raw) > _MAX_BYTES:
                return False, "respuesta demasiado grande (descartada)"
            data = json.loads(raw.decode("utf-8", "replace"))
        except (OSError, ValueError, ssl.SSLError) as e:
            return False, f"error de descarga: {e}"
        n = self._ingest(data)
        if n == 0:
            return False, "feed sin vulnerabilidades válidas"
        self._save_cache(data)
        return True, f"KEV actualizado: {n} CVEs (released {self.released})"

    # ---- parseo ----

    def _ingest(self, data: dict) -> int:
        if not isinstance(data, dict):
            return 0
        vulns = data.get("vulnerabilities")
        if not isinstance(vulns, list):
            return 0
        by_cve: dict[str, dict] = {}
        for v in vulns:
            if not isinstance(v, dict):
                continue
            cve = v.get("cveID")
            if not isinstance(cve, str):
                continue
            cve = cve.strip().upper()
            # CVE-AAAA-NNNN..., sin caracteres raros (defensa ante feed manipulado).
            if not cve.startswith("CVE-") or not set(cve) <= _CVE_RE_OK or len(cve) > 32:
                continue
            by_cve[cve] = {
                "vendor": str(v.get("vendorProject", ""))[:120],
                "product": str(v.get("product", ""))[:120],
                "name": str(v.get("vulnerabilityName", ""))[:200],
                "dateAdded": str(v.get("dateAdded", ""))[:20],
                "ransomware": str(v.get("knownRansomwareCampaignUse", ""))
                              .lower() == "known",
            }
        if by_cve:
            self._by_cve = by_cve
            rel = data.get("dateReleased") or data.get("catalogVersion")
            self.released = str(rel)[:40] if rel else None
        return len(by_cve)
