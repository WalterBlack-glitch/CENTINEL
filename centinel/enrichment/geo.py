"""Geolocalización opcional de IPs (capa de enriquecimiento).

Usa una base de datos local MaxMind GeoLite2 (.mmdb) si está disponible vía la
librería `geoip2`. Es 100% offline y opt-in: si no hay base ni librería, es un
no-op silencioso y el resto del pipeline funciona igual.

Descarga gratuita de GeoLite2-City.mmdb: https://www.maxmind.com/ (requiere
cuenta gratis). Pásala con --geo /ruta/GeoLite2-City.mmdb.
"""
from __future__ import annotations

import ipaddress


class GeoResolver:
    def __init__(self, mmdb_path: str | None = None) -> None:
        self._reader = None
        if mmdb_path:
            try:
                import geoip2.database  # type: ignore
                self._reader = geoip2.database.Reader(mmdb_path)
            except Exception:
                self._reader = None

    @property
    def available(self) -> bool:
        return self._reader is not None

    def lookup(self, ip: str) -> dict | None:
        """Devuelve {country, city, lat, lon} o None. Salta IPs no enrutables."""
        if self._reader is None:
            return None
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                return None
        except ValueError:
            return None
        try:
            r = self._reader.city(ip)
        except Exception:
            return None
        loc = r.location
        if loc.latitude is None or loc.longitude is None:
            return None
        return {
            "country": r.country.iso_code,
            "city": r.city.name,
            "lat": loc.latitude,
            "lon": loc.longitude,
        }

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()
