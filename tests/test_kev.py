"""Tests del catálogo KEV de CISA (offline, sin red)."""
import asyncio
import json

import pytest

from centinela.core import Severity
from centinela.intel.kev import KevCatalog
from centinela.enrichment.resolver import Enricher
from centinela.correlation import signatures as S


def _write(tmp_path, vulns, released="2026-05-01"):
    p = tmp_path / "kev.json"
    p.write_text(json.dumps({"dateReleased": released, "vulnerabilities": vulns}))
    return str(p)


def test_carga_y_consulta(tmp_path):
    path = _write(tmp_path, [
        {"cveID": "CVE-2024-6387", "vendorProject": "OpenBSD",
         "product": "OpenSSH", "knownRansomwareCampaignUse": "Unknown"}])
    kev = KevCatalog(path)
    assert kev.available and kev.count == 1
    assert kev.contains("CVE-2024-6387")
    assert kev.contains("cve-2024-6387")        # case-insensitive
    assert not kev.contains("CVE-9999-0000")
    assert kev.released == "2026-05-01"


def test_ignora_cve_malformado(tmp_path):
    # Defensa ante un feed manipulado: IDs raros se descartan.
    path = _write(tmp_path, [
        {"cveID": "CVE-2024-6387"},
        {"cveID": "'; DROP TABLE--"},
        {"cveID": "x" * 100},
        {"cveID": 12345},
        {"no_cve": True},
    ])
    kev = KevCatalog(path)
    assert kev.count == 1


def test_sin_cache_es_noop(tmp_path):
    kev = KevCatalog(str(tmp_path / "noexiste.json"))
    assert not kev.available and kev.count == 0
    assert kev.contains("CVE-2024-6387") is False


def test_json_corrupto_no_crashea(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{ esto no es json valido ")
    kev = KevCatalog(str(p))
    assert not kev.available


@pytest.mark.asyncio
async def test_enriquecimiento_eleva_severidad(tmp_path):
    path = _write(tmp_path, [
        {"cveID": "CVE-2024-6387", "knownRansomwareCampaignUse": "Unknown"}])
    enr = Enricher(kev=KevCatalog(path))
    ev = S.build_event("Timeout before authentication for 9.9.9.9 port 1")
    ev = await enr.enrich(ev)
    assert "kev" in ev.tags and ev.severity >= Severity.HIGH


@pytest.mark.asyncio
async def test_ransomware_eleva_a_critico(tmp_path):
    path = _write(tmp_path, [
        {"cveID": "CVE-2018-10933", "knownRansomwareCampaignUse": "Known"}])
    enr = Enricher(kev=KevCatalog(path))
    ev = S.build_event("Connection from 8.8.8.8 port 1: client software "
                       "version libssh-0.8")
    ev = await enr.enrich(ev)
    assert "ransomware" in ev.tags and ev.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_cve_no_en_kev_no_se_marca(tmp_path):
    path = _write(tmp_path, [{"cveID": "CVE-1999-0001"}])
    enr = Enricher(kev=KevCatalog(path))
    ev = S.build_event("Timeout before authentication for 9.9.9.9 port 1")
    ev = await enr.enrich(ev)
    assert "kev" not in ev.tags
