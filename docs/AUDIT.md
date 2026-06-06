# Auditoría técnica — CENTINEL

> Estado a v0.2.0 · 7.3k LOC · 172 tests verdes · 0 dependencias obligatorias.

## 1. Veredicto

Base **sólida y madura para un IDS de host open-source**. Arquitectura limpia
(bus async + colectores + correlación + persistencia + presentación + respuesta),
sin dependencias obligatorias, con un modelo de amenazas honesto y documentado.
El salto a "producto" no es de calidad de código sino de **operabilidad,
empaquetado y cobertura de captura**.

## 2. Fortalezas

| Área | Detalle |
|---|---|
| Arquitectura | `EventBus` fan-out async, `Collector` base uniforme, `ThreatEvent` único. Acoplamiento bajo, capas sustituibles. |
| Seguridad propia | Drop de privilegios tras abrir recursos, `safe_path` (anti-traversal), `valid_iface`, anti-SSRF en webhooks, `keyring` endurecido (`O_NOFOLLOW`/`O_EXCL`/`O_EXCL`/`0600`/CSPRNG). |
| Integridad | Event store **tamper-evident** (cadena HMAC-SHA256), detección de huecos por AUTOINCREMENT, `--verify-log`. |
| Resiliencia | Todo colector envuelto en `_guard`/try: un fallo aislado nunca tumba el pipeline. Degradación elegante si falta scapy/auth.log/permisos. |
| Testabilidad | Lógica de detección **pura** (`classify`, `BeaconAnalyzer`, `parse_hex_addr`) separada de I/O. 172 tests, sin red ni root. |
| Honestidad | Limitaciones declaradas en docstrings (ventana ciega del polling, root puede recomputar HMAC). No vende humo. |

## 3. Deuda técnica y huecos (priorizados)

| # | Hueco | Impacto | Esfuerzo |
|---|---|---|---|
| H1 | **Captura de exec por polling** (`execwatch`) pierde procesos ultra-efímeros entre barridos. | Evasión real | Alto (auditd/netlink) |
| H2 | Sin **CHANGELOG/SemVer** formal hasta ahora; versión desincronizada. | Operación/release | Bajo ✅ (resuelto en v0.2) |
| H3 | Sin **CI** (GitHub Actions): tests no corren en cada PR. | Regresiones | Bajo |
| H4 | Sin **escaneo de ficheros** (YARA) de binarios marcados. | Cobertura | Medio |
| H5 | Persistencia solo SQLite local; sin **export a SIEM** (syslog/CEF/JSON-lines). | Integración SOC | Medio |
| H6 | Correlación en memoria: estado se pierde al reiniciar. | Continuidad | Medio |
| H7 | Sin **firma de releases** ni SBOM. | Cadena de suministro | Bajo |
| H8 | Dashboard web sin pruebas de carga/concurrencia documentadas. | Escala | Medio |
| H9 | Reglas de detección hardcodeadas en Python; no **cargables en caliente**. | Mantenibilidad | Medio |

## 4. Riesgos de seguridad del propio proyecto

- **Clave HMAC en `<db>.hmac` legible por root** — documentado; mitigación real
  es anclar `head_hash()` fuera de la máquina (ya soportado por `--verify-log`).
  No es vulnerabilidad explotable por no-root.
- Última revisión de seguridad sobre commits `8810dd6`/`af275df`: **0 hallazgos
  HIGH/MEDIUM** (SQL parametrizado, sin `eval/exec/subprocess`, `/proc` solo
  lectura, fail-closed).

## 5. Recomendaciones inmediatas (orden)

1. **CI en GitHub Actions** (matriz 3.10–3.12, `pytest` + lint). — H3
2. **auditd/execve vía netlink** para cerrar la ventana ciega de exec. — H1
3. **Export JSON-lines / syslog** para enchufar a un SIEM. — H5
4. **YARA opcional** sobre binarios efímeros/borrados que marque execwatch. — H4
5. **Reglas externas** (YAML/JSON) cargables sin tocar código. — H9
