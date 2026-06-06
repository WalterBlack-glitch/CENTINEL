# Roadmap de versiones — CENTINEL

SemVer. Cada minor agrupa un tema; los `0.x` no garantizan compatibilidad de
CLI hasta `1.0`. Marca: ✅ hecho · 🔵 en curso · ⚪ planeado.

## v0.1 — Núcleo multicapa ✅
Bus async, colectores (authlog, sniffer, netwatch, dnswatch, honeypot,
persistence/rootcheck), correlación, enriquecimiento geo/rDNS, KEV, dashboard
terminal/web, respuesta nft/iptables, servicio systemd, drop de privilegios.

## v0.2 — Integridad, C2 moderno y forense ✅
- Event store **tamper-evident** (cadena HMAC) + `--verify-log` / `--report`.
- **Beacon C2** (T1071) por regularidad de intervalos (CoV).
- **ExecWatch** (T1059.004): reverse shells, descarga-y-ejecución, exec efímero.
- **Digest periódico** por webhook (resumen + estado de cadena).
- `keyring`/`_proc_net` compartidos. Versión + CHANGELOG + docs de auditoría.

## v0.3 — Cobertura de captura sin ventanas ciegas ⚪
- **auditd/execve vía netlink** (reemplaza el polling de execwatch; captura
  total de exec, incluido lo ultra-efímero). Fallback a polling si no hay CAP.
- **inotify** sobre rutas de persistencia (cron, authorized_keys, systemd) para
  detección en el instante en vez de por barrido.
- Correlación exec↔red↔persistencia en una sola línea de tiempo de incidente.

## v0.4 — Integración SOC / SIEM ⚪
- **Export estructurado**: JSON-lines a fichero, syslog (RFC 5424) y CEF.
- **Reglas externas** cargables (YAML/JSON) sin recompilar: umbrales, allow/deny
  lists, mapeos TTP. Recarga en caliente (SIGHUP).
- **YARA opcional** (yara-python) sobre binarios marcados por execwatch/rootcheck.

## v0.5 — Operabilidad y multinodo ⚪
- **Estado persistente de correlación** (sobrevive reinicios).
- **Modo agente→colector central** (varios hosts → un agregador) con mTLS.
- Métricas Prometheus (`/metrics`) y healthcheck.

## v1.0 — Estable y empaquetado ⚪
- CLI/flags congelados con compatibilidad garantizada.
- **Paquetes**: `.deb`/`.rpm`, imagen OCI, releases firmadas + SBOM.
- CI completa (test matrix, lint, build, firma) y cobertura ≥85%.
- Documentación de despliegue y runbooks de respuesta a incidentes.

## Transversal (continuo)
- CI en GitHub Actions (pendiente, prioridad alta).
- Auto-auditoría de seguridad por cada superficie nueva.
- Mantener 0 dependencias **obligatorias**; todo extra es opcional.
