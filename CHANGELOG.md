# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/) · SemVer.

## [Sin publicar]

### Añadido
- **Anti-hijacking** (`--hijackwatch`, MITRE T1574/T1055): nuevo colector que
  caza inyección de librería (`LD_PRELOAD` desde `/tmp`/`/dev/shm`/`$HOME`/
  rutas world-writable), secuestro de `PATH` (efímero o `$HOME` antepuesto a
  `/usr/bin`) y ptrace activo sobre procesos ajenos. Self-defense: detecta
  cuando alguien adjunta un tracer al propio centinel (CRITICAL).
- **Arranque early-boot** (`--install-service --early-boot`): la unidad systemd
  se instala a nivel `sysinit` (`Before=basic.target`), de modo que CENTINEL
  arranca **antes que cualquier servicio normal** — un malware persistido como
  unidad systemd no llega a ejecutarse sin que el baseline ya esté vigilando.
- **CI en GitHub Actions**: matriz Python 3.10–3.13 sin extras (verifica las
  0 dependencias obligatorias) + job con `[all]` instalado.
- README: referencia completa de flags, índice de documentación, badges y
  roadmap sincronizado con `docs/ROADMAP.md`.

## [0.2.0] — 2026-06-06

### Añadido
- **Event store tamper-evident**: cada fila encadena un HMAC-SHA256 con la
  anterior (estilo ledger). `--verify-log` recorre la cadena y detecta
  manipulación; `--report` genera un informe forense legible. Detección de
  huecos por AUTOINCREMENT.
- **Beacon C2** (`--beacon`, MITRE T1071): detecta callbacks automatizados por
  la baja varianza (coeficiente de variación) de los intervalos de reconexión.
- **ExecWatch** (`--execwatch`, MITRE T1059.004): caza reverse shells, descarga
  -y-ejecución, exec desde directorios efímeros/binarios borrados/ocultos y
  shells lanzadas por demonios de red (señal de RCE). Clasificación pura.
- **Digest periódico** (`--digest-webhook`, `--digest-interval-h`): resumen de
  actividad cada N horas al webhook, con estado de la cadena HMAC.
- Módulos compartidos `keyring` (carga de clave endurecida) y `_proc_net`
  (parseo de `/proc/net`); `alerter.post_json` reutilizable.
- Documentación: `docs/AUDIT.md`, `docs/ROADMAP.md`, este CHANGELOG.

### Cambiado
- `baseline_store` y `EventStore` comparten `keyring` (sin duplicar código).
- `netwatch` usa `_proc_net` en vez de su parser local.
- Versión sincronizada en `pyproject.toml` y `centinel.__version__`.

### Seguridad
- Carga de clave HMAC con `O_NOFOLLOW`/`O_EXCL`/`O_BINARY`/`0600` y CSPRNG.
- Revisión de seguridad de las superficies nuevas: 0 hallazgos HIGH/MEDIUM.

## [0.1.0]
- Núcleo multicapa: bus async, colectores (authlog, sniffer, netwatch, dnswatch,
  honeypot, persistence/rootcheck), correlación, enriquecimiento, KEV, dashboard
  terminal/web, respuesta nft/iptables, servicio systemd, drop de privilegios.
