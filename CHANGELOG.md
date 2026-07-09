# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/) · SemVer.

## [Sin publicar]

### Añadido
- **Scoring con ML ligero** (`centinel/ml/scoring.py`): modelo de regresión
  logística **sin dependencias** (0 obligatorias) sobre las mismas señales que
  ya extrae la correlación (fallos, usuarios, puertos, flags robótico/campaña/
  canary/exploit/honeypot, intel de IP). Da una **confianza 0..1** como segunda
  opinión: no sustituye a las reglas, las complementa — si la confianza es alta
  (`ml-high`), sube la severidad mínima a HIGH, bajando falsos positivos. Pesos
  calibrados a mano (recalibrables sin tocar lógica); todo puro + 11 tests. El
  evento lleva `enrichment["ml_confidence"]`. Hace la evasión más difícil que
  leer if/else (combinación no lineal de señales).
- **Backend eBPF** (`--ebpf`, MITRE T1059): captura de `execve` por kprobe de
  kernel — **sin la ventana ciega** del polling de /proc; cada ejecución se ve
  en el instante en que ocurre, con su `argv` completo (técnica de Falcon/
  Elastic). Reutiliza el clasificador puro de `execwatch` (mismo veredicto,
  otra fuente). Capa opcional: requiere Linux + `bcc` + root; si falta, degrada
  al polling de `--execwatch`. Si arranca, lo suplanta (no duplica alertas).
  `build_info` puro + 7 tests que verifican paridad con execwatch.
- **Threat intel en vivo** (`--intel-update`, `--intel-cache`, `--intel-feed`):
  blocklist de IPs C2/botnet desde feeds gratuitos (abuse.ch Feodo/SSLBL),
  offline-first y endurecida como el KEV. El Enricher marca cualquier evento
  cuya `src_ip` esté en la lista (`threat-intel`/`c2`, sube a HIGH). Acepta
  blocklists de texto plano propias con `--intel-feed`. `parse_ip_feed` puro
  + 11 tests. Feeds solo desde hosts en allowlist, TLS verificado, cota de
  tamaño, caché 0600.
- **YaraWatch** (`--yara`, `--yara-rules`, extra `[yara]`): escaneo de firmas
  YARA sobre ficheros en directorios efímeros (`/tmp`, `/dev/shm`, `/var/tmp`,
  `/run/shm`) — cierra el hueco "sin firmas" sin tocar el core (dependencia
  opcional; si `yara-python` no está, la capa se desactiva sola). Reglas
  genéricas empaquetadas (`centinel/rules/default.yar`: reverse shells,
  webshells PHP, mineros, ELF empacado, persistencia); `--yara-rules` acepta
  un `.yar` o directorio propio. Severidad derivada de `meta.severity` de la
  regla. Lógica de escaneo pura + 11 tests.
- **Watchdog anti-kill** (`--watchdog`, `--install-watchdog`, MITRE T1562.001):
  servicio hermano `centinel-watchdog.service` (`Restart=always`) que vigila al
  principal y lo **revive** si un atacante con root lo mata, deshabilita o
  enmascara (`systemctl stop/disable/mask`). Cada intervención se reporta como
  CRITICAL por journald. Lógica de decisión pura + 6 tests. Cierra el agujero
  de "matar el agente" que `Restart=on-failure` no cubría (parada limpia/mask).
- **EdgeWatch** (`--edgewatch`, MITRE T1176/T1542.003/T1014/T1620/T1059):
  colector "anti edge malware" en 4 frentes — hijack de Microsoft Edge
  (search provider/homepage/startup URLs forzados, extensiones sideloaded o
  con tríada infostealer webRequest+cookies+`<all_urls>`; lee perfiles Linux
  y el perfil Windows vía `/mnt/c` en WSL), tamper de `/boot` (bootkit),
  módulos kernel nuevos (LKM rootkit) y ejecución fileless/LOLBins
  (`exe → (deleted)`/`memfd:`, `curl|sh`, `base64 -d|bash`, `nc -e`,
  `/dev/tcp/`). Clasificadores puros con 26 tests.
- `docs/ANALISIS_AV_FODA.md`: comparativa CENTINEL vs antivirus comerciales
  (Defender, CrowdStrike, SentinelOne, Bitdefender, Kaspersky, ClamAV, Wazuh)
  + análisis FODA + plan de mejoras priorizado.
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
