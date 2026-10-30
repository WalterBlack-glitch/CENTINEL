# Changelog

## 2026-10-30 — RECON: nmap XML, diff entre corridas e informe HTML

### Nuevo
- **RECON parsea nmap por XML** (`-oX`): `parse_nmap_xml` (puro) y `run_nmap`,
  que ahora emite XML además del texto legible y lo prefiere. El XML es estable
  entre versiones y trae producto/versión/extrainfo del servicio por separado;
  si falta o no parsea, se cae al parseo de la tabla de texto. (RECON #1)
- **`recon/diff`** (puro): compara dos conjuntos de hallazgos por su clave
  natural (`tipo|puerto|proto|url|fuzz`, nunca el PID) → nuevos / desaparecidos
  / comunes, con titular «Desde la corrida anterior: N nuevo(s)». El TUI lo
  muestra tras cada scan; sirve igual para diff entre sesiones. (RECON #4)
- **Informe HTML del recon** (`report.render_html`, export escribe `.html`):
  autocontenido, tema claro/oscuro, con todo valor pasado por `html.escape`
  porque parte del contenido lo escribe el objetivo escaneado. (RECON #4)

### Tests
686 → **707** (1 skip). Recon: 37 → **60** (incluye I/O simulado de `run_nmap`,
que prefiere XML y cae a texto).


## 2026-10-08 — historial, informes, configuración, bitácora y arranque

### Nuevo
- **`snapshots`**: historial de escaneos y diff («esto es nuevo desde ayer»):
  nuevos / agravados / resueltos / sin cambio. Historial JSONL firmado con HMAC;
  la identidad de un hallazgo es `tipo|nombre|ruta`, nunca el PID. (ROADMAP #8)
- **`collectors/winpersist`**: vectores de arranque de Windows en solo lectura —
  `Run`/`RunOnce` (HKLM y HKCU), Startup, servicios y tareas programadas, con
  patrones de living-off-the-land en la línea de comando. (ROADMAP #5)
- **`collectors/hashwatch`**: integridad en disco de los binarios del sistema
  (SHA-256 + firma), con línea base firmada. Cambió y sigue MS-firmado = LOW;
  cambió sin firma válida = CRITICAL. (ROADMAP #4)
- **`storage/export`**: informes JSON / CSV / HTML con fecha en el nombre, HTML
  escapado y CSV injection neutralizada. (ROADMAP #7)
- **`storage/audit`**: bitácora JSONL append-only con rotación. (ROADMAP #13)
- **`config`**: `centinel.toml` opcional que nunca tumba el arranque. (ROADMAP #10)
- **`centinel.desktop`**: modo `--once` sin ventana (código de salida 2 si hay
  hallazgos, apto para el Programador de tareas), `--export`, `--config`,
  `--write-config`, botón «Exportar informe», columna «Estado» con lo nuevo y
  auto-escaneo opcional.

### Corregido
- **La verificación de firmas no funcionaba nunca.** Se pasaban las rutas a
  PowerShell como argumentos tras `--`, que con `-Command` no llegan a `$args`
  (eso es solo de `-File`), así que la consulta devolvía vacío siempre. Ahora van
  incrustadas en el script como literales con comillas escapadas. Síntoma
  visible: seis falsos positivos CRITICAL contra Windows Defender.
- **`Valid` vale 0 en el enum de PowerShell**, así que `if($s.Status)` era falso
  y todo salía como `UnknownError`. Se comprueba el objeto, no su verdad.
- **`subprocess` decodificaba la salida de PowerShell en cp1252** y los subjects
  de certificado con acentos lanzaban `UnicodeDecodeError` en el hilo lector,
  dejando el escaneo sin datos. Se fuerza UTF-8 en los dos extremos
  (`hashwatch`, `winpersist` y el resumen de RAM del escritorio).
- **`--once` reventaba al imprimir** `⚠` en una consola cp1252. Se reconfigura la
  salida a UTF-8 y, si no se puede, se cae a símbolos ASCII.
- **`pyproject.toml` no empaquetaba `centinel.recon`**: un `pip install` dejaba
  fuera el módulo RECON entero.

### Tests
333 → **686** (8 s, sin red y sin tocar el sistema).

Formato basado en [Keep a Changelog](https://keepachangelog.com/) · SemVer.

## [Sin publicar]

### Añadido
- **ProcWatch + CENTINEL Escritorio** (`centinel/collectors/procwatch.py`,
  `centinel/desktop.py`, MITRE T1036.005): compañero para **Windows** que caza
  malware disfrazado de proceso del sistema (`svchost.exe`, `lsass.exe`…). Regla
  **basada en firma**, no en el nombre: alerta si un nombre de sistema no está
  firmado válidamente por Microsoft, si un `svchost` cuelga de un padre que no es
  `services.exe`, o si un binario corre desde `%TEMP%`/`%APPDATA%`/`Downloads`
  sin firma de editor de confianza. Clasificador **puro** (`classify_process`) +
  13 tests; el I/O de Windows (enumerar procesos y verificar Authenticode) se
  apoya en PowerShell — **0 dependencias pip**. `centinel-desktop` abre una
  ventana tkinter con el veredicto (LIMPIO / N amenazas) y el top de consumidores
  de RAM. En Linux el colector se desactiva solo (`available()` -> False).
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
