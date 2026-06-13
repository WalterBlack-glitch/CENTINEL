# 🛰 CENTINEL

[![CI](https://github.com/WalterBlack-glitch/CENTINEL/actions/workflows/ci.yml/badge.svg)](https://github.com/WalterBlack-glitch/CENTINEL/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![Licencia MIT](https://img.shields.io/badge/licencia-MIT-green)
[![Versión 0.2.0](https://img.shields.io/badge/versi%C3%B3n-0.2.0-orange)](CHANGELOG.md)
![Deps obligatorias: 0](https://img.shields.io/badge/deps_obligatorias-0-success)

Rastreo **multicapa** de amenazas en tiempo real para servidores Linux. Va más
allá de "contar intentos de fuerza bruta": correlaciona varias señales por
actor y muestra **de dónde proviene** cada amenaza con IP, MAC (cuando es
visible) y fabricante del dispositivo.

> **Novedades v0.2.0** — log **tamper-evident** (cadena HMAC) con `--report` y
> `--verify-log`; detección de **C2 por beaconing** (`--beacon`); caza de
> **ejecución fileless / reverse shells** (`--execwatch`); **digest periódico**
> al webhook (`--digest-webhook`). Detalle en [CHANGELOG.md](CHANGELOG.md) ·
> auditoría y plan de versiones en [docs/](docs/).

## Por qué multicapa

El valor no está en un solo detector, sino en cómo se combinan las capas:

| Capa | Qué hace | Aporte único |
|------|----------|--------------|
| **1. Colectores** | **journald** (por defecto), `auth.log`, sniffer (scapy), ARP, honeypot, persistencia (rootcheck), netwatch, **dnswatch**, **beacon**, **execwatch**, simulador | Fuentes pluggables; journald aporta **procedencia confiable** y el sniffer ve la **MAC real** de hosts en tu LAN |
| **2. Enriquecimiento** | IP→MAC (tabla ARP), MAC→fabricante (OUI), rDNS, LAN/WAN, **KEV de CISA** | Contexto accionable sin depender de APIs externas |
| **3. Correlación** | Score por actor en ventana deslizante; **detección de periodicidad** (beacon C2) | Detecta fuerza bruta, **password spraying**, **port scan**, **compromiso** (login OK tras N fallos) y **callbacks C2** por su latido regular |
| **4. Persistencia** | Event store en SQLite **con cadena tamper-evident (HMAC encadenado)** | Auditoría/forense; `top_actors()`; **detecta si alguien editó o borró eventos** (`--verify-log`) |
| **5. Presentación** | Dashboard en terminal (`rich`), **modo examen**, **dashboard web** (FastAPI+WebSocket+mapa), **informe forense** (`--report`) | Ranking de actores + feed; mapa mundial con geolocalización; resumen con TTPs de MITRE ATT&CK |
| **6. Respuesta activa** | Bloqueo en firewall (`nft`/`iptables`) con dry-run; **webhook de alertas** y **digest periódico** | Corrige automáticamente al superar el umbral de score; avisa a Slack/Discord/Telegram al instante y con resumen diario |

> ⚠️ **Sobre la MAC:** una MAC de origen solo es visible para dispositivos en
> tu mismo dominio de broadcast (tu LAN). Para tráfico de internet, la MAC que
> ves es la de tu gateway/router — CENTINEL lo etiqueta como `scope=wan` y no
> pretende lo contrario. Es una limitación física de Ethernet/IP, no del tool.

## Instalación

```bash
git clone https://github.com/WalterBlack-glitch/CENTINEL.git
cd CENTINEL
pip install -e ".[all]"      # rich + scapy + web + geo (todo)
# o mínimo:
pip install -e ".[ui]"       # solo dashboard en terminal
```

Tras instalar tienes el binario `centinel` (y `python -m centinel` equivale).

## Uso

```bash
# Demo sin root ni Linux (genera ataques sintéticos):
python -m centinel --simulate

# Modo EXAMEN: monitorea, prioriza lo más grave, lo corrige y sigue.
python -m centinel --simulate --assess          # dry-run: dice qué bloquearía
sudo centinel --assess --respond-live \
     --block-threshold 70 --allow 1.2.3.4         # bloqueo REAL en firewall

# Dashboard web en vivo (http://127.0.0.1:8787) con mapa geo:
pip install -e ".[web,geo]"
python -m centinel --simulate --web
sudo centinel --sniff --web --web-host 0.0.0.0 \
     --geo /ruta/GeoLite2-City.mmdb         # plotea el origen en el mapa

# Producción en un servidor Linux:
sudo centinel --sniff --iface eth0           # logs de auth + captura de paquetes
centinel --authlog-path /var/log/secure      # RHEL/CentOS
centinel --oui oui.csv                        # resolver fabricante por MAC
```

Flags principales: `--simulate`, `--sniff`, `--iface`, `--no-authlog`,
`--authlog-path`, `--oui`, `--db`, `--beacon`, `--execwatch`, `--report`,
`--verify-log`, `--alert-webhook`, `--digest-webhook`.

### Lanzador Windows → WSL (un clic, dashboard web)

Doble clic en `bin/centinel.cmd` (o crea un acceso directo `Centinel.lnk` con
`bin/centinel.ico` como icono): banner estilo Sentinel, arranca WSL/Ubuntu,
clona el repo y crea el venv con extras `[ui,web]` la primera vez, lanza el
dashboard HTML en [http://127.0.0.1:8787](http://127.0.0.1:8787) (`--simulate`,
sin root) y abre el navegador cuando responde.

```powershell
$cmd = "$PWD\bin\centinel.cmd"; $ico = "$PWD\bin\centinel.ico"
$wsh = New-Object -ComObject WScript.Shell
$s = $wsh.CreateShortcut("$env:USERPROFILE\Desktop\Centinel.lnk")
$s.TargetPath = $cmd; $s.IconLocation = "$ico,0"; $s.Save()
```

### Servicio systemd: vigilar desde el arranque

```bash
sudo centinel --install-service               # arranca antes de las sesiones de usuario
sudo centinel --install-service --early-boot  # nivel sysinit: ANTES que todos los servicios
```

Con `--early-boot` la unidad se ordena `Before=basic.target`: ningún servicio
normal (incluido un malware persistido como unidad systemd, cron o autostart)
llega a ejecutarse sin que CENTINEL haya baselineado el sistema y esté
vigilando. La unidad va endurecida (NoNewPrivileges, ProtectSystem=strict,
capabilities mínimas) — comprometer CENTINEL no da escalada.

### Caza de C2 moderno (red saliente)

```bash
# Beaconing C2: callbacks salientes a intervalos regulares (Cobalt Strike,
# Sliver, Mythic). Detecta el "latido" por su baja varianza temporal.
sudo centinel --beacon

# Exfiltración por DNS (T1048.003): túneles dnscat/iodine, subdominios de
# alta entropía, abuso de TXT/NULL.
sudo centinel --dnswatch --iface eth0

# Combo de red completo: paquetes + procesos↔IP + DNS + beaconing.
sudo centinel --sniff --netwatch --dnswatch --beacon
```

### Caza de ejecución fileless / reverse shells (host)

```bash
# ExecWatch (T1059): vigila los exec de /proc y caza reverse shells
# (bash -i >& /dev/tcp, nc -e, mkfifo|sh, python pty), descarga-y-ejecución
# (curl|sh, base64 -d|sh), exec desde /tmp/oculto y —señal clave de RCE—
# un demonio de red (sshd/nginx/postgres) que lanza una shell.
sudo centinel --execwatch
```

### Forense y log a prueba de manipulación

Cada evento se persiste con un **hash HMAC-SHA256 encadenado** con el anterior.
Si un atacante edita, borra o reordena filas de la BD para tapar sus huellas,
la cadena deja de cuadrar:

```bash
centinel --report --db centinel.db        # informe forense: eventos, severidad,
                                           # TTPs de MITRE, actores e integridad
centinel --verify-log --db centinel.db     # ¿tocaron la BD? exit 0=intacta, 2=NO
```

> **Modelo de amenaza honesto:** la clave HMAC vive en `<db>.hmac` (0600). Un
> atacante que ya es **root** puede leerla y recomputar la cadena. Para defensa
> real contra root, **ancla** el `head` que imprime `--report` fuera de la
> máquina (syslog remoto, el webhook, papel): cualquier reescritura divergirá
> del ancla. Contra atacante no-root, edición offline de la BD o corrupción
> accidental, la cadena es efectiva por sí sola (y un borrado deja huecos de id
> que también se reportan).

### Resumen periódico al webhook (digest)

Una ráfaga de eventos MEDIUM puede pasar inadvertida 24h porque ninguno cruza
el umbral de alerta inmediata. El **digest** envía cada N horas un resumen
(totales, severidad, top de tipos/actores y **estado de la cadena HMAC**):

```bash
centinel --digest-webhook https://hooks.tuequipo.dev/centinel \
         --digest-interval-h 24        # 1 resumen al día (por defecto)
```

Reutiliza el endurecimiento anti-SSRF del alerter; si la URL es peligrosa
(metadata de nube, loopback) el digest se desactiva en silencio. Solo lectura
de la BD: convive con el escritor principal (SQLite WAL).

## Arquitectura

```
Colectores ─┐
            ├─► EventBus ─► Enriquecimiento ─► Correlación ─► Persistencia
Sniffer  ───┘                                      │
                                                   └─► alertas ─► EventBus ─► Dashboard
```

Todo fluye como `ThreatEvent` (ver `centinel/core.py`). El bus es async,
sin dependencias. Añadir una fuente nueva = un archivo en `collectors/` que
herede de `Collector`.

## Seguridad

CENTINEL procesa **input hostil** (un atacante remoto controla parcialmente
`auth.log` vía su username SSH y el rDNS de su IP). El código está endurecido
contra ese modelo de amenaza —ver [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) para
la auditoría completa (13 hallazgos) y sus mitigaciones:

- **Anti-spoofing de logs (eliminado, no solo mitigado):** el colector
  **journald** valida la *procedencia* de cada registro (`SYSLOG_IDENTIFIER`/
  `_COMM` = `sshd`, `_UID` = 0) — solo se parsean mensajes que realmente emitió
  el proceso sshd, así que ningún otro proceso puede inyectar eventos falsos.
  El fallback a `auth.log` además ancla los regex a `sshd[pid]:`, usa whitelist
  de username sin espacios y revalida la IP con `ipaddress`.
- **Anti-DoS de memoria:** dict de actores con purga por inactividad y tope duro
  (`MAX_ACTORS`); cachés rDNS con LRU+TTL acotadas; backpressure en el bus.
- **Menor privilegio:** abre los recursos privilegiados y luego hace
  `setuid`/`setgid` a `nobody` (`--user`, `--no-drop`). Mejor aún, **no correr
  como root**: otorga capabilities al binario y lee el log por grupo `adm`:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v python3)"
  sudo usermod -aG adm "$USER"   # acceso a /var/log/auth.log
  centinel --sniff --iface eth0  # sin sudo
  ```
- **Anti-inyección de terminal:** se eliminan secuencias de escape ANSI y se
  escapa el markup de `rich` en todo string derivado del atacante.
- **Subprocess seguro:** rutas absolutas + `PATH` controlado (sin hijacking),
  args como lista (sin `shell=True`).
- **Persistencia:** SQLite parametrizado (sin SQLi), DB con permisos `0600`,
  WAL y commits por lote.

## Modo examen y respuesta activa

`--assess` convierte CENTINEL en un bucle de **examen → corrección**:

1. **Examen:** monitorea tráfico en vivo durante `--assess-window` segundos.
2. **Informe:** ranking de actores por score (IP, MAC, fallos, usuarios, puertos).
3. **Corrige:** bloquea en firewall (`nft`/`iptables`) a quien supere
   `--block-threshold`.
4. **Sigue:** repite, indefinidamente.

Salvaguardas de la respuesta activa (capa `response/`):

- **Dry-run por defecto:** sin `--respond-live` solo *dice* qué bloquearía;
  no toca tu firewall.
- **Nunca corta tu red:** jamás bloquea IPs privadas, loopback, link-local ni
  reservadas; `--allow IP/CIDR` (repetible) define excepciones (tu IP de admin).
- **Idempotente y con timeout:** cada bloqueo nft expira a las 24 h; no se
  reintenta una IP ya bloqueada.
- **`--respond-live` + `--simulate` está prohibido** (no bloquea IPs reales con
  tráfico de demo).

## Roadmap

Plan completo por versiones en [docs/ROADMAP.md](docs/ROADMAP.md). Resumen:

- **v0.3** — auditd/execve vía netlink (cierra la ventana ciega del polling de
  exec), inotify en rutas de persistencia, línea de tiempo de incidente.
- **v0.4** — export a SIEM (JSON-lines / syslog / CEF), reglas externas
  cargables en caliente, escaneo YARA opcional.
- **v0.5** — estado de correlación persistente, modo agente→colector central
  con mTLS, métricas Prometheus.
- **v1.0** — CLI congelada, paquetes `.deb`/`.rpm`/OCI, releases firmadas + SBOM.

## Detección de exploits y CVEs (Metasploit / escáneres)

Los frameworks de explotación (Metasploit, escáneres masivos, kits de RCE) dejan
rastros característicos en los logs de sshd **antes** de la fase de login.
`correlation/signatures.py` los detecta con firmas ancladas y de bajo coste
(verificadas sin ReDoS), cada una con su CVE cuando aplica:

| Firma | Qué detecta | CVE |
|-------|-------------|-----|
| `http_probe_on_ssh` | Verbo HTTP/TLS contra el puerto 22 (escáner web) | — |
| `offensive_tool_banner` | Banners de libssh/paramiko/zgrab/masscan/Nmap/Net::SSH | — |
| `regresshion_timeout` | Ráfagas de `Timeout before authentication` | CVE-2024-6387 |
| `libssh_client` | Cliente libssh (posible bypass de auth) | CVE-2018-10933 |
| `max_auth_exceeded`, `no_kex_match`, `kex_identification_reset` | Fuerza bruta / escaneo / fingerprinting | — |

Las firmas no disparan bloqueos por sí solas: alimentan el score del actor (flag
`exploit`, +25) y las ráfagas escalan como cualquier evento, así que la respuesta
activa decide por score + allowlist.

### Atribución de actor entre IPs (la botnet como un solo adversario)

La defensa más avanzada de CENTINEL: en vez de razonar "por IP", agrupa IPs
distintas en un mismo **adversario** según su huella de comportamiento —el
diccionario de usuarios objetivo, las técnicas y el perfil de temporización
compartidos. Un atacante con IA reparte su campaña entre decenas de IPs para
diluirse; al reconocer la huella común, CENTINEL las atribuye a una sola
entidad y te deja defenderte de la campaña entera, no IP por IP.

Cuando ≥5 IPs comparten diccionario/TTPs → `alert_actor_atribuido` y aparecen
agrupadas en el panel **Adversarios atribuidos** del dashboard web. El algoritmo
es barato y acotado (índice invertido + Jaccard, sin pairwise O(n²); expulsión
LRU O(1): ~5 µs/evento incluso bajo un atacante que rota diccionarios).

### Feed CVE de CISA KEV (gratis, sin API key)

CENTINEL cruza los CVEs detectados contra el catálogo **KEV de CISA** (Known
Exploited Vulnerabilities — la lista oficial de CVEs con explotación confirmada
en el mundo real). Si un CVE está en KEV, el evento sube a `HIGH` y se etiqueta
`kev`; si KEV lo marca con uso en ransomware, sube a `CRITICAL` (`ransomware`).

```bash
centinel --kev-update --kev-cache kev.json      # descarga el feed (~1600 CVEs)
centinel --kev-cache kev.json                    # usa la caché (offline)
```

Offline-first: funciona desde la caché en disco; la descarga es opt-in, solo
desde el host oficial de CISA por HTTPS (TLS verificado, host final validado
contra redirecciones, tamaño acotado). Actualízalo por cron con `--kev-update`.

## Honeypot (servicio-trampa)

`--honeypot 2222,2323` levanta puertos-señuelo. **Cualquier conexión es maliciosa
por definición** (ningún cliente legítimo se conecta a un servicio trampa), así
que es la señal de mayor relación señal/ruido del sistema.

```bash
centinel --honeypot 2222 --assess --respond-live   # captura y bloquea
```

- **Baja interacción:** envía un banner SSH falso, captura el banner del cliente
  (que suele delatar la herramienta — se cruza con las firmas de explotación) y
  cierra. Nunca ejecuta nada: no hay superficie de RCE.
- Un toque al honeypot marca el flag `honeypot` (+70 al score) → bloqueable de
  inmediato por la respuesta activa.
- Endurecido (escucha en la red): límite global y **por-IP** de conexiones
  (rechazo inmediato, sin encolar), timeouts, lectura acotada, rate-limit de
  eventos por IP y saneado de la entrada del atacante. Ver
  [`AUDIT_HONEYPOT.md`](AUDIT_HONEYPOT.md).
- **Usa puertos altos (>1024)** para no necesitar root y evitar conflictos con
  servicios reales. No lo pongas en el puerto 22 real (ahí está tu sshd).

## Defensa contra hacking asistido por IA

Los ataques con IA/LLM rompen la detección clásica yendo **low-and-slow
distribuidos** (cada IP bajo el umbral) y con temporización adaptativa. CENTINEL
incorpora detectores que **no dependen de umbrales por-IP** — ver
[`docs/DEFENSA_IA.md`](docs/DEFENSA_IA.md):

- **Correlación global de campañas:** agrega entre IPs por usuario objetivo
  (≥8 IPs atacando al mismo user → credential stuffing distribuido) y por subred
  (/24 IPv4, /64 IPv6 → botnet de subred). Atrapa la botnet aunque cada nodo
  haga un solo intento.
- **Timing robótico:** mide el coeficiente de variación de los intervalos; una
  cadencia demasiado regular delata automatización.
- **Credenciales-cebo (canary):** `--canary svc_backup,deploy_old` — cualquier
  intento contra un usuario-trampa es CRÍTICO inmediato.

Estado bajo presión: todas las estructuras son LRU acotadas con purga por
ventana (no son un vector de DoS de memoria). Cubierto por tests.

## Remediación guiada: te dice cómo arreglarlo

Detectar no basta. Ante un compromiso (o intento), CENTINEL adjunta a la alerta
un **playbook accionable** — qué comprobar, qué comando ejecutar y cómo cerrar el
agujero. Aparece en un cajón **🛠️ Cómo remediar** del dashboard web (con botón
*copiar* por comando) y en un panel propio de la terminal.

Cada tipo de amenaza tiene su guía: compromiso de cuenta, fuerza bruta, spraying,
escaneo, canary, timing robótico, credential stuffing, botnet de subred, actor
atribuido, intento de exploit/CVE y hit de honeypot. Los valores interpolados
(IP/usuario) se **sanean a un charset seguro**: aunque el username venga de una
fuente hostil, nunca introduce metacaracteres de shell en un comando copiable.

### Doctor: diagnóstico y arreglo previo

Antes de arrancar, CENTINEL revisa las causas habituales de fallo según los
flags pedidos, **arregla lo seguro** (crea el directorio de la BD, endurece
permisos a 0600) y para el resto imprime el **comando exacto** de arreglo
(dependencias ausentes, falta de privilegios para sniffer/honeypot, puerto web
ocupado, GeoLite/KEV inexistentes). No instala nada ni ejecuta acciones de red.

```bash
centinel --doctor            # solo diagnostica y sale
centinel --simulate --web    # diagnostica y arranca; --no-doctor para omitir
```

## Tracker de procesos maliciosos ↔ IP (`--netwatch`)

Un backdoor/C2 deja una huella inevitable: un **proceso** con un **archivo** en
disco que mantiene una **conexión** a una IP. NetWatch los empareja leyendo solo
`/proc` (sin subprocess ni shell):

```
conexión externa  ↔  inode  ↔  pid  ↔  binario en disco
```

y marca el proceso cuyo binario es sospechoso: **borrado** del disco, en
`/tmp`·`/dev/shm`·`/run`, **world-writable**, **oculto**, o un **script**
ejecutado desde un directorio efímero (caza backdoors en Python/Bash cuyo
intérprete es legítimo). El evento sale con la **IP remota como origen**, así el
C2 pasa por geo/rDNS/KEV y la correlación: queda geolocalizado y puntuado como
un actor más, y se puede bloquear.

```bash
sudo centinel --netwatch --web      # root = ve TODOS los procesos
```

## Vigilancia de persistencia / rootkits (`--rootcheck`) — defensa en capas

Como una cebolla (o un laberinto): muchas capas, cada una vigila un vector de
persistencia distinto que usa un atacante para **quedarse**. Solo lectura, sin
shell:

1. **SUID/SGID** nuevos (baseline) o en `/tmp`·`/dev/shm`·`/home`, world-writable u ocultos.
2. **cron / at** con patrones de backdoor (`curl|sh`, `/dev/tcp/`, `nc -e`, `bash -i`, `base64 -d`).
3. **systemd** (`.service`/`.timer`) cuyo `ExecStart` ejecuta lo anterior.
4. **`/etc/ld.so.preload`** — cualquier librería = rootkit candidato (hooking de libc).
5. **Inicio**: `/etc/profile`, `rc.local`, `profile.d`, `update-motd.d`, `init.d`, reglas **udev**, `modprobe.d`.
6. **Dotfiles de shell** por usuario: `~/.bashrc`, `~/.profile`, `~/.zshrc`…
7. **Cuentas**: UID 0 fantasma (además de root) y contraseñas vacías en `shadow`.
8. **sudoers**: `NOPASSWD: ALL` (escalada silenciosa).
9. **`authorized_keys`**: forced-command backdoor o fichero world-writable.
10. **Integridad de binarios del sistema**: baseline SHA-256 + tamaño + mtime de
    `ls`, `ps`, `netstat`, `ss`, `find`, `lsof`, `sshd`, `bash`, `sudo`… Cualquier
    binario modificado, aparecido o desaparecido es alerta (rootkit clásico que
    troyaniza utilidades para ocultarse a sí mismo).

```bash
sudo centinel --rootcheck --web                 # cobertura total con root
sudo centinel --netwatch --rootcheck --web      # red + host, todo junto
```

> Como root ve todo el sistema; tras soltar privilegios solo ve los procesos del
> usuario destino. Para cazar un backdoor que corre como root, ejecútalo como
> root (o con `CAP_SYS_PTRACE`). Solo lectura: nunca abre sockets ni ejecuta nada.

## Exposición a nivel root (endurecimiento)

CENTINEL necesita root **solo** para abrir recursos privilegiados (socket de
captura, lectura de logs, bind de honeypot, `nft`/`iptables`) y **suelta
privilegios** a `nobody` en cuanto los abre. Notas de superficie:

- El **dashboard web** escucha en `127.0.0.1` por defecto y **no tiene auth**: no
  lo expongas con `--web-host 0.0.0.0` sin un proxy con autenticación o un túnel
  SSH. El `doctor` te avisa si lo haces.
- El endpoint **`/api/block`** (controla el firewall) está restringido a
  **loopback**: aunque expongas el dashboard, nadie en la red maneja tu firewall.
- **`--respond-live`** (bloqueo real con `nft`) necesita root sostenido, así que
  requiere `--no-drop`; el `doctor` avisa del conflicto.

## Referencia de flags (CLI)

Todo lo que acepta `centinel` (también visible con `--help`):

**Fuentes / colectores**

| Flag | Qué hace | Default |
|---|---|---|
| `--simulate` | ataques sintéticos (demo sin root ni Linux) | off |
| `--sniff` · `--iface IF` | captura de paquetes (root + scapy) | off |
| `--no-authlog` · `--authlog` · `--authlog-path RUTA` | control del colector de autenticación (journald por defecto; `--authlog` fuerza fichero) | journald |
| `--honeypot P1,P2` · `--honeypot-host H` | puertos-trampa | off · `0.0.0.0` |
| `--netwatch` · `--netwatch-interval S` | procesos↔IP vía `/proc` | off · 10 s |
| `--dnswatch` | exfiltración por DNS (T1048.003) | off |
| `--beacon` · `--beacon-interval S` | beaconing C2 (T1071) | off · 5 s |
| `--execwatch` · `--execwatch-interval S` | exec sospechoso / reverse shells (T1059) | off · 2 s |
| `--rootcheck` · `--rootcheck-interval S` | persistencia / rootkits | off · 60 s |

**Enriquecimiento e inteligencia**

| Flag | Qué hace | Default |
|---|---|---|
| `--rdns` | DNS inverso en background | off |
| `--oui CSV` | fabricante por MAC (prefijo OUI) | — |
| `--geo MMDB` | geolocalización con GeoLite2-City | — |
| `--kev-cache RUTA` · `--kev-update` | feed KEV de CISA (offline-first) | — |
| `--canary u1,u2` | usuarios-cebo → CRITICAL inmediato | — |

**Presentación**

| Flag | Qué hace | Default |
|---|---|---|
| `--web` · `--web-host H` · `--web-port P` | dashboard web (WebSocket + mapa) | off · `127.0.0.1` · 8787 |
| `--web-token TOK` | Bearer obligatorio para el dashboard | — |

**Respuesta y alertas**

| Flag | Qué hace | Default |
|---|---|---|
| `--assess` · `--assess-window S` | modo examen → corrección en bucle | off · 15 s |
| `--block-threshold N` | score a partir del cual se bloquea | 70 |
| `--respond-live` | bloqueo REAL en firewall (sin él: dry-run) | off |
| `--allow IP/CIDR` | nunca bloquear (repetible) | — |
| `--alert-webhook URL` · `--alert-min-sev N` | webhook por alerta | — · 3 (HIGH) |
| `--digest-webhook URL` · `--digest-interval-h H` | resumen periódico al webhook | — · 24 h |

**Forense**

| Flag | Qué hace | Default |
|---|---|---|
| `--db RUTA` | event store SQLite (tamper-evident) | `centinel.db` |
| `--report` | informe forense y salir | — |
| `--verify-log` | verifica la cadena HMAC (exit 0=intacta, 2=manipulada) | — |

**Operación**

| Flag | Qué hace | Default |
|---|---|---|
| `--user U` · `--no-drop` · `--force-drop` | drop de privilegios tras abrir recursos | `nobody` |
| `--install-service` · `--uninstall-service` · `--status-service` | servicio systemd | — |
| `--early-boot` | con `--install-service`: arranque a nivel sysinit, antes que todos los servicios | off |
| `--allow-overlap` | permitir múltiples instancias | off |
| `--ack-baseline` | aceptar el estado actual como baseline limpia | — |
| `--baseline-dir DIR` | baselines firmadas (HMAC) del rootcheck | — |
| `--maintenance-grace S` · `--maintenance-off` | gracia tras arranque / modo paranoico | 90 s |
| `--doctor` · `--no-doctor` | diagnóstico previo (solo / omitir) | on |

## Tests y CI

Suite de regresión centrada en las defensas de seguridad (anti-spoofing,
procedencia journald, salvaguardas del firewall, anti-DoS de la correlación):

```bash
pip install -e ".[test]"
pytest -q
```

Cada push y PR corre la suite en GitHub Actions sobre Python 3.10–3.13, dos
veces: sin ningún extra (verifica las 0 dependencias obligatorias) y con
`[all]` instalado (verifica las ramas con rich/scapy/fastapi).

## Documentación

| Documento | Contenido |
|---|---|
| [CHANGELOG.md](CHANGELOG.md) | Historial de cambios por versión (SemVer) |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Plan de versiones v0.3 → v1.0 |
| [docs/AUDIT.md](docs/AUDIT.md) | Auditoría técnica: fortalezas, deuda y prioridades |
| [docs/DEFENSA_IA.md](docs/DEFENSA_IA.md) | Defensa contra hacking asistido por IA |
| [SECURITY_AUDIT.md](SECURITY_AUDIT.md) | Auditoría de seguridad del propio código (13 hallazgos) |
| [AUDIT_HONEYPOT.md](AUDIT_HONEYPOT.md) | Endurecimiento del honeypot |
| [AUDIT_AI_DEFENSE.md](AUDIT_AI_DEFENSE.md) | Revisión de la capa anti-IA |

## Licencia

MIT.
