# 🛰 Centinel

Rastreo **multicapa** de amenazas en tiempo real para servidores Linux. Va más
allá de "contar intentos de fuerza bruta": correlaciona varias señales por
actor y muestra **de dónde proviene** cada amenaza con IP, MAC (cuando es
visible) y fabricante del dispositivo.

## Por qué multicapa

El valor no está en un solo detector, sino en cómo se combinan las capas:

| Capa | Qué hace | Aporte único |
|------|----------|--------------|
| **1. Colectores** | **journald** (por defecto), `auth.log`, sniffer (scapy), ARP, simulador | Fuentes pluggables; journald aporta **procedencia confiable** y el sniffer ve la **MAC real** de hosts en tu LAN |
| **2. Enriquecimiento** | IP→MAC (tabla ARP), MAC→fabricante (OUI), rDNS, LAN/WAN | Contexto accionable sin depender de APIs externas |
| **3. Correlación** | Score por actor en ventana deslizante | Detecta fuerza bruta, **password spraying**, **port scan** y **compromiso** (login OK tras N fallos) |
| **4. Persistencia** | Event store en SQLite | Auditoría/forense; `top_actors()` |
| **5. Presentación** | Dashboard en terminal (`rich`), **modo examen**, **dashboard web** (FastAPI+WebSocket+mapa) | Ranking de actores + feed; mapa mundial con geolocalización |
| **6. Respuesta activa** | Bloqueo en firewall (`nft`/`iptables`) con dry-run | Corrige automáticamente al superar el umbral de score |

> ⚠️ **Sobre la MAC:** una MAC de origen solo es visible para dispositivos en
> tu mismo dominio de broadcast (tu LAN). Para tráfico de internet, la MAC que
> ves es la de tu gateway/router — Centinel lo etiqueta como `scope=wan` y no
> pretende lo contrario. Es una limitación física de Ethernet/IP, no del tool.

## Instalación

```bash
pip install -e ".[all]"      # rich + scapy
# o mínimo:
pip install -e ".[ui]"       # solo dashboard
```

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
`--authlog-path`, `--oui`, `--db`.

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

Centinel procesa **input hostil** (un atacante remoto controla parcialmente
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

`--assess` convierte Centinel en un bucle de **examen → corrección**:

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

- [x] Capa de presentación web (FastAPI + WebSocket) con mapa geo
- [ ] Hook de threat-intel (AbuseIPDB / listas) opcional
- [x] Respuesta activa: auto-`iptables`/`nft` drop sobre score crítico
- [x] journald estructurado (elimina el spoofing de logs de raíz)
- [ ] Exportador para Prometheus/Grafana

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

La defensa más avanzada de Centinel: en vez de razonar "por IP", agrupa IPs
distintas en un mismo **adversario** según su huella de comportamiento —el
diccionario de usuarios objetivo, las técnicas y el perfil de temporización
compartidos. Un atacante con IA reparte su campaña entre decenas de IPs para
diluirse; al reconocer la huella común, Centinel las atribuye a una sola
entidad y te deja defenderte de la campaña entera, no IP por IP.

Cuando ≥5 IPs comparten diccionario/TTPs → `alert_actor_atribuido` y aparecen
agrupadas en el panel **Adversarios atribuidos** del dashboard web. El algoritmo
es barato y acotado (índice invertido + Jaccard, sin pairwise O(n²); expulsión
LRU O(1): ~5 µs/evento incluso bajo un atacante que rota diccionarios).

### Feed CVE de CISA KEV (gratis, sin API key)

Centinel cruza los CVEs detectados contra el catálogo **KEV de CISA** (Known
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
distribuidos** (cada IP bajo el umbral) y con temporización adaptativa. Centinel
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

Detectar no basta. Ante un compromiso (o intento), Centinel adjunta a la alerta
un **playbook accionable** — qué comprobar, qué comando ejecutar y cómo cerrar el
agujero. Aparece en un cajón **🛠️ Cómo remediar** del dashboard web (con botón
*copiar* por comando) y en un panel propio de la terminal.

Cada tipo de amenaza tiene su guía: compromiso de cuenta, fuerza bruta, spraying,
escaneo, canary, timing robótico, credential stuffing, botnet de subred, actor
atribuido, intento de exploit/CVE y hit de honeypot. Los valores interpolados
(IP/usuario) se **sanean a un charset seguro**: aunque el username venga de una
fuente hostil, nunca introduce metacaracteres de shell en un comando copiable.

### Doctor: diagnóstico y arreglo previo

Antes de arrancar, Centinel revisa las causas habituales de fallo según los
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

Centinel necesita root **solo** para abrir recursos privilegiados (socket de
captura, lectura de logs, bind de honeypot, `nft`/`iptables`) y **suelta
privilegios** a `nobody` en cuanto los abre. Notas de superficie:

- El **dashboard web** escucha en `127.0.0.1` por defecto y **no tiene auth**: no
  lo expongas con `--web-host 0.0.0.0` sin un proxy con autenticación o un túnel
  SSH. El `doctor` te avisa si lo haces.
- El endpoint **`/api/block`** (controla el firewall) está restringido a
  **loopback**: aunque expongas el dashboard, nadie en la red maneja tu firewall.
- **`--respond-live`** (bloqueo real con `nft`) necesita root sostenido, así que
  requiere `--no-drop`; el `doctor` avisa del conflicto.

## Tests

Suite de regresión centrada en las defensas de seguridad (anti-spoofing,
procedencia journald, salvaguardas del firewall, anti-DoS de la correlación):

```bash
pip install -e ".[test]"
pytest -q
```

## Licencia

MIT.
