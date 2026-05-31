# 🛰 Centinela

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
> ves es la de tu gateway/router — Centinela lo etiqueta como `scope=wan` y no
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
python -m centinela --simulate

# Modo EXAMEN: monitorea, prioriza lo más grave, lo corrige y sigue.
python -m centinela --simulate --assess          # dry-run: dice qué bloquearía
sudo centinela --assess --respond-live \
     --block-threshold 70 --allow 1.2.3.4         # bloqueo REAL en firewall

# Dashboard web en vivo (http://127.0.0.1:8787) con mapa geo:
pip install -e ".[web,geo]"
python -m centinela --simulate --web
sudo centinela --sniff --web --web-host 0.0.0.0 \
     --geo /ruta/GeoLite2-City.mmdb         # plotea el origen en el mapa

# Producción en un servidor Linux:
sudo centinela --sniff --iface eth0           # logs de auth + captura de paquetes
centinela --authlog-path /var/log/secure      # RHEL/CentOS
centinela --oui oui.csv                        # resolver fabricante por MAC
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

Todo fluye como `ThreatEvent` (ver `centinela/core.py`). El bus es async,
sin dependencias. Añadir una fuente nueva = un archivo en `collectors/` que
herede de `Collector`.

## Seguridad

Centinela procesa **input hostil** (un atacante remoto controla parcialmente
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
  centinela --sniff --iface eth0  # sin sudo
  ```
- **Anti-inyección de terminal:** se eliminan secuencias de escape ANSI y se
  escapa el markup de `rich` en todo string derivado del atacante.
- **Subprocess seguro:** rutas absolutas + `PATH` controlado (sin hijacking),
  args como lista (sin `shell=True`).
- **Persistencia:** SQLite parametrizado (sin SQLi), DB con permisos `0600`,
  WAL y commits por lote.

## Modo examen y respuesta activa

`--assess` convierte Centinela en un bucle de **examen → corrección**:

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

## Tests

Suite de regresión centrada en las defensas de seguridad (anti-spoofing,
procedencia journald, salvaguardas del firewall, anti-DoS de la correlación):

```bash
pip install -e ".[test]"
pytest -q
```

## Licencia

MIT.
