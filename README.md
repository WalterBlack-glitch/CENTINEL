# 🛰 Centinela

Rastreo **multicapa** de amenazas en tiempo real para servidores Linux. Va más
allá de "contar intentos de fuerza bruta": correlaciona varias señales por
actor y muestra **de dónde proviene** cada amenaza con IP, MAC (cuando es
visible) y fabricante del dispositivo.

## Por qué multicapa

El valor no está en un solo detector, sino en cómo se combinan las capas:

| Capa | Qué hace | Aporte único |
|------|----------|--------------|
| **1. Colectores** | `auth.log`, sniffer de paquetes (scapy), ARP, simulador | Fuentes pluggables; el sniffer ve la **MAC real** de hosts en tu LAN |
| **2. Enriquecimiento** | IP→MAC (tabla ARP), MAC→fabricante (OUI), rDNS, LAN/WAN | Contexto accionable sin depender de APIs externas |
| **3. Correlación** | Score por actor en ventana deslizante | Detecta fuerza bruta, **password spraying**, **port scan** y **compromiso** (login OK tras N fallos) |
| **4. Persistencia** | Event store en SQLite | Auditoría/forense; `top_actors()` |
| **5. Presentación** | Dashboard en vivo en terminal (`rich`) | Ranking de actores + feed coloreado por severidad |

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

## Roadmap

- [ ] Capa de presentación web (FastAPI + WebSocket) con mapa geo
- [ ] Hook de threat-intel (AbuseIPDB / listas) opcional
- [ ] Respuesta activa: auto-`iptables`/`nft` drop sobre score crítico
- [ ] Exportador para Prometheus/Grafana

## Licencia

MIT.
