# CENTINEL vs. el antivirus moderno — comparativa + FODA + plan

> Documento estratégico. Objetivo: entender dónde está CENTINEL frente al
> estado del arte en 2026 y qué hace falta para superarlo. No es marketing:
> lo que hoy es una debilidad está marcado como tal.

---

## 1. Cómo funciona el antivirus / EDR moderno (2026)

El "antivirus" clásico murió. Lo que hoy protege un endpoint es un **EDR/XDR**
(Endpoint/Extended Detection & Response) con estas capas:

| Capa | Qué hace | Ejemplo comercial |
|------|----------|-------------------|
| **Firmas** | Hash/YARA contra malware conocido | ClamAV, Defender |
| **Heurística estática** | Analiza el binario sin ejecutarlo (entropía, imports, secciones PE/ELF) | Bitdefender, Kaspersky |
| **Sandboxing** | Detona el fichero en una VM aislada y observa | CrowdStrike, Defender ATP |
| **Análisis de comportamiento** | Hooks en kernel/user-space; observa syscalls, árbol de procesos, red | SentinelOne, CrowdStrike Falcon |
| **ML en endpoint** | Modelo entrenado clasifica proceso "bueno/malo" en vivo | SentinelOne, Elastic |
| **EDR / telemetría** | Envía eventos a la nube, correlación cross-host, threat hunting | Falcon, MDE, Wazuh |
| **Cloud reputation** | Consulta hash/IP/dominio contra la nube del vendor | todos |
| **Respuesta** | Aísla el host, mata proceso, revierte cambios (rollback) | SentinelOne (rollback), Falcon |
| **Firmado/self-protection** | El agente se protege de ser matado/deshabilitado | todos los EDR serios |

### Los grandes, en una frase
- **Microsoft Defender** — gratis, integrado en Windows, ML + nube enorme, telemetría masiva. El estándar de facto.
- **CrowdStrike Falcon** — agente ligero, todo en la nube, líder en threat hunting y respuesta. Caro, empresarial.
- **SentinelOne** — fuerte en comportamiento + rollback autónomo (deshace ransomware). Empresarial.
- **Bitdefender / Kaspersky** — mejores tasas de detección en tests independientes (AV-TEST, AV-Comparatives). Consumer + enterprise.
- **ClamAV** — open-source, **solo firmas**. Bueno para escaneo de correo/ficheros, débil contra amenazas nuevas.
- **Wazuh** — open-source, HIDS + SIEM. Lo más cercano a CENTINEL en filosofía (reglas, logs, correlación), pero pesado y orientado a flota corporativa.

---

## 2. Dónde encaja CENTINEL

CENTINEL **no es un antivirus** — es un **NIDS/HIDS de comportamiento** en
tiempo real, en Python, sin firmas y sin nube. Compite en la franja de
**detección + respuesta ligera en un solo host Linux**, no en escaneo de
ficheros. Es más honesto compararlo con Wazuh o Suricata que con Defender.

### Tabla comparativa

| Capacidad | CENTINEL | Defender | Falcon/S1 | ClamAV | Wazuh |
|-----------|:--------:|:--------:|:---------:|:------:|:-----:|
| Firmas de fichero | ❌ | ✅ | ✅ | ✅ | ⚠️ |
| Heurística estática de binario | ❌ | ✅ | ✅ | ⚠️ | ❌ |
| Sandboxing | ❌ | ✅ | ✅ | ❌ | ❌ |
| Análisis de comportamiento en vivo | ✅ | ✅ | ✅ | ❌ | ✅ |
| Detección de red (sniff/C2/DNS-exfil) | ✅ | ⚠️ | ✅ | ❌ | ⚠️ |
| Anti-hijacking (LD_PRELOAD/PATH/ptrace) | ✅ | ⚠️ | ✅ | ❌ | ❌ |
| Fileless / LOLBins / memfd | ✅ | ✅ | ✅ | ❌ | ⚠️ |
| Browser hijack (extensiones/homepage) | ✅ | ⚠️ | ⚠️ | ❌ | ❌ |
| Bootkit / kernel module watch | ✅ | ✅ | ✅ | ❌ | ⚠️ |
| Honeypot integrado | ✅ | ❌ | ❌ | ❌ | ❌ |
| Log tamper-evident (HMAC chain) | ✅ | ⚠️ | ✅ | ❌ | ⚠️ |
| Early-boot (antes que el malware) | ✅ | ✅ | ✅ | ❌ | ❌ |
| Respuesta activa (firewall) | ✅ | ✅ | ✅ | ❌ | ✅ |
| Rollback / deshacer daño | ❌ | ⚠️ | ✅ | ❌ | ❌ |
| ML en endpoint | ❌ | ✅ | ✅ | ❌ | ⚠️ |
| Correlación cross-host / SIEM | ❌ | ✅ | ✅ | ❌ | ✅ |
| Cloud reputation (hash/IP/dominio) | ⚠️ KEV | ✅ | ✅ | ✅ | ⚠️ |
| Auto-protección del agente | ⚠️ | ✅ | ✅ | ❌ | ⚠️ |
| Coste | €0 | €0 | €€€ | €0 | €0 |
| Peso / footprint | Muy ligero | Medio | Ligero | Ligero | Pesado |
| Auditable (lees todo el código) | ✅ | ❌ | ❌ | ✅ | ✅ |

✅ = sólido · ⚠️ = parcial/básico · ❌ = no existe

---

## 3. Análisis FODA

### 💪 Fortalezas
- **Comportamiento sin firmas** → detecta amenazas nuevas/zero-day que el AV de firmas no ve.
- **Cobertura de vectores modernos** poco atendidos por consumer AV: LD_PRELOAD, ptrace, DNS-exfil, beaconing C2, memfd/fileless, browser hijack.
- **Log tamper-evident (HMAC chain)** — forense confiable; muchos AV no garantizan esto.
- **Early-boot systemd** — vigila antes de que arranque el malware persistido.
- **Auditable y €0** — todo el código es legible; sin caja negra, sin telemetría a terceros.
- **Muy ligero** — Python asyncio, 0 dependencias obligatorias, corre en un host modesto o WSL.
- **Clasificadores puros y testeados** (221 tests) — la lógica de detección es determinista y verificable.

### 🩹 Debilidades
- **Sin firmas ni escaneo de ficheros** — no detecta malware conocido en disco antes de ejecutarse.
- **Sin ML** — todo es heurística de reglas; un atacante que conoce las reglas puede evadirlas.
- **Solo Linux** (Windows vía WSL, no protege Windows nativo).
- **Sin rollback** — detecta y bloquea, pero no deshace el daño (cifrado ransomware, ficheros borrados).
- **Un solo host** — sin correlación entre máquinas ni consola central.
- ~~**Auto-protección débil**~~ — CERRADO: el watchdog (`--install-watchdog`) revive CENTINEL si lo matan/deshabilitan/enmascaran y alerta CRITICAL.
- **Polling, no hooks en kernel** — hay una ventana entre el escaneo y el evento; un proceso efímero puede aparecer y morir entre barridos.
- **Reputación limitada** — solo KEV de CISA; sin feeds de IP/dominio/hash maliciosos en vivo.

### 🚪 Oportunidades
- **Nicho open-source de comportamiento para Linux** — ClamAV es solo firmas, Wazuh es pesado. Hay hueco para algo ligero, moderno y auditable.
- **eBPF** — reemplazar el polling de `/proc` por tracing de syscalls en kernel: elimina la ventana ciega y baja el coste. Es la tecnología que usan Falcon y Elastic hoy.
- **YARA como plugin opcional** — añadir firmas sin volverse pesado, cubriendo la mayor debilidad.
- **Feeds de threat intel gratuitos** — AbuseIPDB, Feodo Tracker, URLhaus, ThreatFox: enriquecer IPs/dominios sin coste.
- **Modo flota ligero** — que varios CENTINEL reporten a un colector central (el `--digest-webhook` ya es la semilla).
- **Integración con el ecosistema** — exportar a formato Sigma/ECS para caber en SIEMs existentes.

### ⚠️ Amenazas
- **Evasión de reglas** — al ser heurística abierta y auditable, el atacante puede leer el código y diseñar payloads que no crucen los umbrales.
- **Kill del agente** — sin watchdog, un atacante con root mata CENTINEL y sigue.
- **Falsos positivos** — heurística agresiva sin ML genera ruido; el operador aprende a ignorar alertas (fatiga).
- **Los gigantes son gratis y buenos** — Defender viene con Windows y es excelente; el valor de CENTINEL debe estar en Linux/servidores/auditabilidad, no en competir de frente en el desktop.
- **Mantenimiento** — un IDS necesita reglas actualizadas; sin comunidad/feeds, envejece.

---

## 4. Plan de mejora — para superar al AV medio en su nicho

Ordenado por relación **impacto / esfuerzo**. No hace falta hacerlo todo:
las 3 primeras cierran las debilidades más caras.

### 🥇 Alto impacto, esfuerzo medio
1. ✅ **Watchdog + auto-resurrección** — HECHO (`--watchdog`/`--install-watchdog`). Unidad systemd hermana `Restart=always` que revive CENTINEL si lo matan, deshabilitan o enmascaran, y alerta CRITICAL al hacerlo (T1562.001). Cierra "kill del agente".
2. **YARA opcional** (`--yara <reglas>`) — escaneo de ficheros en directorios efímeros (`/tmp`, `/dev/shm`, uploads) y de la memoria de procesos sospechosos. Cierra "sin firmas" sin engordar el core.
3. **Threat intel en vivo** — colector que descarga y cachea Feodo/URLhaus/ThreatFox (como ya se hace con KEV) y enriquece cada IP/dominio. Cierra "reputación limitada".

### 🥈 Alto impacto, esfuerzo alto
4. **Backend eBPF** — sustituir polling de `/proc` por tracepoints de kernel (`execve`, `ptrace`, `connect`, `bpf`). Elimina la ventana ciega y es la base técnica de los líderes. Grande, pero es el salto de liga.
5. **Scoring con ML ligero** — un modelo pequeño (árbol/regresión) sobre las features que ya extraemos (entropía DNS, CV de beacon, permisos de extensión). Reduce falsos positivos y hace la evasión más difícil que leer if/else.

### 🥉 Mejora incremental
6. **Modo flota** — varios agentes → un colector; el `--digest-webhook` ya apunta ahí.
7. **Export Sigma/ECS** — para integrar en SIEMs y no vivir aislado.
8. **Rollback básico** — snapshot de ficheros en directorios críticos + restauración ante patrón ransomware (cifrado masivo). Difícil, pero es el diferencial de SentinelOne.

### La tesis
CENTINEL **no va a ganarle a Defender en el desktop de Windows** — ese
combate está perdido y no es su terreno. Donde sí puede ser **el mejor de su
clase** es en: *IDS de comportamiento, open-source, ligero, auditable y
sin nube, para servidores y hosts Linux*. Cerrando watchdog + YARA opcional +
threat intel en vivo, cubre sus tres agujeros más caros y deja atrás a ClamAV
(solo firmas) y a Wazuh (pesado) en ese nicho concreto.
