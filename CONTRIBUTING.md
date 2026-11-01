# Contribuir a CENTINEL

Gracias por mirar el código. CENTINEL es un IDS multicapa con tres caras (IDS
Linux, escritorio Windows y modo RECON) construido sobre unas pocas reglas
firmes. Respetarlas mantiene el proyecto coherente.

## Puesta en marcha

```bash
git clone https://github.com/WalterBlack-glitch/CENTINEL.git
cd CENTINEL
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[all,test]"                    # todo + pytest
```

Requiere **Python 3.10+**. No hay dependencias obligatorias: los extras (`ui`,
`sniff`, `web`, `geo`, `yara`) son opcionales y el núcleo funciona sin ninguno.

Comprobación rápida de que todo arranca:

```bash
python -m centinel --simulate       # demo sin root ni Linux
python -m centinel --doctor         # diagnóstico del entorno
```

## Tests

```bash
pytest -q                 # suite completa (712 tests, ~8 s)
pytest -q tests/test_recon_parse.py       # un fichero
pytest -q -k signature                    # por nombre
```

Toda contribución debe:

1. **Pasar la suite** sin extras instalados **y** con `[all]` (así corre la CI).
2. **Traer tests** para el comportamiento nuevo, atacando la **lógica pura**
   directamente (ver convención abajo). No subas cobertura solo con mocks de
   `subprocess`: han ocultado bugs reales (firmas que nunca se verificaron).
   Cuando una capa depende de una herramienta externa (nmap, PowerShell,
   tcpdump), prueba el parseo/clasificación con salida real capturada, no solo
   con una respuesta inventada.

La CI (`.github/workflows/ci.yml`) corre en Python 3.10–3.13, hace `compileall`
y repite la suite con y sin extras.

## Convenciones (no negociables)

- **Lógica pura separada del I/O.** Parte cada módulo en un cerebro
  determinista y testeable (parsear, clasificar, decidir — funciones puras) y
  unas manos (leer disco, subprocess, sockets). Patrón de referencia:
  `build_nmap_cmd` (pura) vs `run_nmap` (I/O); `classify_modules` (pura) vs
  `enumerate_module_candidates` (I/O). Los tests atacan la parte pura.
- **0 dependencias pip obligatorias.** Nada nuevo en `dependencies`. Si una
  función necesita algo pesado, va como *extra* opcional e `import` perezoso, y
  la capa **degrada con un mensaje claro** si no está.
- **Degradar, no tumbar.** Un fallo de una capa (tool ausente, config rota, sin
  permisos) se desactiva con aviso; nunca derriba el proceso entero.
- **Subprocess seguro.** Rutas absolutas, `PATH` controlado, args como lista,
  **nunca `shell=True`**. No construyas comandos por concatenación de strings.
- **El contenido hostil se escapa.** Username SSH, rDNS, nombre de proceso,
  versión de servicio: todo lo controla parcialmente el atacante. Escapa antes
  de pintarlo (`html.escape` en HTML, anti CSV-injection, saneado de ANSI/markup
  de `rich`) y sanea a charset seguro antes de meterlo en un comando copiable.
- **Identidad sin PID.** Para historial/diff la identidad es `tipo|nombre|ruta`
  (o `tipo|puerto|proto|url|fuzz` en recon), nunca el PID.
- **Sin exploits ni evasión en RECON.** El modo recon es para objetivos
  **autorizados**: inventaría, no ataca. No se aceptan módulos de explotación ni
  de evasión de detección.

## Añadir una fuente nueva al IDS

Un colector nuevo = un archivo en `centinel/collectors/` que herede de
`Collector` ([`collectors/base.py`](centinel/collectors/base.py)) y emita
`ThreatEvent` ([`core.py`](centinel/core.py)) al bus. Ponle su flag en
`app.py`, su fila en la tabla de flags del README y sus tests. Mira
[ARCHITECTURE.md](ARCHITECTURE.md) para el mapa completo.

## Estilo de commits

- Mensajes en **español**, imperativos y concretos, describiendo el *qué* y el
  *porqué de seguridad* (no «fix bug»). Mira `git log` para el tono.
- Un commit = un cambio coherente con sus tests.
- No subas artefactos: `*.db`, `*.pyc`, `.venv`, informes generados
  (`centinel-*.html`). El `.gitignore` ya los cubre.

## Documentación

Si tu cambio altera comportamiento visible, actualiza en el mismo PR:

| Dónde | Cuándo |
|-------|--------|
| [README.md](README.md) | flag nuevo, capa nueva, cambio de uso |
| [CHANGELOG.md](CHANGELOG.md) | siempre que haya cambio visible (SemVer) |
| [ARCHITECTURE.md](ARCHITECTURE.md) | módulo nuevo o responsabilidad que cambia |
| [RECON.md](RECON.md) | cambios en el modo recon |
| [docs/ROADMAP.md](docs/ROADMAP.md) · [ROADMAP.md](ROADMAP.md) | marca lo hecho |

## Seguridad

¿Encontraste un fallo de seguridad **en CENTINEL mismo**? No abras un issue
público: escribe al autor. Las auditorías del propio código están en
[SECURITY_AUDIT.md](SECURITY_AUDIT.md), [AUDIT_HONEYPOT.md](AUDIT_HONEYPOT.md) y
[AUDIT_AI_DEFENSE.md](AUDIT_AI_DEFENSE.md).

## Licencia

Al contribuir aceptas que tu aporte se publique bajo la licencia [MIT](LICENSE)
del proyecto.
