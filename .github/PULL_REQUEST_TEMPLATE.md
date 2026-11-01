<!-- Gracias por contribuir a CENTINEL. Lee CONTRIBUTING.md si no lo has hecho. -->

## Qué cambia y por qué

<!-- El qué y, sobre todo, el porqué de seguridad. No "fix bug". -->

## Tipo

- [ ] Fix
- [ ] Capa / colector nuevo
- [ ] Mejora de una capa existente
- [ ] Documentación
- [ ] Refactor / interno

## Checklist

- [ ] `pytest -q` pasa **sin extras** y con `[all]` instalado
- [ ] Hay tests nuevos que atacan la **lógica pura** (no solo mocks)
- [ ] Sin dependencias pip obligatorias nuevas (lo pesado va como extra opcional)
- [ ] Subprocess seguro (rutas absolutas, args como lista, sin `shell=True`)
- [ ] El contenido de origen hostil se escapa/sanea antes de pintarse
- [ ] Documentación actualizada (README / CHANGELOG / ARCHITECTURE / ROADMAP según aplique)

## Cómo se probó

<!-- Simulado vs real. Si depende de nmap/PowerShell/tcpdump, di en qué SO se probó de verdad. -->
