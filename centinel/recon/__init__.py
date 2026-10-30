"""Modo recon de CENTINEL — orquestador de reconocimiento consciente del contexto.

Envuelve `nmap`, `ffuf` y un sniffer pasivo (`tcpdump`) bajo una TUI con
sesiones, temas, reporte e historial. Misma filosofía que el resto de CENTINEL:
0 dependencias pip — las herramientas son binarios externos que se invocan por
subprocess; la lógica de decisión/parseo es pura y testeable, separada del I/O.
Si una herramienta falta, la función correspondiente degrada con un mensaje
claro en vez de romper.

Es el complemento ofensivo/de reconocimiento del CENTINEL defensivo (IDS): el
IDS vigila TU host; el recon inventaria un objetivo autorizado.

Uso: `python -m centinel --recon`  ·  `python -m centinel.recon`
"""
__all__ = ["tui"]
