"""Capa de IA OPCIONAL de CENTINEL (local y enchufable).

Fiel al 0-deps y a la privacidad: la IA **asiste y explica**, nunca decide ni
auto-actúa, y nunca sale de la máquina. Todo lo de aquí funciona solo con la
biblioteca estándar; si no hay un Ollama local corriendo, CENTINEL funciona
igual (se degrada a un resumen-plantilla local, no se tumba).
"""
from .explainer import (
    OllamaExplainer,
    build_prompt,
    build_batch_prompt,
    template_summary,
    parse_response,
    is_local_url,
)

__all__ = [
    "OllamaExplainer",
    "build_prompt",
    "build_batch_prompt",
    "template_summary",
    "parse_response",
    "is_local_url",
]
