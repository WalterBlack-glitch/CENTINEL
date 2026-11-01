"""Estado en memoria de la app y construcción de la foto de contexto (`Ctx`).

Siempre hay una sesión: si no hay ninguna con nombre activa, se usa la sesión
implícita `global` (a la que se vuelve con `session close`). El objetivo y los
hallazgos viven en la sesión activa.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import session as sess
from . import tools
from .config import Config
from .context import Ctx
from .history import RunLog

GLOBAL = "global"


@dataclass
class AppState:
    cfg: Config
    session: sess.Session = field(default_factory=lambda: sess.Session(GLOBAL))
    is_named: bool = False               # True si la sesión activa tiene nombre
    runlog: RunLog = field(default_factory=RunLog)
    last_capture: dict | None = None
    root: bool = field(default_factory=tools.is_root)
    tool_status: dict = field(default_factory=tools.tool_status)
    # Puente opt-in al event store firmado del IDS (apagado por defecto).
    to_store: bool = False
    db_path: str = "centinel.db"

    # --- sesión ---
    def use_session(self, s: sess.Session, *, named: bool = True) -> None:
        self.session = s
        self.is_named = named

    def close_session(self) -> None:
        """Vuelve a la sesión global (sin persistir la global en disco)."""
        self.session = sess.Session(GLOBAL)
        self.is_named = False

    def persist(self) -> None:
        """Guarda la sesión activa si tiene nombre (la global es efímera)."""
        if self.is_named:
            sess.save(self.session)

    # --- contexto para el menú ---
    def ctx(self) -> Ctx:
        s = self.session
        return Ctx(
            has_target=bool(s.target),
            is_root=self.root,
            active_session=self.is_named,
            sessions_exist=bool(sess.listing()),
            has_findings=bool(s.findings),
            has_capture=self.last_capture is not None,
            iface_set=bool(self.cfg.interface),
            ffuf_ready=self.tool_status.get("ffuf", False),
            dir_wordlist=bool(self.cfg.wordlist_dir),
            sub_wordlist=bool(self.cfg.wordlist_sub),
            tcpdump_ready=self.tool_status.get("tcpdump", False),
        )
