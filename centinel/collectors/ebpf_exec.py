"""EbpfExec: captura de execve por tracepoint de kernel (eBPF), sin ventana ciega.

El `--execwatch` clásico hace POLLING de /proc: entre dos barridos un proceso
ultra-efímero puede nacer y morir sin ser visto. Este colector cierra esa
ventana usando **eBPF**: engancha un kprobe al syscall `execve` y recibe CADA
ejecución en el instante en que ocurre, con su `argv` completo, directamente
desde el kernel. Es la misma técnica que usan CrowdStrike Falcon y Elastic.

El VEREDICTO es idéntico al de execwatch: reutiliza `execwatch.classify` (misma
lógica pura de reverse shells / curl|sh / exec efímero / RCE). Lo que cambia es
la FUENTE — kernel en tiempo real en vez de /proc muestreado.

Capa **opcional** y degradante:
  - Requiere Linux con kernel BPF + `bcc` (BPF Compiler Collection) instalado:
    `apt install bpfcc-tools python3-bpfcc` (o el paquete equivalente).
  - Requiere root (o CAP_BPF+CAP_PERFMON).
  - No corre en Windows ni WSL1. En WSL2 necesita un kernel con BPF.
  - Si algo falta, `available()` devuelve False y CENTINEL sigue con el
    execwatch por polling (o sin él). El core no gana dependencias.

Si `--ebpf` está activo y disponible, SUPLANTA a `--execwatch` (para no
duplicar alertas): en app.py no se añade el polling si el eBPF arrancó.

MITRE: T1059 (Command and Scripting Interpreter), cobertura de execución.
"""
from __future__ import annotations

import asyncio
import os

from ..core import Severity, ThreatEvent
from .base import Collector
from .execwatch import classify, _clean

# Programa BPF: engancha execve, emite un evento por cada argumento de argv
# (más el filename), y un marcador de fin. El lado Python reensambla el argv.
_BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define ARGSIZE  160
#define MAXARG   24

struct data_t {
    u32 pid;
    u32 ppid;
    int is_end;
    char comm[TASK_COMM_LEN];
    char arg[ARGSIZE];
};

BPF_PERF_OUTPUT(events);

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    struct data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    data.pid  = bpf_get_current_pid_tgid() >> 32;
    data.ppid = task->real_parent->tgid;
    data.is_end = 0;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // filename como primer "arg"
    bpf_probe_read_user(&data.arg, sizeof(data.arg), (void *)filename);
    events.perf_submit(ctx, &data, sizeof(data));

    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &__argv[i]);
        if (argp == NULL) goto done;
        bpf_probe_read_user(&data.arg, sizeof(data.arg), (void *)argp);
        events.perf_submit(ctx, &data, sizeof(data));
    }

done:
    data.is_end = 1;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""


def build_info(comm: str, filename: str, argv: list[str]) -> dict:
    """Construye el dict que espera `classify` a partir del evento eBPF.

    Pura y testeable: el cmdline es el argv unido; el exe es el filename
    (primer arg si no hay filename).
    """
    comm = _clean(comm, 64)
    filename = _clean(filename, 512)
    parts = [_clean(a, 512) for a in argv if a]
    cmdline = " ".join(parts) if parts else filename
    exe = filename or (parts[0] if parts else "")
    return {"comm": comm, "exe": exe, "cmdline": cmdline}


def _parent_comm(ppid: int) -> str:
    try:
        with open(f"/proc/{ppid}/comm", "r") as f:
            return f.read().strip()
    except OSError:
        return ""


class EbpfExecCollector(Collector):
    name = "ebpf"

    def __init__(self, bus) -> None:
        super().__init__(bus)
        self._bpf = None
        # Reensamblado por pid: {pid: {"comm":.., "filename":.., "argv":[..]}}
        self._pending: dict[int, dict] = {}

    def available(self) -> bool:
        if os.name != "posix":
            return False
        if os.geteuid() != 0:
            print("[ebpf] requiere root (o CAP_BPF+CAP_PERFMON); capa desactivada.")
            return False
        try:
            from bcc import BPF  # noqa: F401
        except ImportError:
            print("[ebpf] bcc no instalado "
                  "(apt install python3-bpfcc); capa desactivada.")
            return False
        return True

    async def run(self) -> None:
        if not self.available():
            return
        loop = asyncio.get_event_loop()
        try:
            from bcc import BPF
            self._bpf = BPF(text=_BPF_PROGRAM)
            fnname = self._bpf.get_syscall_fnname("execve")
            self._bpf.attach_kprobe(event=fnname, fn_name="syscall__execve")
        except Exception as exc:   # noqa: BLE001
            print(f"[ebpf] no pude cargar el programa BPF: {exc}")
            return

        def _cb(cpu, data, size):
            ev = self._bpf["events"].event(data)
            self._on_event(ev, loop)

        self._bpf["events"].open_perf_buffer(_cb, page_cnt=64)
        print("[ebpf] tracepoint execve activo (sin ventana ciega)")
        # perf_buffer_poll es bloqueante -> a un thread.
        while True:
            try:
                await asyncio.to_thread(self._bpf.perf_buffer_poll, 500)
            except Exception:  # noqa: BLE001
                await asyncio.sleep(1.0)

    def _on_event(self, ev, loop) -> None:
        pid = int(ev.pid)
        try:
            arg = ev.arg.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            arg = ""
        if not ev.is_end:
            slot = self._pending.setdefault(
                pid, {"comm": ev.comm.decode("utf-8", "replace"),
                      "ppid": int(ev.ppid), "filename": arg, "argv": []})
            # El primer arg es el filename; el resto, argv.
            if slot["argv"] or slot["filename"] != arg:
                slot["argv"].append(arg)
            return
        # Marcador de fin: clasifica y limpia.
        slot = self._pending.pop(pid, None)
        if not slot:
            return
        info = build_info(slot["comm"], slot["filename"], slot["argv"])
        flags, sev = classify(info, parent_comm=_parent_comm(slot["ppid"]))
        if not flags or sev < int(Severity.HIGH):
            return
        msg = "; ".join(flags)
        event = ThreatEvent(
            kind="ebpf_exec", severity=Severity(sev),
            message=f"{msg} — {info['exe']} (pid {pid}, eBPF)",
            tags={"exec", "ebpf", "T1059"})
        asyncio.run_coroutine_threadsafe(self.emit(event), loop)
