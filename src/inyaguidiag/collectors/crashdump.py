"""Colector de volcados de pantallazo azul.

ESTE COLECTOR VIVE FUERA DE online/ Y offline/ A PROPOSITO.

Los demas colectores necesitan una version por modo porque dependen de un
Windows vivo (WMI, servicios, red). Este no: solo abre archivos de una
carpeta que le indica el contexto. Da exactamente igual si esa carpeta
esta en el disco de esta maquina o en el disco averiado que acabamos de
montar desde el USB.

Es la demostracion mas limpia de por que `ScanContext` abstrae las rutas:

    ONLINE   ctx.minidump_dir -> C:\\Windows\\Minidump
    OFFLINE  ctx.minidump_dir -> D:\\Windows\\Minidump   (disco montado)

Mismo codigo, mismos resultados.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from ..core.context import ScanContext, ScanMode
from ..core.minidump import CrashDump, DumpParseError, find_dumps, parse_dump
from ..core.registry import register_collector
from .base import Collector

log = logging.getLogger(__name__)

# Cuantos volcados analizar. Estan ordenados por nombre, que en Windows
# equivale a orden cronologico (formato MMDDYY-NNNNN-NN.dmp), asi que los
# ultimos son los mas recientes y los mas relevantes.
MAX_DUMPS = 12


@register_collector
class CrashDumpCollector(Collector):
    """Lee y decodifica los volcados de pantallazo azul."""

    name = "crashdump"
    provides = "crash.dumps"
    supported_modes = (ScanMode.ONLINE, ScanMode.OFFLINE)
    cost = 3

    def collect(self, ctx: ScanContext) -> Dict[str, Any]:
        paths = find_dumps(ctx.minidump_dir, ctx.memory_dump)

        if not paths:
            return {
                "dumps": [],
                "found": 0,
                "minidump_dir": ctx.minidump_dir,
                "dir_exists": ctx.path_exists(ctx.minidump_dir),
            }

        # Los mas recientes primero, limitando el trabajo.
        selected = paths[-MAX_DUMPS:]

        dumps: List[CrashDump] = []
        unreadable = 0

        for path in selected:
            try:
                dumps.append(parse_dump(path))
            except DumpParseError as exc:
                # Un volcado truncado es habitual cuando el equipo se apago
                # a mitad de escribirlo. No es motivo para abortar.
                log.debug("volcado ilegible %s: %s", path, exc)
                unreadable += 1

        if unreadable:
            ctx.warn(
                "%d volcado(s) estaban danados o incompletos y se omitieron"
                % unreadable
            )

        return {
            "dumps": dumps,
            "found": len(paths),
            "analyzed": len(dumps),
            "unreadable": unreadable,
            "minidump_dir": ctx.minidump_dir,
            "dir_exists": True,
        }
