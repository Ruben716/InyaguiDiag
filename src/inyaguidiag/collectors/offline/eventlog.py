"""Colector de registros de eventos desde un disco que no arranca.

ESTE ES EL COLECTOR QUE JUSTIFICA TODA LA ARQUITECTURA.

Cuando un equipo no bootea, arrancamos desde el USB, montamos su disco y
leemos sus .evtx directamente. No hay servicio de eventos, no hay WMI, no
hay Windows: solo archivos.

`python-evtx` es Python puro, asi que funciona sobre cualquier archivo
.evtx sin importar de que maquina venga ni si su Windows arranca. Produce
el mismo XML que la API en vivo, de modo que `parse_event_xml()` lo
normaliza igual y **las reglas no notan la diferencia**.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, Iterator, List, Optional

from ...core.context import ScanContext, ScanMode
from ...core.events import EventRecord, Timeline, parse_event_xml
from ...core.registry import register_collector
from ..base import Collector

log = logging.getLogger(__name__)

# Archivos .evtx que interesan. El directorio de logs tiene mas de cien;
# leerlos todos en una maquina vieja es inviable.
WANTED_LOGS = (
    "System.evtx",
    "Application.evtx",
    "Microsoft-Windows-Kernel-Boot%4Operational.evtx",
    "Microsoft-Windows-WHEA-Logger%4Errors.evtx",
    "Microsoft-Windows-Diagnostics-Performance%4Operational.evtx",
    "Microsoft-Windows-StorageSpaces-Driver%4Operational.evtx",
)

MAX_PER_FILE = 5000
DEFAULT_DAYS = 30


@register_collector
class OfflineEventLogCollector(Collector):
    """Lee los .evtx de un disco montado."""

    name = "eventlog-offline"
    provides = "events.timeline"
    supported_modes = (ScanMode.OFFLINE,)
    cost = 5

    def collect(self, ctx: ScanContext) -> Dict[str, Any]:
        evtx_dir = ctx.evtx_dir
        if not os.path.isdir(evtx_dir):
            raise RuntimeError(
                "No se encontro la carpeta de registros: %s. Verifica que la "
                "ruta apunte a la carpeta Windows del disco montado." % evtx_dir
            )

        try:
            from Evtx.Evtx import Evtx  # noqa: F401
        except ImportError:
            raise RuntimeError(
                "Falta la libreria python-evtx, imprescindible para el modo "
                "offline. Instalar con: pip install python-evtx"
            )

        cutoff = datetime.now() - timedelta(days=DEFAULT_DAYS if not ctx.deep else 365)
        records: List[EventRecord] = []
        sources: Dict[str, Any] = {}

        for filename in WANTED_LOGS:
            path = os.path.join(evtx_dir, filename)
            if not os.path.isfile(path):
                continue
            log_name = filename.replace(".evtx", "").replace("%4", "/")
            try:
                found = list(self._read_file(path, log_name, cutoff))
            except Exception as exc:  # noqa: BLE001
                ctx.warn("No se pudo leer %s: %s" % (filename, exc))
                sources[log_name] = {"error": str(exc), "count": 0}
                continue
            records.extend(found)
            sources[log_name] = {"count": len(found)}

        if not records:
            ctx.warn(
                "No se leyo ningun evento. Si el equipo lleva mucho tiempo "
                "apagado, prueba con --deep para ampliar la ventana temporal."
            )

        return {
            "timeline": Timeline(records),
            "days": DEFAULT_DAYS,
            "sources": sources,
            "reader": "python-evtx",
            "total": len(records),
            "evtx_dir": evtx_dir,
        }

    # ------------------------------------------------------------------

    @staticmethod
    def _read_file(
        path: str, log_name: str, cutoff: datetime
    ) -> Iterator[EventRecord]:
        """Recorre un .evtx quedandose con criticos y errores recientes.

        Tolerancia a corrupcion: un equipo que dejo de arrancar por un
        corte de energia casi siempre tiene registros truncados al final
        del archivo. Un registro ilegible se salta; el archivo entero no
        se descarta por eso, porque justamente los ultimos registros --los
        mas cercanos al fallo-- son los que mas nos interesan.
        """
        from Evtx.Evtx import Evtx

        emitted = 0
        skipped = 0

        with Evtx(path) as evtx:
            for entry in evtx.records():
                if emitted >= MAX_PER_FILE:
                    break
                try:
                    xml_text = entry.xml()
                except Exception:  # noqa: BLE001 - registro corrupto
                    skipped += 1
                    continue

                record = parse_event_xml(xml_text, log_name)
                if record is None:
                    skipped += 1
                    continue
                if not record.is_problem:
                    continue
                if record.timestamp is not None and record.timestamp < cutoff:
                    continue

                emitted += 1
                yield record

        if skipped:
            log.debug("%s: %d registros ilegibles omitidos", log_name, skipped)
