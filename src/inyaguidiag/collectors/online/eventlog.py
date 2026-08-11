"""Colector de registros de eventos en un Windows arrancado.

Estrategia por capas, igual que el resto del proyecto:

  1. `win32evtlog.EvtQuery` (pywin32)  -- API moderna de eventos. Permite
     filtrar por XPath del lado del servicio, asi que solo cruzan el limite
     los eventos que interesan. Disponible desde Windows Vista.
  2. `wevtutil.exe qe`                 -- respaldo por subproceso, mismo
     XPath, cuando no hay pywin32.

Lo que NO se hace: leer directamente los .evtx de System32 estando el
sistema vivo. El servicio de eventos los tiene abiertos y la lectura
devuelve datos truncados o falla. Esa via es exclusiva del modo OFFLINE.
"""

from __future__ import annotations

import logging
import subprocess
import shutil
from typing import Any, Dict, List, Optional

from ...core.context import ScanContext, ScanMode
from ...core.events import EventRecord, Timeline, parse_event_xml
from ...core.registry import register_collector
from ..base import Collector

log = logging.getLogger(__name__)

_NO_WINDOW = 0x08000000
_TIMEOUT = 120

# Cuantos dias de historia mirar. Mas atras el ruido supera a la senal y
# los eventos dejan de ser relevantes para el problema actual.
DEFAULT_DAYS = 14

# Tope de eventos por registro. Un equipo con un error en bucle puede
# tener cientos de miles; leerlos todos no aporta nada y agota la memoria
# en las maquinas viejas que son justamente nuestro objetivo.
MAX_PER_LOG = 3000

LOGS = ("System", "Application")


@register_collector
class EventLogCollector(Collector):
    """Lee los eventos criticos y de error de los ultimos dias."""

    name = "eventlog"
    provides = "events.timeline"
    supported_modes = (ScanMode.ONLINE,)
    cost = 4

    def collect(self, ctx: ScanContext) -> Dict[str, Any]:
        days = DEFAULT_DAYS if not ctx.deep else 60
        records: List[EventRecord] = []
        sources: Dict[str, Any] = {}

        reader = _pick_reader()
        if reader is None:
            raise RuntimeError(
                "No hay forma de leer los registros de eventos "
                "(falta pywin32 y wevtutil)"
            )

        for log_name in LOGS:
            try:
                found = reader(log_name, days, MAX_PER_LOG)
            except Exception as exc:  # noqa: BLE001
                ctx.warn("No se pudo leer el registro '%s': %s" % (log_name, exc))
                sources[log_name] = {"error": str(exc), "count": 0}
                continue
            records.extend(found)
            sources[log_name] = {"count": len(found)}
            if len(found) >= MAX_PER_LOG:
                ctx.warn(
                    "El registro '%s' supero los %d eventos; se analizaron "
                    "solo los mas recientes" % (log_name, MAX_PER_LOG)
                )

        timeline = Timeline(records)
        return {
            "timeline": timeline,
            "days": days,
            "sources": sources,
            "reader": getattr(reader, "_label", "?"),
            "total": len(records),
        }


# ----------------------------------------------------------------------
# Lectores
# ----------------------------------------------------------------------


def _xpath(days: int) -> str:
    """Filtro XPath: solo criticos y errores dentro de la ventana.

    El filtrado ocurre en el servicio de eventos, no en Python. En un
    equipo con el log lleno esto es la diferencia entre medio segundo y
    varios minutos.
    """
    millis = days * 24 * 60 * 60 * 1000
    return (
        "*[System[(Level=1 or Level=2) and "
        "TimeCreated[timediff(@SystemTime) <= %d]]]" % millis
    )


def _read_with_pywin32(log_name: str, days: int, limit: int) -> List[EventRecord]:
    import win32evtlog  # type: ignore[import-not-found]

    handle = win32evtlog.EvtQuery(
        log_name,
        win32evtlog.EvtQueryReverseDirection,  # del mas reciente al mas viejo
        _xpath(days),
        None,
    )

    records: List[EventRecord] = []
    while len(records) < limit:
        try:
            batch = win32evtlog.EvtNext(handle, 50)
        except Exception:  # noqa: BLE001 - fin del recorrido
            break
        if not batch:
            break
        for event in batch:
            try:
                xml_text = win32evtlog.EvtRender(
                    event, win32evtlog.EvtRenderEventXml
                )
            except Exception:  # noqa: BLE001 - evento suelto ilegible
                continue
            record = parse_event_xml(xml_text, log_name)
            if record is not None:
                records.append(record)
    return records


_read_with_pywin32._label = "pywin32"  # type: ignore[attr-defined]


def _read_with_wevtutil(log_name: str, days: int, limit: int) -> List[EventRecord]:
    exe = shutil.which("wevtutil")
    if not exe:
        raise RuntimeError("wevtutil no disponible")

    output = subprocess.check_output(
        [
            exe, "qe", log_name,
            "/q:" + _xpath(days),
            "/c:%d" % limit,
            "/rd:true",       # mas recientes primero
            "/f:xml",
        ],
        stderr=subprocess.PIPE,
        timeout=_TIMEOUT,
        creationflags=_NO_WINDOW,
    ).decode("utf-8", "ignore")

    return _split_and_parse(output, log_name)


_read_with_wevtutil._label = "wevtutil"  # type: ignore[attr-defined]


def _split_and_parse(output: str, log_name: str) -> List[EventRecord]:
    """Trocea la salida de wevtutil, que concatena <Event>...</Event>.

    No es XML valido en conjunto (no tiene raiz unica), asi que se parte
    por el cierre de cada evento en vez de intentar parsear el bloque.
    """
    records: List[EventRecord] = []
    for chunk in output.split("</Event>"):
        chunk = chunk.strip()
        if not chunk:
            continue
        record = parse_event_xml(chunk + "</Event>", log_name)
        if record is not None:
            records.append(record)
    return records


def _pick_reader():
    """Elige el mejor lector disponible, una sola vez."""
    try:
        import win32evtlog  # noqa: F401

        log.debug("lector de eventos: pywin32")
        return _read_with_pywin32
    except ImportError:
        pass
    if shutil.which("wevtutil"):
        log.debug("lector de eventos: wevtutil")
        return _read_with_wevtutil
    return None
