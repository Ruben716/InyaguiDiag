"""Modelo normalizado de eventos de Windows y su linea de tiempo.

PIEZA CENTRAL DEL DISENO
------------------------
Los dos modos llegan a los eventos por caminos totalmente distintos:

    ONLINE   win32evtlog.EvtQuery  (API del servicio de eventos)
    OFFLINE  Evtx(archivo .evtx)   (lectura directa del disco muerto)

Pero ambos entregan el MISMO XML de evento. Por eso el normalizador vive
aca y se usa desde los dos lados: `parse_event_xml()` es el unico sitio
del proyecto que sabe interpretar el formato de un evento de Windows.

Consecuencia practica: una regla escrita para el modo online funciona sin
cambios en el modo offline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Sequence
from xml.etree import ElementTree

# Namespace del esquema de eventos de Windows. Presente desde Vista.
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Niveles segun el esquema de Windows.
LEVEL_CRITICAL = 1
LEVEL_ERROR = 2
LEVEL_WARNING = 3
LEVEL_INFO = 4

LEVEL_NAMES = {
    LEVEL_CRITICAL: "critico",
    LEVEL_ERROR: "error",
    LEVEL_WARNING: "advertencia",
    LEVEL_INFO: "informacion",
    0: "indefinido",
}


@dataclass
class EventRecord:
    """Un evento de Windows, normalizado e independiente del origen."""

    log: str
    event_id: int
    provider: str
    level: int
    timestamp: Optional[datetime]
    computer: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    raw_xml: str = ""

    @property
    def level_name(self) -> str:
        return LEVEL_NAMES.get(self.level, "desconocido")

    @property
    def is_problem(self) -> bool:
        """Critico o error. Las advertencias generan demasiado ruido."""
        return self.level in (LEVEL_CRITICAL, LEVEL_ERROR)

    @property
    def key(self) -> str:
        """Identidad para agrupar eventos repetidos: proveedor + id."""
        return "%s/%d" % (self.provider, self.event_id)

    def __repr__(self) -> str:
        when = self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "?"
        return "<Event %s id=%d %s>" % (self.provider, self.event_id, when)


# ----------------------------------------------------------------------
# Normalizacion desde XML
# ----------------------------------------------------------------------


def parse_event_xml(xml_text: str, log_name: str = "") -> Optional[EventRecord]:
    """Convierte el XML de un evento en un EventRecord.

    Unico normalizador del proyecto. Lo usan tanto el colector online como
    el offline.

    Returns:
        None si el XML esta corrupto. Los .evtx de equipos que sufrieron un
        corte de energia traen registros truncados; saltarlos es lo
        correcto, no abortar la lectura del archivo entero.
    """
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return None

    system = root.find(_NS + "System")
    if system is None:
        return None

    event_id = _int_of(_text(system.find(_NS + "EventID")))
    if event_id is None:
        return None

    provider_el = system.find(_NS + "Provider")
    provider = ""
    if provider_el is not None:
        provider = provider_el.get("Name") or provider_el.get("EventSourceName") or ""

    level = _int_of(_text(system.find(_NS + "Level"))) or 0

    time_el = system.find(_NS + "TimeCreated")
    timestamp = _parse_timestamp(time_el.get("SystemTime")) if time_el is not None else None

    channel = _text(system.find(_NS + "Channel")) or log_name
    computer = _text(system.find(_NS + "Computer")) or ""

    return EventRecord(
        log=channel,
        event_id=event_id,
        provider=provider,
        level=level,
        timestamp=timestamp,
        computer=computer,
        data=_extract_data(root),
        raw_xml=xml_text,
    )


def _extract_data(root: ElementTree.Element) -> Dict[str, Any]:
    """Saca los campos utiles de EventData / UserData.

    Windows usa dos formas segun el proveedor:
      * <Data Name="BugcheckCode">159</Data>   -> con nombre
      * <Data>valor</Data>                     -> posicional
    La segunda se indexa como Data0, Data1, ... porque muchos proveedores
    clasicos (disk, Ntfs) no ponen nombres.
    """
    data: Dict[str, Any] = {}

    for container in (root.find(_NS + "EventData"), root.find(_NS + "UserData")):
        if container is None:
            continue
        positional = 0
        for element in container.iter():
            tag = element.tag.replace(_NS, "")
            if tag not in ("Data", "Binary"):
                continue
            name = element.get("Name")
            value = (element.text or "").strip()
            if name:
                data[name] = value
            else:
                data["Data%d" % positional] = value
                positional += 1
    return data


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    """Interpreta el SystemTime ISO-8601 de Windows.

    Formato tipico: 2026-08-11T13:31:31.1234567Z -- con 7 decimales, que
    `datetime.fromisoformat` no acepta en Python 3.8. Se recortan a 6.
    """
    if not value:
        return None
    text = value.strip().rstrip("Z")
    match = re.match(r"^(.*\.\d{1,6})\d*$", text)
    if match:
        text = match.group(1)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _text(element: Optional[ElementTree.Element]) -> Optional[str]:
    if element is None or element.text is None:
        return None
    return element.text.strip()


def _int_of(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


# ----------------------------------------------------------------------
# Linea de tiempo
# ----------------------------------------------------------------------


class Timeline:
    """Coleccion de eventos ordenada en el tiempo, con consultas utiles.

    Aca vive el valor real del analisis de logs: no listar errores, sino
    responder "que paso ANTES de esto". Un BSOD precedido de doce errores
    de disco no es un problema de driver aunque el volcado culpe al driver.
    """

    def __init__(self, events: Iterable[EventRecord]) -> None:
        self._events: List[EventRecord] = sorted(
            (e for e in events if e.timestamp is not None),
            key=lambda e: e.timestamp,  # type: ignore[arg-type,return-value]
        )
        # Los eventos sin fecha no sirven para correlacionar pero si para
        # contar, asi que se conservan aparte.
        self._undated: List[EventRecord] = [e for e in events if e.timestamp is None]

    def __len__(self) -> int:
        return len(self._events) + len(self._undated)

    def __iter__(self):
        return iter(self._events)

    @property
    def all(self) -> List[EventRecord]:
        return list(self._events) + list(self._undated)

    # ------------------------------------------------------------------

    def of(
        self,
        provider: Optional[str] = None,
        event_id: Optional[int] = None,
        event_ids: Optional[Sequence[int]] = None,
        level: Optional[int] = None,
        log: Optional[str] = None,
    ) -> List[EventRecord]:
        """Filtra la linea de tiempo. Todos los criterios son opcionales."""
        wanted_ids = set(event_ids or ())
        if event_id is not None:
            wanted_ids.add(event_id)

        result = []
        for event in self._events:
            if provider is not None and event.provider != provider:
                continue
            if wanted_ids and event.event_id not in wanted_ids:
                continue
            if level is not None and event.level != level:
                continue
            if log is not None and event.log != log:
                continue
            result.append(event)
        return result

    def preceding(
        self, moment: datetime, window: timedelta, level: Optional[int] = None
    ) -> List[EventRecord]:
        """Eventos ocurridos en la ventana ANTERIOR a `moment`.

        Es la consulta que sostiene la correlacion: dado un BSOD, que se
        estaba quejando justo antes.
        """
        start = moment - window
        return [
            e
            for e in self._events
            if e.timestamp is not None
            and start <= e.timestamp < moment
            and (level is None or e.level == level)
        ]

    def problems(self) -> List[EventRecord]:
        return [e for e in self._events if e.is_problem]

    def group_by_key(self) -> Dict[str, List[EventRecord]]:
        """Agrupa por proveedor+id para detectar repeticiones.

        Un error que aparece 400 veces es una historia distinta al mismo
        error apareciendo una vez.
        """
        groups: Dict[str, List[EventRecord]] = {}
        for event in self._events:
            groups.setdefault(event.key, []).append(event)
        return groups

    @property
    def span(self) -> Optional[timedelta]:
        """Periodo cubierto por los eventos. Contextualiza los conteos."""
        if len(self._events) < 2:
            return None
        first = self._events[0].timestamp
        last = self._events[-1].timestamp
        if first is None or last is None:
            return None
        return last - first
