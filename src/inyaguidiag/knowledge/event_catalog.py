"""Catalogo de eventos de Windows que importan para el diagnostico.

Windows genera decenas de miles de eventos. La inmensa mayoria es ruido.
Este catalogo define los que si dicen algo, y que significan.

Es el equivalente al diccionario de codigos DTC de un escaner de autos: el
numero por si solo no sirve, hace falta saber que representa.

Cada entrada declara ademas su `weight`, que es cuanto pesa ese evento
como sospechoso al correlacionar la causa de un fallo. Un error de disco
justo antes de un pantallazo pesa mucho mas que un servicio que no arranco.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from ..core.models import Category


@dataclass(frozen=True)
class EventMeaning:
    """Que significa un evento concreto."""

    provider: str
    event_id: int
    title: str
    meaning: str
    category: Category
    weight: int = 1          # 1 = anecdotico, 5 = casi siempre la causa
    hardware_suspect: bool = False


# ----------------------------------------------------------------------
# Arranque y apagones
# ----------------------------------------------------------------------

_BOOT = [
    EventMeaning(
        provider="Microsoft-Windows-Kernel-Power",
        event_id=41,
        title="Apagado inesperado",
        meaning=(
            "El equipo se apago o reinicio sin cerrar Windows correctamente. "
            "Es la huella que deja un corte de luz, un pantallazo azul, un "
            "sobrecalentamiento o una fuente de poder defectuosa."
        ),
        category=Category.POWER,
        weight=4,
        hardware_suspect=True,
    ),
    EventMeaning(
        provider="EventLog",
        event_id=6008,
        title="Apagado sucio registrado",
        meaning=(
            "Windows detecto al arrancar que el apagado anterior no fue "
            "limpio. Confirma el evento 41 desde el otro lado."
        ),
        category=Category.POWER,
        weight=3,
    ),
    EventMeaning(
        provider="Microsoft-Windows-WER-SystemErrorReporting",
        event_id=1001,
        title="Reporte de error del sistema",
        meaning=(
            "Windows registro los detalles de un fallo grave, normalmente "
            "un pantallazo azul, con su codigo de comprobacion de errores."
        ),
        category=Category.CRASH,
        weight=5,
    ),
    EventMeaning(
        provider="BugCheck",
        event_id=1001,
        title="Pantallazo azul",
        meaning=(
            "El sistema se detuvo con un error de comprobacion. El codigo "
            "indica que tipo de fallo fue y el volcado dice que driver lo "
            "provoco."
        ),
        category=Category.CRASH,
        weight=5,
    ),
    EventMeaning(
        provider="Microsoft-Windows-Kernel-Boot",
        event_id=29,
        title="Gestor de arranque con problemas",
        meaning="Windows tuvo que recurrir a la configuracion de arranque de respaldo.",
        category=Category.BOOT,
        weight=3,
    ),
    EventMeaning(
        provider="volmgr",
        event_id=46,
        title="No se pudo crear el volcado de memoria",
        meaning=(
            "Hubo un pantallazo pero Windows no logro guardar el volcado. "
            "Suele indicar archivo de paginacion insuficiente o disco lleno."
        ),
        category=Category.CRASH,
        weight=2,
    ),
]

# ----------------------------------------------------------------------
# Disco y sistema de archivos
# ----------------------------------------------------------------------

_STORAGE = [
    EventMeaning(
        provider="disk",
        event_id=7,
        title="Bloque defectuoso en el disco",
        meaning="El disco reporto un bloque que no se pudo leer ni escribir.",
        category=Category.STORAGE,
        weight=5,
        hardware_suspect=True,
    ),
    EventMeaning(
        provider="disk",
        event_id=11,
        title="Error de controlador de disco",
        meaning=(
            "El controlador detecto un error en el disco. Repetido muchas "
            "veces es una de las senales mas fiables de disco o cable danado."
        ),
        category=Category.STORAGE,
        weight=5,
        hardware_suspect=True,
    ),
    EventMeaning(
        provider="disk",
        event_id=51,
        title="Error de paginacion en el disco",
        meaning="Windows fallo al escribir en el disco durante una operacion de memoria virtual.",
        category=Category.STORAGE,
        weight=4,
        hardware_suspect=True,
    ),
    EventMeaning(
        provider="disk",
        event_id=153,
        title="Reintento de E/S en el disco",
        meaning=(
            "El disco no respondio a la primera y hubo que reintentar. "
            "Aislado es normal; repetido indica un disco que se esta yendo."
        ),
        category=Category.STORAGE,
        weight=3,
        hardware_suspect=True,
    ),
    EventMeaning(
        provider="Ntfs",
        event_id=55,
        title="Corrupcion del sistema de archivos",
        meaning=(
            "NTFS detecto dano en la estructura del volumen. Hace falta "
            "ejecutar chkdsk."
        ),
        category=Category.STORAGE,
        weight=4,
    ),
    EventMeaning(
        provider="Ntfs",
        event_id=137,
        title="Volumen con transacciones sin resolver",
        meaning="El volumen quedo en estado inconsistente tras un apagado sucio.",
        category=Category.STORAGE,
        weight=2,
    ),
]

# ----------------------------------------------------------------------
# Hardware (WHEA)
# ----------------------------------------------------------------------

_HARDWARE = [
    EventMeaning(
        provider="Microsoft-Windows-WHEA-Logger",
        event_id=1,
        title="Error de hardware irrecuperable",
        meaning=(
            "El procesador reporto un error de hardware que no se pudo "
            "corregir. Es de los diagnosticos mas serios que existen."
        ),
        category=Category.HARDWARE,
        weight=5,
        hardware_suspect=True,
    ),
    EventMeaning(
        provider="Microsoft-Windows-WHEA-Logger",
        event_id=17,
        title="Error corregido en bus PCI Express",
        meaning=(
            "Se corrigieron errores en el bus PCIe. Aislado no es grave; "
            "repetido apunta a una tarjeta mal asentada o a la placa."
        ),
        category=Category.HARDWARE,
        weight=3,
        hardware_suspect=True,
    ),
    EventMeaning(
        provider="Microsoft-Windows-WHEA-Logger",
        event_id=18,
        title="Error irrecuperable en bus PCI Express",
        meaning="Error de hardware no corregible en el bus PCIe.",
        category=Category.HARDWARE,
        weight=5,
        hardware_suspect=True,
    ),
    EventMeaning(
        provider="Microsoft-Windows-WHEA-Logger",
        event_id=19,
        title="Error corregido de memoria o cache",
        meaning=(
            "Se corrigieron errores en la memoria. Repetido con frecuencia "
            "es el aviso previo a fallos de RAM."
        ),
        category=Category.MEMORY,
        weight=4,
        hardware_suspect=True,
    ),
    EventMeaning(
        provider="Microsoft-Windows-MemoryDiagnostics-Results",
        event_id=1201,
        title="Diagnostico de memoria: errores detectados",
        meaning=(
            "La herramienta de diagnostico de memoria de Windows encontro "
            "errores en la RAM."
        ),
        category=Category.MEMORY,
        weight=5,
        hardware_suspect=True,
    ),
]

# ----------------------------------------------------------------------
# Servicios y aplicaciones
# ----------------------------------------------------------------------

_SYSTEM = [
    EventMeaning(
        provider="Service Control Manager",
        event_id=7000,
        title="Servicio que no pudo iniciar",
        meaning="Un servicio de Windows fallo al arrancar.",
        category=Category.SYSTEM,
        weight=2,
    ),
    EventMeaning(
        provider="Service Control Manager",
        event_id=7011,
        title="Servicio que no responde",
        meaning=(
            "Un servicio agoto el tiempo de espera. Suele acompanar a "
            "problemas de disco lento o de bloqueo del sistema."
        ),
        category=Category.SYSTEM,
        weight=3,
    ),
    EventMeaning(
        provider="Service Control Manager",
        event_id=7031,
        title="Servicio terminado inesperadamente",
        meaning="Un servicio se cayo solo y Windows intento reiniciarlo.",
        category=Category.SYSTEM,
        weight=2,
    ),
    EventMeaning(
        provider="Application Error",
        event_id=1000,
        title="Aplicacion que se cerro con error",
        meaning="Un programa se cerro de forma anormal.",
        category=Category.SYSTEM,
        weight=1,
    ),
    EventMeaning(
        provider="Application Hang",
        event_id=1002,
        title="Aplicacion que dejo de responder",
        meaning="Un programa se colgo y hubo que cerrarlo.",
        category=Category.SYSTEM,
        weight=1,
    ),
]

# ----------------------------------------------------------------------
# Red
# ----------------------------------------------------------------------

_NETWORK = [
    EventMeaning(
        provider="Microsoft-Windows-DNS-Client",
        event_id=1014,
        title="Tiempo de espera agotado en DNS",
        meaning="El equipo no obtuvo respuesta del servidor DNS configurado.",
        category=Category.NETWORK,
        weight=3,
    ),
    EventMeaning(
        provider="Microsoft-Windows-Dhcp-Client",
        event_id=1002,
        title="Conflicto de direccion IP",
        meaning="Otro equipo de la red ya usa la direccion IP asignada.",
        category=Category.NETWORK,
        weight=3,
    ),
    EventMeaning(
        provider="Tcpip",
        event_id=4227,
        title="Agotamiento de puertos TCP",
        meaning="El sistema se quedo sin puertos disponibles para nuevas conexiones.",
        category=Category.NETWORK,
        weight=2,
    ),
    EventMeaning(
        provider="NETLOGON",
        event_id=5719,
        title="Sin contacto con el controlador de dominio",
        meaning="El equipo no pudo comunicarse con el dominio al arrancar.",
        category=Category.NETWORK,
        weight=2,
    ),
]


# ----------------------------------------------------------------------
# Indice
# ----------------------------------------------------------------------

ALL_MEANINGS: List[EventMeaning] = _BOOT + _STORAGE + _HARDWARE + _SYSTEM + _NETWORK

_INDEX: Dict[str, EventMeaning] = {
    "%s/%d" % (m.provider, m.event_id): m for m in ALL_MEANINGS
}

# Indice secundario solo por id, para proveedores que cambian de nombre
# entre versiones de Windows (pasa con los clasicos: "disk", "Disk", ...).
_BY_ID: Dict[int, List[EventMeaning]] = {}
for _meaning in ALL_MEANINGS:
    _BY_ID.setdefault(_meaning.event_id, []).append(_meaning)


def lookup(provider: str, event_id: int) -> Optional[EventMeaning]:
    """Busca el significado de un evento.

    Intenta primero la coincidencia exacta proveedor+id, y luego solo por
    id si el nombre del proveedor difiere en mayusculas o sufijos, cosa
    que ocurre entre Windows 7 y 11.
    """
    exact = _INDEX.get("%s/%d" % (provider, event_id))
    if exact is not None:
        return exact

    candidates = _BY_ID.get(event_id)
    if not candidates:
        return None

    provider_lower = (provider or "").lower()
    for candidate in candidates:
        if candidate.provider.lower() == provider_lower:
            return candidate
    # Coincidencia laxa: "disk" contra "Disk" o "Microsoft-Windows-disk".
    for candidate in candidates:
        if candidate.provider.lower() in provider_lower:
            return candidate
    return None


def interesting_event_ids() -> Sequence[int]:
    """Ids que vale la pena consultar. Acota la lectura del log."""
    return sorted(_BY_ID)


def hardware_suspects() -> List[EventMeaning]:
    """Eventos que apuntan a hardware, no a software.

    La distincion importa mucho para el usuario: un problema de software
    se arregla desde el USB, uno de hardware requiere comprar algo.
    """
    return [m for m in ALL_MEANINGS if m.hardware_suspect]
