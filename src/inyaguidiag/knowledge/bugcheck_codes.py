"""Catalogo de codigos de comprobacion de errores (bugcheck) de Windows.

Cuando Windows se detiene con un pantallazo azul, deja un codigo. Ese
codigo NO dice que componente fallo, dice que TIPO de fallo ocurrio. La
diferencia importa: 0x7A no significa "el disco esta roto", significa "no
se pudo leer una pagina de memoria desde el disco", que suele deberse al
disco pero tambien a la RAM o al controlador.

Por eso cada entrada declara un `suspect`: la familia de causas mas
probable. Es lo que permite decirle al usuario si tiene que cambiar
hardware o reinstalar un controlador.

Referencia: los codigos son los documentados por Microsoft en la
referencia de Bug Check Codes; las explicaciones y remedios son propios.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from ..core.models import Category


@dataclass(frozen=True)
class BugCheck:
    """Significado de un codigo de detencion."""

    code: int
    name: str
    meaning: str
    suspect: str              # "disco", "memoria", "controlador", "hardware", "video", "sistema"
    category: Category
    hardware: bool = False    # True si tipicamente exige cambiar una pieza

    @property
    def hex_code(self) -> str:
        return "0x%08X" % self.code

    @property
    def short_hex(self) -> str:
        return "0x%X" % self.code


_CATALOG = [
    # -- Controladores --------------------------------------------------
    BugCheck(
        0x0A, "IRQL_NOT_LESS_OR_EQUAL",
        "Un controlador intento acceder a memoria en un nivel de "
        "interrupcion no permitido. Casi siempre es un controlador mal "
        "escrito o desactualizado.",
        "controlador", Category.DRIVERS,
    ),
    BugCheck(
        0xD1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        "Un controlador accedio a memoria invalida. La variante mas comun "
        "de fallo por controlador; suele apuntar a red, audio o antivirus.",
        "controlador", Category.DRIVERS,
    ),
    BugCheck(
        0x1E, "KMODE_EXCEPTION_NOT_HANDLED",
        "Un componente del nucleo genero una excepcion que nadie atendio.",
        "controlador", Category.DRIVERS,
    ),
    BugCheck(
        0x3B, "SYSTEM_SERVICE_EXCEPTION",
        "Fallo una llamada al sistema. Suele venir de controladores de "
        "video o de software que se engancha al nucleo.",
        "controlador", Category.DRIVERS,
    ),
    BugCheck(
        0x7E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        "Un hilo del sistema genero una excepcion no controlada.",
        "controlador", Category.DRIVERS,
    ),
    BugCheck(
        0x9F, "DRIVER_POWER_STATE_FAILURE",
        "Un controlador no respondio al suspender o reanudar el equipo. "
        "Tipico al cerrar la tapa de un portatil o al hibernar.",
        "controlador", Category.DRIVERS,
    ),
    BugCheck(
        0xC2, "BAD_POOL_CALLER",
        "Un controlador pidio o libero memoria del nucleo de forma "
        "incorrecta.",
        "controlador", Category.DRIVERS,
    ),
    BugCheck(
        0xC5, "DRIVER_CORRUPTED_EXPOOL",
        "Un controlador corrompio la memoria del sistema.",
        "controlador", Category.DRIVERS,
    ),
    BugCheck(
        0x133, "DPC_WATCHDOG_VIOLATION",
        "Un controlador retuvo el procesador demasiado tiempo. Muy "
        "asociado a controladores de almacenamiento antiguos y a discos "
        "que responden lento.",
        "controlador", Category.DRIVERS,
    ),

    # -- Memoria --------------------------------------------------------
    BugCheck(
        0x1A, "MEMORY_MANAGEMENT",
        "El administrador de memoria detecto una inconsistencia grave. "
        "Cuando se repite, la RAM es el primer sospechoso.",
        "memoria", Category.MEMORY, hardware=True,
    ),
    BugCheck(
        0x4E, "PFN_LIST_CORRUPT",
        "Las estructuras internas de la memoria fisica estan corruptas. "
        "Apunta con fuerza a RAM defectuosa.",
        "memoria", Category.MEMORY, hardware=True,
    ),
    BugCheck(
        0x50, "PAGE_FAULT_IN_NONPAGED_AREA",
        "Se pidio memoria que no existe. Las dos causas tipicas son RAM "
        "defectuosa y un controlador que escribe donde no debe.",
        "memoria", Category.MEMORY, hardware=True,
    ),
    BugCheck(
        0x1000007E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M",
        "Variante de 0x7E registrada en algunas versiones.",
        "controlador", Category.DRIVERS,
    ),

    # -- Disco ----------------------------------------------------------
    BugCheck(
        0x7A, "KERNEL_DATA_INPAGE_ERROR",
        "Windows no pudo leer del disco una pagina de memoria que "
        "necesitaba. Es uno de los indicadores mas claros de disco o cable "
        "defectuoso.",
        "disco", Category.STORAGE, hardware=True,
    ),
    BugCheck(
        0x7B, "INACCESSIBLE_BOOT_DEVICE",
        "Windows no encontro o no pudo leer el disco de arranque. Causa "
        "clasica de equipo que ya no bootea: disco muerto, cable suelto, o "
        "un cambio de modo del controlador (AHCI/RAID) en la BIOS.",
        "disco", Category.BOOT, hardware=True,
    ),
    BugCheck(
        0x24, "NTFS_FILE_SYSTEM",
        "El sistema de archivos NTFS encontro corrupcion. Puede ser dano "
        "logico (arreglable con chkdsk) o el disco fallando.",
        "disco", Category.STORAGE,
    ),
    BugCheck(
        0xF4, "CRITICAL_OBJECT_TERMINATION",
        "Un proceso critico del sistema murio. A menudo el disco no "
        "respondio a tiempo.",
        "disco", Category.STORAGE,
    ),
    BugCheck(
        0xEF, "CRITICAL_PROCESS_DIED",
        "Un proceso imprescindible se cerro. Suele venir de archivos del "
        "sistema corruptos o de un disco con problemas.",
        "sistema", Category.SYSTEM,
    ),

    # -- Hardware -------------------------------------------------------
    BugCheck(
        0x124, "WHEA_UNCORRECTABLE_ERROR",
        "El hardware reporto un error que no se pudo corregir. Este codigo "
        "practicamente descarta el software: es procesador, placa, fuente "
        "o memoria.",
        "hardware", Category.HARDWARE, hardware=True,
    ),
    BugCheck(
        0x9C, "MACHINE_CHECK_EXCEPTION",
        "El procesador detecto un error interno de hardware. Muy asociado "
        "a sobrecalentamiento y a overclocking inestable.",
        "hardware", Category.HARDWARE, hardware=True,
    ),
    BugCheck(
        0x101, "CLOCK_WATCHDOG_TIMEOUT",
        "Un nucleo del procesador dejo de responder. Apunta a procesador, "
        "alimentacion o temperatura.",
        "hardware", Category.HARDWARE, hardware=True,
    ),

    # -- Video ----------------------------------------------------------
    BugCheck(
        0x116, "VIDEO_TDR_ERROR",
        "La tarjeta de video no respondio y no se pudo reiniciar. "
        "Controlador de video o la GPU sobrecalentada.",
        "video", Category.DRIVERS,
    ),
    BugCheck(
        0x119, "VIDEO_SCHEDULER_INTERNAL_ERROR",
        "El planificador de video encontro un estado invalido.",
        "video", Category.DRIVERS,
    ),

    # -- Sistema --------------------------------------------------------
    BugCheck(
        0x139, "KERNEL_SECURITY_CHECK_FAILURE",
        "Una comprobacion de integridad del nucleo fallo. Corrupcion de "
        "memoria por controlador, o RAM defectuosa.",
        "sistema", Category.SYSTEM,
    ),
    BugCheck(
        0xC000021A, "STATUS_SYSTEM_PROCESS_TERMINATED",
        "Un subsistema critico de usuario fallo. Suele ocurrir tras una "
        "actualizacion interrumpida.",
        "sistema", Category.SYSTEM,
    ),
    BugCheck(
        0xC4, "DRIVER_VERIFIER_DETECTED_VIOLATION",
        "El Verificador de controladores atrapo a un controlador "
        "portandose mal. Si lo activaste tu, este es el resultado buscado: "
        "el modulo senalado es el culpable.",
        "controlador", Category.DRIVERS,
    ),
]

_INDEX: Dict[int, BugCheck] = {entry.code: entry for entry in _CATALOG}


def lookup(code: int) -> Optional[BugCheck]:
    """Devuelve el significado de un codigo de detencion, si se conoce."""
    entry = _INDEX.get(code)
    if entry is not None:
        return entry
    # Algunos codigos llegan con bits altos de contexto; el byte bajo
    # sigue siendo el codigo real.
    return _INDEX.get(code & 0xFFFF)


def describe(code: int) -> str:
    """Nombre legible del codigo, aunque no este catalogado."""
    entry = lookup(code)
    if entry is not None:
        return "%s (%s)" % (entry.name, entry.short_hex)
    return "Codigo desconocido (0x%X)" % code


def known_codes() -> Dict[int, BugCheck]:
    return dict(_INDEX)
