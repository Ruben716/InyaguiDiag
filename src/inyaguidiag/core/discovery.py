"""Deteccion automatica de instalaciones de Windows en los discos montados.

POR QUE EXISTE ESTE MODULO
--------------------------
En modo OFFLINE el tecnico arranca el equipo averiado desde el USB (WinPE)
y tiene que indicar QUE disco analizar. Adivinar la letra es la fuente
numero uno de errores: dentro de WinPE la unidad del equipo averiado casi
nunca sigue siendo C:, porque el propio entorno de rescate se adjudica una
letra y el resto se renumera.

EL ERROR CLASICO QUE ESTE MODULO EVITA
--------------------------------------
Analizar el entorno de rescate en vez del equipo averiado. El WinPE del
USB esta perfectamente sano, asi que el reporte sale limpio y el tecnico
concluye que no hay nada roto. Por eso `find_windows_installations()`
EXCLUYE por defecto la unidad desde la que corre la herramienta.

Marcador de deteccion: `<raiz>\\Windows\\System32\\config\\SYSTEM`. Se
elige el hive SYSTEM y no la carpeta `Windows` porque una carpeta vacia
llamada Windows la crea cualquiera; el hive SYSTEM solo existe si hubo una
instalacion de verdad, y ademas es el archivo que el modo offline necesita
para poder leer algo.
"""

from __future__ import annotations

import contextlib
import ctypes
import logging
import os
import shutil
import string
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Sequence

log = logging.getLogger(__name__)

#: Ruta relativa al hive SYSTEM desde la raiz de un volumen.
SYSTEM_HIVE_RELATIVE = os.path.join("Windows", "System32", "config", "SYSTEM")

# Valores de GetDriveTypeW. Se repiten aca para no depender de win32con,
# que solo existe si pywin32 esta instalado.
DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6

# Senales de que la raiz examinada es un entorno de arranque (WinPE) y no
# una instalacion normal. Un WinPE tiene hive SYSTEM, asi que sin esto se
# colaria como candidato legitimo.
_WINPE_MARKERS = (
    os.path.join("Windows", "System32", "winpeshl.exe"),
    os.path.join("Windows", "System32", "startnet.cmd"),
)

# Senales de que la instalacion es la "de verdad" y no una copia parcial,
# un Windows.old montado o un disco de datos con restos.
_SYSTEM_MARKERS = (
    ("hive SOFTWARE presente", os.path.join("Windows", "System32", "config", "SOFTWARE")),
    ("carpeta Users presente", "Users"),
    ("explorer.exe presente", os.path.join("Windows", "explorer.exe")),
    ("perfiles de usuario", os.path.join("Users", "Default")),
)

# Archivos del gestor de arranque en la raiz del volumen.
_BOOT_MARKERS = (
    "bootmgr",
    os.path.join("Boot", "BCD"),
    os.path.join("EFI", "Microsoft", "Boot", "BCD"),
)


@dataclass
class WindowsInstallation:
    """Una instalacion de Windows encontrada en un volumen montado.

    Attributes:
        root: Raiz del volumen, p.ej. ``D:\\``.
        drive: Letra con dos puntos, p.ej. ``D:``. Vacia si el volumen no
            tiene letra (montado en carpeta, o arbol de pruebas).
        windows_root: Carpeta Windows, que es lo que espera `ScanContext`.
        is_system_disk: Si parece el disco de sistema del equipo averiado
            y no un disco de datos ni un entorno de rescate.
        is_rescue_environment: Si parece un WinPE.
        signals: Motivos legibles de la clasificacion. Se muestran al
            usuario para que pueda desconfiar de la eleccion automatica.
    """

    root: str
    drive: str = ""
    windows_root: str = ""
    system_hive: str = ""
    label: str = ""
    filesystem: str = ""
    drive_type: int = DRIVE_UNKNOWN
    total_bytes: Optional[int] = None
    free_bytes: Optional[int] = None
    is_system_disk: bool = False
    is_rescue_environment: bool = False
    score: int = 0
    signals: List[str] = field(default_factory=list)

    @property
    def free_gb(self) -> Optional[float]:
        if self.free_bytes is None:
            return None
        return round(self.free_bytes / (1024.0 ** 3), 1)

    @property
    def percent_free(self) -> Optional[float]:
        if not self.total_bytes or self.free_bytes is None:
            return None
        return round(self.free_bytes * 100.0 / self.total_bytes, 1)

    def describe(self) -> str:
        """Una linea para elegir en pantalla."""
        name = self.drive or self.root
        label = (" [%s]" % self.label) if self.label else ""
        if self.free_gb is None:
            space = "espacio desconocido"
        else:
            space = "%.1f GB libres" % self.free_gb
        kind = "disco del sistema" if self.is_system_disk else "otra instalacion"
        if self.is_rescue_environment:
            kind = "entorno de rescate"
        return "%s%s  %s  %s  (%s)" % (
            name, label, self.filesystem or "?", space, kind
        )


# ----------------------------------------------------------------------
# Deteccion
# ----------------------------------------------------------------------


def find_windows_installations(
    roots: Optional[Sequence[str]] = None,
    exclude_root: Optional[str] = None,
    exclude_self: bool = True,
) -> List[WindowsInstallation]:
    """Busca instalaciones de Windows en los volumenes indicados.

    Args:
        roots: Raices a examinar. Por defecto, todas las unidades del
            sistema. Se parametriza para poder probar sin discos reales.
        exclude_root: Raiz a ignorar explicitamente.
        exclude_self: Ignorar tambien la unidad desde la que corre esta
            herramienta. Es el comportamiento por defecto a proposito:
            analizar el propio USB de rescate es el error clasico del
            modo offline y produce un reporte "sin problemas" enganoso.

    Returns:
        Candidatos ordenados de mas a menos probable.
    """
    if roots is None:
        roots = available_drive_roots()

    ignored = []
    if exclude_root:
        ignored.append(exclude_root)
    if exclude_self:
        own = tool_root()
        if own:
            ignored.append(own)

    found: List[WindowsInstallation] = []
    for root in roots:
        if any(same_root(root, other) for other in ignored):
            log.debug("descartada %s: es la unidad de la propia herramienta", root)
            continue
        candidate = probe_root(root)
        if candidate is not None:
            found.append(candidate)

    # Mejor candidato primero: el disco de sistema gana, luego el que mas
    # senales acumula, y a igualdad se ordena por letra para que dos
    # ejecuciones seguidas den el mismo resultado.
    found.sort(key=lambda c: (not c.is_system_disk, -c.score, c.root.upper()))
    return found


def best_installation(
    roots: Optional[Sequence[str]] = None,
    exclude_root: Optional[str] = None,
) -> Optional[WindowsInstallation]:
    """El candidato mas probable, o None si no hay ninguno."""
    candidates = find_windows_installations(roots=roots, exclude_root=exclude_root)
    return candidates[0] if candidates else None


def probe_root(root: str) -> Optional[WindowsInstallation]:
    """Examina una raiz de volumen. Devuelve None si no hay Windows ahi.

    Nunca lanza: un lector de tarjetas vacio, un CD sin disco o un volumen
    cifrado son situaciones normales durante el barrido, no errores.
    """
    hive = os.path.join(root, SYSTEM_HIVE_RELATIVE)
    state = _hive_state(root, hive)
    if state is None:
        return None

    windows_root = os.path.join(root, "Windows")
    drive = drive_letter_of_root(root)

    info = volume_info(root)
    usage = disk_usage(root)

    candidate = WindowsInstallation(
        root=root,
        drive=drive,
        windows_root=windows_root,
        system_hive=hive,
        label=info.get("label", ""),
        filesystem=info.get("filesystem", ""),
        drive_type=drive_type(root),
        total_bytes=usage.get("total"),
        free_bytes=usage.get("free"),
    )

    _classify(candidate, root, state)
    return candidate


def _hive_state(root: str, hive: str) -> Optional[str]:
    """Comprueba el marcador de instalacion. None si no hay Windows ahi.

    Devuelve "presente" cuando el hive SYSTEM se ve, e "inaccesible"
    cuando la carpeta que lo contiene existe pero Windows niega su
    lectura. Ese segundo caso importa: sobre un sistema VIVO y sin
    elevacion, `System32\\config` da acceso denegado, y tratar eso como
    "aqui no hay Windows" haria que la deteccion no encontrase nada y el
    usuario creyera que el disco esta vacio. En WinPE no ocurre nunca
    porque todo corre como SYSTEM.

    Nunca lanza: un lector de tarjetas vacio, un CD sin disco o un volumen
    cifrado son situaciones normales durante el barrido, no errores.
    """
    with _quiet_device_errors():
        try:
            if os.path.isfile(hive):
                return "presente"
        except (OSError, ValueError):
            return None

        try:
            os.listdir(os.path.dirname(hive))
        except PermissionError:
            # Que la carpeta este protegida es en si misma una senal de
            # que hay un Windows instalado, pero solo si el resto del
            # arbol responde: se confirma con un archivo legible.
            loader = os.path.join(root, "Windows", "System32", "ntoskrnl.exe")
            try:
                return "inaccesible" if os.path.isfile(loader) else None
            except (OSError, ValueError):
                return None
        except (OSError, ValueError):
            return None
    return None


def _classify(candidate: WindowsInstallation, root: str, hive_state: str) -> None:
    """Decide si la instalacion parece la del equipo averiado.

    No es una regla de diagnostico: no dice si algo esta mal, solo ayuda a
    elegir el disco correcto. Por eso vive en core/ y no en rules/.
    """
    if hive_state == "inaccesible":
        signals: List[str] = ["hive SYSTEM protegido (hace falta elevacion)"]
    else:
        signals = ["hive SYSTEM presente"]
    score = 1

    for marker in _WINPE_MARKERS:
        if os.path.exists(os.path.join(root, marker)):
            candidate.is_rescue_environment = True
            signals.append("parece un entorno de rescate (WinPE)")
            break

    for description, relative in _SYSTEM_MARKERS:
        if os.path.exists(os.path.join(root, relative)):
            signals.append(description)
            score += 1

    for marker in _BOOT_MARKERS:
        if os.path.exists(os.path.join(root, marker)):
            signals.append("gestor de arranque presente")
            score += 1
            break

    if candidate.drive_type == DRIVE_REMOVABLE:
        signals.append("unidad extraible")
    elif candidate.drive_type == DRIVE_RAMDISK:
        signals.append("disco en memoria")
        candidate.is_rescue_environment = True

    candidate.score = score
    candidate.signals = signals
    # Umbral: hive SYSTEM + al menos dos senales mas. Con menos se trata
    # casi siempre de restos de una instalacion vieja o de una copia de
    # seguridad de la carpeta Windows, no de un sistema arrancable.
    candidate.is_system_disk = score >= 3 and not candidate.is_rescue_environment


# ----------------------------------------------------------------------
# Unidades y volumenes
# ----------------------------------------------------------------------


def available_drive_roots() -> List[str]:
    """Todas las raices de unidad presentes, de A:\\ a Z:\\."""
    if sys.platform != "win32":
        return []

    letters: List[str] = []
    try:
        mask = ctypes.windll.kernel32.GetLogicalDrives()  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        mask = 0

    if mask:
        for index, letter in enumerate(string.ascii_uppercase):
            if mask & (1 << index):
                letters.append("%s:\\" % letter)
        return letters

    # Respaldo si la API no responde (no deberia, pero el barrido de
    # unidades no puede ser el motivo por el que la herramienta no arranca).
    with _quiet_device_errors():
        for letter in string.ascii_uppercase:
            root = "%s:\\" % letter
            if os.path.isdir(root):
                letters.append(root)
    return letters


def tool_root() -> str:
    """Raiz del volumen desde el que se esta ejecutando la herramienta.

    Con PyInstaller el codigo vive en una carpeta temporal que puede estar
    en otra unidad, asi que lo que interesa es donde esta el .exe.
    """
    if getattr(sys, "frozen", False):
        base = sys.executable
    else:
        base = os.path.abspath(__file__)
    drive, _ = os.path.splitdrive(base)
    if drive:
        return drive + os.sep
    return ""


def drive_type(root: str) -> int:
    """Tipo de unidad segun GetDriveTypeW. DRIVE_UNKNOWN fuera de Windows."""
    if sys.platform != "win32":
        return DRIVE_UNKNOWN
    try:
        with _quiet_device_errors():
            return int(
                ctypes.windll.kernel32.GetDriveTypeW(  # type: ignore[attr-defined]
                    ctypes.c_wchar_p(_as_api_root(root))
                )
            )
    except (AttributeError, OSError, ValueError):
        return DRIVE_UNKNOWN


def volume_info(root: str) -> Dict[str, str]:
    """Etiqueta y sistema de archivos del volumen.

    Devuelve cadenas vacias si el volumen no responde: en un disco que no
    arranca esto es esperable y no debe interrumpir nada.
    """
    empty = {"label": "", "filesystem": ""}
    if sys.platform != "win32":
        return empty

    name_buffer = ctypes.create_unicode_buffer(261)
    fs_buffer = ctypes.create_unicode_buffer(261)
    serial = ctypes.c_ulong(0)
    max_component = ctypes.c_ulong(0)
    flags = ctypes.c_ulong(0)

    try:
        with _quiet_device_errors():
            ok = ctypes.windll.kernel32.GetVolumeInformationW(  # type: ignore[attr-defined]
                ctypes.c_wchar_p(_as_api_root(root)),
                name_buffer,
                len(name_buffer),
                ctypes.byref(serial),
                ctypes.byref(max_component),
                ctypes.byref(flags),
                fs_buffer,
                len(fs_buffer),
            )
    except (AttributeError, OSError, ValueError):
        return empty

    if not ok:
        return empty
    return {"label": name_buffer.value or "", "filesystem": fs_buffer.value or ""}


def disk_usage(root: str) -> Dict[str, Optional[int]]:
    """Tamano y espacio libre del volumen, tolerante a fallos."""
    try:
        usage = shutil.disk_usage(root)
    except (OSError, ValueError):
        return {"total": None, "used": None, "free": None}
    return {"total": usage.total, "used": usage.used, "free": usage.free}


# ----------------------------------------------------------------------
# Utilidades
# ----------------------------------------------------------------------


def same_root(left: str, right: str) -> bool:
    """Compara dos raices ignorando mayusculas y barras finales.

    ``D:\\`` , ``d:`` y ``D:/`` son la misma unidad; compararlas como
    cadenas sueltas es una fuente segura de fallos en Windows.
    """
    return _normalize_root(left) == _normalize_root(right)


def _normalize_root(path: str) -> str:
    if not path:
        return ""
    normalized = os.path.normcase(os.path.abspath(path))
    trimmed = normalized.rstrip("\\/")
    # abspath("D:") devuelve el directorio actual de esa unidad, no su
    # raiz; tras recortar barras ambas formas quedan como "d:".
    return trimmed or normalized


def drive_letter_of_root(root: str) -> str:
    """``D:`` si la ruta ES la raiz de una unidad; cadena vacia si no.

    Se comprueba que sea la raiz y no solo que empiece por una letra: en
    las pruebas (y con volumenes montados en carpeta) trabajamos con
    rutas como ``C:\\Temp\\pytest-3\\disco1``, y llamarlas "C:" enganaria
    al usuario haciendole creer que analiza la unidad entera.
    """
    drive, tail = os.path.splitdrive(os.path.abspath(root))
    if drive and tail in ("", "\\", "/"):
        return drive
    return ""


def _as_api_root(root: str) -> str:
    """Las APIs de volumen exigen una raiz terminada en barra invertida."""
    if root and not root.endswith(("\\", "/")):
        return root + "\\"
    return root


@contextlib.contextmanager
def _quiet_device_errors() -> Iterator[None]:
    """Silencia los dialogos de "No hay disco en la unidad".

    Sin esto, barrer de A: a Z: en una maquina con lector de tarjetas
    vacio abre un cuadro de dialogo modal y la herramienta se queda
    colgada esperando a un usuario que no esta mirando.
    """
    if sys.platform != "win32":
        yield
        return

    sem_fail_critical_errors = 0x0001
    previous = None
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        previous = kernel32.SetErrorMode(sem_fail_critical_errors)
    except (AttributeError, OSError):
        previous = None
    try:
        yield
    finally:
        if previous is not None:
            try:
                ctypes.windll.kernel32.SetErrorMode(previous)  # type: ignore[attr-defined]
            except (AttributeError, OSError):
                pass


def summarize(candidates: Sequence[WindowsInstallation]) -> Dict[str, Any]:
    """Resumen serializable de una busqueda, util para el reporte JSON."""
    return {
        "count": len(candidates),
        "installations": [
            {
                "root": c.root,
                "drive": c.drive,
                "windows_root": c.windows_root,
                "label": c.label,
                "filesystem": c.filesystem,
                "free_bytes": c.free_bytes,
                "total_bytes": c.total_bytes,
                "is_system_disk": c.is_system_disk,
                "is_rescue_environment": c.is_rescue_environment,
                "signals": list(c.signals),
            }
            for c in candidates
        ],
    }
