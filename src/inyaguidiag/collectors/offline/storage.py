"""Almacenamiento visto desde un disco montado que no arranca.

Mismo `provides` que el colector online (`storage.disks`) y MISMA FORMA de
los datos: las claves `disks` y `volumes`. STO-001 y STO-002 leen por esas
claves; cambiar la forma aca equivaldria a apagar esas reglas en el modo
en el que mas falta hacen.

QUE SE PUEDE Y QUE NO SE PUEDE SABER OFFLINE
--------------------------------------------
    volumenes  : SI. Espacio libre, sistema de archivos, etiqueta.
    SMART      : NO. Requiere hablar con el controlador del disco, no con
                 sus archivos. `disks` queda vacia y se deja un aviso de
                 cobertura para que "sin hallazgos de disco" no se lea
                 como "el disco esta sano".

QUE VOLUMEN SE ANALIZA
----------------------
Solo el que contiene la carpeta Windows indicada. No se barren todas las
unidades a proposito: en un rescate estan montados el USB, el WinPE y a
veces el disco de otro equipo, y reportar "queda poco espacio" del pendrive
del tecnico es ruido que entierra el hallazgo real.

SENALES DE APAGADO SUCIO
------------------------
Se recogen como datos crudos, sin juzgar: existencia de `$Mft`, de
`pagefile.sys` y `hiberfil.sys`, y restos de chkdsk (`FOUND.###`,
`*.CHK`). `hiberfil.sys` merece atencion doble: indica que el equipo pudo
quedar hibernado o con inicio rapido, lo que deja el NTFS marcado como
sucio, y ademas ocupa una fraccion grande de la RAM en disco, que es el
primer sitio donde mirar cuando el volumen esta lleno (BOT-004).
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from ...core import discovery
from ...core.context import ScanContext, ScanMode
from ...core.registry import register_collector
from ..base import Collector
from .system import volume_root_of

#: Tipo de unidad "disco fijo" de WMI/GetDriveTypeW. STO-002 solo mira
#: volumenes de este tipo, asi que el valor importa.
_DRIVE_FIXED = 3

#: Archivos y carpetas que delatan un apagado sucio o un chkdsk previo.
_INTEGRITY_FILES = (
    ("mft", "$Mft"),
    ("pagefile", "pagefile.sys"),
    ("hiberfil", "hiberfil.sys"),
    ("swapfile", "swapfile.sys"),
)

#: Cuantas carpetas FOUND.### listar como mucho. Un volumen que paso por
#: varios chkdsk puede tener cientos y no aportan nada tras las primeras.
_MAX_CHKDSK_ENTRIES = 25


@register_collector
class OfflineStorageCollector(Collector):
    """Volumen del disco montado y sus senales de integridad."""

    name = "storage-offline"
    provides = "storage.disks"
    supported_modes = (ScanMode.OFFLINE,)
    cost = 2

    def collect(self, ctx: ScanContext) -> Dict[str, Any]:
        volume_root = volume_root_of(ctx.windows_root)
        volume = _describe_volume(volume_root, ctx.windows_root)

        ctx.warn(
            "En modo offline no se puede leer SMART: la salud fisica del "
            "disco no se evaluo. Para descartar un disco muriendo hay que "
            "conectarlo a un equipo con Windows arrancado."
        )

        return {
            # Vacia y no ausente: las reglas de disco corren igual y no
            # encuentran nada, en vez de saltarse silenciosamente.
            "disks": [],
            "volumes": [volume],
            "smartctl_available": False,
            "source": "disco-montado",
            "volume_root": volume_root,
        }


# ----------------------------------------------------------------------


def _describe_volume(volume_root: str, windows_root: str) -> Dict[str, Any]:
    """Datos del volumen con la MISMA forma que produce el colector online."""
    usage = discovery.disk_usage(volume_root)
    info = discovery.volume_info(volume_root)

    size = usage.get("total")
    free = usage.get("free")
    percent_free: Optional[float] = None
    if size and free is not None and size > 0:
        percent_free = round(free * 100.0 / size, 1)

    detected_type = discovery.drive_type(volume_root)
    if detected_type in (discovery.DRIVE_UNKNOWN, discovery.DRIVE_NO_ROOT_DIR):
        # El volumen que el tecnico monto para analizar es, por definicion,
        # un disco fijo. Sin este respaldo STO-002 no dispararia nunca en
        # modo offline, que es donde el disco lleno es mas grave.
        detected_type = _DRIVE_FIXED

    return {
        "device": _device_name(volume_root),
        "root": volume_root,
        "drive_type": detected_type,
        "filesystem": info.get("filesystem") or None,
        "label": info.get("label") or None,
        "size_bytes": size,
        "free_bytes": free,
        "percent_free": percent_free,
        "is_system_volume": True,
        "windows_root": windows_root,
        "integrity": _integrity_signals(volume_root, windows_root),
    }


def _device_name(volume_root: str) -> str:
    """``D:`` cuando hay letra; si no, la ruta montada."""
    return discovery.drive_letter_of_root(volume_root) or volume_root


def _integrity_signals(volume_root: str, windows_root: str) -> Dict[str, Any]:
    """Rastros de apagado sucio y de reparaciones previas del sistema de archivos."""
    signals: Dict[str, Any] = {}

    for name, filename in _INTEGRITY_FILES:
        signals[name] = _stat(os.path.join(volume_root, filename))

    chkdsk = _chkdsk_artifacts(volume_root, windows_root)
    signals["chkdsk_artifacts"] = chkdsk

    hiberfil = signals["hiberfil"]
    # Un hiberfil.sys con contenido significa que el volumen puede estar
    # montado en un estado inconsistente (hibernacion o inicio rapido).
    # Es DATO, no diagnostico: quien decide que hacer es una regla.
    signals["hibernation_image"] = bool(
        hiberfil.get("exists") and (hiberfil.get("size_bytes") or 0) > 0
    )
    signals["chkdsk_ran_before"] = bool(chkdsk)

    return signals


def _chkdsk_artifacts(volume_root: str, windows_root: str) -> List[Dict[str, Any]]:
    """Carpetas FOUND.### y registros de chkdsk.

    Cuando chkdsk recupera cadenas de clusters huerfanas las deposita en
    `FOUND.000\\FILE0000.CHK`. Su presencia demuestra que el sistema de
    archivos ya se corrompio al menos una vez en este volumen.
    """
    artifacts: List[Dict[str, Any]] = []

    try:
        entries = sorted(os.listdir(volume_root))
    except OSError:
        entries = []

    for name in entries:
        upper = name.upper()
        if not (upper.startswith("FOUND.") or upper.endswith(".CHK")):
            continue
        artifacts.append(
            {"path": os.path.join(volume_root, name), "kind": "recuperado-por-chkdsk"}
        )
        if len(artifacts) >= _MAX_CHKDSK_ENTRIES:
            return artifacts

    log_dir = os.path.join(windows_root, "System32", "LogFiles", "Chkdsk")
    try:
        logs = sorted(os.listdir(log_dir))
    except OSError:
        logs = []

    for name in logs:
        artifacts.append({"path": os.path.join(log_dir, name), "kind": "registro-chkdsk"})
        if len(artifacts) >= _MAX_CHKDSK_ENTRIES:
            break

    return artifacts


def _stat(path: str) -> Dict[str, Any]:
    """Existencia y tamano, tolerante a metadatos inaccesibles.

    `$Mft` merece un comentario: NTFS lo expone en la raiz pero Windows
    niega el acceso a su contenido. Segun como este montado el volumen, el
    tamano puede venir vacio aunque el archivo exista, asi que la ausencia
    de `$Mft` NO prueba corrupcion. Se informa tal cual y punto.
    """
    entry: Dict[str, Any] = {"path": path, "exists": False, "size_bytes": None}
    try:
        entry["exists"] = os.path.exists(path)
    except OSError:
        return entry
    if not entry["exists"]:
        return entry
    try:
        entry["size_bytes"] = os.path.getsize(path)
    except OSError:
        pass
    return entry
