"""Colector de almacenamiento: discos fisicos, volumenes y SMART.

SMART es el predictor numero uno de muerte de un equipo, asi que este
colector es el de mayor valor diagnostico del proyecto.

Estrategia por capas, de mejor a peor:

  1. `smartctl` (smartmontools) empaquetado en tools/  -> atributos SMART
     crudos, soporta SATA y NVMe. Requiere administrador.
  2. MSStorageDriver_FailurePredictStatus (WMI)        -> solo un booleano
     "va a fallar si/no", pero funciona sin herramientas externas.
  3. Win32_DiskDrive.Status                            -> minimo comun
     denominador, disponible desde Windows 7.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional

from ...core.context import ScanContext, ScanMode
from ...winapi import wmi_bridge
from ..base import Collector
from ...core.registry import register_collector

_NO_WINDOW = 0x08000000
_TIMEOUT = 45


@register_collector
class StorageCollector(Collector):
    """Inventario de discos y su salud."""

    name = "storage"
    provides = "storage.disks"
    supported_modes = (ScanMode.ONLINE,)
    requires_admin = True
    cost = 3

    def collect(self, ctx: ScanContext) -> Dict[str, Any]:
        disks = self._physical_disks()
        volumes = self._volumes()

        smart_tool = _find_smartctl()
        if smart_tool is None:
            ctx.warn(
                "smartctl no encontrado en tools/: se usara la prediccion "
                "de fallo de WMI, que es mucho menos precisa"
            )
        elif not ctx.is_admin:
            ctx.warn("SMART requiere administrador; se omitieron los atributos")

        for disk in disks:
            index = disk.get("index")
            if index is None:
                continue
            if smart_tool and ctx.is_admin:
                disk["smart"] = _smartctl_scan(smart_tool, index)
            else:
                disk["smart"] = None
            disk["failure_predicted"] = self._failure_prediction(index)

        return {
            "disks": disks,
            "volumes": volumes,
            "smartctl_available": smart_tool is not None,
        }

    # ------------------------------------------------------------------

    @staticmethod
    def _physical_disks() -> List[Dict[str, Any]]:
        rows = wmi_bridge.query(
            "Win32_DiskDrive",
            ("Index", "Model", "SerialNumber", "Size", "InterfaceType",
             "MediaType", "Status", "Partitions", "FirmwareRevision"),
        )
        disks: List[Dict[str, Any]] = []
        for row in rows:
            disks.append(
                {
                    "index": _as_int(row.get("Index")),
                    "model": row.get("Model"),
                    "serial": row.get("SerialNumber"),
                    "size_bytes": _as_int(row.get("Size")),
                    "interface": row.get("InterfaceType"),
                    "media_type": row.get("MediaType"),
                    "wmi_status": row.get("Status"),
                    "partitions": _as_int(row.get("Partitions")),
                    "firmware": row.get("FirmwareRevision"),
                }
            )
        return disks

    @staticmethod
    def _volumes() -> List[Dict[str, Any]]:
        rows = wmi_bridge.query(
            "Win32_LogicalDisk",
            ("DeviceID", "DriveType", "FileSystem", "Size", "FreeSpace",
             "VolumeName"),
        )
        volumes: List[Dict[str, Any]] = []
        for row in rows:
            size = _as_int(row.get("Size"))
            free = _as_int(row.get("FreeSpace"))
            percent_free: Optional[float] = None
            if size and free is not None and size > 0:
                percent_free = round(free * 100.0 / size, 1)
            volumes.append(
                {
                    "device": row.get("DeviceID"),
                    "drive_type": _as_int(row.get("DriveType")),
                    "filesystem": row.get("FileSystem"),
                    "label": row.get("VolumeName"),
                    "size_bytes": size,
                    "free_bytes": free,
                    "percent_free": percent_free,
                }
            )
        return volumes

    @staticmethod
    def _failure_prediction(index: int) -> Optional[bool]:
        """Prediccion de fallo de WMI. Disponible desde Windows 7."""
        rows = wmi_bridge.query(
            "MSStorageDriver_FailurePredictStatus",
            ("InstanceName", "PredictFailure", "Reason"),
            namespace="root/wmi",
        )
        for row in rows:
            instance = str(row.get("InstanceName") or "")
            # El InstanceName termina en "_0", "_1"... segun el disco.
            if instance.rstrip("_0123456789").endswith(("SCSI", "IDE")) or True:
                if instance.endswith("_%d" % index):
                    value = row.get("PredictFailure")
                    if isinstance(value, bool):
                        return value
                    if value is not None:
                        return str(value).strip().lower() in ("true", "1")
        return None


# ----------------------------------------------------------------------
# smartctl
# ----------------------------------------------------------------------


def _find_smartctl() -> Optional[str]:
    """Ubica smartctl.exe empaquetado junto al ejecutable.

    Busca en tools/<arch>/ relativo a la raiz del proyecto o del bundle
    de PyInstaller. No usa el PATH del sistema a proposito: queremos la
    version que nosotros validamos, no la que tenga la maquina ajena.
    """
    arch = "x64" if sys.maxsize > 2 ** 32 else "x86"

    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
        roots = [base, os.path.dirname(sys.executable)]
    else:
        # src/inyaguidiag/collectors/online/storage.py -> raiz del repo
        here = os.path.dirname(os.path.abspath(__file__))
        roots = [os.path.abspath(os.path.join(here, "..", "..", "..", ".."))]

    for root in roots:
        candidate = os.path.join(root, "tools", arch, "smartctl.exe")
        if os.path.isfile(candidate):
            return candidate
    return None


def _smartctl_scan(smartctl: str, index: int) -> Optional[Dict[str, Any]]:
    """Ejecuta smartctl en JSON sobre un disco fisico.

    smartctl usa codigos de salida como campo de bits: el bit 0 indica un
    error de linea de comandos, pero los bits 2..7 son avisos de salud del
    disco. Un exit code distinto de cero NO significa que la lectura
    fallo, y tratarlo asi haria que perdamos justo los discos enfermos.
    """
    device = "/dev/pd%d" % index
    cmd = [smartctl, "--json=c", "-a", device]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_TIMEOUT,
            creationflags=_NO_WINDOW,
        )
    except (subprocess.SubprocessError, OSError):
        return None

    if proc.returncode & 0b11:  # bits 0-1: fallo de comando o dispositivo
        return None

    try:
        return json.loads(proc.stdout.decode("utf-8", "ignore"))
    except ValueError:
        return None


def _as_int(value: Any) -> Any:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None
