"""Colector de identidad y estado basico del sistema (modo ONLINE).

Es el primer colector que corre y el unico autorizado a definir la
identidad de la maquina (`MachineInfo`), porque el nombre del equipo
determina la carpeta del reporte en el USB.
"""

from __future__ import annotations

import platform
from typing import Any, Dict

from ...core.context import ScanContext, ScanMode
from ...winapi import wmi_bridge
from ..base import Collector
from ...core.registry import register_collector


@register_collector
class SystemInfoCollector(Collector):
    """Identidad del equipo: SO, fabricante, modelo, arquitectura."""

    name = "system-info"
    provides = "system.info"
    supported_modes = (ScanMode.ONLINE,)
    cost = 1

    def collect(self, ctx: ScanContext) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "hostname": platform.node(),
            "architecture": platform.machine(),
            "wmi_backend": wmi_bridge.active_backend(),
        }

        os_row = wmi_bridge.query_one(
            "Win32_OperatingSystem",
            ("Caption", "Version", "BuildNumber", "OSArchitecture",
             "LastBootUpTime", "InstallDate", "TotalVisibleMemorySize",
             "FreePhysicalMemory"),
        )
        if os_row:
            data.update(
                os_name=os_row.get("Caption"),
                os_version=os_row.get("Version"),
                os_build=os_row.get("BuildNumber"),
                os_architecture=os_row.get("OSArchitecture"),
                last_boot=os_row.get("LastBootUpTime"),
                install_date=os_row.get("InstallDate"),
                total_memory_kb=_as_int(os_row.get("TotalVisibleMemorySize")),
                free_memory_kb=_as_int(os_row.get("FreePhysicalMemory")),
            )
        else:
            # Sin WMI todavia podemos identificar el SO por la stdlib.
            ctx.warn("WMI no respondio; datos del sistema limitados")
            data.update(
                os_name=platform.system(),
                os_version=platform.version(),
                os_build=platform.win32_ver()[1] if hasattr(platform, "win32_ver") else "",
            )

        cs_row = wmi_bridge.query_one(
            "Win32_ComputerSystem",
            ("Manufacturer", "Model", "TotalPhysicalMemory", "NumberOfProcessors",
             "SystemType", "Domain"),
        )
        if cs_row:
            data.update(
                manufacturer=cs_row.get("Manufacturer"),
                model=cs_row.get("Model"),
                total_physical_memory=_as_int(cs_row.get("TotalPhysicalMemory")),
                system_type=cs_row.get("SystemType"),
            )

        bios_row = wmi_bridge.query_one(
            "Win32_BIOS", ("SerialNumber", "SMBIOSBIOSVersion", "ReleaseDate")
        )
        if bios_row:
            data.update(
                serial=bios_row.get("SerialNumber"),
                bios_version=bios_row.get("SMBIOSBIOSVersion"),
                bios_date=bios_row.get("ReleaseDate"),
            )

        cpu_row = wmi_bridge.query_one(
            "Win32_Processor",
            ("Name", "NumberOfCores", "NumberOfLogicalProcessors", "MaxClockSpeed"),
        )
        if cpu_row:
            data.update(
                cpu_name=cpu_row.get("Name"),
                cpu_cores=_as_int(cpu_row.get("NumberOfCores")),
                cpu_threads=_as_int(cpu_row.get("NumberOfLogicalProcessors")),
                cpu_mhz=_as_int(cpu_row.get("MaxClockSpeed")),
            )

        data["windows_generation"] = _windows_generation(
            data.get("os_name"), data.get("os_build")
        )
        return data


def _as_int(value: Any) -> Any:
    """WMI devuelve numeros como strings segun el backend."""
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _windows_generation(caption: Any, build: Any) -> str:
    """Clasifica la version de Windows para condicionar reglas.

    Varias comprobaciones solo aplican a ciertas generaciones (p.ej. el
    estado de Secure Boot no existe en Win7). Las reglas consultan esta
    clave en vez de parsear el caption por su cuenta.
    """
    text = str(caption or "").lower()
    if "windows 7" in text:
        return "win7"
    if "windows 8" in text:
        return "win8"
    if "windows 10" in text or "windows 11" in text:
        # Win10 y Win11 comparten Caption en algunas builds tempranas;
        # el numero de build es el discriminador fiable.
        try:
            if int(str(build)) >= 22000:
                return "win11"
        except (TypeError, ValueError):
            pass
        return "win11" if "windows 11" in text else "win10"
    if "server" in text:
        return "server"
    return "desconocido"
