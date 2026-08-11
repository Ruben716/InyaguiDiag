"""Contexto de escaneo: el "donde" y el "con que permisos".

Esta es la pieza que permite que un mismo motor de reglas sirva para una
maquina viva y para un disco muerto montado desde WinPE. Los colectores
nunca asumen `C:\\`; siempre preguntan al contexto.
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class ScanMode(str, Enum):
    """Modo de operacion.

    ONLINE  : Windows arrancado. Hay WMI, servicios, red, perf counters.
    OFFLINE : Arrancamos desde el USB (WinPE) y montamos el disco del
              equipo averiado. Solo hay archivos: .evtx, minidumps, registro.
    """

    ONLINE = "online"
    OFFLINE = "offline"


@dataclass
class ScanContext:
    """Todo lo que un colector necesita saber antes de recolectar.

    Attributes:
        mode: ONLINE u OFFLINE.
        windows_root: Raiz de la instalacion de Windows a analizar.
            En ONLINE suele ser C:\\Windows. En OFFLINE es la ruta del
            disco montado, p.ej. D:\\Windows.
        is_admin: Si el proceso tiene privilegios elevados. Varios
            colectores (SMART, algunos logs) degradan sin esto.
        quick: Modo rapido; los colectores caros se saltan.
        deep: Habilita analisis costosos (descarga de simbolos, etc).
    """

    mode: ScanMode = ScanMode.ONLINE
    windows_root: str = ""
    is_admin: bool = False
    quick: bool = False
    deep: bool = False
    output_dir: str = ""
    enabled_categories: Optional[List[str]] = None
    _warnings: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Construccion
    # ------------------------------------------------------------------

    @classmethod
    def for_live_system(cls, **kwargs: object) -> "ScanContext":
        """Contexto para la maquina en la que estamos corriendo."""
        return cls(
            mode=ScanMode.ONLINE,
            windows_root=_default_windows_root(),
            is_admin=is_elevated(),
            **kwargs,  # type: ignore[arg-type]
        )

    @classmethod
    def for_offline_disk(cls, windows_root: str, **kwargs: object) -> "ScanContext":
        """Contexto para un disco montado que no arranca.

        Args:
            windows_root: Ruta a la carpeta Windows del disco averiado.
        """
        normalized = os.path.abspath(windows_root)
        if not os.path.isdir(normalized):
            raise ValueError("No existe la carpeta de Windows: %s" % normalized)
        return cls(
            mode=ScanMode.OFFLINE,
            windows_root=normalized,
            is_admin=is_elevated(),
            **kwargs,  # type: ignore[arg-type]
        )

    # ------------------------------------------------------------------
    # Rutas derivadas (los colectores usan esto, nunca rutas literales)
    # ------------------------------------------------------------------

    @property
    def is_online(self) -> bool:
        return self.mode is ScanMode.ONLINE

    @property
    def is_offline(self) -> bool:
        return self.mode is ScanMode.OFFLINE

    @property
    def system32(self) -> str:
        return os.path.join(self.windows_root, "System32")

    @property
    def evtx_dir(self) -> str:
        """Carpeta de los logs de eventos (.evtx)."""
        return os.path.join(self.system32, "winevt", "Logs")

    @property
    def minidump_dir(self) -> str:
        """Volcados de BSOD."""
        return os.path.join(self.windows_root, "Minidump")

    @property
    def memory_dump(self) -> str:
        """Volcado completo del ultimo BSOD, si existe."""
        return os.path.join(self.windows_root, "MEMORY.DMP")

    @property
    def drivers_dir(self) -> str:
        return os.path.join(self.system32, "drivers")

    @property
    def registry_hive_dir(self) -> str:
        """Hives del registro; imprescindibles en modo OFFLINE."""
        return os.path.join(self.system32, "config")

    def path_exists(self, path: str) -> bool:
        try:
            return os.path.exists(path)
        except OSError:
            return False

    # ------------------------------------------------------------------
    # Avisos de cobertura
    # ------------------------------------------------------------------

    def warn(self, message: str) -> None:
        """Registra una limitacion del escaneo (no un hallazgo).

        Ejemplo: "sin privilegios de administrador, SMART omitido".
        El reporte las muestra para que el usuario sepa que quedo sin mirar.
        """
        if message not in self._warnings:
            self._warnings.append(message)

    @property
    def warnings(self) -> List[str]:
        return list(self._warnings)


# ----------------------------------------------------------------------
# Utilidades de plataforma
# ----------------------------------------------------------------------


def _default_windows_root() -> str:
    return os.environ.get("SystemRoot") or os.environ.get("WINDIR") or "C:\\Windows"


def is_elevated() -> bool:
    """True si corremos como administrador.

    En WinPE siempre es True (todo corre como SYSTEM). En Windows normal
    depende de como se lanzo el ejecutable.
    """
    if platform.system() != "Windows":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def is_winpe() -> bool:
    """Detecta si estamos corriendo dentro de WinPE.

    WinPE se identifica por la clave MiniNT en el registro. Sirve para
    que el CLI proponga el modo OFFLINE por defecto al arrancar del USB.
    """
    if platform.system() != "Windows":
        return False
    try:
        import winreg  # noqa: WPS433  (import local: no existe fuera de Windows)

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\MiniNT"
        ):
            return True
    except OSError:
        return False
    except ImportError:
        return False


def python_arch() -> str:
    """'x86' o 'x64' segun el interprete, no segun el sistema.

    Importante: un build x86 corriendo en Windows x64 ve un registro y un
    System32 redirigidos. Los colectores deben saberlo.
    """
    return "x64" if sys.maxsize > 2 ** 32 else "x86"
