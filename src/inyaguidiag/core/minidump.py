"""Lector de volcados de memoria de Windows (minidumps de pantallazo azul).

QUE HACE Y QUE NO
-----------------
Lee la cabecera DUMP_HEADER de un .dmp y extrae el codigo de detencion,
sus cuatro parametros y la lista de modulos presentes. Todo en Python
puro: no necesita WinDbg, ni el paquete de simbolos, ni conexion.

Lo que NO hace, y conviene tener claro: **no resuelve simbolos**. Sin los
simbolos de Microsoft no se puede afirmar "la funcion X del driver Y causo
el fallo". Lo que si se puede -- y es la mayor parte del valor practico --
es decir de que TIPO es el fallo y que modulos habia cargados.

Por que importa igual: el codigo de detencion ya separa las tres grandes
familias (disco / memoria / controlador), y esa separacion es la que le
dice al usuario si tiene que comprar una pieza o reinstalar un driver.

FORMATO
-------
Estructura DUMP_HEADER, identica en volcados completos y minidumps:

    x86 (DUMP_HEADER32)          x64 (DUMP_HEADER64)
    0x00 Signature  "PAGE"       0x00 Signature  "PAGE"
    0x04 ValidDump  "DUMP"       0x04 ValidDump  "DU64"
    0x20 MachineImageType        0x30 MachineImageType
    0x28 BugCheckCode            0x38 BugCheckCode
    0x2C Parametros 1-4 (4B)     0x40 Parametros 1-4 (8B)

Funciona igual en modo ONLINE y OFFLINE porque solo lee archivos: da lo
mismo si el Windows del que salieron arranca o no.
"""

from __future__ import annotations

import logging
import os
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

_SIGNATURE = b"PAGE"
_VALID_X64 = b"DU64"
_VALID_X86 = b"DUMP"

# Tipos de maquina (IMAGE_FILE_MACHINE_*)
_MACHINES = {
    0x014C: "x86",
    0x8664: "x64",
    0xAA64: "ARM64",
    0x01C4: "ARM",
}

# Cabecera minima que hay que poder leer para que el volcado sirva.
_MIN_HEADER = 0x60

# Tope de lectura al buscar nombres de modulos. Un minidump ronda los
# 300 KB; un volcado completo puede tener gigabytes y no vamos a recorrerlo
# entero solo para listar drivers.
_SCAN_LIMIT = 4 * 1024 * 1024

_SYS_NAME = re.compile(r"^[A-Za-z0-9_\-\.]{3,63}\.sys$")


@dataclass
class CrashDump:
    """Un volcado de pantallazo azul, ya interpretado."""

    path: str
    bugcheck_code: int
    parameters: List[int] = field(default_factory=list)
    architecture: str = ""
    timestamp: Optional[datetime] = None
    modules: List[str] = field(default_factory=list)
    size_bytes: int = 0
    truncated: bool = False

    @property
    def filename(self) -> str:
        return os.path.basename(self.path)

    @property
    def hex_code(self) -> str:
        return "0x%X" % self.bugcheck_code

    def parameter_text(self) -> str:
        return ", ".join("0x%X" % p for p in self.parameters)

    def __repr__(self) -> str:
        return "<CrashDump %s %s>" % (self.filename, self.hex_code)


class DumpParseError(Exception):
    """El archivo no es un volcado valido o esta demasiado danado."""


# ----------------------------------------------------------------------


def parse_dump(path: str, extract_modules: bool = True) -> CrashDump:
    """Lee un archivo .dmp y devuelve su contenido interpretado.

    Args:
        path: Ruta al volcado.
        extract_modules: Si buscar nombres de controladores. Cuesta un
            recorrido extra del archivo.

    Raises:
        DumpParseError: si no es un volcado reconocible.
    """
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise DumpParseError("No se pudo abrir %s: %s" % (path, exc))

    if size < _MIN_HEADER:
        raise DumpParseError(
            "Archivo demasiado pequeno para ser un volcado (%d bytes)" % size
        )

    with open(path, "rb") as handle:
        header = handle.read(_MIN_HEADER)

        if header[0:4] != _SIGNATURE:
            raise DumpParseError(
                "Firma invalida: se esperaba 'PAGE', se encontro %r" % header[0:4]
            )

        valid = header[4:8]
        if valid == _VALID_X64:
            is_64 = True
        elif valid == _VALID_X86:
            is_64 = False
        else:
            raise DumpParseError("Marca de volcado desconocida: %r" % valid)

        if is_64:
            machine = struct.unpack_from("<I", header, 0x30)[0]
            code = struct.unpack_from("<I", header, 0x38)[0]
            params = list(struct.unpack_from("<4Q", header, 0x40))
        else:
            machine = struct.unpack_from("<I", header, 0x20)[0]
            code = struct.unpack_from("<I", header, 0x28)[0]
            params = list(struct.unpack_from("<4I", header, 0x2C))

        modules: List[str] = []
        truncated = False
        if extract_modules:
            handle.seek(0)
            to_read = min(size, _SCAN_LIMIT)
            truncated = size > _SCAN_LIMIT
            modules = _find_driver_names(handle.read(to_read))

    return CrashDump(
        path=path,
        bugcheck_code=code,
        parameters=params,
        architecture=_MACHINES.get(machine, "0x%X" % machine),
        timestamp=_file_time(path),
        modules=modules,
        size_bytes=size,
        truncated=truncated,
    )


def _file_time(path: str) -> Optional[datetime]:
    """Momento del fallo, aproximado por la fecha del archivo.

    La cabecera tiene un campo de tiempo, pero su posicion cambia entre
    versiones de Windows y leerlo mal daria una fecha falsa, que es peor
    que una aproximada. Windows escribe el volcado durante el fallo, asi
    que la fecha del archivo es fiable en la practica.
    """
    try:
        return datetime.fromtimestamp(os.path.getmtime(path))
    except OSError:
        return None


def _find_driver_names(blob: bytes) -> List[str]:
    """Extrae nombres de controladores (.sys) presentes en el volcado.

    Los nombres de modulo viven en el volcado como cadenas UTF-16LE. En
    vez de recorrer las estructuras del nucleo --que cambian entre
    versiones de Windows y romperian la compatibilidad 7..11-- se buscan
    directamente las cadenas. Es tosco pero estable, y el resultado (que
    drivers habia cargados) es el mismo.
    """
    found = set()

    try:
        text = blob.decode("utf-16-le", errors="ignore")
    except (UnicodeDecodeError, ValueError):
        return []

    for candidate in re.findall(r"[A-Za-z0-9_\-\.\\]{4,120}\.sys", text):
        name = candidate.rsplit("\\", 1)[-1]
        if _SYS_NAME.match(name):
            found.add(name.lower())

    # Los volcados tambien traen cadenas ASCII en algunas secciones.
    ascii_text = blob.decode("latin-1", errors="ignore")
    for candidate in re.findall(r"[A-Za-z0-9_\-\.\\]{4,120}\.sys", ascii_text):
        name = candidate.rsplit("\\", 1)[-1]
        if _SYS_NAME.match(name):
            found.add(name.lower())

    return sorted(found)


# ----------------------------------------------------------------------


def find_dumps(minidump_dir: str, memory_dump: str = "") -> List[str]:
    """Localiza los archivos de volcado disponibles, sin repetidos.

    La deduplicacion no es cosmetica: un volcado contado dos veces produce
    hallazgos duplicados e infla el conteo de pantallazos, que es
    justamente el numero con el que las reglas deciden la severidad.

    En un Windows estandar MEMORY.DMP vive en <Windows>\\ y los minidumps
    en <Windows>\\Minidump\\, asi que no chocan. Pero en un disco montado
    en modo OFFLINE, o con una configuracion no estandar, si pueden.

    Args:
        minidump_dir: Normalmente <Windows>\\Minidump.
        memory_dump: Ruta al volcado completo (MEMORY.DMP), opcional.
    """
    paths: List[str] = []
    seen = set()

    def add(path: str) -> None:
        key = os.path.normcase(os.path.abspath(path))
        if key in seen:
            return
        seen.add(key)
        paths.append(path)

    if minidump_dir and os.path.isdir(minidump_dir):
        try:
            for entry in sorted(os.listdir(minidump_dir)):
                if entry.lower().endswith(".dmp"):
                    add(os.path.join(minidump_dir, entry))
        except OSError as exc:
            log.debug("no se pudo listar %s: %s", minidump_dir, exc)

    if memory_dump and os.path.isfile(memory_dump):
        add(memory_dump)

    return paths
