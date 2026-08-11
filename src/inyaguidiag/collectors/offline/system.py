"""Identidad de un Windows que no arranca, leida de sus archivos.

Mismo `provides` que el colector online (`system.info`) a proposito: las
reglas y el reporte no deben enterarse de si el dato salio de WMI o de un
hive del registro copiado de un disco muerto. Ese es el contrato que hace
que el modo offline no obligue a duplicar el motor de diagnostico.

DE DONDE SALE CADA DATO
-----------------------
    hive SOFTWARE  ->  nombre del SO, build, edicion, fecha de instalacion
    hive SYSTEM    ->  nombre del equipo, arquitectura
    sistema de archivos -> respaldo cuando el registro no se puede leer

Se usa `python-registry` (Willi Ballenthin, el mismo autor de
python-evtx): Python puro, sin dependencias binarias, y por tanto capaz de
parsear un hive venga del Windows que venga. VERIFICADO instalando en el
entorno 3.8 del proyecto (version 1.3.1).

DEGRADACION
-----------
Si la libreria falta o el hive esta corrupto -- que es exactamente lo que
cabe esperar en un equipo que dejo de arrancar -- el colector NO falla:
deduce lo que puede del arbol de archivos (`Windows\\servicing\\Version`
da el numero de build sin tocar el registro) y deja un `ctx.warn()` para
que el reporte lo liste como cobertura incompleta.

ADEMAS DE LA IDENTIDAD
----------------------
Este colector inventaria el estado de los archivos criticos de arranque
(`system_files`, `boot_files`, `pending_update`). Son datos crudos --
existe / no existe / cuanto pesa -- que consumen las reglas BOT. El
colector no dice si falta algo importante; solo mide. Vive aca y no en un
colector aparte porque describir la instalacion montada es exactamente su
trabajo y recorre ese mismo arbol una sola vez.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from ...core.context import ScanContext, ScanMode
from ...core.registry import register_collector
from ..base import Collector

# Reutilizamos LA MISMA clasificacion de generacion que el modo online. Si
# offline y online clasificaran distinto, una regla condicionada por
# version se comportaria distinto segun el modo, que es precisamente lo
# que la arquitectura promete que no pasa.
from ..online.system import _windows_generation

log = logging.getLogger(__name__)

#: Clave del hive SOFTWARE con la identidad del sistema operativo.
_CURRENT_VERSION = "Microsoft\\Windows NT\\CurrentVersion"

#: Archivos sin los cuales Windows no llega ni a la pantalla de inicio.
#: El colector solo informa si existen y cuanto pesan; QUE significa que
#: falte alguno lo decide BOT-001.
_CRITICAL_FILES = (
    ("ntoskrnl.exe", os.path.join("System32", "ntoskrnl.exe")),
    ("hal.dll", os.path.join("System32", "hal.dll")),
    ("winload.exe", os.path.join("System32", "winload.exe")),
    ("winload.efi", os.path.join("System32", "winload.efi")),
    ("ntdll.dll", os.path.join("System32", "ntdll.dll")),
    ("smss.exe", os.path.join("System32", "smss.exe")),
    ("hive-system", os.path.join("System32", "config", "SYSTEM")),
    ("hive-software", os.path.join("System32", "config", "SOFTWARE")),
    ("ntfs.sys", os.path.join("System32", "drivers", "ntfs.sys")),
)

#: Ubicaciones del almacen de configuracion de arranque, relativas a la
#: raiz del volumen. La primera es el esquema BIOS/MBR, la segunda UEFI.
_BCD_LOCATIONS = (
    ("bios", os.path.join("Boot", "BCD")),
    ("uefi", os.path.join("EFI", "Microsoft", "Boot", "BCD")),
)

#: Otros archivos del gestor de arranque, como contexto para BOT-002.
_BOOT_MANAGER_FILES = (
    ("bootmgr", "bootmgr"),
    ("bootmgfw.efi", os.path.join("EFI", "Microsoft", "Boot", "bootmgfw.efi")),
)

#: Tope de archivos a contar al medir SoftwareDistribution\\Download. Esa
#: carpeta puede tener decenas de miles de entradas y recorrerla entera
#: desde un USB 2.0 tarda mas que todo el resto del escaneo junto.
_MAX_WALK_ENTRIES = 20000


@register_collector
class OfflineSystemInfoCollector(Collector):
    """Identidad y estado de la instalacion montada."""

    name = "system-info-offline"
    provides = "system.info"
    supported_modes = (ScanMode.OFFLINE,)
    cost = 2

    def collect(self, ctx: ScanContext) -> Dict[str, Any]:
        windows_root = ctx.windows_root
        volume_root = volume_root_of(windows_root)

        data: Dict[str, Any] = {
            "source": "disco-montado",
            "windows_root": windows_root,
            "volume_root": volume_root,
            "registry_reader": None,
            "hostname": "",
            "os_name": "",
            "os_version": "",
            "os_build": "",
            "architecture": "",
        }

        reader = _open_reader(ctx)
        if reader is not None:
            data["registry_reader"] = "python-registry"
            data.update(self._from_registry(ctx, reader))

        # El respaldo corre SIEMPRE, no solo cuando el registro falla:
        # rellena unicamente los huecos, asi que un hive parcialmente
        # legible sigue mandando sobre lo que deduce el sistema de
        # archivos.
        self._fill_from_filesystem(ctx, data, windows_root, volume_root)

        data["windows_generation"] = _windows_generation(
            data.get("os_name"), data.get("os_build")
        )
        data["system_files"] = _stat_many(windows_root, _CRITICAL_FILES)
        data["boot_files"] = _boot_files(volume_root)
        data["pending_update"] = _pending_update(windows_root, volume_root)
        return data

    # ------------------------------------------------------------------

    def _from_registry(self, ctx: ScanContext, reader: "_HiveReader") -> Dict[str, Any]:
        """Lee identidad de los hives SOFTWARE y SYSTEM."""
        data: Dict[str, Any] = {}
        config_dir = ctx.registry_hive_dir

        software = reader.load(os.path.join(config_dir, "SOFTWARE"))
        if software is None:
            ctx.warn(
                "No se pudo leer el hive SOFTWARE del disco montado; la "
                "version de Windows se dedujo del sistema de archivos"
            )
        else:
            build = software.value(_CURRENT_VERSION, "CurrentBuildNumber") or \
                software.value(_CURRENT_VERSION, "CurrentBuild")
            data.update(
                os_name=software.value(_CURRENT_VERSION, "ProductName"),
                os_version=software.value(_CURRENT_VERSION, "CurrentVersion"),
                os_build=_as_text(build),
                os_edition=software.value(_CURRENT_VERSION, "EditionID"),
                os_display_version=(
                    software.value(_CURRENT_VERSION, "DisplayVersion")
                    or software.value(_CURRENT_VERSION, "ReleaseId")
                ),
                build_lab=software.value(_CURRENT_VERSION, "BuildLabEx"),
                registered_owner=software.value(_CURRENT_VERSION, "RegisteredOwner"),
                update_build_revision=software.value(_CURRENT_VERSION, "UBR"),
            )
            install_date = software.value(_CURRENT_VERSION, "InstallDate")
            data["install_date"] = _epoch_to_text(install_date)
            data["install_date_epoch"] = install_date

        system = reader.load(os.path.join(config_dir, "SYSTEM"))
        if system is None:
            ctx.warn(
                "No se pudo leer el hive SYSTEM del disco montado; el nombre "
                "real del equipo no esta disponible"
            )
        else:
            control_set = _current_control_set(system)
            data["control_set"] = control_set
            data["hostname"] = _as_text(
                system.value(
                    control_set + "\\Control\\ComputerName\\ComputerName",
                    "ComputerName",
                )
            )
            data["architecture"] = _as_text(
                system.value(
                    control_set + "\\Control\\Session Manager\\Environment",
                    "PROCESSOR_ARCHITECTURE",
                )
            )
            # Marca de que el equipo quedo a mitad de una instalacion o de
            # una actualizacion. Es dato crudo; BOT-003 lo interpreta.
            data["setup_in_progress"] = system.value(
                "Setup", "SystemSetupInProgress"
            )
            data["setup_type"] = system.value("Setup", "SetupType")

        return {k: v for k, v in data.items() if v not in (None, "")}

    # ------------------------------------------------------------------

    def _fill_from_filesystem(
        self,
        ctx: ScanContext,
        data: Dict[str, Any],
        windows_root: str,
        volume_root: str,
    ) -> None:
        """Deduce del arbol de archivos lo que el registro no dio."""
        if not data.get("os_build"):
            build = _build_from_servicing(windows_root)
            if build:
                data["os_build"] = build
                data["build_source"] = "Windows\\servicing\\Version"

        if not data.get("os_name") and data.get("os_build"):
            data["os_name"] = _os_name_from_build(data["os_build"])

        if not data.get("architecture"):
            # Un Windows de 64 bits siempre tiene SysWOW64 para alojar el
            # subsistema de 32 bits; uno de 32 bits nunca la tiene.
            if os.path.isdir(os.path.join(windows_root, "SysWOW64")):
                data["architecture"] = "AMD64"
            elif os.path.isdir(os.path.join(windows_root, "System32")):
                data["architecture"] = "x86"

        if not data.get("hostname"):
            # Nombre sintetico deliberado. Si lo dejamos vacio, el motor
            # conserva el `platform.node()` de MachineInfo.unknown(), que
            # es el nombre del EQUIPO DE RESCATE: el reporte del disco
            # averiado se archivaria bajo el nombre del USB del tecnico y
            # se mezclaria con el de otros equipos.
            data["hostname"] = _synthetic_hostname(volume_root)
            ctx.warn(
                "No se pudo determinar el nombre del equipo averiado; el "
                "reporte se archiva como '%s'" % data["hostname"]
            )

        if not data.get("os_name"):
            ctx.warn(
                "No se pudo identificar la version de Windows del disco "
                "montado; las reglas que dependen de la version se saltaran"
            )


# ----------------------------------------------------------------------
# Lectura de hives
# ----------------------------------------------------------------------


class _HiveReader:
    """Envoltorio minimo sobre python-registry.

    Existe para que el resto del colector no tenga que conocer las
    excepciones concretas de la libreria ni repetir try/except en cada
    valor que lee. Un valor ausente devuelve None, nunca lanza: en un
    disco averiado la mitad de las claves pueden faltar.
    """

    def __init__(self, module: Any) -> None:
        self._module = module

    def load(self, path: str) -> Optional["_Hive"]:
        if not os.path.isfile(path):
            return None
        try:
            return _Hive(self._module.Registry(path))
        except Exception as exc:  # noqa: BLE001 - hive truncado o cifrado
            log.debug("hive ilegible %s: %s", path, exc)
            return None


class _Hive:
    """Un hive abierto. Acceso por ruta de clave y nombre de valor."""

    def __init__(self, registry: Any) -> None:
        self._registry = registry

    def key_exists(self, key_path: str) -> bool:
        return self._open(key_path) is not None

    def value(self, key_path: str, name: str) -> Any:
        key = self._open(key_path)
        if key is None:
            return None
        try:
            return key.value(name).value()
        except Exception:  # noqa: BLE001 - valor ausente o de tipo raro
            return None

    def _open(self, key_path: str) -> Any:
        try:
            return self._registry.open(key_path)
        except Exception:  # noqa: BLE001 - clave ausente
            return None


def _open_reader(ctx: ScanContext) -> Optional[_HiveReader]:
    """Carga python-registry, o avisa y sigue sin el."""
    try:
        from Registry import Registry as registry_module
    except ImportError:
        ctx.warn(
            "Falta la libreria python-registry: no se pudo leer el registro "
            "del disco montado. Instalar con: pip install python-registry"
        )
        return None
    return _HiveReader(registry_module)


def _current_control_set(hive: _Hive) -> str:
    """Nombre del ControlSet activo segun la clave Select.

    Windows mantiene varios ControlSet (001, 002...) y `Select\\Current`
    dice cual estaba en uso. Leer siempre ControlSet001 funciona casi
    siempre, y "casi siempre" es como se cuelan los datos equivocados en
    un reporte de diagnostico.
    """
    current = hive.value("Select", "Current")
    try:
        number = int(current)
    except (TypeError, ValueError):
        number = 1
    if number <= 0:
        number = 1
    return "ControlSet%03d" % number


# ----------------------------------------------------------------------
# Inventario de archivos
# ----------------------------------------------------------------------


def volume_root_of(windows_root: str) -> str:
    """Raiz del volumen que contiene la carpeta Windows indicada.

    Se calcula como el padre de `windows_root` y NO con `splitdrive`. Con
    ``D:\\Windows`` ambas formas dan ``D:\\``, pero la del padre tambien
    funciona con arboles de prueba y con volumenes montados en carpeta, lo
    que hace este codigo verificable sin un disco averiado a mano.
    """
    return os.path.dirname(os.path.abspath(windows_root))


def _stat_one(path: str) -> Dict[str, Any]:
    """Existencia y tamano de un archivo. Nunca lanza.

    `exists` es de TRES estados y eso es deliberado:

        True   el archivo esta y se pudo medir
        False  el archivo no esta (o su sector esta ilegible)
        None   NO SE SABE: no hubo permiso para mirar

    POR QUE NO ALCANZA `os.path.exists()`
    -------------------------------------
    Devuelve False ante cualquier OSError, incluido "acceso denegado". O
    sea que no distingue "no esta el archivo" de "no me dejan mirar", y
    esa confusion produjo un falso positivo grave: analizando un Windows
    sano pero en uso, los hives del registro dan WinError 5 y la regla
    BOT-001 reportaba CRITICO "faltan archivos esenciales de Windows".

    Decirle a un tecnico que el sistema esta destruido cuando esta sano es
    el peor error que puede cometer esta herramienta: invita a reinstalar
    sin necesidad y tira abajo la credibilidad del resto del reporte.

    El sector ilegible SI se reporta como ausente (False) a proposito: al
    cargador de arranque le da lo mismo un archivo que no esta que uno que
    no se puede leer del disco. Lo que no puede mezclarse es eso con un
    problema de permisos del entorno de analisis.
    """
    entry: Dict[str, Any] = {
        "path": path,
        "exists": False,
        "size_bytes": None,
        "access_denied": False,
    }
    try:
        entry["size_bytes"] = os.path.getsize(path)
        entry["exists"] = True
    except PermissionError:
        # No se puede afirmar nada sobre este archivo.
        entry["exists"] = None
        entry["access_denied"] = True
    except OSError:
        # FileNotFoundError y errores de E/S: para el arranque, equivalen.
        pass
    return entry


def _stat_many(base: str, items: Tuple[Tuple[str, str], ...]) -> Dict[str, Any]:
    return {name: _stat_one(os.path.join(base, relative)) for name, relative in items}


def _boot_files(volume_root: str) -> Dict[str, Any]:
    """Estado del BCD y del gestor de arranque en la raiz del volumen."""
    data: Dict[str, Any] = {
        "volume_root": volume_root,
        "bcd": _stat_many(volume_root, _BCD_LOCATIONS),
        "manager": _stat_many(volume_root, _BOOT_MANAGER_FILES),
    }
    return data


def _pending_update(windows_root: str, volume_root: str) -> Dict[str, Any]:
    """Restos de una actualizacion que no llego a terminar."""
    data: Dict[str, Any] = {
        "winre_agent": _dir_entry(os.path.join(volume_root, "$WinREAgent")),
        "windows_old": _dir_entry(os.path.join(volume_root, "Windows.old")),
        # Dos ubicaciones porque las dos existen segun la version: la del
        # servicio de componentes (WinSxS) es la clasica del bucle
        # "Deshaciendo los cambios"; la de config aparece en instalaciones
        # que quedaron a medias durante el arranque.
        "pending_xml": _stat_one(
            os.path.join(windows_root, "WinSxS", "pending.xml")
        ),
        "pending_xml_config": _stat_one(
            os.path.join(windows_root, "System32", "config", "pending.xml")
        ),
        "software_distribution_download": _measure_dir(
            os.path.join(windows_root, "SoftwareDistribution", "Download")
        ),
    }
    return data


def _dir_entry(path: str) -> Dict[str, Any]:
    return {"path": path, "exists": os.path.isdir(path)}


def _measure_dir(path: str) -> Dict[str, Any]:
    """Tamano aproximado de una carpeta, con tope de entradas.

    Devuelve `truncated=True` si se corto: el consumidor debe leer el
    tamano como un minimo, no como el total. Preferimos un dato marcado
    como incompleto antes que un escaneo que tarda diez minutos leyendo
    una carpeta de caches por USB.
    """
    result: Dict[str, Any] = {
        "path": path,
        "exists": os.path.isdir(path),
        "size_bytes": 0,
        "file_count": 0,
        "truncated": False,
    }
    if not result["exists"]:
        return result

    total = 0
    count = 0
    for current_dir, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(current_dir, name))
            except OSError:
                continue
            count += 1
            if count >= _MAX_WALK_ENTRIES:
                result["truncated"] = True
                break
        if result["truncated"]:
            break

    result["size_bytes"] = total
    result["file_count"] = count
    return result


# ----------------------------------------------------------------------
# Deducciones desde el sistema de archivos
# ----------------------------------------------------------------------


def _build_from_servicing(windows_root: str) -> str:
    """Numero de build leido de `Windows\\servicing\\Version`.

    Esa carpeta contiene subcarpetas con el nombre de la version completa
    (p.ej. `10.0.19041.1`). Es la forma mas fiable de saber la build sin
    abrir el registro ni parsear un ejecutable PE.
    """
    versions_dir = os.path.join(windows_root, "servicing", "Version")
    best: Optional[Tuple[int, ...]] = None
    try:
        names = os.listdir(versions_dir)
    except OSError:
        return ""

    for name in names:
        parts = name.split(".")
        try:
            numbers = tuple(int(p) for p in parts)
        except ValueError:
            continue
        if len(numbers) < 3:
            continue
        if best is None or numbers > best:
            best = numbers

    if best is None:
        return ""
    return str(best[2])


def _os_name_from_build(build: Any) -> str:
    """Nombre comercial aproximado a partir del numero de build."""
    try:
        number = int(str(build).strip())
    except (TypeError, ValueError):
        return ""
    if number >= 22000:
        return "Windows 11"
    if number >= 10240:
        return "Windows 10"
    if number >= 9600:
        return "Windows 8.1"
    if number >= 9200:
        return "Windows 8"
    if number >= 7600:
        return "Windows 7"
    return ""


def _synthetic_hostname(volume_root: str) -> str:
    drive, _ = os.path.splitdrive(os.path.abspath(volume_root))
    if drive:
        tag = drive.rstrip(":") or "x"
    else:
        tag = os.path.basename(os.path.abspath(volume_root)) or "x"
    return "equipo-offline-%s" % tag


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _epoch_to_text(value: Any) -> str:
    """`InstallDate` es un entero de segundos Unix en UTC."""
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return ""
    if seconds <= 0:
        return ""
    try:
        return datetime.utcfromtimestamp(seconds).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""
