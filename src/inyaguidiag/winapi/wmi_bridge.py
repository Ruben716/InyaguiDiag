"""Acceso a WMI compatible con Windows 7 hasta Windows 11.

EL PROBLEMA
-----------
No existe una sola forma de consultar WMI que funcione en todo el rango:

  * `wmic.exe`            : disponible en Win7..Win10, DEPRECADO y en
                            proceso de eliminacion desde Win11 24H2.
  * PowerShell + JSON     : `ConvertTo-Json` llego en PowerShell 3.0.
                            Windows 7 sale de fabrica con PowerShell 2.0.
  * pywin32 / modulo wmi  : rapido y nativo, pero es una dependencia
                            binaria que hay que empaquetar por arquitectura.

LA SOLUCION
-----------
Cadena de respaldo con degradacion ordenada. Se intenta el mejor backend
disponible y se cae al siguiente:

    1. COM via pywin32      (preferido: rapido, sin crear procesos)
    2. PowerShell + JSON    (si hay PS >= 3.0)
    3. wmic.exe + CSV       (ultimo recurso para Win7 sin pywin32)

El backend elegido se resuelve UNA vez y se cachea. Los colectores llaman
a `query()` y no se enteran de nada de esto.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import shutil
import subprocess
import threading
from typing import Any, Dict, List, Optional, Sequence

log = logging.getLogger(__name__)

# Evita que las llamadas a procesos abran una consola negra cuando el
# ejecutable corre en modo ventana.
_NO_WINDOW = 0x08000000

_TIMEOUT = 30


class WmiUnavailable(RuntimeError):
    """No hay ningun backend de WMI utilizable en esta maquina."""


# ----------------------------------------------------------------------
# Backends
# ----------------------------------------------------------------------


class _Backend:
    name = "base"

    def available(self) -> bool:
        raise NotImplementedError

    def query(
        self,
        wmi_class: str,
        properties: Sequence[str],
        namespace: str,
        where: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        raise NotImplementedError


class _ComBackend(_Backend):
    """Consulta WMI por COM. Requiere pywin32.

    Sobre la inicializacion de COM: se hace UNA vez por hilo y no se
    deshace. La alternativa aparentemente correcta -- envolver cada
    consulta en CoInitialize/CoUninitialize -- esta mal: los objetos COM
    locales de la funcion siguen vivos cuando corre el `finally`, y al
    liberarse despues de CoUninitialize lanzan

        Win32 exception occurred releasing IUnknown at 0x...

    No llamar a CoUninitialize no filtra nada relevante: el runtime lo
    resuelve al terminar el proceso, y este proceso es de vida corta.
    """

    name = "com"

    def __init__(self) -> None:
        self._client = None
        self._local = threading.local()

    def available(self) -> bool:
        if self._client is not None:
            return True
        try:
            import win32com.client  # noqa: F401

            self._client = win32com.client
            return True
        except ImportError:
            return False

    def _ensure_com(self) -> None:
        """Inicializa COM en el hilo actual si aun no se hizo."""
        if getattr(self._local, "initialized", False):
            return
        import pythoncom  # type: ignore[import-not-found]

        try:
            pythoncom.CoInitialize()
        except Exception as exc:  # noqa: BLE001
            # RPC_E_CHANGED_MODE: el hilo ya estaba inicializado en otro
            # modelo de apartamento. Sigue siendo utilizable.
            log.debug("CoInitialize devolvio %s; se continua", exc)
        self._local.initialized = True

    def query(
        self,
        wmi_class: str,
        properties: Sequence[str],
        namespace: str,
        where: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        self._ensure_com()

        locator = self._client.Dispatch("WbemScripting.SWbemLocator")
        service = locator.ConnectServer(".", namespace)
        select = ", ".join(properties) if properties else "*"
        wql = "SELECT %s FROM %s" % (select, wmi_class)
        if where:
            wql += " WHERE " + where
        items = service.ExecQuery(wql)

        rows: List[Dict[str, Any]] = []
        for item in items:
            names = properties or [p.Name for p in item.Properties_]
            row: Dict[str, Any] = {}
            for prop in names:
                try:
                    row[prop] = _normalize(getattr(item, prop))
                except AttributeError:
                    row[prop] = None
            rows.append(row)
        return rows


class _PowerShellBackend(_Backend):
    """Consulta via PowerShell con salida JSON. Necesita PS >= 3.0."""

    name = "powershell"

    def __init__(self) -> None:
        self._checked = False
        self._ok = False
        self._exe: Optional[str] = None

    def available(self) -> bool:
        if self._checked:
            return self._ok
        self._checked = True

        # pwsh (PowerShell 7+) tiene prioridad; si no, Windows PowerShell.
        for candidate in ("pwsh", "powershell"):
            path = shutil.which(candidate)
            if not path:
                continue
            version = self._major_version(path)
            if version is not None and version >= 3:
                self._exe = path
                self._ok = True
                log.debug("backend powershell: %s (v%s)", path, version)
                break
        return self._ok

    @staticmethod
    def _major_version(exe: str) -> Optional[int]:
        try:
            out = subprocess.check_output(
                [exe, "-NoProfile", "-NonInteractive", "-Command",
                 "$PSVersionTable.PSVersion.Major"],
                stderr=subprocess.STDOUT,
                timeout=_TIMEOUT,
                creationflags=_NO_WINDOW,
            )
            return int(out.decode("utf-8", "ignore").strip())
        except (subprocess.SubprocessError, ValueError, OSError):
            return None

    def query(
        self,
        wmi_class: str,
        properties: Sequence[str],
        namespace: str,
        where: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        select = ",".join(properties) if properties else "*"
        # Con filtro se usa -Query (WQL) en vez de -ClassName: es la unica
        # forma de que clases como Win32_PingStatus, que EXIGEN un WHERE,
        # funcionen por este backend.
        if where:
            wql = "SELECT %s FROM %s WHERE %s" % (
                ",".join(properties) if properties else "*", wmi_class, where,
            )
            source = "Get-CimInstance -Namespace '{ns}' -Query \"{q}\" -ErrorAction Stop".format(
                ns=namespace, q=wql.replace('"', '`"'),
            )
        else:
            source = (
                "Get-CimInstance -Namespace '{ns}' -ClassName {cls} -ErrorAction Stop"
            ).format(ns=namespace, cls=wmi_class)

        script = (
            "{src} | Select-Object {props} | ConvertTo-Json -Depth 3 -Compress"
        ).format(src=source, props=select)

        out = subprocess.check_output(
            [str(self._exe), "-NoProfile", "-NonInteractive", "-Command", script],
            stderr=subprocess.PIPE,
            timeout=_TIMEOUT,
            creationflags=_NO_WINDOW,
        )
        text = out.decode("utf-8", "ignore").strip()
        if not text:
            return []

        parsed = json.loads(text)
        # ConvertTo-Json colapsa una lista de un elemento en un objeto.
        if isinstance(parsed, dict):
            parsed = [parsed]
        return [{k: _normalize(v) for k, v in row.items()} for row in parsed]


class _WmicBackend(_Backend):
    """Ultimo recurso: wmic.exe con salida CSV. Solo Windows 7/8/10."""

    name = "wmic"

    def __init__(self) -> None:
        self._exe: Optional[str] = None

    def available(self) -> bool:
        if self._exe:
            return True
        self._exe = shutil.which("wmic")
        return self._exe is not None

    def query(
        self,
        wmi_class: str,
        properties: Sequence[str],
        namespace: str,
        where: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if not properties:
            raise WmiUnavailable("El backend wmic requiere propiedades explicitas")

        # wmic usa rutas de namespace con backslash: root\wmi
        ns = namespace.replace("/", "\\")
        cmd = [
            str(self._exe),
            "/namespace:\\\\" + ns,
            "path",
            wmi_class,
        ]
        if where:
            cmd += ["where", where]
        cmd += [
            "get",
            ",".join(properties),
            "/format:csv",
        ]
        out = subprocess.check_output(
            cmd, stderr=subprocess.PIPE, timeout=_TIMEOUT, creationflags=_NO_WINDOW
        )
        text = out.decode("utf-8", "ignore")

        # wmic emite lineas en blanco y un BOM que rompen a csv.DictReader.
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if len(lines) < 2:
            return []
        reader = csv.DictReader(io.StringIO("\n".join(lines)))

        rows: List[Dict[str, Any]] = []
        for raw in reader:
            row = {k: _normalize(v) for k, v in raw.items() if k and k != "Node"}
            rows.append(row)
        return rows


# ----------------------------------------------------------------------
# Seleccion de backend
# ----------------------------------------------------------------------

_BACKENDS: List[_Backend] = [_ComBackend(), _PowerShellBackend(), _WmicBackend()]
_active: Optional[_Backend] = None
_resolved = False


def active_backend() -> Optional[str]:
    """Nombre del backend en uso, o None si no hay ninguno."""
    _resolve()
    return _active.name if _active else None


def _resolve() -> None:
    global _active, _resolved
    if _resolved:
        return
    _resolved = True
    if os.name != "nt":
        log.debug("no estamos en Windows; WMI deshabilitado")
        return
    for backend in _BACKENDS:
        try:
            if backend.available():
                _active = backend
                log.info("backend WMI seleccionado: %s", backend.name)
                return
        except Exception as exc:  # noqa: BLE001
            log.debug("backend %s no disponible: %s", backend.name, exc)
    log.warning("ningun backend WMI disponible")


def query(
    wmi_class: str,
    properties: Sequence[str] = (),
    namespace: str = "root/cimv2",
    where: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Consulta una clase WMI y devuelve filas normalizadas.

    Args:
        wmi_class: p.ej. "Win32_OperatingSystem".
        properties: Propiedades a traer. Vacio = todas (no soportado por
            el backend wmic).
        namespace: Namespace WMI. Ojo que wmic usa backslash.
        where: Filtro WQL sin la palabra WHERE, p.ej. "Address='8.8.8.8'".
            Algunas clases lo EXIGEN: Win32_PingStatus no devuelve nada
            sin el.

    Returns:
        Lista de dicts. Lista vacia si la clase no existe o no hay datos;
        eso es un resultado valido, no un error.

    Raises:
        WmiUnavailable: si no hay ningun backend utilizable.
    """
    _resolve()
    if _active is None:
        raise WmiUnavailable("No hay backend WMI disponible en este sistema")

    try:
        return _active.query(wmi_class, properties, namespace, where)
    except subprocess.TimeoutExpired:
        log.warning("timeout consultando %s", wmi_class)
        return []
    except subprocess.CalledProcessError as exc:
        # Clase inexistente en esta version de Windows: caso esperado.
        log.debug("consulta %s fallo: %s", wmi_class, exc)
        return []
    except Exception as exc:  # noqa: BLE001
        log.debug("consulta %s fallo (%s): %s", wmi_class, type(exc).__name__, exc)
        return []


def query_one(
    wmi_class: str,
    properties: Sequence[str] = (),
    namespace: str = "root/cimv2",
) -> Dict[str, Any]:
    """Como `query` pero devuelve la primera fila, o {} si no hay."""
    rows = query(wmi_class, properties, namespace)
    return rows[0] if rows else {}


# ----------------------------------------------------------------------


def _normalize(value: Any) -> Any:
    """Aplana los tipos que devuelve WMI a tipos de Python simples.

    WMI entrega objetos COM, fechas en formato CIM y strings con espacios
    de relleno. Los colectores no deberian lidiar con eso.
    """
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else None
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    if isinstance(value, dict):
        # PowerShell serializa CIM datetime como {"value": "/Date(...)/"}.
        if "value" in value and len(value) <= 2:
            return _normalize(value["value"])
        return {k: _normalize(v) for k, v in value.items()}
    return value
