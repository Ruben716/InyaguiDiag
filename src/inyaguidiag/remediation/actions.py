"""Acciones de reparacion concretas.

Cada `action_id` de aca corresponde a un `Remedy.action_id` que ya emiten
las reglas. La lista no se inventa: si una regla propone una reparacion
automatizable, aca tiene que existir la accion, y hay un test que recorre
todas las reglas para que ninguna quede huerfana.

    clean-temp-files        STO-002                       SAFE
    run-chkdsk              EVT (disco), CRA (disco)      INVASIVE
    run-sfc                 CRA (controlador/sistema)     INVASIVE
    run-memory-diagnostic   CRA (memoria)                 MODERATE
    renew-dhcp              NET-003                       MODERATE
    set-public-dns          NET-005                       MODERATE
    reset-winsock           NET-006                       INVASIVE

Todas heredan los cerrojos de `base.Action`: `execute()` simula por
defecto y ejecutar de verdad exige una `Confirmation` emitida a partir
del preview que vio el usuario. Ver la explicacion en base.py.
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..core.context import ScanContext
from ..core.models import RiskLevel
from .base import (
    Action,
    ActionPreview,
    ActionResult,
    human_size,
    is_valid_interface_name,
    is_valid_ipv4,
    is_valid_volume,
    path_is_within,
    register_action,
    run_command,
)

log = logging.getLogger(__name__)

#: DNS publicos de Cloudflare y Google. Se eligen estos dos y de distintos
#: proveedores a proposito: si uno se cae, el otro no depende de la misma
#: infraestructura.
PUBLIC_DNS = ("1.1.1.1", "8.8.8.8")

#: Nombre del respaldo de DNS. Se guarda en disco y no solo en memoria
#: porque el proceso es de vida corta: si el tecnico cierra la
#: herramienta, tiene que poder volver atras igual.
DNS_BACKUP_FILE = "inyaguidiag-dns-backup.json"

_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _system_tool(ctx: ScanContext, name: str) -> str:
    """Ruta absoluta a una herramienta de System32, si se puede resolver.

    Se usa ruta absoluta y no el nombre suelto porque CreateProcess de
    Windows busca primero en el directorio actual: un `netsh.exe`
    plantado en la carpeta desde la que se lanzo el USB se ejecutaria en
    lugar del real. Si no esta donde deberia, se cae al nombre simple
    (WinPE y algunos equipos mueven las cosas de sitio).
    """
    candidate = os.path.join(ctx.system32, name)
    try:
        if os.path.isfile(candidate):
            return candidate
    except OSError:
        pass
    return name


def _system_drive(ctx: ScanContext) -> str:
    """Unidad donde vive Windows, en formato 'C:'."""
    drive = os.path.splitdrive(ctx.windows_root or "C:\\Windows")[0]
    return drive if is_valid_volume(drive) else "C:"


# ======================================================================
# clean-temp-files
# ======================================================================


@register_action
class CleanTempFilesAction(Action):
    """Borra archivos temporales de Windows y del usuario.

    Es la unica accion que no delega en un programa externo: borra
    archivos ella misma. Por eso es tambien la que necesita la
    comprobacion de alcance mas estricta (ver `_collect_files`): un error
    aca no da un mensaje feo, borra datos del cliente.
    """

    action_id = "clean-temp-files"
    title = "Limpiar archivos temporales"
    description = (
        "Vacia las carpetas temporales del usuario y de Windows, el "
        "Prefetch y las descargas ya instaladas de Windows Update."
    )
    risk = RiskLevel.SAFE
    requires_admin = False   # el TEMP del usuario no lo necesita; el resto se salta
    requires_reboot = False
    timeout = 300

    # ------------------------------------------------------------------

    def targets(self, ctx: ScanContext) -> List[Tuple[str, str, bool]]:
        """Carpetas objetivo: (etiqueta, ruta, necesita_admin).

        Es la lista CERRADA de lo que esta accion puede tocar. Nada fuera
        de estas carpetas se borra jamas, y eso se comprueba archivo por
        archivo, no una sola vez al principio.
        """
        root = ctx.windows_root or "C:\\Windows"
        candidates = [
            ("Temporales del usuario",
             os.environ.get("TEMP") or os.environ.get("TMP") or "", False),
            ("Temporales de Windows", os.path.join(root, "Temp"), True),
            ("Prefetch", os.path.join(root, "Prefetch"), True),
            ("Descargas de Windows Update",
             os.path.join(root, "SoftwareDistribution", "Download"), True),
        ]
        result = []
        for label, path, needs_admin in candidates:
            if path and self._is_safe_root(path, ctx):
                result.append((label, path, needs_admin))
        return result

    @staticmethod
    def _is_safe_root(path: str, ctx: ScanContext) -> bool:
        """Rechaza carpetas objetivo absurdas antes de mirarlas siquiera.

        Si la variable TEMP viniera mal puesta (apuntando a C:\\ o a la
        propia carpeta de Windows, cosa que pasa en equipos manoseados),
        una limpieza "segura" arrasaria el sistema. Se descarta cualquier
        raiz que contenga a System32 o a la carpeta de Windows, y
        cualquier raiz de unidad.
        """
        try:
            if not os.path.isdir(path):
                return False
        except OSError:
            return False
        real = os.path.realpath(path)
        # Raiz de unidad: "C:\\" -> el resto de la ruta esta vacio.
        drive, tail = os.path.splitdrive(real)
        if not tail.strip("\\/"):
            return False
        # Contiene a Windows o a System32: demasiado arriba en el arbol.
        if path_is_within(ctx.windows_root, real) and not path_is_within(
            real, ctx.windows_root
        ):
            return False
        if path_is_within(ctx.system32, real):
            return False
        return True

    # ------------------------------------------------------------------

    def _collect_files(self, root: str) -> Tuple[List[str], int, int]:
        """Lista los archivos borrables de `root`.

        Returns:
            (rutas, bytes_totales, descartados_por_alcance)

        CADA ruta se valida contra `root` con `path_is_within`, que
        compara rutas reales. Eso cubre los dos escapes posibles en
        Windows: un junction dentro de la carpeta temporal apuntando a
        otro sitio, y un nombre con `..`. Un archivo que se sale del
        alcance no se borra: se cuenta y se ignora.
        """
        files: List[str] = []
        total = 0
        outside = 0
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            # Poda: no bajar por subcarpetas que en realidad apuntan fuera.
            dirnames[:] = [
                d for d in dirnames
                if path_is_within(os.path.join(dirpath, d), root)
            ]
            for name in filenames:
                full = os.path.join(dirpath, name)
                if not path_is_within(full, root):
                    outside += 1
                    continue
                try:
                    total += os.path.getsize(full)
                except OSError:
                    # Archivo que desaparecio o al que no se puede mirar:
                    # se borra igual si se deja, pero no suma al calculo.
                    pass
                files.append(full)
        return files, total, outside

    def _clean_root(self, root: str) -> Dict[str, Any]:
        """Borra el contenido de una carpeta objetivo. Nunca la carpeta."""
        files, _size, outside = self._collect_files(root)
        deleted = 0
        freed = 0
        locked = 0
        for full in files:
            # Segunda comprobacion, justo antes de borrar. Es barata y
            # cierra la ventana entre listar y borrar.
            if not path_is_within(full, root):
                outside += 1
                continue
            try:
                size = os.path.getsize(full)
            except OSError:
                size = 0
            try:
                os.remove(full)
            except PermissionError:
                # Tipico: archivo de solo lectura. Se reintenta una vez
                # quitandole el atributo; si sigue sin poder, esta en uso.
                try:
                    os.chmod(full, stat.S_IWRITE)
                    os.remove(full)
                except OSError:
                    locked += 1
                    continue
            except OSError:
                locked += 1
                continue
            deleted += 1
            freed += size

        removed_dirs = self._remove_empty_dirs(root)
        return {
            "root": root,
            "deleted": deleted,
            "freed": freed,
            "locked": locked,
            "outside": outside,
            "removed_dirs": removed_dirs,
        }

    def _remove_empty_dirs(self, root: str) -> int:
        """Quita las subcarpetas que quedaron vacias. Nunca la raiz."""
        removed = 0
        for dirpath, dirnames, _filenames in os.walk(root, topdown=False):
            if os.path.realpath(dirpath) == os.path.realpath(root):
                continue
            if not path_is_within(dirpath, root):
                continue
            try:
                os.rmdir(dirpath)
                removed += 1
            except OSError:
                pass  # no estaba vacia o esta en uso
        return removed

    # ------------------------------------------------------------------

    def preview(self, ctx: ScanContext) -> ActionPreview:
        targets = self.targets(ctx)
        lines: List[str] = []
        total = 0
        warnings: List[str] = []
        for label, path, needs_admin in targets:
            if needs_admin and not ctx.is_admin:
                lines.append("%s: %s  (se omite: requiere administrador)"
                             % (label, path))
                continue
            files, size, _outside = self._collect_files(path)
            total += size
            lines.append("%s: %s  (%d archivos, %s)"
                         % (label, path, len(files), human_size(size)))

        if not ctx.is_admin:
            warnings.append(
                "sin administrador solo se limpia el temporal del usuario"
            )
        warnings.append(
            "los archivos en uso no se pueden borrar y se omiten sin error"
        )
        warnings.append(
            "vaciar Prefetch hace que los primeros arranques sean algo mas "
            "lentos hasta que Windows lo reconstruye"
        )

        return ActionPreview(
            action_id=self.action_id,
            title=self.title,
            summary=(
                "Se borrara el CONTENIDO de las carpetas listadas abajo. No "
                "se toca ningun archivo fuera de ellas ni se borran las "
                "carpetas en si. No se tocan documentos, fotos ni la "
                "papelera de reciclaje."
            ),
            risk=self.risk,
            requires_admin=self.requires_admin,
            requires_reboot=self.requires_reboot,
            commands=["(borrado de archivos desde la propia herramienta, "
                      "sin comandos externos)"],
            targets=lines,
            warnings=warnings,
            reversible=False,   # un temporal borrado no vuelve
            estimated_freed_bytes=total,
        )

    def _perform(self, ctx: ScanContext) -> ActionResult:
        reports = []
        freed = 0
        deleted = 0
        locked = 0
        outside = 0
        for label, path, needs_admin in self.targets(ctx):
            if needs_admin and not ctx.is_admin:
                reports.append("%s: omitido (requiere administrador)" % label)
                continue
            stats = self._clean_root(path)
            freed += stats["freed"]
            deleted += stats["deleted"]
            locked += stats["locked"]
            outside += stats["outside"]
            reports.append(
                "%s: %d archivos borrados, %s liberados, %d en uso omitidos"
                % (label, stats["deleted"], human_size(stats["freed"]),
                   stats["locked"])
            )

        message = "Se liberaron %s borrando %d archivos." % (
            human_size(freed), deleted)
        if locked:
            message += (" %d archivos estaban en uso y se dejaron como "
                        "estaban." % locked)
        if outside:
            # Nunca deberia pasar; si pasa, es informacion valiosa.
            message += (" %d rutas quedaron fuera del alcance permitido y NO "
                        "se tocaron." % outside)

        return self._result(
            success=True,
            message=message,
            output="\n".join(reports),
            returncode=0,
            details={"freed_bytes": freed, "deleted": deleted,
                     "locked": locked, "outside_scope": outside},
        )


# ======================================================================
# run-chkdsk
# ======================================================================


@register_action
class RunChkdskAction(Action):
    """Programa una comprobacion del disco para el proximo arranque."""

    action_id = "run-chkdsk"
    title = "Comprobar y reparar el disco (chkdsk)"
    description = (
        "Programa chkdsk con reparacion de errores y analisis de sectores "
        "para el proximo reinicio."
    )
    risk = RiskLevel.INVASIVE
    requires_admin = True
    requires_reboot = True
    #: chkdsk sobre el volumen del sistema no puede bloquearlo: pregunta y
    #: sale enseguida. El margen es por si el volumen indicado no es el del
    #: sistema y decide empezar el analisis.
    timeout = 300

    def __init__(self, volume: Optional[str] = None) -> None:
        # Validacion en el constructor: el parametro nunca llega crudo al
        # comando. 'C:' y nada mas; cualquier otra cosa es un error de
        # programacion y se detecta aca, no al armar la linea de comandos.
        if volume is not None and not is_valid_volume(volume):
            raise ValueError(
                "Volumen invalido '%s': se espera el formato 'C:'" % volume
            )
        self._volume = volume.upper() if volume else None

    def volume(self, ctx: ScanContext) -> str:
        return self._volume or _system_drive(ctx)

    def _command(self, ctx: ScanContext) -> List[str]:
        volume = self.volume(ctx)
        if not is_valid_volume(volume):   # defensa en profundidad
            raise ValueError("Volumen invalido: %s" % volume)
        return [_system_tool(ctx, "chkdsk.exe"), volume, "/F", "/R"]

    def preview(self, ctx: ScanContext) -> ActionPreview:
        volume = self.volume(ctx)
        return ActionPreview(
            action_id=self.action_id,
            title=self.title,
            summary=(
                "Se le pedira a Windows que revise y repare el sistema de "
                "archivos de %s y que busque sectores danados. Como el "
                "volumen esta en uso, la comprobacion queda PROGRAMADA y se "
                "ejecuta durante el proximo arranque, antes de que cargue "
                "Windows." % volume
            ),
            risk=self.risk,
            requires_admin=self.requires_admin,
            requires_reboot=self.requires_reboot,
            commands=[" ".join(self._command(ctx)), "chkntfs %s" % volume],
            targets=["Volumen %s" % volume],
            warnings=[
                "el analisis puede tardar horas en discos grandes o con "
                "problemas; el equipo no se puede usar mientras corre",
                "si el disco esta muriendo, chkdsk puede acelerar el fallo: "
                "respalda los datos ANTES de reiniciar",
                "no apagues el equipo durante la comprobacion",
            ],
            reversible=False,
        )

    def _perform(self, ctx: ScanContext) -> ActionResult:
        volume = self.volume(ctx)
        # chkdsk pregunta si se desea programar la comprobacion para el
        # proximo arranque. La respuesta afirmativa depende del idioma de
        # Windows (S en castellano, Y en ingles), asi que se mandan las dos.
        result = run_command(self._command(ctx), timeout=self.timeout,
                             input_text="S\r\nY\r\n")

        if result.not_found:
            return self._result(False, "No se encontro chkdsk en este sistema.")
        if result.timed_out:
            return self._result(
                False,
                "chkdsk no respondio a tiempo. Puede haber empezado a "
                "analizar el volumen; revisalo desde una consola de "
                "administrador antes de repetir la operacion.",
                output=result.output,
            )

        # Verificacion independiente: chkntfs dice si el volumen quedo
        # marcado. Es de solo lectura y aclara un exito dudoso.
        check = run_command([_system_tool(ctx, "chkntfs.exe"), volume], timeout=30)
        output = result.output
        if check.output:
            output += "\n\n" + check.output

        scheduled = result.returncode == 0 or "chkdsk" in check.output.lower()
        if scheduled:
            message = (
                "Comprobacion de %s programada. Reinicia el equipo para que "
                "se ejecute; no lo apagues mientras trabaja." % volume
            )
        else:
            message = (
                "chkdsk termino con codigo %s. Revisa la salida: puede que "
                "el volumen no exista o que no haya permisos suficientes."
                % result.returncode
            )
        return self._result(scheduled, message, output=output,
                            returncode=result.returncode)


# ======================================================================
# run-sfc
# ======================================================================


@register_action
class RunSfcAction(Action):
    """Comprueba y repara los archivos de sistema con sfc /scannow."""

    action_id = "run-sfc"
    title = "Reparar archivos del sistema (sfc /scannow)"
    description = (
        "Compara los archivos del sistema con la copia de referencia de "
        "Windows y restaura los que esten danados."
    )
    risk = RiskLevel.INVASIVE
    requires_admin = True
    requires_reboot = False
    #: sfc tarda de 10 a 45 minutos en un equipo con disco mecanico. Un
    #: timeout corto lo mataria a mitad de una reparacion.
    timeout = 3600

    def _command(self, ctx: ScanContext) -> List[str]:
        return [_system_tool(ctx, "sfc.exe"), "/scannow"]

    def preview(self, ctx: ScanContext) -> ActionPreview:
        return ActionPreview(
            action_id=self.action_id,
            title=self.title,
            summary=(
                "Windows revisara uno por uno sus archivos de sistema y "
                "restaurara los que no coincidan con el original. Corre "
                "ahora mismo, no al reiniciar, y no se puede interrumpir "
                "sin riesgo."
            ),
            risk=self.risk,
            requires_admin=self.requires_admin,
            requires_reboot=self.requires_reboot,
            commands=[" ".join(self._command(ctx))],
            targets=["Archivos de sistema de %s" % (ctx.windows_root or "C:\\Windows")],
            warnings=[
                "tarda entre 10 y 45 minutos; no cierres la herramienta",
                "si sfc no logra reparar todo, el siguiente paso es DISM "
                "/RestoreHealth (no automatizado en esta version)",
            ],
            reversible=False,
        )

    def _perform(self, ctx: ScanContext) -> ActionResult:
        result = run_command(self._command(ctx), timeout=self.timeout)

        if result.not_found:
            return self._result(False, "No se encontro sfc en este sistema.")
        if result.timed_out:
            return self._result(
                False,
                "sfc supero el tiempo maximo (%d minutos) y se interrumpio. "
                "Vuelve a ejecutarlo desde una consola de administrador."
                % (self.timeout // 60),
                output=result.output,
            )

        lowered = result.output.lower()
        # sfc no distingue con el codigo de salida entre "todo bien" y
        # "repare cosas"; hay que leer el texto.
        if "no encontr" in lowered or "did not find" in lowered:
            message = "Los archivos del sistema estan integros: no habia nada que reparar."
        elif "repar" in lowered or "repair" in lowered:
            message = ("Se encontraron archivos danados y se repararon. "
                       "Conviene reiniciar y volver a diagnosticar.")
        elif result.returncode == 0:
            message = "sfc termino correctamente."
        else:
            message = ("sfc termino con codigo %s. Si dice que no pudo "
                       "reparar algunos archivos, el siguiente paso es DISM."
                       % result.returncode)

        return self._result(result.returncode == 0, message,
                            output=result.output, returncode=result.returncode)


# ======================================================================
# run-memory-diagnostic
# ======================================================================


@register_action
class RunMemoryDiagnosticAction(Action):
    """Programa el Diagnostico de memoria de Windows para el proximo arranque."""

    action_id = "run-memory-diagnostic"
    title = "Programar el diagnostico de memoria de Windows"
    description = (
        "Marca el arranque siguiente para que corra la prueba de memoria "
        "integrada de Windows antes de cargar el sistema."
    )
    risk = RiskLevel.MODERATE
    #: bcdedit exige elevacion, asi que esto es True y el remedio de la
    #: regla (crash_rules) declara lo mismo. Antes iban en desacuerdo: la
    #: regla ofrecia el arreglo sin avisar que hacia falta administrador y
    #: la accion fallaba al intentarlo, delante del cliente. Si alguna vez
    #: divergen otra vez, el test que compara ambos lo detecta.
    requires_admin = True
    requires_reboot = True
    timeout = 60

    def _command(self, ctx: ScanContext) -> List[str]:
        # Se usa bcdedit y no mdsched.exe a proposito: mdsched abre una
        # ventana y espera que alguien haga clic, cosa imposible desde una
        # herramienta que corre sin interaccion.
        return [_system_tool(ctx, "bcdedit.exe"), "/bootsequence", "{memdiag}"]

    def preview(self, ctx: ScanContext) -> ActionPreview:
        warnings = [
            "la prueba corre al arrancar y puede tardar de 15 minutos a "
            "varias horas segun la cantidad de memoria",
            "el resultado aparece despues, en el Visor de eventos "
            "(origen MemoryDiagnostics-Results)",
        ]
        if not ctx.is_admin:
            warnings.insert(0, (
                "sin privilegios de administrador Windows no deja programar "
                "el arranque: la accion fallara con un mensaje claro"
            ))
        return ActionPreview(
            action_id=self.action_id,
            title=self.title,
            summary=(
                "Se marca el proximo arranque para que ejecute el "
                "Diagnostico de memoria de Windows. No se cambia nada mas "
                "de la configuracion de arranque y el equipo NO se reinicia "
                "ahora."
            ),
            risk=self.risk,
            requires_admin=self.requires_admin,
            requires_reboot=self.requires_reboot,
            commands=[" ".join(self._command(ctx))],
            targets=["Secuencia de arranque (solo el proximo inicio)"],
            warnings=warnings,
            #: bootsequence se consume en el arranque siguiente: si no se
            #: reinicia, no queda rastro.
            reversible=True,
        )

    def _perform(self, ctx: ScanContext) -> ActionResult:
        result = run_command(self._command(ctx), timeout=self.timeout)

        if result.not_found:
            return self._result(
                False, "No se encontro bcdedit en este sistema.")
        if result.timed_out:
            return self._result(
                False, "bcdedit no respondio a tiempo.", output=result.output)
        if result.returncode != 0:
            hint = ""
            if not ctx.is_admin:
                hint = (" Vuelve a abrir la herramienta con 'Ejecutar como "
                        "administrador'.")
            return self._result(
                False,
                "No se pudo programar el diagnostico de memoria.%s" % hint,
                output=result.output,
                returncode=result.returncode,
            )

        return self._result(
            True,
            "Diagnostico de memoria programado. Se ejecutara la proxima vez "
            "que reinicies; el resultado queda en el Visor de eventos.",
            output=result.output,
            returncode=result.returncode,
            undo_data={"command": "bcdedit /deletevalue {bootmgr} bootsequence"},
        )


# ======================================================================
# renew-dhcp
# ======================================================================


@register_action
class RenewDhcpAction(Action):
    """Libera y vuelve a pedir la direccion IP al router."""

    action_id = "renew-dhcp"
    title = "Renovar la direccion IP (DHCP)"
    description = (
        "Devuelve la direccion actual y pide una nueva al router. Arregla "
        "las direcciones 169.254.x.x y los conflictos de IP."
    )
    risk = RiskLevel.MODERATE
    requires_admin = True
    requires_reboot = False
    timeout = 120

    def __init__(self, adapter: Optional[str] = None) -> None:
        # ipconfig acepta un comodin de adaptador. Se valida igual que un
        # nombre de conexion para que no pueda colarse nada raro.
        if adapter is not None and not is_valid_interface_name(adapter):
            raise ValueError("Nombre de adaptador invalido: %r" % adapter)
        self._adapter = adapter.strip() if adapter else None

    def _commands(self, ctx: ScanContext) -> List[List[str]]:
        ipconfig = _system_tool(ctx, "ipconfig.exe")
        tail = [self._adapter] if self._adapter else []
        return [
            [ipconfig, "/release"] + tail,
            [ipconfig, "/renew"] + tail,
            [ipconfig, "/flushdns"],
        ]

    def preview(self, ctx: ScanContext) -> ActionPreview:
        alcance = ("adaptador '%s'" % self._adapter) if self._adapter else \
            "todos los adaptadores de red"
        return ActionPreview(
            action_id=self.action_id,
            title=self.title,
            summary=(
                "Se devuelve la direccion IP actual y se pide una nueva al "
                "router para %s. Tambien se vacia la cache de nombres. La "
                "conexion se corta unos segundos." % alcance
            ),
            risk=self.risk,
            requires_admin=self.requires_admin,
            requires_reboot=self.requires_reboot,
            commands=[" ".join(c) for c in self._commands(ctx)],
            targets=[alcance],
            warnings=[
                "se pierde la conexion durante unos segundos; no lo hagas "
                "en medio de una descarga o una llamada",
                "si el adaptador tiene una IP fija configurada a mano, esto "
                "no cambia nada: hay que quitarla antes",
            ],
            reversible=True,
        )

    def _perform(self, ctx: ScanContext) -> ActionResult:
        outputs: List[str] = []
        last_rc = 0
        renewed_ok = False
        for command in self._commands(ctx):
            result = run_command(command, timeout=self.timeout)
            outputs.append("$ %s\n%s" % (" ".join(command), result.output))
            if result.not_found:
                return self._result(
                    False, "No se encontro ipconfig en este sistema.",
                    output="\n\n".join(outputs))
            if result.timed_out:
                return self._result(
                    False,
                    "ipconfig no respondio a tiempo. Suele indicar que el "
                    "servicio DHCP esta detenido o el adaptador colgado.",
                    output="\n\n".join(outputs))
            last_rc = result.returncode if result.returncode is not None else last_rc
            if command[1] == "/renew" and result.returncode == 0:
                renewed_ok = True

        output = "\n\n".join(outputs)
        addresses = [ip for ip in _IPV4_RE.findall(output)
                     if not ip.startswith("169.254.")]
        if renewed_ok and addresses:
            message = ("Direccion renovada. El equipo obtuvo: %s"
                       % ", ".join(sorted(set(addresses))[:4]))
        elif renewed_ok:
            message = ("Se renovo la configuracion, pero no se vio una "
                       "direccion valida. Revisa el router.")
        else:
            message = ("No se pudo renovar la direccion. Si el router no "
                       "responde, reinicialo y vuelve a intentarlo.")
        return self._result(renewed_ok, message, output=output,
                            returncode=last_rc)


# ======================================================================
# set-public-dns
# ======================================================================


@register_action
class SetPublicDnsAction(Action):
    """Cambia los DNS de las conexiones activas a servidores publicos."""

    action_id = "set-public-dns"
    title = "Usar DNS publicos (1.1.1.1 y 8.8.8.8)"
    description = (
        "Sustituye los servidores DNS del proveedor por Cloudflare y "
        "Google. Los valores anteriores se guardan para poder volver atras."
    )
    risk = RiskLevel.MODERATE
    requires_admin = True
    requires_reboot = False
    timeout = 60

    def __init__(
        self,
        interfaces: Optional[Sequence[str]] = None,
        servers: Optional[Sequence[str]] = None,
    ) -> None:
        # Los dos parametros acaban dentro de una linea de comandos, asi
        # que se validan aca y no se vuelve a confiar en ellos.
        if interfaces is not None:
            for name in interfaces:
                if not is_valid_interface_name(name):
                    raise ValueError("Nombre de conexion invalido: %r" % name)
            interfaces = [n.strip() for n in interfaces]
        if servers is not None:
            for ip in servers:
                if not is_valid_ipv4(ip):
                    raise ValueError("Direccion DNS invalida: %r" % ip)
            if not servers:
                raise ValueError("Hace falta al menos un servidor DNS")
        self._interfaces = list(interfaces) if interfaces else None
        self._servers = list(servers) if servers else list(PUBLIC_DNS)

    # ------------------------------------------------------------------

    def interfaces(self, ctx: ScanContext) -> List[str]:
        """Conexiones a las que se les cambiara el DNS.

        Se piden a WMI y no se parsea la salida de `netsh interface show`
        porque esa salida esta traducida: en un Windows en castellano las
        columnas cambian de nombre y el parseo se rompe. WMI devuelve el
        NetConnectionID tal cual, sin traducir.
        """
        if self._interfaces is not None:
            return list(self._interfaces)

        try:
            from ..winapi import wmi_bridge

            rows = wmi_bridge.query(
                "Win32_NetworkAdapter",
                ["NetConnectionID", "NetEnabled", "PhysicalAdapter"],
                where="NetEnabled=True",
            )
        except Exception as exc:  # noqa: BLE001 - sin WMI no hay lista, no hay crash
            log.debug("no se pudo listar adaptadores: %s", exc)
            return []

        names = []
        for row in rows or []:
            name = row.get("NetConnectionID")
            # PhysicalAdapter descarta los adaptadores virtuales de VPN y
            # maquinas virtuales, que no son por donde sale el trafico.
            if not name or row.get("PhysicalAdapter") is False:
                continue
            if is_valid_interface_name(name) and name not in names:
                names.append(name)
        return names

    def _current_dns(self, ctx: ScanContext, interface: str) -> List[str]:
        """DNS configurados ahora en una conexion. Lista vacia = automatico."""
        result = run_command(
            [_system_tool(ctx, "netsh.exe"), "interface", "ipv4",
             "show", "dnsservers", "name=%s" % interface],
            timeout=30,
        )
        # Se extraen IPs por patron en vez de por posicion: las etiquetas
        # de netsh estan traducidas, los numeros no.
        return [ip for ip in _IPV4_RE.findall(result.output) if is_valid_ipv4(ip)]

    def _set_commands(self, ctx: ScanContext, interface: str) -> List[List[str]]:
        netsh = _system_tool(ctx, "netsh.exe")
        commands = [[
            netsh, "interface", "ipv4", "set", "dnsservers",
            "name=%s" % interface, "static", self._servers[0],
            "primary", "validate=no",
        ]]
        for index, server in enumerate(self._servers[1:], start=2):
            commands.append([
                netsh, "interface", "ipv4", "add", "dnsservers",
                "name=%s" % interface, server, "index=%d" % index,
                "validate=no",
            ])
        return commands

    @staticmethod
    def restore_commands(backup: Dict[str, List[str]]) -> List[str]:
        """Comandos para dejar los DNS como estaban, a partir del respaldo.

        Se devuelven como texto y no se ejecutan: revertir tambien es una
        modificacion del sistema y merece su propia confirmacion.
        """
        lines = []
        for interface, servers in sorted(backup.items()):
            if not servers:
                # No habia DNS fijos: la conexion los tomaba por DHCP.
                lines.append(
                    'netsh interface ipv4 set dnsservers name="%s" dhcp'
                    % interface)
                continue
            lines.append(
                'netsh interface ipv4 set dnsservers name="%s" static %s '
                'primary validate=no' % (interface, servers[0]))
            for index, server in enumerate(servers[1:], start=2):
                lines.append(
                    'netsh interface ipv4 add dnsservers name="%s" %s '
                    'index=%d validate=no' % (interface, server, index))
        return lines

    def _backup_path(self, ctx: ScanContext) -> str:
        base = ctx.output_dir or tempfile.gettempdir()
        return os.path.join(base, DNS_BACKUP_FILE)

    def _save_backup(self, ctx: ScanContext, backup: Dict[str, List[str]]) -> str:
        """Guarda el respaldo en disco. Devuelve la ruta, o '' si no pudo."""
        path = self._backup_path(ctx)
        payload = {
            "servers_previous": backup,
            "servers_applied": list(self._servers),
            "restore": self.restore_commands(backup),
        }
        try:
            directory = os.path.dirname(path)
            if directory and not os.path.isdir(directory):
                os.makedirs(directory)
            with open(path, "w") as handle:
                json.dump(payload, handle, indent=2)
        except (OSError, TypeError, ValueError) as exc:
            log.debug("no se pudo guardar el respaldo de DNS: %s", exc)
            return ""
        return path

    # ------------------------------------------------------------------

    def preview(self, ctx: ScanContext) -> ActionPreview:
        interfaces = self.interfaces(ctx)
        warnings = []
        targets = []
        commands = []
        for interface in interfaces:
            current = self._current_dns(ctx, interface)
            targets.append(
                "%s  (DNS actuales: %s)"
                % (interface, ", ".join(current) if current else "automaticos")
            )
            commands.extend(" ".join(c) for c in self._set_commands(ctx, interface))
        if not interfaces:
            warnings.append(
                "no se pudo determinar ninguna conexion activa; la accion no "
                "tendra nada sobre lo que actuar"
            )
        warnings.append(
            "los DNS anteriores se guardan en %s para poder revertir"
            % self._backup_path(ctx)
        )
        warnings.append(
            "en redes de empresa los DNS internos son necesarios para ver "
            "servidores locales: cambiarlos puede dejar sin acceso a la red "
            "interna"
        )

        return ActionPreview(
            action_id=self.action_id,
            title=self.title,
            summary=(
                "Se cambian los servidores DNS de las conexiones activas a "
                "%s. Antes se leen y guardan los actuales para poder "
                "deshacerlo." % " y ".join(self._servers)
            ),
            risk=self.risk,
            requires_admin=self.requires_admin,
            requires_reboot=self.requires_reboot,
            commands=commands or ["(sin conexiones sobre las que actuar)"],
            targets=targets or ["(ninguna conexion activa detectada)"],
            warnings=warnings,
            reversible=True,
            details={"interfaces": interfaces, "servers": list(self._servers)},
        )

    def _perform(self, ctx: ScanContext) -> ActionResult:
        interfaces = self.interfaces(ctx)
        if not interfaces:
            return self._result(
                False,
                "No se encontro ninguna conexion de red activa a la que "
                "cambiarle los DNS.",
            )

        backup: Dict[str, List[str]] = {}
        outputs: List[str] = []
        changed: List[str] = []
        failed: List[str] = []

        for interface in interfaces:
            # Primero el respaldo. Si no se puede leer que habia, no se
            # cambia esa conexion: sin respaldo no hay vuelta atras y la
            # promesa de reversibilidad seria mentira.
            backup[interface] = self._current_dns(ctx, interface)

            ok = True
            for command in self._set_commands(ctx, interface):
                result = run_command(command, timeout=self.timeout)
                outputs.append("$ %s\n%s" % (" ".join(command), result.output))
                if result.not_found:
                    return self._result(
                        False, "No se encontro netsh en este sistema.",
                        output="\n\n".join(outputs))
                if not result.ok:
                    ok = False
                    break
            (changed if ok else failed).append(interface)

        backup_path = self._save_backup(ctx, backup)
        # Vaciar la cache evita que el equipo siga usando respuestas viejas
        # del DNS que acabamos de dejar de usar.
        flush = run_command([_system_tool(ctx, "ipconfig.exe"), "/flushdns"],
                            timeout=30)
        outputs.append("$ ipconfig /flushdns\n%s" % flush.output)

        if not changed:
            return self._result(
                False,
                "No se pudo cambiar el DNS de ninguna conexion (%s)."
                % ", ".join(failed),
                output="\n\n".join(outputs),
                undo_data={"previous_dns": backup, "backup_file": backup_path},
            )

        message = "DNS cambiados a %s en: %s." % (
            " y ".join(self._servers), ", ".join(changed))
        if failed:
            message += " No se pudo en: %s." % ", ".join(failed)
        if backup_path:
            message += (" Los DNS anteriores quedaron guardados en %s."
                        % backup_path)
        else:
            message += (" No se pudo guardar el respaldo en disco; los "
                        "valores previos van en este mismo resultado.")

        return self._result(
            True, message,
            output="\n\n".join(outputs),
            returncode=0,
            undo_data={
                "previous_dns": backup,
                "backup_file": backup_path,
                "restore": self.restore_commands(backup),
            },
            details={"changed": changed, "failed": failed},
        )


# ======================================================================
# reset-winsock
# ======================================================================


@register_action
class ResetWinsockAction(Action):
    """Devuelve la pila de red de Windows a su estado de fabrica."""

    action_id = "reset-winsock"
    title = "Reparar la pila de red (netsh winsock reset)"
    description = (
        "Deshace los cambios que antivirus, VPN y programas de red dejan "
        "en el catalogo Winsock y lo devuelve al estado original."
    )
    risk = RiskLevel.INVASIVE
    requires_admin = True
    requires_reboot = True
    timeout = 120

    def _command(self, ctx: ScanContext) -> List[str]:
        return [_system_tool(ctx, "netsh.exe"), "winsock", "reset"]

    def preview(self, ctx: ScanContext) -> ActionPreview:
        return ActionPreview(
            action_id=self.action_id,
            title=self.title,
            summary=(
                "Se restaura el catalogo Winsock, la capa por la que todos "
                "los programas acceden a la red. Elimina los enganches que "
                "dejan antivirus y VPN y que a veces impiden navegar aunque "
                "la conexion este bien."
            ),
            risk=self.risk,
            requires_admin=self.requires_admin,
            requires_reboot=self.requires_reboot,
            commands=[" ".join(self._command(ctx))],
            targets=["Catalogo Winsock del sistema"],
            warnings=[
                "hay que reiniciar para que surta efecto",
                "clientes VPN, proxies y algunos antivirus pueden dejar de "
                "funcionar hasta que se reinstalen",
                "no se puede deshacer con un comando: habria que volver a "
                "instalar el software de red afectado",
            ],
            reversible=False,
        )

    def _perform(self, ctx: ScanContext) -> ActionResult:
        result = run_command(self._command(ctx), timeout=self.timeout)

        if result.not_found:
            return self._result(False, "No se encontro netsh en este sistema.")
        if result.timed_out:
            return self._result(
                False, "netsh no respondio a tiempo.", output=result.output)
        if result.returncode != 0:
            return self._result(
                False,
                "No se pudo restablecer Winsock (codigo %s)." % result.returncode,
                output=result.output, returncode=result.returncode)

        return self._result(
            True,
            "Catalogo Winsock restablecido. REINICIA el equipo: hasta "
            "entonces la red puede comportarse de forma erratica.",
            output=result.output,
            returncode=result.returncode,
        )
