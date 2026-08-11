"""Contrato de las acciones de reparacion.

Hasta la fase 7 el sistema solo diagnosticaba: miraba, interpretaba y
explicaba. Este paquete agrega el otro sentido -- ejecutar el arreglo --
y con el aparece un riesgo que el resto del programa no tenia: aca se
TOCA la maquina del cliente.

EL PRINCIPIO INNEGOCIABLE
-------------------------
Una accion nunca se ejecuta sola. La confirmacion la pide quien llama
(el CLI), pero el contrato esta disenado para que ejecutar por accidente
sea imposible, no solo desaconsejado. Tres cerrojos independientes:

  1. `dry_run=True` es el DEFAULT. `action.execute(ctx)` -- la llamada
     mas corta y la que sale por descuido -- simula y no toca nada.
     Ejecutar de verdad exige escribir `dry_run=False`: un acto
     deliberado y visible en el codigo y en el diff.

  2. Con `dry_run=False` hace falta ademas un objeto `Confirmation`
     emitido por `Confirmation.grant(action, preview)`. No se puede
     fabricar sin tener en la mano el `ActionPreview` de ESA accion, y
     el preview es justamente lo que se le muestra al usuario. Es decir:
     el tipo del argumento hace cumplir "primero mostrar, despues
     ejecutar". Si falta, se lanza `ConfirmationRequired`; se LANZA y no
     se devuelve un resultado fallido a proposito, porque un error
     silencioso aca es lo que produce ejecuciones no queridas.

  3. `execute()` es plantilla cerrada: las subclases no la sobrescriben,
     implementan `_perform()`, que solo se invoca cuando los dos
     cerrojos anteriores pasaron. Una accion nueva hereda la seguridad
     sin tener que acordarse de nada.

El cuarto cerrojo no es tecnico sino de informacion: `preview()` es
obligatorio y debe describir el comando exacto, los archivos afectados y
el espacio que se libera. Nadie puede aceptar lo que no puede ver.

Compatibilidad: Python 3.8 (Windows 7). Sin `match`, sin `X | Y` en
anotaciones, sin `dict[str, x]`.
"""

from __future__ import annotations

import abc
import hashlib
import importlib
import locale
import logging
import os
import pkgutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional, Sequence, Type, TypeVar

from ..core.context import ScanContext, ScanMode
from ..core.models import RiskLevel

log = logging.getLogger(__name__)

#: Evita la consola negra parpadeando cuando el .exe corre en modo ventana.
#: Mismo valor y misma razon que en winapi/wmi_bridge.py.
_NO_WINDOW = 0x08000000

#: Ninguna reparacion deberia colgar el programa para siempre. Cada accion
#: ajusta el suyo (sfc tarda mucho mas que ipconfig).
DEFAULT_TIMEOUT = 120

_RISK_LABELS = {
    RiskLevel.SAFE: "seguro",
    RiskLevel.MODERATE: "moderado",
    RiskLevel.INVASIVE: "invasivo",
}


def risk_label(risk: RiskLevel) -> str:
    """Nombre en castellano del nivel de riesgo, para mostrar al usuario."""
    return _RISK_LABELS.get(risk, "desconocido")


# ----------------------------------------------------------------------
# Errores
# ----------------------------------------------------------------------


class RemediationError(RuntimeError):
    """Base de los errores del subsistema de reparacion."""


class UnknownAction(RemediationError):
    """Se pidio un action_id que no esta registrado."""


class ConfirmationRequired(RemediationError):
    """Se intento ejecutar de verdad sin confirmacion valida.

    Es una excepcion y no un resultado fallido a proposito: quien la
    provoca cometio un error de programacion (se salto la confirmacion) y
    debe enterarse fuerte, no leer un booleano que quiza nadie mira.
    """


# ----------------------------------------------------------------------
# Ejecucion de comandos externos
# ----------------------------------------------------------------------


class CommandOutput:
    """Resultado de correr un programa externo. Nunca lanza."""

    __slots__ = ("command", "returncode", "output", "timed_out", "not_found", "elapsed")

    def __init__(
        self,
        command: Sequence[str],
        returncode: Optional[int] = None,
        output: str = "",
        timed_out: bool = False,
        not_found: bool = False,
        elapsed: float = 0.0,
    ) -> None:
        self.command = list(command)
        self.returncode = returncode
        self.output = output
        self.timed_out = timed_out
        self.not_found = not_found
        self.elapsed = elapsed

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.not_found

    @property
    def command_line(self) -> str:
        return " ".join(_quote(part) for part in self.command)

    def __repr__(self) -> str:
        return "<CommandOutput %s rc=%s>" % (self.command[:1], self.returncode)


def _quote(part: str) -> str:
    return '"%s"' % part if " " in part else part


def _decode(raw: bytes) -> str:
    """Convierte la salida de un programa de consola a texto.

    Windows no tiene una sola codificacion de consola: chkdsk e ipconfig
    salen en la pagina de codigos OEM (850/437 en equipos en castellano),
    mientras que `sfc /scannow` escribe UTF-16LE. Adivinar mal deja el
    reporte lleno de basura justo en las lineas que el tecnico necesita
    leer.
    """
    if not raw:
        return ""
    # UTF-16LE se delata por los bytes nulos intercalados; ninguna pagina
    # de codigos de un byte los produce en texto normal.
    if raw.count(b"\x00") > len(raw) // 4:
        return raw.decode("utf-16-le", "replace").replace("\x00", "").strip()
    for encoding in (locale.getpreferredencoding(False), "cp850", "utf-8"):
        if not encoding:
            continue
        try:
            return raw.decode(encoding).strip()
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace").strip()


def run_command(
    cmd: Sequence[str],
    timeout: int = DEFAULT_TIMEOUT,
    input_text: Optional[str] = None,
) -> CommandOutput:
    """Ejecuta un programa externo y captura su salida. No lanza nunca.

    Args:
        cmd: Comando ya troceado en argumentos. SIEMPRE lista, nunca una
            cadena con `shell=True`: sin shell no hay interpretacion de
            metacaracteres y un parametro malicioso no puede convertirse
            en un comando extra.
        timeout: Segundos antes de matar el proceso.
        input_text: Texto a mandar por stdin (chkdsk pregunta si se
            programa el analisis para el proximo arranque).

    Returns:
        CommandOutput. Un fallo del programa es un resultado, no una
        excepcion: una reparacion que falla debe poder contarse en el
        reporte, no tumbar la sesion.
    """
    started = time.time()
    kwargs: Dict[str, Any] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "timeout": timeout,
        "shell": False,
    }
    if os.name == "nt":
        kwargs["creationflags"] = _NO_WINDOW
    if input_text is None:
        # Sin stdin conectado: si un comando decide preguntar algo, recibe
        # EOF y termina, en vez de quedarse colgado hasta el timeout.
        kwargs["stdin"] = subprocess.DEVNULL
    else:
        kwargs["input"] = input_text.encode("ascii", "ignore")

    try:
        completed = subprocess.run(list(cmd), **kwargs)  # noqa: S603
    except subprocess.TimeoutExpired as exc:
        return CommandOutput(
            cmd,
            returncode=None,
            output=_decode(exc.output or b"") if getattr(exc, "output", None) else "",
            timed_out=True,
            elapsed=time.time() - started,
        )
    except FileNotFoundError:
        return CommandOutput(cmd, returncode=None, not_found=True,
                             elapsed=time.time() - started)
    except (OSError, ValueError) as exc:  # permisos, argumentos invalidos
        return CommandOutput(
            cmd,
            returncode=None,
            output="%s: %s" % (type(exc).__name__, exc),
            elapsed=time.time() - started,
        )

    raw = completed.stdout if isinstance(completed.stdout, bytes) else b""
    return CommandOutput(
        cmd,
        returncode=completed.returncode,
        output=_decode(raw),
        elapsed=time.time() - started,
    )


# ----------------------------------------------------------------------
# Validacion de parametros
# ----------------------------------------------------------------------


def path_is_within(path: str, root: str) -> bool:
    """True si `path` esta realmente contenido en `root`.

    Se comparan rutas REALES (`realpath`), no las escritas. En Windows
    esto no es paranoia: %TEMP% contiene enlaces y junctions con
    frecuencia, y un junction dentro de una carpeta temporal apuntando a
    C:\\Windows convertiria un "limpiar temporales" en un desastre. Al
    resolver el destino real, ese archivo deja de estar dentro de la
    carpeta objetivo y no se toca.

    Tambien atrapa lo obvio: rutas con `..` que se salen del arbol.
    """
    if not path or not root:
        return False
    try:
        real_path = os.path.realpath(path)
        real_root = os.path.realpath(root)
    except (OSError, ValueError):
        return False

    if os.name == "nt":
        # NTFS no distingue mayusculas: comparar tal cual dejaria pasar
        # C:\TEMP\.. contra c:\temp.
        real_path = real_path.lower()
        real_root = real_root.lower()

    real_root = real_root.rstrip("\\/")
    if not real_root:
        return False
    if real_path == real_root:
        return True
    return real_path.startswith(real_root + os.sep)


def is_valid_ipv4(text: str) -> bool:
    """Valida una IPv4 en notacion decimal punteada.

    Se usa `ipaddress` en vez de una expresion regular porque acepta
    exactamente lo que acepta el sistema. Ademas se rechaza cualquier
    cosa que no sea IPv4 literal: nombres de host no valen, porque
    terminarian pasando a `netsh` como texto arbitrario.
    """
    import ipaddress

    if not isinstance(text, str) or not text.strip():
        return False
    candidate = text.strip()
    try:
        address = ipaddress.IPv4Address(u"%s" % candidate)
    except ValueError:
        return False
    # "1.2.3.4 " ya quedo limpio; pero "010.1.1.1" u otras formas raras se
    # descartan exigiendo que el texto vuelva a salir igual.
    return str(address) == candidate


_INTERFACE_FORBIDDEN = set('"\'&|<>^%!\r\n\t`$;')


def is_valid_interface_name(name: str) -> bool:
    """Valida el nombre de una conexion de red antes de pasarlo a netsh.

    Aunque se invoca sin shell, `netsh` reparte sus propios argumentos y
    un nombre con comillas o `&` puede alterar la orden. Se admite lo que
    Windows realmente permite en un nombre de conexion y nada mas.
    """
    if not isinstance(name, str):
        return False
    stripped = name.strip()
    if not stripped or len(stripped) > 128:
        return False
    return not any(ch in _INTERFACE_FORBIDDEN for ch in stripped)


def is_valid_volume(volume: str) -> bool:
    """Valida una unidad con el formato 'C:' (una letra y dos puntos)."""
    if not isinstance(volume, str):
        return False
    v = volume.strip()
    return len(v) == 2 and v[0].isalpha() and v[0].isascii() and v[1] == ":"


def human_size(num_bytes: float) -> str:
    """Tamano legible. El usuario piensa en MB, no en bytes."""
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(value) < 1024.0 or unit == "GB":
            if unit == "B":
                return "%d B" % int(value)
            return "%.1f %s" % (value, unit)
        value /= 1024.0
    return "%.1f GB" % value


# ----------------------------------------------------------------------
# Preview, confirmacion y resultado
# ----------------------------------------------------------------------


@dataclass
class ActionPreview:
    """Lo que la accion HARIA, sin haber hecho nada todavia.

    Es obligatorio y es el corazon del diseno: el usuario no puede
    aceptar lo que no puede ver. Debe decir el comando exacto, sobre que
    archivos y con que consecuencia (espacio liberado, reinicio).
    """

    action_id: str
    title: str
    summary: str
    risk: RiskLevel = RiskLevel.SAFE
    requires_admin: bool = False
    requires_reboot: bool = False
    commands: List[str] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    reversible: bool = True
    estimated_freed_bytes: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def digest(self) -> str:
        """Huella del contenido mostrado al usuario.

        Ata la confirmacion a ESTE preview concreto: si entre que se
        muestra y que se acepta cambiara lo que la accion va a hacer, la
        huella deja de coincidir.
        """
        payload = "|".join(
            [self.action_id, self.summary]
            + list(self.commands)
            + list(self.targets)
        )
        return hashlib.sha1(payload.encode("utf-8", "replace")).hexdigest()

    def as_text(self) -> str:
        """Render en texto plano, listo para imprimir en la consola."""
        lines = ["%s  [riesgo %s]" % (self.title, risk_label(self.risk))]
        lines.append("")
        lines.append(self.summary)
        if self.commands:
            lines.append("")
            lines.append("Comandos que se ejecutaran:")
            lines.extend("    %s" % c for c in self.commands)
        if self.targets:
            lines.append("")
            lines.append("Alcance (nada fuera de esto se toca):")
            lines.extend("    %s" % t for t in self.targets)
        if self.estimated_freed_bytes is not None:
            lines.append("")
            lines.append("Espacio que se liberaria: %s"
                         % human_size(self.estimated_freed_bytes))
        flags = []
        if self.requires_admin:
            flags.append("requiere administrador")
        if self.requires_reboot:
            flags.append("requiere reiniciar")
        if not self.reversible:
            flags.append("no se puede deshacer")
        if flags:
            lines.append("")
            lines.append("Ojo: " + "; ".join(flags) + ".")
        for warning in self.warnings:
            lines.append("  aviso: %s" % warning)
        return "\n".join(lines)


@dataclass(frozen=True)
class Confirmation:
    """Prueba de que un humano vio el preview y dijo que si.

    Solo `grant()` produce una valida, y `grant()` exige el
    `ActionPreview` de la accion. Por eso no existe forma razonable de
    llegar a `execute(..., dry_run=False)` sin haber generado antes lo
    que se le muestra al usuario.

    Es inmutable (`frozen`) para que nadie la recicle apuntandola a otra
    accion despues de haberla obtenido.
    """

    action_id: str
    token: str
    accepted_by: str = "usuario"
    accepted_at: datetime = field(default_factory=datetime.now)

    @classmethod
    def grant(
        cls,
        action: "Action",
        preview: ActionPreview,
        accepted_by: str = "usuario",
    ) -> "Confirmation":
        """Emite la confirmacion para una accion y el preview mostrado."""
        if preview.action_id != action.action_id:
            raise ValueError(
                "El preview es de '%s' y la accion es '%s'"
                % (preview.action_id, action.action_id)
            )
        return cls(
            action_id=action.action_id,
            token=_token_for(action.action_id, preview.digest),
            accepted_by=accepted_by,
        )

    def grants(self, action: "Action") -> bool:
        """True si esta confirmacion autoriza a ejecutar `action`."""
        if self.action_id != action.action_id:
            return False
        # El token se deriva del action_id: una confirmacion armada a mano
        # con el campo `token` vacio o inventado no pasa. No es criptografia
        # (no hay adversario dentro del proceso), es un pestillo contra el
        # descuido de construir Confirmation("x", "") y creerlo suficiente.
        return bool(self.token) and self.token.startswith(_token_prefix(self.action_id))


def _token_prefix(action_id: str) -> str:
    return hashlib.sha1(("inyaguidiag:" + action_id).encode("utf-8")).hexdigest()[:12]


def _token_for(action_id: str, digest: str) -> str:
    return _token_prefix(action_id) + ":" + digest


@dataclass
class ActionResult:
    """Que paso al ejecutar (o simular) una accion."""

    action_id: str
    success: bool
    message: str
    output: str = ""
    simulated: bool = True
    requires_reboot: bool = False
    returncode: Optional[int] = None
    elapsed: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    #: Datos para revertir (p.ej. los DNS que habia antes). Vacio si la
    #: accion no es reversible o no hizo falta.
    undo_data: Dict[str, Any] = field(default_factory=dict)

    @property
    def applied(self) -> bool:
        """True solo si se toco la maquina de verdad y salio bien."""
        return self.success and not self.simulated


# ----------------------------------------------------------------------
# La accion
# ----------------------------------------------------------------------


class Action(abc.ABC):
    """Una reparacion ejecutable.

    Subclases definen `action_id`, `title` y `_perform()`. El resto --
    cerrojos de confirmacion, simulacion, control de admin y captura de
    fallos -- lo pone la clase base y no se puede desactivar por olvido.

    Attributes:
        action_id: Identificador estable. Es el mismo que las reglas
            ponen en `Remedy.action_id`; si no coincide, el remedio queda
            huerfano (hay un test que lo comprueba).
        title: Nombre corto para mostrar.
        description: Que hace, en castellano llano.
        risk: `RiskLevel` de core.models. Debe coincidir con el que
            declara el remedio de la regla.
        requires_admin: Si necesita elevacion para funcionar.
        requires_reboot: Si el efecto solo se ve tras reiniciar.
        supported_modes: Por defecto solo ONLINE. Reparar un Windows que
            no arranca desde WinPE es otro problema: los comandos actuan
            sobre el sistema en ejecucion, no sobre el disco montado.
        timeout: Segundos maximos del comando.
    """

    action_id: str = ""
    title: str = ""
    description: str = ""
    risk: RiskLevel = RiskLevel.SAFE
    requires_admin: bool = False
    requires_reboot: bool = False
    supported_modes = (ScanMode.ONLINE,)
    timeout: int = DEFAULT_TIMEOUT

    #: Marca de base abstracta intermedia, igual que en rules/base.py y
    #: collectors/base.py. Se usa un marcador explicito porque
    #: `__abstractmethods__` todavia no existe cuando corre
    #: `__init_subclass__`: ABCMeta lo calcula despues de crear la clase.
    abstract = True

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if cls.__dict__.get("abstract"):
            return
        cls.abstract = False
        # Falla temprano: una accion sin identidad es un bug de
        # programacion, no una condicion de runtime.
        if not cls.action_id:
            raise TypeError(
                "%s debe definir 'action_id' (o 'abstract = True' si es una "
                "base intermedia)" % cls.__name__
            )
        if not cls.title:
            raise TypeError("%s debe definir 'title'" % cls.__name__)
        if "execute" in cls.__dict__:
            # `execute` es la plantilla que impone los cerrojos. Si una
            # subclase la reemplaza, se los salta sin querer.
            raise TypeError(
                "%s no debe sobrescribir 'execute': implementa '_perform'"
                % cls.__name__
            )

    # ------------------------------------------------------------------
    # A implementar por cada accion
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def preview(self, ctx: ScanContext) -> ActionPreview:
        """Describe QUE se haria, sin hacer nada.

        Contrato: es de solo lectura. Puede mirar el disco para calcular
        cuanto liberaria, pero no modifica nada. Si no puede calcular
        algo, lo dice en `warnings`; no revienta.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def _perform(self, ctx: ScanContext) -> ActionResult:
        """Ejecuta de verdad. Solo lo llama `execute()`.

        Cuando este metodo corre, ya se comprobo que la accion aplica,
        que hay confirmacion valida y que hay permisos. No debe volver a
        preguntar nada ni interactuar con el usuario.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------

    def can_run(self, ctx: ScanContext) -> bool:
        """Si la accion tiene sentido en este contexto.

        La comprobacion de modo esta aca y no en cada accion para que una
        accion nueva no pueda olvidarse de ella. En OFFLINE (WinPE con el
        disco del equipo montado) casi nada aplica: `netsh` configuraria
        la red de WinPE, no la del equipo averiado.
        """
        return ctx.mode in self.supported_modes

    def not_applicable_reason(self, ctx: ScanContext) -> str:
        """Por que no aplica, en castellano, para mostrarlo al usuario."""
        if ctx.mode not in self.supported_modes:
            return (
                "Esta accion solo funciona sobre un Windows arrancado; en "
                "modo offline actuaria sobre el entorno de arranque, no "
                "sobre el equipo averiado."
            )
        return "No aplica en este contexto."

    # ------------------------------------------------------------------
    # Plantilla de ejecucion: aca viven los cerrojos
    # ------------------------------------------------------------------

    def execute(
        self,
        ctx: ScanContext,
        confirmation: Optional[Confirmation] = None,
        dry_run: bool = True,
    ) -> ActionResult:
        """Simula (por defecto) o ejecuta la accion.

        Args:
            ctx: Contexto del escaneo.
            confirmation: Obligatoria si `dry_run` es False. Se obtiene
                con `Confirmation.grant(action, preview)` DESPUES de
                haberle mostrado el preview al usuario y de que este
                acepte.
            dry_run: True por defecto -- y ese default es la funcionalidad
                principal de este metodo, no una comodidad. La llamada
                descuidada `execute(ctx)` simula. Tocar la maquina exige
                escribir `dry_run=False` explicitamente.

        Returns:
            ActionResult. En simulacion, `simulated=True` y el mensaje
            describe lo que habria hecho.

        Raises:
            ConfirmationRequired: si `dry_run=False` sin confirmacion
                valida para esta accion.
        """
        if not self.can_run(ctx):
            return ActionResult(
                action_id=self.action_id,
                success=False,
                message=self.not_applicable_reason(ctx),
                simulated=True,
            )

        if dry_run:
            # Camino de simulacion: no se llama a `_perform` bajo ninguna
            # circunstancia, ni siquiera si hay confirmacion valida.
            return self._simulated_result(ctx)

        # Cerrojo: sin confirmacion valida no se sigue. Se lanza, no se
        # devuelve, para que un `if result.success` distraido no lo tape.
        if confirmation is None:
            raise ConfirmationRequired(
                "La accion '%s' exige confirmacion explicita del usuario "
                "antes de ejecutarse" % self.action_id
            )
        if not confirmation.grants(self):
            raise ConfirmationRequired(
                "La confirmacion recibida no corresponde a la accion '%s'"
                % self.action_id
            )

        if self.requires_admin and not ctx.is_admin:
            return ActionResult(
                action_id=self.action_id,
                success=False,
                message=(
                    "Se necesitan privilegios de administrador. Cierra y "
                    "vuelve a abrir la herramienta con 'Ejecutar como "
                    "administrador'."
                ),
                simulated=False,
            )

        started = time.time()
        try:
            result = self._perform(ctx)
        except Exception as exc:  # noqa: BLE001 - una reparacion no tumba la sesion
            log.exception("la accion %s fallo", self.action_id)
            return ActionResult(
                action_id=self.action_id,
                success=False,
                message="La reparacion fallo: %s: %s" % (type(exc).__name__, exc),
                simulated=False,
                elapsed=time.time() - started,
            )

        result.simulated = False
        if not result.elapsed:
            result.elapsed = time.time() - started
        return result

    # ------------------------------------------------------------------

    def _simulated_result(self, ctx: ScanContext) -> ActionResult:
        """Construye el resultado de la simulacion a partir del preview."""
        try:
            preview = self.preview(ctx)
        except Exception as exc:  # noqa: BLE001
            log.exception("el preview de %s fallo", self.action_id)
            return ActionResult(
                action_id=self.action_id,
                success=False,
                message="No se pudo calcular la vista previa: %s" % exc,
                simulated=True,
            )
        return ActionResult(
            action_id=self.action_id,
            success=True,
            message="SIMULACION: no se modifico nada.\n" + preview.as_text(),
            output="\n".join(preview.commands),
            simulated=True,
            requires_reboot=self.requires_reboot,
            details={
                "commands": list(preview.commands),
                "targets": list(preview.targets),
                "estimated_freed_bytes": preview.estimated_freed_bytes,
            },
        )

    # Ayuda para construir resultados sin repetir campos.
    def _result(
        self,
        success: bool,
        message: str,
        output: str = "",
        returncode: Optional[int] = None,
        undo_data: Optional[Dict[str, Any]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> ActionResult:
        return ActionResult(
            action_id=self.action_id,
            success=success,
            message=message,
            output=output,
            simulated=False,
            requires_reboot=self.requires_reboot and success,
            returncode=returncode,
            undo_data=undo_data or {},
            details=details or {},
        )

    def __repr__(self) -> str:
        return "<Action %s risk=%s>" % (self.action_id, risk_label(self.risk))


# ----------------------------------------------------------------------
# Registro
# ----------------------------------------------------------------------
#
# Mismo patron que core/registry.py: agregar una accion es UN gesto --
# crear la clase y decorarla. El descubrimiento se hace aca y no en
# core/registry para no arrastrar colectores y reglas cuando el CLI solo
# quiere listar reparaciones.

_ACTIONS: Dict[str, Type[Action]] = {}

A = TypeVar("A", bound=Type[Action])


def register_action(cls: A) -> A:
    """Decorador: inscribe una accion en el registro global."""
    if cls.action_id in _ACTIONS and _ACTIONS[cls.action_id] is not cls:
        raise ValueError(
            "action_id duplicado '%s': %s vs %s"
            % (cls.action_id, _ACTIONS[cls.action_id].__name__, cls.__name__)
        )
    _ACTIONS[cls.action_id] = cls
    return cls


_discovered = False


def discover(force: bool = False) -> None:
    """Importa los modulos de `remediation` para disparar los decoradores.

    Nota de empaquetado: PyInstaller no ve estos imports dinamicos. El
    .spec ya declara `inyaguidiag.remediation` en `hiddenimports`.
    """
    global _discovered
    if _discovered and not force:
        return
    _discovered = True
    package = importlib.import_module(__package__)
    prefix = package.__name__ + "."
    for _, module_name, _is_pkg in pkgutil.iter_modules(package.__path__, prefix):
        if module_name == __name__:
            continue
        try:
            importlib.import_module(module_name)
        except ImportError as exc:  # una accion opcional no rompe el resto
            log.debug("no se pudo importar %s: %s", module_name, exc)


def all_actions() -> List[Action]:
    """Instancias de todas las acciones registradas, orden estable."""
    discover()
    return [cls() for _, cls in sorted(_ACTIONS.items())]


def action_ids() -> Iterator[str]:
    discover()
    return iter(sorted(_ACTIONS))


def has_action(action_id: str) -> bool:
    discover()
    return action_id in _ACTIONS


def get_action(action_id: str) -> Action:
    """Devuelve la accion pedida.

    Raises:
        UnknownAction: si el id no existe. Que un remedio apunte a una
            accion inexistente es un bug, no un caso a ignorar.
    """
    discover()
    cls = _ACTIONS.get(action_id)
    if cls is None:
        raise UnknownAction(
            "No existe la accion '%s'. Disponibles: %s"
            % (action_id, ", ".join(sorted(_ACTIONS)) or "ninguna")
        )
    return cls()
