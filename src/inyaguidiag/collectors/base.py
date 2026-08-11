"""Contrato de los colectores.

Un colector SOLO recolecta. No juzga, no clasifica, no propone arreglos.
Devuelve datos crudos normalizados. Toda la interpretacion vive en las
reglas.

Esta separacion es lo que hace posible el modo OFFLINE: cambiamos el
colector (WMI en vivo -> archivos de un disco muerto) y las reglas siguen
funcionando sin tocarse.
"""

from __future__ import annotations

import abc
import time
from typing import Any, Dict, Optional

from ..core.context import ScanContext, ScanMode


class Collector(abc.ABC):
    """Fuente de datos del diagnostico.

    Subclases deben definir `name`, `provides` y `collect()`.

    Attributes:
        name: Identificador unico, en minusculas con guiones.
        provides: Clave bajo la cual el motor guarda los datos en
            `ScanReport.facts`. Las reglas leen por esta clave.
        supported_modes: Modos en los que este colector puede operar.
        requires_admin: Si necesita elevacion para dar datos completos.
        cost: Peso relativo (1 = instantaneo, 5 = varios segundos). En
            modo `--quick` se saltan los de cost >= 4.
    """

    name: str = ""
    provides: str = ""
    supported_modes = (ScanMode.ONLINE, ScanMode.OFFLINE)
    requires_admin: bool = False
    cost: int = 1

    #: Igual que en `Rule`: marca de base abstracta intermedia. Ver la nota
    #: en rules/base.py sobre por que no se usa `__abstractmethods__`.
    abstract = True

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Falla temprano: un colector sin identidad es un bug de programacion,
        # no una condicion de runtime.
        if cls.__dict__.get("abstract"):
            return
        cls.abstract = False
        if not cls.name:
            raise TypeError(
                "%s debe definir 'name' (o 'abstract = True' si es una base "
                "intermedia)" % cls.__name__
            )
        if not cls.provides:
            raise TypeError("%s debe definir 'provides'" % cls.__name__)

    # ------------------------------------------------------------------

    def applies_to(self, ctx: ScanContext) -> bool:
        """Si este colector tiene sentido en el contexto dado.

        El motor lo consulta antes de ejecutar. Sobrescribir para agregar
        condiciones propias (p.ej. "solo si hay bateria").
        """
        if ctx.mode not in self.supported_modes:
            return False
        if ctx.quick and self.cost >= 4:
            return False
        return True

    @abc.abstractmethod
    def collect(self, ctx: ScanContext) -> Dict[str, Any]:
        """Recolecta y devuelve datos normalizados.

        Contrato:
          - Devolver siempre un dict, aunque este vacio.
          - No lanzar por datos ausentes; eso es un resultado valido.
          - Lanzar solo si la recoleccion es imposible (permiso, ruta).
          - Nunca modificar el sistema. Los colectores son de solo lectura.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------

    def run(self, ctx: ScanContext) -> "CollectorResult":
        """Ejecuta `collect` midiendo tiempo y capturando fallos."""
        started = time.time()
        try:
            data = self.collect(ctx)
            if data is None:
                data = {}
            return CollectorResult(
                collector=self.name,
                data=data,
                elapsed=time.time() - started,
            )
        except Exception as exc:  # noqa: BLE001 - un colector no tumba el escaneo
            return CollectorResult(
                collector=self.name,
                data={},
                elapsed=time.time() - started,
                error="%s: %s" % (type(exc).__name__, exc),
            )


class CollectorResult:
    """Resultado de ejecutar un colector, con o sin exito."""

    __slots__ = ("collector", "data", "elapsed", "error")

    def __init__(
        self,
        collector: str,
        data: Dict[str, Any],
        elapsed: float = 0.0,
        error: Optional[str] = None,
    ) -> None:
        self.collector = collector
        self.data = data
        self.elapsed = elapsed
        self.error = error

    @property
    def ok(self) -> bool:
        return self.error is None

    def __repr__(self) -> str:
        state = "ok" if self.ok else "error"
        return "<CollectorResult %s %s %.2fs>" % (self.collector, state, self.elapsed)
