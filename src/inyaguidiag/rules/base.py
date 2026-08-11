"""Contrato de las reglas de diagnostico.

Una regla toma los datos crudos de los colectores y decide si hay un
problema. Es el unico lugar donde se define "que esta mal" y "como se
arregla".

Convencion de rule_id:  XXX-NNN
    STO  almacenamiento     BOT  arranque
    MEM  memoria            CRA  pantallazos (BSOD)
    NET  red                SYS  sistema
    DRV  controladores      SEC  seguridad
    PRF  rendimiento        PWR  energia
    HWR  hardware

Los ids son estables y publicos: aparecen en el reporte y el usuario los
puede buscar. Nunca reutilizar un id retirado.
"""

from __future__ import annotations

import abc
from typing import Any, Dict, Iterable, List, Sequence

from ..core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Remedy,
    Severity,
)


class Rule(abc.ABC):
    """Evalua los hechos recolectados y emite hallazgos.

    Attributes:
        rule_id: Identificador estable (ver convencion arriba).
        category: Area a la que pertenece.
        requires: Claves de `facts` que la regla necesita. Si falta
            alguna, el motor salta la regla en vez de reventar.
        title: Titulo por defecto de los hallazgos que emite.
    """

    rule_id: str = ""
    category: Category = Category.SYSTEM
    requires: Sequence[str] = ()
    title: str = ""

    #: Marca de base abstracta intermedia. Una clase que agrupa logica
    #: comun para varias reglas (p.ej. `_LayerRule` en network_rules) NO es
    #: una regla y no debe declarar rule_id: pone `abstract = True` en su
    #: propio cuerpo para saltarse la validacion.
    #:
    #: Se usa un marcador explicito y no `cls.__abstractmethods__` porque
    #: ese atributo aun no existe cuando corre `__init_subclass__`: ABCMeta
    #: lo calcula despues de crear la clase.
    abstract = True

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if cls.__dict__.get("abstract"):
            return
        cls.abstract = False
        if not cls.rule_id:
            raise TypeError(
                "%s debe definir 'rule_id' (o 'abstract = True' si es una "
                "base intermedia)" % cls.__name__
            )

    # ------------------------------------------------------------------

    def can_evaluate(self, facts: Dict[str, Any]) -> bool:
        """Si estan presentes los datos que la regla necesita.

        Una regla que no puede evaluarse no es un error: significa que el
        colector correspondiente no corrio o no aplicaba.
        """
        return all(key in facts for key in self.requires)

    @abc.abstractmethod
    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        """Analiza los hechos y devuelve 0..N hallazgos.

        Devolver lista vacia significa "revisado, sin problemas". No es lo
        mismo que no poder evaluar.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Ayudas para construir hallazgos sin repetir boilerplate
    # ------------------------------------------------------------------

    def finding(
        self,
        title: str,
        severity: Severity,
        summary: str,
        evidence: Iterable[Evidence] = (),
        remedy: Remedy = None,  # type: ignore[assignment]
        confidence: Confidence = Confidence.CERTAIN,
        suffix: str = "",
    ) -> Finding:
        """Construye un Finding heredando id y categoria de la regla.

        Args:
            suffix: Discriminador cuando una misma regla emite varios
                hallazgos (p.ej. un disco distinto cada uno).
        """
        return Finding(
            rule_id=self.rule_id + (("/" + suffix) if suffix else ""),
            title=title,
            severity=severity,
            category=self.category,
            summary=summary,
            evidence=list(evidence),
            remedy=remedy,
            confidence=confidence,
        )


class RuleSet:
    """Coleccion de reglas evaluadas en conjunto."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        self._rules: List[Rule] = list(rules)
        self._check_unique_ids()

    def _check_unique_ids(self) -> None:
        seen = {}
        for rule in self._rules:
            if rule.rule_id in seen:
                raise ValueError(
                    "rule_id duplicado '%s' entre %s y %s"
                    % (rule.rule_id, seen[rule.rule_id], type(rule).__name__)
                )
            seen[rule.rule_id] = type(rule).__name__

    def __iter__(self):
        return iter(self._rules)

    def __len__(self) -> int:
        return len(self._rules)

    def for_categories(self, categories: Iterable[str]) -> "RuleSet":
        wanted = {c.lower() for c in categories}
        return RuleSet(r for r in self._rules if r.category.value in wanted)
