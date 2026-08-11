"""Registro y descubrimiento de colectores y reglas.

Objetivo de diseno: agregar un colector o una regla debe requerir UN solo
gesto -- crear la clase y decorarla. Nada de listas centrales que hay que
acordarse de actualizar (fuente clasica de reglas que "no corren" y nadie
sabe por que).

Uso:

    @register_collector
    class SmartCollector(Collector):
        name = "smart"
        provides = "storage.smart"
        ...

    @register_rule
    class FailingDiskRule(Rule):
        rule_id = "STO-001"
        ...
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Dict, Iterator, List, Type, TypeVar

from ..collectors.base import Collector
from ..rules.base import Rule, RuleSet

_COLLECTORS: Dict[str, Type[Collector]] = {}
_RULES: Dict[str, Type[Rule]] = {}

C = TypeVar("C", bound=Type[Collector])
R = TypeVar("R", bound=Type[Rule])


def register_collector(cls: C) -> C:
    """Decorador: inscribe un colector en el registro global."""
    if cls.name in _COLLECTORS and _COLLECTORS[cls.name] is not cls:
        raise ValueError(
            "Colector duplicado '%s': %s vs %s"
            % (cls.name, _COLLECTORS[cls.name].__name__, cls.__name__)
        )
    _COLLECTORS[cls.name] = cls
    return cls


def register_rule(cls: R) -> R:
    """Decorador: inscribe una regla en el registro global."""
    if cls.rule_id in _RULES and _RULES[cls.rule_id] is not cls:
        raise ValueError(
            "rule_id duplicado '%s': %s vs %s"
            % (cls.rule_id, _RULES[cls.rule_id].__name__, cls.__name__)
        )
    _RULES[cls.rule_id] = cls
    return cls


# ----------------------------------------------------------------------
# Descubrimiento
# ----------------------------------------------------------------------


def _import_submodules(package_name: str) -> None:
    """Importa recursivamente un paquete para disparar los decoradores.

    Nota para el empaquetado: PyInstaller no ve estos imports dinamicos.
    El .spec debe declararlos en `hiddenimports` (ver build/inyaguidiag.spec).
    """
    try:
        package = importlib.import_module(package_name)
    except ImportError:
        return

    prefix = package.__name__ + "."
    for _, module_name, is_pkg in pkgutil.iter_modules(package.__path__, prefix):
        try:
            importlib.import_module(module_name)
        except ImportError:
            # Un colector puede depender de una libreria opcional ausente.
            # No es fatal: simplemente ese colector no existira.
            continue
        if is_pkg:
            _import_submodules(module_name)


_discovered = False


def discover(force: bool = False) -> None:
    """Carga todos los colectores y reglas disponibles. Idempotente."""
    global _discovered
    if _discovered and not force:
        return
    _import_submodules("inyaguidiag.collectors")
    _import_submodules("inyaguidiag.rules")
    _discovered = True


# ----------------------------------------------------------------------
# Acceso
# ----------------------------------------------------------------------


def all_collectors() -> List[Collector]:
    """Instancias de todos los colectores registrados, orden estable."""
    discover()
    return [cls() for _, cls in sorted(_COLLECTORS.items())]


def all_rules() -> RuleSet:
    """Todas las reglas registradas, orden estable por rule_id."""
    discover()
    return RuleSet(cls() for _, cls in sorted(_RULES.items()))


def collector_names() -> Iterator[str]:
    discover()
    return iter(sorted(_COLLECTORS))


def rule_ids() -> Iterator[str]:
    discover()
    return iter(sorted(_RULES))
