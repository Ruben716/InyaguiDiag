"""Motor de diagnostico: orquesta colectores, reglas y correlacion.

Flujo:

    1. Selecciona los colectores que aplican al contexto.
    2. Los ejecuta; cada uno aporta su bloque a `facts`.
    3. Evalua las reglas contra `facts`.
    4. Corre los correlacionadores (que ven TODOS los hallazgos juntos).
    5. Devuelve un ScanReport.

Principio rector: ningun fallo individual aborta el escaneo. Un colector
que revienta se registra como cobertura perdida y el resto continua. Una
herramienta de diagnostico que se cae ante una maquina rota es inutil,
porque las maquinas rotas son precisamente su caso de uso.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from ..collectors.base import Collector
from ..rules.base import Rule, RuleSet
from .context import ScanContext
from .models import CollectorError, Finding, MachineInfo, ScanReport
from .registry import all_collectors, all_rules

log = logging.getLogger(__name__)

ProgressCallback = Callable[[str, int, int], None]


class DiagnosticEngine:
    """Ejecuta un escaneo completo.

    Args:
        collectors: Colectores a usar. Por defecto, todos los registrados.
        rules: Reglas a evaluar. Por defecto, todas las registradas.
        correlators: Funciones que reciben la lista completa de hallazgos
            y devuelven hallazgos adicionales (o los enriquecen). Aca es
            donde vive la logica de "el BSOD y los errores de disco estan
            relacionados".
    """

    def __init__(
        self,
        collectors: Optional[List[Collector]] = None,
        rules: Optional[RuleSet] = None,
        correlators: Optional[List[Callable[[List[Finding], Dict[str, Any]], List[Finding]]]] = None,
    ) -> None:
        self._collectors = collectors if collectors is not None else all_collectors()
        self._rules = rules if rules is not None else all_rules()
        if correlators is None:
            from .correlation import DEFAULT_CORRELATORS

            correlators = list(DEFAULT_CORRELATORS)
        self._correlators = correlators

    # ------------------------------------------------------------------

    def scan(
        self,
        ctx: ScanContext,
        on_progress: Optional[ProgressCallback] = None,
    ) -> ScanReport:
        """Ejecuta el diagnostico completo sobre el contexto dado."""
        report = ScanReport(
            machine=MachineInfo.unknown(),
            started_at=datetime.now(),
            mode=ctx.mode.value,
        )

        self._run_collectors(ctx, report, on_progress)
        self._run_rules(report)
        self._run_correlators(report)

        report.finished_at = datetime.now()
        return report

    # ------------------------------------------------------------------

    def _run_collectors(
        self,
        ctx: ScanContext,
        report: ScanReport,
        on_progress: Optional[ProgressCallback],
    ) -> None:
        # Partir primero y enumerar despues. Enumerar sobre la lista
        # completa mientras el total cuenta solo los aplicables produce
        # contadores absurdos del tipo "[4/3]".
        applicable = []
        for collector in self._collectors:
            if collector.applies_to(ctx):
                applicable.append(collector)
            else:
                report.skipped_collectors.append(collector.name)

        total = len(applicable)

        for index, collector in enumerate(applicable, start=1):
            if collector.requires_admin and not ctx.is_admin:
                ctx.warn(
                    "Sin permisos de administrador: '%s' devolvera datos "
                    "incompletos" % collector.name
                )

            if on_progress is not None:
                on_progress(collector.name, index, total)

            result = collector.run(ctx)
            log.debug("colector %s -> %r", collector.name, result)

            if result.error is not None:
                report.errors.append(
                    CollectorError(collector=collector.name, message=result.error)
                )
                continue

            report.facts[collector.provides] = result.data

            # El colector de sistema es el unico autorizado a definir la
            # identidad de la maquina; el resto solo aporta datos.
            if collector.provides == "system.info":
                self._apply_machine_info(report, result.data)

    @staticmethod
    def _apply_machine_info(report: ScanReport, data: Dict[str, Any]) -> None:
        machine = report.machine
        for field_name in (
            "hostname",
            "os_name",
            "os_version",
            "os_build",
            "architecture",
            "manufacturer",
            "model",
            "serial",
        ):
            value = data.get(field_name)
            if value:
                setattr(machine, field_name, str(value))

    # ------------------------------------------------------------------

    def _run_rules(self, report: ScanReport) -> None:
        for rule in self._rules:
            if not rule.can_evaluate(report.facts):
                log.debug("regla %s saltada: faltan %s", rule.rule_id, rule.requires)
                continue
            try:
                findings = list(rule.evaluate(report.facts))
            except Exception as exc:  # noqa: BLE001 - una regla rota no tumba el escaneo
                log.warning("regla %s fallo: %s", rule.rule_id, exc)
                report.errors.append(
                    CollectorError(
                        collector="rule:" + rule.rule_id,
                        message="%s: %s" % (type(exc).__name__, exc),
                    )
                )
                continue
            report.findings.extend(findings)

    # ------------------------------------------------------------------

    def _run_correlators(self, report: ScanReport) -> None:
        """Segunda pasada: hipotesis que requieren ver el cuadro completo.

        Ejemplo: PWR-001 (arranques inesperados) + STO-001 (disco con
        sectores malos) => el disco es la causa raiz, no dos problemas
        independientes.
        """
        for correlate in self._correlators:
            try:
                extra = correlate(report.findings, report.facts)
            except Exception as exc:  # noqa: BLE001
                log.warning("correlacionador fallo: %s", exc)
                continue
            if extra:
                report.findings.extend(extra)
