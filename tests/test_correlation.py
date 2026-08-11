"""Pruebas de la correlacion.

Lo que se protege aca es la prudencia del sistema. Un correlacionador que
senala al componente equivocado con seguridad manda al usuario a gastar
dinero al pedo, asi que las pruebas verifican tanto que ACIERTE cuando hay
senal como que se CALLE cuando no la hay.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from inyaguidiag.core.correlation import (
    correlate_crash_cause,
    correlate_disk_evidence,
)
from inyaguidiag.core.events import EventRecord, Timeline
from inyaguidiag.core.models import (
    Category,
    Confidence,
    Finding,
    Severity,
)

CRASH_TIME = datetime(2026, 8, 11, 12, 0)


def _event(provider, event_id, minutes_before, level=2):
    return EventRecord(
        log="System",
        event_id=event_id,
        provider=provider,
        level=level,
        timestamp=CRASH_TIME - timedelta(minutes=minutes_before),
    )


def _crash(minutes_before=0):
    return EventRecord(
        log="System",
        event_id=1001,
        provider="BugCheck",
        level=2,
        timestamp=CRASH_TIME - timedelta(minutes=minutes_before),
    )


def _facts(events):
    return {"events.timeline": {"timeline": Timeline(events)}}


# ----------------------------------------------------------------------
# COR-001 / COR-002
# ----------------------------------------------------------------------


class TestCrashCause:
    def test_sin_fallos_no_dice_nada(self):
        facts = _facts([_event("disk", 11, 5)])
        assert correlate_crash_cause([], facts) == []

    def test_sin_linea_de_tiempo_no_revienta(self):
        assert correlate_crash_cause([], {}) == []

    def test_identifica_el_disco_como_causa(self):
        """Errores de disco justo antes del pantallazo -> el disco."""
        events = [_crash()]
        events += [_event("disk", 11, m) for m in (2, 3, 4, 5)]
        findings = correlate_crash_cause([], _facts(events))

        assert len(findings) == 1
        assert findings[0].rule_id == "COR-001"
        assert findings[0].category is Category.STORAGE
        assert "disk" in findings[0].title

    def test_la_correlacion_nunca_afirma_certeza(self):
        """Una inferencia no es una medicion.

        Presentar una conjetura como hecho manda al usuario a cambiar el
        componente equivocado.
        """
        events = [_crash()] + [_event("disk", 11, m) for m in range(1, 9)]
        findings = correlate_crash_cause([], _facts(events))
        assert findings[0].confidence is not Confidence.CERTAIN

    def test_evidencia_debil_se_calla(self):
        """Un solo evento de peso bajo no alcanza para acusar a nadie."""
        events = [_crash(), _event("Application Error", 1000, 3)]
        assert correlate_crash_cause([], _facts(events)) == []

    def test_ignora_lo_que_paso_despues_del_fallo(self):
        """Lo posterior al fallo es consecuencia, no causa.

        Sin precursores el correlacionador debe concluir COR-002 (apagado
        sin aviso), nunca acusar al disco por errores que aparecieron
        DESPUES del pantallazo.
        """
        events = [_crash()]
        events += [
            EventRecord("System", 11, "disk", 2, CRASH_TIME + timedelta(minutes=m))
            for m in (1, 2, 3, 4)
        ]
        findings = correlate_crash_cause([], _facts(events))
        assert [f.rule_id for f in findings] == ["COR-002"]

    def test_ignora_lo_muy_anterior(self):
        """Fuera de la ventana de 10 minutos no hay relacion causal."""
        events = [_crash()] + [_event("disk", 11, m) for m in (30, 40, 50, 60)]
        findings = correlate_crash_cause([], _facts(events))
        assert [f.rule_id for f in findings] == ["COR-002"]

    def test_fallo_sin_precursores_apunta_a_energia(self):
        """La ausencia de rastro ES la pista: apagado instantaneo."""
        findings = correlate_crash_cause([], _facts([_crash()]))
        assert len(findings) == 1
        assert findings[0].rule_id == "COR-002"
        assert findings[0].category is Category.POWER
        assert findings[0].confidence is Confidence.POSSIBLE

    def test_mas_evidencia_sube_la_confianza(self):
        pocos = [_crash()] + [_event("disk", 11, m) for m in (1, 2)]
        muchos = [_crash()] + [_event("disk", 11, m) for m in range(1, 10)]
        f_pocos = correlate_crash_cause([], _facts(pocos))
        f_muchos = correlate_crash_cause([], _facts(muchos))
        assert f_muchos[0].confidence > f_pocos[0].confidence


# ----------------------------------------------------------------------
# COR-003
# ----------------------------------------------------------------------


def _finding(rule_id, category=Category.STORAGE):
    return Finding(
        rule_id=rule_id,
        title="prueba " + rule_id,
        severity=Severity.WARNING,
        category=category,
        summary="",
    )


class TestDiskEvidence:
    def test_una_sola_fuente_no_confirma(self):
        assert correlate_disk_evidence([_finding("STO-001")], {}) == []
        assert correlate_disk_evidence([_finding("STO-003")], {}) == []

    def test_dos_fuentes_independientes_confirman(self):
        findings = correlate_disk_evidence(
            [_finding("STO-001"), _finding("STO-003")], {}
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "COR-003"
        assert findings[0].severity is Severity.CRITICAL
        # Aca si corresponde certeza: son dos mediciones, no una inferencia.
        assert findings[0].confidence is Confidence.CERTAIN

    def test_funciona_con_sufijos_de_disco(self):
        """Los hallazgos por disco llevan sufijo: STO-001/disco0-attr5."""
        findings = correlate_disk_evidence(
            [_finding("STO-001/disco0-attr5"), _finding("STO-003")], {}
        )
        assert len(findings) == 1

    def test_el_remedio_prioriza_respaldar(self):
        findings = correlate_disk_evidence(
            [_finding("STO-001"), _finding("STO-003")], {}
        )
        assert "RESPALDAR" in findings[0].remedy.steps[0].upper()
