"""Reglas basadas en los registros de eventos de Windows.

Estas reglas leen `events.timeline`, que proveen TANTO el colector online
como el offline. Por eso funcionan igual en un equipo arrancado que en un
disco muerto montado desde el USB, sin una sola linea condicional.

Criterio general: un evento aislado casi nunca es un diagnostico. Lo que
importa es la REPETICION y el CONTEXTO. Por eso casi todas las reglas de
aqui cuentan ocurrencias y las contrastan con el periodo cubierto.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from ..core.events import EventRecord, Timeline
from ..core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Remedy,
    RiskLevel,
    Severity,
)
from ..core.registry import register_rule
from ..knowledge import event_catalog
from .base import Rule


def _timeline(facts: Dict[str, Any]) -> Timeline:
    return facts["events.timeline"]["timeline"]


def _evidence_from(events: List[EventRecord], limit: int = 3) -> List[Evidence]:
    """Convierte eventos en evidencia, mostrando solo una muestra."""
    result = []
    for event in events[:limit]:
        result.append(
            Evidence(
                source="%s:%s" % (event.log, event.key),
                detail="Evento %d de %s (%s)"
                % (event.event_id, event.provider, event.level_name),
                data=dict(event.data),
                timestamp=event.timestamp,
            )
        )
    if len(events) > limit:
        result.append(
            Evidence(
                source="resumen",
                detail="... y %d ocurrencias mas" % (len(events) - limit),
            )
        )
    return result


# ----------------------------------------------------------------------
# Pantallazos azules
# ----------------------------------------------------------------------


@register_rule
class BlueScreenRule(Rule):
    """Detecta pantallazos azules registrados en el log.

    El log no guarda el volcado, pero si el codigo de comprobacion. Con eso
    ya se puede decir de que familia es el fallo antes de tocar el minidump
    (que es la fase 3).
    """

    rule_id = "CRA-001"
    category = Category.CRASH
    requires = ("events.timeline",)

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        timeline = _timeline(facts)
        crashes = timeline.of(event_ids=(1001,), provider="BugCheck")
        crashes += timeline.of(
            event_ids=(1001,), provider="Microsoft-Windows-WER-SystemErrorReporting"
        )
        if not crashes:
            return []

        codes = _bugcheck_codes(crashes)
        count = len(crashes)
        last = max(c.timestamp for c in crashes if c.timestamp) if crashes else None

        severity = Severity.CRITICAL if count >= 3 else Severity.WARNING
        code_text = ""
        if codes:
            code_text = " Codigos vistos: %s." % ", ".join(sorted(codes))

        return [
            self.finding(
                title="%d pantallazo(s) azul(es) registrado(s)" % count,
                severity=severity,
                summary=(
                    "Windows registro %d detencion(es) por error grave.%s "
                    "El ultimo fue el %s."
                    % (
                        count,
                        code_text,
                        last.strftime("%d/%m/%Y a las %H:%M") if last else "?",
                    )
                ),
                evidence=_evidence_from(crashes),
                remedy=Remedy(
                    explanation=(
                        "Un pantallazo azul es Windows deteniendose para no "
                        "danar datos. La causa esta casi siempre en un "
                        "controlador defectuoso, en la memoria RAM o en el "
                        "disco. El codigo indica la familia del fallo."
                    ),
                    steps=[
                        "Revisar los demas hallazgos de este reporte: si hay "
                        "errores de disco o de memoria, esa es la causa",
                        "Actualizar los controladores de video y de red",
                        "Ejecutar el diagnostico de memoria de Windows",
                        "Si es reciente, deshacer el ultimo cambio de hardware "
                        "o el ultimo controlador instalado",
                    ],
                    risk=RiskLevel.SAFE,
                ),
                confidence=Confidence.CERTAIN,
            )
        ]


def _bugcheck_codes(events: List[EventRecord]) -> set:
    codes = set()
    for event in events:
        for key in ("BugcheckCode", "param1", "Data0"):
            value = event.data.get(key)
            if not value:
                continue
            text = str(value).strip()
            if text.startswith("0x"):
                codes.add(text)
            else:
                try:
                    codes.add("0x%X" % int(text))
                except ValueError:
                    continue
            break
    return codes


# ----------------------------------------------------------------------
# Apagones
# ----------------------------------------------------------------------


@register_rule
class UnexpectedShutdownRule(Rule):
    """Apagados sucios repetidos.

    Uno es un corte de luz. Cinco en dos semanas es un sintoma: fuente de
    poder, sobrecalentamiento, o bateria de portatil agotada.
    """

    rule_id = "PWR-001"
    category = Category.POWER
    requires = ("events.timeline",)

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        timeline = _timeline(facts)
        events = timeline.of(
            provider="Microsoft-Windows-Kernel-Power", event_ids=(41,)
        )
        events += timeline.of(provider="EventLog", event_ids=(6008,))
        if not events:
            return []

        count = len(events)
        if count == 1:
            severity = Severity.INFO
        elif count < 5:
            severity = Severity.WARNING
        else:
            severity = Severity.CRITICAL

        return [
            self.finding(
                title="%d apagado(s) inesperado(s)" % count,
                severity=severity,
                summary=(
                    "El equipo se apago sin cerrar Windows %d vez(ces). "
                    "Cada apagado sucio arriesga corromper archivos del "
                    "sistema." % count
                ),
                evidence=_evidence_from(events),
                remedy=Remedy(
                    explanation=(
                        "Un apagado limpio deja rastro; uno sucio significa "
                        "que se corto la corriente de golpe. Las causas "
                        "tipicas son corte de luz, fuente de poder debil, "
                        "sobrecalentamiento que fuerza el apagado, o una "
                        "bateria de portatil que ya no sostiene carga."
                    ),
                    steps=[
                        "Si es de escritorio: probar con otro tomacorriente "
                        "y considerar un estabilizador o UPS",
                        "Si es portatil: revisar el desgaste de la bateria",
                        "Limpiar el polvo de ventiladores y disipadores",
                        "Revisar si coincide con los pantallazos de este reporte",
                    ],
                    risk=RiskLevel.SAFE,
                ),
                confidence=Confidence.LIKELY if count < 5 else Confidence.CERTAIN,
            )
        ]


# ----------------------------------------------------------------------
# Disco visto desde el log
# ----------------------------------------------------------------------


@register_rule
class DiskEventRule(Rule):
    """Errores de disco reportados por el controlador.

    Complementa a STO-001 (que mira SMART) desde otro angulo. Un disco
    puede pasar SMART y aun asi estar generando errores de E/S, tipicamente
    por cable o controladora.
    """

    rule_id = "STO-003"
    category = Category.STORAGE
    requires = ("events.timeline",)

    _DISK_IDS = (7, 11, 51, 153)

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        timeline = _timeline(facts)
        events = [
            e
            for e in timeline.problems()
            if e.event_id in self._DISK_IDS
            and ("disk" in e.provider.lower() or "storahci" in e.provider.lower())
        ]
        events += timeline.of(provider="Ntfs", event_ids=(55, 137))
        if not events:
            return []

        count = len(events)
        severity = Severity.CRITICAL if count >= 10 else Severity.WARNING

        return [
            self.finding(
                title="%d error(es) de disco en el registro" % count,
                severity=severity,
                summary=(
                    "El controlador de almacenamiento reporto %d errores de "
                    "lectura, escritura o integridad. Los errores de disco "
                    "en el log preceden a la perdida de datos." % count
                ),
                evidence=_evidence_from(events, limit=4),
                remedy=Remedy(
                    explanation=(
                        "El sistema no logro completar operaciones sobre el "
                        "disco. Puede ser el disco muriendo, pero tambien un "
                        "cable SATA flojo o una controladora con problemas."
                    ),
                    steps=[
                        "Respaldar los archivos importantes cuanto antes",
                        "Revisar el hallazgo de SMART en este mismo reporte",
                        "Reconectar o cambiar el cable de datos del disco",
                        "Ejecutar chkdsk en el volumen afectado",
                    ],
                    action_id="run-chkdsk",
                    risk=RiskLevel.INVASIVE,
                    requires_admin=True,
                    requires_reboot=True,
                ),
            )
        ]


# ----------------------------------------------------------------------
# Hardware y memoria
# ----------------------------------------------------------------------


@register_rule
class HardwareErrorRule(Rule):
    """Errores de hardware reportados por WHEA."""

    rule_id = "HWR-001"
    category = Category.HARDWARE
    requires = ("events.timeline",)

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        timeline = _timeline(facts)
        events = timeline.of(provider="Microsoft-Windows-WHEA-Logger")
        if not events:
            return []

        fatal = [e for e in events if e.event_id in (1, 18)]
        corrected = [e for e in events if e.event_id in (17, 19)]
        findings: List[Finding] = []

        if fatal:
            findings.append(
                self.finding(
                    title="Error de hardware irrecuperable",
                    severity=Severity.CRITICAL,
                    summary=(
                        "El sistema reporto %d error(es) de hardware que no "
                        "pudo corregir. Es de los diagnosticos mas serios: "
                        "apunta a procesador, placa o memoria." % len(fatal)
                    ),
                    evidence=_evidence_from(fatal),
                    remedy=Remedy(
                        explanation=(
                            "WHEA es el subsistema que reporta fallos del "
                            "hardware fisico. Un error irrecuperable no se "
                            "arregla con software."
                        ),
                        steps=[
                            "Respaldar los datos",
                            "Comprobar temperaturas y limpiar el polvo",
                            "Reasentar la memoria RAM y las tarjetas de expansion",
                            "Probar con un solo modulo de RAM a la vez",
                            "Si persiste, llevar a servicio tecnico",
                        ],
                        risk=RiskLevel.SAFE,
                    ),
                    suffix="fatal",
                )
            )

        if len(corrected) >= 20:
            findings.append(
                self.finding(
                    title="%d errores de hardware corregidos" % len(corrected),
                    severity=Severity.WARNING,
                    summary=(
                        "El hardware corrigio %d errores por su cuenta. "
                        "Individualmente no son graves, pero esta cantidad "
                        "suele anticipar un fallo definitivo."
                        % len(corrected)
                    ),
                    evidence=_evidence_from(corrected),
                    remedy=Remedy(
                        explanation=(
                            "Los errores corregidos son avisos tempranos: el "
                            "hardware todavia se recupera solo, pero la "
                            "frecuencia indica degradacion."
                        ),
                        steps=[
                            "Ejecutar el diagnostico de memoria de Windows",
                            "Reasentar los modulos de RAM",
                            "Vigilar si la cantidad crece con el tiempo",
                        ],
                        risk=RiskLevel.SAFE,
                    ),
                    confidence=Confidence.LIKELY,
                    suffix="corregidos",
                )
            )

        return findings


@register_rule
class MemoryDiagnosticRule(Rule):
    """Resultados del diagnostico de memoria de Windows."""

    rule_id = "MEM-001"
    category = Category.MEMORY
    requires = ("events.timeline",)

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        timeline = _timeline(facts)
        events = timeline.of(
            provider="Microsoft-Windows-MemoryDiagnostics-Results",
            event_ids=(1201,),
        )
        if not events:
            return []

        return [
            self.finding(
                title="La memoria RAM tiene errores",
                severity=Severity.CRITICAL,
                summary=(
                    "El diagnostico de memoria de Windows encontro errores en "
                    "la RAM. La memoria defectuosa causa pantallazos azules, "
                    "corrupcion de archivos y cierres aleatorios."
                ),
                evidence=_evidence_from(events),
                remedy=Remedy(
                    explanation=(
                        "Una memoria con errores corrompe datos de forma "
                        "silenciosa. No se repara: se reemplaza."
                    ),
                    steps=[
                        "Apagar y reasentar los modulos de RAM (a veces basta)",
                        "Si hay varios modulos, probar de a uno para "
                        "identificar el defectuoso",
                        "Reemplazar el modulo que falla",
                    ],
                    risk=RiskLevel.SAFE,
                ),
            )
        ]


# ----------------------------------------------------------------------
# Ruido recurrente
# ----------------------------------------------------------------------


@register_rule
class RecurringErrorRule(Rule):
    """Errores que se repiten mucho aunque no esten catalogados.

    Complemento al catalogo: recoge lo que no conocemos por nombre pero
    que por pura frecuencia merece una mirada. Es la red de seguridad
    contra el sesgo de "solo veo lo que ya se buscar".
    """

    rule_id = "SYS-001"
    category = Category.SYSTEM
    requires = ("events.timeline",)

    _THRESHOLD = 25
    _MAX_REPORTED = 5

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        timeline = _timeline(facts)
        groups = timeline.group_by_key()

        candidates = []
        for key, events in groups.items():
            if len(events) < self._THRESHOLD:
                continue
            if not events[0].is_problem:
                continue
            # Si ya hay una regla dedicada, no duplicar el hallazgo.
            meaning = event_catalog.lookup(events[0].provider, events[0].event_id)
            if meaning is not None and meaning.weight >= 4:
                continue
            candidates.append((len(events), key, events))

        candidates.sort(reverse=True, key=lambda item: item[0])
        findings: List[Finding] = []

        for count, key, events in candidates[: self._MAX_REPORTED]:
            sample = events[0]
            meaning = event_catalog.lookup(sample.provider, sample.event_id)
            description = meaning.meaning if meaning else (
                "Este evento no esta en nuestro catalogo, pero su frecuencia "
                "es anormal."
            )
            findings.append(
                self.finding(
                    title="Error repetido %d veces: %s" % (count, sample.provider),
                    severity=Severity.WARNING if count < 100 else Severity.CRITICAL,
                    summary=(
                        "El evento %d de '%s' se registro %d veces. %s"
                        % (sample.event_id, sample.provider, count, description)
                    ),
                    evidence=_evidence_from(events, limit=2),
                    remedy=Remedy(
                        explanation=(
                            "Un error que se repite cientos de veces consume "
                            "recursos y suele ser sintoma de un componente "
                            "atascado en un bucle de reintentos."
                        ),
                        steps=[
                            "Buscar el evento %d de '%s' para el detalle exacto"
                            % (sample.event_id, sample.provider),
                            "Revisar si corresponde a un programa que se puede "
                            "reinstalar o desactivar",
                        ],
                        risk=RiskLevel.SAFE,
                    ),
                    confidence=Confidence.POSSIBLE,
                    suffix=key.replace("/", "-"),
                )
            )
        return findings
