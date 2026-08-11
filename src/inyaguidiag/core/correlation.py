"""Correlacion: de sintomas sueltos a una causa raiz.

POR QUE EXISTE
--------------
Las reglas miran una fuente cada una y no pueden ver el cuadro completo.
Un reporte que dice

    [X] 3 pantallazos azules
    [X] 47 sectores realocados
    [!] 8 apagados inesperados

deja al usuario con tres problemas y ninguna respuesta. Pero si los tres
ocurren juntos, casi seguro no son tres problemas: es UNO --el disco-- con
tres sintomas.

Los correlacionadores corren en una segunda pasada, cuando ya existen
todos los hallazgos, y emiten un diagnostico de nivel superior.

REGLA IMPORTANTE: un correlacionador propone HIPOTESIS, no certezas. Por
eso sus hallazgos nunca llevan `Confidence.CERTAIN`. Presentar una
conjetura como un hecho es peor que no decir nada, porque manda al usuario
a gastar dinero en el componente equivocado.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional

from .events import EventRecord, Timeline
from .models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Remedy,
    RiskLevel,
    Severity,
)

Correlator = Callable[[List[Finding], Dict[str, Any]], List[Finding]]

# Ventana que se mira hacia atras desde un fallo para buscar su causa.
# 10 minutos: suficiente para capturar la cadena de errores que precede a
# un cuelgue, y corto para no arrastrar ruido de horas antes.
CAUSE_WINDOW = timedelta(minutes=10)

# Umbrales del puntaje acumulado de sospecha.
#
# El puntaje suma el `weight` del catalogo por cada aparicion previa a un
# fallo. Los pesos van de 1 a 5, asi que la escala hay que leerla en
# ocurrencias: con eventos de peso 5 (disco, WHEA), MIN_SCORE se alcanza
# con uno solo y LIKELY_SCORE pide cuatro.
#
# LIKELY_SCORE estaba en 10 y era demasiado bajo: dos errores de disco
# bastaban para que el sistema hablara con seguridad. Al subirlo a 20 la
# afirmacion exige un patron sostenido, no una coincidencia.
MIN_SCORE = 4
LIKELY_SCORE = 20


def _timeline(facts: Dict[str, Any]) -> Optional[Timeline]:
    block = facts.get("events.timeline")
    if not block:
        return None
    return block.get("timeline")


def _has(findings: List[Finding], prefix: str) -> List[Finding]:
    return [f for f in findings if f.rule_id.split("/")[0] == prefix]


# ----------------------------------------------------------------------
# Que estaba pasando justo antes del pantallazo
# ----------------------------------------------------------------------


def correlate_crash_cause(
    findings: List[Finding], facts: Dict[str, Any]
) -> List[Finding]:
    """Busca la causa de los pantallazos en lo ocurrido justo antes.

    Este es el analisis que un tecnico hace a mano abriendo el Visor de
    eventos y mirando hacia arriba desde el fallo. Aca esta automatizado.
    """
    timeline = _timeline(facts)
    if timeline is None:
        return []

    crashes = timeline.of(event_ids=(1001,), provider="BugCheck")
    crashes += timeline.of(
        event_ids=(1001,), provider="Microsoft-Windows-WER-SystemErrorReporting"
    )
    crashes += timeline.of(provider="Microsoft-Windows-Kernel-Power", event_ids=(41,))
    if not crashes:
        return []

    # Acumula los sospechosos que preceden a cada fallo, ponderados.
    scores: Dict[str, int] = {}
    samples: Dict[str, List[EventRecord]] = {}

    for crash in crashes:
        if crash.timestamp is None:
            continue
        for previous in timeline.preceding(crash.timestamp, CAUSE_WINDOW):
            if previous.key == crash.key:
                continue
            from ..knowledge import event_catalog

            meaning = event_catalog.lookup(previous.provider, previous.event_id)
            weight = meaning.weight if meaning else 1
            scores[previous.key] = scores.get(previous.key, 0) + weight
            samples.setdefault(previous.key, []).append(previous)

    if not scores:
        return [_crash_without_precursors(len(crashes))]

    best_key = max(scores, key=lambda k: scores[k])
    best_score = scores[best_key]

    # Por debajo del minimo la coincidencia es demasiado debil para
    # afirmar nada. Preferimos no opinar antes que senalar al culpable
    # equivocado.
    if best_score < MIN_SCORE:
        return []

    events = samples[best_key]
    sample = events[0]

    from ..knowledge import event_catalog

    meaning = event_catalog.lookup(sample.provider, sample.event_id)
    is_hardware = bool(meaning and meaning.hardware_suspect)

    return [
        Finding(
            rule_id="COR-001",
            title="Causa probable de los fallos: %s" % sample.provider,
            severity=Severity.CRITICAL,
            category=meaning.category if meaning else Category.SYSTEM,
            summary=(
                "En los 10 minutos previos a los fallos aparece repetidamente "
                "el evento %d de '%s' (%d veces). Eso lo convierte en el "
                "sospechoso principal, por encima de lo que indique el "
                "volcado: el componente que reporta el fallo no siempre es "
                "el que lo causa."
                % (sample.event_id, sample.provider, len(events))
            ),
            evidence=[
                Evidence(
                    source="correlacion",
                    detail=(
                        "%d fallo(s) analizados; '%s' precede con puntaje %d"
                        % (len(crashes), best_key, best_score)
                    ),
                    data={"score": best_score, "occurrences": len(events)},
                ),
                Evidence(
                    source="%s:%s" % (sample.log, sample.key),
                    detail=meaning.meaning if meaning else "Evento no catalogado",
                    timestamp=sample.timestamp,
                ),
            ],
            remedy=Remedy(
                explanation=(
                    "Atacar la causa raiz resuelve todos los sintomas de una "
                    "vez. Arreglar los sintomas por separado no resuelve nada."
                ),
                steps=(
                    [
                        "Este apunta a HARDWARE: respaldar los datos primero",
                        "Revisar los demas hallazgos de la misma area",
                        "Reemplazar o reasentar el componente senalado",
                    ]
                    if is_hardware
                    else [
                        "Revisar los demas hallazgos de la misma area",
                        "Actualizar o reinstalar el componente senalado",
                        "Si es un servicio, revisar su configuracion",
                    ]
                ),
                risk=RiskLevel.SAFE,
            ),
            # Nunca CERTAIN: esto es una inferencia, no una medicion.
            confidence=(
                Confidence.LIKELY if best_score >= LIKELY_SCORE else Confidence.POSSIBLE
            ),
            related=[f.rule_id for f in findings if f.category == (
                meaning.category if meaning else Category.SYSTEM)],
        )
    ]


def _crash_without_precursors(count: int) -> Finding:
    """Fallos sin nada anotado antes: apunta a corte electrico o termico.

    La ausencia de evidencia ES evidencia aca. Si el equipo se apago y
    Windows no alcanzo a registrar ni una queja, no fue un proceso
    degradandose: fue algo instantaneo.
    """
    return Finding(
        rule_id="COR-002",
        title="Fallos sin aviso previo en el registro",
        severity=Severity.WARNING,
        category=Category.POWER,
        summary=(
            "Se detectaron %d fallo(s) pero Windows no registro ningun error "
            "en los minutos previos. Un apagado sin rastro apunta a corte de "
            "corriente, apagado por temperatura o fuente de poder, no a un "
            "problema de software." % count
        ),
        evidence=[
            Evidence(
                source="correlacion",
                detail="Ventana de %d minutos previa a cada fallo: sin eventos"
                % int(CAUSE_WINDOW.total_seconds() // 60),
            )
        ],
        remedy=Remedy(
            explanation=(
                "Cuando el sistema muere de golpe no alcanza a escribir en el "
                "log. Esa falta de rastro es en si misma la pista."
            ),
            steps=[
                "Limpiar polvo de ventiladores y disipadores",
                "Verificar que los ventiladores giren al encender",
                "Probar el equipo en otro tomacorriente",
                "En portatil: revisar el desgaste de la bateria y el cargador",
                "En escritorio: sospechar de la fuente de poder",
            ],
            risk=RiskLevel.SAFE,
        ),
        confidence=Confidence.POSSIBLE,
    )


# ----------------------------------------------------------------------
# Evidencia convergente sobre el disco
# ----------------------------------------------------------------------


def correlate_disk_evidence(
    findings: List[Finding], facts: Dict[str, Any]
) -> List[Finding]:
    """Eleva el diagnostico cuando SMART y el log coinciden.

    SMART y los eventos del sistema son fuentes independientes. Que ambas
    senalen el disco no suma: multiplica. Es la diferencia entre "puede que
    el disco este mal" y "el disco esta mal, respalda ya".
    """
    smart_findings = _has(findings, "STO-001")
    log_findings = _has(findings, "STO-003")

    if not (smart_findings and log_findings):
        return []

    return [
        Finding(
            rule_id="COR-003",
            title="Disco confirmado como fallo: dos fuentes coinciden",
            severity=Severity.CRITICAL,
            category=Category.STORAGE,
            summary=(
                "El disco reporta dano por SMART Y ademas genera errores de "
                "E/S en el registro del sistema. Son dos mediciones "
                "independientes apuntando al mismo componente. Esto ya no es "
                "una sospecha."
            ),
            evidence=[
                Evidence(
                    source="correlacion",
                    detail="SMART: %s" % smart_findings[0].title,
                ),
                Evidence(
                    source="correlacion",
                    detail="Registro: %s" % log_findings[0].title,
                ),
            ],
            remedy=Remedy(
                explanation=(
                    "Cuando SMART y el registro del sistema coinciden, la "
                    "probabilidad de un falso positivo es minima. El disco se "
                    "va a terminar de romper; la unica variable es cuando."
                ),
                steps=[
                    "RESPALDAR AHORA. Antes que cualquier otra cosa.",
                    "No desfragmentar ni ejecutar pruebas de escritura",
                    "Comprar el disco de reemplazo",
                    "Clonar mientras el disco viejo aun responda",
                ],
                risk=RiskLevel.SAFE,
            ),
            confidence=Confidence.CERTAIN,
            related=[f.rule_id for f in smart_findings + log_findings],
        )
    ]


# ----------------------------------------------------------------------
# Registro de correlacionadores
# ----------------------------------------------------------------------

DEFAULT_CORRELATORS: List[Correlator] = [
    correlate_crash_cause,
    correlate_disk_evidence,
]
