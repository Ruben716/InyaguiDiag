"""Reglas de analisis de pantallazos azules.

Complementan a CRA-001 (que solo ve el registro de eventos) con lo que
dice el volcado en si: el codigo de detencion y los modulos cargados.

El aporte central de estas reglas es traducir el codigo a una FAMILIA DE
CAUSAS. Decirle al usuario "0x7A" no sirve de nada; decirle "el disco no
pudo entregar una pagina de memoria, respalda y revisa el cable" si.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, List

from ..core.minidump import CrashDump
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
from ..knowledge import bugcheck_codes
from .base import Rule

# Controladores de terceros que aparecen con frecuencia como causa. Los de
# Microsoft se excluyen del senalamiento porque casi siempre son la
# victima que reporta, no el culpable.
_MICROSOFT_DRIVERS = {
    "ntoskrnl.exe", "ntfs.sys", "ndis.sys", "tcpip.sys", "win32k.sys",
    "hal.dll", "fltmgr.sys", "ntkrnlmp.exe", "volsnap.sys", "partmgr.sys",
    "storport.sys", "disk.sys", "classpnp.sys", "acpi.sys", "pci.sys",
    "wdf01000.sys", "ksecdd.sys", "cng.sys", "msrpc.sys", "afd.sys",
}


def _dumps(facts: Dict[str, Any]) -> List[CrashDump]:
    return facts["crash.dumps"].get("dumps", [])


@register_rule
class BugCheckAnalysisRule(Rule):
    """Interpreta los codigos de detencion de los volcados encontrados."""

    rule_id = "CRA-002"
    category = Category.CRASH
    requires = ("crash.dumps",)

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        dumps = _dumps(facts)
        if not dumps:
            return []

        findings: List[Finding] = []
        by_code = Counter(d.bugcheck_code for d in dumps)

        for code, count in by_code.most_common():
            samples = [d for d in dumps if d.bugcheck_code == code]
            findings.append(self._for_code(code, count, samples, len(dumps)))

        return findings

    def _for_code(
        self, code: int, count: int, samples: List[CrashDump], total: int
    ) -> Finding:
        entry = bugcheck_codes.lookup(code)
        sample = samples[0]

        if entry is None:
            return self.finding(
                title="Pantallazo con codigo no catalogado %s" % sample.hex_code,
                severity=Severity.WARNING,
                summary=(
                    "Se encontraron %d volcado(s) con el codigo %s, que no "
                    "esta en nuestro catalogo. Los parametros fueron: %s"
                    % (count, sample.hex_code, sample.parameter_text())
                ),
                evidence=_evidence(samples),
                remedy=Remedy(
                    explanation=(
                        "El codigo identifica el tipo de fallo. Este no lo "
                        "tenemos documentado, pero el numero es buscable."
                    ),
                    steps=[
                        "Buscar 'bugcheck %s' en la documentacion de Microsoft"
                        % sample.hex_code,
                        "Revisar los demas hallazgos de este reporte",
                    ],
                    risk=RiskLevel.SAFE,
                ),
                confidence=Confidence.POSSIBLE,
                suffix=sample.hex_code,
            )

        # Repetir el mismo codigo es mucho mas informativo que codigos
        # variados: apunta a una causa unica y persistente.
        repeated = count >= 3
        severity = Severity.CRITICAL if (repeated or entry.hardware) else Severity.WARNING

        summary = "%s Se repitio %d de %d volcado(s) analizados." % (
            entry.meaning, count, total,
        )
        if repeated:
            summary += (
                " Que siempre sea el mismo codigo refuerza que hay una unica "
                "causa de fondo."
            )

        return self.finding(
            title="%s: %s" % (entry.short_hex, entry.name),
            severity=severity,
            summary=summary,
            evidence=_evidence(samples),
            remedy=_remedy_for(entry),
            confidence=Confidence.CERTAIN if repeated else Confidence.LIKELY,
            suffix=entry.short_hex,
        )


@register_rule
class SuspectDriverRule(Rule):
    """Senala controladores de terceros presentes en todos los volcados.

    Precaucion deliberada: sin simbolos NO se puede afirmar quien causo el
    fallo. Lo que si es significativo es que un controlador de terceros
    aparezca en TODOS los volcados. Por eso esta regla nunca emite
    `CERTAIN` y su titulo dice "presente en", no "causante de".
    """

    rule_id = "CRA-003"
    category = Category.DRIVERS
    requires = ("crash.dumps",)

    _MIN_DUMPS = 2

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        dumps = [d for d in _dumps(facts) if d.modules]
        if len(dumps) < self._MIN_DUMPS:
            return []

        # Interseccion: modulos de terceros presentes en todos los volcados.
        common = None
        for dump in dumps:
            third_party = {
                m for m in dump.modules if m.lower() not in _MICROSOFT_DRIVERS
            }
            common = third_party if common is None else (common & third_party)

        if not common:
            return []

        # Demasiados candidatos no es una pista, es ruido.
        if len(common) > 8:
            return []

        names = sorted(common)
        return [
            self.finding(
                title="Controlador(es) de terceros presente(s) en todos los volcados",
                severity=Severity.WARNING,
                summary=(
                    "Estos controladores que no son de Windows aparecen en "
                    "los %d volcados analizados: %s. No prueba que sean la "
                    "causa, pero son los primeros que conviene actualizar."
                    % (len(dumps), ", ".join(names))
                ),
                evidence=[
                    Evidence(
                        source="volcados",
                        detail="Presente en los %d volcados: %s"
                        % (len(dumps), ", ".join(names)),
                        data={"modules": names},
                    )
                ],
                remedy=Remedy(
                    explanation=(
                        "Identificar el controlador exacto exige WinDbg con "
                        "los simbolos de Microsoft. Lo que si sabemos es que "
                        "estos estaban cargados en todos los fallos, y los "
                        "controladores de terceros son la causa mas comun de "
                        "pantallazos."
                    ),
                    steps=[
                        "Actualizar estos controladores desde la web del "
                        "fabricante, no desde Windows Update",
                        "Si alguno pertenece a un antivirus de terceros, "
                        "probar a desinstalarlo temporalmente",
                        "Si el problema empezo tras instalar algo, "
                        "desinstalarlo",
                    ],
                    risk=RiskLevel.MODERATE,
                ),
                # Nunca CERTAIN: es coincidencia, no atribucion.
                confidence=Confidence.POSSIBLE,
            )
        ]


@register_rule
class CrashDumpsDisabledRule(Rule):
    """Avisa cuando hubo pantallazos pero no hay volcados que analizar.

    Es un hallazgo por ausencia. Sin volcados el diagnostico de un
    pantallazo se vuelve adivinanza, asi que conviene activarlos antes del
    proximo fallo.
    """

    rule_id = "CRA-004"
    category = Category.CRASH
    requires = ("crash.dumps",)

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        block = facts["crash.dumps"]
        if block.get("found"):
            return []

        return [
            self.finding(
                title="No hay volcados de pantallazo para analizar",
                severity=Severity.INFO,
                summary=(
                    "No se encontraron archivos de volcado en %s. Si el "
                    "equipo tuvo pantallazos, sin volcados no se puede "
                    "saber que los causo."
                    % block.get("minidump_dir", "la carpeta Minidump")
                ),
                evidence=[
                    Evidence(
                        source="sistema-archivos",
                        detail="Carpeta %s: %s"
                        % (
                            block.get("minidump_dir", "?"),
                            "existe pero vacia" if block.get("dir_exists")
                            else "no existe",
                        ),
                    )
                ],
                remedy=Remedy(
                    explanation=(
                        "Windows puede tener los volcados desactivados, o el "
                        "archivo de paginacion puede ser demasiado pequeno "
                        "para escribirlos. Tambien puede ser, simplemente, "
                        "que este equipo nunca tuvo un pantallazo."
                    ),
                    steps=[
                        "Configuracion avanzada del sistema > Inicio y "
                        "recuperacion",
                        "En 'Escribir informacion de depuracion' elegir "
                        "'Volcado de memoria pequeno (256 KB)'",
                        "Verificar que el archivo de paginacion este "
                        "administrado por el sistema",
                    ],
                    risk=RiskLevel.SAFE,
                ),
                confidence=Confidence.CERTAIN,
            )
        ]


# ----------------------------------------------------------------------


def _evidence(samples: List[CrashDump], limit: int = 3) -> List[Evidence]:
    result = []
    for dump in samples[:limit]:
        result.append(
            Evidence(
                source="volcado:%s" % dump.filename,
                detail="Codigo %s, parametros: %s (%s, %d KB)"
                % (
                    dump.hex_code,
                    dump.parameter_text(),
                    dump.architecture,
                    dump.size_bytes // 1024,
                ),
                data={
                    "bugcheck": dump.bugcheck_code,
                    "parameters": dump.parameters,
                    "modules": dump.modules[:20],
                },
                timestamp=dump.timestamp,
            )
        )
    if len(samples) > limit:
        result.append(
            Evidence(
                source="resumen",
                detail="... y %d volcado(s) mas con el mismo codigo"
                % (len(samples) - limit),
            )
        )
    return result


def _remedy_for(entry: "bugcheck_codes.BugCheck") -> Remedy:
    """Pasos concretos segun la familia de causas del codigo."""
    if entry.suspect == "disco":
        return Remedy(
            explanation=(
                "Este codigo aparece cuando el sistema no logra leer o "
                "escribir en el disco de forma fiable. El disco es el "
                "sospechoso principal, seguido del cable."
            ),
            steps=[
                "RESPALDAR antes de seguir investigando",
                "Revisar el hallazgo de SMART en este reporte",
                "Reconectar o cambiar el cable de datos del disco",
                "Ejecutar chkdsk en el volumen del sistema",
            ],
            action_id="run-chkdsk",
            risk=RiskLevel.INVASIVE,
            requires_admin=True,
            requires_reboot=True,
        )

    if entry.suspect == "memoria":
        return Remedy(
            explanation=(
                "Este codigo indica corrupcion de memoria. Puede ser RAM "
                "defectuosa o un controlador escribiendo donde no debe; "
                "descartar la RAM primero es mas rapido y barato."
            ),
            steps=[
                "Ejecutar el Diagnostico de memoria de Windows",
                "Apagar y reasentar los modulos de RAM",
                "Si hay varios modulos, probar de a uno",
                "Si la RAM esta sana, sospechar de los controladores",
            ],
            action_id="run-memory-diagnostic",
            risk=RiskLevel.MODERATE,
            # La accion marca el arranque siguiente con bcdedit, que exige
            # elevacion. Declararlo aqui evita ofrecer un arreglo que va a
            # fallar delante del cliente por falta de permisos.
            requires_admin=True,
            requires_reboot=True,
        )

    if entry.suspect == "hardware":
        return Remedy(
            explanation=(
                "Este codigo practicamente descarta el software: el "
                "hardware reporto un fallo propio. Reinstalar Windows no "
                "lo va a resolver."
            ),
            steps=[
                "Respaldar los datos",
                "Limpiar polvo y verificar que los ventiladores giren",
                "Comprobar temperaturas bajo carga",
                "Deshacer cualquier overclocking",
                "Reasentar RAM y tarjetas; si persiste, servicio tecnico",
            ],
            risk=RiskLevel.SAFE,
        )

    if entry.suspect == "video":
        return Remedy(
            explanation=(
                "La tarjeta de video dejo de responder. Suele ser el "
                "controlador, y en equipos con polvo acumulado, temperatura."
            ),
            steps=[
                "Actualizar el controlador de video desde la web del "
                "fabricante (NVIDIA, AMD o Intel)",
                "Si empezo tras una actualizacion, instalar la version anterior",
                "Limpiar el disipador de la tarjeta",
            ],
            risk=RiskLevel.MODERATE,
        )

    # controlador / sistema
    return Remedy(
        explanation=(
            "Este codigo apunta a software de bajo nivel: un controlador o "
            "un componente del sistema. Suele resolverse actualizando o "
            "quitando el responsable."
        ),
        steps=[
            "Revisar si hay un controlador senalado en este reporte",
            "Actualizar controladores de red, video y almacenamiento",
            "Comprobar la integridad de los archivos del sistema",
            "Si empezo tras instalar algo, desinstalarlo",
        ],
        action_id="run-sfc",
        risk=RiskLevel.INVASIVE,
        requires_admin=True,
    )
