"""Modelos de dominio de InyaguiDiag.

Estas estructuras son el contrato entre las tres capas del sistema:

    Colector  --produce-->  Facts
    Motor     --consume-->  Facts   --produce-->  Finding
    Reporte   --consume-->  Finding

Nada fuera de este modulo define que es un hallazgo. Si una regla necesita
un campo nuevo, se agrega aca y se propaga; no se inventan diccionarios
sueltos en las reglas.

Compatibilidad: Python 3.8 (soporte Windows 7). No usar `match`, ni
uniones con `|`, ni `dict[str, x]` en anotaciones evaluadas.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional


class Severity(IntEnum):
    """Nivel de gravedad. Ordenable: mayor valor = mas urgente.

    El orden importa. El reporte ordena por severidad descendente y el
    codigo de salida del CLI se deriva del maximo encontrado.
    """

    OK = 0
    INFO = 1
    WARNING = 2
    CRITICAL = 3

    @property
    def label(self) -> str:
        return _SEVERITY_LABELS[self]

    @property
    def icon(self) -> str:
        return _SEVERITY_ICONS[self]


_SEVERITY_LABELS = {
    Severity.OK: "CORRECTO",
    Severity.INFO: "INFORMACION",
    Severity.WARNING: "ADVERTENCIA",
    Severity.CRITICAL: "CRITICO",
}

_SEVERITY_ICONS = {
    Severity.OK: "[OK]",
    Severity.INFO: "[i]",
    Severity.WARNING: "[!]",
    Severity.CRITICAL: "[X]",
}


class Category(str, Enum):
    """Area del diagnostico. Agrupa los hallazgos en el reporte."""

    STORAGE = "almacenamiento"
    MEMORY = "memoria"
    BOOT = "arranque"
    CRASH = "pantallazos"
    NETWORK = "red"
    SYSTEM = "sistema"
    DRIVERS = "controladores"
    SECURITY = "seguridad"
    PERFORMANCE = "rendimiento"
    POWER = "energia"
    HARDWARE = "hardware"


class Confidence(IntEnum):
    """Que tan seguro esta el motor de la causa que propone.

    Existe porque correlacionar eventos produce hipotesis, no certezas.
    El reporte debe distinguir "tu disco tiene 47 sectores realocados"
    (CERTAIN) de "probablemente el driver de red causo el BSOD" (LIKELY).
    """

    POSSIBLE = 1
    LIKELY = 2
    CERTAIN = 3


class RiskLevel(IntEnum):
    """Riesgo de aplicar una accion de reparacion automatica."""

    SAFE = 0        # Reversible y sin efectos colaterales (limpiar temporales)
    MODERATE = 1    # Cambia configuracion del sistema (DNS, servicios)
    INVASIVE = 2    # Requiere reinicio o toca archivos del sistema (SFC/DISM)


@dataclass
class Evidence:
    """Dato crudo que respalda un hallazgo.

    Sin evidencia no hay hallazgo. Todo Finding debe poder responder
    "de donde sacaste eso" apuntando a un origen concreto.
    """

    source: str                       # p.ej. "SMART:PhysicalDrive0", "evtx:System"
    detail: str                       # descripcion legible del dato
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[datetime] = None


@dataclass
class Remedy:
    """Como se arregla el problema.

    `steps` son instrucciones para un humano. `action_id` apunta a una
    accion ejecutable registrada en `inyaguidiag.remediation`; si es None,
    el arreglo no se puede automatizar (p.ej. cambiar un disco).
    """

    explanation: str                  # que significa, en castellano simple
    steps: List[str] = field(default_factory=list)
    action_id: Optional[str] = None
    risk: RiskLevel = RiskLevel.SAFE
    requires_admin: bool = False
    requires_reboot: bool = False

    @property
    def automatable(self) -> bool:
        return self.action_id is not None


@dataclass
class Finding:
    """Un problema detectado, con su explicacion y su solucion.

    Es la unidad de salida del sistema. El reporte no hace mas que
    formatear una lista de estos.
    """

    rule_id: str                      # identificador estable, p.ej. "STO-001"
    title: str
    severity: Severity
    category: Category
    summary: str                      # 1-2 frases, sin jerga
    evidence: List[Evidence] = field(default_factory=list)
    remedy: Optional[Remedy] = None
    confidence: Confidence = Confidence.CERTAIN
    related: List[str] = field(default_factory=list)   # rule_ids correlacionados

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ValueError("Finding requiere rule_id")


@dataclass
class MachineInfo:
    """Identidad de la maquina analizada.

    Se usa como nombre de carpeta del reporte, para poder llevar historial
    de multiples equipos en el mismo USB.
    """

    hostname: str = "desconocido"
    os_name: str = ""
    os_version: str = ""
    os_build: str = ""
    architecture: str = ""
    manufacturer: str = ""
    model: str = ""
    serial: str = ""

    @classmethod
    def unknown(cls) -> "MachineInfo":
        return cls(
            hostname=platform.node() or "desconocido",
            architecture=platform.machine(),
        )

    @property
    def slug(self) -> str:
        """Nombre seguro para usar como carpeta en FAT32."""
        base = self.hostname or "desconocido"
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in base)
        return safe[:40] or "desconocido"


@dataclass
class CollectorError:
    """Fallo de un colector.

    Un colector que revienta no debe tumbar el escaneo: se registra aca y
    el reporte lo muestra como cobertura incompleta. Es importante que el
    usuario sepa que NO se pudo mirar, no solo que se encontro.
    """

    collector: str
    message: str
    fatal: bool = False


@dataclass
class ScanReport:
    """Resultado completo de un escaneo."""

    machine: MachineInfo
    started_at: datetime
    finished_at: Optional[datetime] = None
    mode: str = "online"
    findings: List[Finding] = field(default_factory=list)
    errors: List[CollectorError] = field(default_factory=list)
    facts: Dict[str, Any] = field(default_factory=dict)
    skipped_collectors: List[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def worst_severity(self) -> Severity:
        if not self.findings:
            return Severity.OK
        return max(f.severity for f in self.findings)

    def by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def counts(self) -> Dict[Severity, int]:
        result = {s: 0 for s in Severity}
        for f in self.findings:
            result[f.severity] += 1
        return result

    def sorted_findings(self) -> List[Finding]:
        """Peor primero; a igual severidad, agrupa por categoria."""
        return sorted(
            self.findings,
            key=lambda f: (-int(f.severity), f.category.value, f.rule_id),
        )
