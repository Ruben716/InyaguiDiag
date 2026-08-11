"""Salida JSON del reporte.

Para dos usos:

  1. Historial en el USB. El HTML es para leer; el JSON es para que un dia
     se puedan comparar dos escaneos del mismo equipo y ver si el disco
     empeoro.
  2. Integracion. Si esto alguna vez se conecta a un sistema de tickets,
     el JSON es la puerta.

Solo se serializan los hallazgos y la identidad del equipo, NO los datos
crudos de los colectores: incluyen rutas, seriales y nombres de red, y no
tienen por que salir de la maquina.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from ..core.models import Finding, ScanReport
from ..version import __version__

SCHEMA_VERSION = 1


def to_dict(report: ScanReport) -> Dict[str, Any]:
    """Convierte el reporte a estructuras serializables."""
    machine = report.machine
    return {
        "schema": SCHEMA_VERSION,
        "tool": {"name": "InyaguiDiag", "vendor": "Inyagui Solutions",
                 "version": __version__},
        "scan": {
            "mode": report.mode,
            "started_at": report.started_at.isoformat(),
            "finished_at": (
                report.finished_at.isoformat() if report.finished_at else None
            ),
            "duration_seconds": round(report.duration_seconds, 2),
            "worst_severity": report.worst_severity.name,
        },
        "machine": {
            "hostname": machine.hostname,
            "os_name": machine.os_name,
            "os_version": machine.os_version,
            "os_build": machine.os_build,
            "architecture": machine.architecture,
            "manufacturer": machine.manufacturer,
            "model": machine.model,
            "serial": machine.serial,
        },
        "summary": {
            severity.name: count for severity, count in report.counts().items()
        },
        "findings": [_finding(f) for f in report.sorted_findings()],
        "coverage_gaps": [
            {"collector": e.collector, "message": e.message} for e in report.errors
        ],
        "skipped_collectors": list(report.skipped_collectors),
    }


def _finding(finding: Finding) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.name,
        "category": finding.category.value,
        "confidence": finding.confidence.name,
        "summary": finding.summary,
        "related": list(finding.related),
        "evidence": [
            {
                "source": e.source,
                "detail": e.detail,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            }
            for e in finding.evidence
        ],
    }
    if finding.remedy is not None:
        data["remedy"] = {
            "explanation": finding.remedy.explanation,
            "steps": list(finding.remedy.steps),
            "automatable": finding.remedy.automatable,
            "action_id": finding.remedy.action_id,
            # `automatable` solo dice que la REGLA propuso un action_id.
            # Esto dice si esa accion existe de verdad en esta version.
            # Distinguirlos evita prometer un arreglo que no esta.
            "action_available": _action_available(finding.remedy.action_id),
            "risk": finding.remedy.risk.name,
            "requires_admin": finding.remedy.requires_admin,
            "requires_reboot": finding.remedy.requires_reboot,
        }
    return data


def _action_available(action_id) -> bool:
    if not action_id:
        return False
    try:
        from .. import remediation

        return remediation.has_action(action_id)
    except ImportError:
        return False


def write_json(report: ScanReport, output_dir: str) -> str:
    """Escribe el JSON junto al HTML y devuelve la ruta."""
    folder = os.path.join(output_dir, report.machine.slug)
    os.makedirs(folder, exist_ok=True)

    name = report.started_at.strftime("%Y-%m-%d_%H%M") + ".json"
    path = os.path.join(folder, name)

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(to_dict(report), handle, ensure_ascii=False, indent=2)
    return path
