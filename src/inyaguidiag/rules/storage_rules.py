"""Reglas de almacenamiento.

Estas reglas son las de mayor prioridad del sistema: un disco muriendo se
lleva por delante los datos del usuario, y a diferencia de casi todo lo
demas, no se arregla con software. Por eso STO-001 es siempre CRITICO y
su primer paso es siempre "respalda".

Umbrales: se eligieron conservadores a proposito. Un falso positivo cuesta
una copia de seguridad innecesaria; un falso negativo cuesta los datos.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

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
from .base import Rule

# Atributos SMART de discos giratorios y SATA que importan.
# id -> (nombre legible, umbral de advertencia, umbral critico)
_ATA_ATTRS = {
    5: ("Sectores realocados", 1, 10),
    197: ("Sectores pendientes de realocar", 1, 5),
    198: ("Sectores incorregibles", 1, 1),
    199: ("Errores CRC del cable SATA", 10, 100),
}


@register_rule
class FailingDiskRule(Rule):
    """Detecta discos con dano fisico confirmado por SMART."""

    rule_id = "STO-001"
    category = Category.STORAGE
    requires = ("storage.disks",)

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        findings: List[Finding] = []
        for disk in facts["storage.disks"].get("disks", []):
            findings.extend(self._check_disk(disk))
        return findings

    def _check_disk(self, disk: Dict[str, Any]) -> List[Finding]:
        label = _disk_label(disk)
        smart = disk.get("smart")

        # Camino sin smartctl: solo tenemos el booleano de WMI.
        if not smart:
            if disk.get("failure_predicted") is True:
                return [self._predicted_failure(disk, label)]
            return []

        findings: List[Finding] = []
        findings.extend(self._check_ata(smart, disk, label))
        findings.extend(self._check_nvme(smart, disk, label))
        findings.extend(self._check_overall(smart, disk, label))
        return findings

    # ------------------------------------------------------------------

    def _check_ata(
        self, smart: Dict[str, Any], disk: Dict[str, Any], label: str
    ) -> List[Finding]:
        table = (smart.get("ata_smart_attributes") or {}).get("table") or []
        findings: List[Finding] = []

        for attr in table:
            attr_id = attr.get("id")
            if attr_id not in _ATA_ATTRS:
                continue
            raw = ((attr.get("raw") or {}).get("value")) or 0
            if not isinstance(raw, int) or raw <= 0:
                continue

            name, warn_at, crit_at = _ATA_ATTRS[attr_id]
            if raw < warn_at:
                continue

            severity = Severity.CRITICAL if raw >= crit_at else Severity.WARNING
            is_cable = attr_id == 199

            findings.append(
                self.finding(
                    title="%s: %s" % (label, name.lower()),
                    severity=severity,
                    summary=_ata_summary(attr_id, name, raw, label),
                    evidence=[
                        Evidence(
                            source="SMART:disco%s" % disk.get("index"),
                            detail="Atributo %d (%s) = %d" % (attr_id, name, raw),
                            data={"attribute_id": attr_id, "raw_value": raw},
                        )
                    ],
                    remedy=_cable_remedy() if is_cable else _replace_disk_remedy(),
                    suffix="disco%s-attr%d" % (disk.get("index"), attr_id),
                )
            )
        return findings

    def _check_nvme(
        self, smart: Dict[str, Any], disk: Dict[str, Any], label: str
    ) -> List[Finding]:
        health = smart.get("nvme_smart_health_information_log")
        if not health:
            return []

        findings: List[Finding] = []
        idx = disk.get("index")

        used = health.get("percentage_used")
        if isinstance(used, int) and used >= 80:
            severity = Severity.CRITICAL if used >= 95 else Severity.WARNING
            findings.append(
                self.finding(
                    title="%s: vida util al %d%%" % (label, used),
                    severity=severity,
                    summary=(
                        "El SSD consumio el %d%% de su resistencia de escritura "
                        "estimada. Al llegar a 100%% el fabricante ya no "
                        "garantiza la retencion de datos." % used
                    ),
                    evidence=[
                        Evidence(
                            source="SMART-NVMe:disco%s" % idx,
                            detail="percentage_used = %d%%" % used,
                            data={"percentage_used": used},
                        )
                    ],
                    remedy=_replace_disk_remedy(urgent=used >= 95),
                    suffix="disco%s-vida" % idx,
                )
            )

        spare = health.get("available_spare")
        threshold = health.get("available_spare_threshold")
        if isinstance(spare, int) and isinstance(threshold, int) and spare < threshold:
            findings.append(
                self.finding(
                    title="%s: bloques de reserva agotados" % label,
                    severity=Severity.CRITICAL,
                    summary=(
                        "El SSD se quedo sin bloques de repuesto (%d%% frente a un "
                        "minimo de %d%%). Es el aviso previo a la perdida de datos."
                        % (spare, threshold)
                    ),
                    evidence=[
                        Evidence(
                            source="SMART-NVMe:disco%s" % idx,
                            detail="available_spare=%d%% umbral=%d%%" % (spare, threshold),
                            data={"available_spare": spare, "threshold": threshold},
                        )
                    ],
                    remedy=_replace_disk_remedy(urgent=True),
                    suffix="disco%s-reserva" % idx,
                )
            )

        errors = health.get("media_errors")
        if isinstance(errors, int) and errors > 0:
            findings.append(
                self.finding(
                    title="%s: %d errores de medio" % (label, errors),
                    severity=Severity.CRITICAL if errors > 10 else Severity.WARNING,
                    summary=(
                        "El controlador del SSD reporto %d errores de integridad "
                        "que no pudo corregir. Puede haber archivos danados."
                        % errors
                    ),
                    evidence=[
                        Evidence(
                            source="SMART-NVMe:disco%s" % idx,
                            detail="media_errors = %d" % errors,
                            data={"media_errors": errors},
                        )
                    ],
                    remedy=_replace_disk_remedy(),
                    suffix="disco%s-errores" % idx,
                )
            )

        warning = health.get("critical_warning")
        if isinstance(warning, int) and warning != 0:
            findings.append(
                self.finding(
                    title="%s: aviso critico del controlador" % label,
                    severity=Severity.CRITICAL,
                    summary=(
                        "El propio SSD levanto una bandera de aviso critico "
                        "(codigo 0x%02X). Respalda antes de seguir usandolo."
                        % warning
                    ),
                    evidence=[
                        Evidence(
                            source="SMART-NVMe:disco%s" % idx,
                            detail="critical_warning = 0x%02X" % warning,
                            data={"critical_warning": warning},
                        )
                    ],
                    remedy=_replace_disk_remedy(urgent=True),
                    suffix="disco%s-aviso" % idx,
                )
            )

        return findings

    def _check_overall(
        self, smart: Dict[str, Any], disk: Dict[str, Any], label: str
    ) -> List[Finding]:
        status = smart.get("smart_status") or {}
        if status.get("passed") is False:
            return [
                self.finding(
                    title="%s: SMART reporta FALLO" % label,
                    severity=Severity.CRITICAL,
                    summary=(
                        "El disco declara que esta fallando. Este es el aviso "
                        "mas serio que puede dar un disco por si mismo."
                    ),
                    evidence=[
                        Evidence(
                            source="SMART:disco%s" % disk.get("index"),
                            detail="smart_status.passed = false",
                        )
                    ],
                    remedy=_replace_disk_remedy(urgent=True),
                    suffix="disco%s-global" % disk.get("index"),
                )
            ]
        return []

    def _predicted_failure(self, disk: Dict[str, Any], label: str) -> Finding:
        return self.finding(
            title="%s: Windows predice un fallo" % label,
            severity=Severity.CRITICAL,
            summary=(
                "Windows activo la prediccion de fallo para este disco. No "
                "tenemos los atributos SMART detallados, pero el aviso basta."
            ),
            evidence=[
                Evidence(
                    source="WMI:MSStorageDriver_FailurePredictStatus",
                    detail="PredictFailure = True",
                )
            ],
            remedy=_replace_disk_remedy(urgent=True),
            confidence=Confidence.LIKELY,
            suffix="disco%s-prediccion" % disk.get("index"),
        )


@register_rule
class LowDiskSpaceRule(Rule):
    """Volumenes sin espacio libre.

    Un disco de sistema por debajo del 10%% causa fallos de actualizacion,
    archivo de paginacion insuficiente y cuelgues. Es de las causas mas
    comunes de "la PC anda lenta" y de las mas faciles de arreglar.
    """

    rule_id = "STO-002"
    category = Category.STORAGE
    requires = ("storage.disks",)

    _FIXED_DRIVE = 3

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        findings: List[Finding] = []
        for volume in facts["storage.disks"].get("volumes", []):
            if volume.get("drive_type") != self._FIXED_DRIVE:
                continue
            percent = volume.get("percent_free")
            if percent is None:
                continue

            if percent < 5:
                severity = Severity.CRITICAL
            elif percent < 12:
                severity = Severity.WARNING
            else:
                continue

            device = volume.get("device") or "?"
            free_gb = (volume.get("free_bytes") or 0) / (1024.0 ** 3)

            findings.append(
                self.finding(
                    title="Poco espacio libre en %s" % device,
                    severity=severity,
                    summary=(
                        "Quedan %.1f GB libres (%.1f%%). Con tan poco espacio "
                        "Windows falla al actualizar, no puede crecer el archivo "
                        "de paginacion y el equipo se vuelve lento."
                        % (free_gb, percent)
                    ),
                    evidence=[
                        Evidence(
                            source="WMI:Win32_LogicalDisk",
                            detail="%s libre=%.1f GB (%.1f%%)" % (device, free_gb, percent),
                            data={"device": device, "percent_free": percent},
                        )
                    ],
                    remedy=Remedy(
                        explanation=(
                            "El volumen esta lleno. Liberar espacio suele "
                            "recuperar buena parte del rendimiento perdido."
                        ),
                        steps=[
                            "Vaciar archivos temporales y la papelera",
                            "Ejecutar Liberador de espacio (limpieza de archivos del sistema)",
                            "Revisar y desinstalar programas que no se usan",
                            "Mover fotos y videos a un disco externo",
                        ],
                        action_id="clean-temp-files",
                        risk=RiskLevel.SAFE,
                    ),
                    suffix=str(device).replace(":", ""),
                )
            )
        return findings


# ----------------------------------------------------------------------
# Remedios reutilizables
# ----------------------------------------------------------------------


def _replace_disk_remedy(urgent: bool = False) -> Remedy:
    first = (
        "RESPALDA AHORA MISMO. Antes de cualquier otra cosa."
        if urgent
        else "Respalda tus archivos importantes hoy."
    )
    return Remedy(
        explanation=(
            "El dano en un disco no se repara con software. Los sectores "
            "malos no se 'arreglan'; se marcan y el disco sigue perdiendo "
            "otros. La unica solucion real es cambiar el disco."
        ),
        steps=[
            first,
            "No ejecutes desfragmentacion ni pruebas de escritura: aceleran el fallo",
            "Reemplaza el disco por uno nuevo",
            "Clona el disco viejo al nuevo si aun se puede leer",
        ],
        action_id=None,  # no automatizable: es hardware
        risk=RiskLevel.SAFE,
    )


def _cable_remedy() -> Remedy:
    return Remedy(
        explanation=(
            "Los errores CRC no indican un disco danado sino una conexion "
            "defectuosa: cable SATA suelto, en mal estado, o un puerto sucio. "
            "Es de los pocos problemas de disco que salen baratos."
        ),
        steps=[
            "Apagar y desconectar el equipo de la corriente",
            "Reconectar firmemente el cable SATA en ambos extremos",
            "Si persiste, cambiar el cable SATA (cuestan poco)",
            "Probar otro puerto SATA de la placa",
        ],
        action_id=None,
        risk=RiskLevel.SAFE,
    )


def _ata_summary(attr_id: int, name: str, raw: int, label: str) -> str:
    if attr_id == 5:
        return (
            "El disco realoco %d sectores danados a su zona de reserva. "
            "Los sectores malos no dejan de aparecer una vez que empiezan."
            % raw
        )
    if attr_id == 197:
        return (
            "Hay %d sectores que el disco no logra leer bien y espera "
            "realocar. Puede haber archivos ya corruptos." % raw
        )
    if attr_id == 198:
        return (
            "Hay %d sectores que el disco no pudo corregir de ninguna "
            "manera. Los datos en esos sectores estan perdidos." % raw
        )
    if attr_id == 199:
        return (
            "Se registraron %d errores de transmision en el cable SATA. "
            "Normalmente es el cable, no el disco." % raw
        )
    return "%s: %d en %s" % (name, raw, label)


def _disk_label(disk: Dict[str, Any]) -> str:
    model = disk.get("model") or "Disco %s" % disk.get("index")
    return str(model).strip()
