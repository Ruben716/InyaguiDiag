"""Pruebas de las reglas de almacenamiento.

Estas reglas son las mas criticas del sistema (un disco muriendo se lleva
los datos del usuario), asi que son las primeras que cubrimos.

Las pruebas alimentan `facts` a mano. Esa es justamente la ventaja de
separar colectores de reglas: se puede probar el criterio de diagnostico
sin necesitar un disco enfermo de verdad.
"""

from __future__ import annotations

import pytest

from inyaguidiag.core.models import Severity
from inyaguidiag.rules.storage_rules import FailingDiskRule, LowDiskSpaceRule


def _facts(disks=None, volumes=None):
    return {
        "storage.disks": {
            "disks": disks or [],
            "volumes": volumes or [],
            "smartctl_available": True,
        }
    }


def _disk(index=0, model="Disco de prueba", smart=None, predicted=None):
    return {
        "index": index,
        "model": model,
        "smart": smart,
        "failure_predicted": predicted,
    }


# ----------------------------------------------------------------------
# STO-001
# ----------------------------------------------------------------------


class TestFailingDiskRule:
    def test_disco_sano_no_produce_hallazgos(self):
        smart = {
            "smart_status": {"passed": True},
            "ata_smart_attributes": {"table": [
                {"id": 5, "raw": {"value": 0}},
                {"id": 197, "raw": {"value": 0}},
            ]},
        }
        findings = list(FailingDiskRule().evaluate(_facts([_disk(smart=smart)])))
        assert findings == []

    def test_sectores_realocados_pocos_es_advertencia(self):
        smart = {"ata_smart_attributes": {"table": [{"id": 5, "raw": {"value": 3}}]}}
        findings = list(FailingDiskRule().evaluate(_facts([_disk(smart=smart)])))
        assert len(findings) == 1
        assert findings[0].severity is Severity.WARNING

    def test_sectores_realocados_muchos_es_critico(self):
        smart = {"ata_smart_attributes": {"table": [{"id": 5, "raw": {"value": 47}}]}}
        findings = list(FailingDiskRule().evaluate(_facts([_disk(smart=smart)])))
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL

    def test_errores_crc_proponen_cambiar_el_cable_no_el_disco(self):
        """Regresion: el atributo 199 NO indica un disco danado.

        Confundirlo manda al usuario a comprar un disco cuando el problema
        era un cable de dos soles.
        """
        smart = {"ata_smart_attributes": {"table": [{"id": 199, "raw": {"value": 250}}]}}
        findings = list(FailingDiskRule().evaluate(_facts([_disk(smart=smart)])))
        assert len(findings) == 1
        texto = " ".join(findings[0].remedy.steps).lower()
        assert "cable" in texto
        assert "reemplaza el disco" not in texto

    def test_nvme_vida_util_agotada(self):
        smart = {"nvme_smart_health_information_log": {"percentage_used": 97}}
        findings = list(FailingDiskRule().evaluate(_facts([_disk(smart=smart)])))
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL

    def test_nvme_vida_util_normal_no_alarma(self):
        smart = {"nvme_smart_health_information_log": {"percentage_used": 12}}
        findings = list(FailingDiskRule().evaluate(_facts([_disk(smart=smart)])))
        assert findings == []

    def test_smart_status_fallido_es_critico(self):
        smart = {"smart_status": {"passed": False}}
        findings = list(FailingDiskRule().evaluate(_facts([_disk(smart=smart)])))
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL

    def test_sin_smart_usa_la_prediccion_de_wmi(self):
        findings = list(
            FailingDiskRule().evaluate(_facts([_disk(smart=None, predicted=True)]))
        )
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL

    def test_varios_discos_generan_ids_distintos(self):
        """Dos discos enfermos no deben colisionar en el mismo rule_id."""
        smart = {"ata_smart_attributes": {"table": [{"id": 5, "raw": {"value": 20}}]}}
        facts = _facts([_disk(index=0, smart=smart), _disk(index=1, smart=smart)])
        findings = list(FailingDiskRule().evaluate(facts))
        assert len({f.rule_id for f in findings}) == 2


# ----------------------------------------------------------------------
# STO-002
# ----------------------------------------------------------------------


def _volume(device="C:", percent=50.0, free_gb=100.0, drive_type=3):
    return {
        "device": device,
        "drive_type": drive_type,
        "percent_free": percent,
        "free_bytes": int(free_gb * 1024 ** 3),
    }


class TestLowDiskSpaceRule:
    @pytest.mark.parametrize(
        "percent,esperado",
        [(50.0, None), (15.0, None), (10.0, Severity.WARNING), (3.0, Severity.CRITICAL)],
    )
    def test_umbrales(self, percent, esperado):
        findings = list(
            LowDiskSpaceRule().evaluate(_facts(volumes=[_volume(percent=percent)]))
        )
        if esperado is None:
            assert findings == []
        else:
            assert len(findings) == 1
            assert findings[0].severity is esperado

    def test_ignora_unidades_extraibles(self):
        """Un USB lleno no es un problema del equipo."""
        usb = _volume(device="F:", percent=1.0, drive_type=2)
        findings = list(LowDiskSpaceRule().evaluate(_facts(volumes=[usb])))
        assert findings == []

    def test_sin_dato_de_porcentaje_no_revienta(self):
        volume = _volume()
        volume["percent_free"] = None
        assert list(LowDiskSpaceRule().evaluate(_facts(volumes=[volume]))) == []

    def test_el_remedio_es_automatizable(self):
        findings = list(
            LowDiskSpaceRule().evaluate(_facts(volumes=[_volume(percent=2.0)]))
        )
        assert findings[0].remedy.automatable
