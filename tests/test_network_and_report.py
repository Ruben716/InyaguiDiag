"""Pruebas del diagnostico de red por capas y de los reportes.

Lo que mas se protege aca es la regla de "un solo culpable": cuando no hay
cable, TODO falla en cascada, y un reporte que liste las cinco fallas
sepulta la causa bajo sus consecuencias.
"""

from __future__ import annotations

import json
from datetime import datetime

from inyaguidiag.core.models import (
    Category,
    Evidence,
    Finding,
    MachineInfo,
    Remedy,
    ScanReport,
    Severity,
)
from inyaguidiag.report.html import render_html
from inyaguidiag.report.json_out import to_dict
from inyaguidiag.rules.network_rules import (
    DnsFailureRule,
    GatewayUnreachableRule,
    GhostProxyRule,
    NoAdapterRule,
    NoAddressRule,
    NoInternetRule,
    NoLinkRule,
)

ALL_LAYER_RULES = [
    NoAdapterRule(), NoLinkRule(), NoAddressRule(),
    GatewayUnreachableRule(), DnsFailureRule(), NoInternetRule(),
]


def _facts(failed_layer=None, layers=None, adapters=(), proxy=None):
    return {
        "network.state": {
            "adapters": list(adapters),
            "configurations": [],
            "active": [],
            "proxy": proxy or {"enabled": False, "server": None},
            "layers": layers or [],
            "failed_layer": failed_layer,
        }
    }


def _all_findings(facts):
    out = []
    for rule in ALL_LAYER_RULES:
        out.extend(rule.evaluate(facts))
    return out


# ----------------------------------------------------------------------
# Un solo culpable
# ----------------------------------------------------------------------


class TestLayeredDiagnosis:
    def test_red_sana_no_produce_hallazgos(self):
        assert _all_findings(_facts(failed_layer=None)) == []

    def test_solo_dispara_la_capa_que_fallo(self):
        """Con el cable desconectado tambien falla DNS, gateway e internet.

        Reportar las cuatro cosas es cierto e inutil: la unica accionable
        es la primera.
        """
        findings = _all_findings(_facts(failed_layer="enlace"))
        assert len(findings) == 1
        assert findings[0].rule_id == "NET-002"

    def test_cada_capa_mapea_a_su_regla(self):
        esperado = {
            "adaptador": "NET-001",
            "enlace": "NET-002",
            "direccion": "NET-003",
            "puerta": "NET-004",
            "nombres": "NET-005",
            "salida": "NET-006",
        }
        for layer, rule_id in esperado.items():
            findings = _all_findings(_facts(failed_layer=layer))
            assert len(findings) == 1, layer
            assert findings[0].rule_id == rule_id

    def test_apipa_se_explica_como_dhcp_caido(self):
        layers = [{"layer": "direccion", "ok": False, "detail": "IP: 169.254.10.2",
                   "apipa": ["169.254.10.2"], "addresses": ["169.254.10.2"]}]
        findings = list(NoAddressRule().evaluate(
            _facts(failed_layer="direccion", layers=layers)))
        assert "169.254.10.2" in findings[0].summary
        assert "router no le dio" in findings[0].summary

    def test_adaptador_con_error_de_dispositivo_se_menciona(self):
        adapters = [{"name": "Realtek PCIe GbE", "device_error": 28,
                     "net_enabled": False}]
        findings = list(NoAdapterRule().evaluate(
            _facts(failed_layer="adaptador", adapters=adapters)))
        assert "Realtek" in findings[0].summary
        assert "28" in findings[0].summary

    def test_sin_internet_con_proxy_lo_senala(self):
        proxy = {"enabled": True, "server": "10.0.0.9:8080"}
        findings = list(NoInternetRule().evaluate(
            _facts(failed_layer="salida", proxy=proxy)))
        assert "10.0.0.9:8080" in findings[0].summary
        assert any("proxy" in s.lower() for s in findings[0].remedy.steps)


class TestGhostProxy:
    def test_avisa_si_hay_proxy_aunque_la_red_ande(self):
        proxy = {"enabled": True, "server": "127.0.0.1:1080"}
        findings = list(GhostProxyRule().evaluate(_facts(proxy=proxy)))
        assert len(findings) == 1
        assert findings[0].severity is Severity.INFO

    def test_no_duplica_cuando_ya_fallo_la_salida(self):
        """NET-006 ya menciona el proxy; repetirlo es ruido."""
        proxy = {"enabled": True, "server": "127.0.0.1:1080"}
        facts = _facts(failed_layer="salida", proxy=proxy)
        assert list(GhostProxyRule().evaluate(facts)) == []

    def test_calla_si_no_hay_proxy(self):
        assert list(GhostProxyRule().evaluate(_facts())) == []


# ----------------------------------------------------------------------
# Reportes
# ----------------------------------------------------------------------


def _report(findings=()):
    return ScanReport(
        machine=MachineInfo(hostname="PRUEBA", os_name="Windows 10 Pro",
                            os_build="19045", manufacturer="Dell",
                            model="OptiPlex"),
        started_at=datetime(2026, 8, 11, 15, 30),
        finished_at=datetime(2026, 8, 11, 15, 30, 4),
        findings=list(findings),
    )


def _finding(**kw):
    base = dict(
        rule_id="STO-001", title="Disco fallando", severity=Severity.CRITICAL,
        category=Category.STORAGE, summary="El disco tiene sectores danados.",
        evidence=[Evidence(source="SMART", detail="atributo 5 = 47")],
        remedy=Remedy(explanation="No se repara.", steps=["Respaldar", "Cambiar"]),
    )
    base.update(kw)
    return Finding(**base)


class TestHtmlReport:
    def test_es_autocontenido(self):
        """Se abre en equipos sin internet, que suele ser el caso."""
        out = render_html(_report([_finding()]))
        for forbidden in ("http://", "https://", "<script", "src="):
            assert forbidden not in out, forbidden

    def test_incluye_datos_del_equipo_y_hallazgo(self):
        out = render_html(_report([_finding()]))
        assert "PRUEBA" in out
        assert "Windows 10 Pro" in out
        assert "Disco fallando" in out
        assert "Respaldar" in out
        assert "Inyagui Solutions" in out

    def test_escapa_html_de_la_maquina_analizada(self):
        """Los nombres vienen del equipo ajeno: no son confiables."""
        malicioso = _finding(title="<script>alert(1)</script>")
        out = render_html(_report([malicioso]))
        assert "<script>alert(1)</script>" not in out
        assert "&lt;script&gt;" in out

    def test_escapa_el_nombre_del_equipo(self):
        report = _report([_finding()])
        report.machine.hostname = "<img onerror=x>"
        out = render_html(report)
        assert "<img onerror=x>" not in out

    def test_sin_hallazgos_muestra_mensaje(self):
        out = render_html(_report([]))
        assert "No se detectaron problemas" in out


class TestJsonReport:
    def test_estructura_serializable(self):
        data = to_dict(_report([_finding()]))
        json.dumps(data)          # no debe lanzar
        assert data["schema"] == 1
        assert data["tool"]["vendor"] == "Inyagui Solutions"
        assert data["machine"]["hostname"] == "PRUEBA"
        assert len(data["findings"]) == 1

    def test_incluye_el_remedio(self):
        data = to_dict(_report([_finding()]))
        remedy = data["findings"][0]["remedy"]
        assert remedy["steps"] == ["Respaldar", "Cambiar"]
        assert remedy["automatable"] is False

    def test_no_expone_los_datos_crudos_de_los_colectores(self):
        """Los facts traen seriales, rutas y nombres de red.

        No tienen por que salir de la maquina en el archivo del reporte.
        """
        report = _report([_finding()])
        report.facts["storage.disks"] = {"serial_secreto": "ABC123"}
        assert "ABC123" not in json.dumps(to_dict(report))

    def test_peor_severidad(self):
        data = to_dict(_report([_finding(severity=Severity.WARNING)]))
        assert data["scan"]["worst_severity"] == "WARNING"
