"""Reglas de red.

PRINCIPIO DE DISENO: UN SOLO CULPABLE
------------------------------------
Cuando no hay cable conectado, tambien falla el DHCP, tambien falla el
gateway, tambien falla el DNS y tambien falla internet. Un reporte que
liste las cinco cosas es tecnicamente cierto e inutil: sepulta la causa
bajo sus consecuencias.

El colector ya identifico el PRIMER peldano roto (`failed_layer`). Estas
reglas emiten un unico hallazgo por ese peldano y callan sobre el resto.

Cada capa rota tiene su propia regla para que el id sea estable y
buscable, pero solo dispara la que corresponde.
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


def _state(facts: Dict[str, Any]) -> Dict[str, Any]:
    return facts["network.state"]


def _layer(facts: Dict[str, Any], name: str) -> Optional[Dict[str, Any]]:
    for entry in _state(facts).get("layers", []):
        if entry.get("layer") == name:
            return entry
    return None


class _LayerRule(Rule):
    """Base de las reglas de capa: solo actua si SU capa es la que fallo."""

    abstract = True          # agrupa logica comun; no es una regla en si
    layer = ""
    requires = ("network.state",)
    category = Category.NETWORK

    def applies(self, facts: Dict[str, Any]) -> bool:
        return _state(facts).get("failed_layer") == self.layer

    def _evidence(self, facts: Dict[str, Any]) -> List[Evidence]:
        entry = _layer(facts, self.layer) or {}
        return [
            Evidence(
                source="diagnostico-red",
                detail="Capa '%s': %s" % (self.layer, entry.get("detail", "?")),
                data={k: v for k, v in entry.items() if k != "detail"},
            )
        ]


# ----------------------------------------------------------------------


@register_rule
class NoAdapterRule(_LayerRule):
    """Sin tarjeta de red utilizable."""

    rule_id = "NET-001"
    layer = "adaptador"
    category = Category.DRIVERS

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        if not self.applies(facts):
            return []

        broken = [
            a for a in _state(facts).get("adapters", [])
            if a.get("device_error")
        ]
        detail = ""
        if broken:
            names = ", ".join(str(a.get("name")) for a in broken[:3])
            codes = ", ".join(str(a.get("device_error")) for a in broken[:3])
            detail = (
                " Hay adaptadores con error de dispositivo (%s), codigo %s."
                % (names, codes)
            )

        return [
            self.finding(
                title="No hay ninguna tarjeta de red disponible",
                severity=Severity.CRITICAL,
                summary=(
                    "El equipo no tiene ningun adaptador de red fisico "
                    "habilitado.%s Sin esto no hay conexion posible, ni por "
                    "cable ni por WiFi." % detail
                ),
                evidence=self._evidence(facts),
                remedy=Remedy(
                    explanation=(
                        "O la tarjeta esta deshabilitada, o su controlador "
                        "no esta instalado o fallo. Es lo primero que hay "
                        "que resolver: todo lo demas depende de esto."
                    ),
                    steps=[
                        "Abrir el Administrador de dispositivos",
                        "Buscar 'Adaptadores de red' y ver si hay algo con "
                        "signo de admiracion amarillo",
                        "Si esta deshabilitado, habilitarlo con clic derecho",
                        "Si falta el controlador, instalarlo desde la web del "
                        "fabricante del equipo (hara falta otra computadora "
                        "para descargarlo)",
                        "En portatiles, verificar que el WiFi no este apagado "
                        "por el interruptor fisico o por Fn+tecla",
                    ],
                    risk=RiskLevel.MODERATE,
                ),
            )
        ]


@register_rule
class NoLinkRule(_LayerRule):
    """Hay tarjeta pero sin enlace fisico."""

    rule_id = "NET-002"
    layer = "enlace"

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        if not self.applies(facts):
            return []
        return [
            self.finding(
                title="La tarjeta de red no tiene conexion",
                severity=Severity.CRITICAL,
                summary=(
                    "Hay adaptador de red funcionando, pero ninguno esta "
                    "conectado: no hay cable enchufado o no hay WiFi asociado."
                ),
                evidence=self._evidence(facts),
                remedy=Remedy(
                    explanation=(
                        "El sistema esta bien; falta el medio fisico. Es el "
                        "problema mas comun y el mas facil de descartar."
                    ),
                    steps=[
                        "Verificar que el cable de red este bien enchufado en "
                        "ambos extremos y que la lucecita del puerto encienda",
                        "Probar con otro cable de red",
                        "Si es WiFi, comprobar que este conectado a una red",
                        "Verificar que el router este encendido",
                    ],
                    risk=RiskLevel.SAFE,
                ),
            )
        ]


@register_rule
class NoAddressRule(_LayerRule):
    """Sin direccion IP valida. Casi siempre DHCP."""

    rule_id = "NET-003"
    layer = "direccion"

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        if not self.applies(facts):
            return []

        entry = _layer(facts, "direccion") or {}
        apipa = entry.get("apipa") or []

        if apipa:
            summary = (
                "El equipo se auto-asigno la direccion %s porque el router "
                "no le dio una. Ese rango (169.254.x.x) no sirve para salir "
                "a ningun lado." % apipa[0]
            )
            explanation = (
                "Cuando el servidor DHCP no responde, Windows se inventa una "
                "direccion para no quedarse sin nada. Es una senal inequivoca "
                "de que el router no esta repartiendo direcciones."
            )
        else:
            summary = (
                "El adaptador esta conectado pero no tiene ninguna direccion "
                "IP utilizable."
            )
            explanation = (
                "Sin direccion IP el equipo no puede comunicarse, aunque el "
                "cable este bien."
            )

        return [
            self.finding(
                title="Sin direccion IP valida",
                severity=Severity.CRITICAL,
                summary=summary,
                evidence=self._evidence(facts),
                remedy=Remedy(
                    explanation=explanation,
                    steps=[
                        "Reiniciar el router y esperar dos minutos",
                        "Renovar la direccion: ipconfig /release y luego "
                        "ipconfig /renew",
                        "Verificar que el adaptador este en 'Obtener IP "
                        "automaticamente' y no con una IP fija vieja",
                        "Si hay varios equipos con el mismo problema, el "
                        "router es el culpable",
                    ],
                    action_id="renew-dhcp",
                    risk=RiskLevel.MODERATE,
                    requires_admin=True,
                ),
            )
        ]


@register_rule
class GatewayUnreachableRule(_LayerRule):
    """Hay IP pero el router no responde."""

    rule_id = "NET-004"
    layer = "puerta"

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        if not self.applies(facts):
            return []

        entry = _layer(facts, "puerta") or {}
        gateways = entry.get("gateways") or []

        if not gateways:
            summary = (
                "El equipo tiene direccion IP pero no tiene configurada "
                "ninguna puerta de enlace, asi que no sabe por donde salir "
                "de la red local."
            )
        else:
            summary = (
                "El equipo tiene direccion IP, pero la puerta de enlace (%s) "
                "no responde. Se llega hasta la red local y ahi se corta."
                % ", ".join(gateways)
            )

        return [
            self.finding(
                title="El router no responde",
                severity=Severity.CRITICAL,
                summary=summary,
                evidence=self._evidence(facts),
                remedy=Remedy(
                    explanation=(
                        "La puerta de enlace es el router. Si no contesta, o "
                        "esta caido, o la direccion configurada es incorrecta, "
                        "o algo bloquea el trafico en la red local."
                    ),
                    steps=[
                        "Reiniciar el router",
                        "Comprobar si otros equipos de la misma red navegan",
                        "Revisar que no haya una IP fija mal configurada",
                        "Desactivar temporalmente el firewall de terceros para "
                        "descartarlo",
                    ],
                    risk=RiskLevel.MODERATE,
                ),
            )
        ]


@register_rule
class DnsFailureRule(_LayerRule):
    """Se llega a internet pero los nombres no resuelven."""

    rule_id = "NET-005"
    layer = "nombres"

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        if not self.applies(facts):
            return []

        entry = _layer(facts, "nombres") or {}
        servers = entry.get("servers") or []

        return [
            self.finding(
                title="El DNS no resuelve nombres",
                severity=Severity.CRITICAL,
                summary=(
                    "La conexion llega al router y hasta internet, pero los "
                    "nombres de sitios no se traducen a direcciones. Sintoma "
                    "tipico: las paginas no cargan pero el ping por IP si "
                    "funciona. Servidores configurados: %s."
                    % (", ".join(servers) if servers else "ninguno")
                ),
                evidence=self._evidence(facts),
                remedy=Remedy(
                    explanation=(
                        "El DNS es la agenda telefonica de internet. Sin el, "
                        "el equipo sabe llegar pero no sabe a donde. Es de los "
                        "problemas que mas asustan y mas rapido se arreglan."
                    ),
                    steps=[
                        "Cambiar los servidores DNS a 1.1.1.1 y 8.8.8.8",
                        "Vaciar la cache: ipconfig /flushdns",
                        "Si funciona con los DNS nuevos, el del proveedor "
                        "estaba caido",
                    ],
                    action_id="set-public-dns",
                    risk=RiskLevel.MODERATE,
                    requires_admin=True,
                ),
                confidence=Confidence.CERTAIN,
            )
        ]


@register_rule
class NoInternetRule(_LayerRule):
    """Todo bien en la red local pero no se sale a internet."""

    rule_id = "NET-006"
    layer = "salida"

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        if not self.applies(facts):
            return []

        proxy = _state(facts).get("proxy") or {}
        proxy_note = ""
        if proxy.get("enabled"):
            proxy_note = (
                " ATENCION: hay un proxy configurado (%s). Un proxy que ya no "
                "existe es causa clasica de este sintoma."
                % (proxy.get("server") or "sin direccion")
            )

        return [
            self.finding(
                title="Red local funcionando pero sin internet",
                severity=Severity.CRITICAL,
                summary=(
                    "El equipo se comunica bien con el router, pero no logra "
                    "salir a internet.%s" % proxy_note
                ),
                evidence=self._evidence(facts),
                remedy=Remedy(
                    explanation=(
                        "La red interna esta sana; el corte esta del router "
                        "hacia afuera, o en algo del equipo que bloquea la "
                        "salida (proxy, firewall, VPN a medio desinstalar)."
                    ),
                    steps=(
                        ["Quitar el proxy: Configuracion > Red > Proxy, "
                         "desactivar 'Usar servidor proxy'"]
                        if proxy.get("enabled") else []
                    ) + [
                        "Comprobar si otros equipos de la red si navegan",
                        "Si ninguno navega, el problema es del proveedor",
                        "Reiniciar el modem y el router",
                        "Reparar la pila de red: netsh winsock reset "
                        "(requiere reiniciar)",
                        "Revisar si un antivirus o VPN esta bloqueando",
                    ],
                    action_id="reset-winsock",
                    risk=RiskLevel.INVASIVE,
                    requires_admin=True,
                    requires_reboot=True,
                ),
            )
        ]


# ----------------------------------------------------------------------


@register_rule
class GhostProxyRule(Rule):
    """Proxy configurado aunque la red funcione.

    No es una regla de capa: avisa aunque todo lo demas ande, porque un
    proxy olvidado rompe la navegacion de forma intermitente y confusa.
    """

    rule_id = "NET-007"
    category = Category.NETWORK
    requires = ("network.state",)

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        state = _state(facts)
        proxy = state.get("proxy") or {}

        # Si ya fallo la salida, NET-006 lo menciona; no duplicar.
        if not proxy.get("enabled") or state.get("failed_layer") == "salida":
            return []

        return [
            self.finding(
                title="Hay un proxy configurado",
                severity=Severity.INFO,
                summary=(
                    "El equipo tiene configurado el proxy '%s'. Ahora mismo "
                    "la red funciona, pero si ese proxy deja de existir la "
                    "navegacion se cortara sin explicacion aparente."
                    % (proxy.get("server") or "sin direccion")
                ),
                evidence=[
                    Evidence(
                        source="registro:Internet Settings",
                        detail="ProxyEnable=1, ProxyServer=%s"
                        % (proxy.get("server") or "?"),
                    )
                ],
                remedy=Remedy(
                    explanation=(
                        "Los proxys quedan configurados por programas que se "
                        "desinstalaron mal, o por adware. Si no sabes que hace "
                        "ahi, probablemente no deberia estar."
                    ),
                    steps=[
                        "Configuracion > Red e Internet > Proxy",
                        "Si no lo pusiste a proposito (o no es de tu trabajo), "
                        "desactivarlo",
                    ],
                    risk=RiskLevel.SAFE,
                ),
                confidence=Confidence.POSSIBLE,
            )
        ]
