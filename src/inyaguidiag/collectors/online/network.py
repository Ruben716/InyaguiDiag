"""Colector de red: configuracion y pruebas de conectividad por capas.

IDEA CENTRAL
------------
"No tengo internet" no es un diagnostico, es un sintoma con seis causas
posibles. Este colector prueba la conectividad como una escalera y anota
en que peldano se rompe:

    1. adaptador   -> hay tarjeta de red y su controlador funciona
    2. enlace      -> hay cable conectado o WiFi asociado
    3. direccion   -> el equipo tiene IP valida (no APIPA)
    4. puerta      -> el router responde
    5. nombres     -> el DNS resuelve
    6. salida      -> se llega a internet

Cada peldano solo se prueba si el anterior paso. No tiene sentido probar
DNS cuando no hay cable: fallaria igual y ensuciaria el diagnostico con
sintomas derivados.

NOTA: este colector hace trafico de red real (ping al gateway, consulta
DNS, conexion TCP saliente). Es inherente a lo que mide. Se salta entero
con --quick.
"""

from __future__ import annotations

import logging
import socket
from typing import Any, Dict, List, Optional

from ...core.context import ScanContext, ScanMode
from ...core.registry import register_collector
from ...winapi import wmi_bridge
from ..base import Collector

log = logging.getLogger(__name__)

# Rango de auto-configuracion (APIPA). Si el equipo tiene una de estas,
# el servidor DHCP no respondio y se la asigno solo.
APIPA_PREFIX = "169.254."

# Objetivos de prueba. Se eligen direcciones IP literales para el paso 6
# de modo que NO dependa del DNS: asi se distingue "no hay internet" de
# "el DNS no resuelve", que son problemas distintos con arreglos distintos.
INTERNET_TARGETS = (("1.1.1.1", 443), ("8.8.8.8", 53))
DNS_TEST_NAMES = ("www.msftconnecttest.com", "cloudflare.com")

TIMEOUT = 3.0


@register_collector
class NetworkCollector(Collector):
    """Configuracion de red y diagnostico de conectividad escalonado."""

    name = "network"
    provides = "network.state"
    supported_modes = (ScanMode.ONLINE,)
    cost = 4

    def collect(self, ctx: ScanContext) -> Dict[str, Any]:
        adapters = self._adapters()
        configs = self._configurations()
        active = [c for c in configs if c.get("ip_addresses")]

        state: Dict[str, Any] = {
            "adapters": adapters,
            "configurations": configs,
            "active": active,
            "proxy": self._proxy(),
        }

        # La escalera. `failed_layer` es el resultado que consumen las
        # reglas: el PRIMER peldano roto, o None si todo paso.
        layers: List[Dict[str, Any]] = []
        state["layers"] = layers
        state["failed_layer"] = None

        def step(name: str, ok: bool, detail: str, **extra: Any) -> bool:
            layers.append(dict(layer=name, ok=ok, detail=detail, **extra))
            if not ok and state["failed_layer"] is None:
                state["failed_layer"] = name
            return ok

        # 1 -- adaptador
        usable = [a for a in adapters if a.get("net_enabled")]
        if not step(
            "adaptador",
            bool(usable),
            "%d adaptador(es) de red habilitado(s)" % len(usable),
            count=len(usable),
        ):
            return state

        # 2 -- enlace
        connected = [a for a in adapters if a.get("connected")]
        if not step(
            "enlace",
            bool(connected),
            "%d adaptador(es) con enlace activo" % len(connected),
            count=len(connected),
        ):
            return state

        # 3 -- direccion
        addresses = [ip for c in active for ip in c.get("ip_addresses", [])]
        apipa = [ip for ip in addresses if ip.startswith(APIPA_PREFIX)]
        routable = [
            ip for ip in addresses
            if not ip.startswith(APIPA_PREFIX) and not ip.startswith("127.")
        ]
        if not step(
            "direccion",
            bool(routable),
            "IP: %s" % (", ".join(addresses) if addresses else "ninguna"),
            addresses=addresses,
            apipa=apipa,
        ):
            return state

        # 4 -- puerta de enlace
        gateways = sorted({
            g for c in active for g in (c.get("gateways") or []) if g
        })
        gateway_ok = False
        gateway_detail = "sin puerta de enlace configurada"
        if gateways:
            gateway_ok = any(self._ping(g) for g in gateways)
            gateway_detail = "puerta de enlace %s: %s" % (
                ", ".join(gateways), "responde" if gateway_ok else "no responde"
            )
        if not step("puerta", gateway_ok, gateway_detail, gateways=gateways):
            return state

        # 6 antes que 5 a proposito: probar la salida con IP literal
        # permite separar "sin internet" de "DNS caido".
        internet_ok = any(self._tcp(host, port) for host, port in INTERNET_TARGETS)

        # 5 -- nombres
        servers = sorted({
            s for c in active for s in (c.get("dns_servers") or []) if s
        })
        resolved = self._resolve_any(DNS_TEST_NAMES)
        step(
            "nombres",
            resolved is not None,
            "DNS %s: %s" % (
                ", ".join(servers) if servers else "sin servidores",
                "resuelve" if resolved else "no resuelve",
            ),
            servers=servers,
            resolved=resolved,
        )

        # 7 -- salida
        step(
            "salida",
            internet_ok,
            "conexion saliente a internet: %s" % ("ok" if internet_ok else "falla"),
        )

        return state

    # ------------------------------------------------------------------
    # Inventario
    # ------------------------------------------------------------------

    @staticmethod
    def _adapters() -> List[Dict[str, Any]]:
        rows = wmi_bridge.query(
            "Win32_NetworkAdapter",
            ("Index", "Name", "NetConnectionID", "NetConnectionStatus",
             "NetEnabled", "PhysicalAdapter", "MACAddress", "Speed",
             "ConfigManagerErrorCode"),
        )
        adapters = []
        for row in rows:
            # Solo tarjetas fisicas: los adaptadores virtuales de VPN,
            # VirtualBox y similares ensucian el diagnostico.
            if not _as_bool(row.get("PhysicalAdapter")):
                continue
            if not row.get("MACAddress"):
                continue
            status = _as_int(row.get("NetConnectionStatus"))
            error = _as_int(row.get("ConfigManagerErrorCode"))
            adapters.append({
                "index": _as_int(row.get("Index")),
                "name": row.get("Name"),
                "connection_name": row.get("NetConnectionID"),
                "status_code": status,
                "connected": status == 2,       # 2 = Connected
                "net_enabled": _as_bool(row.get("NetEnabled")),
                "mac": row.get("MACAddress"),
                "speed_bps": _as_int(row.get("Speed")),
                "device_error": error if error else None,
            })
        return adapters

    @staticmethod
    def _configurations() -> List[Dict[str, Any]]:
        rows = wmi_bridge.query(
            "Win32_NetworkAdapterConfiguration",
            ("Index", "Description", "IPAddress", "DefaultIPGateway",
             "DNSServerSearchOrder", "DHCPEnabled", "DHCPServer",
             "IPEnabled", "MACAddress"),
        )
        configs = []
        for row in rows:
            if not _as_bool(row.get("IPEnabled")):
                continue
            configs.append({
                "index": _as_int(row.get("Index")),
                "description": row.get("Description"),
                "ip_addresses": _as_list(row.get("IPAddress")),
                "gateways": _as_list(row.get("DefaultIPGateway")),
                "dns_servers": _as_list(row.get("DNSServerSearchOrder")),
                "dhcp_enabled": _as_bool(row.get("DHCPEnabled")),
                "dhcp_server": row.get("DHCPServer"),
                "mac": row.get("MACAddress"),
            })
        return configs

    @staticmethod
    def _proxy() -> Dict[str, Any]:
        """Proxy de WinHTTP. Un proxy fantasma es causa clasica de
        'tengo red pero no navego' que nadie mira."""
        try:
            import winreg

            key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
                enabled = _read_reg(handle, "ProxyEnable")
                server = _read_reg(handle, "ProxyServer")
            return {"enabled": bool(enabled), "server": server}
        except Exception:  # noqa: BLE001
            return {"enabled": None, "server": None}

    # ------------------------------------------------------------------
    # Pruebas
    # ------------------------------------------------------------------

    @staticmethod
    def _ping(address: str) -> bool:
        """ICMP real via Win32_PingStatus.

        Se usa WMI en vez de sockets crudos porque el ICMP por socket
        exige privilegios de administrador en Windows, y esta herramienta
        tiene que servir corriendo como usuario normal.

        Si WMI no responde se cae a un sondeo TCP: un router que acepta
        conexion en cualquier puerto habitual esta vivo, aunque no sea
        equivalente a un ping (hay routers que no abren ningun puerto).
        """
        if not _is_ip(address):
            return False
        rows = wmi_bridge.query(
            "Win32_PingStatus",
            ("StatusCode", "ResponseTime"),
            where="Address='%s' AND Timeout=2000" % address,
        )
        if rows:
            return _as_int(rows[0].get("StatusCode")) == 0

        for port in (80, 443, 53, 8080):
            if NetworkCollector._tcp(address, port, timeout=1.0):
                return True
        return False

    @staticmethod
    def _tcp(host: str, port: int, timeout: float = TIMEOUT) -> bool:
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            return True
        except (socket.timeout, OSError):
            return False
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    @staticmethod
    def _resolve_any(names: tuple) -> Optional[str]:
        for name in names:
            try:
                socket.setdefaulttimeout(TIMEOUT)
                return socket.gethostbyname(name)
            except (socket.gaierror, socket.timeout, OSError):
                continue
            finally:
                socket.setdefaulttimeout(None)
        return None


# ----------------------------------------------------------------------


def _as_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("true", "1", "yes")


def _is_ip(text: str) -> bool:
    """Valida IPv4 antes de meterla en un WHERE de WQL.

    No es cosmetico: la direccion viene de la configuracion del sistema y
    se concatena en una consulta. Validarla cierra la puerta a que un
    valor raro rompa o altere la consulta.
    """
    parts = str(text).split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True


def _as_list(value: Any) -> List[str]:
    """WMI devuelve arreglos o un escalar segun el backend."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v]
    text = str(value).strip()
    return [text] if text else []


def _read_reg(handle: Any, name: str) -> Any:
    import winreg

    try:
        return winreg.QueryValueEx(handle, name)[0]
    except OSError:
        return None
