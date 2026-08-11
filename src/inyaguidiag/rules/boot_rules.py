"""Reglas de arranque: por que este equipo no llega al escritorio.

Son las reglas del modo OFFLINE. Se evaluan sobre datos que solo existen
cuando montamos el disco de un equipo averiado desde WinPE, asi que en un
Windows vivo se quedan calladas por si solas: las claves que leen no estan
en `facts` y cada regla devuelve una lista vacia.

CRITERIO DE REDACCION DE LOS REMEDIOS
-------------------------------------
Quien lee esto esta delante de un equipo que no enciende, con una consola
de WinPE abierta y sin Google a mano. Los pasos son ordenes concretas,
copiables tal cual, y usan la letra real del disco montado en vez de un
`X:` generico. El primer paso siempre es verificar la letra: aplicar una
reparacion a la unidad equivocada convierte un equipo averiado en dos.

NINGUNA de estas reglas propone una accion automatizable (`action_id` es
siempre None). El motor de remediacion corre sobre el sistema en vivo; en
modo offline la maquina que ejecuta no es la que hay que reparar, y una
accion automatica que se confunda de disco borraria el equipo del tecnico.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List, Tuple

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

#: Archivos sin los cuales el cargador de Windows no llega ni a mostrar el
#: logotipo. La ausencia de cualquiera de ellos explica por si sola un
#: equipo que no arranca.
_REQUIRED_FILES = (
    ("ntoskrnl.exe", "el nucleo de Windows"),
    ("hal.dll", "la capa de abstraccion del hardware"),
    ("ntdll.dll", "la biblioteca base del sistema"),
    ("smss.exe", "el gestor de sesiones"),
    ("ntfs.sys", "el controlador del sistema de archivos"),
    ("hive-system", "el registro de configuracion (hive SYSTEM)"),
)

#: winload.exe (BIOS) y winload.efi (UEFI) hacen el mismo trabajo en
#: esquemas de arranque distintos. Exigir los dos daria un falso positivo
#: en cualquier equipo antiguo, asi que basta con que exista uno.
_LOADER_ALTERNATIVES = ("winload.exe", "winload.efi")

#: Por debajo de esto Windows no puede crear el archivo de paginacion ni
#: escribir los perfiles de usuario, y el arranque se queda a medias.
_MIN_FREE_BYTES = 500 * 1024 * 1024

#: Una cola de descargas de Windows Update de este tamano significa que
#: hay una actualizacion bajada y sin aplicar.
_HUGE_DOWNLOAD_BYTES = 4 * 1024 * 1024 * 1024


# ----------------------------------------------------------------------
# Acceso a los hechos
# ----------------------------------------------------------------------


def _system(facts: Dict[str, Any]) -> Dict[str, Any]:
    value = facts.get("system.info") or {}
    return value if isinstance(value, dict) else {}


def _volume_letter(facts: Dict[str, Any]) -> str:
    """Letra del disco montado, para escribir remedios copiables.

    Si no hay letra (volumen montado en carpeta, o pruebas), se cae a la
    ruta completa: un comando largo pero correcto es mejor que uno corto
    que apunta a la unidad equivocada.
    """
    info = _system(facts)
    root = info.get("volume_root") or ""
    if not root:
        storage = facts.get("storage.disks") or {}
        if isinstance(storage, dict):
            root = storage.get("volume_root") or ""
    if not root:
        return "D:"
    drive, tail = os.path.splitdrive(root)
    if drive and tail in ("", "\\", "/"):
        return drive
    return root.rstrip("\\/") or "D:"


def _join(volume: str, *parts: str) -> str:
    """Ruta para mostrar en un comando, con la letra del disco montado."""
    base = volume if volume.endswith((":", "\\", "/")) else volume + "\\"
    if base.endswith(":"):
        base += "\\"
    return base + "\\".join(parts)


def _is_broken(entry: Any) -> bool:
    """Un archivo cuenta como roto si no esta o si mide cero bytes.

    El tamano cero importa tanto como la ausencia: un corte de energia en
    plena actualizacion deja entradas de directorio validas apuntando a
    archivos vacios, y el cargador falla igual pero sin decir que falta.

    ABSTENERSE ANTE LA DUDA: `exists is None` significa que no hubo
    permiso para mirar el archivo (ver `_stat_one` en el colector). Eso NO
    es un hallazgo, es una limitacion de cobertura, y confundirlos hacia
    que un Windows sano pero en uso se reportara como destruido.
    """
    if not isinstance(entry, dict):
        return False
    exists = entry.get("exists")
    if exists is None:
        return False
    if not exists:
        return True
    size = entry.get("size_bytes")
    return size is not None and size <= 0


def _is_unknown(entry: Any) -> bool:
    """Si no se pudo determinar el estado del archivo."""
    return isinstance(entry, dict) and entry.get("exists") is None


def _describe(entry: Any) -> str:
    if not isinstance(entry, dict):
        return "?"
    if entry.get("exists") is None:
        return "%s: no se pudo comprobar" % entry.get("path")
    if not entry.get("exists"):
        return "%s: no existe" % entry.get("path")
    return "%s: 0 bytes" % entry.get("path")


# ----------------------------------------------------------------------
# BOT-001
# ----------------------------------------------------------------------


@register_rule
class MissingSystemFilesRule(Rule):
    """Archivos criticos del sistema ausentes o vacios."""

    rule_id = "BOT-001"
    category = Category.BOOT
    requires = ("system.info",)

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        files = _system(facts).get("system_files")
        if not isinstance(files, dict) or not files:
            # Modo online: nadie inventario los archivos de arranque.
            return []

        broken: List[Tuple[str, str]] = []
        for key, description in _REQUIRED_FILES:
            entry = files.get(key)
            if entry is not None and _is_broken(entry):
                broken.append((description, _describe(entry)))

        loaders = [files.get(key) for key in _LOADER_ALTERNATIVES]
        present = [e for e in loaders if isinstance(e, dict) and not _is_broken(e)]
        known = [e for e in loaders if isinstance(e, dict)]
        if known and not present:
            broken.append(
                (
                    "el cargador de arranque (winload)",
                    " y ".join(_describe(e) for e in known),
                )
            )

        if not broken:
            return []

        volume = _volume_letter(facts)
        names = ", ".join(description for description, _ in broken)

        return [
            self.finding(
                title="Faltan archivos esenciales de Windows",
                severity=Severity.CRITICAL,
                summary=(
                    "En el disco montado faltan (o estan vacios) %d archivo(s) "
                    "sin los cuales Windows no puede arrancar: %s. Suele ser "
                    "consecuencia de un apagado durante una actualizacion, de "
                    "sectores danados, o de un antivirus que puso en "
                    "cuarentena un archivo del sistema."
                    % (len(broken), names)
                ),
                evidence=[
                    Evidence(
                        source="disco-montado",
                        detail="%s -- %s" % (description, detail),
                    )
                    for description, detail in broken
                ],
                remedy=_repair_files_remedy(volume),
            )
        ]


def _repair_files_remedy(volume: str) -> Remedy:
    return Remedy(
        explanation=(
            "Windows sabe reponer sus propios archivos si se le apunta al "
            "disco correcto desde el entorno de recuperacion. Solo si eso "
            "falla hay que pensar en reinstalar, y siempre despues de "
            "haber puesto a salvo los datos del usuario."
        ),
        steps=[
            "Confirmar la letra del disco averiado: abrir diskpart, escribir "
            "'list volume' y comprobar que %s es el disco del equipo y no el USB"
            % volume,
            "Reparar los archivos del sistema sin arrancar Windows: "
            "sfc /scannow /offbootdir=%s\\ /offwindir=%s"
            % (volume.rstrip("\\"), _join(volume, "Windows")),
            "Si sfc no lo resuelve: dism /image:%s\\ /cleanup-image /restorehealth"
            % volume.rstrip("\\"),
            "Si el hive SYSTEM es lo que falta, probar la copia de seguridad: "
            "copy %s %s"
            % (
                _join(volume, "Windows", "System32", "config", "RegBack", "SYSTEM"),
                _join(volume, "Windows", "System32", "config", "SYSTEM"),
            ),
            "Antes de reinstalar, copiar %s a un disco externo"
            % _join(volume, "Users"),
        ],
        action_id=None,
        risk=RiskLevel.INVASIVE,
        requires_admin=True,
        requires_reboot=True,
    )


# ----------------------------------------------------------------------
# BOT-002
# ----------------------------------------------------------------------


@register_rule
class MissingBcdRule(Rule):
    """El almacen de configuracion de arranque (BCD) falta o esta vacio."""

    rule_id = "BOT-002"
    category = Category.BOOT
    requires = ("system.info",)

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        boot = _system(facts).get("boot_files")
        if not isinstance(boot, dict):
            return []
        stores = boot.get("bcd")
        if not isinstance(stores, dict) or not stores:
            return []

        healthy = [e for e in stores.values() if isinstance(e, dict) and not _is_broken(e)]
        if healthy:
            return []

        empty = [
            e
            for e in stores.values()
            if isinstance(e, dict) and e.get("exists") and _is_broken(e)
        ]
        volume = _volume_letter(facts)

        if empty:
            # Un archivo presente y de cero bytes es prueba directa: el
            # almacen se corrompio, no es que no lo estemos viendo.
            summary = (
                "El almacen de arranque (BCD) existe pero esta vacio. Sin el, "
                "el equipo no sabe que sistema operativo cargar y se queda en "
                "un error del gestor de arranque."
            )
            confidence = Confidence.CERTAIN
            severity = Severity.CRITICAL
        else:
            # En equipos UEFI el BCD vive en la particion EFI, que casi
            # nunca tiene letra asignada. No verlo NO prueba que falte, y
            # decir lo contrario mandaria al tecnico a reconstruir un
            # almacen que estaba perfectamente.
            summary = (
                "No se encontro el almacen de arranque (BCD) en el disco "
                "montado. Si el equipo es UEFI puede estar en la particion "
                "EFI, que normalmente no tiene letra asignada: hay que "
                "asignarsela y volver a comprobar antes de reconstruir nada."
            )
            confidence = Confidence.LIKELY
            # ADVERTENCIA y no CRITICO a proposito. En un equipo UEFI sano
            # el BCD vive en la particion EFI, que casi nunca tiene letra
            # asignada, asi que este caso se da SIEMPRE al analizar un UEFI
            # offline. Un critico que salta en todas las maquinas sanas no
            # informa: entrena al tecnico a ignorar los criticos, y el dia
            # que uno sea real va a pasar de largo.
            severity = Severity.WARNING

        return [
            self.finding(
                title="El almacen de arranque (BCD) no esta disponible",
                severity=severity,
                summary=summary,
                evidence=[
                    Evidence(
                        source="disco-montado",
                        detail="%s -> %s" % (scheme, _describe(entry)),
                        data={"scheme": scheme},
                    )
                    for scheme, entry in sorted(stores.items())
                    if isinstance(entry, dict)
                ],
                remedy=_rebuild_bcd_remedy(volume),
                confidence=confidence,
            )
        ]


def _rebuild_bcd_remedy(volume: str) -> Remedy:
    letter = volume.rstrip("\\")
    return Remedy(
        explanation=(
            "El BCD es la lista de sistemas que el equipo puede arrancar. "
            "No contiene datos del usuario: se puede reconstruir entero sin "
            "perder nada. Lo unico que hay que acertar es el esquema, BIOS "
            "o UEFI, porque el comando cambia."
        ),
        steps=[
            "Averiguar si el equipo es UEFI: en diskpart, 'list disk'. Un "
            "asterisco en la columna GPT significa UEFI",
            "Solo en UEFI: dar letra a la particion EFI desde diskpart "
            "(select disk 0 / list partition / select partition N / "
            "assign letter=S) y revisar si el BCD ya estaba ahi",
            "Buscar instalaciones y rehacer el almacen: bootrec /rebuildbcd",
            "Si no encuentra ninguna, generarlo a mano en UEFI: "
            "bcdboot %s /s S: /f UEFI" % _join(volume, "Windows"),
            "En BIOS/MBR en cambio: bcdboot %s /s %s /f BIOS, y despues "
            "bootrec /fixmbr y bootrec /fixboot" % (_join(volume, "Windows"), letter),
            "Reiniciar y comprobar en la BIOS que el orden de arranque "
            "apunta a este disco",
        ],
        action_id=None,
        risk=RiskLevel.INVASIVE,
        requires_admin=True,
        requires_reboot=True,
    )


# ----------------------------------------------------------------------
# BOT-003
# ----------------------------------------------------------------------


@register_rule
class InterruptedUpdateRule(Rule):
    """Actualizacion de Windows aplicada a medias."""

    rule_id = "BOT-003"
    category = Category.BOOT
    requires = ("system.info",)

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        info = _system(facts)
        pending = info.get("pending_update")
        if not isinstance(pending, dict) or not pending:
            return []

        evidence: List[Evidence] = []
        severity = Severity.INFO
        confirmed = False

        for key in ("pending_xml", "pending_xml_config"):
            entry = pending.get(key)
            if isinstance(entry, dict) and entry.get("exists"):
                confirmed = True
                severity = Severity.CRITICAL
                evidence.append(
                    Evidence(
                        source="disco-montado",
                        detail="pending.xml presente: %s" % entry.get("path"),
                        data={"marker": key},
                    )
                )

        winre = pending.get("winre_agent")
        if isinstance(winre, dict) and winre.get("exists"):
            confirmed = True
            severity = max(severity, Severity.WARNING)
            evidence.append(
                Evidence(
                    source="disco-montado",
                    detail="carpeta $WinREAgent presente: %s" % winre.get("path"),
                    data={"marker": "winre_agent"},
                )
            )

        download = pending.get("software_distribution_download")
        if isinstance(download, dict) and download.get("exists"):
            size = download.get("size_bytes") or 0
            if size >= _HUGE_DOWNLOAD_BYTES:
                confirmed = True
                severity = max(severity, Severity.WARNING)
                evidence.append(
                    Evidence(
                        source="disco-montado",
                        detail="cola de Windows Update de %.1f GB en %s%s"
                        % (
                            size / (1024.0 ** 3),
                            download.get("path"),
                            " (medida parcial)" if download.get("truncated") else "",
                        ),
                        data={"size_bytes": size},
                    )
                )

        setup_flag = info.get("setup_in_progress")
        if setup_flag not in (None, 0, "0"):
            confirmed = True
            severity = max(severity, Severity.WARNING)
            evidence.append(
                Evidence(
                    source="registro-offline",
                    detail="SYSTEM\\Setup\\SystemSetupInProgress = %s" % setup_flag,
                )
            )

        # Windows.old por si sola es normal despues de una actualizacion
        # correcta. Solo se suma como contexto cuando ya hay otra senal:
        # si no, todo equipo actualizado en los ultimos diez dias saldria
        # marcado y la regla dejaria de significar nada.
        windows_old = pending.get("windows_old")
        if confirmed and isinstance(windows_old, dict) and windows_old.get("exists"):
            evidence.append(
                Evidence(
                    source="disco-montado",
                    detail="carpeta Windows.old presente: %s" % windows_old.get("path"),
                    data={"marker": "windows_old"},
                )
            )

        if not confirmed:
            return []

        volume = _volume_letter(facts)
        return [
            self.finding(
                title="Actualizacion de Windows a medio aplicar",
                severity=severity,
                summary=(
                    "El disco tiene marcas de una actualizacion que empezo y "
                    "no termino. Es la causa tipica del equipo que se queda "
                    "en 'Deshaciendo los cambios' o que reinicia en bucle: "
                    "Windows intenta completar la operacion en cada arranque "
                    "y vuelve a fallar."
                ),
                evidence=evidence,
                remedy=_interrupted_update_remedy(volume),
                confidence=Confidence.LIKELY,
            )
        ]


def _interrupted_update_remedy(volume: str) -> Remedy:
    return Remedy(
        explanation=(
            "Windows guarda en disco la lista de cambios pendientes y la "
            "reintenta en cada arranque. Si uno de esos cambios es el que "
            "rompe el arranque, el equipo entra en bucle. Quitar la cola "
            "corta el bucle; la actualizacion se puede volver a instalar "
            "despues, ya con el equipo encendido."
        ),
        steps=[
            "Primero, lo barato: encender y dejarlo intentar dos o tres "
            "arranques completos. Muchas actualizaciones terminan de "
            "deshacerse solas",
            "Si sigue en bucle, desde WinPE renombrar la cola de cambios: "
            "ren %s pending.xml.old"
            % _join(volume, "Windows", "WinSxS", "pending.xml"),
            "Vaciar las descargas de Windows Update: rd /s /q %s"
            % _join(volume, "Windows", "SoftwareDistribution", "Download"),
            "Arrancar el equipo y, si entra, ejecutar el solucionador de "
            "problemas de Windows Update antes de volver a actualizar",
            "Si existe %s, ahi estan los archivos del usuario y la "
            "instalacion anterior: respaldarlos antes de tocar nada mas"
            % _join(volume, "Windows.old"),
        ],
        action_id=None,
        risk=RiskLevel.INVASIVE,
        requires_admin=True,
        requires_reboot=True,
    )


# ----------------------------------------------------------------------
# BOT-004
# ----------------------------------------------------------------------


@register_rule
class DiskFullPreventingBootRule(Rule):
    """El volumen del sistema esta tan lleno que Windows no puede arrancar.

    Se solapa a proposito con STO-002, que avisa por porcentaje libre. Un
    disco de 4 TB al 3% tiene 120 GB y arranca perfectamente; un disco de
    120 GB al 1% tiene 1,2 GB y tampoco impide arrancar. Lo que impide
    arrancar es un valor ABSOLUTO, y esa es la comprobacion que hace falta
    delante de un equipo que no enciende.
    """

    rule_id = "BOT-004"
    category = Category.BOOT
    requires = ("storage.disks",)

    def evaluate(self, facts: Dict[str, Any]) -> Iterable[Finding]:
        storage = facts.get("storage.disks") or {}
        if not isinstance(storage, dict):
            return []

        findings: List[Finding] = []
        for volume in storage.get("volumes") or []:
            if not isinstance(volume, dict):
                continue
            # Sin esta marca no sabemos si el volumen es el del sistema, y
            # avisar de un disco de datos lleno no explica por que no
            # arranca. La produce el colector offline.
            if not volume.get("is_system_volume"):
                continue
            free = volume.get("free_bytes")
            if not isinstance(free, int) or free >= _MIN_FREE_BYTES:
                continue

            finding = self._build(volume, free, facts)
            finding.related = ["STO-002"]
            findings.append(finding)
        return findings

    def _build(
        self, volume: Dict[str, Any], free: int, facts: Dict[str, Any]
    ) -> Finding:
        device = volume.get("device") or "?"
        free_mb = free / (1024.0 ** 2)

        evidence = [
            Evidence(
                source="disco-montado",
                detail="%s: %.0f MB libres (minimo necesario %d MB)"
                % (device, free_mb, _MIN_FREE_BYTES // (1024 * 1024)),
                data={"device": device, "free_bytes": free},
            )
        ]
        evidence.extend(_reclaimable_evidence(volume, facts))

        return self.finding(
            title="Disco lleno: el sistema no tiene espacio para arrancar",
            severity=Severity.CRITICAL,
            summary=(
                "Al volumen del sistema le quedan %.0f MB libres. Windows "
                "necesita espacio para el archivo de paginacion, los perfiles "
                "de usuario y los archivos temporales; sin el, el arranque se "
                "queda a mitad o vuelve a la pantalla de inicio de sesion una "
                "y otra vez." % free_mb
            ),
            evidence=evidence,
            remedy=_free_space_remedy(_volume_letter(facts), _reclaimable(volume, facts)),
        )


def _reclaimable(volume: Dict[str, Any], facts: Dict[str, Any]) -> List[Tuple[str, int]]:
    """Los bultos grandes que se pueden borrar desde WinPE, mayor primero.

    Enumerarlos con su tamano evita el consejo inutil de "libera espacio":
    el tecnico ve de entrada que borrando hiberfil.sys recupera 6 GB.
    """
    items: List[Tuple[str, int]] = []

    integrity = volume.get("integrity")
    if isinstance(integrity, dict):
        for key, label in (("hiberfil", "hiberfil.sys"), ("pagefile", "pagefile.sys")):
            entry = integrity.get(key)
            if isinstance(entry, dict) and entry.get("exists"):
                size = entry.get("size_bytes") or 0
                if size > 0:
                    items.append((label, size))

    pending = _system(facts).get("pending_update")
    if isinstance(pending, dict):
        download = pending.get("software_distribution_download")
        if isinstance(download, dict) and download.get("exists"):
            size = download.get("size_bytes") or 0
            if size > 0:
                items.append(("SoftwareDistribution\\Download", size))

    items.sort(key=lambda pair: -pair[1])
    return items


def _reclaimable_evidence(
    volume: Dict[str, Any], facts: Dict[str, Any]
) -> List[Evidence]:
    return [
        Evidence(
            source="disco-montado",
            detail="%s ocupa %.1f GB y se puede liberar" % (name, size / (1024.0 ** 3)),
            data={"item": name, "size_bytes": size},
        )
        for name, size in _reclaimable(volume, facts)
    ]


def _free_space_remedy(volume: str, items: List[Tuple[str, int]]) -> Remedy:
    steps = [
        "Confirmar en diskpart ('list volume') que %s es el disco del equipo "
        "averiado y no el USB de rescate" % volume,
    ]
    for name, _size in items:
        if name == "hiberfil.sys":
            steps.append(
                "Borrar el archivo de hibernacion, Windows lo recrea solo: "
                "del /f /a:h %s" % _join(volume, "hiberfil.sys")
            )
        elif name == "pagefile.sys":
            steps.append(
                "Borrar el archivo de paginacion, Windows lo recrea al "
                "arrancar: del /f /a:h %s" % _join(volume, "pagefile.sys")
            )
        else:
            steps.append(
                "Vaciar la cache de Windows Update: rd /s /q %s"
                % _join(volume, "Windows", "SoftwareDistribution", "Download")
            )

    steps.extend(
        [
            "Vaciar los temporales del sistema: rd /s /q %s"
            % _join(volume, "Windows", "Temp"),
            "Si existe %s y ya no hace falta volver a la version anterior, "
            "borrarla" % _join(volume, "Windows.old"),
            "No dar por bueno el arreglo hasta tener al menos 2 GB libres",
            "Con el equipo ya arrancado, revisar que ocupa el disco y mover "
            "fotos y videos a un disco externo",
        ]
    )

    return Remedy(
        explanation=(
            "Un disco de sistema sin espacio no es un problema de "
            "rendimiento: es un problema de arranque. Windows aborta el "
            "inicio de sesion si no puede escribir el perfil del usuario. "
            "Se arregla borrando archivos que el propio Windows regenera."
        ),
        steps=steps,
        action_id=None,
        risk=RiskLevel.MODERATE,
        requires_admin=True,
    )
