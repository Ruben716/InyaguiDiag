"""Pruebas del modo OFFLINE: deteccion, colectores y reglas BOT.

No hace falta un disco averiado de verdad. Se fabrica un arbol de archivos
falso con `tmp_path` que imita la estructura minima de un Windows
instalado, y los colectores lo recorren igual que recorrerian el disco
montado de un equipo que no arranca.

Que esto sea posible es consecuencia directa de dos decisiones de diseno:
`ScanContext` abstrae la raiz (nada dice `C:\\`), y los colectores derivan
la raiz del volumen del padre de la carpeta Windows en vez de la letra de
unidad.
"""

from __future__ import annotations

import os

import pytest

from inyaguidiag.collectors.offline.storage import OfflineStorageCollector
from inyaguidiag.collectors.offline.system import (
    OfflineSystemInfoCollector,
    volume_root_of,
)
from inyaguidiag.core import discovery
from inyaguidiag.core.context import ScanContext, ScanMode
from inyaguidiag.core.models import Confidence, Severity
from inyaguidiag.rules.boot_rules import (
    DiskFullPreventingBootRule,
    InterruptedUpdateRule,
    MissingBcdRule,
    MissingSystemFilesRule,
)

# Archivos que un Windows sano tiene y que las reglas BOT vigilan.
_SANE_FILES = (
    "Windows/System32/ntoskrnl.exe",
    "Windows/System32/hal.dll",
    "Windows/System32/ntdll.dll",
    "Windows/System32/smss.exe",
    "Windows/System32/winload.exe",
    "Windows/System32/winload.efi",
    "Windows/System32/drivers/ntfs.sys",
    "Windows/System32/config/SYSTEM",
    "Windows/System32/config/SOFTWARE",
    "Windows/explorer.exe",
    "Boot/BCD",
    "bootmgr",
)


def _write(root, relative, content=b"contenido"):
    """Crea un archivo con su arbol de carpetas dentro de `root`."""
    path = os.path.join(str(root), *relative.split("/"))
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    with open(path, "wb") as handle:
        handle.write(content)
    return path


def fake_install(base, name="disco", files=_SANE_FILES, users=True):
    """Fabrica una instalacion de Windows creible en `base/name`."""
    root = os.path.join(str(base), name)
    os.makedirs(root, exist_ok=True)
    for relative in files:
        _write(root, relative)
    if users:
        os.makedirs(os.path.join(root, "Users", "Default"), exist_ok=True)
    return root


def _raise(error):
    """Sustituto de una funcion del sistema que siempre falla."""

    def _fail(*_args, **_kwargs):
        raise error

    return _fail


def offline_context(root):
    """Contexto OFFLINE apuntando al arbol falso."""
    return ScanContext(
        mode=ScanMode.OFFLINE,
        windows_root=os.path.join(root, "Windows"),
        is_admin=True,
    )


# ----------------------------------------------------------------------
# 6.1 Deteccion automatica
# ----------------------------------------------------------------------


class TestDiscovery:
    def test_encuentra_una_instalacion_por_el_hive_system(self, tmp_path):
        root = fake_install(tmp_path)
        found = discovery.find_windows_installations(
            roots=[root], exclude_self=False
        )
        assert len(found) == 1
        assert found[0].windows_root == os.path.join(root, "Windows")
        assert found[0].is_system_disk

    def test_una_carpeta_windows_vacia_no_cuenta(self, tmp_path):
        """El marcador es el hive SYSTEM, no la carpeta.

        Cualquiera puede tener una carpeta llamada Windows; sin hive no
        hay nada que analizar y ofrecerla como candidata solo confunde.
        """
        root = os.path.join(str(tmp_path), "vacio")
        os.makedirs(os.path.join(root, "Windows", "System32", "config"))
        assert discovery.probe_root(root) is None

    def test_un_config_protegido_sigue_contando_como_instalacion(
        self, tmp_path, monkeypatch
    ):
        """Sobre un sistema vivo y sin elevacion, System32\\config da acceso
        denegado. Tratarlo como "aqui no hay Windows" haria que la deteccion
        automatica no encontrase nada y el usuario creyera el disco vacio.
        """
        root = fake_install(tmp_path)
        hive = os.path.join(root, "Windows", "System32", "config", "SYSTEM")

        real_isfile = os.path.isfile

        def denegado(path):
            if os.path.normcase(path) == os.path.normcase(hive):
                return False
            return real_isfile(path)

        monkeypatch.setattr(os.path, "isfile", denegado)
        monkeypatch.setattr(
            os, "listdir", _raise(PermissionError(5, "Acceso denegado"))
        )

        candidate = discovery.probe_root(root)
        assert candidate is not None
        assert "protegido" in candidate.signals[0]

    def test_sin_arbol_de_windows_el_acceso_denegado_no_inventa_nada(
        self, tmp_path, monkeypatch
    ):
        root = os.path.join(str(tmp_path), "otro")
        os.makedirs(os.path.join(root, "Windows", "System32", "config"))
        monkeypatch.setattr(
            os, "listdir", _raise(PermissionError(5, "Acceso denegado"))
        )
        assert discovery.probe_root(root) is None

    def test_excluye_la_unidad_de_la_propia_herramienta(self, tmp_path):
        """El error clasico del modo offline: analizar el USB de rescate."""
        averiado = fake_install(tmp_path, "averiado")
        rescate = fake_install(tmp_path, "rescate")

        found = discovery.find_windows_installations(
            roots=[averiado, rescate], exclude_root=rescate, exclude_self=False
        )
        roots = [c.root for c in found]
        assert averiado in roots
        assert rescate not in roots

    def test_la_exclusion_ignora_mayusculas_y_barra_final(self, tmp_path):
        rescate = fake_install(tmp_path, "rescate")
        found = discovery.find_windows_installations(
            roots=[rescate],
            exclude_root=rescate.upper() + os.sep,
            exclude_self=False,
        )
        assert found == []

    def test_un_winpe_no_se_confunde_con_el_equipo_averiado(self, tmp_path):
        winpe = fake_install(tmp_path, "winpe")
        _write(winpe, "Windows/System32/winpeshl.exe")

        candidate = discovery.probe_root(winpe)
        assert candidate is not None
        assert candidate.is_rescue_environment
        assert not candidate.is_system_disk

    def test_el_disco_del_sistema_va_primero(self, tmp_path):
        restos = fake_install(
            tmp_path,
            "restos",
            files=("Windows/System32/config/SYSTEM",),
            users=False,
        )
        completo = fake_install(tmp_path, "completo")

        found = discovery.find_windows_installations(
            roots=[restos, completo], exclude_self=False
        )
        assert [c.root for c in found] == [completo, restos]
        assert not found[1].is_system_disk

    def test_reporta_espacio_libre_y_etiqueta(self, tmp_path):
        root = fake_install(tmp_path)
        candidate = discovery.probe_root(root)
        assert candidate.free_bytes is not None and candidate.free_bytes > 0
        assert candidate.total_bytes is not None
        # La etiqueta puede venir vacia (arbol de pruebas, no una unidad),
        # pero el campo tiene que existir y ser texto.
        assert isinstance(candidate.label, str)

    def test_best_installation_devuelve_none_sin_candidatos(self, tmp_path):
        vacio = os.path.join(str(tmp_path), "nada")
        os.makedirs(vacio)
        assert discovery.best_installation(roots=[vacio]) is None

    def test_tool_root_no_esta_vacio_en_windows(self):
        """Sin esto la exclusion automatica seria una ilusion."""
        root = discovery.tool_root()
        assert root
        assert discovery.same_root(root, root.lower())

    def test_summarize_es_serializable(self, tmp_path):
        root = fake_install(tmp_path)
        found = discovery.find_windows_installations(roots=[root], exclude_self=False)
        resumen = discovery.summarize(found)
        assert resumen["count"] == 1
        assert resumen["installations"][0]["is_system_disk"] is True


# ----------------------------------------------------------------------
# 6.2 Colector offline de sistema
# ----------------------------------------------------------------------


class TestOfflineSystemCollector:
    def test_usa_la_misma_clave_que_el_colector_online(self):
        """Si cambia, las reglas dejan de ver los datos del modo offline."""
        assert OfflineSystemInfoCollector.provides == "system.info"
        assert OfflineSystemInfoCollector.supported_modes == (ScanMode.OFFLINE,)

    def test_no_aplica_en_modo_online(self):
        ctx = ScanContext(mode=ScanMode.ONLINE, windows_root="C:\\Windows")
        assert not OfflineSystemInfoCollector().applies_to(ctx)

    def test_deduce_la_build_del_arbol_de_archivos(self, tmp_path):
        """Respaldo sin registro: Windows\\servicing\\Version da la build."""
        root = fake_install(tmp_path)
        os.makedirs(
            os.path.join(root, "Windows", "servicing", "Version", "10.0.22621.1")
        )
        os.makedirs(
            os.path.join(root, "Windows", "servicing", "Version", "10.0.19041.1")
        )

        data = OfflineSystemInfoCollector().collect(offline_context(root))
        assert data["os_build"] == "22621"
        assert data["os_name"] == "Windows 11"
        assert data["windows_generation"] == "win11"

    def test_un_hive_ilegible_no_revienta_el_colector(self, tmp_path):
        """Es el caso NORMAL: el disco dejo de arrancar por algo.

        El hive falso no es un hive de verdad, asi que python-registry
        falla al parsearlo. El colector tiene que degradar y avisar, no
        propagar la excepcion.
        """
        root = fake_install(tmp_path)
        ctx = offline_context(root)

        data = OfflineSystemInfoCollector().collect(ctx)

        assert data["hostname"]
        assert any("nombre del equipo" in w for w in ctx.warnings)

    def test_inventa_un_nombre_de_equipo_en_vez_de_heredar_el_del_rescate(
        self, tmp_path
    ):
        """Regresion: el reporte no debe archivarse bajo el nombre del USB.

        Si el colector deja `hostname` vacio, el motor conserva el
        `platform.node()` de la maquina de rescate y todos los equipos
        averiados terminan mezclados en la misma carpeta.
        """
        root = fake_install(tmp_path)
        data = OfflineSystemInfoCollector().collect(offline_context(root))
        assert data["hostname"].startswith("equipo-offline-")

    def test_inventaria_los_archivos_criticos(self, tmp_path):
        root = fake_install(tmp_path)
        data = OfflineSystemInfoCollector().collect(offline_context(root))

        files = data["system_files"]
        assert files["ntoskrnl.exe"]["exists"] is True
        assert files["ntoskrnl.exe"]["size_bytes"] > 0
        assert files["hive-system"]["exists"] is True

    def test_detecta_los_archivos_ausentes_sin_juzgarlos(self, tmp_path):
        """El colector informa; interpretar es cosa de BOT-001."""
        root = fake_install(tmp_path)
        os.remove(os.path.join(root, "Windows", "System32", "hal.dll"))

        data = OfflineSystemInfoCollector().collect(offline_context(root))
        assert data["system_files"]["hal.dll"]["exists"] is False

    def test_mide_la_cola_de_windows_update(self, tmp_path):
        root = fake_install(tmp_path)
        _write(root, "Windows/SoftwareDistribution/Download/x.cab", b"0" * 2048)

        data = OfflineSystemInfoCollector().collect(offline_context(root))
        download = data["pending_update"]["software_distribution_download"]
        assert download["exists"] is True
        assert download["size_bytes"] == 2048
        assert download["file_count"] == 1

    def test_volume_root_es_el_padre_de_la_carpeta_windows(self):
        assert volume_root_of("D:\\Windows").rstrip("\\/") == "D:"


# ----------------------------------------------------------------------
# 6.3 Colector offline de almacenamiento
# ----------------------------------------------------------------------


class TestOfflineStorageCollector:
    def test_respeta_la_forma_que_esperan_las_reglas_sto(self, tmp_path):
        """STO-001 y STO-002 leen 'disks' y 'volumes'. Sin eso no disparan."""
        root = fake_install(tmp_path)
        data = OfflineStorageCollector().collect(offline_context(root))
        assert "disks" in data
        assert "volumes" in data
        assert data["disks"] == []
        assert len(data["volumes"]) == 1

    def test_avisa_de_que_no_hay_smart(self, tmp_path):
        """"Sin hallazgos de disco" no puede leerse como "disco sano"."""
        root = fake_install(tmp_path)
        ctx = offline_context(root)
        OfflineStorageCollector().collect(ctx)
        assert any("SMART" in w for w in ctx.warnings)

    def test_el_volumen_se_marca_como_disco_fijo(self, tmp_path):
        """Si no, STO-002 lo descarta por no ser drive_type 3."""
        root = fake_install(tmp_path)
        data = OfflineStorageCollector().collect(offline_context(root))
        volume = data["volumes"][0]
        assert volume["drive_type"] == 3
        assert volume["is_system_volume"] is True
        assert volume["percent_free"] is not None

    def test_detecta_pagefile_e_hiberfil(self, tmp_path):
        root = fake_install(tmp_path)
        _write(root, "pagefile.sys", b"p" * 100)
        _write(root, "hiberfil.sys", b"h" * 200)

        data = OfflineStorageCollector().collect(offline_context(root))
        integrity = data["volumes"][0]["integrity"]
        assert integrity["pagefile"]["exists"] is True
        assert integrity["hiberfil"]["size_bytes"] == 200
        assert integrity["hibernation_image"] is True

    def test_detecta_restos_de_chkdsk(self, tmp_path):
        root = fake_install(tmp_path)
        _write(root, "FOUND.000/FILE0000.CHK")
        _write(root, "Windows/System32/LogFiles/Chkdsk/Chkdsk20240101.log")

        data = OfflineStorageCollector().collect(offline_context(root))
        integrity = data["volumes"][0]["integrity"]
        assert integrity["chkdsk_ran_before"] is True
        clases = {a["kind"] for a in integrity["chkdsk_artifacts"]}
        assert clases == {"recuperado-por-chkdsk", "registro-chkdsk"}

    def test_un_volumen_limpio_no_reporta_senales(self, tmp_path):
        root = fake_install(tmp_path)
        data = OfflineStorageCollector().collect(offline_context(root))
        integrity = data["volumes"][0]["integrity"]
        assert integrity["chkdsk_ran_before"] is False
        assert integrity["hibernation_image"] is False


# ----------------------------------------------------------------------
# 6.4 Reglas BOT
# ----------------------------------------------------------------------


def system_facts(tmp_path, **overrides):
    """`facts` como los produciria el colector offline sobre un disco sano."""
    root = fake_install(tmp_path)
    data = OfflineSystemInfoCollector().collect(offline_context(root))
    data.update(overrides)
    return {"system.info": data}, root


def storage_facts(root, free_bytes=50 * 1024 ** 3, **volume_overrides):
    volume = {
        "device": "D:",
        "root": root,
        "drive_type": 3,
        "filesystem": "NTFS",
        "size_bytes": 200 * 1024 ** 3,
        "free_bytes": free_bytes,
        "percent_free": 25.0,
        "is_system_volume": True,
        "integrity": {},
    }
    volume.update(volume_overrides)
    return {
        "storage.disks": {
            "disks": [],
            "volumes": [volume],
            "volume_root": root,
        }
    }


class TestBot001:
    def test_un_windows_completo_no_dispara(self, tmp_path):
        facts, _ = system_facts(tmp_path)
        assert list(MissingSystemFilesRule().evaluate(facts)) == []

    def test_falta_el_nucleo(self, tmp_path):
        facts, root = system_facts(tmp_path)
        facts["system.info"]["system_files"]["ntoskrnl.exe"]["exists"] = False

        findings = list(MissingSystemFilesRule().evaluate(facts))
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL
        assert "nucleo" in findings[0].summary

    def test_un_archivo_de_cero_bytes_cuenta_como_ausente(self, tmp_path):
        """Un apagado a mitad de escritura deja archivos vacios, no ausentes."""
        root = fake_install(tmp_path)
        _write(root, "Windows/System32/hal.dll", b"")
        data = OfflineSystemInfoCollector().collect(offline_context(root))

        findings = list(MissingSystemFilesRule().evaluate({"system.info": data}))
        assert len(findings) == 1
        assert "0 bytes" in findings[0].evidence[0].detail

    def test_basta_con_uno_de_los_dos_cargadores(self, tmp_path):
        """Un Windows 7 con BIOS no tiene winload.efi y arranca igual."""
        root = fake_install(tmp_path)
        os.remove(os.path.join(root, "Windows", "System32", "winload.efi"))
        data = OfflineSystemInfoCollector().collect(offline_context(root))
        assert list(MissingSystemFilesRule().evaluate({"system.info": data})) == []

    def test_sin_ningun_cargador_si_dispara(self, tmp_path):
        root = fake_install(tmp_path)
        for name in ("winload.exe", "winload.efi"):
            os.remove(os.path.join(root, "Windows", "System32", name))
        data = OfflineSystemInfoCollector().collect(offline_context(root))

        findings = list(MissingSystemFilesRule().evaluate({"system.info": data}))
        assert len(findings) == 1
        assert "winload" in findings[0].summary

    def test_calla_en_modo_online(self):
        """El colector online no inventaria archivos: la regla no opina."""
        facts = {"system.info": {"hostname": "PC", "os_name": "Windows 11"}}
        assert list(MissingSystemFilesRule().evaluate(facts)) == []

    def test_el_remedio_usa_la_letra_real_del_disco(self, tmp_path):
        facts, root = system_facts(tmp_path)
        facts["system.info"]["system_files"]["hal.dll"]["exists"] = False
        facts["system.info"]["volume_root"] = "E:\\"

        findings = list(MissingSystemFilesRule().evaluate(facts))
        pasos = " ".join(findings[0].remedy.steps)
        assert "E:\\Windows" in pasos
        assert findings[0].remedy.action_id is None


class TestBot002:
    def test_con_bcd_valido_no_dispara(self, tmp_path):
        facts, _ = system_facts(tmp_path)
        assert list(MissingBcdRule().evaluate(facts)) == []

    def test_bcd_vacio_es_certeza(self, tmp_path):
        root = fake_install(tmp_path)
        _write(root, "Boot/BCD", b"")
        data = OfflineSystemInfoCollector().collect(offline_context(root))

        findings = list(MissingBcdRule().evaluate({"system.info": data}))
        assert len(findings) == 1
        assert findings[0].confidence is Confidence.CERTAIN
        assert findings[0].severity is Severity.CRITICAL

    def test_bcd_ausente_es_solo_probable_por_la_particion_efi(self, tmp_path):
        """En UEFI el BCD vive en una particion que no suele tener letra."""
        root = fake_install(
            tmp_path, files=tuple(f for f in _SANE_FILES if f != "Boot/BCD")
        )
        data = OfflineSystemInfoCollector().collect(offline_context(root))

        findings = list(MissingBcdRule().evaluate({"system.info": data}))
        assert len(findings) == 1
        assert findings[0].confidence is Confidence.LIKELY
        assert "EFI" in findings[0].summary

    def test_el_bcd_uefi_tambien_vale(self, tmp_path):
        files = tuple(f for f in _SANE_FILES if f != "Boot/BCD")
        root = fake_install(tmp_path, files=files)
        _write(root, "EFI/Microsoft/Boot/BCD")
        data = OfflineSystemInfoCollector().collect(offline_context(root))
        assert list(MissingBcdRule().evaluate({"system.info": data})) == []

    def test_calla_en_modo_online(self):
        assert list(MissingBcdRule().evaluate({"system.info": {"hostname": "PC"}})) == []


class TestBot003:
    def test_un_sistema_sin_restos_no_dispara(self, tmp_path):
        facts, _ = system_facts(tmp_path)
        assert list(InterruptedUpdateRule().evaluate(facts)) == []

    def test_pending_xml_es_critico(self, tmp_path):
        root = fake_install(tmp_path)
        _write(root, "Windows/WinSxS/pending.xml", b"<xml/>")
        data = OfflineSystemInfoCollector().collect(offline_context(root))

        findings = list(InterruptedUpdateRule().evaluate({"system.info": data}))
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL

    def test_pending_xml_en_config_tambien_cuenta(self, tmp_path):
        root = fake_install(tmp_path)
        _write(root, "Windows/System32/config/pending.xml", b"<xml/>")
        data = OfflineSystemInfoCollector().collect(offline_context(root))
        assert len(list(InterruptedUpdateRule().evaluate({"system.info": data}))) == 1

    def test_winre_agent_es_advertencia(self, tmp_path):
        root = fake_install(tmp_path)
        os.makedirs(os.path.join(root, "$WinREAgent"))
        data = OfflineSystemInfoCollector().collect(offline_context(root))

        findings = list(InterruptedUpdateRule().evaluate({"system.info": data}))
        assert len(findings) == 1
        assert findings[0].severity is Severity.WARNING

    def test_windows_old_sola_no_dispara(self, tmp_path):
        """Regresion: toda actualizacion correcta deja Windows.old.

        Marcarla como problema convertiria la regla en ruido permanente.
        """
        root = fake_install(tmp_path)
        os.makedirs(os.path.join(root, "Windows.old"))
        data = OfflineSystemInfoCollector().collect(offline_context(root))
        assert list(InterruptedUpdateRule().evaluate({"system.info": data})) == []

    def test_windows_old_se_suma_como_contexto_si_hay_otra_senal(self, tmp_path):
        root = fake_install(tmp_path)
        os.makedirs(os.path.join(root, "Windows.old"))
        os.makedirs(os.path.join(root, "$WinREAgent"))
        data = OfflineSystemInfoCollector().collect(offline_context(root))

        findings = list(InterruptedUpdateRule().evaluate({"system.info": data}))
        detalles = " ".join(e.detail for e in findings[0].evidence)
        assert "Windows.old" in detalles

    def test_cola_de_descargas_pequena_no_dispara(self, tmp_path):
        root = fake_install(tmp_path)
        _write(root, "Windows/SoftwareDistribution/Download/x.cab", b"0" * 1024)
        data = OfflineSystemInfoCollector().collect(offline_context(root))
        assert list(InterruptedUpdateRule().evaluate({"system.info": data})) == []

    def test_cola_de_descargas_gigante_si_dispara(self, tmp_path):
        facts, _ = system_facts(tmp_path)
        facts["system.info"]["pending_update"]["software_distribution_download"] = {
            "path": "D:\\Windows\\SoftwareDistribution\\Download",
            "exists": True,
            "size_bytes": 6 * 1024 ** 3,
            "file_count": 120,
            "truncated": False,
        }
        findings = list(InterruptedUpdateRule().evaluate(facts))
        assert len(findings) == 1
        assert findings[0].severity is Severity.WARNING

    def test_marca_del_registro_de_instalacion_en_curso(self, tmp_path):
        facts, _ = system_facts(tmp_path, setup_in_progress=1)
        findings = list(InterruptedUpdateRule().evaluate(facts))
        assert len(findings) == 1

    def test_calla_en_modo_online(self):
        assert list(InterruptedUpdateRule().evaluate({"system.info": {}})) == []


class TestBot004:
    def test_con_espacio_de_sobra_no_dispara(self, tmp_path):
        facts = storage_facts(str(tmp_path), free_bytes=50 * 1024 ** 3)
        assert list(DiskFullPreventingBootRule().evaluate(facts)) == []

    def test_justo_en_el_umbral_no_dispara(self, tmp_path):
        facts = storage_facts(str(tmp_path), free_bytes=500 * 1024 ** 2)
        assert list(DiskFullPreventingBootRule().evaluate(facts)) == []

    def test_por_debajo_de_500_mb_es_critico(self, tmp_path):
        facts = storage_facts(str(tmp_path), free_bytes=120 * 1024 ** 2)
        findings = list(DiskFullPreventingBootRule().evaluate(facts))
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL
        assert "STO-002" in findings[0].related

    def test_ignora_volumenes_que_no_son_el_del_sistema(self, tmp_path):
        """Un disco de datos lleno no explica que el equipo no arranque."""
        facts = storage_facts(str(tmp_path), free_bytes=1024)
        facts["storage.disks"]["volumes"][0]["is_system_volume"] = False
        assert list(DiskFullPreventingBootRule().evaluate(facts)) == []

    def test_calla_con_los_volumenes_del_colector_online(self, tmp_path):
        """El colector online no marca is_system_volume: la regla no opina."""
        facts = {
            "storage.disks": {
                "disks": [],
                "volumes": [{"device": "C:", "drive_type": 3, "free_bytes": 1024}],
            }
        }
        assert list(DiskFullPreventingBootRule().evaluate(facts)) == []

    def test_enumera_lo_que_se_puede_liberar_con_su_tamano(self, tmp_path):
        """"Libera espacio" no ayuda; "borra hiberfil.sys, son 6 GB" si."""
        facts = storage_facts(
            str(tmp_path),
            free_bytes=10 * 1024 ** 2,
            integrity={
                "hiberfil": {"exists": True, "size_bytes": 6 * 1024 ** 3},
                "pagefile": {"exists": True, "size_bytes": 2 * 1024 ** 3},
            },
        )
        findings = list(DiskFullPreventingBootRule().evaluate(facts))
        detalles = " ".join(e.detail for e in findings[0].evidence)
        assert "hiberfil.sys" in detalles
        pasos = " ".join(findings[0].remedy.steps)
        assert "hiberfil.sys" in pasos
        assert "pagefile.sys" in pasos

    def test_sin_senales_de_integridad_el_remedio_sigue_siendo_util(self, tmp_path):
        facts = storage_facts(str(tmp_path), free_bytes=10 * 1024 ** 2)
        findings = list(DiskFullPreventingBootRule().evaluate(facts))
        assert findings[0].remedy.steps
        assert findings[0].remedy.action_id is None


# ----------------------------------------------------------------------
# Integracion con el registro global
# ----------------------------------------------------------------------


class TestRegistro:
    def test_los_colectores_offline_estan_registrados(self):
        from inyaguidiag.core.registry import collector_names

        nombres = set(collector_names())
        assert {"system-info-offline", "storage-offline"} <= nombres

    def test_las_reglas_bot_estan_registradas(self):
        from inyaguidiag.core.registry import rule_ids

        ids = set(rule_ids())
        assert {"BOT-001", "BOT-002", "BOT-003", "BOT-004"} <= ids

    def test_no_hay_dos_colectores_para_la_misma_clave_y_modo(self):
        """Online y offline comparten `provides` pero nunca coinciden.

        Si los dos aplicaran al mismo contexto, el segundo pisaria los
        hechos del primero y el resultado dependeria del orden alfabetico.
        """
        from inyaguidiag.core.registry import all_collectors

        for mode in (ScanMode.ONLINE, ScanMode.OFFLINE):
            ctx = ScanContext(mode=mode, windows_root="C:\\Windows")
            vistos = {}
            for collector in all_collectors():
                if not collector.applies_to(ctx):
                    continue
                assert collector.provides not in vistos, (
                    "%s y %s producen '%s' en modo %s"
                    % (
                        vistos.get(collector.provides),
                        collector.name,
                        collector.provides,
                        mode.value,
                    )
                )
                vistos[collector.provides] = collector.name
