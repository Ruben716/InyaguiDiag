"""Regresion: no confundir "no se pudo mirar" con "no esta".

POR QUE EXISTE ESTE ARCHIVO
---------------------------
Un escaneo offline real contra un Windows sano pero en uso reporto:

    [X] CRITICO - FALTAN ARCHIVOS ESENCIALES DE WINDOWS
        el registro de configuracion (hive SYSTEM)

El hive estaba perfecto. Lo que pasaba es que `os.path.exists()` devuelve
False ante CUALQUIER OSError, incluido "acceso denegado", asi que el
colector no podia distinguir un archivo ausente de uno bloqueado.

Es el peor error que puede cometer esta herramienta: decirle a un tecnico
que un sistema sano esta destruido invita a reinstalar sin necesidad y
tira abajo la credibilidad de todo el reporte.

Estas pruebas fijan el comportamiento correcto para que no vuelva.
"""

from __future__ import annotations

import os

import pytest

from inyaguidiag.collectors.offline.system import _stat_one
from inyaguidiag.core.models import Confidence, Severity
from inyaguidiag.rules.boot_rules import (
    MissingBcdRule,
    MissingSystemFilesRule,
    _is_broken,
    _is_unknown,
)


# ----------------------------------------------------------------------
# El colector: tres estados, no dos
# ----------------------------------------------------------------------


class TestStatOne:
    def test_archivo_presente(self, tmp_path):
        path = tmp_path / "ntoskrnl.exe"
        path.write_bytes(b"x" * 100)
        entry = _stat_one(str(path))
        assert entry["exists"] is True
        assert entry["size_bytes"] == 100
        assert entry["access_denied"] is False

    def test_archivo_ausente(self, tmp_path):
        entry = _stat_one(str(tmp_path / "no-existe.exe"))
        assert entry["exists"] is False
        assert entry["access_denied"] is False

    def test_acceso_denegado_es_DESCONOCIDO_no_ausente(self, tmp_path, monkeypatch):
        """El caso que causo el falso positivo.

        Permiso denegado NO es lo mismo que archivo ausente. Tiene que
        quedar como None (no se sabe), nunca como False.
        """
        path = tmp_path / "SYSTEM"
        path.write_bytes(b"hive")

        def denegar(_p):
            raise PermissionError(13, "Acceso denegado")

        monkeypatch.setattr(os.path, "getsize", denegar)

        entry = _stat_one(str(path))
        assert entry["exists"] is None, "acceso denegado no puede ser 'no existe'"
        assert entry["access_denied"] is True

    def test_error_de_lectura_si_cuenta_como_ausente(self, tmp_path, monkeypatch):
        """Un sector ilegible SI equivale a ausente.

        Al cargador de arranque le da lo mismo un archivo que no esta que
        uno que el disco no puede entregar. Esto es distinto de un
        problema de permisos del entorno de analisis.
        """
        path = tmp_path / "hal.dll"
        path.write_bytes(b"x")

        def fallo_es(_p):
            raise OSError(5, "Error de E/S del dispositivo")

        monkeypatch.setattr(os.path, "getsize", fallo_es)

        entry = _stat_one(str(path))
        assert entry["exists"] is False
        assert entry["access_denied"] is False


# ----------------------------------------------------------------------
# Los predicados
# ----------------------------------------------------------------------


def _entry(exists, size=1000, denied=False):
    return {
        "path": "X:\\Windows\\System32\\algo",
        "exists": exists,
        "size_bytes": size,
        "access_denied": denied,
    }


class TestPredicados:
    @pytest.mark.parametrize(
        "entry,roto",
        [
            (_entry(True, 1000), False),
            (_entry(True, 0), True),        # presente pero vacio
            (_entry(False, None), True),    # ausente de verdad
            (_entry(None, None, True), False),  # desconocido: abstenerse
        ],
    )
    def test_is_broken(self, entry, roto):
        assert _is_broken(entry) is roto

    def test_is_unknown(self):
        assert _is_unknown(_entry(None, None, True)) is True
        assert _is_unknown(_entry(True)) is False
        assert _is_unknown(_entry(False)) is False


# ----------------------------------------------------------------------
# BOT-001
# ----------------------------------------------------------------------


def _facts(files):
    return {"system.info": {"system_files": files, "volume_root": "X:\\"}}


class TestBot001:
    def test_no_dispara_con_hives_inaccesibles(self):
        """EL caso del falso positivo, end-to-end.

        Todo presente salvo los hives, que dan acceso denegado. No debe
        salir ningun hallazgo.
        """
        files = {
            "ntoskrnl.exe": _entry(True),
            "hal.dll": _entry(True),
            "winload.exe": _entry(True),
            "ntdll.dll": _entry(True),
            "smss.exe": _entry(True),
            "hive-system": _entry(None, None, True),
            "hive-software": _entry(None, None, True),
        }
        assert list(MissingSystemFilesRule().evaluate(_facts(files))) == []

    def test_si_dispara_con_hive_realmente_ausente(self):
        files = {
            "ntoskrnl.exe": _entry(True),
            "hive-system": _entry(False, None),
        }
        findings = list(MissingSystemFilesRule().evaluate(_facts(files)))
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL

    def test_si_dispara_con_archivo_de_cero_bytes(self):
        files = {"ntoskrnl.exe": _entry(True, 0)}
        findings = list(MissingSystemFilesRule().evaluate(_facts(files)))
        assert len(findings) == 1

    def test_sistema_sano_no_dispara(self):
        files = {
            "ntoskrnl.exe": _entry(True),
            "hal.dll": _entry(True),
            "hive-system": _entry(True),
        }
        assert list(MissingSystemFilesRule().evaluate(_facts(files))) == []


# ----------------------------------------------------------------------
# BOT-002
# ----------------------------------------------------------------------


def _bcd_facts(stores):
    return {"system.info": {"boot_files": {"bcd": stores}, "volume_root": "X:\\"}}


class TestBot002:
    def test_bcd_no_encontrado_es_ADVERTENCIA_no_critico(self):
        """En UEFI sano el BCD vive en la particion EFI, sin letra.

        Este caso se da SIEMPRE al analizar un UEFI offline. Marcarlo
        critico haria que el tecnico aprenda a ignorar los criticos.
        """
        findings = list(MissingBcdRule().evaluate(
            _bcd_facts({"bios": _entry(False, None), "uefi": _entry(False, None)})
        ))
        assert len(findings) == 1
        assert findings[0].severity is Severity.WARNING
        assert findings[0].confidence is Confidence.LIKELY

    def test_bcd_vacio_si_es_critico(self):
        """Presente y de cero bytes es prueba directa de corrupcion."""
        findings = list(MissingBcdRule().evaluate(
            _bcd_facts({"bios": _entry(True, 0)})
        ))
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL
        assert findings[0].confidence is Confidence.CERTAIN

    def test_bcd_sano_no_dispara(self):
        assert list(MissingBcdRule().evaluate(
            _bcd_facts({"bios": _entry(True, 262144)})
        )) == []

    def test_bcd_inaccesible_no_dispara(self):
        assert list(MissingBcdRule().evaluate(
            _bcd_facts({"bios": _entry(None, None, True)})
        )) == []
