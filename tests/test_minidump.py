"""Pruebas del lector de volcados y de las reglas de pantallazo.

Los volcados se fabrican byte a byte. No hace falta un equipo que se
caiga: la cabecera DUMP_HEADER es un formato fijo y documentado, y
construirla en la prueba deja explicito que offsets estamos leyendo.
"""

from __future__ import annotations

import os
import struct

import pytest

from inyaguidiag.core.minidump import (
    DumpParseError,
    find_dumps,
    parse_dump,
)
from inyaguidiag.core.models import Confidence, Severity
from inyaguidiag.knowledge import bugcheck_codes
from inyaguidiag.rules.crash_rules import (
    BugCheckAnalysisRule,
    CrashDumpsDisabledRule,
    SuspectDriverRule,
)


# ----------------------------------------------------------------------
# Fabricacion de volcados
# ----------------------------------------------------------------------


def _dump_x64(code=0x7A, params=(1, 2, 3, 4), machine=0x8664, drivers=()):
    """Construye un DUMP_HEADER64 valido."""
    buf = bytearray(0x1000)
    buf[0x00:0x04] = b"PAGE"
    buf[0x04:0x08] = b"DU64"
    struct.pack_into("<I", buf, 0x30, machine)
    struct.pack_into("<I", buf, 0x38, code)
    struct.pack_into("<4Q", buf, 0x40, *params)
    if drivers:
        blob = ("\x00".join(drivers)).encode("utf-16-le")
        buf[0x200:0x200 + len(blob)] = blob
    return bytes(buf)


def _dump_x86(code=0x0A, params=(1, 2, 3, 4)):
    buf = bytearray(0x1000)
    buf[0x00:0x04] = b"PAGE"
    buf[0x04:0x08] = b"DUMP"
    struct.pack_into("<I", buf, 0x20, 0x014C)
    struct.pack_into("<I", buf, 0x28, code)
    struct.pack_into("<4I", buf, 0x2C, *params)
    return bytes(buf)


@pytest.fixture
def dump_dir(tmp_path):
    return tmp_path


def _write(directory, name, data):
    path = os.path.join(str(directory), name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


# ----------------------------------------------------------------------
# Parser
# ----------------------------------------------------------------------


class TestParseDump:
    def test_lee_cabecera_x64(self, dump_dir):
        path = _write(dump_dir, "a.dmp", _dump_x64(code=0x7A, params=(0xA, 0xB, 0xC, 0xD)))
        dump = parse_dump(path)
        assert dump.bugcheck_code == 0x7A
        assert dump.parameters == [0xA, 0xB, 0xC, 0xD]
        assert dump.architecture == "x64"

    def test_lee_cabecera_x86(self, dump_dir):
        """Windows 7 de 32 bits sigue existiendo: es nuestro piso."""
        path = _write(dump_dir, "b.dmp", _dump_x86(code=0x1A, params=(1, 2, 3, 4)))
        dump = parse_dump(path)
        assert dump.bugcheck_code == 0x1A
        assert dump.architecture == "x86"
        assert dump.parameters == [1, 2, 3, 4]

    def test_firma_invalida(self, dump_dir):
        path = _write(dump_dir, "c.dmp", b"NOPE" + b"\x00" * 0x100)
        with pytest.raises(DumpParseError):
            parse_dump(path)

    def test_archivo_truncado(self, dump_dir):
        path = _write(dump_dir, "d.dmp", b"PAGE")
        with pytest.raises(DumpParseError):
            parse_dump(path)

    def test_marca_de_volcado_desconocida(self, dump_dir):
        path = _write(dump_dir, "e.dmp", b"PAGE" + b"XXXX" + b"\x00" * 0x100)
        with pytest.raises(DumpParseError):
            parse_dump(path)

    def test_extrae_nombres_de_controladores(self, dump_dir):
        drivers = ("nvlddmkm.sys", "rtwlane.sys", "ntoskrnl.exe")
        path = _write(dump_dir, "f.dmp", _dump_x64(drivers=drivers))
        dump = parse_dump(path)
        assert "nvlddmkm.sys" in dump.modules
        assert "rtwlane.sys" in dump.modules

    def test_timestamp_desde_el_archivo(self, dump_dir):
        path = _write(dump_dir, "g.dmp", _dump_x64())
        assert parse_dump(path).timestamp is not None


class TestFindDumps:
    def test_carpeta_inexistente_no_revienta(self):
        assert find_dumps("Z:\\no\\existe") == []

    def test_solo_toma_dmp(self, dump_dir):
        _write(dump_dir, "uno.dmp", _dump_x64())
        _write(dump_dir, "leeme.txt", b"hola")
        assert len(find_dumps(str(dump_dir))) == 1

    def test_incluye_el_volcado_completo(self, tmp_path):
        minidumps = tmp_path / "Minidump"
        minidumps.mkdir()
        _write(minidumps, "uno.dmp", _dump_x64())
        memory = _write(tmp_path, "MEMORY.DMP", _dump_x64())
        assert len(find_dumps(str(minidumps), memory)) == 2

    def test_no_duplica_si_el_volcado_completo_esta_en_la_misma_carpeta(self, dump_dir):
        """Regresion: contar un volcado dos veces infla la severidad.

        Las reglas deciden CRITICO vs ADVERTENCIA segun cuantos volcados
        hay, asi que un duplicado no es cosmetico: cambia el diagnostico.
        """
        _write(dump_dir, "uno.dmp", _dump_x64())
        memory = _write(dump_dir, "MEMORY.DMP", _dump_x64())
        assert len(find_dumps(str(dump_dir), memory)) == 2


# ----------------------------------------------------------------------
# Catalogo
# ----------------------------------------------------------------------


class TestBugCheckCatalog:
    def test_codigos_de_disco_marcan_disco(self):
        assert bugcheck_codes.lookup(0x7A).suspect == "disco"
        assert bugcheck_codes.lookup(0x7B).suspect == "disco"

    def test_codigos_de_memoria_marcan_memoria(self):
        assert bugcheck_codes.lookup(0x1A).suspect == "memoria"
        assert bugcheck_codes.lookup(0x4E).suspect == "memoria"

    def test_whea_es_hardware(self):
        entry = bugcheck_codes.lookup(0x124)
        assert entry.suspect == "hardware"
        assert entry.hardware is True

    def test_codigo_desconocido(self):
        assert bugcheck_codes.lookup(0xDEADBEEF) is None
        assert "0xDEADBEEF" in bugcheck_codes.describe(0xDEADBEEF)


# ----------------------------------------------------------------------
# Reglas
# ----------------------------------------------------------------------


class _FakeDump:
    def __init__(self, code, modules=(), name="x.dmp"):
        self.bugcheck_code = code
        self.parameters = [0, 0, 0, 0]
        self.modules = list(modules)
        self.filename = name
        self.path = name
        self.architecture = "x64"
        self.size_bytes = 300 * 1024
        self.timestamp = None
        self.hex_code = "0x%X" % code

    def parameter_text(self):
        return "0x0, 0x0, 0x0, 0x0"


def _facts(dumps, found=None):
    return {
        "crash.dumps": {
            "dumps": dumps,
            "found": len(dumps) if found is None else found,
            "minidump_dir": "C:\\Windows\\Minidump",
            "dir_exists": True,
        }
    }


class TestBugCheckAnalysisRule:
    def test_sin_volcados_no_dice_nada(self):
        assert list(BugCheckAnalysisRule().evaluate(_facts([]))) == []

    def test_codigo_de_disco_propone_respaldar(self):
        findings = list(BugCheckAnalysisRule().evaluate(_facts([_FakeDump(0x7A)])))
        assert len(findings) == 1
        assert "RESPALDAR" in findings[0].remedy.steps[0].upper()

    def test_codigo_de_hardware_es_critico(self):
        findings = list(BugCheckAnalysisRule().evaluate(_facts([_FakeDump(0x124)])))
        assert findings[0].severity is Severity.CRITICAL

    def test_codigo_repetido_sube_severidad_y_confianza(self):
        uno = list(BugCheckAnalysisRule().evaluate(_facts([_FakeDump(0x0A)])))
        tres = list(BugCheckAnalysisRule().evaluate(
            _facts([_FakeDump(0x0A), _FakeDump(0x0A), _FakeDump(0x0A)])))
        assert tres[0].severity > uno[0].severity
        assert tres[0].confidence > uno[0].confidence

    def test_codigos_distintos_generan_hallazgos_distintos(self):
        findings = list(BugCheckAnalysisRule().evaluate(
            _facts([_FakeDump(0x7A), _FakeDump(0x1A)])))
        assert len(findings) == 2
        assert len({f.rule_id for f in findings}) == 2

    def test_codigo_desconocido_no_revienta(self):
        findings = list(BugCheckAnalysisRule().evaluate(_facts([_FakeDump(0xABCDEF)])))
        assert len(findings) == 1
        assert findings[0].confidence is Confidence.POSSIBLE


class TestSuspectDriverRule:
    def test_necesita_al_menos_dos_volcados(self):
        facts = _facts([_FakeDump(0x0A, ["raro.sys"])])
        assert list(SuspectDriverRule().evaluate(facts)) == []

    def test_senala_el_driver_comun_a_todos(self):
        facts = _facts([
            _FakeDump(0x0A, ["nvlddmkm.sys", "ntfs.sys"]),
            _FakeDump(0x0A, ["nvlddmkm.sys", "tcpip.sys"]),
        ])
        findings = list(SuspectDriverRule().evaluate(facts))
        assert len(findings) == 1
        assert "nvlddmkm.sys" in findings[0].summary

    def test_ignora_los_drivers_de_microsoft(self):
        """ntfs.sys aparece en casi todos los volcados; no es una pista."""
        facts = _facts([
            _FakeDump(0x0A, ["ntfs.sys", "tcpip.sys"]),
            _FakeDump(0x0A, ["ntfs.sys", "tcpip.sys"]),
        ])
        assert list(SuspectDriverRule().evaluate(facts)) == []

    def test_nunca_afirma_certeza(self):
        """Sin simbolos no se puede atribuir la culpa a un driver."""
        facts = _facts([
            _FakeDump(0x0A, ["raro.sys"]),
            _FakeDump(0x0A, ["raro.sys"]),
        ])
        findings = list(SuspectDriverRule().evaluate(facts))
        assert findings[0].confidence is Confidence.POSSIBLE
        assert "presente" in findings[0].title.lower()

    def test_sin_interseccion_no_acusa(self):
        facts = _facts([
            _FakeDump(0x0A, ["uno.sys"]),
            _FakeDump(0x0A, ["dos.sys"]),
        ])
        assert list(SuspectDriverRule().evaluate(facts)) == []

    def test_demasiados_candidatos_es_ruido(self):
        muchos = ["d%d.sys" % i for i in range(12)]
        facts = _facts([_FakeDump(0x0A, muchos), _FakeDump(0x0A, muchos)])
        assert list(SuspectDriverRule().evaluate(facts)) == []


class TestCrashDumpsDisabledRule:
    def test_avisa_cuando_no_hay_volcados(self):
        findings = list(CrashDumpsDisabledRule().evaluate(_facts([], found=0)))
        assert len(findings) == 1
        assert findings[0].severity is Severity.INFO

    def test_calla_si_hay_volcados(self):
        facts = _facts([_FakeDump(0x0A)])
        assert list(CrashDumpsDisabledRule().evaluate(facts)) == []
