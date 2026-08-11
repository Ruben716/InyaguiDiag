"""Pruebas del normalizador de eventos y la linea de tiempo.

`parse_event_xml` es el unico punto del proyecto que interpreta el formato
de un evento de Windows, y lo usan los dos modos (online y offline). Un
fallo aca rompe todo el analisis de registros, asi que se cubre a fondo.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from inyaguidiag.core.events import (
    LEVEL_CRITICAL,
    LEVEL_ERROR,
    LEVEL_INFO,
    EventRecord,
    Timeline,
    parse_event_xml,
)

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _xml(
    event_id=41,
    provider="Microsoft-Windows-Kernel-Power",
    level=LEVEL_CRITICAL,
    time="2026-08-11T13:31:31.1234567Z",
    data_xml="",
):
    return (
        '<Event xmlns="%s">'
        "<System>"
        '<Provider Name="%s"/>'
        "<EventID>%d</EventID>"
        "<Level>%d</Level>"
        '<TimeCreated SystemTime="%s"/>'
        "<Channel>System</Channel>"
        "<Computer>PRUEBA</Computer>"
        "</System>"
        "%s"
        "</Event>"
    ) % (NS, provider, event_id, level, time, data_xml)


class TestParseEventXml:
    def test_campos_basicos(self):
        record = parse_event_xml(_xml())
        assert record is not None
        assert record.event_id == 41
        assert record.provider == "Microsoft-Windows-Kernel-Power"
        assert record.level == LEVEL_CRITICAL
        assert record.log == "System"
        assert record.computer == "PRUEBA"

    def test_timestamp_con_siete_decimales(self):
        """Regresion: Windows emite 7 decimales de segundo.

        `datetime.fromisoformat` de Python 3.8 solo acepta 6. Si esto se
        rompe, TODOS los eventos pierden fecha y la correlacion temporal
        --que es el corazon del analisis-- deja de funcionar en silencio.
        """
        record = parse_event_xml(_xml(time="2026-08-11T13:31:31.1234567Z"))
        assert record is not None
        assert record.timestamp is not None
        assert record.timestamp.year == 2026
        assert record.timestamp.month == 8
        assert record.timestamp.day == 11
        assert record.timestamp.hour == 13

    def test_timestamp_sin_decimales(self):
        record = parse_event_xml(_xml(time="2026-08-11T13:31:31Z"))
        assert record is not None and record.timestamp is not None
        assert record.timestamp.second == 31

    def test_timestamp_invalido_no_revienta(self):
        record = parse_event_xml(_xml(time="no-es-una-fecha"))
        assert record is not None
        assert record.timestamp is None

    def test_datos_con_nombre(self):
        data = '<EventData><Data Name="BugcheckCode">159</Data></EventData>'
        record = parse_event_xml(_xml(data_xml=data))
        assert record is not None
        assert record.data["BugcheckCode"] == "159"

    def test_datos_posicionales(self):
        """Los proveedores clasicos (disk, Ntfs) no ponen nombres."""
        data = "<EventData><Data>uno</Data><Data>dos</Data></EventData>"
        record = parse_event_xml(_xml(provider="disk", data_xml=data))
        assert record is not None
        assert record.data["Data0"] == "uno"
        assert record.data["Data1"] == "dos"

    def test_xml_corrupto_devuelve_none(self):
        """Los .evtx de equipos con corte de energia traen basura al final.

        Debe saltarse el registro, no abortar la lectura del archivo.
        """
        assert parse_event_xml("<Event><roto") is None
        assert parse_event_xml("") is None

    def test_xml_sin_event_id_devuelve_none(self):
        xml = '<Event xmlns="%s"><System><Level>2</Level></System></Event>' % NS
        assert parse_event_xml(xml) is None

    def test_is_problem(self):
        assert parse_event_xml(_xml(level=LEVEL_CRITICAL)).is_problem
        assert parse_event_xml(_xml(level=LEVEL_ERROR)).is_problem
        assert not parse_event_xml(_xml(level=LEVEL_INFO)).is_problem


# ----------------------------------------------------------------------


def _event(minutes_ago=0, event_id=11, provider="disk", level=LEVEL_ERROR):
    return EventRecord(
        log="System",
        event_id=event_id,
        provider=provider,
        level=level,
        timestamp=datetime(2026, 8, 11, 12, 0) - timedelta(minutes=minutes_ago),
    )


class TestTimeline:
    def test_ordena_cronologicamente(self):
        timeline = Timeline([_event(0), _event(30), _event(10)])
        stamps = [e.timestamp for e in timeline]
        assert stamps == sorted(stamps)

    def test_filtra_por_proveedor_e_id(self):
        timeline = Timeline([
            _event(1, event_id=11, provider="disk"),
            _event(2, event_id=41, provider="Microsoft-Windows-Kernel-Power"),
        ])
        assert len(timeline.of(provider="disk")) == 1
        assert len(timeline.of(event_ids=(41,))) == 1
        assert len(timeline.of(provider="disk", event_ids=(41,))) == 0

    def test_preceding_solo_toma_la_ventana_anterior(self):
        """El corazon de la correlacion: que paso ANTES del fallo."""
        crash_time = datetime(2026, 8, 11, 12, 0)
        timeline = Timeline([
            _event(5),    # dentro de la ventana
            _event(9),    # dentro
            _event(30),   # fuera: demasiado antiguo
            EventRecord("System", 11, "disk", LEVEL_ERROR,
                        crash_time + timedelta(minutes=5)),  # posterior
        ])
        previous = timeline.preceding(crash_time, timedelta(minutes=10))
        assert len(previous) == 2

    def test_preceding_excluye_el_momento_exacto(self):
        crash_time = datetime(2026, 8, 11, 12, 0)
        timeline = Timeline([_event(0)])  # justo en crash_time
        assert timeline.preceding(crash_time, timedelta(minutes=10)) == []

    def test_agrupa_por_clave(self):
        timeline = Timeline([_event(1), _event(2), _event(3, event_id=51)])
        groups = timeline.group_by_key()
        assert len(groups["disk/11"]) == 2
        assert len(groups["disk/51"]) == 1

    def test_eventos_sin_fecha_se_conservan_pero_no_correlacionan(self):
        undated = EventRecord("System", 11, "disk", LEVEL_ERROR, None)
        timeline = Timeline([_event(1), undated])
        assert len(timeline) == 2
        assert len(list(timeline)) == 1        # iterar da solo los fechados
        assert len(timeline.all) == 2

    def test_span(self):
        timeline = Timeline([_event(0), _event(60)])
        assert timeline.span == timedelta(minutes=60)
