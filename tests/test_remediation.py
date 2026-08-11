"""Pruebas de las acciones de reparacion (fase 8).

Regla de oro de este archivo: NINGUNA prueba puede ejecutar un comando de
verdad. Una suite que corre `netsh winsock reset` o borra %TEMP% en la
maquina del que la ejecuta es peor que no tener pruebas. Por eso hay un
fixture `sin_procesos_reales` de tipo autouse que revienta si algo llega a
`subprocess`, y las acciones que borran archivos solo se prueban contra
carpetas temporales creadas por la propia prueba.
"""

from __future__ import annotations

import os
import re
import subprocess
from types import SimpleNamespace

import pytest

from inyaguidiag import remediation
from inyaguidiag.core.context import ScanContext, ScanMode
from inyaguidiag.core.models import RiskLevel
from inyaguidiag.remediation import base
from inyaguidiag.remediation import actions as acciones
from inyaguidiag.remediation.base import (
    Action,
    ActionPreview,
    ActionResult,
    CommandOutput,
    Confirmation,
    ConfirmationRequired,
    UnknownAction,
)

#: Los siete ids que las reglas ya referencian. Si esta lista y el registro
#: dejan de coincidir, alguien agrego o quito una accion sin mirar las
#: reglas.
IDS_ESPERADOS = {
    "clean-temp-files",
    "run-chkdsk",
    "run-sfc",
    "run-memory-diagnostic",
    "renew-dhcp",
    "set-public-dns",
    "reset-winsock",
}


# ----------------------------------------------------------------------
# Andamiaje
# ----------------------------------------------------------------------


#: Comandos de solo lectura que un preview SI puede ejecutar: mirar como
#: esta configurado el equipo no lo modifica. Todo lo demas ejecutado
#: durante una simulacion es un fallo.
LECTURA_PERMITIDA = ("show dnsservers",)


@pytest.fixture(autouse=True)
def sin_procesos_reales(monkeypatch):
    """Corta cualquier intento de lanzar un proceso durante las pruebas."""

    def prohibido(*args, **kwargs):
        raise AssertionError(
            "una prueba intento ejecutar un comando real: %r" % (args,)
        )

    monkeypatch.setattr(base.subprocess, "run", prohibido)

    # WMI tampoco: sin esto, el preview de set-public-dns consultaria los
    # adaptadores reales de la maquina que corre las pruebas y el resultado
    # dependeria del equipo.
    from inyaguidiag.winapi import wmi_bridge

    monkeypatch.setattr(wmi_bridge, "query", lambda *a, **k: [
        {"NetConnectionID": "Ethernet", "NetEnabled": True,
         "PhysicalAdapter": True},
    ])
    return prohibido


@pytest.fixture
def ctx(tmp_path):
    """Contexto ONLINE con administrador, apuntando a un Windows de mentira."""
    windows = tmp_path / "Windows"
    (windows / "System32").mkdir(parents=True)
    return ScanContext(
        mode=ScanMode.ONLINE,
        windows_root=str(windows),
        is_admin=True,
        output_dir=str(tmp_path / "Reportes"),
    )


@pytest.fixture
def ctx_offline(tmp_path):
    windows = tmp_path / "DiscoMuerto" / "Windows"
    (windows / "System32").mkdir(parents=True)
    return ScanContext(
        mode=ScanMode.OFFLINE, windows_root=str(windows), is_admin=True
    )


class Runner:
    """Sustituto de `run_command`: registra llamadas y responde a medida."""

    def __init__(self, respuestas=None, por_defecto=None):
        self.calls = []
        self._respuestas = respuestas or []
        self._por_defecto = por_defecto or CommandOutput(["fake"], returncode=0,
                                                         output="ok")

    def __call__(self, cmd, timeout=None, input_text=None):
        self.calls.append({"cmd": list(cmd), "timeout": timeout,
                           "input": input_text})
        linea = " ".join(cmd).lower()
        for patron, salida in self._respuestas:
            if patron in linea:
                return salida
        return self._por_defecto

    @property
    def lineas(self):
        return [" ".join(c["cmd"]) for c in self.calls]


@pytest.fixture
def runner(monkeypatch):
    r = Runner()
    monkeypatch.setattr(acciones, "run_command", r)
    return r


def autorizar(accion, contexto):
    """Confirmacion valida, como la que emitiria el CLI tras el 'si'."""
    return Confirmation.grant(accion, accion.preview(contexto), accepted_by="prueba")


# ----------------------------------------------------------------------
# 1. Ningun remedio apunta a una accion inexistente
# ----------------------------------------------------------------------


def _action_ids_referenciados_por_las_reglas():
    """Extrae los `action_id=` del codigo fuente del paquete de reglas.

    Se lee el fuente y no se ejecutan las reglas porque una regla solo
    construye su `Remedy` cuando encuentra el problema: recorrerlas en
    caliente exigiria fabricar los datos de todas las averias posibles y
    aun asi no garantizaria haber pasado por todas las ramas.
    """
    import inyaguidiag.rules as paquete_reglas

    patron = re.compile(r"action_id\s*=\s*[\"']([^\"']+)[\"']")
    encontrados = {}
    for carpeta in paquete_reglas.__path__:
        for nombre in sorted(os.listdir(carpeta)):
            if not nombre.endswith(".py"):
                continue
            ruta = os.path.join(carpeta, nombre)
            with open(ruta, "r", encoding="utf-8") as handle:
                for action_id in patron.findall(handle.read()):
                    encontrados.setdefault(action_id, []).append(nombre)
    return encontrados


class TestSinRemediosHuerfanos:
    """El test importante: un remedio que apunta a la nada es un boton roto."""

    def test_toda_accion_referenciada_esta_registrada(self):
        referenciados = _action_ids_referenciados_por_las_reglas()
        assert referenciados, "no se encontro ningun action_id en las reglas"
        huerfanos = {
            action_id: archivos
            for action_id, archivos in referenciados.items()
            if not remediation.has_action(action_id)
        }
        assert not huerfanos, (
            "estos remedios apuntan a acciones que no existen: %s" % huerfanos
        )

    def test_toda_accion_referenciada_se_puede_instanciar(self):
        for action_id in _action_ids_referenciados_por_las_reglas():
            accion = remediation.get_action(action_id)
            assert accion.action_id == action_id

    def test_el_registro_contiene_exactamente_lo_esperado(self):
        assert set(remediation.action_ids()) == IDS_ESPERADOS

    def test_pedir_una_accion_inexistente_es_un_error_ruidoso(self):
        with pytest.raises(UnknownAction):
            remediation.get_action("formatear-todo")

    def test_contrato_declarado_de_cada_accion(self):
        """Fija riesgo, elevacion y reinicio de cada accion.

        No compara contra las reglas: es una tabla escrita a mano que hace
        de contrato. Su valor es que cambiar cualquiera de estos tres
        campos obliga a tocar tambien este archivo, y ahi es donde uno se
        acuerda de revisar que el `Remedy` de la regla diga lo mismo.

        Importa que coincidan: si la regla promete "no hace falta
        administrador" y la accion si lo necesita, el arreglo se ofrece y
        despues falla delante del cliente. Paso exactamente eso con
        `run-memory-diagnostic`, que usa bcdedit.
        """
        esperado = {
            "clean-temp-files": (RiskLevel.SAFE, False, False),
            "run-chkdsk": (RiskLevel.INVASIVE, True, True),
            "run-sfc": (RiskLevel.INVASIVE, True, False),
            # bcdedit exige elevacion; la regla en crash_rules declara lo mismo
            "run-memory-diagnostic": (RiskLevel.MODERATE, True, True),
            "renew-dhcp": (RiskLevel.MODERATE, True, False),
            "set-public-dns": (RiskLevel.MODERATE, True, False),
            "reset-winsock": (RiskLevel.INVASIVE, True, True),
        }
        for action_id, (riesgo, admin, reinicio) in esperado.items():
            accion = remediation.get_action(action_id)
            assert accion.risk is riesgo, action_id
            assert accion.requires_admin is admin, action_id
            assert accion.requires_reboot is reinicio, action_id


# ----------------------------------------------------------------------
# 2. Nada se ejecuta sin confirmacion
# ----------------------------------------------------------------------


class TestCerrojos:
    def test_dry_run_es_el_valor_por_defecto(self, ctx, runner):
        """La llamada mas corta posible NO debe tocar la maquina."""
        for accion in remediation.all_actions():
            resultado = accion.execute(ctx)
            assert resultado.simulated is True, accion.action_id
            assert resultado.applied is False, accion.action_id
        # El preview puede consultar como esta el equipo, pero nada mas.
        for linea in runner.lineas:
            assert any(p in linea for p in LECTURA_PERMITIDA), (
                "la simulacion ejecuto un comando que modifica: %s" % linea
            )

    def test_la_simulacion_describe_lo_que_haria(self, ctx, runner):
        accion = remediation.get_action("reset-winsock")
        resultado = accion.execute(ctx)
        assert "SIMULACION" in resultado.message
        assert "winsock" in resultado.message.lower()

    def test_la_simulacion_no_borra_archivos(self, ctx, tmp_path, monkeypatch):
        temp = tmp_path / "usertemp"
        temp.mkdir()
        victima = temp / "basura.tmp"
        victima.write_bytes(b"x" * 2048)
        monkeypatch.setenv("TEMP", str(temp))

        resultado = remediation.get_action("clean-temp-files").execute(ctx)

        assert resultado.simulated is True
        assert victima.exists(), "la simulacion borro un archivo"
        assert resultado.details["estimated_freed_bytes"] >= 2048

    def test_ejecutar_sin_confirmacion_lanza(self, ctx, runner):
        accion = remediation.get_action("run-sfc")
        with pytest.raises(ConfirmationRequired):
            accion.execute(ctx, dry_run=False)
        assert runner.calls == []

    def test_todas_las_acciones_exigen_confirmacion(self, ctx, runner):
        for accion in remediation.all_actions():
            with pytest.raises(ConfirmationRequired):
                accion.execute(ctx, dry_run=False)
        assert runner.calls == []

    def test_una_confirmacion_no_sirve_para_otra_accion(self, ctx, runner):
        origen = remediation.get_action("clean-temp-files")
        permiso = autorizar(origen, ctx)
        destino = remediation.get_action("reset-winsock")
        with pytest.raises(ConfirmationRequired):
            destino.execute(ctx, confirmation=permiso, dry_run=False)
        assert runner.calls == []

    def test_una_confirmacion_inventada_a_mano_no_vale(self, ctx, runner):
        falsa = Confirmation(action_id="reset-winsock", token="")
        accion = remediation.get_action("reset-winsock")
        with pytest.raises(ConfirmationRequired):
            accion.execute(ctx, confirmation=falsa, dry_run=False)
        assert runner.calls == []

    def test_no_se_puede_confirmar_con_el_preview_de_otra_accion(self, ctx):
        otra = remediation.get_action("run-sfc")
        vista = remediation.get_action("run-chkdsk").preview(ctx)
        with pytest.raises(ValueError):
            Confirmation.grant(otra, vista)

    def test_con_confirmacion_pero_en_dry_run_sigue_sin_ejecutar(self, ctx, runner):
        """El dry_run manda: tener permiso no implica usarlo."""
        accion = remediation.get_action("reset-winsock")
        resultado = accion.execute(ctx, confirmation=autorizar(accion, ctx))
        assert resultado.simulated is True
        assert runner.calls == []

    def test_con_confirmacion_y_dry_run_falso_si_ejecuta(self, ctx, runner):
        accion = remediation.get_action("reset-winsock")
        resultado = accion.execute(
            ctx, confirmation=autorizar(accion, ctx), dry_run=False)
        assert resultado.simulated is False
        assert resultado.applied is True
        assert any("winsock reset" in linea for linea in runner.lineas)

    def test_una_subclase_no_puede_saltarse_la_plantilla(self):
        """Sobrescribir `execute` desactivaria los cerrojos: se prohibe."""
        with pytest.raises(TypeError):

            class AccionTramposa(Action):
                action_id = "accion-tramposa"
                title = "Tramposa"

                def preview(self, ctx):
                    return ActionPreview(self.action_id, self.title, "")

                def _perform(self, ctx):
                    return ActionResult(self.action_id, True, "")

                def execute(self, ctx, confirmation=None, dry_run=True):
                    return ActionResult(self.action_id, True, "ja")

    def test_una_accion_sin_identidad_no_se_puede_declarar(self):
        with pytest.raises(TypeError):

            class SinId(Action):
                title = "Sin id"

                def preview(self, ctx):
                    return ActionPreview("", "", "")

                def _perform(self, ctx):
                    return ActionResult("", True, "")


# ----------------------------------------------------------------------
# 3. Permisos y contexto
# ----------------------------------------------------------------------


class TestPermisosYContexto:
    def test_las_acciones_que_piden_admin_lo_declaran(self):
        for action_id in ("run-chkdsk", "run-sfc", "renew-dhcp",
                          "set-public-dns", "reset-winsock"):
            assert remediation.get_action(action_id).requires_admin is True

    def test_sin_admin_no_se_ejecuta_y_se_explica(self, tmp_path, runner):
        contexto = ScanContext(
            mode=ScanMode.ONLINE,
            windows_root=str(tmp_path / "Windows"),
            is_admin=False,
        )
        accion = remediation.get_action("reset-winsock")
        resultado = accion.execute(
            contexto, confirmation=autorizar(accion, contexto), dry_run=False)
        assert resultado.success is False
        assert "administrador" in resultado.message.lower()
        assert runner.calls == [], "se ejecuto un comando sin permisos"

    def test_ninguna_accion_aplica_en_modo_offline(self, ctx_offline):
        for accion in remediation.all_actions():
            assert accion.can_run(ctx_offline) is False, accion.action_id

    def test_en_offline_execute_no_hace_nada_y_lo_dice(self, ctx_offline, runner):
        accion = remediation.get_action("renew-dhcp")
        resultado = accion.execute(
            ctx_offline, confirmation=None, dry_run=False)
        assert resultado.success is False
        assert "offline" in resultado.message.lower()
        assert runner.calls == []

    def test_todas_aplican_en_modo_online(self, ctx):
        for accion in remediation.all_actions():
            assert accion.can_run(ctx) is True, accion.action_id

    def test_el_preview_nunca_esta_vacio(self, ctx, runner):
        """Sin preview util no hay consentimiento informado."""
        for accion in remediation.all_actions():
            vista = accion.preview(ctx)
            assert vista.action_id == accion.action_id
            assert vista.summary.strip(), accion.action_id
            assert vista.commands, accion.action_id
            assert accion.title in vista.as_text()


# ----------------------------------------------------------------------
# 4. Validacion de parametros y alcance de rutas
# ----------------------------------------------------------------------


class TestValidacionDeParametros:
    @pytest.mark.parametrize("valor", ["1.1.1.1", "8.8.8.8", "192.168.0.1"])
    def test_ipv4_validas(self, valor):
        assert base.is_valid_ipv4(valor) is True

    @pytest.mark.parametrize(
        "valor",
        ["", "8.8.8.8 && del C:\\", "999.1.1.1", "localhost", "8.8.8",
         "010.1.1.1", "::1", "8.8.8.8;netsh"],
    )
    def test_ipv4_invalidas(self, valor):
        assert base.is_valid_ipv4(valor) is False

    def test_dns_invalido_se_rechaza_al_construir_la_accion(self):
        with pytest.raises(ValueError):
            acciones.SetPublicDnsAction(servers=["8.8.8.8; shutdown /r"])

    def test_nombre_de_conexion_con_metacaracteres_se_rechaza(self):
        with pytest.raises(ValueError):
            acciones.SetPublicDnsAction(interfaces=['Ethernet" & del *.*'])

    def test_nombre_de_conexion_normal_se_acepta(self):
        accion = acciones.SetPublicDnsAction(interfaces=["Conexion de area local"])
        assert accion.interfaces(None) == ["Conexion de area local"]

    @pytest.mark.parametrize("valor", ["C:\\", "C", "CD:", "C:/x", "; rm"])
    def test_volumen_invalido_se_rechaza(self, valor):
        with pytest.raises(ValueError):
            acciones.RunChkdskAction(volume=valor)

    def test_volumen_valido_se_acepta(self, ctx):
        assert acciones.RunChkdskAction(volume="d:").volume(ctx) == "D:"

    def test_adaptador_invalido_se_rechaza(self):
        with pytest.raises(ValueError):
            acciones.RenewDhcpAction(adapter="Wi-Fi | shutdown")


class TestAlcanceDeRutas:
    def test_ruta_dentro(self, tmp_path):
        (tmp_path / "sub").mkdir()
        assert base.path_is_within(str(tmp_path / "sub" / "a.tmp"), str(tmp_path))

    def test_la_propia_raiz_cuenta_como_dentro(self, tmp_path):
        assert base.path_is_within(str(tmp_path), str(tmp_path))

    def test_ruta_fuera(self, tmp_path):
        fuera = tmp_path.parent / "otro_sitio"
        assert base.path_is_within(str(fuera), str(tmp_path)) is False

    def test_escape_con_punto_punto(self, tmp_path):
        escape = os.path.join(str(tmp_path), "..", "victima.txt")
        assert base.path_is_within(escape, str(tmp_path)) is False

    def test_carpeta_hermana_con_el_mismo_prefijo_no_cuenta(self, tmp_path):
        raiz = tmp_path / "temp"
        hermana = tmp_path / "temporal"
        raiz.mkdir()
        hermana.mkdir()
        assert base.path_is_within(str(hermana / "x"), str(raiz)) is False

    def test_rutas_vacias(self, tmp_path):
        assert base.path_is_within("", str(tmp_path)) is False
        assert base.path_is_within(str(tmp_path), "") is False


# ----------------------------------------------------------------------
# 5. clean-temp-files
# ----------------------------------------------------------------------


@pytest.fixture
def temp_poblado(tmp_path, monkeypatch):
    """%TEMP% de mentira con contenido, aislado del sistema real."""
    temp = tmp_path / "usertemp"
    (temp / "sub").mkdir(parents=True)
    (temp / "uno.tmp").write_bytes(b"a" * 1000)
    (temp / "sub" / "dos.tmp").write_bytes(b"b" * 500)
    monkeypatch.setenv("TEMP", str(temp))
    monkeypatch.setenv("TMP", str(temp))
    return temp


class TestLimpiarTemporales:
    def test_el_preview_calcula_el_espacio_que_liberaria(self, ctx, temp_poblado):
        vista = remediation.get_action("clean-temp-files").preview(ctx)
        assert vista.estimated_freed_bytes >= 1500
        assert "MB" in vista.as_text() or "KB" in vista.as_text()

    def test_el_preview_no_borra_nada(self, ctx, temp_poblado):
        remediation.get_action("clean-temp-files").preview(ctx)
        assert (temp_poblado / "uno.tmp").exists()

    def test_ejecutar_borra_solo_dentro_del_temporal(self, ctx, temp_poblado,
                                                     tmp_path):
        intocable = tmp_path / "documento_importante.docx"
        intocable.write_bytes(b"z" * 100)

        accion = remediation.get_action("clean-temp-files")
        resultado = accion.execute(
            ctx, confirmation=autorizar(accion, ctx), dry_run=False)

        assert resultado.success is True
        assert not (temp_poblado / "uno.tmp").exists()
        assert not (temp_poblado / "sub" / "dos.tmp").exists()
        assert temp_poblado.is_dir(), "no debe borrarse la carpeta objetivo"
        assert intocable.exists(), "borro algo fuera de su alcance"
        assert resultado.details["freed_bytes"] >= 1500

    def test_rechaza_archivos_que_se_salen_del_alcance(self, ctx, tmp_path,
                                                       monkeypatch):
        """Simula un junction o un nombre con '..' dentro del temporal.

        La ruta listada parece estar dentro pero apunta fuera. La accion
        debe contarla como fuera de alcance y NO borrarla.
        """
        raiz = tmp_path / "usertemp"
        raiz.mkdir()
        (raiz / "normal.tmp").write_bytes(b"x" * 10)
        victima = tmp_path / "victima.txt"
        victima.write_bytes(b"no me borres")

        escape = os.path.join("..", "victima.txt")

        def walk_falso(top, topdown=True):
            yield str(raiz), [], ["normal.tmp", escape]

        monkeypatch.setattr(acciones.os, "walk", walk_falso)

        stats = acciones.CleanTempFilesAction()._clean_root(str(raiz))

        assert victima.exists(), "borro un archivo fuera de la carpeta objetivo"
        assert not (raiz / "normal.tmp").exists()
        # Se cuenta dos veces: al listar y en la revalidacion previa al borrado.
        assert stats["outside"] >= 1
        assert stats["deleted"] == 1

    def test_no_acepta_como_objetivo_la_raiz_de_una_unidad(self, ctx, tmp_path):
        accion = acciones.CleanTempFilesAction()
        raiz_unidad = os.path.splitdrive(str(tmp_path))[0] + os.sep
        assert accion._is_safe_root(raiz_unidad, ctx) is False

    def test_no_acepta_como_objetivo_la_carpeta_de_windows(self, ctx):
        accion = acciones.CleanTempFilesAction()
        assert accion._is_safe_root(ctx.windows_root, ctx) is False

    def test_un_temp_mal_configurado_no_se_limpia(self, ctx, monkeypatch,
                                                  tmp_path):
        """Si TEMP apunta a la carpeta de Windows, no se toca nada."""
        monkeypatch.setenv("TEMP", ctx.windows_root)
        monkeypatch.setenv("TMP", ctx.windows_root)
        rutas = [ruta for _label, ruta, _admin
                 in acciones.CleanTempFilesAction().targets(ctx)]
        assert ctx.windows_root not in rutas

    def test_sin_admin_se_salta_las_carpetas_del_sistema(self, tmp_path,
                                                         temp_poblado):
        windows = tmp_path / "Windows"
        (windows / "Prefetch").mkdir(parents=True)
        (windows / "Prefetch" / "algo.pf").write_bytes(b"p" * 50)
        contexto = ScanContext(mode=ScanMode.ONLINE,
                               windows_root=str(windows), is_admin=False)

        accion = remediation.get_action("clean-temp-files")
        resultado = accion.execute(
            contexto, confirmation=autorizar(accion, contexto), dry_run=False)

        assert (windows / "Prefetch" / "algo.pf").exists()
        assert "administrador" in resultado.output.lower()

    def test_los_archivos_en_uso_no_rompen_la_limpieza(self, ctx, temp_poblado,
                                                       monkeypatch):
        def remove_falso(path):
            raise PermissionError("archivo en uso")

        monkeypatch.setattr(acciones.os, "remove", remove_falso)
        monkeypatch.setattr(acciones.os, "chmod",
                            lambda *a, **k: (_ for _ in ()).throw(OSError()))

        accion = remediation.get_action("clean-temp-files")
        resultado = accion.execute(
            ctx, confirmation=autorizar(accion, ctx), dry_run=False)

        assert resultado.success is True
        assert resultado.details["locked"] >= 2
        assert "en uso" in resultado.message


# ----------------------------------------------------------------------
# 6. Acciones que llaman a programas externos
# ----------------------------------------------------------------------


class TestAccionesDeComando:
    def test_chkdsk_programa_el_analisis_y_responde_al_prompt(self, ctx, runner):
        accion = acciones.RunChkdskAction(volume="C:")
        resultado = accion.execute(
            ctx, confirmation=autorizar(accion, ctx), dry_run=False)

        primera = runner.calls[0]
        assert os.path.basename(primera["cmd"][0]).lower().startswith("chkdsk")
        assert primera["cmd"][1:] == ["C:", "/F", "/R"]
        # Responde que si en castellano y en ingles: el idioma del Windows
        # analizado no se conoce de antemano.
        assert "S" in primera["input"] and "Y" in primera["input"]
        assert primera["timeout"] > 0
        assert resultado.requires_reboot is True

    def test_sfc_reporta_cuando_no_hay_nada_que_reparar(self, ctx, monkeypatch):
        r = Runner(por_defecto=CommandOutput(
            ["sfc"], returncode=0,
            output="La Proteccion de recursos de Windows no encontro "
                   "ninguna infraccion de integridad."))
        monkeypatch.setattr(acciones, "run_command", r)

        accion = remediation.get_action("run-sfc")
        resultado = accion.execute(
            ctx, confirmation=autorizar(accion, ctx), dry_run=False)

        assert resultado.success is True
        assert "integros" in resultado.message
        assert r.calls[0]["cmd"][1] == "/scannow"

    def test_sfc_no_se_mata_antes_de_media_hora(self):
        """Matar a sfc a mitad de una reparacion deja el sistema peor."""
        assert remediation.get_action("run-sfc").timeout >= 1800

    def test_diagnostico_de_memoria_usa_bcdedit_y_no_una_ventana(self, ctx,
                                                                 runner):
        accion = remediation.get_action("run-memory-diagnostic")
        resultado = accion.execute(
            ctx, confirmation=autorizar(accion, ctx), dry_run=False)

        linea = runner.lineas[0].lower()
        assert "bcdedit" in linea and "{memdiag}" in linea
        assert "mdsched" not in linea
        assert resultado.requires_reboot is True

    def test_renew_dhcp_libera_antes_de_pedir(self, ctx, runner):
        accion = remediation.get_action("renew-dhcp")
        accion.execute(ctx, confirmation=autorizar(accion, ctx), dry_run=False)

        argumentos = [c["cmd"][1] for c in runner.calls]
        assert argumentos[:2] == ["/release", "/renew"]

    def test_renew_dhcp_informa_la_direccion_obtenida(self, ctx, monkeypatch):
        r = Runner(por_defecto=CommandOutput(
            ["ipconfig"], returncode=0,
            output="Direccion IPv4. . . . . . . . . . : 192.168.1.45"))
        monkeypatch.setattr(acciones, "run_command", r)
        accion = remediation.get_action("renew-dhcp")
        resultado = accion.execute(
            ctx, confirmation=autorizar(accion, ctx), dry_run=False)
        assert resultado.success is True
        assert "192.168.1.45" in resultado.message

    def test_un_comando_que_no_existe_no_revienta(self, ctx, monkeypatch):
        r = Runner(por_defecto=CommandOutput(["netsh"], not_found=True))
        monkeypatch.setattr(acciones, "run_command", r)
        accion = remediation.get_action("reset-winsock")
        resultado = accion.execute(
            ctx, confirmation=autorizar(accion, ctx), dry_run=False)
        assert resultado.success is False
        assert "no se encontro" in resultado.message.lower()

    def test_un_comando_colgado_no_cuelga_la_herramienta(self, ctx, monkeypatch):
        r = Runner(por_defecto=CommandOutput(["netsh"], timed_out=True))
        monkeypatch.setattr(acciones, "run_command", r)
        accion = remediation.get_action("reset-winsock")
        resultado = accion.execute(
            ctx, confirmation=autorizar(accion, ctx), dry_run=False)
        assert resultado.success is False
        assert "tiempo" in resultado.message.lower()

    def test_una_excepcion_inesperada_se_convierte_en_resultado(self, ctx,
                                                                monkeypatch):
        def explota(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(acciones, "run_command", explota)
        accion = remediation.get_action("reset-winsock")
        resultado = accion.execute(
            ctx, confirmation=autorizar(accion, ctx), dry_run=False)
        assert resultado.success is False
        assert "boom" in resultado.message


class TestDnsPublicos:
    def _runner_dns(self, monkeypatch, previos="192.168.1.1"):
        r = Runner(respuestas=[
            ("show dnsservers", CommandOutput(
                ["netsh"], returncode=0,
                output="Configuracion para la interfaz Ethernet\n"
                       "    Servidores DNS configurados: %s" % previos)),
        ])
        monkeypatch.setattr(acciones, "run_command", r)
        return r

    def test_guarda_los_dns_anteriores_para_poder_revertir(self, ctx,
                                                           monkeypatch):
        self._runner_dns(monkeypatch)
        accion = acciones.SetPublicDnsAction(interfaces=["Ethernet"])
        resultado = accion.execute(
            ctx, confirmation=autorizar(accion, ctx), dry_run=False)

        assert resultado.success is True
        assert resultado.undo_data["previous_dns"]["Ethernet"] == ["192.168.1.1"]
        assert os.path.isfile(resultado.undo_data["backup_file"])
        assert any("192.168.1.1" in linea
                   for linea in resultado.undo_data["restore"])

    def test_aplica_los_dos_dns_publicos(self, ctx, monkeypatch):
        r = self._runner_dns(monkeypatch)
        accion = acciones.SetPublicDnsAction(interfaces=["Ethernet"])
        accion.execute(ctx, confirmation=autorizar(accion, ctx), dry_run=False)

        aplicados = " ".join(r.lineas)
        assert "1.1.1.1" in aplicados and "8.8.8.8" in aplicados
        assert "name=Ethernet" in aplicados

    def test_los_comandos_de_reversion_devuelven_a_dhcp(self):
        lineas = acciones.SetPublicDnsAction.restore_commands({"Ethernet": []})
        assert lineas == [
            'netsh interface ipv4 set dnsservers name="Ethernet" dhcp'
        ]

    def test_sin_conexiones_no_hace_nada(self, ctx, monkeypatch):
        self._runner_dns(monkeypatch)
        accion = acciones.SetPublicDnsAction(interfaces=None)
        monkeypatch.setattr(accion, "interfaces", lambda contexto: [])
        resultado = accion.execute(
            ctx, confirmation=autorizar(accion, ctx), dry_run=False)
        assert resultado.success is False
        assert "ninguna conexion" in resultado.message.lower()

    def test_las_conexiones_salen_de_wmi_no_de_texto_traducido(self, ctx,
                                                               monkeypatch):
        from inyaguidiag.winapi import wmi_bridge

        monkeypatch.setattr(wmi_bridge, "query", lambda *a, **k: [
            {"NetConnectionID": "Wi-Fi", "NetEnabled": True,
             "PhysicalAdapter": True},
            {"NetConnectionID": "VPN virtual", "NetEnabled": True,
             "PhysicalAdapter": False},
            {"NetConnectionID": None, "NetEnabled": True,
             "PhysicalAdapter": True},
        ])
        assert acciones.SetPublicDnsAction().interfaces(ctx) == ["Wi-Fi"]

    def test_si_wmi_falla_no_revienta(self, ctx, monkeypatch):
        from inyaguidiag.winapi import wmi_bridge

        def explota(*args, **kwargs):
            raise RuntimeError("sin WMI")

        monkeypatch.setattr(wmi_bridge, "query", explota)
        assert acciones.SetPublicDnsAction().interfaces(ctx) == []


# ----------------------------------------------------------------------
# 7. El ejecutor de comandos
# ----------------------------------------------------------------------


class TestRunCommand:
    def _fake_run(self, capturado, salida=b"ok", returncode=0):
        def fake(cmd, **kwargs):
            capturado["cmd"] = cmd
            capturado.update(kwargs)
            return SimpleNamespace(returncode=returncode, stdout=salida)

        return fake

    def test_captura_la_salida_y_el_codigo(self, monkeypatch):
        capturado = {}
        monkeypatch.setattr(base.subprocess, "run",
                            self._fake_run(capturado, b"todo bien"))
        salida = base.run_command(["ipconfig", "/all"], timeout=5)
        assert salida.ok is True
        assert salida.output == "todo bien"
        assert capturado["cmd"] == ["ipconfig", "/all"]
        assert capturado["timeout"] == 5

    def test_nunca_usa_shell(self, monkeypatch):
        """Sin shell no hay metacaracteres que interpretar."""
        capturado = {}
        monkeypatch.setattr(base.subprocess, "run", self._fake_run(capturado))
        base.run_command(["netsh", "winsock", "reset"])
        assert capturado["shell"] is False

    @pytest.mark.skipif(os.name != "nt", reason="creationflags es de Windows")
    def test_no_abre_ventana_de_consola(self, monkeypatch):
        capturado = {}
        monkeypatch.setattr(base.subprocess, "run", self._fake_run(capturado))
        base.run_command(["ipconfig"])
        assert capturado["creationflags"] == 0x08000000

    def test_sin_entrada_se_desconecta_stdin(self, monkeypatch):
        """Un comando que pregunta algo debe morir, no colgarse."""
        capturado = {}
        monkeypatch.setattr(base.subprocess, "run", self._fake_run(capturado))
        base.run_command(["chkdsk"])
        assert capturado["stdin"] == subprocess.DEVNULL

    def test_el_timeout_se_reporta_sin_lanzar(self, monkeypatch):
        def caducar(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 1, output=b"a medias")

        monkeypatch.setattr(base.subprocess, "run", caducar)
        salida = base.run_command(["sfc", "/scannow"], timeout=1)
        assert salida.timed_out is True
        assert salida.ok is False

    def test_un_ejecutable_ausente_se_reporta_sin_lanzar(self, monkeypatch):
        def no_esta(cmd, **kwargs):
            raise FileNotFoundError(cmd)

        monkeypatch.setattr(base.subprocess, "run", no_esta)
        salida = base.run_command(["wmic"])
        assert salida.not_found is True
        assert salida.ok is False

    def test_un_error_del_sistema_operativo_se_reporta_sin_lanzar(self,
                                                                  monkeypatch):
        def sin_permiso(cmd, **kwargs):
            raise OSError("acceso denegado")

        monkeypatch.setattr(base.subprocess, "run", sin_permiso)
        salida = base.run_command(["chkdsk"])
        assert salida.ok is False
        assert "acceso denegado" in salida.output

    def test_decodifica_la_salida_utf16_de_sfc(self):
        """sfc escribe UTF-16LE; leerlo como ANSI llena el reporte de basura."""
        crudo = u"Proteccion de recursos".encode("utf-16-le")
        assert base._decode(crudo) == "Proteccion de recursos"

    def test_decodifica_la_salida_de_un_byte(self):
        assert base._decode(b"Windows IP\r\n") == "Windows IP"


# ----------------------------------------------------------------------
# 8. Ayudas de presentacion
# ----------------------------------------------------------------------


class TestPresentacion:
    def test_tamano_legible(self):
        assert base.human_size(512) == "512 B"
        assert base.human_size(2048) == "2.0 KB"
        assert base.human_size(5 * 1024 ** 2) == "5.0 MB"

    def test_etiquetas_de_riesgo_en_castellano(self):
        assert base.risk_label(RiskLevel.SAFE) == "seguro"
        assert base.risk_label(RiskLevel.INVASIVE) == "invasivo"

    def test_el_texto_del_preview_avisa_de_reinicio_y_admin(self, ctx, runner):
        texto = remediation.get_action("run-chkdsk").preview(ctx).as_text()
        assert "administrador" in texto
        assert "reiniciar" in texto

    def test_la_huella_del_preview_cambia_si_cambia_el_contenido(self):
        uno = ActionPreview("x", "X", "hace algo", commands=["a"])
        dos = ActionPreview("x", "X", "hace algo", commands=["b"])
        assert uno.digest != dos.digest

    def test_acciones_para_un_reporte(self, ctx):
        from datetime import datetime

        from inyaguidiag.core.models import (
            Category, Finding, MachineInfo, Remedy, ScanReport, Severity,
        )

        reporte = ScanReport(machine=MachineInfo(), started_at=datetime.now())
        reporte.findings = [
            Finding(rule_id="STO-002", title="Disco lleno",
                    severity=Severity.CRITICAL, category=Category.STORAGE,
                    summary="", remedy=Remedy(explanation="",
                                              action_id="clean-temp-files")),
            Finding(rule_id="STO-001", title="Disco muriendo",
                    severity=Severity.CRITICAL, category=Category.STORAGE,
                    summary="", remedy=Remedy(explanation="")),
        ]
        pares = remediation.actions_for_report(reporte)
        assert len(pares) == 1
        assert pares[0][1].action_id == "clean-temp-files"
